use alloy::primitives::{Address, FixedBytes, U256, Uint, keccak256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};

use crate::crypto::hash_to_scalar;
use crate::crypto::poseidon::poseidon;
use crate::crypto::railgun::pack_chain_id;
use crate::notes::Note;

sol! {
    struct G1Point { uint256 x; uint256 y; }
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct SnarkProof { G1Point a; G2Point b; G1Point c; }

    struct CommitmentCiphertext {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertext[] commitmentCiphertext;
    }

    struct TokenData {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    struct CommitmentPreimage {
        bytes32 npk;
        TokenData token;
        uint120 value;
    }

    struct Transaction {
        SnarkProof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParams boundParams;
        CommitmentPreimage unshieldPreimage;
    }

    #[derive(Debug)]
    struct Call {
        address to;
        bytes data;
        uint256 value;
    }

    #[derive(Debug)]
    struct ActionData {
        bytes31 random;
        bool requireSuccess;
        uint256 minGasLimit;
        Call[] calls;
    }

    struct TokenTransfer {
        TokenData token;
        address to;
        uint256 value;
    }

    #[derive(Debug)]
    struct RelayAdaptParamsInput {
        bytes32[][] nullifiers;
        uint256 transactions_length;
        ActionData action_data;
    }

    struct ShieldCiphertext {
        bytes32[3] encryptedBundle;
        bytes32 shieldKey;
    }

    struct LegacyCommitmentPreimage {
        uint256 npk;
        TokenData token;
        uint120 value;
    }

    struct LegacyCommitmentCiphertext {
        uint256[4] ciphertext;
        uint256[2] ephemeralKeys;
        uint256[] memo;
    }

    function transact(Transaction[] _transactions) payable;
    function relay(Transaction[] _transactions, ActionData _actionData) payable;

    function unwrapBase(uint256 _amount);
    function transfer(TokenTransfer[] _transfers);

    event Transact(
        uint256 treeNumber,
        uint256 startPosition,
        bytes32[] hash,
        CommitmentCiphertext[] ciphertext
    );

    event Shield(
        uint256 treeNumber,
        uint256 startPosition,
        CommitmentPreimage[] commitments,
        ShieldCiphertext[] shieldCiphertext,
        uint256[] fees
    );

    event ShieldLegacyPreMar23(
        uint256 treeNumber,
        uint256 startPosition,
        CommitmentPreimage[] commitments,
        ShieldCiphertext[] shieldCiphertext
    );

    event CommitmentBatch(
        uint256 treeNumber,
        uint256 startPosition,
        uint256[] hash,
        LegacyCommitmentCiphertext[] ciphertext
    );

    event GeneratedCommitmentBatch(
        uint256 treeNumber,
        uint256 startPosition,
        LegacyCommitmentPreimage[] commitments,
        uint256[2][] encryptedRandom
    );

    event Nullifiers(
        uint256 treeNumber,
        uint256[] nullifier
    );

    event Nullified(
        uint16 treeNumber,
        bytes32[] nullifier
    );

    event Unshield(
        address to,
        TokenData token,
        uint256 amount,
        uint256 fee
    );
}

impl Default for SnarkProof {
    fn default() -> Self {
        Self {
            a: G1Point {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            b: G2Point {
                x: [U256::ZERO, U256::ZERO],
                y: [U256::ZERO, U256::ZERO],
            },
            c: G1Point {
                x: U256::ZERO,
                y: U256::ZERO,
            },
        }
    }
}

impl BoundParams {
    #[must_use]
    pub fn new_unshield(
        tree_number: u32,
        chain_type: u8,
        chain_id: u64,
        commitment_ciphertext: Vec<CommitmentCiphertext>,
        adapt_contract: Address,
        adapt_params: FixedBytes<32>,
    ) -> Self {
        let chain_id = pack_chain_id(chain_type, chain_id);
        Self {
            treeNumber: tree_number as u16,
            minGasPrice: Uint::<72, 2>::ZERO,
            unshield: 1,
            chainID: chain_id,
            adaptContract: adapt_contract,
            adaptParams: adapt_params,
            commitmentCiphertext: commitment_ciphertext,
        }
    }

    #[must_use]
    pub fn new_transact(
        tree_number: u32,
        chain_type: u8,
        chain_id: u64,
        commitment_ciphertext: Vec<CommitmentCiphertext>,
        adapt_contract: Address,
        adapt_params: FixedBytes<32>,
    ) -> Self {
        let chain_id = pack_chain_id(chain_type, chain_id);
        Self {
            treeNumber: tree_number as u16,
            minGasPrice: Uint::<72, 2>::ZERO,
            unshield: 0,
            chainID: chain_id,
            adaptContract: adapt_contract,
            adaptParams: adapt_params,
            commitmentCiphertext: commitment_ciphertext,
        }
    }

    #[must_use]
    pub fn hash(&self) -> U256 {
        hash_to_scalar(self.abi_encode())
    }
}

impl CommitmentPreimage {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            npk: FixedBytes::from([0u8; 32]),
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::ZERO,
                tokenSubID: U256::ZERO,
            },
            value: Uint::<120, 2>::ZERO,
        }
    }

    #[must_use]
    pub fn new_unshield(note: &Note, token_address: Address) -> Self {
        let value: u128 = note.value.to::<u128>();
        Self {
            npk: FixedBytes::from(note.npk.to_be_bytes::<32>()),
            token: TokenData {
                tokenType: 0,
                tokenAddress: token_address,
                tokenSubID: U256::ZERO,
            },
            value: Uint::<120, 2>::from(value),
        }
    }

    #[must_use]
    pub fn hash(&self) -> U256 {
        let token_id_value = self.token.id();
        let npk = U256::from_be_bytes(self.npk.0);
        let value = U256::from(self.value);
        poseidon(vec![npk, token_id_value, value])
    }

    #[must_use]
    pub fn note_with_random(&self, random: [u8; 16]) -> Note {
        let token_hash = self.token.id();
        let value: u128 = self.value.to();
        let value = U256::from(value);
        let npk = U256::from_be_bytes(self.npk.0);
        Note {
            token_hash,
            value,
            random,
            npk,
        }
    }
}

impl TokenData {
    #[must_use]
    pub fn id(&self) -> U256 {
        if self.tokenType == 0 {
            U256::from_be_slice(self.tokenAddress.as_slice())
        } else {
            hash_to_scalar(self.abi_encode())
        }
    }
}

impl LegacyCommitmentPreimage {
    #[must_use]
    pub fn hash(&self) -> U256 {
        let token_id_value = self.token.id();
        let value = U256::from(self.value);
        poseidon(vec![self.npk, token_id_value, value])
    }
}

impl ActionData {
    #[must_use]
    pub fn unwrap_base(
        relay_adapt: Address,
        recipient: Address,
        random: FixedBytes<31>,
        require_success: bool,
    ) -> Self {
        let unwrap_call = Call {
            to: relay_adapt,
            data: unwrapBaseCall {
                _amount: U256::ZERO,
            }
            .abi_encode()
            .into(),
            value: U256::ZERO,
        };

        let base_token = TokenData {
            tokenType: 0,
            tokenAddress: Address::ZERO,
            tokenSubID: U256::ZERO,
        };
        let transfer = TokenTransfer {
            token: base_token,
            to: recipient,
            value: U256::ZERO,
        };
        let transfer_call = Call {
            to: relay_adapt,
            data: transferCall {
                _transfers: vec![transfer],
            }
            .abi_encode()
            .into(),
            value: U256::ZERO,
        };

        Self {
            random,
            requireSuccess: require_success,
            minGasLimit: U256::ZERO,
            calls: vec![unwrap_call, transfer_call],
        }
    }

    #[must_use]
    pub fn adapt_params(&self, transactions: &[&Transaction]) -> FixedBytes<32> {
        let nullifiers: Vec<Vec<FixedBytes<32>>> = transactions
            .iter()
            .map(|tx| tx.nullifiers.clone())
            .collect();
        let input = RelayAdaptParamsInput {
            nullifiers,
            transactions_length: U256::from(transactions.len()),
            action_data: self.clone(),
        };
        keccak256(input.abi_encode_params())
    }
}

#[cfg(test)]
mod tests {
    use crate::contracts::railgun::{ActionData, Call, RelayAdaptParamsInput};
    use alloy::hex;
    use alloy::primitives::{U256, address, keccak256};
    use alloy::sol_types::SolValue;

    #[test]
    fn test_adapt_params() {
        let params = RelayAdaptParamsInput {
            nullifiers: vec![vec![
                hex!("0x1c911118dcfc8ebc3e315bf17151b5a5c7e03c16988fb8019ebc2f82b2cea48f").into(),
                hex!("0x230fbeddc40f83d49790efbe87e5de0ced0ef1ecbf8da4c7c44f6fdf11f2f400").into(),
                hex!("0x0f8fd272010594e02bfb22c3c7c8e1ad29f54a6ad68279693d9405dda99f9c46").into(),
                hex!("0x07030295c7d49345dcf74f06065b4af6cc1f1097de2f0514537da6618effedc9").into(),
                hex!("0x2215519c762b8cb8d8785260209e52fbd2096bbeb40ea7332d39337ee7ff0222").into(),
                hex!("0x0ca77c648f3a9887165935b0ce9dfd004c53550d89370c9a34761d3ca6656ee6").into(),
                hex!("0x04f949ae13b78c069022584abed7ac6d5c3c7ad96f5409c8c86ac69a3116deb3").into(),
                hex!("0x0950a3ed83f83d224656b533af70062e0b3535d83e15e824bce1f10aaacae63b").into(),
                hex!("0x04f8652775bba33f82a5bf062b9a8bb4577046b69a3c463dd10c192e8c979c5c").into(),
                hex!("0x14e1eecf6d4c3085f2875050ba63ee413026e98903f16c05cd83d7afa5607a55").into(),
            ]],
            transactions_length: U256::ONE,
            action_data: ActionData {
                random: hex!("0x291e6288093ace23c0a65f63fef9cbca72e30e2c2567013027fed15fff7761").into(),
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: vec![
                        Call{
                            to: address!("0xac9f360ae85469b27aeddeafc579ef2d052ad405"),
                            data: hex!("0xd5774a280000000000000000000000000000000000000000000000000000000000000000").into(),
                            value: U256::ZERO
                        },
                        Call{
                            to: address!("0xac9f360ae85469b27aeddeafc579ef2d052ad405"),
                            data: hex!("0xc2e9ffd8000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d0efc24db8fe005e24271c6f823cac22b0641d80000000000000000000000000000000000000000000000000000000000000000").into(),
                            value: U256::ZERO
                        }
                ],
            },
        };
        let encoded = params.abi_encode_params();
        let hash = keccak256(&encoded);
        assert_eq!(
            hash,
            hex!("0x830b9e3899d14ee500b62572acd396d45f9f79084a342b7a4368e9a5d075bf6a")
        );
    }
}
