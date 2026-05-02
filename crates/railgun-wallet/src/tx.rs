use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::Instant;

use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use alloy::sol_types::SolCall;
use alloy::uint;
use rand::Rng;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use thiserror::Error;

use broadcaster_core::contracts::railgun::{
    ActionData, BoundParams, CommitmentPreimage, SnarkProof, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, MERKLE_ZERO_VALUE, PreTxPoi, SnarkJsProof, dummy_txid_root,
    pad_with_merkle_zero, railgun_txid_leaf_hash,
};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::{MerkleForest, MerkleProof};
use poi::error::PoiRpcError;
use poi::poi::{PoiMerkleProof, PoiRpcClient};

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::{Note, NoteCiphertext};
use crate::prover::{ProverError, ProverService};

pub const UNRELAYED_ADAPT_PARAMS: FixedBytes<32> = FixedBytes::ZERO;

/// Maximum number of UTXOs that can be used as inputs in a single transaction.
pub const MAX_CIRCUIT_INPUTS: usize = 13;

/// Maximum total inputs to the signature hash (inputs + outputs + 2 for root and bound params).
pub const MAX_SIGNATURE_INPUTS: usize = 16;

/// Maximum number of inner Railgun transactions to include in one outer call.
pub const MAX_BATCH_TRANSACTIONS: usize = 8;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("no matching utxos for amount. max immediately spendable: {0}")]
    InsufficientBalance(U256),
    #[error("utxos exceed circuit input limit")]
    TooManyInputs,
    #[error("inputs span multiple trees")]
    MixedTrees,
    #[error("inputs contain unexpected token")]
    TokenMismatch,
    #[error("signature message too large: {inputs} inputs + {outputs} outputs (max 16)")]
    SignatureInputLimit { inputs: usize, outputs: usize },
    #[error("missing merkle root")]
    MissingRoot,
    #[error("missing action data for unwrap")]
    MissingActionData,
    #[error("missing merkle proof for tree {tree} position {position}")]
    MissingProof { tree: u32, position: u64 },
    #[error("min gas price exceeds uint72: {0}")]
    MinGasPriceTooLarge(u128),
    #[error("encrypt note failed: {0}")]
    Encrypt(#[from] crate::notes::NoteError),
    #[error("prove failed: {0}")]
    Prover(#[from] ProverError),
}

#[derive(Debug, Error)]
pub enum PreTransactionPoiError {
    #[error("POI proof input count mismatch: expected {expected}, got {got}")]
    InputCountMismatch { expected: usize, got: usize },
    #[error("POI output count mismatch: expected at least {expected}, got {got}")]
    OutputCountMismatch { expected: usize, got: usize },
    #[error("missing private output before unshield marker")]
    MissingPrivateOutputBeforeUnshield,
    #[error("POI merkle proof count mismatch: expected {expected}, got {got}")]
    MerkleProofCountMismatch { expected: usize, got: usize },
    #[error("POI merkle proof leaf mismatch at index {index}: expected {expected}, got {actual}")]
    MerkleProofLeafMismatch {
        index: usize,
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error(
        "POI merkle proof path length mismatch at index {index}: expected {expected}, got {got}"
    )]
    MerkleProofPathLengthMismatch {
        index: usize,
        expected: usize,
        got: usize,
    },
    #[error("TXID merkle proof path length mismatch: expected {expected}, got {got}")]
    TxidMerkleProofPathLengthMismatch { expected: usize, got: usize },
    #[error("TXID leaf hash mismatch: expected {expected}, got {actual}")]
    TxidLeafHashMismatch {
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("POI public signal count mismatch: expected {expected}, got {got}")]
    PublicSignalCountMismatch { expected: usize, got: usize },
    #[error("POI public signal mismatch for {field}: expected {expected}, got {actual}")]
    PublicSignalMismatch {
        field: &'static str,
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("invalid hex field {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("POI RPC failed: {0}")]
    PoiRpc(#[from] PoiRpcError),
    #[error("POI prove failed: {0}")]
    Prover(#[from] ProverError),
}

#[derive(Debug, Clone)]
pub struct TransactionCall {
    pub to: Address,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct InputWitness {
    pub utxo: Utxo,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone)]
pub struct TransactionPlanChunk {
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub has_unshield: bool,
    pub public_inputs: PublicInputs,
    pub private_inputs: PrivateInputs,
    pub signature: [U256; 3],
}

impl TransactionPlanChunk {
    #[must_use]
    pub fn railgun_txid(&self) -> U256 {
        compute_railgun_txid_from_public_inputs(&self.public_inputs)
    }
}

#[derive(Debug, Clone)]
pub struct UnshieldPlan {
    pub call: TransactionCall,
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub chunks: Vec<TransactionPlanChunk>,
    pub broadcaster_fee_note: Option<Note>,
    pub unshield_note: Note,
    pub unshield_notes: Vec<Note>,
    pub change_note: Option<Note>,
    pub public_inputs: PublicInputs,
    pub private_inputs: PrivateInputs,
    pub signature: [U256; 3],
}

#[derive(Debug, Clone)]
pub struct SendPlan {
    pub call: TransactionCall,
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub chunks: Vec<TransactionPlanChunk>,
    pub broadcaster_fee_note: Option<Note>,
    pub recipient_note: Note,
    pub recipient_notes: Vec<Note>,
    pub change_note: Option<Note>,
    pub public_inputs: PublicInputs,
    pub private_inputs: PrivateInputs,
    pub signature: [U256; 3],
}

#[derive(Debug, Clone)]
pub struct TransactPlan {
    pub call: TransactionCall,
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub public_inputs: PublicInputs,
    pub private_inputs: PrivateInputs,
    pub signature: [U256; 3],
}

impl UnshieldPlan {
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.chunks.len()
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    #[must_use]
    pub fn private_output_count(&self) -> usize {
        self.outputs.len()
    }

    #[must_use]
    pub fn public_output_count(&self) -> usize {
        self.unshield_notes.len()
    }

    #[must_use]
    pub fn unshield_amount(&self) -> U256 {
        self.unshield_notes
            .iter()
            .fold(U256::ZERO, |sum, note| sum + note.value)
    }
}

impl SendPlan {
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.chunks.len()
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    #[must_use]
    pub fn private_output_count(&self) -> usize {
        self.outputs.len()
    }

    #[must_use]
    pub const fn public_output_count(&self) -> usize {
        0
    }

    #[must_use]
    pub fn send_amount(&self) -> U256 {
        self.recipient_notes
            .iter()
            .fold(U256::ZERO, |sum, note| sum + note.value)
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub merkle_root: U256,
    pub bound_params_hash: U256,
    pub nullifiers: Vec<U256>,
    pub commitments_out: Vec<U256>,
}

#[derive(Debug, Clone)]
pub struct PrivateInputs {
    pub token_address: U256,
    pub random_in: Vec<U256>,
    pub value_in: Vec<U256>,
    pub path_elements: Vec<U256>,
    pub leaves_indices: Vec<U256>,
    pub value_out: Vec<U256>,
    pub public_key: [U256; 2],
    pub npk_out: Vec<U256>,
    pub nullifying_key: U256,
}

impl PublicInputs {
    #[must_use]
    pub fn from_transaction(
        merkle_root: U256,
        transaction: &Transaction,
        outputs: &[Note],
    ) -> Self {
        let bound_params_hash = transaction.boundParams.hash();
        let nullifiers = transaction
            .nullifiers
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect();
        let commitments_out = outputs.iter().map(Note::commitment).collect();
        Self {
            merkle_root,
            bound_params_hash,
            nullifiers,
            commitments_out,
        }
    }

    #[must_use]
    pub fn signature_message(&self) -> Vec<U256> {
        let mut inputs = Vec::with_capacity(2 + self.nullifiers.len() + self.commitments_out.len());
        inputs.push(self.merkle_root);
        inputs.push(self.bound_params_hash);
        inputs.extend_from_slice(&self.nullifiers);
        inputs.extend_from_slice(&self.commitments_out);
        inputs
    }

    #[must_use]
    pub fn signature(&self, signer: &impl RailgunSpendSigner) -> [U256; 3] {
        let msg = poseidon(self.signature_message());
        signer.sign_spend_message(msg)
    }
}

impl PrivateInputs {
    #[must_use]
    pub fn from_inputs(
        token_address: Address,
        inputs: &[InputWitness],
        outputs: &[Note],
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
    ) -> Self {
        let token_address = U256::from_be_slice(token_address.as_slice());
        let mut path_elements = Vec::with_capacity(inputs.len() * merkletree::tree::TREE_DEPTH);
        let mut random_in = Vec::with_capacity(inputs.len());
        let mut value_in = Vec::with_capacity(inputs.len());
        let mut leaves_indices = Vec::with_capacity(inputs.len());

        for input in inputs {
            random_in.push(U256::from_be_slice(&input.utxo.note.random));
            value_in.push(input.utxo.note.value);
            leaves_indices.push(U256::from(input.utxo.position));
            path_elements.extend_from_slice(&input.merkle_proof.path_elements);
        }

        let value_out = outputs.iter().map(|note| note.value).collect();
        let npk_out = outputs.iter().map(|note| note.npk).collect();

        Self {
            token_address,
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            value_out,
            public_key: signer.spending_public_key(),
            npk_out,
            nullifying_key: viewing.nullifying_key,
        }
    }
}

pub type PreTransactionPoiMap = BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoiCircuitVariant {
    pub max_inputs: usize,
    pub max_outputs: usize,
}

#[must_use]
pub const fn poi_circuit_variant(nullifiers: usize, commitments_out: usize) -> PoiCircuitVariant {
    if nullifiers <= 3 && commitments_out <= 3 {
        PoiCircuitVariant {
            max_inputs: 3,
            max_outputs: 3,
        }
    } else {
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoiProofInputs {
    pub any_railgun_txid_merkleroot_after_transaction: U256,
    pub bound_params_hash: U256,
    pub nullifiers: Vec<U256>,
    pub commitments_out: Vec<U256>,
    pub spending_public_key: [U256; 2],
    pub nullifying_key: U256,
    pub token: U256,
    pub randoms_in: Vec<U256>,
    pub values_in: Vec<U256>,
    pub utxo_positions_in: Vec<U256>,
    pub utxo_tree_in: U256,
    pub npks_out: Vec<U256>,
    pub values_out: Vec<U256>,
    pub utxo_batch_global_start_position_out: U256,
    pub railgun_txid_if_has_unshield: U256,
    pub railgun_txid_merkle_proof_indices: U256,
    pub railgun_txid_merkle_proof_path_elements: Vec<U256>,
    pub poi_merkleroots: Vec<U256>,
    pub poi_in_merkle_proof_indices: Vec<U256>,
    pub poi_in_merkle_proof_path_elements: Vec<Vec<U256>>,
}

#[derive(Debug, Clone)]
pub struct PreTransactionPoiChunkInputs {
    pub txid_leaf_hash: FixedBytes<32>,
    pub txid_merkleroot: FixedBytes<32>,
    pub blinded_commitments_in: Vec<FixedBytes<32>>,
    pub blinded_commitments_out: Vec<FixedBytes<32>>,
    pub railgun_txid_if_has_unshield: Bytes,
    proof_base_inputs: PoiProofBaseInputs,
}

#[derive(Debug, Clone)]
pub struct PostTransactionPoiData {
    pub txid_leaf_hash: FixedBytes<32>,
    pub txid_merkleroot: FixedBytes<32>,
    pub txid_merkleroot_index: u64,
    pub txid_merkle_proof_indices: U256,
    pub txid_merkle_proof_path_elements: Vec<U256>,
    pub utxo_batch_global_start_position_out: U256,
}

#[derive(Debug, Clone)]
struct PoiProofBaseInputs {
    any_railgun_txid_merkleroot_after_transaction: U256,
    bound_params_hash: U256,
    nullifiers: Vec<U256>,
    commitments_out: Vec<U256>,
    spending_public_key: [U256; 2],
    nullifying_key: U256,
    token: U256,
    randoms_in: Vec<U256>,
    values_in: Vec<U256>,
    utxo_positions_in: Vec<U256>,
    utxo_tree_in: U256,
    npks_out: Vec<U256>,
    values_out: Vec<U256>,
    utxo_batch_global_start_position_out: U256,
    railgun_txid_if_has_unshield: U256,
    railgun_txid_merkle_proof_indices: U256,
    railgun_txid_merkle_proof_path_elements: Vec<U256>,
}

impl PreTransactionPoiChunkInputs {
    pub fn proof_inputs(
        &self,
        merkle_proofs: &[PoiMerkleProof],
    ) -> Result<PoiProofInputs, PreTransactionPoiError> {
        if merkle_proofs.len() != self.blinded_commitments_in.len() {
            return Err(PreTransactionPoiError::MerkleProofCountMismatch {
                expected: self.blinded_commitments_in.len(),
                got: merkle_proofs.len(),
            });
        }

        let mut poi_merkleroots = Vec::with_capacity(merkle_proofs.len());
        let mut poi_in_merkle_proof_indices = Vec::with_capacity(merkle_proofs.len());
        let mut poi_in_merkle_proof_path_elements = Vec::with_capacity(merkle_proofs.len());

        for (index, proof) in merkle_proofs.iter().enumerate() {
            let leaf = parse_fixed_hex(&proof.leaf, "leaf")?;
            let expected = self.blinded_commitments_in[index];
            if leaf != expected {
                return Err(PreTransactionPoiError::MerkleProofLeafMismatch {
                    index,
                    expected,
                    actual: leaf,
                });
            }
            if proof.elements.len() != merkletree::tree::TREE_DEPTH {
                return Err(PreTransactionPoiError::MerkleProofPathLengthMismatch {
                    index,
                    expected: merkletree::tree::TREE_DEPTH,
                    got: proof.elements.len(),
                });
            }
            poi_merkleroots.push(parse_u256_hex(&proof.root, "root")?);
            poi_in_merkle_proof_indices.push(parse_u256_hex(&proof.indices, "indices")?);
            poi_in_merkle_proof_path_elements.push(
                proof
                    .elements
                    .iter()
                    .map(|element| parse_u256_hex(element, "elements"))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(PoiProofInputs {
            any_railgun_txid_merkleroot_after_transaction: self
                .proof_base_inputs
                .any_railgun_txid_merkleroot_after_transaction,
            bound_params_hash: self.proof_base_inputs.bound_params_hash,
            nullifiers: self.proof_base_inputs.nullifiers.clone(),
            commitments_out: self.proof_base_inputs.commitments_out.clone(),
            spending_public_key: self.proof_base_inputs.spending_public_key,
            nullifying_key: self.proof_base_inputs.nullifying_key,
            token: self.proof_base_inputs.token,
            randoms_in: self.proof_base_inputs.randoms_in.clone(),
            values_in: self.proof_base_inputs.values_in.clone(),
            utxo_positions_in: self.proof_base_inputs.utxo_positions_in.clone(),
            utxo_tree_in: self.proof_base_inputs.utxo_tree_in,
            npks_out: self.proof_base_inputs.npks_out.clone(),
            values_out: self.proof_base_inputs.values_out.clone(),
            utxo_batch_global_start_position_out: self
                .proof_base_inputs
                .utxo_batch_global_start_position_out,
            railgun_txid_if_has_unshield: self.proof_base_inputs.railgun_txid_if_has_unshield,
            railgun_txid_merkle_proof_indices: self
                .proof_base_inputs
                .railgun_txid_merkle_proof_indices,
            railgun_txid_merkle_proof_path_elements: self
                .proof_base_inputs
                .railgun_txid_merkle_proof_path_elements
                .clone(),
            poi_merkleroots,
            poi_in_merkle_proof_indices,
            poi_in_merkle_proof_path_elements,
        })
    }

    #[must_use]
    pub fn pre_tx_poi(&self, snark_proof: SnarkJsProof, proof_inputs: &PoiProofInputs) -> PreTxPoi {
        PreTxPoi {
            snark_proof,
            txid_merkleroot: self.txid_merkleroot,
            poi_merkleroots: proof_inputs
                .poi_merkleroots
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            blinded_commitments_out: self.blinded_commitments_out.clone(),
            railgun_txid_if_has_unshield: self.railgun_txid_if_has_unshield.clone(),
        }
    }

    pub fn post_tx_poi_from_public_signals(
        &self,
        snark_proof: SnarkJsProof,
        proof_inputs: &PoiProofInputs,
        public_signals: &[U256],
        variant: PoiCircuitVariant,
    ) -> Result<PreTxPoi, PreTransactionPoiError> {
        let expected_len = variant.max_outputs + 2 + variant.max_inputs;
        if public_signals.len() != expected_len {
            return Err(PreTransactionPoiError::PublicSignalCountMismatch {
                expected: expected_len,
                got: public_signals.len(),
            });
        }

        let mut expected_blinded_commitments_out = self.blinded_commitments_out.clone();
        expected_blinded_commitments_out.resize(variant.max_outputs, FixedBytes::ZERO);
        for (index, expected) in expected_blinded_commitments_out.iter().enumerate() {
            validate_public_signal(
                "blindedCommitmentsOut",
                FixedBytes::from(public_signals[index].to_be_bytes::<32>()),
                *expected,
            )?;
        }

        let txid_merkleroot =
            FixedBytes::from(public_signals[variant.max_outputs].to_be_bytes::<32>());
        let expected_txid_merkleroot = FixedBytes::from(
            self.proof_base_inputs
                .any_railgun_txid_merkleroot_after_transaction
                .to_be_bytes::<32>(),
        );
        validate_public_signal("txidMerkleroot", txid_merkleroot, expected_txid_merkleroot)?;

        let railgun_txid_if_has_unshield = public_signals[variant.max_outputs + 1];
        validate_public_signal(
            "railgunTxidIfHasUnshield",
            FixedBytes::from(railgun_txid_if_has_unshield.to_be_bytes::<32>()),
            FixedBytes::from(
                self.proof_base_inputs
                    .railgun_txid_if_has_unshield
                    .to_be_bytes::<32>(),
            ),
        )?;

        let poi_merkleroots_start = variant.max_outputs + 2;
        let mut expected_poi_merkleroots = proof_inputs.poi_merkleroots.clone();
        expected_poi_merkleroots.resize(variant.max_inputs, MERKLE_ZERO_VALUE);
        for (index, expected) in expected_poi_merkleroots.iter().enumerate() {
            let actual = public_signals[poi_merkleroots_start + index];
            validate_public_signal(
                "poiMerkleroots",
                FixedBytes::from(actual.to_be_bytes::<32>()),
                FixedBytes::from(expected.to_be_bytes::<32>()),
            )?;
        }

        let railgun_txid_if_has_unshield = if railgun_txid_if_has_unshield == U256::ZERO {
            Bytes::copy_from_slice(&[0_u8])
        } else {
            Bytes::copy_from_slice(&railgun_txid_if_has_unshield.to_be_bytes::<32>())
        };

        Ok(PreTxPoi {
            snark_proof,
            txid_merkleroot,
            poi_merkleroots: proof_inputs
                .poi_merkleroots
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            blinded_commitments_out: public_signals[..self.blinded_commitments_out.len()]
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            railgun_txid_if_has_unshield,
        })
    }
}

pub fn pre_transaction_poi_inputs_from_chunk(
    chunk: &TransactionPlanChunk,
) -> Result<PreTransactionPoiChunkInputs, PreTransactionPoiError> {
    if chunk.inputs.len() != chunk.public_inputs.nullifiers.len() {
        return Err(PreTransactionPoiError::InputCountMismatch {
            expected: chunk.public_inputs.nullifiers.len(),
            got: chunk.inputs.len(),
        });
    }

    let private_output_count = if chunk.has_unshield {
        chunk
            .public_inputs
            .commitments_out
            .len()
            .checked_sub(1)
            .ok_or(PreTransactionPoiError::MissingPrivateOutputBeforeUnshield)?
    } else {
        chunk.public_inputs.commitments_out.len()
    };
    if chunk.private_inputs.npk_out.len() < private_output_count
        || chunk.private_inputs.value_out.len() < private_output_count
    {
        return Err(PreTransactionPoiError::OutputCountMismatch {
            expected: private_output_count,
            got: chunk
                .private_inputs
                .npk_out
                .len()
                .min(chunk.private_inputs.value_out.len()),
        });
    }

    let railgun_txid = compute_railgun_txid_from_public_inputs(&chunk.public_inputs);
    let txid_leaf = railgun_txid_leaf_hash(railgun_txid, u64::from(chunk.tree_number));
    let txid_merkleroot = dummy_txid_root(txid_leaf);
    let railgun_txid_if_has_unshield = if chunk.has_unshield {
        Bytes::copy_from_slice(&railgun_txid.to_be_bytes::<32>())
    } else {
        Bytes::copy_from_slice(&[0_u8])
    };
    let railgun_txid_if_has_unshield_value = if chunk.has_unshield {
        railgun_txid
    } else {
        U256::ZERO
    };

    let blinded_commitments_in = chunk
        .inputs
        .iter()
        .map(|input| input.utxo.poi.blinded_commitment)
        .collect::<Vec<_>>();
    let blinded_commitments_out = chunk
        .public_inputs
        .commitments_out
        .iter()
        .take(private_output_count)
        .zip(
            chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count),
        )
        .enumerate()
        .map(|(index, (commitment, npk))| {
            let global_position = pre_transaction_output_global_position() + U256::from(index);
            poseidon(vec![*commitment, *npk, global_position]).into()
        })
        .collect::<Vec<_>>();

    Ok(PreTransactionPoiChunkInputs {
        txid_leaf_hash: FixedBytes::from(txid_leaf.to_be_bytes::<32>()),
        txid_merkleroot: FixedBytes::from(txid_merkleroot.to_be_bytes::<32>()),
        blinded_commitments_in,
        blinded_commitments_out,
        railgun_txid_if_has_unshield,
        proof_base_inputs: PoiProofBaseInputs {
            any_railgun_txid_merkleroot_after_transaction: txid_merkleroot,
            bound_params_hash: chunk.public_inputs.bound_params_hash,
            nullifiers: chunk.public_inputs.nullifiers.clone(),
            commitments_out: chunk.public_inputs.commitments_out.clone(),
            spending_public_key: chunk.private_inputs.public_key,
            nullifying_key: chunk.private_inputs.nullifying_key,
            token: chunk.private_inputs.token_address,
            randoms_in: chunk.private_inputs.random_in.clone(),
            values_in: chunk.private_inputs.value_in.clone(),
            utxo_positions_in: chunk.private_inputs.leaves_indices.clone(),
            utxo_tree_in: U256::from(chunk.tree_number),
            npks_out: chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count)
                .copied()
                .collect(),
            values_out: chunk
                .private_inputs
                .value_out
                .iter()
                .take(private_output_count)
                .copied()
                .collect(),
            utxo_batch_global_start_position_out: pre_transaction_output_global_position(),
            railgun_txid_if_has_unshield: railgun_txid_if_has_unshield_value,
            railgun_txid_merkle_proof_indices: U256::ZERO,
            railgun_txid_merkle_proof_path_elements: vec![U256::ZERO; merkletree::tree::TREE_DEPTH],
        },
    })
}

pub fn post_transaction_poi_inputs_from_chunk(
    chunk: &TransactionPlanChunk,
    txid_data: &PostTransactionPoiData,
) -> Result<PreTransactionPoiChunkInputs, PreTransactionPoiError> {
    if chunk.inputs.len() != chunk.public_inputs.nullifiers.len() {
        return Err(PreTransactionPoiError::InputCountMismatch {
            expected: chunk.public_inputs.nullifiers.len(),
            got: chunk.inputs.len(),
        });
    }
    if txid_data.txid_merkle_proof_path_elements.len() != merkletree::tree::TREE_DEPTH {
        return Err(PreTransactionPoiError::TxidMerkleProofPathLengthMismatch {
            expected: merkletree::tree::TREE_DEPTH,
            got: txid_data.txid_merkle_proof_path_elements.len(),
        });
    }

    let private_output_count = if chunk.has_unshield {
        chunk
            .public_inputs
            .commitments_out
            .len()
            .checked_sub(1)
            .ok_or(PreTransactionPoiError::MissingPrivateOutputBeforeUnshield)?
    } else {
        chunk.public_inputs.commitments_out.len()
    };
    if chunk.private_inputs.npk_out.len() < private_output_count
        || chunk.private_inputs.value_out.len() < private_output_count
    {
        return Err(PreTransactionPoiError::OutputCountMismatch {
            expected: private_output_count,
            got: chunk
                .private_inputs
                .npk_out
                .len()
                .min(chunk.private_inputs.value_out.len()),
        });
    }

    let railgun_txid = compute_railgun_txid_from_public_inputs(&chunk.public_inputs);
    let expected_txid_leaf = poseidon(vec![
        railgun_txid,
        U256::from(chunk.tree_number),
        txid_data.utxo_batch_global_start_position_out,
    ]);
    let expected_txid_leaf_hash = FixedBytes::from(expected_txid_leaf.to_be_bytes::<32>());
    if expected_txid_leaf_hash != txid_data.txid_leaf_hash {
        return Err(PreTransactionPoiError::TxidLeafHashMismatch {
            expected: expected_txid_leaf_hash,
            actual: txid_data.txid_leaf_hash,
        });
    }

    let railgun_txid_if_has_unshield = if chunk.has_unshield {
        Bytes::copy_from_slice(&railgun_txid.to_be_bytes::<32>())
    } else {
        Bytes::copy_from_slice(&[0_u8])
    };
    let railgun_txid_if_has_unshield_value = if chunk.has_unshield {
        railgun_txid
    } else {
        U256::ZERO
    };

    let blinded_commitments_in = chunk
        .inputs
        .iter()
        .map(|input| input.utxo.poi.blinded_commitment)
        .collect::<Vec<_>>();
    let blinded_commitments_out = chunk
        .public_inputs
        .commitments_out
        .iter()
        .take(private_output_count)
        .zip(
            chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count),
        )
        .zip(
            chunk
                .private_inputs
                .value_out
                .iter()
                .take(private_output_count),
        )
        .enumerate()
        .map(|(index, ((commitment, npk), value))| {
            if *value == U256::ZERO {
                FixedBytes::ZERO
            } else {
                let global_position =
                    txid_data.utxo_batch_global_start_position_out + U256::from(index);
                poseidon(vec![*commitment, *npk, global_position]).into()
            }
        })
        .collect::<Vec<_>>();

    Ok(PreTransactionPoiChunkInputs {
        txid_leaf_hash: txid_data.txid_leaf_hash,
        txid_merkleroot: txid_data.txid_merkleroot,
        blinded_commitments_in,
        blinded_commitments_out,
        railgun_txid_if_has_unshield,
        proof_base_inputs: PoiProofBaseInputs {
            any_railgun_txid_merkleroot_after_transaction: U256::from_be_bytes(
                txid_data.txid_merkleroot.0,
            ),
            bound_params_hash: chunk.public_inputs.bound_params_hash,
            nullifiers: chunk.public_inputs.nullifiers.clone(),
            commitments_out: chunk.public_inputs.commitments_out.clone(),
            spending_public_key: chunk.private_inputs.public_key,
            nullifying_key: chunk.private_inputs.nullifying_key,
            token: chunk.private_inputs.token_address,
            randoms_in: chunk.private_inputs.random_in.clone(),
            values_in: chunk.private_inputs.value_in.clone(),
            utxo_positions_in: chunk.private_inputs.leaves_indices.clone(),
            utxo_tree_in: U256::from(chunk.tree_number),
            npks_out: chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count)
                .copied()
                .collect(),
            values_out: chunk
                .private_inputs
                .value_out
                .iter()
                .take(private_output_count)
                .copied()
                .collect(),
            utxo_batch_global_start_position_out: txid_data.utxo_batch_global_start_position_out,
            railgun_txid_if_has_unshield: railgun_txid_if_has_unshield_value,
            railgun_txid_merkle_proof_indices: txid_data.txid_merkle_proof_indices,
            railgun_txid_merkle_proof_path_elements: txid_data
                .txid_merkle_proof_path_elements
                .clone(),
        },
    })
}

pub struct PreTransactionPoiGenerationRequest<'a> {
    pub chunks: &'a [TransactionPlanChunk],
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: Option<&'a str>,
    pub required_poi_list_keys: &'a [FixedBytes<32>],
    pub poi_client: &'a PoiRpcClient,
    pub prover: &'a ProverService,
    pub verify_proof: bool,
}

pub async fn generate_pre_transaction_pois(
    request: PreTransactionPoiGenerationRequest<'_>,
) -> Result<PreTransactionPoiMap, PreTransactionPoiError> {
    let mut map = BTreeMap::new();
    if request.required_poi_list_keys.is_empty() {
        return Ok(map);
    }
    let txid_version = request.txid_version.unwrap_or(DEFAULT_TXID_VERSION);
    for chunk in request.chunks {
        let chunk_inputs = pre_transaction_poi_inputs_from_chunk(chunk)?;
        for list_key in request.required_poi_list_keys {
            let merkle_started = Instant::now();
            let merkle_proofs = request
                .poi_client
                .poi_merkle_proofs(
                    txid_version,
                    request.chain_type,
                    request.chain_id,
                    list_key,
                    &chunk_inputs.blinded_commitments_in,
                )
                .await?;
            let merkle_elapsed_ms = merkle_started.elapsed().as_millis();
            let proof_inputs = chunk_inputs.proof_inputs(&merkle_proofs)?;
            let prove_started = Instant::now();
            let snark_proof = request
                .prover
                .prove_poi(&proof_inputs, request.verify_proof)
                .await?;
            let prove_elapsed_ms = prove_started.elapsed().as_millis();
            tracing::debug!(
                chain_type = request.chain_type,
                chain_id = request.chain_id,
                tree_number = chunk.tree_number,
                input_count = chunk.inputs.len(),
                output_count = chunk.outputs.len(),
                has_unshield = chunk.has_unshield,
                list_key = %hex::encode(list_key),
                merkle_elapsed_ms,
                prove_elapsed_ms,
                "generated pre-transaction POI proof"
            );
            let pre_tx_poi = chunk_inputs.pre_tx_poi(snark_proof, &proof_inputs);
            insert_pre_transaction_poi(
                &mut map,
                *list_key,
                chunk_inputs.txid_leaf_hash,
                pre_tx_poi,
            );
        }
    }
    Ok(map)
}

pub struct PostTransactionPoiGenerationRequest<'a> {
    pub chunk: &'a TransactionPlanChunk,
    pub txid_data: &'a PostTransactionPoiData,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: Option<&'a str>,
    pub required_poi_list_keys: &'a [FixedBytes<32>],
    pub poi_client: &'a PoiRpcClient,
    pub prover: &'a ProverService,
    pub verify_proof: bool,
}

pub async fn generate_post_transaction_pois(
    request: PostTransactionPoiGenerationRequest<'_>,
) -> Result<PreTransactionPoiMap, PreTransactionPoiError> {
    let mut map = BTreeMap::new();
    if request.required_poi_list_keys.is_empty() {
        return Ok(map);
    }
    let txid_version = request.txid_version.unwrap_or(DEFAULT_TXID_VERSION);
    let chunk_inputs = post_transaction_poi_inputs_from_chunk(request.chunk, request.txid_data)?;
    for list_key in request.required_poi_list_keys {
        let merkle_started = Instant::now();
        let merkle_proofs = request
            .poi_client
            .poi_merkle_proofs(
                txid_version,
                request.chain_type,
                request.chain_id,
                list_key,
                &chunk_inputs.blinded_commitments_in,
            )
            .await?;
        let merkle_elapsed_ms = merkle_started.elapsed().as_millis();
        let proof_inputs = chunk_inputs.proof_inputs(&merkle_proofs)?;
        let variant = poi_circuit_variant(
            request.chunk.public_inputs.nullifiers.len(),
            request.chunk.public_inputs.commitments_out.len(),
        );
        let prove_started = Instant::now();
        let proof_result = request
            .prover
            .prove_poi_with_public_signals(&proof_inputs, request.verify_proof)
            .await?;
        let prove_elapsed_ms = prove_started.elapsed().as_millis();
        tracing::debug!(
            chain_type = request.chain_type,
            chain_id = request.chain_id,
            tree_number = request.chunk.tree_number,
            input_count = request.chunk.inputs.len(),
            output_count = request.chunk.outputs.len(),
            has_unshield = request.chunk.has_unshield,
            list_key = %hex::encode(list_key),
            txid_merkleroot_index = request.txid_data.txid_merkleroot_index,
            merkle_elapsed_ms,
            prove_elapsed_ms,
            "generated post-transaction POI proof"
        );
        let pre_tx_poi = chunk_inputs.post_tx_poi_from_public_signals(
            proof_result.snark_proof,
            &proof_inputs,
            &proof_result.public_signals,
            variant,
        )?;
        insert_pre_transaction_poi(&mut map, *list_key, chunk_inputs.txid_leaf_hash, pre_tx_poi);
    }
    Ok(map)
}

pub fn insert_pre_transaction_poi(
    map: &mut PreTransactionPoiMap,
    list_key: FixedBytes<32>,
    txid_leaf_hash: FixedBytes<32>,
    pre_tx_poi: PreTxPoi,
) {
    map.entry(list_key)
        .or_default()
        .insert(txid_leaf_hash, pre_tx_poi);
}

fn compute_railgun_txid_from_public_inputs(public_inputs: &PublicInputs) -> U256 {
    let nullifiers_hash = poseidon(pad_with_merkle_zero(public_inputs.nullifiers.clone(), 13));
    let commitments_hash = poseidon(pad_with_merkle_zero(
        public_inputs.commitments_out.clone(),
        13,
    ));
    poseidon(vec![
        nullifiers_hash,
        commitments_hash,
        public_inputs.bound_params_hash,
    ])
}

fn pre_transaction_output_global_position() -> U256 {
    const PRE_TRANSACTION_POI_TREE: U256 = uint!(199_999_U256);
    const PRE_TRANSACTION_POI_POSITION: U256 = uint!(199_999_U256);

    PRE_TRANSACTION_POI_TREE * merkletree::tree::TREE_LEAF_COUNT_U256 + PRE_TRANSACTION_POI_POSITION
}

fn validate_public_signal(
    field: &'static str,
    actual: FixedBytes<32>,
    expected: FixedBytes<32>,
) -> Result<(), PreTransactionPoiError> {
    if actual != expected {
        return Err(PreTransactionPoiError::PublicSignalMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn parse_fixed_hex(
    value: &str,
    field: &'static str,
) -> Result<FixedBytes<32>, PreTransactionPoiError> {
    parse_u256_hex(value, field).map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
}

fn parse_u256_hex(value: &str, field: &'static str) -> Result<U256, PreTransactionPoiError> {
    let value_without_prefix = value.strip_prefix("0x").unwrap_or(value);
    if value_without_prefix.len() > 64 {
        return Err(PreTransactionPoiError::InvalidHex {
            field,
            value: value.to_string(),
        });
    }
    let padded = format!("{value_without_prefix:0>64}");
    let bytes = hex::decode(padded).map_err(|_| PreTransactionPoiError::InvalidHex {
        field,
        value: value.to_string(),
    })?;
    Ok(U256::from_be_slice(&bytes))
}

#[derive(Debug, Clone, Copy)]
pub enum UnshieldMode {
    Token,
    UnwrapBase,
}

#[derive(Debug, Clone, Copy)]
pub struct BroadcasterFeeOutput {
    pub recipient: AddressData,
    pub amount: U256,
}

#[derive(Debug, Clone, Copy)]
pub struct UnshieldRequest {
    pub token_address: Address,
    pub amount: U256,
    pub recipient: Address,
    pub mode: UnshieldMode,
    pub verify_proof: bool,
    pub spend_up_to: bool,
    pub broadcaster_fee: Option<BroadcasterFeeOutput>,
    pub min_gas_price: u128,
}

#[derive(Debug, Clone, Copy)]
pub struct SendRequest {
    pub token_address: Address,
    pub amount: U256,
    pub recipient: AddressData,
    pub verify_proof: bool,
    pub spend_up_to: bool,
    pub broadcaster_fee: Option<BroadcasterFeeOutput>,
    pub min_gas_price: u128,
}

impl UnshieldRequest {
    fn fee_amount(self) -> U256 {
        self.broadcaster_fee.map_or(U256::ZERO, |fee| fee.amount)
    }

    fn target_amount(self) -> U256 {
        self.amount + self.fee_amount()
    }

    fn base_output_count(self) -> usize {
        1 + usize::from(self.broadcaster_fee.is_some())
    }
}

impl SendRequest {
    fn fee_amount(self) -> U256 {
        self.broadcaster_fee.map_or(U256::ZERO, |fee| fee.amount)
    }

    fn target_amount(self) -> U256 {
        self.amount + self.fee_amount()
    }

    fn base_output_count(self) -> usize {
        1 + usize::from(self.broadcaster_fee.is_some())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnshieldSelectionInfo {
    pub total: U256,
    pub input_count: usize,
    pub transaction_count: usize,
    pub private_output_count: usize,
    pub public_output_count: usize,
    pub max_spendable: U256,
}

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    pub chain_type: u8,
    pub chain_id: u64,
    pub railgun_contract: Address,
    pub relay_adapt_contract: Address,
}

impl TransactionBuilder {
    /// Build an unshield plan using token selection from available UTXOs.
    pub async fn build_unshield_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        self.build_unshield_plan_with_signer(
            &wallet.viewing,
            wallet,
            forest,
            utxos,
            request,
            prover,
        )
        .await
    }

    /// Build an unshield plan using externally scoped viewing data and spend signer.
    pub async fn build_unshield_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        let selection = select_batched_utxos(
            utxos,
            request.token_address,
            request.target_amount(),
            request.spend_up_to,
            request.base_output_count(),
            1,
        )?;

        self.build_unshield_batch_with_signer(viewing, signer, forest, selection, request, prover)
            .await
    }

    /// Build a private send plan using token selection from available UTXOs.
    pub async fn build_send_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        self.build_send_plan_with_signer(&wallet.viewing, wallet, forest, utxos, request, prover)
            .await
    }

    /// Build a private send plan using externally scoped viewing data and spend signer.
    pub async fn build_send_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        let selection = select_batched_utxos(
            utxos,
            request.token_address,
            request.target_amount(),
            request.spend_up_to,
            request.base_output_count(),
            1,
        )?;

        self.build_send_batch_with_signer(viewing, signer, forest, selection, request, prover)
            .await
    }

    async fn build_unshield_batch_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        selection: BatchUtxoSelection,
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.broadcaster_fee,
            request.spend_up_to,
        )?;
        let receiver = viewing.address_data();
        let unshield_to = match request.mode {
            UnshieldMode::Token => request.recipient,
            UnshieldMode::UnwrapBase => self.relay_adapt_contract,
        };

        let mut unproven_plans = Vec::with_capacity(selection.chunks.len());
        let mut broadcaster_fee_note = None;
        let mut unshield_notes = Vec::with_capacity(selection.chunks.len());
        let mut change_note = None;

        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                prover,
                chunk.utxos,
                request.token_address,
            )?;
            let UnshieldOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: chunk_fee_note,
                unshield_note,
                change_note: chunk_change_note,
            } = build_unshield_outputs(
                request.token_address,
                allocation.amount,
                unshield_to,
                allocation.change,
                &receiver,
                allocation.fee,
                &viewing.viewing_private_key,
            )?;
            if broadcaster_fee_note.is_none() {
                broadcaster_fee_note = chunk_fee_note;
            }
            if chunk_change_note.is_some() {
                change_note = chunk_change_note.clone();
            }
            unshield_notes.push(unshield_note);
            unproven_plans.push(plan_builder.build_unproven_unshield(
                request,
                outputs,
                commitment_ciphertext,
                unshield_notes.last().expect("pushed unshield note"),
            )?);
        }

        let action_data = if matches!(request.mode, UnshieldMode::UnwrapBase) {
            let random = FixedBytes::<31>::from(rand_array());
            Some(ActionData::unwrap_base(
                self.relay_adapt_contract,
                request.recipient,
                random,
                true,
            ))
        } else {
            None
        };
        if let Some(action_data) = action_data.as_ref() {
            let transactions = unproven_plans
                .iter()
                .map(|plan| &plan.transaction)
                .collect::<Vec<_>>();
            let adapt_params = action_data.adapt_params(&transactions);
            for plan in &mut unproven_plans {
                plan.transaction.boundParams.adaptContract = self.relay_adapt_contract;
                plan.transaction.boundParams.adaptParams = adapt_params;
            }
        }

        let mut transactions = Vec::with_capacity(unproven_plans.len());
        let mut chunks = Vec::with_capacity(unproven_plans.len());
        for plan in unproven_plans {
            let proven = prove_transaction_plan(plan, signer, prover, request.verify_proof).await?;
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let first_chunk = chunks
            .first()
            .expect("selection has at least one chunk")
            .clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let unshield_note = unshield_notes
            .first()
            .expect("selection has at least one chunk")
            .clone();

        let call = if matches!(request.mode, UnshieldMode::UnwrapBase) {
            let action_data = action_data.ok_or(BuildError::MissingActionData)?;
            let data = relayCall {
                _transactions: transactions,
                _actionData: action_data,
            }
            .abi_encode();
            TransactionCall {
                to: self.relay_adapt_contract,
                data: data.into(),
            }
        } else {
            let data = transactCall {
                _transactions: transactions,
            }
            .abi_encode();
            TransactionCall {
                to: self.railgun_contract,
                data: data.into(),
            }
        };

        Ok(UnshieldPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note,
            unshield_note,
            unshield_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    async fn build_send_batch_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        selection: BatchUtxoSelection,
        request: SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.broadcaster_fee,
            request.spend_up_to,
        )?;
        let sender = viewing.address_data();
        let mut unproven_plans = Vec::with_capacity(selection.chunks.len());
        let mut broadcaster_fee_note = None;
        let mut recipient_notes = Vec::with_capacity(selection.chunks.len());
        let mut change_note = None;

        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                prover,
                chunk.utxos,
                request.token_address,
            )?;
            let SendOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: chunk_fee_note,
                recipient_note,
                change_note: chunk_change_note,
            } = build_send_outputs(
                request.token_address,
                allocation.amount,
                allocation.change,
                &sender,
                &request.recipient,
                allocation.fee,
                &viewing.viewing_private_key,
            )?;
            if broadcaster_fee_note.is_none() {
                broadcaster_fee_note = chunk_fee_note;
            }
            if chunk_change_note.is_some() {
                change_note = chunk_change_note.clone();
            }
            recipient_notes.push(recipient_note);
            unproven_plans.push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
            )?);
        }

        let mut transactions = Vec::with_capacity(unproven_plans.len());
        let mut chunks = Vec::with_capacity(unproven_plans.len());
        for plan in unproven_plans {
            let proven = prove_transaction_plan(plan, signer, prover, request.verify_proof).await?;
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let first_chunk = chunks
            .first()
            .expect("selection has at least one chunk")
            .clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let recipient_note = recipient_notes
            .first()
            .expect("selection has at least one chunk")
            .clone();

        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };

        Ok(SendPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note,
            recipient_note,
            recipient_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    /// Build a transact plan for UTXO consolidation.
    pub async fn build_transact_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        inputs: &[Utxo],
        token_address: Address,
        prover: &ProverService,
    ) -> Result<TransactPlan, BuildError> {
        let plan_builder = TransactionPlanBuilder::new(
            self,
            &wallet.viewing,
            wallet,
            forest,
            prover,
            inputs.to_vec(),
            token_address,
        )?;

        plan_builder.build_transact().await
    }
}

/// Builder for constructing Railgun transaction plans.
struct TransactionPlanBuilder<'a, S: RailgunSpendSigner> {
    builder: &'a TransactionBuilder,
    viewing: &'a ViewingKeyData,
    signer: &'a S,
    forest: &'a MerkleForest,
    prover: &'a ProverService,
    inputs: Vec<Utxo>,
    token_address: Address,
}

struct UnprovenTransactionPlan {
    transaction: Transaction,
    tree_number: u32,
    merkle_root: U256,
    inputs: Vec<InputWitness>,
    outputs: Vec<Note>,
    has_unshield: bool,
    private_inputs: PrivateInputs,
}

struct ProvenTransactionPlan {
    transaction: Transaction,
    chunk: TransactionPlanChunk,
}

#[derive(Debug, Clone, Copy)]
struct SpendAllocation {
    amount: U256,
    change: U256,
    fee: Option<BroadcasterFeeOutput>,
}

impl<'a, S: RailgunSpendSigner> TransactionPlanBuilder<'a, S> {
    /// Create a new builder with validated inputs.
    fn new(
        builder: &'a TransactionBuilder,
        viewing: &'a ViewingKeyData,
        signer: &'a S,
        forest: &'a MerkleForest,
        prover: &'a ProverService,
        inputs: Vec<Utxo>,
        token_address: Address,
    ) -> Result<Self, BuildError> {
        if inputs.is_empty() {
            return Err(BuildError::InsufficientBalance(U256::ZERO));
        }
        if inputs.len() > MAX_CIRCUIT_INPUTS {
            return Err(BuildError::TooManyInputs);
        }

        let tree_number = inputs[0].tree;
        if inputs.iter().any(|utxo| utxo.tree != tree_number) {
            return Err(BuildError::MixedTrees);
        }

        let token_hash = U256::from_be_slice(token_address.as_slice());
        if inputs.iter().any(|utxo| utxo.note.token_hash != token_hash) {
            return Err(BuildError::TokenMismatch);
        }

        Ok(Self {
            builder,
            viewing,
            signer,
            forest,
            prover,
            inputs,
            token_address,
        })
    }

    #[must_use]
    fn tree_number(&self) -> u32 {
        self.inputs[0].tree
    }

    /// Get the total value of all inputs.
    #[must_use]
    fn total_value(&self) -> U256 {
        self.inputs
            .iter()
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value)
    }

    /// Get the merkle root for the input tree.
    fn get_root(&self) -> Result<U256, BuildError> {
        self.forest
            .roots()
            .get(&self.tree_number())
            .copied()
            .ok_or(BuildError::MissingRoot)
    }

    /// Compute nullifiers for all inputs.
    fn compute_nullifiers(&self) -> Vec<FixedBytes<32>> {
        self.inputs
            .iter()
            .map(|utxo| {
                FixedBytes::from(
                    utxo.nullifier(self.viewing.nullifying_key)
                        .to_be_bytes::<32>(),
                )
            })
            .collect()
    }

    /// Build input witnesses with merkle proofs.
    fn build_input_witnesses(&self) -> Result<Vec<InputWitness>, BuildError> {
        self.inputs
            .par_iter()
            .map(|utxo| {
                self.forest
                    .prove(utxo.tree, utxo.position)
                    .ok_or(BuildError::MissingProof {
                        tree: utxo.tree,
                        position: utxo.position,
                    })
                    .map(|proof| InputWitness {
                        utxo: utxo.clone(),
                        merkle_proof: proof,
                    })
            })
            .collect()
    }

    /// Validate that the total signature inputs don't exceed the limit.
    fn validate_signature_limit(&self, num_outputs: usize) -> Result<(), BuildError> {
        let signature_input_len = 2 + self.inputs.len() + num_outputs;
        if signature_input_len > MAX_SIGNATURE_INPUTS {
            return Err(BuildError::SignatureInputLimit {
                inputs: self.inputs.len(),
                outputs: num_outputs,
            });
        }
        Ok(())
    }

    /// Compute output commitments as fixed bytes.
    fn compute_commitments(outputs: &[Note]) -> Vec<FixedBytes<32>> {
        outputs
            .iter()
            .map(|note| FixedBytes::from(note.commitment().to_be_bytes::<32>()))
            .collect()
    }

    fn build_unproven_unshield(
        self,
        request: UnshieldRequest,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
        unshield_note: &Note,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let root = self.get_root()?;
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext = commitment_ciphertext
            .into_iter()
            .map(NoteCiphertext::into_commitment_ciphertext)
            .collect();
        let bound_params = BoundParams::new_unshield(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        )
        .with_min_gas_price(request.min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::new_unshield(
                unshield_note,
                request.token_address,
            ),
        };
        let inputs = self.build_input_witnesses()?;
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );

        Ok(UnprovenTransactionPlan {
            transaction,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            has_unshield: true,
            private_inputs,
        })
    }

    fn build_unproven_send(
        self,
        request: SendRequest,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let root = self.get_root()?;
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext = commitment_ciphertext
            .into_iter()
            .map(NoteCiphertext::into_commitment_ciphertext)
            .collect();
        let bound_params = BoundParams::new_transact(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        )
        .with_min_gas_price(request.min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };
        let inputs = self.build_input_witnesses()?;
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );

        Ok(UnprovenTransactionPlan {
            transaction,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            has_unshield: false,
            private_inputs,
        })
    }

    /// Build a transact plan.
    async fn build_transact(self) -> Result<TransactPlan, BuildError> {
        let total = self.total_value();
        if total.is_zero() {
            return Err(BuildError::InsufficientBalance(total));
        }

        let receiver = self.viewing.address_data();
        let random = rand_array();
        let output = Note::new_change(
            receiver.master_public_key,
            self.token_address,
            total,
            random,
        );

        let ciphertext = NoteCiphertext::try_from_note(
            &output,
            &receiver,
            &receiver,
            &self.viewing.viewing_private_key,
        )?;

        let outputs = vec![output];
        let commitment_ciphertext = vec![ciphertext.into_commitment_ciphertext()];

        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let root = self.get_root()?;

        // Build transaction
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);

        let bound_params = BoundParams::new_transact(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        );

        let mut transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };

        // Build witnesses and inputs
        let inputs = self.build_input_witnesses()?;
        let public_inputs = PublicInputs::from_transaction(root, &transaction, &outputs);
        let private_inputs = PrivateInputs::from_inputs(
            self.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );
        let signature = public_inputs.signature(self.signer);

        let proof = self
            .prover
            .prove_unshield(&public_inputs, &private_inputs, &signature, true)
            .await?;
        transaction.proof = proof;

        // Build final call
        let data = transactCall {
            _transactions: vec![transaction],
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.builder.railgun_contract,
            data: data.into(),
        };

        Ok(TransactPlan {
            call,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            public_inputs,
            private_inputs,
            signature,
        })
    }
}

struct SendOutputs {
    outputs: Vec<Note>,
    commitment_ciphertext: Vec<NoteCiphertext>,
    broadcaster_fee_note: Option<Note>,
    recipient_note: Note,
    change_note: Option<Note>,
}

struct UnshieldOutputs {
    outputs: Vec<Note>,
    commitment_ciphertext: Vec<NoteCiphertext>,
    broadcaster_fee_note: Option<Note>,
    unshield_note: Note,
    change_note: Option<Note>,
}

trait BoundParamsExt {
    fn with_min_gas_price(self, min_gas_price: u128) -> Result<BoundParams, BuildError>;
}

impl BoundParamsExt for BoundParams {
    fn with_min_gas_price(mut self, min_gas_price: u128) -> Result<BoundParams, BuildError> {
        const MAX_UINT72: u128 = (1_u128 << 72) - 1;
        if min_gas_price > MAX_UINT72 {
            return Err(BuildError::MinGasPriceTooLarge(min_gas_price));
        }
        self.minGasPrice = Uint::<72, 2>::from(min_gas_price);
        Ok(self)
    }
}

fn spend_allocations(
    selection: &BatchUtxoSelection,
    requested_amount: U256,
    fee_amount: U256,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    spend_up_to: bool,
) -> Result<Vec<SpendAllocation>, BuildError> {
    if selection.total < fee_amount {
        return Err(BuildError::InsufficientBalance(selection.total));
    }
    let spendable_after_fee = selection.total - fee_amount;
    if !spend_up_to && spendable_after_fee < requested_amount {
        return Err(BuildError::InsufficientBalance(selection.total));
    }
    let amount = if spend_up_to {
        spendable_after_fee.min(requested_amount)
    } else {
        requested_amount
    };
    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(selection.total));
    }

    let mut remaining = amount;
    let mut allocations = Vec::with_capacity(selection.chunks.len());
    for (index, chunk) in selection.chunks.iter().enumerate() {
        let fee = if index == 0 { broadcaster_fee } else { None };
        let chunk_fee = fee.map_or(U256::ZERO, |fee| fee.amount);
        if chunk.total <= chunk_fee {
            return Err(BuildError::InsufficientBalance(selection.total));
        }
        let spendable = chunk.total - chunk_fee;
        let amount = spendable.min(remaining);
        if amount.is_zero() {
            return Err(BuildError::InsufficientBalance(selection.total));
        }
        let change = spendable - amount;
        remaining -= amount;
        allocations.push(SpendAllocation {
            amount,
            change,
            fee,
        });
    }

    if remaining.is_zero() {
        Ok(allocations)
    } else {
        Err(BuildError::InsufficientBalance(selection.total))
    }
}

async fn prove_transaction_plan(
    mut plan: UnprovenTransactionPlan,
    signer: &impl RailgunSpendSigner,
    prover: &ProverService,
    verify_proof: bool,
) -> Result<ProvenTransactionPlan, BuildError> {
    let public_inputs =
        PublicInputs::from_transaction(plan.merkle_root, &plan.transaction, &plan.outputs);
    let signature = public_inputs.signature(signer);
    let proof = prover
        .prove_unshield(
            &public_inputs,
            &plan.private_inputs,
            &signature,
            verify_proof,
        )
        .await?;
    plan.transaction.proof = proof;
    let chunk = TransactionPlanChunk {
        tree_number: plan.tree_number,
        merkle_root: plan.merkle_root,
        inputs: plan.inputs,
        outputs: plan.outputs,
        has_unshield: plan.has_unshield,
        public_inputs,
        private_inputs: plan.private_inputs,
        signature,
    };
    Ok(ProvenTransactionPlan {
        transaction: plan.transaction,
        chunk,
    })
}

fn push_broadcaster_fee_output(
    outputs: &mut Vec<Note>,
    commitment_ciphertext: &mut Vec<NoteCiphertext>,
    token_address: Address,
    sender: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<Option<Note>, BuildError> {
    let Some(fee) = broadcaster_fee else {
        return Ok(None);
    };
    let note = Note::new_change(
        fee.recipient.master_public_key,
        token_address,
        fee.amount,
        rand_array(),
    );
    let ciphertext =
        NoteCiphertext::try_from_note(&note, sender, &fee.recipient, sender_viewing_private_key)?;
    outputs.push(note.clone());
    commitment_ciphertext.push(ciphertext);
    Ok(Some(note))
}

fn build_unshield_outputs(
    token_address: Address,
    unshield_amount: U256,
    unshield_to: Address,
    change: U256,
    receiver: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<UnshieldOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(broadcaster_fee.is_some()) + 1);
    let mut commitment_ciphertext = Vec::with_capacity(usize::from(broadcaster_fee.is_some()) + 1);
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        token_address,
        receiver,
        broadcaster_fee,
        sender_viewing_private_key,
    )?;

    let mut change_note = None;
    if !change.is_zero() {
        let note = Note::new_change(
            receiver.master_public_key,
            token_address,
            change,
            rand_array(),
        );
        let ciphertext =
            NoteCiphertext::try_from_note(&note, receiver, receiver, sender_viewing_private_key)?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        change_note = Some(note);
    }

    let unshield_note = Note::new_unshield(unshield_to, token_address, unshield_amount);
    outputs.push(unshield_note.clone());

    Ok(UnshieldOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        unshield_note,
        change_note,
    })
}

fn build_send_outputs(
    token_address: Address,
    send_amount: U256,
    change: U256,
    sender: &AddressData,
    recipient: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<SendOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(broadcaster_fee.is_some()) + 1);
    let mut commitment_ciphertext = Vec::with_capacity(outputs.capacity());
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        token_address,
        sender,
        broadcaster_fee,
        sender_viewing_private_key,
    )?;

    let recipient_note = Note::new_change(
        recipient.master_public_key,
        token_address,
        send_amount,
        rand_array(),
    );
    let recipient_ciphertext = NoteCiphertext::try_from_note(
        &recipient_note,
        sender,
        recipient,
        sender_viewing_private_key,
    )?;
    outputs.push(recipient_note.clone());
    commitment_ciphertext.push(recipient_ciphertext);

    let mut change_note = None;
    if !change.is_zero() {
        let note = Note::new_change(
            sender.master_public_key,
            token_address,
            change,
            rand_array(),
        );
        let ciphertext =
            NoteCiphertext::try_from_note(&note, sender, sender, sender_viewing_private_key)?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        change_note = Some(note);
    }

    Ok(SendOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        recipient_note,
        change_note,
    })
}

#[derive(Debug, Clone)]
struct UtxoSelection {
    utxos: Vec<Utxo>,
    total: U256,
}

#[derive(Debug, Clone)]
struct BatchUtxoSelection {
    chunks: Vec<UtxoSelection>,
    total: U256,
}

impl BatchUtxoSelection {
    #[must_use]
    fn input_count(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.utxos.len()).sum()
    }
}

#[must_use]
pub fn max_unshield_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_batch_spendable(utxos, token_address, 1, 1)
}

pub fn unshield_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let max_spendable = max_batch_spendable(utxos, token_address, 1, 1);
    let selection = select_batched_utxos(utxos, token_address, amount, spend_up_to, 1, 1)?;
    let shape = batch_shape(&selection, amount, U256::ZERO, false, false);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn unshield_selection_info_with_broadcaster_fee(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let target_amount = amount + fee_amount;
    let max_total = max_batch_spendable(utxos, token_address, 2, 1);
    let max_spendable = if max_total > fee_amount {
        max_total - fee_amount
    } else {
        U256::ZERO
    };
    let selection = select_batched_utxos(utxos, token_address, target_amount, spend_up_to, 2, 1)
        .map_err(|error| match error {
            BuildError::InsufficientBalance(_) => BuildError::InsufficientBalance(max_spendable),
            other => other,
        })?;
    let shape = batch_shape(&selection, amount, fee_amount, true, false);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

#[must_use]
pub fn max_send_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_batch_spendable(utxos, token_address, 1, 1)
}

pub fn send_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let max_spendable = max_batch_spendable(utxos, token_address, 1, 1);
    let selection = select_batched_utxos(utxos, token_address, amount, spend_up_to, 1, 1)?;
    let shape = batch_shape(&selection, amount, U256::ZERO, false, true);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn send_selection_info_with_broadcaster_fee(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let target_amount = amount + fee_amount;
    let max_total = max_batch_spendable(utxos, token_address, 2, 1);
    let max_spendable = if max_total > fee_amount {
        max_total - fee_amount
    } else {
        U256::ZERO
    };
    let selection = select_batched_utxos(utxos, token_address, target_amount, spend_up_to, 2, 1)
        .map_err(|error| match error {
            BuildError::InsufficientBalance(_) => BuildError::InsufficientBalance(max_spendable),
            other => other,
        })?;
    let shape = batch_shape(&selection, amount, fee_amount, true, true);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

#[derive(Debug, Clone, Copy)]
struct BatchShape {
    transaction_count: usize,
    private_output_count: usize,
    public_output_count: usize,
}

fn batch_shape(
    selection: &BatchUtxoSelection,
    amount: U256,
    fee_amount: U256,
    has_fee_output: bool,
    send: bool,
) -> BatchShape {
    let mut remaining = selection.total.saturating_sub(fee_amount).min(amount);
    let mut private_output_count = 0;
    let mut public_output_count = 0;

    for (index, chunk) in selection.chunks.iter().enumerate() {
        let chunk_fee = if index == 0 { fee_amount } else { U256::ZERO };
        let spendable = chunk.total.saturating_sub(chunk_fee);
        let amount_out = spendable.min(remaining);
        let change = spendable.saturating_sub(amount_out);

        if send {
            private_output_count += 1 + usize::from(index == 0 && has_fee_output);
        } else {
            private_output_count += usize::from(index == 0 && has_fee_output);
            public_output_count += 1;
        }
        private_output_count += usize::from(!change.is_zero());
        remaining = remaining.saturating_sub(amount_out);
    }

    BatchShape {
        transaction_count: selection.chunks.len(),
        private_output_count,
        public_output_count,
    }
}

#[must_use]
fn max_batch_spendable(
    utxos: &[Utxo],
    token_address: Address,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> U256 {
    max_batch_selection(
        utxos,
        token_address,
        first_base_output_count,
        continuation_base_output_count,
    )
    .map_or(U256::ZERO, |selection| selection.total)
}

fn max_batch_selection(
    utxos: &[Utxo],
    token_address: Address,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> Option<BatchUtxoSelection> {
    let mut remaining = utxos.to_vec();
    let mut chunks = Vec::new();
    let mut total = U256::ZERO;

    for index in 0..MAX_BATCH_TRANSACTIONS {
        let base_output_count = if index == 0 {
            first_base_output_count
        } else {
            continuation_base_output_count
        };
        let Some(selection) =
            max_unshield_selection_with_output_count(&remaining, token_address, base_output_count)
        else {
            break;
        };
        if selection.total.is_zero() {
            break;
        }
        remove_selected_utxos(&mut remaining, &selection.utxos);
        total += selection.total;
        chunks.push(selection);
    }

    if chunks.is_empty() {
        None
    } else {
        Some(BatchUtxoSelection { chunks, total })
    }
}

fn select_batched_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> Result<BatchUtxoSelection, BuildError> {
    let max_selection = max_batch_selection(
        utxos,
        token_address,
        first_base_output_count,
        continuation_base_output_count,
    );
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(max_spendable));
    }

    if let Some(selection) =
        best_unshield_selection(utxos, token_address, amount, first_base_output_count)
    {
        let total = selection.total;
        return Ok(BatchUtxoSelection {
            chunks: vec![selection],
            total,
        });
    }

    if let Some(selection) = greedy_batched_selection(
        utxos,
        token_address,
        amount,
        first_base_output_count,
        continuation_base_output_count,
    ) {
        return Ok(selection);
    }

    if spend_up_to
        && max_selection
            .as_ref()
            .is_some_and(|selection| !selection.total.is_zero() && selection.total < amount)
    {
        return Ok(max_selection.expect("checked above"));
    }

    Err(BuildError::InsufficientBalance(max_spendable))
}

fn greedy_batched_selection(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> Option<BatchUtxoSelection> {
    let mut remaining_utxos = utxos.to_vec();
    let mut remaining_amount = amount;
    let mut chunks = Vec::new();
    let mut total = U256::ZERO;

    for index in 0..MAX_BATCH_TRANSACTIONS {
        let base_output_count = if index == 0 {
            first_base_output_count
        } else {
            continuation_base_output_count
        };

        if let Some(selection) = best_unshield_selection(
            &remaining_utxos,
            token_address,
            remaining_amount,
            base_output_count,
        ) {
            total += selection.total;
            chunks.push(selection);
            return Some(BatchUtxoSelection { chunks, total });
        }

        let Some(selection) = max_unshield_selection_with_output_count(
            &remaining_utxos,
            token_address,
            base_output_count,
        ) else {
            break;
        };
        if selection.total.is_zero() {
            return None;
        }
        let selection = if selection.total < remaining_amount {
            selection
        } else {
            best_partial_selection_below_amount(
                &remaining_utxos,
                token_address,
                remaining_amount,
                base_output_count,
            )?
        };

        remaining_amount -= selection.total;
        total += selection.total;
        remove_selected_utxos(&mut remaining_utxos, &selection.utxos);
        chunks.push(selection);
    }

    None
}

fn remove_selected_utxos(utxos: &mut Vec<Utxo>, selected: &[Utxo]) {
    utxos.retain(|utxo| {
        !selected
            .iter()
            .any(|selected| selected.tree == utxo.tree && selected.position == utxo.position)
    });
}

#[cfg(test)]
fn select_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    base_output_count: usize,
) -> Result<(Vec<Utxo>, U256), BuildError> {
    let max_selection =
        max_unshield_selection_with_output_count(utxos, token_address, base_output_count);
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(max_spendable));
    }

    if let Some(selection) =
        best_unshield_selection(utxos, token_address, amount, base_output_count)
    {
        return Ok((selection.utxos, selection.total));
    }

    if spend_up_to
        && max_selection
            .as_ref()
            .is_some_and(|selection| !selection.total.is_zero() && selection.total < amount)
    {
        let selection = max_selection.expect("checked above");
        return Ok((selection.utxos, selection.total));
    }

    Err(BuildError::InsufficientBalance(max_spendable))
}

fn best_unshield_selection(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    for candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        if let Some(selection) = best_tree_selection(candidates, amount, base_output_count)
            && best
                .as_ref()
                .is_none_or(|best| selection_is_better(&selection, best, amount))
        {
            best = Some(selection);
        }
    }
    best
}

fn best_partial_selection_below_amount(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    if amount <= uint!(1_U256) {
        return None;
    }
    let max_input_count = max_inputs_for_base_outputs(base_output_count);
    if max_input_count == 0 {
        return None;
    }

    let mut best: Option<UtxoSelection> = None;
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        let mut search = PartialSelectionSearch::new(&candidates, amount, max_input_count);
        search.run();
        if let Some(selection) = search.best
            && best
                .as_ref()
                .is_none_or(|best| max_selection_is_better(&selection, best))
        {
            best = Some(selection);
        }
    }
    best
}

fn max_unshield_selection_with_output_count(
    utxos: &[Utxo],
    token_address: Address,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    let max_input_count = max_inputs_for_base_outputs(base_output_count);
    if max_input_count == 0 {
        return None;
    }
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        candidates.truncate(max_input_count);
        let total = candidates
            .iter()
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value);
        if total.is_zero() {
            continue;
        }
        normalize_selection(&mut candidates);
        let selection = UtxoSelection {
            utxos: candidates,
            total,
        };
        if best
            .as_ref()
            .is_none_or(|best| max_selection_is_better(&selection, best))
        {
            best = Some(selection);
        }
    }
    best
}

const fn max_inputs_for_base_outputs(base_output_count: usize) -> usize {
    let signature_room = MAX_SIGNATURE_INPUTS.saturating_sub(2 + base_output_count);
    if signature_room < MAX_CIRCUIT_INPUTS {
        signature_room
    } else {
        MAX_CIRCUIT_INPUTS
    }
}

fn token_utxos_by_tree(utxos: &[Utxo], token_address: Address) -> BTreeMap<u32, Vec<Utxo>> {
    let token_hash = U256::from_be_slice(token_address.as_slice());
    let mut by_tree: BTreeMap<u32, Vec<Utxo>> = BTreeMap::new();
    for utxo in utxos
        .iter()
        .filter(|utxo| utxo.note.token_hash == token_hash && !utxo.note.value.is_zero())
    {
        by_tree.entry(utxo.tree).or_default().push(utxo.clone());
    }
    by_tree
}

fn best_tree_selection(
    mut candidates: Vec<Utxo>,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    sort_search_candidates(&mut candidates);

    for input_count in 1..=max_inputs_for_base_outputs(base_output_count) {
        let mut search = SelectionSearch::new(&candidates, amount, input_count, base_output_count);
        search.run();
        if let Some(selection) = search.best {
            return Some(selection);
        }
    }
    None
}

fn sort_search_candidates(candidates: &mut [Utxo]) {
    candidates.sort_by(|a, b| {
        b.note
            .value
            .cmp(&a.note.value)
            .then_with(|| a.tree.cmp(&b.tree))
            .then_with(|| a.position.cmp(&b.position))
    });
}

fn normalize_selection(utxos: &mut [Utxo]) {
    utxos.sort_by_key(|utxo| (utxo.tree, utxo.position));
}

fn selection_is_better(candidate: &UtxoSelection, best: &UtxoSelection, amount: U256) -> bool {
    match candidate.utxos.len().cmp(&best.utxos.len()) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }

    let candidate_excess = candidate.total - amount;
    let best_excess = best.total - amount;
    match candidate_excess.cmp(&best_excess) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            selection_position_key(&candidate.utxos) < selection_position_key(&best.utxos)
        }
    }
}

fn max_selection_is_better(candidate: &UtxoSelection, best: &UtxoSelection) -> bool {
    match candidate.total.cmp(&best.total) {
        Ordering::Greater => return true,
        Ordering::Less => return false,
        Ordering::Equal => {}
    }

    match candidate.utxos.len().cmp(&best.utxos.len()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            selection_position_key(&candidate.utxos) < selection_position_key(&best.utxos)
        }
    }
}

fn selection_position_key(utxos: &[Utxo]) -> Vec<(u32, u64)> {
    utxos
        .iter()
        .map(|utxo| (utxo.tree, utxo.position))
        .collect()
}

struct PartialSelectionSearch<'a> {
    candidates: &'a [Utxo],
    amount: U256,
    max_input_count: usize,
    selected: Vec<usize>,
    best: Option<UtxoSelection>,
}

impl<'a> PartialSelectionSearch<'a> {
    fn new(candidates: &'a [Utxo], amount: U256, max_input_count: usize) -> Self {
        Self {
            candidates,
            amount,
            max_input_count,
            selected: Vec::with_capacity(max_input_count),
            best: None,
        }
    }

    fn run(&mut self) {
        self.search(0, U256::ZERO);
    }

    fn search(&mut self, start: usize, total: U256) {
        if self.selected.len() == self.max_input_count || start >= self.candidates.len() {
            return;
        }
        let remaining_slots = self.max_input_count - self.selected.len();
        if let Some(best) = &self.best
            && total + self.max_possible_from(start, remaining_slots) <= best.total
        {
            return;
        }

        for index in start..self.candidates.len() {
            let next_total = total + self.candidates[index].note.value;
            if next_total >= self.amount {
                continue;
            }
            self.selected.push(index);
            self.record(next_total);
            self.search(index + 1, next_total);
            self.selected.pop();
        }
    }

    fn max_possible_from(&self, start: usize, remaining_slots: usize) -> U256 {
        self.candidates[start..]
            .iter()
            .take(remaining_slots)
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value)
    }

    fn record(&mut self, total: U256) {
        let mut utxos = self
            .selected
            .iter()
            .map(|index| self.candidates[*index].clone())
            .collect::<Vec<_>>();
        normalize_selection(&mut utxos);
        let selection = UtxoSelection { utxos, total };
        if self
            .best
            .as_ref()
            .is_none_or(|best| max_selection_is_better(&selection, best))
        {
            self.best = Some(selection);
        }
    }
}

struct SelectionSearch<'a> {
    candidates: &'a [Utxo],
    amount: U256,
    target_count: usize,
    base_output_count: usize,
    selected: Vec<usize>,
    best: Option<UtxoSelection>,
}

impl<'a> SelectionSearch<'a> {
    fn new(
        candidates: &'a [Utxo],
        amount: U256,
        target_count: usize,
        base_output_count: usize,
    ) -> Self {
        Self {
            candidates,
            amount,
            target_count,
            base_output_count,
            selected: Vec::with_capacity(target_count),
            best: None,
        }
    }

    fn run(&mut self) {
        self.search(0, self.target_count, U256::ZERO);
    }

    fn search(&mut self, start: usize, remaining: usize, total: U256) {
        if remaining == 0 {
            self.record_if_valid(total);
            return;
        }
        if self.candidates.len().saturating_sub(start) < remaining {
            return;
        }
        if self.exact_only() && total > self.amount {
            return;
        }
        if !self.exact_only() && self.best.as_ref().is_some_and(|best| total >= best.total) {
            return;
        }
        if total + self.max_possible_from(start, remaining) < self.amount {
            return;
        }

        let end = self.candidates.len() - remaining;
        for index in start..=end {
            let next_total = total + self.candidates[index].note.value;
            if self.exact_only() && next_total > self.amount {
                continue;
            }
            if !self.exact_only()
                && self
                    .best
                    .as_ref()
                    .is_some_and(|best| next_total >= best.total)
            {
                continue;
            }
            self.selected.push(index);
            self.search(index + 1, remaining - 1, next_total);
            self.selected.pop();
        }
    }

    fn max_possible_from(&self, start: usize, remaining: usize) -> U256 {
        self.candidates[start..]
            .iter()
            .take(remaining)
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value)
    }

    fn exact_only(&self) -> bool {
        2 + self.target_count + self.base_output_count + 1 > MAX_SIGNATURE_INPUTS
    }

    fn record_if_valid(&mut self, total: U256) {
        if total < self.amount {
            return;
        }
        let output_count = self.base_output_count + usize::from(total > self.amount);
        if 2 + self.target_count + output_count > MAX_SIGNATURE_INPUTS {
            return;
        }

        let mut utxos = self
            .selected
            .iter()
            .map(|index| self.candidates[*index].clone())
            .collect::<Vec<_>>();
        normalize_selection(&mut utxos);
        let selection = UtxoSelection { utxos, total };
        if self
            .best
            .as_ref()
            .is_none_or(|best| selection_is_better(&selection, best, self.amount))
        {
            self.best = Some(selection);
        }
    }
}

fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use broadcaster_core::utxo::{UtxoCommitmentKind, UtxoSource};

    struct MockSpendSigner {
        signed_msg: Cell<Option<U256>>,
    }

    impl RailgunSpendSigner for MockSpendSigner {
        fn spending_public_key(&self) -> [U256; 2] {
            [uint!(11_U256), uint!(12_U256)]
        }

        fn sign_spend_message(&self, msg: U256) -> [U256; 3] {
            self.signed_msg.set(Some(msg));
            [uint!(1_U256), uint!(2_U256), uint!(3_U256)]
        }
    }

    fn test_utxo(token: Address, value: u64, tree: u32, position: u64) -> Utxo {
        Utxo::new(
            Note::new_unshield(Address::ZERO, token, U256::from(value)),
            tree,
            position,
            UtxoSource {
                tx_hash: FixedBytes::ZERO,
                block_number: 1,
                block_timestamp: 1,
            },
            UtxoCommitmentKind::Transact,
        )
    }

    fn selected_positions(selection: &[Utxo]) -> Vec<u64> {
        selection.iter().map(|utxo| utxo.position).collect()
    }

    fn dummy_merkle_proof(leaf: U256, leaf_index: u64) -> MerkleProof {
        MerkleProof {
            root: U256::ZERO,
            leaf,
            leaf_index,
            path_elements: [U256::ZERO; merkletree::tree::TREE_DEPTH],
            path_indices: [0u8; merkletree::tree::TREE_DEPTH],
        }
    }

    fn sample_chunk(
        seed: u8,
        input_count: usize,
        private_output_count: usize,
        has_unshield: bool,
    ) -> TransactionPlanChunk {
        let token = Address::from([seed; 20]);
        let inputs = (0..input_count)
            .map(|index| {
                let utxo = test_utxo(
                    token,
                    u64::try_from(index + 1).unwrap(),
                    seed.into(),
                    index as u64,
                );
                InputWitness {
                    merkle_proof: dummy_merkle_proof(utxo.note.commitment(), index as u64),
                    utxo,
                }
            })
            .collect::<Vec<_>>();
        let mut outputs = (0..private_output_count)
            .map(|index| {
                Note::new_change(
                    U256::from(1_000_u64 + u64::from(seed) + index as u64),
                    token,
                    U256::from(10_u64 + index as u64),
                    [seed.saturating_add(index as u8); 16],
                )
            })
            .collect::<Vec<_>>();
        if has_unshield {
            outputs.push(Note::new_unshield(
                Address::from([seed.saturating_add(1); 20]),
                token,
                uint!(5_U256),
            ));
        }

        let public_inputs = PublicInputs {
            merkle_root: uint!(7_U256),
            bound_params_hash: U256::from(2_000_u64 + u64::from(seed)),
            nullifiers: (0..input_count)
                .map(|index| U256::from(3_000_u64 + u64::from(seed) + index as u64))
                .collect(),
            commitments_out: outputs.iter().map(Note::commitment).collect(),
        };
        let private_inputs = PrivateInputs {
            token_address: U256::from_be_slice(token.as_slice()),
            random_in: inputs
                .iter()
                .map(|input| U256::from_be_slice(&input.utxo.note.random))
                .collect(),
            value_in: inputs.iter().map(|input| input.utxo.note.value).collect(),
            path_elements: vec![U256::ZERO; input_count * merkletree::tree::TREE_DEPTH],
            leaves_indices: inputs
                .iter()
                .map(|input| U256::from(input.utxo.position))
                .collect(),
            value_out: outputs.iter().map(|note| note.value).collect(),
            public_key: [uint!(11_U256), uint!(12_U256)],
            npk_out: outputs.iter().map(|note| note.npk).collect(),
            nullifying_key: uint!(13_U256),
        };

        TransactionPlanChunk {
            tree_number: seed.into(),
            merkle_root: uint!(7_U256),
            inputs,
            outputs,
            has_unshield,
            public_inputs,
            private_inputs,
            signature: [uint!(1_U256), uint!(2_U256), uint!(3_U256)],
        }
    }

    fn sample_poi_merkle_proofs(blinded_commitments: &[FixedBytes<32>]) -> Vec<PoiMerkleProof> {
        blinded_commitments
            .iter()
            .enumerate()
            .map(|(index, blinded_commitment)| PoiMerkleProof {
                leaf: hex::encode_prefixed(blinded_commitment),
                elements: (0..merkletree::tree::TREE_DEPTH)
                    .map(|level| format!("0x{:064x}", index + level + 1))
                    .collect(),
                indices: format!("0x{index:064x}"),
                root: format!("0x{:064x}", 100 + index),
            })
            .collect()
    }

    fn sample_pre_tx_poi() -> PreTxPoi {
        PreTxPoi {
            snark_proof: SnarkJsProof::zero(),
            txid_merkleroot: FixedBytes::ZERO,
            poi_merkleroots: vec![FixedBytes::ZERO],
            blinded_commitments_out: vec![FixedBytes::ZERO],
            railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
        }
    }

    fn sample_post_txid_data(
        chunk: &TransactionPlanChunk,
        utxo_batch_global_start_position_out: U256,
    ) -> PostTransactionPoiData {
        let railgun_txid = compute_railgun_txid_from_public_inputs(&chunk.public_inputs);
        let txid_leaf_hash = poseidon(vec![
            railgun_txid,
            U256::from(chunk.tree_number),
            utxo_batch_global_start_position_out,
        ]);

        PostTransactionPoiData {
            txid_leaf_hash: FixedBytes::from(txid_leaf_hash.to_be_bytes::<32>()),
            txid_merkleroot: FixedBytes::from([0x77; 32]),
            txid_merkleroot_index: 123,
            txid_merkle_proof_indices: uint!(9_U256),
            txid_merkle_proof_path_elements: vec![uint!(8_U256); merkletree::tree::TREE_DEPTH],
            utxo_batch_global_start_position_out,
        }
    }

    fn sample_address_data(seed: u8) -> ViewingKeyData {
        ViewingKeyData::from_spending_public_key(
            [seed; 32],
            [U256::from(seed), U256::from(seed + 1)],
        )
    }

    #[test]
    fn poi_circuit_variant_selects_smallest_supported_variant() {
        assert_eq!(
            poi_circuit_variant(3, 3),
            PoiCircuitVariant {
                max_inputs: 3,
                max_outputs: 3,
            }
        );
        assert_eq!(
            poi_circuit_variant(4, 3),
            PoiCircuitVariant {
                max_inputs: 13,
                max_outputs: 13,
            }
        );
        assert_eq!(
            poi_circuit_variant(3, 4),
            PoiCircuitVariant {
                max_inputs: 13,
                max_outputs: 13,
            }
        );
    }

    #[test]
    fn pre_transaction_poi_inputs_exclude_unshield_output_from_blinded_outputs() {
        let chunk = sample_chunk(31, 2, 2, true);

        let chunk_inputs = pre_transaction_poi_inputs_from_chunk(&chunk).expect("chunk inputs");
        let proof_inputs = chunk_inputs
            .proof_inputs(&sample_poi_merkle_proofs(
                &chunk_inputs.blinded_commitments_in,
            ))
            .expect("proof inputs");

        assert_eq!(chunk_inputs.blinded_commitments_in.len(), 2);
        assert_eq!(chunk_inputs.blinded_commitments_out.len(), 2);
        assert_eq!(chunk_inputs.railgun_txid_if_has_unshield.len(), 32);
        assert_eq!(proof_inputs.commitments_out.len(), 3);
        assert_eq!(proof_inputs.npks_out.len(), 2);
        assert_eq!(proof_inputs.values_out.len(), 2);
        assert_ne!(proof_inputs.railgun_txid_if_has_unshield, U256::ZERO);
        assert_eq!(proof_inputs.poi_merkleroots.len(), 2);
        assert_eq!(proof_inputs.poi_in_merkle_proof_path_elements[0].len(), 16);
    }

    #[test]
    fn pre_transaction_poi_map_shape_single_chunk_send() {
        let chunk = sample_chunk(41, 1, 1, false);
        let chunk_inputs = pre_transaction_poi_inputs_from_chunk(&chunk).expect("chunk inputs");
        let list_key = FixedBytes::from([0x11; 32]);
        let mut map = BTreeMap::new();

        insert_pre_transaction_poi(
            &mut map,
            list_key,
            chunk_inputs.txid_leaf_hash,
            sample_pre_tx_poi(),
        );

        assert_eq!(map.len(), 1);
        assert!(
            map.get(&list_key)
                .is_some_and(|per_leaf| per_leaf.contains_key(&chunk_inputs.txid_leaf_hash))
        );
        assert_eq!(
            chunk_inputs.railgun_txid_if_has_unshield,
            Bytes::copy_from_slice(&[0_u8])
        );
    }

    #[test]
    fn pre_transaction_poi_map_shape_multi_chunk_unshield() {
        let chunks = [sample_chunk(51, 2, 1, true), sample_chunk(52, 3, 1, true)];
        let list_keys = [FixedBytes::from([0x21; 32]), FixedBytes::from([0x22; 32])];
        let mut map = BTreeMap::new();
        let chunk_inputs = chunks
            .iter()
            .map(pre_transaction_poi_inputs_from_chunk)
            .collect::<Result<Vec<_>, _>>()
            .expect("chunk inputs");

        for list_key in list_keys {
            for inputs in &chunk_inputs {
                insert_pre_transaction_poi(
                    &mut map,
                    list_key,
                    inputs.txid_leaf_hash,
                    sample_pre_tx_poi(),
                );
            }
        }

        assert_eq!(map.len(), 2);
        for list_key in list_keys {
            let per_leaf = map.get(&list_key).expect("list key");
            assert_eq!(per_leaf.len(), 2);
            for inputs in &chunk_inputs {
                assert!(per_leaf.contains_key(&inputs.txid_leaf_hash));
            }
        }
        assert_ne!(
            chunk_inputs[0].txid_leaf_hash,
            chunk_inputs[1].txid_leaf_hash
        );
    }

    #[test]
    fn post_transaction_poi_inputs_use_included_txid_leaf_and_global_output_positions() {
        let chunk = sample_chunk(61, 2, 2, false);
        let output_start = uint!(65_540_U256);
        let txid_data = sample_post_txid_data(&chunk, output_start);

        let chunk_inputs =
            post_transaction_poi_inputs_from_chunk(&chunk, &txid_data).expect("chunk inputs");
        let proof_inputs = chunk_inputs
            .proof_inputs(&sample_poi_merkle_proofs(
                &chunk_inputs.blinded_commitments_in,
            ))
            .expect("proof inputs");

        assert_eq!(chunk_inputs.txid_leaf_hash, txid_data.txid_leaf_hash);
        assert_eq!(chunk_inputs.txid_merkleroot, txid_data.txid_merkleroot);
        assert_eq!(
            proof_inputs.utxo_batch_global_start_position_out,
            output_start
        );
        assert_eq!(
            proof_inputs.railgun_txid_merkle_proof_indices,
            uint!(9_U256)
        );
        assert_eq!(
            proof_inputs.railgun_txid_merkle_proof_path_elements.len(),
            16
        );
        for (index, blinded_commitment) in chunk_inputs.blinded_commitments_out.iter().enumerate() {
            let expected = poseidon(vec![
                chunk.public_inputs.commitments_out[index],
                chunk.private_inputs.npk_out[index],
                output_start + U256::from(index),
            ]);
            assert_eq!(
                *blinded_commitment,
                FixedBytes::from(expected.to_be_bytes::<32>())
            );
        }
    }

    #[test]
    fn post_transaction_poi_from_public_signals_uses_canonical_public_outputs() {
        let chunk = sample_chunk(62, 1, 1, false);
        let txid_data = sample_post_txid_data(&chunk, uint!(123_456_U256));
        let chunk_inputs =
            post_transaction_poi_inputs_from_chunk(&chunk, &txid_data).expect("chunk inputs");
        let proof_inputs = chunk_inputs
            .proof_inputs(&sample_poi_merkle_proofs(
                &chunk_inputs.blinded_commitments_in,
            ))
            .expect("proof inputs");
        let variant = poi_circuit_variant(
            chunk.public_inputs.nullifiers.len(),
            chunk.public_inputs.commitments_out.len(),
        );
        let mut public_signals = vec![U256::ZERO; variant.max_outputs + 2 + variant.max_inputs];
        public_signals[0] = U256::from_be_bytes(chunk_inputs.blinded_commitments_out[0].0);
        public_signals[variant.max_outputs] = U256::from_be_bytes(txid_data.txid_merkleroot.0);
        public_signals[variant.max_outputs + 1] = U256::ZERO;
        public_signals[variant.max_outputs + 2] = proof_inputs.poi_merkleroots[0];
        public_signals[variant.max_outputs + 3] = MERKLE_ZERO_VALUE;
        public_signals[variant.max_outputs + 4] = MERKLE_ZERO_VALUE;

        let poi = chunk_inputs
            .post_tx_poi_from_public_signals(
                sample_pre_tx_poi().snark_proof,
                &proof_inputs,
                &public_signals,
                variant,
            )
            .expect("post tx poi");

        assert_eq!(poi.txid_merkleroot, txid_data.txid_merkleroot);
        assert_eq!(
            poi.blinded_commitments_out,
            chunk_inputs.blinded_commitments_out
        );
        assert_eq!(poi.poi_merkleroots.len(), 1);
        assert_eq!(
            poi.poi_merkleroots[0],
            FixedBytes::from(proof_inputs.poi_merkleroots[0].to_be_bytes::<32>())
        );
        assert_eq!(
            poi.railgun_txid_if_has_unshield,
            Bytes::copy_from_slice(&[0_u8])
        );

        public_signals[variant.max_outputs + 3] = U256::ZERO;
        let err = chunk_inputs
            .post_tx_poi_from_public_signals(
                sample_pre_tx_poi().snark_proof,
                &proof_inputs,
                &public_signals,
                variant,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PreTransactionPoiError::PublicSignalMismatch {
                field: "poiMerkleroots",
                ..
            }
        ));
    }

    #[test]
    fn public_inputs_signature_uses_spend_signer_boundary() {
        let public_inputs = PublicInputs {
            merkle_root: uint!(1_U256),
            bound_params_hash: uint!(2_U256),
            nullifiers: vec![uint!(3_U256)],
            commitments_out: vec![uint!(4_U256)],
        };
        let signer = MockSpendSigner {
            signed_msg: Cell::new(None),
        };

        let signature = public_inputs.signature(&signer);

        assert_eq!(signature, [uint!(1_U256), uint!(2_U256), uint!(3_U256)]);
        assert_eq!(
            signer.signed_msg.get(),
            Some(poseidon(public_inputs.signature_message()))
        );
    }

    #[test]
    fn bound_params_min_gas_price_defaults_to_zero_and_accepts_nonzero() {
        let params =
            BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
                .with_min_gas_price(0)
                .expect("zero min gas price");
        assert_eq!(params.minGasPrice, Uint::<72, 2>::ZERO);

        let params =
            BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
                .with_min_gas_price(123)
                .expect("nonzero min gas price");
        assert_eq!(params.minGasPrice, Uint::<72, 2>::from(123_u128));
    }

    #[test]
    fn unshield_selection_prefers_fewest_inputs() {
        let token = Address::from([1_u8; 20]);
        let utxos = vec![
            test_utxo(token, 40, 0, 1),
            test_utxo(token, 30, 0, 2),
            test_utxo(token, 5, 0, 3),
        ];

        let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

        assert_eq!(total, uint!(40_U256));
        assert_eq!(selected_positions(&selected), vec![1]);
    }

    #[test]
    fn unshield_selection_prefers_exact_match_with_same_input_count() {
        let token = Address::from([2_u8; 20]);
        let utxos = vec![
            test_utxo(token, 12, 0, 1),
            test_utxo(token, 10, 0, 2),
            test_utxo(token, 6, 0, 3),
            test_utxo(token, 5, 0, 4),
        ];

        let (selected, total) = select_utxos(&utxos, token, uint!(16_U256), false, 1).unwrap();

        assert_eq!(total, uint!(16_U256));
        assert_eq!(selected_positions(&selected), vec![2, 3]);
    }

    #[test]
    fn unshield_selection_minimizes_change_with_same_input_count() {
        let token = Address::from([3_u8; 20]);
        let utxos = vec![
            test_utxo(token, 10, 0, 1),
            test_utxo(token, 7, 0, 2),
            test_utxo(token, 6, 0, 3),
        ];

        let (selected, total) = select_utxos(&utxos, token, uint!(12_U256), false, 1).unwrap();

        assert_eq!(total, uint!(13_U256));
        assert_eq!(selected_positions(&selected), vec![2, 3]);
    }

    #[test]
    fn partial_unshield_uses_at_most_twelve_inputs_when_change_is_needed() {
        let token = Address::from([4_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let (selected, total) = select_utxos(&utxos, token, uint!(23_U256), false, 1).unwrap();

        assert_eq!(selected.len(), 12);
        assert_eq!(total, uint!(24_U256));
    }

    #[test]
    fn exact_unshield_can_use_thirteen_inputs() {
        let token = Address::from([5_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let (selected, total) = select_utxos(&utxos, token, uint!(26_U256), false, 1).unwrap();

        assert_eq!(selected.len(), 13);
        assert_eq!(total, uint!(26_U256));
    }

    #[test]
    fn max_unshield_spendable_uses_eight_batched_chunks() {
        let token = Address::from([6_u8; 20]);
        let mut utxos = (0..20)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

        assert_eq!(max_unshield_spendable(&utxos, token), uint!(35_U256));
    }

    #[test]
    fn unshield_selection_error_reports_max_single_transaction_amount() {
        let token = Address::from([7_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();

        let error = select_utxos(&utxos, token, uint!(14_U256), false, 1).unwrap_err();

        assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(13_U256)));
    }

    #[test]
    fn send_outputs_create_recipient_and_change_notes() {
        let token = Address::from([8_u8; 20]);
        let sender_viewing = sample_address_data(10);
        let sender = sender_viewing.address_data();
        let recipient = sample_address_data(20).address_data();

        let outputs = build_send_outputs(
            token,
            uint!(7_U256),
            uint!(3_U256),
            &sender,
            &recipient,
            None,
            &sender_viewing.viewing_private_key,
        )
        .expect("send outputs");

        assert_eq!(outputs.outputs.len(), 2);
        assert_eq!(outputs.recipient_note.value, uint!(7_U256));
        assert_eq!(
            outputs.recipient_note.npk,
            crate::notes::note_public_key(
                recipient.master_public_key,
                outputs.recipient_note.random
            )
        );
        let change_note = outputs.change_note.expect("change note");
        assert_eq!(change_note.value, uint!(3_U256));
        assert_eq!(
            change_note.npk,
            crate::notes::note_public_key(sender.master_public_key, change_note.random)
        );
    }

    #[test]
    fn send_outputs_omit_change_for_exact_send() {
        let token = Address::from([9_u8; 20]);
        let sender_viewing = sample_address_data(11);
        let sender = sender_viewing.address_data();
        let recipient = sample_address_data(21).address_data();

        let outputs = build_send_outputs(
            token,
            uint!(7_U256),
            U256::ZERO,
            &sender,
            &recipient,
            None,
            &sender_viewing.viewing_private_key,
        )
        .expect("send outputs");

        assert_eq!(outputs.outputs.len(), 1);
        assert!(outputs.change_note.is_none());
    }

    #[test]
    fn send_outputs_put_broadcaster_fee_note_first() {
        let token = Address::from([14_u8; 20]);
        let sender_viewing = sample_address_data(12);
        let sender = sender_viewing.address_data();
        let recipient = sample_address_data(22).address_data();
        let broadcaster = sample_address_data(32).address_data();

        let outputs = build_send_outputs(
            token,
            uint!(7_U256),
            uint!(3_U256),
            &sender,
            &recipient,
            Some(BroadcasterFeeOutput {
                recipient: broadcaster,
                amount: uint!(2_U256),
            }),
            &sender_viewing.viewing_private_key,
        )
        .expect("send outputs");

        assert_eq!(outputs.outputs.len(), 3);
        let fee_note = outputs.broadcaster_fee_note.expect("fee note");
        assert_eq!(outputs.outputs[0].value, uint!(2_U256));
        assert_eq!(fee_note.value, uint!(2_U256));
        assert_eq!(
            outputs.outputs[0].npk,
            crate::notes::note_public_key(broadcaster.master_public_key, outputs.outputs[0].random)
        );
        assert_eq!(outputs.outputs[1].value, uint!(7_U256));
        assert_eq!(outputs.outputs[2].value, uint!(3_U256));
    }

    #[test]
    fn unshield_outputs_put_broadcaster_fee_note_first() {
        let token = Address::from([15_u8; 20]);
        let receiver_viewing = sample_address_data(13);
        let receiver = receiver_viewing.address_data();
        let broadcaster = sample_address_data(33).address_data();
        let unshield_to = Address::from([16_u8; 20]);

        let outputs = build_unshield_outputs(
            token,
            uint!(7_U256),
            unshield_to,
            uint!(3_U256),
            &receiver,
            Some(BroadcasterFeeOutput {
                recipient: broadcaster,
                amount: uint!(2_U256),
            }),
            &receiver_viewing.viewing_private_key,
        )
        .expect("unshield outputs");

        assert_eq!(outputs.outputs.len(), 3);
        assert_eq!(outputs.commitment_ciphertext.len(), 2);
        let fee_note = outputs.broadcaster_fee_note.expect("fee note");
        assert_eq!(outputs.outputs[0].value, uint!(2_U256));
        assert_eq!(fee_note.value, uint!(2_U256));
        assert_eq!(outputs.outputs[1].value, uint!(3_U256));
        assert_eq!(outputs.outputs[2].value, uint!(7_U256));
        assert_eq!(
            outputs.unshield_note.npk,
            U256::from_be_slice(unshield_to.as_slice())
        );
    }

    #[test]
    fn send_selection_prefers_fewest_inputs() {
        let token = Address::from([10_u8; 20]);
        let utxos = vec![
            test_utxo(token, 40, 0, 1),
            test_utxo(token, 30, 0, 2),
            test_utxo(token, 5, 0, 3),
        ];

        let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

        assert_eq!(total, uint!(40_U256));
        assert_eq!(selected_positions(&selected), vec![1]);
    }

    #[test]
    fn partial_send_uses_at_most_twelve_inputs_when_change_is_needed() {
        let token = Address::from([11_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let info = send_selection_info(&utxos, token, uint!(23_U256), false).unwrap();

        assert_eq!(info.input_count, 12);
        assert_eq!(info.total, uint!(24_U256));
    }

    #[test]
    fn exact_send_can_use_thirteen_inputs() {
        let token = Address::from([12_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let info = send_selection_info(&utxos, token, uint!(26_U256), false).unwrap();

        assert_eq!(info.input_count, 13);
        assert_eq!(info.total, uint!(26_U256));
    }

    #[test]
    fn broadcaster_fee_selection_batches_when_fee_output_reduces_first_chunk() {
        let token = Address::from([17_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let info = send_selection_info_with_broadcaster_fee(
            &utxos,
            token,
            uint!(23_U256),
            uint!(3_U256),
            false,
        )
        .unwrap();

        assert_eq!(info.total, uint!(26_U256));
        assert_eq!(info.input_count, 13);
        assert_eq!(info.transaction_count, 2);
        assert_eq!(info.private_output_count, 3);
        assert_eq!(info.public_output_count, 0);
        assert_eq!(info.max_spendable, uint!(23_U256));
    }

    #[test]
    fn batched_selection_can_use_smaller_first_chunk_for_satisfiable_remainder() {
        let token = Address::from([19_u8; 20]);
        let mut utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();
        utxos.push(test_utxo(token, 1, 1, 0));

        let info = send_selection_info(&utxos, token, uint!(25_U256), false).unwrap();

        assert_eq!(info.total, uint!(25_U256));
        assert_eq!(info.input_count, 13);
        assert_eq!(info.transaction_count, 2);
        assert_eq!(info.private_output_count, 2);
        assert_eq!(info.public_output_count, 0);
    }

    #[test]
    fn max_send_spendable_uses_eight_batched_chunks() {
        let token = Address::from([13_u8; 20]);
        let mut utxos = (0..20)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

        assert_eq!(max_send_spendable(&utxos, token), uint!(35_U256));
    }

    #[test]
    fn batched_selection_reports_eight_chunk_cap() {
        let token = Address::from([18_u8; 20]);
        let utxos = (0..9)
            .flat_map(|tree| (0..13).map(move |position| test_utxo(token, 1, tree, position)))
            .collect::<Vec<_>>();

        let error = send_selection_info(&utxos, token, uint!(105_U256), false).unwrap_err();

        assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(104_U256)));
    }
}
