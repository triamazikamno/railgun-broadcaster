use super::*;

pub const UNRELAYED_ADAPT_PARAMS: FixedBytes<32> = FixedBytes::ZERO;

/// Maximum number of UTXOs that can be used as inputs in a single transaction.
pub const MAX_CIRCUIT_INPUTS: usize = 13;

/// Maximum total inputs to the signature hash (inputs + outputs + 2 for root and bound params).
pub const MAX_SIGNATURE_INPUTS: usize = 16;

/// Maximum number of inner Railgun transactions to include in one outer call.
pub const MAX_BATCH_TRANSACTIONS: usize = 8;

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

    #[must_use]
    pub fn private_output_count(&self) -> Option<usize> {
        if self.has_unshield {
            self.outputs.len().checked_sub(1)
        } else {
            Some(self.outputs.len())
        }
    }

    pub(super) fn private_output_count_for_poi(&self) -> Result<usize, PreTransactionPoiError> {
        let private_output_count = if self.has_unshield {
            self.public_inputs
                .commitments_out
                .len()
                .checked_sub(1)
                .ok_or(PreTransactionPoiError::MissingPrivateOutputBeforeUnshield)?
        } else {
            self.public_inputs.commitments_out.len()
        };
        if self.private_inputs.npk_out.len() < private_output_count
            || self.private_inputs.value_out.len() < private_output_count
        {
            return Err(PreTransactionPoiError::OutputCountMismatch {
                expected: private_output_count,
                got: self
                    .private_inputs
                    .npk_out
                    .len()
                    .min(self.private_inputs.value_out.len()),
            });
        }
        Ok(private_output_count)
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
    pub fn from_parts(
        merkle_root: U256,
        bound_params_hash: U256,
        nullifiers: Vec<U256>,
        outputs: &[Note],
    ) -> Self {
        let commitments_out = outputs.iter().map(Note::commitment).collect();
        Self {
            merkle_root,
            bound_params_hash,
            nullifiers,
            commitments_out,
        }
    }

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
        Self::from_parts(merkle_root, bound_params_hash, nullifiers, outputs)
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
        let mut path_elements = Vec::with_capacity(inputs.len() * TREE_DEPTH);
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

#[derive(Debug, Clone, Copy)]
pub enum UnshieldMode {
    Token,
    UnwrapBase,
}

#[derive(Debug, Clone, Copy)]
pub struct BroadcasterFeeOutput {
    pub recipient: AddressData,
    pub token_address: Address,
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
    pub(super) fn same_token_broadcaster_fee(self) -> Option<BroadcasterFeeOutput> {
        self.broadcaster_fee
            .filter(|fee| fee.token_address == self.token_address)
    }

    pub(super) fn different_token_broadcaster_fee(self) -> Option<BroadcasterFeeOutput> {
        self.broadcaster_fee
            .filter(|fee| fee.token_address != self.token_address)
    }

    pub(super) fn fee_amount(self) -> U256 {
        self.same_token_broadcaster_fee()
            .map_or(U256::ZERO, |fee| fee.amount)
    }

    pub(super) fn target_amount(self) -> U256 {
        self.amount + self.fee_amount()
    }

    pub(super) fn base_output_count(self) -> usize {
        1 + usize::from(self.same_token_broadcaster_fee().is_some())
    }
}

impl SendRequest {
    pub(super) fn same_token_broadcaster_fee(self) -> Option<BroadcasterFeeOutput> {
        self.broadcaster_fee
            .filter(|fee| fee.token_address == self.token_address)
    }

    pub(super) fn different_token_broadcaster_fee(self) -> Option<BroadcasterFeeOutput> {
        self.broadcaster_fee
            .filter(|fee| fee.token_address != self.token_address)
    }

    pub(super) fn fee_amount(self) -> U256 {
        self.same_token_broadcaster_fee()
            .map_or(U256::ZERO, |fee| fee.amount)
    }

    pub(super) fn target_amount(self) -> U256 {
        self.amount + self.fee_amount()
    }

    pub(super) fn base_output_count(self) -> usize {
        1 + usize::from(self.same_token_broadcaster_fee().is_some())
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
