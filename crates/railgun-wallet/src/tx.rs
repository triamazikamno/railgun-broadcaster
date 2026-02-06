use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use rand::RngCore;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use thiserror::Error;

use broadcaster_core::contracts::railgun::{
    ActionData, BoundParams, CommitmentPreimage, SnarkProof, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::poseidon::poseidon;
use merkletree::tree::{MerkleForest, MerkleProof};

use crate::keys::{EddsaSignature, WalletKeys};
use crate::notes::{Note, NoteCiphertext};
use crate::prover::ProverService;
use broadcaster_core::utxo::Utxo;

pub const UNRELAYED_ADAPT_PARAMS: FixedBytes<32> = FixedBytes::ZERO;

/// Maximum number of UTXOs that can be used as inputs in a single transaction.
const MAX_CIRCUIT_INPUTS: usize = 13;

/// Maximum total inputs to the signature hash (inputs + outputs + 2 for root and bound params).
const MAX_SIGNATURE_INPUTS: usize = 16;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("no matching utxos for amount")]
    InsufficientBalance,
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
    #[error("encrypt note failed: {0}")]
    Encrypt(#[from] crate::notes::NoteError),
    #[error("prove failed: {0}")]
    Prover(#[from] crate::prover::ProverError),
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
pub struct UnshieldPlan {
    pub call: TransactionCall,
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub unshield_note: Note,
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
    pub fn signature(&self, wallet: &WalletKeys) -> [U256; 3] {
        let msg = poseidon(self.signature_message());
        let signature = EddsaSignature::new(&wallet.spending_private_key, msg);
        [signature.r8[0], signature.r8[1], signature.s]
    }
}

impl PrivateInputs {
    #[must_use]
    pub fn from_inputs(
        token_address: Address,
        inputs: &[InputWitness],
        outputs: &[Note],
        wallet: &WalletKeys,
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
            public_key: wallet.spending_public_key,
            npk_out,
            nullifying_key: wallet.viewing.nullifying_key,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UnshieldMode {
    Token,
    UnwrapBase,
}

#[derive(Debug, Clone, Copy)]
pub struct UnshieldRequest {
    pub token_address: Address,
    pub amount: U256,
    pub recipient: Address,
    pub mode: UnshieldMode,
    pub verify_proof: bool,
    pub spend_up_to: bool,
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
        let (selected_utxos, total) = select_utxos(utxos, request.token_address, request.amount)?;

        let plan_builder = TransactionPlanBuilder::new(
            self,
            wallet,
            forest,
            prover,
            selected_utxos,
            request.token_address,
        )?;

        plan_builder.build_unshield(request, total).await
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
struct TransactionPlanBuilder<'a> {
    builder: &'a TransactionBuilder,
    wallet: &'a WalletKeys,
    forest: &'a MerkleForest,
    prover: &'a ProverService,
    inputs: Vec<Utxo>,
    token_address: Address,
}

impl<'a> TransactionPlanBuilder<'a> {
    /// Create a new builder with validated inputs.
    fn new(
        builder: &'a TransactionBuilder,
        wallet: &'a WalletKeys,
        forest: &'a MerkleForest,
        prover: &'a ProverService,
        inputs: Vec<Utxo>,
        token_address: Address,
    ) -> Result<Self, BuildError> {
        if inputs.is_empty() {
            return Err(BuildError::InsufficientBalance);
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
            wallet,
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
                    utxo.nullifier(self.wallet.viewing.nullifying_key)
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

    /// Build an unshield plan.
    async fn build_unshield(
        self,
        request: UnshieldRequest,
        total: U256,
    ) -> Result<UnshieldPlan, BuildError> {
        // Validate spend amount
        if !request.spend_up_to && total < request.amount {
            return Err(BuildError::InsufficientBalance);
        }
        let unshield_amount = if request.spend_up_to {
            total.min(request.amount)
        } else {
            request.amount
        };
        if unshield_amount.is_zero() {
            return Err(BuildError::InsufficientBalance);
        }

        let change = total - unshield_amount;
        let receiver = self.wallet.address_data();

        tracing::info!(
            %unshield_amount,
            %change,
            len = self.inputs.len(),
            "selected utxos"
        );

        let mut outputs = Vec::with_capacity(2);
        let mut commitment_ciphertext = Vec::with_capacity(1);
        let mut change_note = None;

        if !change.is_zero() {
            let random = rand_array();
            let note = Note::new_change(
                receiver.master_public_key,
                request.token_address,
                change,
                random,
            );
            let ciphertext = NoteCiphertext::try_from_note(
                &note,
                &receiver,
                &receiver,
                &self.wallet.viewing.viewing_private_key,
            )?;
            outputs.push(note.clone());
            commitment_ciphertext.push(ciphertext);
            change_note = Some(note);
        }

        // Create unshield note
        let unshield_to = match request.mode {
            UnshieldMode::Token => request.recipient,
            UnshieldMode::UnwrapBase => self.builder.relay_adapt_contract,
        };
        let unshield_note =
            Note::new_unshield(unshield_to, request.token_address, unshield_amount);
        outputs.push(unshield_note.clone());

        self.validate_signature_limit(outputs.len())?;

        // Create action data for unwrap mode
        let action_data = if matches!(request.mode, UnshieldMode::UnwrapBase) {
            let random = FixedBytes::<31>::from(rand_array());
            Some(ActionData::unwrap_base(
                self.builder.relay_adapt_contract,
                request.recipient,
                random,
                true,
            ))
        } else {
            None
        };

        let tree_number = self.tree_number();
        let root = self.get_root()?;

        // Build transaction
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext: Vec<_> = commitment_ciphertext
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
        );

        let mut transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::new_unshield(
                &unshield_note,
                request.token_address,
            ),
        };

        // Apply adapt params for unwrap mode
        if let Some(action_data) = action_data.as_ref() {
            let adapt_params = action_data.adapt_params(&[&transaction]);
            transaction.boundParams.adaptContract = self.builder.relay_adapt_contract;
            transaction.boundParams.adaptParams = adapt_params;
        }

        // Build witnesses and inputs
        let inputs = self.build_input_witnesses()?;
        let public_inputs = PublicInputs::from_transaction(root, &transaction, &outputs);
        let private_inputs =
            PrivateInputs::from_inputs(request.token_address, &inputs, &outputs, self.wallet);
        let signature = public_inputs.signature(self.wallet);

        // Generate proof
        tracing::info!("proving");
        let proof = self
            .prover
            .prove_unshield(
                &public_inputs,
                &private_inputs,
                &signature,
                request.verify_proof,
            )
            .await?;
        transaction.proof = proof;

        // Build final call
        tracing::info!("building transaction call");
        let call = if matches!(request.mode, UnshieldMode::UnwrapBase) {
            let action_data = action_data.ok_or(BuildError::MissingActionData)?;
            let data = relayCall {
                _transactions: vec![transaction],
                _actionData: action_data,
            }
            .abi_encode();
            TransactionCall {
                to: self.builder.relay_adapt_contract,
                data: data.into(),
            }
        } else {
            let data = transactCall {
                _transactions: vec![transaction],
            }
            .abi_encode();
            TransactionCall {
                to: self.builder.railgun_contract,
                data: data.into(),
            }
        };

        Ok(UnshieldPlan {
            call,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            unshield_note,
            change_note,
            public_inputs,
            private_inputs,
            signature,
        })
    }

    /// Build a transact plan.
    async fn build_transact(self) -> Result<TransactPlan, BuildError> {
        let total = self.total_value();
        if total.is_zero() {
            return Err(BuildError::InsufficientBalance);
        }

        let receiver = self.wallet.address_data();
        let random = rand_array();
        let output =
            Note::new_change(receiver.master_public_key, self.token_address, total, random);

        let ciphertext = NoteCiphertext::try_from_note(
            &output,
            &receiver,
            &receiver,
            &self.wallet.viewing.viewing_private_key,
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
        let private_inputs =
            PrivateInputs::from_inputs(self.token_address, &inputs, &outputs, self.wallet);
        let signature = public_inputs.signature(self.wallet);

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

fn select_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
) -> Result<(Vec<Utxo>, U256), BuildError> {
    let token_hash = U256::from_be_slice(token_address.as_slice());
    let mut candidates: Vec<_> = utxos
        .iter()
        .filter(|utxo| utxo.note.token_hash == token_hash)
        .cloned()
        .collect();
    candidates.sort_by(|a, b| b.note.value.cmp(&a.note.value));

    let mut best: Option<(Vec<Utxo>, U256)> = None;
    for tree in candidates
        .iter()
        .map(|utxo| utxo.tree)
        .collect::<std::collections::BTreeSet<_>>()
    {
        let mut selected = Vec::with_capacity(MAX_CIRCUIT_INPUTS);
        let mut total = U256::ZERO;
        for utxo in candidates.iter().filter(|utxo| utxo.tree == tree) {
            if selected.len() >= MAX_CIRCUIT_INPUTS {
                break;
            }
            selected.push(utxo.clone());
            total += utxo.note.value;
            if total >= amount {
                return Ok((selected, total));
            }
        }
        if selected.is_empty() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, best_total)| total > *best_total)
        {
            best = Some((selected, total));
        }
    }

    best.ok_or(BuildError::InsufficientBalance)
}

fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}
