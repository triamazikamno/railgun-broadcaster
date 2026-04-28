use std::cmp::Ordering;
use std::collections::BTreeMap;

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use rand::Rng;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use thiserror::Error;

use broadcaster_core::contracts::railgun::{
    ActionData, BoundParams, CommitmentPreimage, SnarkProof, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::{MerkleForest, MerkleProof};

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::{Note, NoteCiphertext};
use crate::prover::ProverService;

pub const UNRELAYED_ADAPT_PARAMS: FixedBytes<32> = FixedBytes::ZERO;

/// Maximum number of UTXOs that can be used as inputs in a single transaction.
pub const MAX_CIRCUIT_INPUTS: usize = 13;

/// Maximum total inputs to the signature hash (inputs + outputs + 2 for root and bound params).
pub const MAX_SIGNATURE_INPUTS: usize = 16;

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
pub struct SendPlan {
    pub call: TransactionCall,
    pub tree_number: u32,
    pub merkle_root: U256,
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<Note>,
    pub recipient_note: Note,
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

#[derive(Debug, Clone, Copy)]
pub struct SendRequest {
    pub token_address: Address,
    pub amount: U256,
    pub recipient: AddressData,
    pub verify_proof: bool,
    pub spend_up_to: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnshieldSelectionInfo {
    pub total: U256,
    pub input_count: usize,
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
        let (selected_utxos, total) = select_utxos(
            utxos,
            request.token_address,
            request.amount,
            request.spend_up_to,
        )?;

        let plan_builder = TransactionPlanBuilder::new(
            self,
            viewing,
            signer,
            forest,
            prover,
            selected_utxos,
            request.token_address,
        )?;

        plan_builder.build_unshield(request, total).await
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
        let (selected_utxos, total) = select_utxos(
            utxos,
            request.token_address,
            request.amount,
            request.spend_up_to,
        )?;

        let plan_builder = TransactionPlanBuilder::new(
            self,
            viewing,
            signer,
            forest,
            prover,
            selected_utxos,
            request.token_address,
        )?;

        plan_builder.build_send(request, total).await
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

    /// Build an unshield plan.
    async fn build_unshield(
        self,
        request: UnshieldRequest,
        total: U256,
    ) -> Result<UnshieldPlan, BuildError> {
        // Validate spend amount
        if !request.spend_up_to && total < request.amount {
            return Err(BuildError::InsufficientBalance(total));
        }
        let unshield_amount = if request.spend_up_to {
            total.min(request.amount)
        } else {
            request.amount
        };
        if unshield_amount.is_zero() {
            return Err(BuildError::InsufficientBalance(total));
        }

        let change = total - unshield_amount;
        let receiver = self.viewing.address_data();

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
                &self.viewing.viewing_private_key,
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
        let unshield_note = Note::new_unshield(unshield_to, request.token_address, unshield_amount);
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
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );
        let signature = public_inputs.signature(self.signer);

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

    /// Build a private send plan.
    async fn build_send(self, request: SendRequest, total: U256) -> Result<SendPlan, BuildError> {
        if !request.spend_up_to && total < request.amount {
            return Err(BuildError::InsufficientBalance(total));
        }
        let send_amount = if request.spend_up_to {
            total.min(request.amount)
        } else {
            request.amount
        };
        if send_amount.is_zero() {
            return Err(BuildError::InsufficientBalance(total));
        }

        let change = total - send_amount;
        let sender = self.viewing.address_data();

        tracing::info!(
            %send_amount,
            %change,
            len = self.inputs.len(),
            "selected send utxos"
        );

        let SendOutputs {
            outputs,
            commitment_ciphertext,
            recipient_note,
            change_note,
        } = build_send_outputs(
            request.token_address,
            send_amount,
            change,
            &sender,
            &request.recipient,
            &self.viewing.viewing_private_key,
        )?;

        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let root = self.get_root()?;

        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext: Vec<_> = commitment_ciphertext
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
        );

        let mut transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };

        let inputs = self.build_input_witnesses()?;
        let public_inputs = PublicInputs::from_transaction(root, &transaction, &outputs);
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );
        let signature = public_inputs.signature(self.signer);

        tracing::info!("proving private send");
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

        tracing::info!("building send transaction call");
        let data = transactCall {
            _transactions: vec![transaction],
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.builder.railgun_contract,
            data: data.into(),
        };

        Ok(SendPlan {
            call,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            recipient_note,
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
    recipient_note: Note,
    change_note: Option<Note>,
}

fn build_send_outputs(
    token_address: Address,
    send_amount: U256,
    change: U256,
    sender: &AddressData,
    recipient: &AddressData,
    sender_viewing_private_key: &[u8; 32],
) -> Result<SendOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(2);
    let mut commitment_ciphertext = Vec::with_capacity(2);

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
        recipient_note,
        change_note,
    })
}

#[derive(Debug, Clone)]
struct UtxoSelection {
    utxos: Vec<Utxo>,
    total: U256,
}

#[must_use]
pub fn max_unshield_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_unshield_selection(utxos, token_address).map_or(U256::ZERO, |selection| selection.total)
}

pub fn unshield_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let max_spendable = max_unshield_spendable(utxos, token_address);
    let (selected, total) = select_utxos(utxos, token_address, amount, spend_up_to)?;
    Ok(UnshieldSelectionInfo {
        total,
        input_count: selected.len(),
        max_spendable,
    })
}

#[must_use]
pub fn max_send_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_unshield_spendable(utxos, token_address)
}

pub fn send_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    unshield_selection_info(utxos, token_address, amount, spend_up_to)
}

fn select_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<(Vec<Utxo>, U256), BuildError> {
    let max_selection = max_unshield_selection(utxos, token_address);
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(max_spendable));
    }

    if let Some(selection) = best_unshield_selection(utxos, token_address, amount) {
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
) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    for candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        if let Some(selection) = best_tree_selection(candidates, amount)
            && best
                .as_ref()
                .is_none_or(|best| selection_is_better(&selection, best, amount))
        {
            best = Some(selection);
        }
    }
    best
}

fn max_unshield_selection(utxos: &[Utxo], token_address: Address) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        candidates.truncate(MAX_CIRCUIT_INPUTS);
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

fn best_tree_selection(mut candidates: Vec<Utxo>, amount: U256) -> Option<UtxoSelection> {
    sort_search_candidates(&mut candidates);

    for input_count in 1..=MAX_CIRCUIT_INPUTS {
        let mut search = SelectionSearch::new(&candidates, amount, input_count);
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

struct SelectionSearch<'a> {
    candidates: &'a [Utxo],
    amount: U256,
    target_count: usize,
    selected: Vec<usize>,
    best: Option<UtxoSelection>,
}

impl<'a> SelectionSearch<'a> {
    fn new(candidates: &'a [Utxo], amount: U256, target_count: usize) -> Self {
        Self {
            candidates,
            amount,
            target_count,
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
        2 + self.target_count + 2 > MAX_SIGNATURE_INPUTS
    }

    fn record_if_valid(&mut self, total: U256) {
        if total < self.amount {
            return;
        }
        let output_count = if total == self.amount { 1 } else { 2 };
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
    use broadcaster_core::utxo::UtxoSource;

    struct MockSpendSigner {
        signed_msg: Cell<Option<U256>>,
    }

    impl RailgunSpendSigner for MockSpendSigner {
        fn spending_public_key(&self) -> [U256; 2] {
            [U256::from(11_u8), U256::from(12_u8)]
        }

        fn sign_spend_message(&self, msg: U256) -> [U256; 3] {
            self.signed_msg.set(Some(msg));
            [U256::from(1_u8), U256::from(2_u8), U256::from(3_u8)]
        }
    }

    fn test_utxo(token: Address, value: u64, tree: u32, position: u64) -> Utxo {
        Utxo {
            note: Note::new_unshield(Address::ZERO, token, U256::from(value)),
            tree,
            position,
            source: UtxoSource {
                tx_hash: FixedBytes::ZERO,
                block_number: 1,
                block_timestamp: 1,
            },
        }
    }

    fn selected_positions(selection: &[Utxo]) -> Vec<u64> {
        selection.iter().map(|utxo| utxo.position).collect()
    }

    fn sample_address_data(seed: u8) -> ViewingKeyData {
        ViewingKeyData::from_spending_public_key(
            [seed; 32],
            [U256::from(seed), U256::from(seed + 1)],
        )
    }

    #[test]
    fn public_inputs_signature_uses_spend_signer_boundary() {
        let public_inputs = PublicInputs {
            merkle_root: U256::from(1_u8),
            bound_params_hash: U256::from(2_u8),
            nullifiers: vec![U256::from(3_u8)],
            commitments_out: vec![U256::from(4_u8)],
        };
        let signer = MockSpendSigner {
            signed_msg: Cell::new(None),
        };

        let signature = public_inputs.signature(&signer);

        assert_eq!(
            signature,
            [U256::from(1_u8), U256::from(2_u8), U256::from(3_u8)]
        );
        assert_eq!(
            signer.signed_msg.get(),
            Some(poseidon(public_inputs.signature_message()))
        );
    }

    #[test]
    fn unshield_selection_prefers_fewest_inputs() {
        let token = Address::from([1_u8; 20]);
        let utxos = vec![
            test_utxo(token, 40, 0, 1),
            test_utxo(token, 30, 0, 2),
            test_utxo(token, 5, 0, 3),
        ];

        let (selected, total) = select_utxos(&utxos, token, U256::from(35_u8), false).unwrap();

        assert_eq!(total, U256::from(40_u8));
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

        let (selected, total) = select_utxos(&utxos, token, U256::from(16_u8), false).unwrap();

        assert_eq!(total, U256::from(16_u8));
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

        let (selected, total) = select_utxos(&utxos, token, U256::from(12_u8), false).unwrap();

        assert_eq!(total, U256::from(13_u8));
        assert_eq!(selected_positions(&selected), vec![2, 3]);
    }

    #[test]
    fn partial_unshield_uses_at_most_twelve_inputs_when_change_is_needed() {
        let token = Address::from([4_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let (selected, total) = select_utxos(&utxos, token, U256::from(23_u8), false).unwrap();

        assert_eq!(selected.len(), 12);
        assert_eq!(total, U256::from(24_u8));
    }

    #[test]
    fn exact_unshield_can_use_thirteen_inputs() {
        let token = Address::from([5_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let (selected, total) = select_utxos(&utxos, token, U256::from(26_u8), false).unwrap();

        assert_eq!(selected.len(), 13);
        assert_eq!(total, U256::from(26_u8));
    }

    #[test]
    fn max_unshield_spendable_uses_largest_single_tree_top_thirteen() {
        let token = Address::from([6_u8; 20]);
        let mut utxos = (0..20)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

        assert_eq!(max_unshield_spendable(&utxos, token), U256::from(15_u8));
    }

    #[test]
    fn unshield_selection_error_reports_max_single_transaction_amount() {
        let token = Address::from([7_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();

        let error = select_utxos(&utxos, token, U256::from(14_u8), false).unwrap_err();

        assert!(matches!(error, BuildError::InsufficientBalance(max) if max == U256::from(13_u8)));
    }

    #[test]
    fn send_outputs_create_recipient_and_change_notes() {
        let token = Address::from([8_u8; 20]);
        let sender_viewing = sample_address_data(10);
        let sender = sender_viewing.address_data();
        let recipient = sample_address_data(20).address_data();

        let outputs = build_send_outputs(
            token,
            U256::from(7_u8),
            U256::from(3_u8),
            &sender,
            &recipient,
            &sender_viewing.viewing_private_key,
        )
        .expect("send outputs");

        assert_eq!(outputs.outputs.len(), 2);
        assert_eq!(outputs.recipient_note.value, U256::from(7_u8));
        assert_eq!(
            outputs.recipient_note.npk,
            crate::notes::note_public_key(
                recipient.master_public_key,
                outputs.recipient_note.random
            )
        );
        let change_note = outputs.change_note.expect("change note");
        assert_eq!(change_note.value, U256::from(3_u8));
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
            U256::from(7_u8),
            U256::ZERO,
            &sender,
            &recipient,
            &sender_viewing.viewing_private_key,
        )
        .expect("send outputs");

        assert_eq!(outputs.outputs.len(), 1);
        assert!(outputs.change_note.is_none());
    }

    #[test]
    fn send_selection_prefers_fewest_inputs() {
        let token = Address::from([10_u8; 20]);
        let utxos = vec![
            test_utxo(token, 40, 0, 1),
            test_utxo(token, 30, 0, 2),
            test_utxo(token, 5, 0, 3),
        ];

        let (selected, total) = select_utxos(&utxos, token, U256::from(35_u8), false).unwrap();

        assert_eq!(total, U256::from(40_u8));
        assert_eq!(selected_positions(&selected), vec![1]);
    }

    #[test]
    fn partial_send_uses_at_most_twelve_inputs_when_change_is_needed() {
        let token = Address::from([11_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let info = send_selection_info(&utxos, token, U256::from(23_u8), false).unwrap();

        assert_eq!(info.input_count, 12);
        assert_eq!(info.total, U256::from(24_u8));
    }

    #[test]
    fn exact_send_can_use_thirteen_inputs() {
        let token = Address::from([12_u8; 20]);
        let utxos = (0..13)
            .map(|position| test_utxo(token, 2, 0, position))
            .collect::<Vec<_>>();

        let info = send_selection_info(&utxos, token, U256::from(26_u8), false).unwrap();

        assert_eq!(info.input_count, 13);
        assert_eq!(info.total, U256::from(26_u8));
    }

    #[test]
    fn max_send_spendable_uses_largest_single_tree_top_thirteen() {
        let token = Address::from([13_u8; 20]);
        let mut utxos = (0..20)
            .map(|position| test_utxo(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

        assert_eq!(max_send_spendable(&utxos, token), U256::from(15_u8));
    }
}
