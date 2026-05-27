use super::*;

use selection::{
    BatchUtxoSelection, UtxoSelection, select_batched_utxos, select_batched_utxos_with_limit,
    select_fee_utxos,
};

mod selection;

pub use selection::{
    max_broadcaster_fee_token_spendable, max_send_spendable, max_unshield_spendable,
    send_selection_info, send_selection_info_with_broadcaster_fee,
    send_selection_info_with_broadcaster_fee_token,
    send_selection_info_with_separate_broadcaster_fee_seed, unshield_selection_info,
    unshield_selection_info_with_broadcaster_fee,
    unshield_selection_info_with_broadcaster_fee_token,
    unshield_selection_info_with_separate_broadcaster_fee_seed,
};

#[cfg(test)]
use alloy::uint;
#[cfg(test)]
use selection::select_utxos;

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
        if let Some(fee) = request.different_token_broadcaster_fee() {
            let fee_selection = select_fee_utxos(utxos, fee.token_address, fee.amount)?;
            let action_selection = select_batched_utxos_with_limit(
                utxos,
                request.token_address,
                request.amount,
                request.spend_up_to,
                1,
                1,
                MAX_BATCH_TRANSACTIONS - 1,
            )?;
            return self
                .build_unshield_batch_with_separate_fee_token(
                    viewing,
                    signer,
                    forest,
                    fee_selection,
                    action_selection,
                    request,
                    fee,
                    prover,
                )
                .await;
        }

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
        if let Some(fee) = request.different_token_broadcaster_fee() {
            let fee_selection = select_fee_utxos(utxos, fee.token_address, fee.amount)?;
            let action_selection = select_batched_utxos_with_limit(
                utxos,
                request.token_address,
                request.amount,
                request.spend_up_to,
                1,
                1,
                MAX_BATCH_TRANSACTIONS - 1,
            )?;
            return self
                .build_send_batch_with_separate_fee_token(
                    viewing,
                    signer,
                    forest,
                    fee_selection,
                    action_selection,
                    request,
                    fee,
                    prover,
                )
                .await;
        }

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

    #[allow(clippy::too_many_arguments)]
    async fn build_unshield_batch_with_separate_fee_token(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        fee_selection: UtxoSelection,
        action_selection: BatchUtxoSelection,
        request: UnshieldRequest,
        fee: BroadcasterFeeOutput,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let receiver = viewing.address_data();
        let fee_change = fee_selection.total - fee.amount;
        let fee_plan_builder = TransactionPlanBuilder::new(
            self,
            viewing,
            signer,
            forest,
            prover,
            fee_selection.utxos,
            fee.token_address,
        )?;
        let FeeOnlyOutputs {
            outputs,
            commitment_ciphertext,
            broadcaster_fee_note,
            mut change_note,
        } = build_fee_only_outputs(fee, fee_change, &receiver, &viewing.viewing_private_key)?;
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            request.min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut input_witness_cache),
        )?;

        let allocations = spend_allocations(
            &action_selection,
            request.amount,
            U256::ZERO,
            None,
            request.spend_up_to,
        )?;
        let unshield_to = match request.mode {
            UnshieldMode::Token => request.recipient,
            UnshieldMode::UnwrapBase => self.relay_adapt_contract,
        };
        let mut unproven_plans = Vec::with_capacity(1 + action_selection.chunks.len());
        unproven_plans.push(fee_unproven_plan);
        let mut unshield_notes = Vec::with_capacity(action_selection.chunks.len());

        for (chunk, allocation) in action_selection.chunks.into_iter().zip(allocations) {
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
                broadcaster_fee_note: _,
                unshield_note,
                change_note: chunk_change_note,
            } = build_unshield_outputs(
                request.token_address,
                allocation.amount,
                unshield_to,
                allocation.change,
                &receiver,
                None,
                &viewing.viewing_private_key,
            )?;
            if chunk_change_note.is_some() {
                change_note = chunk_change_note.clone();
            }
            unshield_notes.push(unshield_note);
            unproven_plans.push(plan_builder.build_unproven_unshield(
                request,
                outputs,
                commitment_ciphertext,
                unshield_notes.last().expect("pushed unshield note"),
                Some(&mut input_witness_cache),
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

        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let first_chunk = chunks.first().expect("fee selection has one chunk").clone();
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
            .expect("action selection has at least one chunk")
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
            broadcaster_fee_note: Some(broadcaster_fee_note),
            unshield_note,
            unshield_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_send_batch_with_separate_fee_token(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        fee_selection: UtxoSelection,
        action_selection: BatchUtxoSelection,
        request: SendRequest,
        fee: BroadcasterFeeOutput,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        let total_started = Instant::now();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let setup_started = Instant::now();
        let sender = viewing.address_data();
        let fee_change = fee_selection.total - fee.amount;
        let setup_elapsed_ms = setup_started.elapsed().as_millis();
        let fee_plan_builder = TransactionPlanBuilder::new(
            self,
            viewing,
            signer,
            forest,
            prover,
            fee_selection.utxos,
            fee.token_address,
        )?;
        let fee_outputs_started = Instant::now();
        let FeeOnlyOutputs {
            outputs,
            commitment_ciphertext,
            broadcaster_fee_note,
            mut change_note,
        } = build_fee_only_outputs(fee, fee_change, &sender, &viewing.viewing_private_key)?;
        let fee_outputs_elapsed_ms = fee_outputs_started.elapsed().as_millis();
        let fee_unproven_started = Instant::now();
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            request.min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut input_witness_cache),
        )?;
        let fee_unproven_elapsed_ms = fee_unproven_started.elapsed().as_millis();

        let allocations_started = Instant::now();
        let allocations = spend_allocations(
            &action_selection,
            request.amount,
            U256::ZERO,
            None,
            request.spend_up_to,
        )?;
        let allocations_elapsed_ms = allocations_started.elapsed().as_millis();
        let mut unproven_plans = Vec::with_capacity(1 + action_selection.chunks.len());
        unproven_plans.push(fee_unproven_plan);
        let mut recipient_notes = Vec::with_capacity(action_selection.chunks.len());
        let mut action_outputs_elapsed_ms = 0_u128;
        let mut action_unproven_elapsed_ms = 0_u128;

        for (chunk, allocation) in action_selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                prover,
                chunk.utxos,
                request.token_address,
            )?;
            let action_outputs_started = Instant::now();
            let SendOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: _,
                recipient_note,
                change_note: chunk_change_note,
            } = build_send_outputs(
                request.token_address,
                allocation.amount,
                allocation.change,
                &sender,
                &request.recipient,
                None,
                &viewing.viewing_private_key,
            )?;
            action_outputs_elapsed_ms += action_outputs_started.elapsed().as_millis();
            if chunk_change_note.is_some() {
                change_note = chunk_change_note.clone();
            }
            recipient_notes.push(recipient_note);
            let action_unproven_started = Instant::now();
            unproven_plans.push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
                Some(&mut input_witness_cache),
            )?);
            action_unproven_elapsed_ms += action_unproven_started.elapsed().as_millis();
        }

        let prove_started = Instant::now();
        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }
        let prove_elapsed_ms = prove_started.elapsed().as_millis();

        let first_chunk = chunks.first().expect("fee selection has one chunk").clone();
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
            .expect("action selection has at least one chunk")
            .clone();

        let abi_started = Instant::now();
        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let abi_elapsed_ms = abi_started.elapsed().as_millis();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };
        let witness_stats = input_witness_cache.stats();
        tracing::debug!(
            transaction_count = chunks.len(),
            setup_elapsed_ms,
            fee_outputs_elapsed_ms,
            fee_unproven_elapsed_ms,
            allocations_elapsed_ms,
            action_outputs_elapsed_ms,
            action_unproven_elapsed_ms,
            prove_elapsed_ms,
            abi_elapsed_ms,
            input_witness_proofs = witness_stats.proof_count,
            input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
            input_witness_dense_tree_build_elapsed_ms = witness_stats.dense_tree_build_elapsed_ms,
            elapsed_ms = total_started.elapsed().as_millis(),
            "built separate-fee send batch"
        );

        Ok(SendPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: Some(broadcaster_fee_note),
            recipient_note,
            recipient_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
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
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.same_token_broadcaster_fee(),
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
                Some(&mut input_witness_cache),
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

        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
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
        let total_started = Instant::now();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let allocations_started = Instant::now();
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.same_token_broadcaster_fee(),
            request.spend_up_to,
        )?;
        let allocations_elapsed_ms = allocations_started.elapsed().as_millis();
        let sender = viewing.address_data();
        let mut unproven_plans = Vec::with_capacity(selection.chunks.len());
        let mut broadcaster_fee_note = None;
        let mut recipient_notes = Vec::with_capacity(selection.chunks.len());
        let mut change_note = None;
        let mut outputs_elapsed_ms = 0_u128;
        let mut unproven_elapsed_ms = 0_u128;

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
            let outputs_started = Instant::now();
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
            outputs_elapsed_ms += outputs_started.elapsed().as_millis();
            if broadcaster_fee_note.is_none() {
                broadcaster_fee_note = chunk_fee_note;
            }
            if chunk_change_note.is_some() {
                change_note = chunk_change_note.clone();
            }
            recipient_notes.push(recipient_note);
            let unproven_started = Instant::now();
            unproven_plans.push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
                Some(&mut input_witness_cache),
            )?);
            unproven_elapsed_ms += unproven_started.elapsed().as_millis();
        }

        let prove_started = Instant::now();
        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }
        let prove_elapsed_ms = prove_started.elapsed().as_millis();

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

        let abi_started = Instant::now();
        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let abi_elapsed_ms = abi_started.elapsed().as_millis();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };
        let witness_stats = input_witness_cache.stats();
        tracing::debug!(
            transaction_count = chunks.len(),
            allocations_elapsed_ms,
            outputs_elapsed_ms,
            unproven_elapsed_ms,
            prove_elapsed_ms,
            abi_elapsed_ms,
            input_witness_proofs = witness_stats.proof_count,
            input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
            input_witness_dense_tree_build_elapsed_ms = witness_stats.dense_tree_build_elapsed_ms,
            elapsed_ms = total_started.elapsed().as_millis(),
            "built send batch"
        );

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

#[derive(Debug, Default, Clone, Copy)]
struct InputWitnessProofCacheStats {
    proof_count: usize,
    dense_tree_build_count: usize,
    dense_tree_build_elapsed_ms: u128,
}

struct InputWitnessProofCache<'a> {
    forest: &'a MerkleForest,
    dense_trees: BTreeMap<u32, DenseMerkleTree>,
    stats: InputWitnessProofCacheStats,
}

impl<'a> InputWitnessProofCache<'a> {
    fn new(forest: &'a MerkleForest) -> Self {
        Self {
            forest,
            dense_trees: BTreeMap::new(),
            stats: InputWitnessProofCacheStats::default(),
        }
    }

    fn prove(&mut self, tree_number: u32, tree_position: u64) -> Result<MerkleProof, BuildError> {
        let (normalized_tree, normalized_position) =
            normalize_tree_position(tree_number, tree_position);
        if !self.forest.contains_tree(normalized_tree) {
            return Err(BuildError::MissingProof {
                tree: tree_number,
                position: tree_position,
            });
        }

        if !self.dense_trees.contains_key(&normalized_tree) {
            let build_started = Instant::now();
            let dense_tree =
                DenseMerkleTree::from_forest_prefix(self.forest, normalized_tree, TREE_LEAF_COUNT);
            self.stats.dense_tree_build_elapsed_ms += build_started.elapsed().as_millis();
            self.stats.dense_tree_build_count += 1;
            self.dense_trees.insert(normalized_tree, dense_tree);
        }
        self.stats.proof_count += 1;
        Ok(self
            .dense_trees
            .get(&normalized_tree)
            .expect("dense tree inserted")
            .prove(normalized_position))
    }

    const fn stats(&self) -> InputWitnessProofCacheStats {
        self.stats
    }
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

struct PreparedTransactionPlan {
    plan: UnprovenTransactionPlan,
    public_inputs: PublicInputs,
    signature: [U256; 3],
    started: Instant,
    public_inputs_elapsed_ms: u128,
    signature_elapsed_ms: u128,
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
    fn build_input_witnesses(
        &self,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<Vec<InputWitness>, BuildError> {
        if let Some(proof_cache) = proof_cache {
            return self
                .inputs
                .iter()
                .map(|utxo| {
                    proof_cache
                        .prove(utxo.tree, utxo.position)
                        .map(|proof| InputWitness {
                            utxo: utxo.clone(),
                            merkle_proof: proof,
                        })
                })
                .collect();
        }

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

    /// Build witnesses and derive the public root from their proofs.
    fn build_input_witnesses_and_root(
        &self,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<(Vec<InputWitness>, U256), BuildError> {
        let inputs = self.build_input_witnesses(proof_cache)?;
        let root = inputs
            .first()
            .map(|input| input.merkle_proof.root)
            .ok_or(BuildError::MissingRoot)?;
        Ok((inputs, root))
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
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
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
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
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

    fn build_unproven_fee_only(
        self,
        token_address: Address,
        min_gas_price: u128,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
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
        .with_min_gas_price(min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };
        let private_inputs =
            PrivateInputs::from_inputs(token_address, &inputs, &outputs, self.viewing, self.signer);

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
        let (inputs, root) = self.build_input_witnesses_and_root(None)?;

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

        // Build inputs from the same proof-derived root used in the transaction.
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

struct FeeOnlyOutputs {
    outputs: Vec<Note>,
    commitment_ciphertext: Vec<NoteCiphertext>,
    broadcaster_fee_note: Note,
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

fn prepare_transaction_plan(
    plan: UnprovenTransactionPlan,
    signer: &impl RailgunSpendSigner,
) -> PreparedTransactionPlan {
    let started = Instant::now();
    let public_inputs_started = Instant::now();
    let public_inputs =
        PublicInputs::from_transaction(plan.merkle_root, &plan.transaction, &plan.outputs);
    let public_inputs_elapsed_ms = public_inputs_started.elapsed().as_millis();
    let signature_started = Instant::now();
    let signature = public_inputs.signature(signer);
    let signature_elapsed_ms = signature_started.elapsed().as_millis();
    PreparedTransactionPlan {
        plan,
        public_inputs,
        signature,
        started,
        public_inputs_elapsed_ms,
        signature_elapsed_ms,
    }
}

async fn prove_transaction_plans(
    plans: Vec<UnprovenTransactionPlan>,
    signer: &impl RailgunSpendSigner,
    prover: &ProverService,
    verify_proof: bool,
) -> Result<Vec<ProvenTransactionPlan>, BuildError> {
    let plan_count = plans.len();
    if plan_count == 0 {
        return Ok(Vec::new());
    }
    let prepared_plans = plans
        .into_iter()
        .map(|plan| prepare_transaction_plan(plan, signer))
        .collect::<Vec<_>>();

    if plan_count == 1 {
        let proven = prove_prepared_transaction_plan(
            prepared_plans.into_iter().next().expect("one plan"),
            prover,
            verify_proof,
        )
        .await?;
        return Ok(vec![proven]);
    }

    let mut handles = Vec::with_capacity(plan_count);
    for (index, prepared) in prepared_plans.into_iter().enumerate() {
        let prover = prover.clone();
        handles.push(tokio::spawn(async move {
            prove_prepared_transaction_plan(prepared, &prover, verify_proof)
                .await
                .map(|proven| (index, proven))
        }));
    }

    let mut proven_plans = std::iter::repeat_with(|| None)
        .take(plan_count)
        .collect::<Vec<_>>();
    for handle in handles {
        let (index, proven) = handle.await.map_err(join_error_to_prover_error)??;
        proven_plans[index] = Some(proven);
    }

    Ok(proven_plans
        .into_iter()
        .map(|proven| proven.expect("all plans proved"))
        .collect())
}

async fn prove_prepared_transaction_plan(
    prepared: PreparedTransactionPlan,
    prover: &ProverService,
    verify_proof: bool,
) -> Result<ProvenTransactionPlan, BuildError> {
    let mut plan = prepared.plan;
    let public_inputs = prepared.public_inputs;
    let signature = prepared.signature;
    let prove_started = Instant::now();
    let proof = prover
        .prove_unshield(
            &public_inputs,
            &plan.private_inputs,
            &signature,
            verify_proof,
        )
        .await?;
    let prove_elapsed_ms = prove_started.elapsed().as_millis();
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
    tracing::debug!(
        tree_number = plan.tree_number,
        input_count = chunk.inputs.len(),
        output_count = chunk.outputs.len(),
        has_unshield = chunk.has_unshield,
        public_inputs_elapsed_ms = prepared.public_inputs_elapsed_ms,
        signature_elapsed_ms = prepared.signature_elapsed_ms,
        prove_elapsed_ms,
        elapsed_ms = prepared.started.elapsed().as_millis(),
        "proved transaction plan"
    );
    Ok(ProvenTransactionPlan {
        transaction: plan.transaction,
        chunk,
    })
}

pub fn join_error_to_prover_error(error: tokio::task::JoinError) -> ProverError {
    ProverError::WorkerPanic(error.to_string())
}

fn push_broadcaster_fee_output(
    outputs: &mut Vec<Note>,
    commitment_ciphertext: &mut Vec<NoteCiphertext>,
    sender: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<Option<Note>, BuildError> {
    let Some(fee) = broadcaster_fee else {
        return Ok(None);
    };
    let note = Note::new_change(
        fee.recipient.master_public_key,
        fee.token_address,
        fee.amount,
        rand_array(),
    );
    let ciphertext =
        NoteCiphertext::try_from_note(&note, sender, &fee.recipient, sender_viewing_private_key)?;
    outputs.push(note.clone());
    commitment_ciphertext.push(ciphertext);
    Ok(Some(note))
}

fn build_fee_only_outputs(
    broadcaster_fee: BroadcasterFeeOutput,
    change: U256,
    sender: &AddressData,
    sender_viewing_private_key: &[u8; 32],
) -> Result<FeeOnlyOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(!change.is_zero()));
    let mut commitment_ciphertext = Vec::with_capacity(outputs.capacity());
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        sender,
        Some(broadcaster_fee),
        sender_viewing_private_key,
    )?
    .expect("broadcaster fee is provided");

    let mut change_note = None;
    if !change.is_zero() {
        let note = Note::new_change(
            sender.master_public_key,
            broadcaster_fee.token_address,
            change,
            rand_array(),
        );
        let ciphertext =
            NoteCiphertext::try_from_note(&note, sender, sender, sender_viewing_private_key)?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        change_note = Some(note);
    }

    Ok(FeeOnlyOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        change_note,
    })
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

fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests;
