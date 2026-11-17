use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::Provider;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::Transact;
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::tree::TREE_LEAF_COUNT_U256;
use local_db::DbStore;
use poi::poi::PoiStatus;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::fee_note_store::{
    FeeNoteAssuranceDbExt, FeeNoteAssuranceTerminalOutcome, PendingFeeNoteAssuranceRecord,
};
use crate::poi_validation::BroadcasterPoiValidator;

const FEE_NOTE_ASSURANCE_SUBMIT_BACKOFF: Duration = Duration::from_mins(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivedFeeOutputPosition {
    pub utxo_tree_out: u64,
    pub utxo_position_out: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReceiptObservation {
    pub block_number: u64,
    pub status: bool,
    pub logs: Vec<Log>,
}

impl ReceiptObservation {
    pub(crate) fn evaluate(
        &self,
        safe_head: u64,
        railgun_contract: Address,
        fee_commitment: FixedBytes<32>,
    ) -> ReceiptEvaluation {
        if self.block_number > safe_head {
            return ReceiptEvaluation::Pending;
        }

        if !self.status {
            return ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::RevertedReceipt);
        }

        match derive_fee_output_position_from_logs(&self.logs, railgun_contract, fee_commitment) {
            Some(output) => ReceiptEvaluation::Ready(output),
            None => {
                ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::CommitmentMismatch)
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct FeeNoteAssuranceSubmissionTracker {
    logged_submissions: Mutex<HashSet<FixedBytes<32>>>,
    submission_attempts: Mutex<HashMap<FixedBytes<32>, Instant>>,
}

impl FeeNoteAssuranceSubmissionTracker {
    pub(crate) fn mark_logged(&self, public_tx_hash: FixedBytes<32>) -> bool {
        let mut logged_submissions = self
            .logged_submissions
            .lock()
            .expect("fee-note assurance submission log set poisoned");
        logged_submissions.insert(public_tx_hash)
    }

    pub(crate) fn next_submit_in(
        &self,
        public_tx_hash: FixedBytes<32>,
        now: Instant,
        backoff: Duration,
    ) -> Option<Duration> {
        let submission_attempts = self
            .submission_attempts
            .lock()
            .expect("fee-note assurance submission attempt map poisoned");
        submission_attempts
            .get(&public_tx_hash)
            .and_then(|last_attempt| backoff.checked_sub(now.duration_since(*last_attempt)))
    }

    pub(crate) fn mark_attempt(&self, public_tx_hash: FixedBytes<32>, now: Instant) {
        let mut submission_attempts = self
            .submission_attempts
            .lock()
            .expect("fee-note assurance submission attempt map poisoned");
        submission_attempts.insert(public_tx_hash, now);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptEvaluation {
    Pending,
    Ready(DerivedFeeOutputPosition),
    Terminal(FeeNoteAssuranceTerminalOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeeNoteAssuranceRecordOutcome {
    Pending,
    Completed,
    Terminal,
}

pub(crate) async fn process_fee_note_assurance_record(
    db: &DbStore,
    query_rpc_pool: &QueryRpcPool,
    poi: &BroadcasterPoiValidator,
    submission_tracker: &FeeNoteAssuranceSubmissionTracker,
    railgun_contract: Address,
    finality_depth: u64,
    record: PendingFeeNoteAssuranceRecord,
) -> FeeNoteAssuranceRecordOutcome {
    let Some(provider_handle) = query_rpc_pool.random_provider() else {
        warn!(
            chain_id = record.chain_id,
            tx_hash = %record.public_tx_hash,
            "no query rpc available for fee-note assurance"
        );
        return FeeNoteAssuranceRecordOutcome::Pending;
    };

    let head = match provider_handle.provider.get_block_number().await {
        Ok(head) => head,
        Err(error) => {
            warn!(
                %error,
                rpc = %provider_handle.url,
                chain_id = record.chain_id,
                tx_hash = %record.public_tx_hash,
                "fetch latest block failed for fee-note assurance"
            );
            query_rpc_pool.mark_bad_provider(&provider_handle);
            return FeeNoteAssuranceRecordOutcome::Pending;
        }
    };
    let safe_head = head.saturating_sub(finality_depth);

    let receipt = match provider_handle
        .provider
        .get_transaction_receipt(record.public_tx_hash)
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!(
                %error,
                rpc = %provider_handle.url,
                chain_id = record.chain_id,
                tx_hash = %record.public_tx_hash,
                "fetch transaction receipt failed for fee-note assurance"
            );
            query_rpc_pool.mark_bad_provider(&provider_handle);
            return FeeNoteAssuranceRecordOutcome::Pending;
        }
    };

    let receipt_observation = receipt.as_ref().and_then(|receipt| {
        receipt.block_number.map(|block_number| ReceiptObservation {
            block_number,
            status: receipt.status(),
            logs: receipt.logs().to_vec(),
        })
    });

    match receipt_observation
        .as_ref()
        .map_or(ReceiptEvaluation::Pending, |receipt| {
            receipt.evaluate(safe_head, railgun_contract, record.context.fee_commitment)
        }) {
        ReceiptEvaluation::Pending => FeeNoteAssuranceRecordOutcome::Pending,
        ReceiptEvaluation::Terminal(reason) => {
            if let Err(error) = db.mark_fee_note_assurance_terminal(&record, reason) {
                error!(
                    ?error,
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    ?reason,
                    "persisting terminal fee-note assurance outcome failed"
                );
                FeeNoteAssuranceRecordOutcome::Pending
            } else {
                warn!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    ?reason,
                    "fee-note assurance reached a terminal non-retriable outcome"
                );
                FeeNoteAssuranceRecordOutcome::Terminal
            }
        }
        ReceiptEvaluation::Ready(output) => {
            let fee_blinded_commitment = derive_fee_note_blinded_commitment(
                record.context.fee_commitment,
                record.context.fee_note_npk,
                output.utxo_tree_out,
                output.utxo_position_out,
            );

            if let Ok(statuses) = poi
                .fee_note_statuses_for_blinded_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context.txid_version,
                    &record.context.required_poi_list_keys,
                    &fee_blinded_commitment,
                )
                .await
                && required_list_statuses_valid(&record.context.required_poi_list_keys, &statuses)
            {
                if let Err(error) =
                    db.delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
                {
                    error!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "deleting completed fee-note assurance record failed"
                    );
                    return FeeNoteAssuranceRecordOutcome::Pending;
                }
                info!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    "fee-note assurance already complete"
                );
                return FeeNoteAssuranceRecordOutcome::Completed;
            }

            let now = Instant::now();
            if let Some(next_submit_in) = submission_tracker.next_submit_in(
                record.public_tx_hash,
                now,
                FEE_NOTE_ASSURANCE_SUBMIT_BACKOFF,
            ) {
                debug!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    fee_blinded_commitment = %fee_blinded_commitment,
                    next_submit_in_secs = next_submit_in.as_secs(),
                    "fee-note assurance pending; submit backoff active"
                );
                return FeeNoteAssuranceRecordOutcome::Pending;
            }

            if let Err(error) = poi
                .submit_fee_note_single_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context,
                    output.utxo_tree_out,
                    output.utxo_position_out,
                )
                .await
            {
                warn!(
                    ?error,
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    utxo_tree_out = output.utxo_tree_out,
                    utxo_position_out = output.utxo_position_out,
                    "submit single-commitment fee-note POI failed; keeping record pending"
                );
                return FeeNoteAssuranceRecordOutcome::Pending;
            }

            submission_tracker.mark_attempt(record.public_tx_hash, now);

            if submission_tracker.mark_logged(record.public_tx_hash) {
                info!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    fee_blinded_commitment = %fee_blinded_commitment,
                    utxo_tree_out = output.utxo_tree_out,
                    utxo_position_out = output.utxo_position_out,
                    "submitted fee-note single-commitment poi"
                );
            }

            let statuses = match poi
                .fee_note_statuses_for_blinded_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context.txid_version,
                    &record.context.required_poi_list_keys,
                    &fee_blinded_commitment,
                )
                .await
            {
                Ok(statuses) => statuses,
                Err(error) => {
                    warn!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "query fee-note POI statuses failed after submission; keeping record pending"
                    );
                    return FeeNoteAssuranceRecordOutcome::Pending;
                }
            };

            if required_list_statuses_valid(&record.context.required_poi_list_keys, &statuses) {
                if let Err(error) =
                    db.delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
                {
                    error!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "deleting completed fee-note assurance record failed"
                    );
                    FeeNoteAssuranceRecordOutcome::Pending
                } else {
                    info!(
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "fee-note assurance completed"
                    );
                    FeeNoteAssuranceRecordOutcome::Completed
                }
            } else {
                debug!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    fee_blinded_commitment = %fee_blinded_commitment,
                    ?statuses,
                    "fee-note assurance still pending required POI validity"
                );
                FeeNoteAssuranceRecordOutcome::Pending
            }
        }
    }
}

pub(crate) fn required_list_statuses_valid(
    required_poi_list_keys: &[FixedBytes<32>],
    statuses: &BTreeMap<FixedBytes<32>, PoiStatus>,
) -> bool {
    required_poi_list_keys.iter().all(|list_key| {
        statuses
            .get(list_key)
            .is_some_and(|status| *status == PoiStatus::Valid)
    })
}

fn derive_fee_note_blinded_commitment(
    fee_commitment: FixedBytes<32>,
    fee_note_npk: FixedBytes<32>,
    utxo_tree_out: u64,
    utxo_position_out: u64,
) -> FixedBytes<32> {
    let global_tree_position =
        U256::from(utxo_tree_out) * TREE_LEAF_COUNT_U256 + U256::from(utxo_position_out);

    poseidon(vec![
        fee_commitment.into(),
        fee_note_npk.into(),
        global_tree_position,
    ])
    .into()
}

fn derive_fee_output_position_from_logs(
    logs: &[Log],
    railgun_contract: Address,
    fee_commitment: FixedBytes<32>,
) -> Option<DerivedFeeOutputPosition> {
    logs.iter()
        .filter(|log| log.address() == railgun_contract)
        .filter_map(|log| log.log_decode::<Transact>().ok())
        .find_map(|log| {
            let event = log.inner.data;
            (event.hash.first().copied() == Some(fee_commitment)).then(|| {
                DerivedFeeOutputPosition {
                    utxo_tree_out: event.treeNumber.to(),
                    utxo_position_out: event.startPosition.to(),
                }
            })
        })
}

#[cfg(test)]
mod tests;
