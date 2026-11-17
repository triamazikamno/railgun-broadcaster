//! The fee-note assurance worker, and the in-memory fallback that holds
//! records the submitter could not persist.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::DbStore;
use tracing::{Instrument, error, info, info_span, warn};

use crate::fee_note_assurance::{
    FeeNoteAssuranceRecordOutcome, FeeNoteAssuranceSubmissionTracker,
    process_fee_note_assurance_record,
};
use crate::fee_note_store::{FeeNoteAssuranceDbExt, PendingFeeNoteAssuranceRecord};
use crate::{BroadcasterPoiValidator, BroadcasterService};

impl BroadcasterService {
    pub fn spawn_fee_note_assurance_worker(&self) {
        let Some(poi) = self.poi.clone() else {
            return;
        };
        let Some(railgun_contract) = self.railgun_contract else {
            return;
        };
        let Some(finality_depth) = self.finality_depth else {
            return;
        };

        let chain_id = self.chain_id;
        let worker = FeeNoteAssuranceWorker {
            db: self.db.clone(),
            pending_fee_note_assurance_fallback: self.pending_fee_note_assurance_fallback.clone(),
            fee_note_assurance_submission_tracker: self
                .fee_note_assurance_submission_tracker
                .clone(),
            query_rpc_pool: self.query_rpc_pool.clone(),
            poi,
            railgun_contract,
            finality_depth,
            chain_id,
            poll_interval: self.receipt_poll_interval,
        };

        tokio::spawn(
            worker
                .run()
                .instrument(info_span!("fee_note_assurance", chain_id)),
        );
    }
}

struct FeeNoteAssuranceWorker {
    db: Arc<DbStore>,
    pending_fee_note_assurance_fallback: Arc<FeeNoteAssuranceFallback>,
    fee_note_assurance_submission_tracker: Arc<FeeNoteAssuranceSubmissionTracker>,
    query_rpc_pool: Arc<QueryRpcPool>,
    poi: Arc<BroadcasterPoiValidator>,
    railgun_contract: Address,
    finality_depth: u64,
    chain_id: u64,
    poll_interval: Duration,
}

impl FeeNoteAssuranceWorker {
    async fn run(self) {
        let mut interval = tokio::time::interval(self.poll_interval);
        loop {
            interval.tick().await;
            self.process_once().await;
        }
    }

    /// Persists fallback records, then processes every pending record once.
    async fn process_once(&self) {
        let chain_id = self.chain_id;
        self.pending_fee_note_assurance_fallback
            .try_persist(self.db.as_ref(), chain_id);

        let db_records = match self.db.list_pending_fee_note_assurance(chain_id) {
            Ok(records) => records,
            Err(error) => {
                error!(?error, chain_id, "list fee-note assurance records failed");
                return;
            }
        };
        let records = collect_pending_fee_note_assurance_records(
            db_records,
            self.pending_fee_note_assurance_fallback.snapshot(),
        );

        for (record, was_fallback_only) in records {
            let outcome = process_fee_note_assurance_record(
                self.db.as_ref(),
                self.query_rpc_pool.as_ref(),
                self.poi.as_ref(),
                self.fee_note_assurance_submission_tracker.as_ref(),
                self.railgun_contract,
                self.finality_depth,
                record.clone(),
            )
            .await;
            if should_remove_fee_note_assurance_fallback(outcome, was_fallback_only) {
                self.pending_fee_note_assurance_fallback
                    .remove(&record.public_tx_hash);
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct FeeNoteAssuranceFallback {
    records: Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>,
}

impl FeeNoteAssuranceFallback {
    pub(crate) fn insert(&self, record: PendingFeeNoteAssuranceRecord) {
        let mut records = self
            .records
            .lock()
            .expect("fee-note assurance fallback poisoned");
        records.insert(record.public_tx_hash, record);
    }

    fn snapshot(&self) -> Vec<PendingFeeNoteAssuranceRecord> {
        let records = self
            .records
            .lock()
            .expect("fee-note assurance fallback poisoned");
        records.values().cloned().collect()
    }

    fn remove(&self, public_tx_hash: &FixedBytes<32>) {
        let mut records = self
            .records
            .lock()
            .expect("fee-note assurance fallback poisoned");
        records.remove(public_tx_hash);
    }

    fn try_persist(&self, db: &DbStore, chain_id: u64) {
        for record in self.snapshot() {
            match db.put_pending_fee_note_assurance(&record) {
                Ok(()) => {
                    info!(
                        chain_id,
                        tx_hash = %record.public_tx_hash,
                        "persisted fallback fee-note assurance record"
                    );
                    self.remove(&record.public_tx_hash);
                }
                Err(error) => {
                    warn!(
                        ?error,
                        chain_id,
                        tx_hash = %record.public_tx_hash,
                        "persist fallback fee-note assurance record failed"
                    );
                }
            }
        }
    }
}

fn collect_pending_fee_note_assurance_records(
    db_records: Vec<PendingFeeNoteAssuranceRecord>,
    fallback_records: Vec<PendingFeeNoteAssuranceRecord>,
) -> Vec<(PendingFeeNoteAssuranceRecord, bool)> {
    let mut records = HashMap::with_capacity(db_records.len() + fallback_records.len());
    for record in fallback_records {
        records.insert(record.public_tx_hash, (record, true));
    }
    for record in db_records {
        records.insert(record.public_tx_hash, (record, false));
    }
    records.into_values().collect()
}

const fn should_remove_fee_note_assurance_fallback(
    record_outcome: FeeNoteAssuranceRecordOutcome,
    was_fallback_only: bool,
) -> bool {
    was_fallback_only
        && matches!(
            record_outcome,
            FeeNoteAssuranceRecordOutcome::Completed | FeeNoteAssuranceRecordOutcome::Terminal
        )
}

#[cfg(test)]
mod tests;
