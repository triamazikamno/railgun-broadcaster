use std::io::Cursor;

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::FeeNoteAssuranceContext;
use local_db::{AppTable, DbError, DbStore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// Persisted table names; existing broadcaster databases depend on these exact strings.
const PENDING_FEE_NOTE_ASSURANCE_TABLE: AppTable = AppTable::new("fee_note_assurance_pending");
const TERMINAL_FEE_NOTE_ASSURANCE_TABLE: AppTable = AppTable::new("fee_note_assurance_terminal");

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum FeeNoteAssuranceTerminalOutcome {
    RevertedReceipt,
    CommitmentMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingFeeNoteAssuranceRecord {
    pub chain_id: u64,
    pub public_tx_hash: FixedBytes<32>,
    pub context: FeeNoteAssuranceContext,
}

impl PendingFeeNoteAssuranceRecord {
    fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.public_tx_hash)
    }

    fn key_for(chain_id: u64, public_tx_hash: &FixedBytes<32>) -> String {
        format!("{chain_id}|{}", hex::encode(public_tx_hash))
    }

    fn prefix_for_chain(chain_id: u64) -> String {
        format!("{chain_id}|")
    }
}

#[derive(Serialize)]
struct TerminalFeeNoteAssuranceRecord {
    chain_id: u64,
    public_tx_hash: FixedBytes<32>,
    context: FeeNoteAssuranceContext,
    outcome: FeeNoteAssuranceTerminalOutcome,
}

pub(crate) trait FeeNoteAssuranceDbExt {
    fn put_pending_fee_note_assurance(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
    ) -> Result<(), DbError>;
    fn delete_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<(), DbError>;
    fn list_pending_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<PendingFeeNoteAssuranceRecord>, DbError>;
    /// Moves the pending record to the terminal table in one write transaction.
    fn mark_fee_note_assurance_terminal(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
        outcome: FeeNoteAssuranceTerminalOutcome,
    ) -> Result<(), DbError>;
}

impl FeeNoteAssuranceDbExt for DbStore {
    fn put_pending_fee_note_assurance(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
    ) -> Result<(), DbError> {
        let data = rmp_serde::to_vec_named(record)?;
        self.write_app_tables(|writer| {
            writer.insert(PENDING_FEE_NOTE_ASSURANCE_TABLE, &record.key(), &data)
        })
    }

    fn delete_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        self.write_app_tables(|writer| {
            writer.remove(PENDING_FEE_NOTE_ASSURANCE_TABLE, &key)?;
            Ok(())
        })
    }

    fn list_pending_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<PendingFeeNoteAssuranceRecord>, DbError> {
        let prefix = PendingFeeNoteAssuranceRecord::prefix_for_chain(chain_id);
        let rows = self.read_app_tables(|reader| {
            reader.list_prefix(PENDING_FEE_NOTE_ASSURANCE_TABLE, &prefix)
        })?;
        rows.iter().map(|(_, value)| decode(value)).collect()
    }

    fn mark_fee_note_assurance_terminal(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
        outcome: FeeNoteAssuranceTerminalOutcome,
    ) -> Result<(), DbError> {
        let key = record.key();
        let data = rmp_serde::to_vec_named(&TerminalFeeNoteAssuranceRecord {
            chain_id: record.chain_id,
            public_tx_hash: record.public_tx_hash,
            context: record.context.clone(),
            outcome,
        })?;
        self.write_app_tables(|writer| {
            writer.remove(PENDING_FEE_NOTE_ASSURANCE_TABLE, &key)?;
            writer.insert(TERMINAL_FEE_NOTE_ASSURANCE_TABLE, &key, &data)
        })
    }
}

// Same strict decoding local-db applied when it owned these tables: trailing bytes are an error.
fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, DbError> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(data));
    let value = T::deserialize(&mut deserializer)?;
    if deserializer.get_ref().position() != u64::try_from(data.len()).unwrap_or(u64::MAX) {
        return Err(rmp_serde::decode::Error::Syntax(
            "trailing bytes after MessagePack value".to_string(),
        )
        .into());
    }
    Ok(value)
}
