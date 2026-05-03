pub mod types;

use alloy::sol_types::{Error as SolError, SolEvent};
use alloy_rpc_types_eth::Log;
use thiserror::Error;

use crate::errors::SyncError;
use crate::tree::MerkleForest;
use types::{
    CommitmentBatch, GeneratedCommitmentBatch, IntoCommitmentUpdates, Shield, ShieldLegacyPreMar23,
    Transact,
};

#[derive(Debug, Error)]
pub enum CommitmentUpdateError {
    #[error("decode log: {0}")]
    Decode(#[from] SolError),
    #[error("apply commitment updates: {0}")]
    Update(#[from] SyncError),
}

pub fn apply_commitment_updates_from_logs(
    forest: &mut MerkleForest,
    logs: &[Log],
) -> Result<(), CommitmentUpdateError> {
    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = Transact::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = Shield::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == ShieldLegacyPreMar23::SIGNATURE_HASH {
            let event = ShieldLegacyPreMar23::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
            let event = CommitmentBatch::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
            let event = GeneratedCommitmentBatch::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        }
    }
    Ok(())
}
