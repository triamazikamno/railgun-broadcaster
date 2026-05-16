use crate::store::StoredBlockedShield;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedShieldsArtifact {
    pub format_version: u16,
    pub list_key: String,
    pub chain_id: u64,
    pub chain_type: u8,
    pub upstream_endpoint_hash: String,
    pub blocked_shields: Vec<BlockedShieldArtifactRecord>,
}

impl BlockedShieldsArtifact {
    #[must_use]
    pub fn from_records(
        format_version: u16,
        list_key: &[u8; 32],
        chain_id: u64,
        chain_type: u8,
        upstream_endpoint_hash: &[u8; 32],
        records: &[StoredBlockedShield],
    ) -> Self {
        let mut blocked_shields = records
            .iter()
            .map(BlockedShieldArtifactRecord::from)
            .collect::<Vec<_>>();
        blocked_shields.sort_by(|left, right| {
            left.blinded_commitment
                .cmp(&right.blinded_commitment)
                .then_with(|| left.commitment_hash.cmp(&right.commitment_hash))
        });

        Self {
            format_version,
            list_key: prefixed_hex(list_key),
            chain_id,
            chain_type,
            upstream_endpoint_hash: prefixed_hex(upstream_endpoint_hash),
            blocked_shields,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BlockedShieldsArtifactError> {
        serde_json::to_vec(self).map_err(BlockedShieldsArtifactError::Json)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, BlockedShieldsArtifactError> {
        serde_json::from_slice(bytes).map_err(BlockedShieldsArtifactError::Json)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedShieldArtifactRecord {
    pub commitment_hash: String,
    pub blinded_commitment: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,
}

impl From<&StoredBlockedShield> for BlockedShieldArtifactRecord {
    fn from(record: &StoredBlockedShield) -> Self {
        Self {
            commitment_hash: prefixed_hex(&record.commitment_hash),
            blinded_commitment: prefixed_hex(&record.blinded_commitment),
            signature: prefixed_hex(&record.signature),
            block_reason: record.block_reason.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum BlockedShieldsArtifactError {
    #[error("blocked-shields artifact JSON serialization failed")]
    Json(#[from] serde_json::Error),
}

#[must_use]
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_bytes_are_deterministic_and_sorted() {
        let artifact = BlockedShieldsArtifact::from_records(
            2,
            &[9; 32],
            1,
            0,
            &[7; 32],
            &[
                stored_blocked_shield(2, Some("second")),
                stored_blocked_shield(1, Some("first")),
            ],
        );

        let bytes = artifact.to_bytes().expect("encode artifact");
        let decoded = BlockedShieldsArtifact::read(&bytes).expect("decode artifact");

        assert_eq!(
            decoded.blocked_shields[0].blinded_commitment,
            prefixed_hex(&[1; 32])
        );
        assert_eq!(
            decoded.blocked_shields[1].blinded_commitment,
            prefixed_hex(&[2; 32])
        );
        assert_eq!(decoded.to_bytes().expect("re-encode artifact"), bytes);
    }

    #[test]
    fn artifact_roundtrip_distinguishes_absent_reason_from_empty() {
        let artifact = BlockedShieldsArtifact::from_records(
            2,
            &[9; 32],
            1,
            0,
            &[7; 32],
            &[
                stored_blocked_shield(1, None),
                stored_blocked_shield(2, Some("")),
            ],
        );

        let decoded = BlockedShieldsArtifact::read(&artifact.to_bytes().expect("encode artifact"))
            .expect("decode artifact");

        assert_eq!(decoded.blocked_shields[0].block_reason, None);
        assert_eq!(decoded.blocked_shields[1].block_reason.as_deref(), Some(""));
    }

    fn stored_blocked_shield(byte: u8, block_reason: Option<&str>) -> StoredBlockedShield {
        StoredBlockedShield {
            commitment_hash: [byte + 10; 32],
            blinded_commitment: [byte; 32],
            block_reason: block_reason.map(ToString::to_string),
            signature: [byte + 20; 64],
        }
    }
}
