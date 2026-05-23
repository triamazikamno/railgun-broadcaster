use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::poi::SignedBlockedShield;

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
    pub fn new(
        format_version: u16,
        list_key: &[u8; 32],
        chain_id: u64,
        chain_type: u8,
        upstream_endpoint_hash: &[u8; 32],
        mut blocked_shields: Vec<BlockedShieldArtifactRecord>,
    ) -> Self {
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

    #[must_use]
    pub fn from_signed_records(
        format_version: u16,
        list_key: &[u8; 32],
        chain_id: u64,
        chain_type: u8,
        upstream_endpoint_hash: &[u8; 32],
        records: &[SignedBlockedShield],
    ) -> Self {
        Self::new(
            format_version,
            list_key,
            chain_id,
            chain_type,
            upstream_endpoint_hash,
            records
                .iter()
                .map(BlockedShieldArtifactRecord::from)
                .collect(),
        )
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

impl BlockedShieldArtifactRecord {
    #[must_use]
    pub fn into_signed_blocked_shield(self) -> SignedBlockedShield {
        SignedBlockedShield {
            commitment_hash: self.commitment_hash,
            blinded_commitment: self.blinded_commitment,
            block_reason: self.block_reason,
            signature: self.signature,
        }
    }
}

impl From<&SignedBlockedShield> for BlockedShieldArtifactRecord {
    fn from(record: &SignedBlockedShield) -> Self {
        Self {
            commitment_hash: record.commitment_hash.clone(),
            blinded_commitment: record.blinded_commitment.clone(),
            signature: record.signature.clone(),
            block_reason: record.block_reason.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum BlockedShieldsArtifactError {
    #[error("blocked-shields artifact JSON serialization failed")]
    Json(#[from] serde_json::Error),
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_bytes_are_deterministic_and_sorted() {
        let artifact = BlockedShieldsArtifact::from_signed_records(
            2,
            &[9; 32],
            1,
            0,
            &[7; 32],
            &[
                blocked_shield(2, Some("second")),
                blocked_shield(1, Some("first")),
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
        let artifact = BlockedShieldsArtifact::from_signed_records(
            2,
            &[9; 32],
            1,
            0,
            &[7; 32],
            &[blocked_shield(1, None), blocked_shield(2, Some(""))],
        );

        let decoded = BlockedShieldsArtifact::read(&artifact.to_bytes().expect("encode artifact"))
            .expect("decode artifact");

        assert_eq!(decoded.blocked_shields[0].block_reason, None);
        assert_eq!(decoded.blocked_shields[1].block_reason.as_deref(), Some(""));
    }

    fn blocked_shield(byte: u8, block_reason: Option<&str>) -> SignedBlockedShield {
        SignedBlockedShield {
            commitment_hash: prefixed_hex(&[byte + 10; 32]),
            blinded_commitment: prefixed_hex(&[byte; 32]),
            block_reason: block_reason.map(ToString::to_string),
            signature: prefixed_hex(&[byte + 20; 64]),
        }
    }
}
