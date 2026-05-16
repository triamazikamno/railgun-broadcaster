use crate::blocked::{BlockedShieldsArtifact, BlockedShieldsArtifactError};
use crate::snapshot::format::FORMAT_VERSION;
use crate::snapshot::{SnapshotError, SnapshotHeaderInput, SnapshotKind, SnapshotWriter};
use crate::store::{Store, StoreError};
use alloy_primitives::FixedBytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Lifecycle {
    store: Store,
    upstream_url: String,
    chain_type: u8,
    upstream_endpoint_hash: [u8; 32],
}

impl Lifecycle {
    #[must_use]
    pub const fn new(
        store: Store,
        upstream_url: String,
        chain_type: u8,
        upstream_endpoint_hash: [u8; 32],
    ) -> Self {
        Self {
            store,
            upstream_url,
            chain_type,
            upstream_endpoint_hash,
        }
    }

    pub async fn build_base(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        end_index: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        let events = self
            .store
            .page_event_range(list_key, chain_id, 0, end_index)
            .await?;
        let header = self
            .snapshot_header(list_key, chain_id, SnapshotKind::Base, 0, end_index)
            .await?;
        SnapshotWriter::write(&header, &events).map_err(LifecycleError::Snapshot)
    }

    pub async fn build_delta(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        let events = self
            .store
            .page_event_range(list_key, chain_id, start_index, end_index)
            .await?;
        let header = self
            .snapshot_header(
                list_key,
                chain_id,
                SnapshotKind::Delta,
                start_index,
                end_index,
            )
            .await?;
        SnapshotWriter::write(&header, &events).map_err(LifecycleError::Snapshot)
    }

    pub async fn build_blocked_shields_artifact(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
    ) -> Result<BlockedShieldsArtifact, LifecycleError> {
        let blocked_shields = self.store.all_blocked_shields(list_key, chain_id).await?;
        Ok(BlockedShieldsArtifact::from_records(
            FORMAT_VERSION,
            &fixed_bytes(list_key),
            chain_id,
            self.chain_type,
            &self.upstream_endpoint_hash,
            &blocked_shields,
        ))
    }

    #[must_use]
    pub fn should_publish_delta(
        current_tip: u64,
        last_published_delta_tip: Option<u64>,
        last_published_at: Option<SystemTime>,
        now: SystemTime,
        delta_publish_interval: Duration,
    ) -> bool {
        let tip_advanced = last_published_delta_tip.is_none_or(|tip| current_tip > tip);
        let interval_elapsed = last_published_at.is_none_or(|published_at| {
            now.duration_since(published_at)
                .is_ok_and(|elapsed| elapsed >= delta_publish_interval)
        });
        tip_advanced && interval_elapsed
    }

    #[must_use]
    pub fn should_rebuild_base(
        last_base_at: Option<SystemTime>,
        now: SystemTime,
        base_rebuild_interval: Duration,
    ) -> bool {
        last_base_at.is_none_or(|published_at| {
            now.duration_since(published_at)
                .is_ok_and(|elapsed| elapsed >= base_rebuild_interval)
        })
    }

    async fn snapshot_header(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
    ) -> Result<SnapshotHeaderInput, LifecycleError> {
        let tip = self
            .store
            .chain_tip(list_key, chain_id, &self.upstream_url)
            .await?
            .ok_or(LifecycleError::MissingChainTip { chain_id })?;
        if tip.last_event_index < end_index {
            return Err(LifecycleError::TipBeforeSnapshotEnd {
                tip_index: tip.last_event_index,
                end_index,
            });
        }
        let tip_merkleroot = tip
            .last_tip_merkleroot
            .ok_or(LifecycleError::MissingTipMerkleroot)?;

        Ok(SnapshotHeaderInput {
            list_key: fixed_bytes(list_key),
            chain_id,
            chain_type: self.chain_type,
            kind,
            start_index,
            end_index,
            tip_merkleroot,
            upstream_endpoint_hash: self.upstream_endpoint_hash,
            created_at_unix_seconds: unix_now()?,
        })
    }
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("store operation failed")]
    Store(#[from] StoreError),
    #[error("snapshot encode failed")]
    Snapshot(#[from] SnapshotError),
    #[error("blocked-shields artifact encode failed")]
    BlockedShieldsArtifact(#[from] BlockedShieldsArtifactError),
    #[error("missing chain tip for chain_id={chain_id}")]
    MissingChainTip { chain_id: u64 },
    #[error("chain tip is missing tip merkleroot")]
    MissingTipMerkleroot,
    #[error("chain tip {tip_index} is before requested snapshot end {end_index}")]
    TipBeforeSnapshotEnd { tip_index: u64, end_index: u64 },
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("system clock is before unix epoch")]
    TimeBeforeUnixEpoch(#[source] std::time::SystemTimeError),
}

const fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}

fn unix_now() -> Result<i64, LifecycleError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(LifecycleError::TimeBeforeUnixEpoch)?;
    i64::try_from(duration.as_secs()).map_err(|_| LifecycleError::InvalidByteLen {
        field: "created_at_unix_seconds",
        expected: std::mem::size_of::<i64>(),
        actual: std::mem::size_of::<u64>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_publish_requires_tip_advance_and_elapsed_interval() {
        let now = UNIX_EPOCH + Duration::from_secs(100);

        assert!(Lifecycle::should_publish_delta(
            10,
            Some(9),
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_publish_delta(
            10,
            Some(10),
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_publish_delta(
            11,
            Some(10),
            Some(UNIX_EPOCH + Duration::from_secs(90)),
            now,
            Duration::from_secs(30),
        ));
    }

    #[test]
    fn base_rebuild_requires_elapsed_interval() {
        let now = UNIX_EPOCH + Duration::from_secs(100);

        assert!(Lifecycle::should_rebuild_base(
            Some(UNIX_EPOCH + Duration::from_secs(50)),
            now,
            Duration::from_secs(30),
        ));
        assert!(!Lifecycle::should_rebuild_base(
            Some(UNIX_EPOCH + Duration::from_secs(90)),
            now,
            Duration::from_secs(30),
        ));
    }
}
