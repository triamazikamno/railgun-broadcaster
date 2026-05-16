use alloy_primitives::FixedBytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub type SharedStatus = Arc<RwLock<Status>>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub pairs: Vec<PairSyncStatus>,
    pub last_published_manifest_cid: Option<String>,
    pub ipfs_reachable: bool,
}

impl Status {
    #[must_use]
    pub fn for_pairs(
        list_keys: &[FixedBytes<32>],
        chain_ids: &[u64],
        initial_page_size: usize,
    ) -> Self {
        let pairs = list_keys
            .iter()
            .flat_map(|list_key| {
                chain_ids.iter().map(|chain_id| {
                    PairSyncStatus::new(list_key_hex(list_key), *chain_id, initial_page_size)
                })
            })
            .collect();

        Self {
            pairs,
            last_published_manifest_cid: None,
            ipfs_reachable: false,
        }
    }

    #[must_use]
    pub fn shared(self) -> SharedStatus {
        Arc::new(RwLock::new(self))
    }

    pub fn record_page_success(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        last_event_index: u64,
        current_page_size: usize,
    ) {
        let now = unix_now();
        let pair = self.ensure_pair(list_key, chain_id, current_page_size);
        pair.last_event_index = Some(last_event_index);
        pair.last_successful_page_unix_seconds = Some(now);
        pair.seconds_since_last_page = Some(0);
        pair.current_page_size = current_page_size;
        pair.retry_backoff = RetryBackoffStatus::idle();
    }

    pub fn record_page_failure(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        current_page_size: usize,
        attempts: usize,
        next_backoff: Option<Duration>,
        error: String,
    ) {
        let pair = self.ensure_pair(list_key, chain_id, current_page_size);
        pair.current_page_size = current_page_size;
        pair.retry_backoff = RetryBackoffStatus {
            state: if next_backoff.is_some() {
                RetryBackoffState::BackingOff
            } else {
                RetryBackoffState::Failed
            },
            attempts,
            next_backoff_seconds: next_backoff.map(|duration| duration.as_secs()),
            last_error: Some(error),
        };
    }

    pub fn record_manifest_publication(&mut self, manifest_cid: impl Into<String>) {
        self.last_published_manifest_cid = Some(manifest_cid.into());
        self.ipfs_reachable = true;
    }

    pub const fn set_ipfs_reachable(&mut self, reachable: bool) {
        self.ipfs_reachable = reachable;
    }

    #[must_use]
    pub fn snapshot_at(&self, now: SystemTime) -> Self {
        let now = unix_seconds(now);
        let mut status = self.clone();
        for pair in &mut status.pairs {
            pair.seconds_since_last_page = pair
                .last_successful_page_unix_seconds
                .and_then(|last_page| now.checked_sub(last_page))
                .and_then(|seconds| u64::try_from(seconds).ok());
        }
        status
    }

    fn ensure_pair(
        &mut self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        initial_page_size: usize,
    ) -> &mut PairSyncStatus {
        let list_key = list_key_hex(list_key);
        if let Some(index) = self
            .pairs
            .iter()
            .position(|pair| pair.list_key == list_key && pair.chain_id == chain_id)
        {
            return &mut self.pairs[index];
        }

        self.pairs
            .push(PairSyncStatus::new(list_key, chain_id, initial_page_size));
        self.pairs
            .last_mut()
            .expect("just pushed pair status must exist")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairSyncStatus {
    pub list_key: String,
    pub chain_id: u64,
    pub last_event_index: Option<u64>,
    pub last_successful_page_unix_seconds: Option<i64>,
    pub seconds_since_last_page: Option<u64>,
    pub current_page_size: usize,
    pub retry_backoff: RetryBackoffStatus,
}

impl PairSyncStatus {
    #[must_use]
    pub const fn new(list_key: String, chain_id: u64, current_page_size: usize) -> Self {
        Self {
            list_key,
            chain_id,
            last_event_index: None,
            last_successful_page_unix_seconds: None,
            seconds_since_last_page: None,
            current_page_size,
            retry_backoff: RetryBackoffStatus::idle(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBackoffStatus {
    pub state: RetryBackoffState,
    pub attempts: usize,
    pub next_backoff_seconds: Option<u64>,
    pub last_error: Option<String>,
}

impl RetryBackoffStatus {
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            state: RetryBackoffState::Idle,
            attempts: 0,
            next_backoff_seconds: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryBackoffState {
    Idle,
    BackingOff,
    Failed,
}

fn list_key_hex(list_key: &FixedBytes<32>) -> String {
    format!("0x{}", hex::encode(list_key.as_slice()))
}

fn unix_now() -> i64 {
    unix_seconds(SystemTime::now())
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_snapshot_refreshes_time_since_last_page() {
        let list_key = FixedBytes::from([1_u8; 32]);
        let mut status = Status::for_pairs(&[list_key], &[1], 500);

        status.record_page_success(&list_key, 1, 9, 250);
        status.pairs[0].last_successful_page_unix_seconds = Some(100);

        let snapshot = status.snapshot_at(UNIX_EPOCH + Duration::from_secs(130));

        assert_eq!(snapshot.pairs[0].last_event_index, Some(9));
        assert_eq!(snapshot.pairs[0].seconds_since_last_page, Some(30));
        assert_eq!(snapshot.pairs[0].current_page_size, 250);
        assert_eq!(
            snapshot.pairs[0].retry_backoff.state,
            RetryBackoffState::Idle
        );
    }
}
