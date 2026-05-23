use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use alloy::primitives::Address;
use parking_lot::RwLock;
use ruint::aliases::U256;
use tokio::sync::watch;

pub const DEFAULT_EVENT_CAPACITY: usize = 1_024;

/// Identifier for a single fee row, keyed by chain, broadcaster, and token.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct FeeRowKey {
    pub chain_id: u64,
    pub railgun_address: Arc<str>,
    pub token_address: Address,
}

/// Snapshot of the latest fee entry for a single `(chain, broadcaster, token)` tuple.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FeeRow {
    pub chain_id: u64,
    pub railgun_address: Arc<str>,
    pub token_address: Address,
    pub fee: U256,
    pub signature_valid: bool,
    pub fees_id: Arc<str>,
    pub fee_expiration: SystemTime,
    pub available_wallets: u32,
    pub version: Arc<str>,
    pub relay_adapt: Address,
    pub relay_adapt_7702: Option<Address>,
    pub required_poi_list_keys: Vec<Arc<str>>,
    pub identifier: Option<Arc<str>>,
    pub last_seen: SystemTime,
    pub reliability: f64,
}

/// Aggregate peer statistics mirrored from the Waku node for the UI header.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PeerSummary {
    pub connected: usize,
    pub known: usize,
    pub dialing: usize,
    pub lightpush_capable: usize,
    pub peer_exchange_capable: usize,
    pub network_label: Arc<str>,
    pub network_degraded: bool,
}

/// Read-only per-peer row derived from Waku peer state for the peers pane.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerRow {
    pub peer_id: Arc<str>,
    pub addrs: Vec<Arc<str>>,
    pub connected: bool,
    pub dialing: bool,
    pub supports_lightpush_v3: bool,
    pub supports_peer_exchange: bool,
    pub supports_filter: bool,
    pub dial_failures: u32,
}

/// Mutable broadcaster monitor state read by the UI and mutated by background events.
pub struct MonitorState {
    fees: HashMap<FeeRowKey, FeeRow>,
    peer_summary: PeerSummary,
    peer_rows: Vec<PeerRow>,
    rev: AtomicU64,
}

impl MonitorState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fees: HashMap::new(),
            peer_summary: PeerSummary::default(),
            peer_rows: Vec::new(),
            rev: AtomicU64::new(0),
        }
    }

    /// Current user-visible state revision. Increases on changes that should redraw the UI.
    #[must_use]
    pub fn rev(&self) -> u64 {
        self.rev.load(Ordering::Acquire)
    }

    fn bump_rev(&self) -> u64 {
        self.rev.fetch_add(1, Ordering::Release) + 1
    }

    pub fn upsert_fee(&mut self, row: FeeRow) -> u64 {
        let key = FeeRowKey {
            chain_id: row.chain_id,
            railgun_address: row.railgun_address.clone(),
            token_address: row.token_address,
        };
        self.fees.insert(key, row);
        self.bump_rev()
    }

    pub fn set_peers(&mut self, summary: PeerSummary, rows: Vec<PeerRow>) -> Option<u64> {
        if self.peer_summary == summary && self.peer_rows == rows {
            return None;
        }
        self.peer_summary = summary;
        self.peer_rows = rows;
        Some(self.bump_rev())
    }

    pub fn clear(&mut self) -> u64 {
        self.fees.clear();
        self.peer_summary = PeerSummary::default();
        self.peer_rows.clear();
        self.bump_rev()
    }

    #[must_use]
    pub fn fee_rows(&self) -> Vec<FeeRow> {
        self.fees.values().cloned().collect()
    }

    #[must_use]
    pub fn peer_summary(&self) -> PeerSummary {
        self.peer_summary.clone()
    }

    #[must_use]
    pub fn peer_rows(&self) -> Vec<PeerRow> {
        self.peer_rows.clone()
    }
}

impl Default for MonitorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle for the broadcaster monitor's mutable state.
pub type Shared = Arc<RwLock<MonitorState>>;

/// Build a fresh shared state container.
#[must_use]
pub fn shared() -> Shared {
    Arc::new(RwLock::new(MonitorState::new()))
}

/// Revision signal used between background tasks and the UI polling path.
pub type EventTx = watch::Sender<u64>;
pub type EventRx = watch::Receiver<u64>;

#[must_use]
pub fn event_channel(_capacity: usize) -> (EventTx, EventRx) {
    watch::channel(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::uint;

    fn sample_row(chain_id: u64, token: Address, fee: u64, fees_id: &str) -> FeeRow {
        sample_row_with_metadata(chain_id, token, fee, fees_id, 1, "8.2.3", Vec::new())
    }

    fn sample_row_with_metadata(
        chain_id: u64,
        token: Address,
        fee: u64,
        fees_id: &str,
        available_wallets: u32,
        version: &str,
        required_poi_list_keys: Vec<Arc<str>>,
    ) -> FeeRow {
        FeeRow {
            chain_id,
            railgun_address: Arc::from("0zk-test"),
            token_address: token,
            fee: U256::from(fee),
            signature_valid: true,
            fees_id: Arc::from(fees_id),
            fee_expiration: SystemTime::now(),
            available_wallets,
            version: Arc::from(version),
            relay_adapt: address!("0000000000000000000000000000000000000003"),
            relay_adapt_7702: Some(address!("0000000000000000000000000000000000000004")),
            required_poi_list_keys,
            identifier: None,
            last_seen: SystemTime::now(),
            reliability: 1.0,
        }
    }

    #[test]
    fn upsert_replaces_existing_row_for_same_key() {
        let mut state = MonitorState::new();
        let token = address!("0000000000000000000000000000000000000001");
        state.upsert_fee(sample_row(1, token, 100, "a"));
        state.upsert_fee(sample_row(1, token, 200, "b"));

        let rows = state.fee_rows();
        assert_eq!(
            rows.len(),
            1,
            "same (chain, broadcaster, token) must not duplicate"
        );
        let row = &rows[0];
        assert_eq!(row.fee, uint!(200_U256));
        assert_eq!(row.fees_id.as_ref(), "b");
    }

    #[test]
    fn upsert_replaces_metadata_for_same_key() {
        let mut state = MonitorState::new();
        let token = address!("0000000000000000000000000000000000000001");
        state.upsert_fee(sample_row_with_metadata(
            1,
            token,
            100,
            "a",
            0,
            "7.9.0",
            Vec::new(),
        ));
        state.upsert_fee(sample_row_with_metadata(
            1,
            token,
            200,
            "b",
            2,
            "8.2.3",
            vec![Arc::from("poi-list")],
        ));

        let rows = state.fee_rows();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.available_wallets, 2);
        assert_eq!(row.version.as_ref(), "8.2.3");
        assert_eq!(row.required_poi_list_keys, vec![Arc::from("poi-list")]);
    }

    #[test]
    fn upsert_keeps_separate_rows_per_token() {
        let mut state = MonitorState::new();
        let t1 = address!("0000000000000000000000000000000000000001");
        let t2 = address!("0000000000000000000000000000000000000002");
        state.upsert_fee(sample_row(1, t1, 100, "a"));
        state.upsert_fee(sample_row(1, t2, 200, "b"));
        assert_eq!(state.fee_rows().len(), 2);
    }

    #[test]
    fn upsert_keeps_separate_rows_per_chain() {
        let mut state = MonitorState::new();
        let token = address!("0000000000000000000000000000000000000001");
        state.upsert_fee(sample_row(1, token, 100, "a"));
        state.upsert_fee(sample_row(137, token, 200, "b"));
        assert_eq!(state.fee_rows().len(), 2);
    }
}
