use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use parking_lot::RwLock;
use ruint::aliases::U256;
use tokio::sync::mpsc;
use tracing::Level;

/// Maximum number of retained log lines kept in the bounded in-memory ring.
pub(crate) const DEFAULT_LOG_CAPACITY: usize = 2_000;

/// Identifier for a single fee row, keyed by chain, broadcaster, and token.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct FeeRowKey {
    pub(crate) chain_id: u64,
    pub(crate) railgun_address: Arc<str>,
    pub(crate) token_address: Address,
}

/// Snapshot of the latest fee entry for a single `(chain, broadcaster, token)` tuple.
///
/// String-ish fields use `Arc<str>` so the UI's per-render clone of the row
/// list is a cheap refcount bump instead of a heap allocation per field.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct FeeRow {
    pub(crate) chain_id: u64,
    pub(crate) railgun_address: Arc<str>,
    pub(crate) token_address: Address,
    pub(crate) fee: U256,
    pub(crate) signature_valid: bool,
    pub(crate) fees_id: Arc<str>,
    pub(crate) fee_expiration: SystemTime,
    /// Optional broadcaster identifier from the fees payload. Shared across
    /// all rows of a single message, so `Arc<str>` keeps per-row clones cheap.
    pub(crate) identifier: Option<Arc<str>>,
    /// Local unix-millis timestamp when this row was last updated.
    pub(crate) last_seen: SystemTime,
    pub(crate) reliability: f64,
}

/// Aggregate peer statistics mirrored from the Waku node for the UI header.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct PeerSummary {
    pub(crate) connected: usize,
    pub(crate) known: usize,
    pub(crate) dialing: usize,
    pub(crate) lightpush_capable: usize,
    pub(crate) peer_exchange_capable: usize,
}

/// Read-only per-peer row derived from `waku::PeerSnapshot` for the peers pane.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PeerRow {
    pub(crate) peer_id: Arc<str>,
    pub(crate) addrs: Vec<Arc<str>>,
    pub(crate) connected: bool,
    pub(crate) dialing: bool,
    pub(crate) supports_lightpush_v3: bool,
    pub(crate) supports_peer_exchange: bool,
    pub(crate) supports_filter: bool,
    pub(crate) dial_failures: u32,
}

/// Single retained log line from the viewer's in-memory tracing layer.
///
/// `seq` is currently written-only; retained for future sort / diff work.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct LogEntry {
    pub(crate) seq: u64,
    pub(crate) unix_ms: u64,
    pub(crate) level: Level,
    pub(crate) target: Arc<str>,
    pub(crate) message: Arc<str>,
}

/// Events emitted by background workers into the viewer pipeline.
///
/// The channel is bounded; workers should treat `try_send` failure as
/// backpressure and drop non-critical updates rather than blocking. The UI
/// drains the channel so producers never block, but currently re-renders
/// from `Shared` on its own tick and does not read payloads directly.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ViewerEvent {
    FeeRow(FeeRow),
    Peers {
        summary: PeerSummary,
        rows: Vec<PeerRow>,
    },
    Log(LogEntry),
}

/// Mutable shared state read by the UI and mutated by background events.
///
/// `rev` is a monotonic counter bumped on any user-visible state change.
/// The UI task gates `cx.notify()` on this counter so idle wakeups (e.g. a
/// peer poll that produced identical data) don't trigger a full gpui layout
/// + Metal present cycle.
pub(crate) struct AppState {
    fees: HashMap<FeeRowKey, FeeRow>,
    peer_summary: PeerSummary,
    peer_rows: Vec<PeerRow>,
    logs: VecDeque<LogEntry>,
    log_capacity: usize,
    log_seq: AtomicU64,
    rev: AtomicU64,
}

impl AppState {
    #[must_use]
    pub(crate) fn new(log_capacity: usize) -> Self {
        Self {
            fees: HashMap::new(),
            peer_summary: PeerSummary::default(),
            peer_rows: Vec::new(),
            logs: VecDeque::with_capacity(log_capacity),
            log_capacity,
            log_seq: AtomicU64::new(0),
            rev: AtomicU64::new(0),
        }
    }

    /// Current user-visible state revision. Increases by at least one on any
    /// change that should trigger a UI redraw; unchanged otherwise.
    pub(crate) fn rev(&self) -> u64 {
        self.rev.load(Ordering::Acquire)
    }

    fn bump_rev(&self) {
        self.rev.fetch_add(1, Ordering::Release);
    }

    /// Monotonically increasing sequence number for new log entries.
    pub(crate) fn next_log_seq(&self) -> u64 {
        self.log_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn upsert_fee(&mut self, row: FeeRow) {
        let key = FeeRowKey {
            chain_id: row.chain_id,
            railgun_address: row.railgun_address.clone(),
            token_address: row.token_address,
        };
        self.fees.insert(key, row);
        self.bump_rev();
    }

    pub(crate) fn set_peers(&mut self, summary: PeerSummary, rows: Vec<PeerRow>) {
        if self.peer_summary == summary && self.peer_rows == rows {
            return;
        }
        self.peer_summary = summary;
        self.peer_rows = rows;
        self.bump_rev();
    }

    pub(crate) fn push_log(&mut self, entry: LogEntry) {
        if self.logs.len() == self.log_capacity {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
        self.bump_rev();
    }

    #[must_use]
    pub(crate) fn fee_rows(&self) -> Vec<FeeRow> {
        self.fees.values().cloned().collect()
    }

    #[must_use]
    pub(crate) fn peer_summary(&self) -> PeerSummary {
        self.peer_summary.clone()
    }

    #[must_use]
    pub(crate) fn peer_rows(&self) -> Vec<PeerRow> {
        self.peer_rows.clone()
    }

    #[must_use]
    pub(crate) fn logs(&self) -> Vec<LogEntry> {
        self.logs.iter().cloned().collect()
    }

    #[must_use]
    #[allow(dead_code)] // still consumed by tests asserting bounded retention
    pub(crate) const fn log_capacity(&self) -> usize {
        self.log_capacity
    }
}

/// Shared handle for the viewer's mutable state.
pub(crate) type Shared = Arc<RwLock<AppState>>;

/// Build a fresh shared state container with the given bounded log capacity.
#[must_use]
pub(crate) fn shared(log_capacity: usize) -> Shared {
    Arc::new(RwLock::new(AppState::new(log_capacity)))
}

/// Event channel used between background tasks and the UI polling path.
pub(crate) type EventTx = mpsc::Sender<ViewerEvent>;
pub(crate) type EventRx = mpsc::Receiver<ViewerEvent>;

#[must_use]
pub(crate) fn event_channel(capacity: usize) -> (EventTx, EventRx) {
    mpsc::channel(capacity)
}

/// Wall-clock unix-millis helper used by event producers.
#[must_use]
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    fn sample_row(chain_id: u64, token: Address, fee: u64, fees_id: &str) -> FeeRow {
        FeeRow {
            chain_id,
            railgun_address: Arc::from("0zk-test"),
            token_address: token,
            fee: U256::from(fee),
            signature_valid: true,
            fees_id: Arc::from(fees_id),
            fee_expiration: SystemTime::now(),
            identifier: None,
            last_seen: SystemTime::now(),
            reliability: 1.0,
        }
    }

    #[test]
    fn upsert_replaces_existing_row_for_same_key() {
        let mut state = AppState::new(16);
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
        assert_eq!(row.fee, U256::from(200));
        assert_eq!(row.fees_id.as_ref(), "b");
    }

    #[test]
    fn upsert_keeps_separate_rows_per_token() {
        let mut state = AppState::new(16);
        let t1 = address!("0000000000000000000000000000000000000001");
        let t2 = address!("0000000000000000000000000000000000000002");
        state.upsert_fee(sample_row(1, t1, 100, "a"));
        state.upsert_fee(sample_row(1, t2, 200, "b"));
        assert_eq!(state.fee_rows().len(), 2);
    }

    #[test]
    fn upsert_keeps_separate_rows_per_chain() {
        let mut state = AppState::new(16);
        let token = address!("0000000000000000000000000000000000000001");
        state.upsert_fee(sample_row(1, token, 100, "a"));
        state.upsert_fee(sample_row(137, token, 200, "b"));
        assert_eq!(state.fee_rows().len(), 2);
    }

    #[test]
    fn log_ring_drops_oldest_when_full() {
        let mut state = AppState::new(3);
        for i in 0..5_u64 {
            state.push_log(LogEntry {
                seq: i,
                unix_ms: i,
                level: Level::INFO,
                target: Arc::from("t"),
                message: Arc::from(format!("msg-{i}")),
            });
        }
        let logs = state.logs();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs.first().unwrap().seq, 2);
        assert_eq!(logs.last().unwrap().seq, 4);
    }

    #[test]
    fn log_capacity_reports_configured_value() {
        let state = AppState::new(128);
        assert_eq!(state.log_capacity(), 128);
    }
}
