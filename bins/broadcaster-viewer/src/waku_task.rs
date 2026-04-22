use std::sync::Arc;
use std::time::{Duration, SystemTime};

use eyre::{Result, WrapErr};
use tokio::sync::mpsc;
use waku::PeerSnapshot;
use waku::proto::WakuMessage;
use waku_relay::client::{Client, PUBSUB_PATH};

use crate::cli::{
    DEFAULT_CLUSTER_ID, DEFAULT_DOH_ENDPOINT, DEFAULT_MAX_PEERS,
    DEFAULT_PEER_CONNECTION_TIMEOUT_SECS, Options,
};
use crate::state::{EventTx, FeeRow, LogEntry, PeerRow, PeerSummary, Shared, ViewerEvent};

/// Interval for refreshing peer snapshots from the Waku node.
const PEER_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Build a `config::Waku` from parsed CLI options. The viewer intentionally
/// does not load a broadcaster config file; every Waku input is CLI-driven
/// and falls back to the design-document defaults when the flag is omitted.
pub(crate) fn waku_config_from_cli(opts: &Options) -> config::Waku {
    let doh = opts
        .doh_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_DOH_ENDPOINT.to_string());
    let timeout = opts
        .peer_connection_timeout
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_PEER_CONNECTION_TIMEOUT_SECS));

    config::Waku {
        nwaku_url: opts.nwaku_url.clone(),
        direct_peers: Vec::new(),
        dns_enr_trees: None,
        doh_endpoint: Some(doh),
        cluster_id: Some(opts.cluster_id.unwrap_or(DEFAULT_CLUSTER_ID)),
        max_peers: Some(opts.max_peers.unwrap_or(DEFAULT_MAX_PEERS)),
        peer_connection_timeout: Some(humantime_serde::Serde::from(timeout)),
    }
}

/// Construct and start the viewer's Waku client from CLI inputs.
pub(crate) fn build_waku_client(opts: &Options) -> Result<Arc<Client>> {
    let cfg = waku_config_from_cli(opts);
    let client = Client::new(&cfg).wrap_err("construct waku relay client")?;
    Ok(Arc::new(client))
}

/// Spawn the viewer's background Waku + fees workers on the current runtime.
pub(crate) async fn spawn_workers(
    opts: Options,
    waku: Arc<Client>,
    shared: Shared,
    events: EventTx,
) -> Result<()> {
    let chain_ids = opts.effective_chain_ids();
    let content_topics: Vec<String> = chain_ids
        .iter()
        .map(|chain_id| format!("/railgun/v2/0-{chain_id}-fees/json"))
        .collect();

    tracing::info!(
        chains = ?chain_ids,
        topics = ?content_topics,
        "subscribing to broadcaster fees content topics"
    );

    let msg_rx = waku
        .subscribe(PUBSUB_PATH, content_topics)
        .await
        .wrap_err("subscribe to fees content topics")?;

    // Fees message pipeline.
    {
        let shared = shared.clone();
        let events = events.clone();
        tokio::spawn(async move {
            run_fees_loop(msg_rx, shared, events).await;
        });
    }

    // Periodic peer snapshot poller.
    {
        let shared = shared.clone();
        let events = events.clone();
        let waku = waku.clone();
        tokio::spawn(async move {
            run_peer_poll_loop(waku, shared, events).await;
        });
    }

    Ok(())
}

async fn run_fees_loop(mut msg_rx: mpsc::Receiver<WakuMessage>, shared: Shared, events: EventTx) {
    while let Some(msg) = msg_rx.recv().await {
        let Some(chain_id) = extract_fees_chain_id(&msg.content_topic) else {
            tracing::trace!(topic = %msg.content_topic, "ignoring non-fees content topic");
            continue;
        };
        handle_fees_message(chain_id, &msg.payload, &shared, &events);
    }
    tracing::warn!("fees subscription channel closed");
}

/// Decode one fees `WakuMessage` payload and emit one row per token fee.
/// Returns the number of rows produced (for testability).
pub(crate) fn handle_fees_message(
    chain_id: u64,
    payload: &[u8],
    shared: &Shared,
    events: &EventTx,
) -> usize {
    let payload: fees::Payload = match serde_json::from_slice(payload) {
        Ok(p) => p,
        Err(error) => {
            tracing::warn!(%error, chain_id, "failed to decode fees envelope");
            return 0;
        }
    };

    let (body, signature_valid) = match payload.decode_and_verify() {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, chain_id, "failed to verify fees payload");
            return 0;
        }
    };

    let railgun_address: Arc<str> = Arc::from(body.railgun_address.as_ref());
    let fees_id: Arc<str> = Arc::from(body.fees_id.as_str());
    let identifier: Option<Arc<str>> = body.identifier.map(|s| Arc::from(s.as_str()));
    let fee_expiration = SystemTime::UNIX_EPOCH + Duration::from_millis(body.fee_expiration);
    let now = SystemTime::now();

    let mut produced = 0;
    for (token_address, fee) in body.fees {
        let row = FeeRow {
            chain_id,
            railgun_address: railgun_address.clone(),
            token_address,
            fee,
            signature_valid,
            fees_id: fees_id.clone(),
            fee_expiration,
            identifier: identifier.clone(),
            last_seen: now,
            reliability: body.reliability,
        };
        shared.write().upsert_fee(row.clone());
        let _ = events.try_send(ViewerEvent::FeeRow(row));
        produced += 1;
    }
    produced
}

/// Extract the chain id from a `/railgun/v2/0-{chain_id}-fees/json` topic.
/// Returns `None` for non-fees topics.
pub(crate) fn extract_fees_chain_id(topic: &str) -> Option<u64> {
    let rest = topic.strip_prefix("/railgun/v2/0-")?;
    let chain = rest.strip_suffix("-fees/json")?;
    chain.parse::<u64>().ok()
}

async fn run_peer_poll_loop(waku: Arc<Client>, shared: Shared, events: EventTx) {
    let mut ticker = tokio::time::interval(PEER_POLL_INTERVAL);
    loop {
        ticker.tick().await;
        let stats = waku.peer_stats();
        let snapshots = waku.peer_snapshots();
        let summary = PeerSummary {
            connected: stats.connected_peers.len(),
            known: stats.known_peers,
            dialing: stats.dialing_count,
            lightpush_capable: stats.lightpush_capable,
            peer_exchange_capable: stats.peer_exchange_capable,
        };
        let rows: Vec<PeerRow> = snapshots.iter().map(peer_row_from_snapshot).collect();

        shared.write().set_peers(summary.clone(), rows.clone());
        let _ = events.try_send(ViewerEvent::Peers { summary, rows });
    }
}

pub(crate) fn peer_row_from_snapshot(snapshot: &PeerSnapshot) -> PeerRow {
    PeerRow {
        peer_id: Arc::from(snapshot.peer_id.to_string().as_str()),
        addrs: snapshot
            .addrs
            .iter()
            .map(|a| Arc::from(a.to_string().as_str()))
            .collect(),
        connected: snapshot.connected,
        dialing: snapshot.dialing,
        supports_lightpush_v3: snapshot.supports_lightpush_v3,
        supports_peer_exchange: snapshot.supports_peer_exchange,
        supports_filter: snapshot.supports_filter,
        dial_failures: snapshot.dial_failures,
    }
}

// Silence `LogEntry` dead-code until the UI consumes it.
#[allow(dead_code)]
fn _log_entry_use(_: LogEntry) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{event_channel, shared};
    use structopt::StructOpt;

    #[test]
    fn extract_fees_chain_id_matches_valid_topic() {
        assert_eq!(extract_fees_chain_id("/railgun/v2/0-1-fees/json"), Some(1));
        assert_eq!(
            extract_fees_chain_id("/railgun/v2/0-42161-fees/json"),
            Some(42161)
        );
    }

    #[test]
    fn extract_fees_chain_id_rejects_non_fees_topics() {
        assert_eq!(extract_fees_chain_id("/railgun/v2/0-1-transact/json"), None);
        assert_eq!(extract_fees_chain_id("/other/v2/0-1-fees/json"), None);
        assert_eq!(extract_fees_chain_id("/railgun/v2/0-NaN-fees/json"), None);
    }

    #[test]
    fn peer_row_is_derived_from_snapshot_fields() {
        use libp2p::PeerId;
        let pid = PeerId::random();
        let snap = PeerSnapshot {
            peer_id: pid,
            addrs: Vec::new(),
            connected: true,
            dialing: false,
            supports_lightpush_v3: true,
            supports_peer_exchange: false,
            supports_filter: true,
            dial_failures: 2,
        };
        let row = peer_row_from_snapshot(&snap);
        assert_eq!(row.peer_id.as_ref(), pid.to_string());
        assert!(row.connected);
        assert!(!row.dialing);
        assert!(row.supports_lightpush_v3);
        assert!(!row.supports_peer_exchange);
        assert!(row.supports_filter);
        assert_eq!(row.dial_failures, 2);
    }

    #[test]
    fn waku_config_defaults_apply_when_flags_are_absent() {
        let opts = Options::from_iter_safe(["broadcaster-viewer"]).unwrap();
        let cfg = waku_config_from_cli(&opts);
        assert_eq!(cfg.cluster_id, Some(DEFAULT_CLUSTER_ID));
        assert_eq!(cfg.max_peers, Some(DEFAULT_MAX_PEERS));
        assert_eq!(cfg.doh_endpoint.as_deref(), Some(DEFAULT_DOH_ENDPOINT));
        assert_eq!(
            cfg.peer_connection_timeout
                .map(humantime_serde::Serde::into_inner),
            Some(Duration::from_secs(DEFAULT_PEER_CONNECTION_TIMEOUT_SECS))
        );
        assert!(cfg.direct_peers.is_empty());
        assert!(cfg.dns_enr_trees.is_none());
    }

    #[test]
    fn waku_config_overrides_apply_when_flags_present() {
        let opts = Options::from_iter_safe([
            "broadcaster-viewer",
            "--cluster-id",
            "7",
            "--max-peers",
            "42",
            "--doh-endpoint",
            "https://example.invalid/dns-query",
            "--peer-connection-timeout",
            "3s",
            "--nwaku-url",
            "http://127.0.0.1:8645",
        ])
        .unwrap();
        let cfg = waku_config_from_cli(&opts);
        assert_eq!(cfg.cluster_id, Some(7));
        assert_eq!(cfg.max_peers, Some(42));
        assert_eq!(
            cfg.doh_endpoint.as_deref(),
            Some("https://example.invalid/dns-query")
        );
        assert_eq!(
            cfg.peer_connection_timeout
                .map(humantime_serde::Serde::into_inner),
            Some(Duration::from_secs(3))
        );
        assert_eq!(cfg.nwaku_url.as_deref(), Some("http://127.0.0.1:8645"));
    }

    #[test]
    fn handle_fees_message_rejects_invalid_json_without_producing_rows() {
        let shared = shared(16);
        let (tx, _rx) = event_channel(16);
        let produced = handle_fees_message(1, b"not-json", &shared, &tx);
        assert_eq!(produced, 0);
        assert!(shared.read().fee_rows().is_empty());
    }
}
