use crate::config::{NodeConfig, WakuConfig};
use crate::discovery;
use crate::discovery::{DiscoveryConfig};
use crate::error::WakuError;
use crate::proto;
use crate::proto::HashKey;
use crate::protocols;
use crate::protocols::filter::FilterPushAck;
use crate::transport::{ReqId, Transport, TransportCmd, TransportEvent};
use crate::types::OpId;
use libp2p::request_response::{OutboundFailure, ResponseChannel};
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Currently connected peer IDs.
    pub connected_peers: Vec<PeerId>,
    /// Total number of known peers (connected or not).
    pub known_peers: usize,
    /// Number of peers currently being dialed.
    pub dialing_count: usize,
    /// Number of connected peers that support `LightPush` v3.
    pub lightpush_capable: usize,
    /// Number of connected peers that support Peer Exchange.
    pub peer_exchange_capable: usize,
}

#[derive(Debug)]
pub struct LightPushResult {
    pub peer_id: PeerId,
    pub status_code: Option<u32>,
    pub status_desc: Option<String>,
    pub relay_peer_count: Option<u32>,
    pub error: Option<OutboundFailure>,
}

static LIGHTPUSH_UNIMPLEMENTED: OnceLock<proto::light_push::LightPushResponseV3> = OnceLock::new();
static PEER_EXCHANGE_EMPTY_RESPONSE: OnceLock<proto::peer_exchange::PeerExchangeRpc> =
    OnceLock::new();

#[derive(Debug, Default)]
struct PeerState {
    addrs: Vec<Multiaddr>,
    connected: bool,
    supports_lightpush_v3: bool,
    supports_peer_exchange: bool,
    supports_filter: bool,
    dial_failures: u32,
    next_dial_at: Option<Instant>,
    last_peer_exchange_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct PeerBook {
    peers: HashMap<PeerId, PeerState>,
    connected: HashSet<PeerId>,
    dialing: HashSet<PeerId>,
}

impl PeerBook {
    /// Get statistics about the current peer state.
    #[must_use]
    pub fn get_stats(&self) -> PeerStats {
        let connected_peers: Vec<PeerId> = self.connected.iter().copied().collect();
        let lightpush_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_lightpush_v3))
            .count();
        let peer_exchange_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_peer_exchange))
            .count();

        PeerStats {
            connected_peers,
            known_peers: self.peers.len(),
            dialing_count: self.dialing.len(),
            lightpush_capable,
            peer_exchange_capable,
        }
    }

    /// Get the list of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected.iter().copied().collect()
    }

    #[must_use]
    pub fn num_connections(&self) -> usize {
        self.connected.len() + self.dialing.len()
    }
}

#[derive(Debug)]
struct ResponseBatch<T> {
    expected: usize,
    finished: usize,
    results: Vec<T>,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct LightPushState {
    pending: HashMap<ReqId, (OpId, PeerId)>,
    ops: HashMap<OpId, ResponseBatch<LightPushResult>>,
    waiters: HashMap<OpId, oneshot::Sender<Vec<LightPushResult>>>,
}

#[derive(Debug)]
struct PeerExchangeOp {
    remaining_rounds: usize,
    current_batch: Option<usize>,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct PeerExchangeState {
    pending: HashMap<ReqId, usize>,
    ops: HashMap<usize, ResponseBatch<Vec<u8>>>,
    next_batch_id: usize,
    round_ops: HashMap<OpId, PeerExchangeOp>,
    waiters: HashMap<OpId, oneshot::Sender<()>>,
}

/// Unique identifier for a filter subscription.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SubId(u64);

impl SubId {
    fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

/// A single filter subscription.
#[derive(Debug)]
struct Subscription {
    pubsub_topic: String,
    content_topics: Vec<String>,
    sender: mpsc::Sender<proto::WakuMessage>,
}

#[derive(Debug)]
enum FilterOp {
    Subscribe {
        sub_id: SubId,
    },
    Unsubscribe {
        sub_id: SubId,
        batch_id: u64,
    },
    UnsubscribeAll {
        pubsub_topic: String,
        batch_id: u64,
    },
    #[allow(dead_code)]
    Ping,
    #[allow(dead_code)]
    SubscribeOnPeer {
        sub_id: SubId,
    },
}

#[derive(Debug)]
struct FilterBatch {
    expected: usize,
    finished: usize,
    succeeded: bool,
    waiter: oneshot::Sender<Result<(), WakuError>>,
    last_error: Option<WakuError>,
}

#[derive(Debug)]
struct FilterState {
    /// Active subscriptions by ID.
    subscriptions: HashMap<SubId, Subscription>,
    /// Pending outbound requests.
    pending: HashMap<ReqId, FilterOp>,
    /// Dedup cache: hash of (`content_topic`, `payload`).
    dedup_cache: LruCache<u64, ()>,
    /// Next subscription ID counter.
    next_sub_id: AtomicU64,
    /// Next batch ID counter.
    next_batch_id: AtomicU64,
    /// Pending unsubscribe batches.
    batches: HashMap<u64, FilterBatch>,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            subscriptions: HashMap::default(),
            pending: HashMap::default(),
            dedup_cache: LruCache::new(NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap()),
            next_sub_id: AtomicU64::default(),
            next_batch_id: AtomicU64::default(),
            batches: HashMap::default(),
        }
    }
}

struct OpTracker {
    next_req_id: AtomicU64,
    lightpush: Mutex<LightPushState>,
    peer_exchange: Mutex<PeerExchangeState>,
    filter: Mutex<FilterState>,
}

const DEDUP_CACHE_SIZE: usize = 500;

impl OpTracker {
    fn new() -> Self {
        Self {
            next_req_id: AtomicU64::new(1),
            lightpush: Mutex::new(LightPushState::default()),
            peer_exchange: Mutex::new(PeerExchangeState::default()),
            filter: Mutex::new(FilterState::default()),
        }
    }

    fn next_req_id(&self) -> ReqId {
        self.next_req_id.fetch_add(1, Ordering::Relaxed)
    }
}

fn build_filter_request(
    filter_type: proto::filter::filter_subscribe_request::FilterSubscribeType,
    pubsub_topic: String,
    content_topics: Vec<String>,
) -> proto::filter::FilterSubscribeRequest {
    proto::filter::FilterSubscribeRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        filter_subscribe_type: filter_type as i32,
        pubsub_topic: Some(pubsub_topic),
        content_topics,
    }
}

struct NodeInner {
    config: NodeConfig,
    discovery_config: DiscoveryConfig,
    peer_book: Arc<RwLock<PeerBook>>,
    ops: OpTracker,
    transport_tx: mpsc::Sender<TransportCmd>,
    dial_tx: mpsc::Sender<PeerId>,
    metadata_response: proto::metadata::WakuMetadataResponse,
    peer_exchange_cooldown: Duration,
    op_counter: AtomicU64,
}

impl NodeInner {
    fn maybe_dial(&self) {
        let book = self.peer_book.read();

        if book.num_connections() >= self.config.connection_cap {
            trace!(
                connections = book.num_connections(),
                "connection cap reached, not dialing any more peers"
            );
            return;
        }

        let now = Instant::now();
        let mut in_flight = 0;

        for (peer_id, state) in &book.peers {
            if book.num_connections() + in_flight >= self.config.connection_cap
                || state.connected
                || book.dialing.contains(peer_id)
                || state.next_dial_at.is_some_and(|next| next > now)
                || state.addrs.is_empty()
                || in_flight >= self.config.dial_concurrency
            {
                continue;
            }

            if let Err(error) = self.dial_tx.try_send(*peer_id) {
                debug!(%peer_id, %error, "dial queue full, dropping request");
                continue;
            }

            in_flight += 1;
        }
    }

    async fn discover(&self) -> Result<usize, discovery::DiscoveryError> {
        let peers = discovery::discover_all(&self.discovery_config).await?;
        Ok(self.apply_discovered_peers(peers))
    }

    async fn peer_exchange_rounds(&self, rounds: usize) -> Result<(), WakuError> {
        if rounds == 0 {
            return Ok(());
        }

        let op_id = OpId::next(&self.op_counter);
        let (tx, rx) = oneshot::channel();

        {
            let mut px = self.ops.peer_exchange.lock().await;
            px.waiters.insert(op_id, tx);

            let op = PeerExchangeOp {
                remaining_rounds: rounds,
                current_batch: None,
                deadline: Instant::now() + self.config.request_timeout,
            };
            px.round_ops.insert(op_id, op);
        }

        self.start_peer_exchange_round(op_id).await;
        rx.await.map_err(|_| WakuError::Cancelled)
    }

    fn apply_discovered_peers(&self, peers: Vec<discovery::DiscoveredPeer>) -> usize {
        let discovered = peers.len();

        {
            let mut book = self.peer_book.write();
            for peer in peers {
                let entry = book.peers.entry(peer.peer_id).or_default();
                entry.addrs.extend(peer.addrs);
                entry.addrs.sort();
                entry.addrs.dedup();
            }
        }

        self.maybe_dial();
        discovered
    }

    async fn run_discovery_loop(self: Arc<Self>) {
        if let Err(error) = self.discover().await {
            warn!(?error, "dns discovery failed");
        }

        let mut ticker = tokio::time::interval(self.discovery_config.dns_discovery_interval);
        loop {
            ticker.tick().await;
            if let Err(error) = self.discover().await {
                warn!(?error, "dns discovery failed");
            }
        }
    }

    async fn run_peer_exchange_loop(self: Arc<Self>) {
        loop {
            let connected = self.peer_book.read().connected.len();
            let interval = if connected < self.discovery_config.peer_exchange_bootstrap_peers {
                self.discovery_config.peer_exchange_bootstrap_interval
            } else {
                self.discovery_config.peer_exchange_interval
            };

            if connected == 0 {
                debug!("skipping peer exchange: no connected peers");
                tokio::time::sleep(interval).await;
                continue;
            }

            if connected >= self.config.connection_cap {
                debug!("skipping peer exchange: connection cap reached");
                tokio::time::sleep(interval).await;
                continue;
            }

            debug!(connected, "performing peer exchange");
            match self
                .peer_exchange_rounds(self.discovery_config.peer_exchange_rounds)
                .await
            {
                Ok(()) => {}
                Err(WakuError::Cancelled) => warn!("peer exchange cancelled"),
                Err(error) => {
                    error!(?error, "peer exchange failed, stopping loop");
                    break;
                }
            }

            tokio::time::sleep(interval).await;
        }
    }

    async fn run_dialer(self: Arc<Self>, mut dial_rx: mpsc::Receiver<PeerId>) {
        while let Some(peer_id) = dial_rx.recv().await {
            let addrs = {
                let mut book = self.peer_book.write();

                if book.num_connections() >= self.config.connection_cap {
                    debug!(%peer_id, "connection cap reached, dropping dial request");
                    continue;
                }

                if book.connected.contains(&peer_id) || book.dialing.contains(&peer_id) {
                    debug!(%peer_id, "peer already connected or dialing, dropping request");
                    continue;
                }

                let Some(state) = book.peers.get(&peer_id) else {
                    debug!(%peer_id, "missing peer state, dropping request");
                    continue;
                };

                if state.addrs.is_empty() {
                    debug!(%peer_id, "peer has no addrs, dropping request");
                    continue;
                }

                let addrs = state.addrs.clone();
                book.dialing.insert(peer_id);
                addrs
            };

            if let Err(error) = self
                .transport_tx
                .try_send(TransportCmd::Dial { peer_id, addrs })
            {
                debug!(%peer_id, %error, "failed to send dial command, rolling back");
                let mut book = self.peer_book.write();
                book.dialing.remove(&peer_id);
            }
        }
    }

    async fn run_event_loop(self: Arc<Self>, mut transport_rx: mpsc::Receiver<TransportEvent>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    self.handle_tick(Instant::now()).await;
                }
                ev = transport_rx.recv() => {
                    let Some(ev) = ev else { break };
                    self.handle_transport_event(ev).await;
                }
            }
        }
    }

    async fn handle_tick(&self, now: Instant) {
        // LightPush timeouts
        {
            let mut lp = self.ops.lightpush.lock().await;
            let expired = lp
                .ops
                .extract_if(|_, op| op.deadline <= now)
                .collect::<Vec<_>>();

            for (op_id, op) in expired {
                if let Some(tx) = lp.waiters.remove(&op_id)
                    && tx.send(op.results).is_err()
                {
                    debug!(?op_id, "lightpush results receiver dropped");
                }
            }
        }

        // PeerExchange timeouts
        let expired_batches = {
            let mut px = self.ops.peer_exchange.lock().await;
            px.ops
                .extract_if(|_, batch| batch.deadline <= now)
                .map(|(batch_id, batch)| (batch_id, batch.results))
                .collect::<Vec<_>>()
        };

        for (batch_id, enrs) in expired_batches {
            self.finish_peer_exchange_batch(batch_id, enrs).await;
        }

        self.maybe_dial();
    }

    async fn handle_transport_event(&self, ev: TransportEvent) {
        match ev {
            TransportEvent::ConnectionEstablished { peer_id } => {
                debug!(%peer_id, "connected");
                {
                    let mut book = self.peer_book.write();
                    book.connected.insert(peer_id);
                    book.dialing.remove(&peer_id);
                    let state = book.peers.entry(peer_id).or_default();
                    state.connected = true;
                    if state.dial_failures > 5
                        && state.next_dial_at.is_some_and(|t| t <= Instant::now())
                    {
                        state.dial_failures = state.dial_failures.saturating_sub(1);
                    }
                }
                self.maybe_dial();
            }
            TransportEvent::ConnectionClosed { peer_id } => {
                debug!(%peer_id, "disconnected");
                {
                    let mut book = self.peer_book.write();
                    book.connected.remove(&peer_id);
                    book.dialing.remove(&peer_id);
                    if let Some(state) = book.peers.get_mut(&peer_id) {
                        state.connected = false;
                        state.dial_failures = state.dial_failures.saturating_add(1);
                        let pow = state.dial_failures.min(8);
                        let backoff = Duration::from_secs(1 << pow);
                        state.next_dial_at = Some(Instant::now() + backoff);
                    }
                }
                self.maybe_dial();
            }
            TransportEvent::DialError { peer_id } => {
                debug!(%peer_id, "dial error");
                let mut book = self.peer_book.write();
                book.dialing.remove(&peer_id);
                if let Some(state) = book.peers.get_mut(&peer_id) {
                    state.dial_failures = state.dial_failures.saturating_add(1);
                    let pow = state.dial_failures.min(8);
                    let backoff = Duration::from_secs(1 << pow);
                    state.next_dial_at = Some(Instant::now() + backoff);
                }
            }
            TransportEvent::IdentifyReceived {
                peer_id,
                protocols,
                addrs,
            } => {
                trace!(%peer_id, ?addrs, ?protocols, "received identify");
                let supports_lightpush = protocols
                    .iter()
                    .any(|p| p == protocols::lightpush::LIGHTPUSH_V3_CODEC);
                let supports_px = protocols
                    .iter()
                    .any(|p| p == protocols::peer_exchange::PEER_EXCHANGE_CODEC);
                let supports_filter = protocols
                    .iter()
                    .any(|p| p == protocols::filter::FILTER_SUBSCRIBE_CODEC);

                {
                    let mut book = self.peer_book.write();
                    let entry = book.peers.entry(peer_id).or_default();
                    entry.supports_lightpush_v3 = supports_lightpush;
                    entry.supports_peer_exchange = supports_px;
                    entry.supports_filter = supports_filter;
                    entry.addrs.extend(addrs);
                    entry.addrs.sort();
                    entry.addrs.dedup();
                }

                // Resubscribe to filter on reconnect if peer supports filter
                if supports_filter {
                    self.subscribe_on_peer(peer_id).await;
                }
            }
            TransportEvent::MetadataRequest { channel, .. } => {
                let response = self.metadata_response.clone();
                if let Err(error) = self
                    .transport_tx
                    .try_send(TransportCmd::SendMetadataResponse { channel, response })
                {
                    error!(%error, "failed to send metadata response command");
                }
            }
            TransportEvent::LightPushRequest { channel, .. } => {
                let response = LIGHTPUSH_UNIMPLEMENTED
                    .get_or_init(|| proto::light_push::LightPushResponseV3 {
                        request_id: String::new(),
                        status_code: 503,
                        status_desc: Some("not implemented".to_string()),
                        relay_peer_count: None,
                    })
                    .clone();
                if let Err(error) = self
                    .transport_tx
                    .try_send(TransportCmd::SendLightPushResponse { channel, response })
                {
                    error!(%error, "failed to send lightpush response command");
                }
            }
            TransportEvent::PeerExchangeRequest { channel, .. } => {
                let response = PEER_EXCHANGE_EMPTY_RESPONSE
                    .get_or_init(|| proto::peer_exchange::PeerExchangeRpc {
                        query: None,
                        response: Some(proto::peer_exchange::PeerExchangeResponse {
                            peer_infos: Vec::new(),
                        }),
                    })
                    .clone();
                if let Err(error) = self
                    .transport_tx
                    .try_send(TransportCmd::SendPeerExchangeResponse { channel, response })
                {
                    error!(%error, "failed to send peer exchange response command");
                }
            }
            TransportEvent::LightPushResponse {
                req_id,
                peer_id,
                result,
            } => {
                self.handle_lightpush_response(req_id, peer_id, result)
                    .await;
            }
            TransportEvent::PeerExchangeResponse { req_id, result } => {
                self.handle_peer_exchange_response(req_id, result).await;
            }
            TransportEvent::FilterSubscribeResponse {
                req_id,
                peer_id,
                result,
            } => {
                self.handle_filter_subscribe_response(req_id, peer_id, result)
                    .await;
            }
            TransportEvent::FilterPush {
                peer_id,
                push,
                channel,
            } => {
                self.handle_filter_push(peer_id, *push, channel).await;
            }
        }
    }

    async fn handle_lightpush_response(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::light_push::LightPushResponseV3, OutboundFailure>,
    ) {
        let mut lp = self.ops.lightpush.lock().await;
        let Some((op_id, _)) = lp.pending.remove(&req_id) else {
            return;
        };
        let Some(op) = lp.ops.get_mut(&op_id) else {
            return;
        };

        op.finished += 1;
        match result {
            Ok(response) => {
                op.results.push(LightPushResult {
                    peer_id,
                    status_code: Some(response.status_code),
                    status_desc: response.status_desc,
                    relay_peer_count: response.relay_peer_count,
                    error: None,
                });
            }
            Err(e) => {
                op.results.push(LightPushResult {
                    peer_id,
                    status_code: None,
                    status_desc: None,
                    relay_peer_count: None,
                    error: Some(e),
                });
            }
        }

        if op.finished >= op.expected
            && let Some(finished_op) = lp.ops.remove(&op_id)
            && let Some(tx) = lp.waiters.remove(&op_id)
            && tx.send(finished_op.results).is_err()
        {
            debug!(?op_id, "lightpush response receiver dropped");
        }
    }

    async fn start_peer_exchange_round(&self, op_id: OpId) {
        {
            let mut px = self.ops.peer_exchange.lock().await;
            let Some(op) = px.round_ops.get_mut(&op_id) else {
                return;
            };

            if op.remaining_rounds == 0 {
                px.round_ops.remove(&op_id);
                if let Some(tx) = px.waiters.remove(&op_id)
                    && tx.send(()).is_err()
                {
                    debug!(?op_id, "peer exchange receiver dropped");
                }
                return;
            }
        }

        let now = Instant::now();
        let peers: Vec<PeerId> = {
            let book = self.peer_book.read();
            book.connected
                .iter()
                .filter_map(|peer_id| {
                    let state = book.peers.get(peer_id)?;
                    if !state.supports_peer_exchange {
                        return None;
                    }
                    if state
                        .last_peer_exchange_at
                        .is_some_and(|last| now.duration_since(last) < self.peer_exchange_cooldown)
                    {
                        return None;
                    }
                    Some(*peer_id)
                })
                .collect()
        };

        let mut sent_peers = Vec::new();
        {
            let mut px = self.ops.peer_exchange.lock().await;
            {
                let Some(op) = px.round_ops.get_mut(&op_id) else {
                    return;
                };

                if peers.is_empty() {
                    op.remaining_rounds = 0;
                    px.round_ops.remove(&op_id);
                    if let Some(tx) = px.waiters.remove(&op_id)
                        && tx.send(()).is_err()
                    {
                        debug!(?op_id, "peer exchange receiver dropped");
                    }
                    return;
                }
            }

            let batch_id = px.next_batch_id;
            px.next_batch_id += 1;

            let Some(op) = px.round_ops.get_mut(&op_id) else {
                return;
            };
            op.current_batch = Some(batch_id);
            op.deadline = Instant::now() + self.config.request_timeout;

            let mut expected = 0;
            for peer in peers {
                let req_id = self.ops.next_req_id();
                let request = proto::peer_exchange::PeerExchangeRpc {
                    query: Some(proto::peer_exchange::PeerExchangeQuery {
                        num_peers: Some(self.config.peer_exchange_peers_per_query),
                    }),
                    response: None,
                };

                let cmd = TransportCmd::SendPeerExchange {
                    req_id,
                    peer_id: peer,
                    request,
                };
                if self.transport_tx.try_send(cmd).is_ok() {
                    px.pending.insert(req_id, batch_id);
                    expected += 1;
                    sent_peers.push(peer);
                }
            }

            let batch = ResponseBatch {
                expected,
                finished: 0,
                results: Vec::new(),
                deadline: Instant::now() + self.config.request_timeout,
            };
            px.ops.insert(batch_id, batch);
        }

        if !sent_peers.is_empty() {
            let mut book = self.peer_book.write();
            for peer_id in sent_peers {
                if let Some(state) = book.peers.get_mut(&peer_id) {
                    state.last_peer_exchange_at = Some(now);
                }
            }
        }
    }

    async fn handle_peer_exchange_response(
        &self,
        req_id: ReqId,
        result: Result<proto::peer_exchange::PeerExchangeRpc, OutboundFailure>,
    ) {
        let (batch_id, enrs) = {
            let mut px = self.ops.peer_exchange.lock().await;
            let Some(batch_id) = px.pending.remove(&req_id) else {
                return;
            };
            let Some(batch) = px.ops.get_mut(&batch_id) else {
                return;
            };

            batch.finished += 1;
            if let Ok(response) = result
                && let Some(resp) = response.response
            {
                batch
                    .results
                    .extend(resp.peer_infos.into_iter().filter_map(|p| p.enr));
            }

            if batch.finished < batch.expected {
                return;
            }

            let Some(batch) = px.ops.remove(&batch_id) else {
                return;
            };
            (batch_id, batch.results)
        };

        self.finish_peer_exchange_batch(batch_id, enrs).await;
    }

    async fn finish_peer_exchange_batch(&self, batch_id: usize, enrs: Vec<Vec<u8>>) {
        {
            let mut book = self.peer_book.write();
            for enr_rlp in enrs {
                if let Ok(peer) = discovery::enr::decode_enr_rlp(&enr_rlp) {
                    let entry = book.peers.entry(peer.peer_id).or_default();
                    entry.addrs.extend(peer.addrs);
                    entry.addrs.sort();
                    entry.addrs.dedup();
                }
            }
        }

        self.maybe_dial();

        let op_id = {
            let mut px = self.ops.peer_exchange.lock().await;
            let op_id = px
                .round_ops
                .iter()
                .find_map(|(op_id, op)| (op.current_batch == Some(batch_id)).then_some(*op_id));

            let Some(op_id) = op_id else { return };

            if let Some(op) = px.round_ops.get_mut(&op_id) {
                op.remaining_rounds = op.remaining_rounds.saturating_sub(1);
                op.current_batch = None;
            }

            op_id
        };

        self.start_peer_exchange_round(op_id).await;
    }

    async fn send_filter_request(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::filter::FilterSubscribeRequest,
        op: FilterOp,
    ) -> Result<(), WakuError> {
        let cmd = TransportCmd::SendFilterSubscribe {
            req_id,
            peer_id,
            request,
        };
        if self.transport_tx.try_send(cmd).is_err() {
            return Err(WakuError::ChannelFull);
        }

        let mut filter = self.ops.filter.lock().await;
        filter.pending.insert(req_id, op);
        Ok(())
    }

    fn update_filter_batch<F>(
        filter: &mut FilterState,
        batch_id: u64,
        result_status: Result<(), WakuError>,
        on_success: F,
    ) where
        F: FnOnce(&mut FilterState),
    {
        let mut finalize_success = false;
        let mut finalize_failure = false;

        if let Some(batch) = filter.batches.get_mut(&batch_id) {
            batch.finished += 1;
            match result_status {
                Ok(()) => {
                    if !batch.succeeded {
                        batch.succeeded = true;
                        finalize_success = true;
                    }
                }
                Err(error) => {
                    batch.last_error = Some(error);
                    if batch.finished >= batch.expected && !batch.succeeded {
                        finalize_failure = true;
                    }
                }
            }

            if batch.finished >= batch.expected && !batch.succeeded {
                finalize_failure = true;
            }
        }

        if (finalize_success || finalize_failure)
            && let Some(batch) = filter.batches.remove(&batch_id)
        {
            let outcome = if finalize_success {
                on_success(filter);
                Ok(())
            } else {
                Err(batch.last_error.unwrap_or(WakuError::FilterRequestFailed))
            };
            let _ = batch.waiter.send(outcome);
        }
    }

    async fn handle_filter_subscribe_response(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::filter::FilterSubscribeResponse, OutboundFailure>,
    ) {
        let mut filter = self.ops.filter.lock().await;
        let Some(op) = filter.pending.remove(&req_id) else {
            return;
        };

        let result_status = match &result {
            Ok(response) if response.status_code == 200 => Ok(()),
            Ok(response) => Err(WakuError::FilterSubscribeFailed {
                status_code: response.status_code,
                status_desc: response.status_desc.clone(),
            }),
            Err(_) => Err(WakuError::FilterRequestFailed),
        };

        match op {
            FilterOp::Subscribe { sub_id } => match result_status {
                Ok(()) => {
                    debug!(%peer_id, ?sub_id, "filter subscribe succeeded");
                }
                Err(error) => {
                    warn!(%peer_id, ?sub_id, ?error, "filter subscribe failed");
                }
            },
            FilterOp::Unsubscribe { sub_id, batch_id } => {
                Self::update_filter_batch(&mut filter, batch_id, result_status, |filter| {
                    filter.subscriptions.remove(&sub_id);
                });
            }
            FilterOp::UnsubscribeAll {
                pubsub_topic,
                batch_id,
            } => {
                Self::update_filter_batch(&mut filter, batch_id, result_status, |filter| {
                    filter
                        .subscriptions
                        .retain(|_, sub| sub.pubsub_topic != pubsub_topic);
                });
            }
            FilterOp::Ping => {
                if let Err(error) = result {
                    warn!(%peer_id, ?error, "filter ping failed");
                }
            }
            FilterOp::SubscribeOnPeer { sub_id } => match result_status {
                Ok(()) => {
                    debug!(%peer_id, ?sub_id, "filter subscribe (peer) succeeded");
                }
                Err(error) => {
                    warn!(%peer_id, ?sub_id, ?error, "filter subscribe (peer) failed");
                }
            },
        }
    }

    async fn handle_filter_push(
        &self,
        peer_id: PeerId,
        push: proto::filter::MessagePush,
        channel: ResponseChannel<FilterPushAck>,
    ) {
        // Ack the push immediately
        if let Err(error) = self
            .transport_tx
            .try_send(TransportCmd::SendFilterPushAck { channel })
        {
            debug!(%error, "failed to send filter push ack");
        }

        let Some(message) = push.waku_message else {
            debug!(%peer_id, "received filter push without message");
            return;
        };

        let hash = message.hash_key();

        let mut filter = self.ops.filter.lock().await;

        if filter.dedup_cache.contains(&hash) {
            trace!(%peer_id, "duplicate filter push, ignoring");
            return;
        }
        filter.dedup_cache.put(hash, ());

        // Route to matching subscriptions
        let Some(pubsub_topic) = push.pubsub_topic.as_deref() else {
            debug!(%peer_id, "received filter push without pubsub topic");
            return;
        };
        let content_topic = &message.content_topic;

        for sub in filter.subscriptions.values() {
            if sub.pubsub_topic != pubsub_topic {
                continue;
            }

            if !sub.content_topics.iter().any(|ct| ct == content_topic) {
                continue;
            }

            if let Err(error) = sub.sender.try_send(message.clone()) {
                debug!(%error, "failed to deliver filter push to subscriber");
            }
        }
    }

    async fn send_subscribe_request(
        &self,
        peer_id: PeerId,
        sub_id: SubId,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) {
        let req_id = self.ops.next_req_id();
        let request = build_filter_request(
            proto::filter::filter_subscribe_request::FilterSubscribeType::Subscribe,
            pubsub_topic,
            content_topics,
        );

        if let Err(error) = self
            .send_filter_request(
                req_id,
                peer_id,
                request,
                FilterOp::SubscribeOnPeer { sub_id },
            )
            .await
        {
            warn!(%peer_id, ?sub_id, ?error, "failed to send filter subscribe request");
        }
    }

    async fn subscribe_on_peer(&self, peer_id: PeerId) {
        let subs_to_send: Vec<(SubId, String, Vec<String>)> = {
            let filter = self.ops.filter.lock().await;
            filter
                .subscriptions
                .iter()
                .map(|(id, sub)| (*id, sub.pubsub_topic.clone(), sub.content_topics.clone()))
                .collect()
        };

        if subs_to_send.is_empty() {
            return;
        }

        debug!(%peer_id, count = subs_to_send.len(), "subscribing filter subscriptions on peer");

        for (sub_id, pubsub_topic, content_topics) in subs_to_send {
            self.send_subscribe_request(peer_id, sub_id, pubsub_topic, content_topics)
                .await;
        }
    }
}

#[derive(Clone)]
pub struct WakuNode {
    inner: Arc<NodeInner>,
}

impl WakuNode {
    /// Spawn the node and transport tasks.
    pub fn spawn(config: WakuConfig) -> Result<Self, WakuError> {
        let transport = Transport::new(&config.node)?;
        let (transport_tx, transport_cmd_rx) = mpsc::channel(64);
        let (transport_event_tx, transport_event_rx) = mpsc::channel(64);
        let (dial_tx, dial_rx) = mpsc::channel(64);

        tokio::spawn(transport.run(transport_cmd_rx, transport_event_tx));

        let metadata_response = proto::metadata::WakuMetadataResponse {
            cluster_id: Some(config.cluster_id),
            shards: Vec::new(),
        };

        let inner = Arc::new(NodeInner {
            config: config.node,
            discovery_config: config.discovery,
            peer_book: Arc::new(RwLock::new(PeerBook::default())),
            ops: OpTracker::new(),
            transport_tx,
            dial_tx,
            metadata_response,
            peer_exchange_cooldown: config.peer_exchange_cooldown,
            op_counter: AtomicU64::new(1),
        });

        {
            let inner = inner.clone();
            tokio::spawn(async move {
                inner.run_event_loop(transport_event_rx).await;
            });
        }

        {
            let inner = inner.clone();
            tokio::spawn(async move {
                inner.run_dialer(dial_rx).await;
            });
        }

        {
            let inner = inner.clone();
            tokio::spawn(async move {
                inner.run_discovery_loop().await;
            });
        }

        {
            let inner = inner.clone();
            tokio::spawn(async move {
                inner.run_peer_exchange_loop().await;
            });
        }

        Ok(Self { inner })
    }

    pub fn add_additional_peers(&self, peers: Vec<discovery::DiscoveredPeer>) {
        self.inner.apply_discovered_peers(peers);
    }

    /// Get peer statistics
    #[must_use]
    pub fn get_stats(&self) -> PeerStats {
        self.inner.peer_book.read().get_stats()
    }

    /// Get the list of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.inner.peer_book.read().connected_peers()
    }

    /// Dial known peers until the configured connection cap is reached.
    pub fn connect_until_cap(&self) {
        self.inner.maybe_dial();
    }

    /// `LightPush` a message to all currently connected peers supporting `LightPush` v3.
    pub async fn lightpush_all(
        &self,
        pubsub_topic: String,
        content_topic: String,
        payload: Vec<u8>,
    ) -> Result<Vec<LightPushResult>, WakuError> {
        let op_id = OpId::next(&self.inner.op_counter);
        let (tx, rx) = oneshot::channel();

        {
            let mut lp = self.inner.ops.lightpush.lock().await;
            lp.waiters.insert(op_id, tx);

            let candidates: Vec<PeerId> = {
                let book = self.inner.peer_book.read();
                book.connected
                    .iter()
                    .filter(|p| book.peers.get(p).is_some_and(|s| s.supports_lightpush_v3))
                    .copied()
                    .collect()
            };

            if candidates.is_empty() {
                lp.waiters.remove(&op_id);
                return Ok(Vec::new());
            }

            let mut expected = 0;
            let now_ns = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(i64::MAX);

            for peer_id in candidates {
                let req_id = self.inner.ops.next_req_id();
                let request = proto::light_push::LightPushRequestV3 {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    pubsub_topic: Some(pubsub_topic.clone()),
                    message: Some(proto::message::WakuMessage {
                        payload: payload.clone(),
                        content_topic: content_topic.clone(),
                        version: None,
                        timestamp: Some(now_ns),
                        meta: None,
                        rate_limit_proof: None,
                        ephemeral: None,
                    }),
                };

                let cmd = TransportCmd::SendLightPush {
                    req_id,
                    peer_id,
                    request,
                };
                if self.inner.transport_tx.try_send(cmd).is_ok() {
                    lp.pending.insert(req_id, (op_id, peer_id));
                    expected += 1;
                }
            }

            if expected == 0 {
                lp.waiters.remove(&op_id);
                return Ok(Vec::new());
            }

            let op = ResponseBatch {
                expected,
                finished: 0,
                results: Vec::new(),
                deadline: Instant::now() + self.inner.config.request_timeout,
            };
            lp.ops.insert(op_id, op);
        }

        rx.await.map_err(|_| WakuError::Cancelled)
    }

    fn filter_peers(&self) -> Vec<PeerId> {
        let book = self.inner.peer_book.read();
        book.connected
            .iter()
            .filter(|p| book.peers.get(p).is_some_and(|s| s.supports_filter))
            .copied()
            .collect()
    }

    async fn await_filter_result<T, F>(
        &self,
        waiter_rx: oneshot::Receiver<Result<T, WakuError>>,
        cleanup: F,
    ) -> Result<T, WakuError>
    where
        F: FnOnce(&mut FilterState) + Send,
    {
        if let Ok(result) = waiter_rx.await {
            result
        } else {
            let mut filter = self.inner.ops.filter.lock().await;
            cleanup(&mut filter);
            Err(WakuError::Cancelled)
        }
    }

    async fn run_filter_batch<F>(
        &self,
        peers: Vec<PeerId>,
        make_request: F,
    ) -> Result<(), WakuError>
    where
        F: Fn(PeerId, ReqId, u64) -> (proto::filter::FilterSubscribeRequest, FilterOp),
    {
        let (waiter_tx, waiter_rx) = oneshot::channel();
        let batch_id = {
            let mut filter = self.inner.ops.filter.lock().await;
            let batch_id = filter.next_batch_id.fetch_add(1, Ordering::Relaxed);
            let batch = FilterBatch {
                expected: peers.len(),
                finished: 0,
                succeeded: false,
                waiter: waiter_tx,
                last_error: None,
            };
            filter.batches.insert(batch_id, batch);
            batch_id
        };

        for peer_id in peers {
            let req_id = self.inner.ops.next_req_id();
            let (request, op) = make_request(peer_id, req_id, batch_id);

            if let Err(error) = self
                .inner
                .send_filter_request(req_id, peer_id, request, op)
                .await
            {
                let mut filter = self.inner.ops.filter.lock().await;
                if let Some(batch) = filter.batches.get_mut(&batch_id) {
                    batch.expected = batch.expected.saturating_sub(1);
                    batch.last_error.get_or_insert(error);
                }
            }
        }

        let empty_batch = {
            let mut filter = self.inner.ops.filter.lock().await;
            if let Some(batch) = filter.batches.get(&batch_id)
                && batch.expected == 0
            {
                filter.batches.remove(&batch_id)
            } else {
                None
            }
        };

        if let Some(batch) = empty_batch {
            return Err(batch.last_error.unwrap_or(WakuError::ChannelFull));
        }

        self.await_filter_result(waiter_rx, |filter| {
            filter.batches.remove(&batch_id);
        })
        .await
    }

    /// Subscribe to filter messages matching the given criteria.
    /// Returns a receiver that will receive matching `WakuMessage`s.
    pub async fn filter_subscribe(
        &self,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<proto::WakuMessage>, WakuError> {
        if content_topics.is_empty() {
            return Err(WakuError::InvalidArgument(
                "content_topics cannot be empty".to_string(),
            ));
        }

        let (msg_tx, msg_rx) = mpsc::channel(64);
        let sub_content_topics = content_topics.clone();
        let sub_pubsub_topic = pubsub_topic.clone();

        let sub_id = {
            let mut filter = self.inner.ops.filter.lock().await;
            let sub_id = SubId::next(&filter.next_sub_id);

            let subscription = Subscription {
                pubsub_topic: sub_pubsub_topic,
                content_topics: sub_content_topics,
                sender: msg_tx,
            };
            filter.subscriptions.insert(sub_id, subscription);
            sub_id
        };

        let peers = self.filter_peers();
        if peers.is_empty() {
            debug!(
                ?sub_id,
                "no filter peers available; subscription will activate on connect"
            );
            return Ok(msg_rx);
        }

        for peer_id in peers {
            let req_id = self.inner.ops.next_req_id();
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::Subscribe,
                pubsub_topic.clone(),
                content_topics.clone(),
            );

            if let Err(error) = self
                .inner
                .send_filter_request(req_id, peer_id, request, FilterOp::Subscribe { sub_id })
                .await
            {
                warn!(%peer_id, ?sub_id, ?error, "failed to send filter subscribe request");
            }
        }

        Ok(msg_rx)
    }

    /// Unsubscribe from specific content topics.
    pub async fn filter_unsubscribe(
        &self,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) -> Result<(), WakuError> {
        if content_topics.is_empty() {
            return Err(WakuError::InvalidArgument(
                "content_topics cannot be empty".to_string(),
            ));
        }

        let peers = self.filter_peers();
        if peers.is_empty() {
            return Err(WakuError::NoPeersAvailable);
        }

        // Find matching subscription
        let sub_id = {
            let filter = self.inner.ops.filter.lock().await;
            filter.subscriptions.iter().find_map(|(id, sub)| {
                if sub.pubsub_topic == pubsub_topic && sub.content_topics == content_topics {
                    Some(*id)
                } else {
                    None
                }
            })
        };

        let Some(sub_id) = sub_id else {
            return Err(WakuError::SubscriptionNotFound);
        };

        let pubsub_topic = pubsub_topic.clone();
        let content_topics = content_topics.clone();

        self.run_filter_batch(peers, move |_peer_id, _req_id, batch_id| {
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::Unsubscribe,
                pubsub_topic.clone(),
                content_topics.clone(),
            );
            (request, FilterOp::Unsubscribe { sub_id, batch_id })
        })
        .await
    }

    /// Unsubscribe from all content topics for the given pubsub topic.
    pub async fn filter_unsubscribe_all(&self, pubsub_topic: String) -> Result<(), WakuError> {
        let peers = self.filter_peers();
        if peers.is_empty() {
            return Err(WakuError::NoPeersAvailable);
        }

        let pubsub_topic = pubsub_topic.clone();

        self.run_filter_batch(peers, move |_peer_id, _req_id, batch_id| {
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::UnsubscribeAll,
                pubsub_topic.clone(),
                Vec::new(),
            );
            (
                request,
                FilterOp::UnsubscribeAll {
                    pubsub_topic: pubsub_topic.clone(),
                    batch_id,
                },
            )
        })
        .await
    }
}
