use crate::error::ClientError;
use crate::msg::{ContentTopic, Message};
use base64::Engine;
use base64::engine::general_purpose;
use lru::LruCache;
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use waku::proto::{HashKey, WakuMessage};
use waku::{
    DEFAULT_CLEARNET_DOH_ENDPOINT, DiscoveredPeer, PeerSnapshot, PeerStats, StoreQueryOptions,
    WakuConfig, WakuNetworkConfig, WakuNode, WakuTorClientProvider, parse_multiaddr, parse_peer_id,
};

pub const DEFAULT_CLUSTER_ID: u32 = 5;
pub const DEFAULT_SHARD_ID: u32 = 1;
const FEE_HISTORY_LOOKBACK: Duration = Duration::from_mins(2);
const FEE_HISTORY_PAGE_LIMIT: u64 = 500;
const CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(500) {
    Some(n) => n,
    None => panic!("cache size must be non-zero"),
};

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub nwaku_url: Option<String>,
    pub shard_id: Option<u32>,
    pub direct_peers: Vec<AdditionalPeer>,
    pub dns_enr_trees: Option<Vec<String>>,
    pub doh_endpoint: Option<String>,
    pub doh_fallback_endpoints: Option<Vec<String>>,
    pub cluster_id: Option<u32>,
    pub max_peers: Option<usize>,
    pub peer_connection_timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RelayNetworkMode {
    Direct,
    Tor,
    Proxy,
}

#[derive(Clone)]
pub struct RelayNetworkConfig {
    pub mode: RelayNetworkMode,
    pub http_client: Option<reqwest::Client>,
    pub tor_client: Option<WakuTorClientProvider>,
}

impl RelayNetworkConfig {
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            mode: RelayNetworkMode::Direct,
            http_client: None,
            tor_client: None,
        }
    }

    #[must_use]
    pub fn tor_with_client_provider(
        tor_client: WakuTorClientProvider,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            mode: RelayNetworkMode::Tor,
            http_client: Some(http_client),
            tor_client: Some(tor_client),
        }
    }

    #[must_use]
    pub const fn proxy(http_client: reqwest::Client) -> Self {
        Self {
            mode: RelayNetworkMode::Proxy,
            http_client: Some(http_client),
            tor_client: None,
        }
    }
}

impl Default for RelayNetworkConfig {
    fn default() -> Self {
        Self::direct()
    }
}

impl std::fmt::Debug for RelayNetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayNetworkConfig")
            .field("mode", &self.mode)
            .field("http_client", &self.http_client.is_some())
            .field("tor_client", &self.tor_client.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMessageOutcome {
    Delivered,
    Duplicate,
    Dropped,
    SinkClosed,
}

fn handle_relay_message(
    cache: &mut LruCache<u64, ()>,
    sink_tx: &mpsc::Sender<WakuMessage>,
    message: WakuMessage,
) -> RelayMessageOutcome {
    let hash = message.hash_key();

    if cache.contains(&hash) {
        tracing::debug!(hash, "duplicate message, ignoring");
        return RelayMessageOutcome::Duplicate;
    }
    cache.put(hash, ());
    match sink_tx.try_send(message) {
        Ok(()) => RelayMessageOutcome::Delivered,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("failed to send message to sink: channel full");
            RelayMessageOutcome::Dropped
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("message sink closed; stopping relay subscription task");
            RelayMessageOutcome::SinkClosed
        }
    }
}

fn relay_sink_is_closed(sink_tx: &mpsc::Sender<WakuMessage>) -> bool {
    if sink_tx.is_closed() {
        tracing::debug!("message sink closed; stopping relay subscription task");
        return true;
    }
    false
}

async fn wait_for_relay_sink_closed(sink_tx: &mpsc::Sender<WakuMessage>) {
    sink_tx.closed().await;
    tracing::debug!("message sink closed; stopping relay subscription task");
}

pub struct Client {
    http_client: reqwest::Client,
    nwaku_url: Option<String>,
    pubsub_path: String,
    waku_fleet: Option<Arc<WakuNode>>,
    network_mode: RelayNetworkMode,
    disabled_reason: Option<Arc<str>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(waku_fleet) = self.waku_fleet.as_ref() {
            waku_fleet.shutdown();
        }
    }
}

impl Client {
    pub fn new(cfg: &ClientConfig) -> Result<Self, ClientError> {
        Self::new_with_network(cfg, RelayNetworkConfig::direct())
    }

    pub fn new_with_network(
        cfg: &ClientConfig,
        network: RelayNetworkConfig,
    ) -> Result<Self, ClientError> {
        let RelayNetworkConfig {
            mode,
            http_client,
            tor_client,
        } = network;
        let cluster_id = configured_cluster_id(cfg);
        let shard_id = configured_shard_id(cfg);
        let http_client = http_client.unwrap_or_default();
        let disabled_reason = (mode == RelayNetworkMode::Proxy)
            .then(|| Arc::<str>::from("proxy mode does not support Waku libp2p transports"));
        let waku = if let Some(reason) = disabled_reason.as_ref() {
            tracing::warn!(%reason, "Waku disabled by network policy");
            None
        } else {
            let mut config = Self::build_waku_config(cfg);
            if mode == RelayNetworkMode::Tor {
                let tor_client = tor_client.ok_or_else(|| {
                    ClientError::Disabled("Tor Waku profile requires an Arti client".to_string())
                })?;
                add_tor_doh_fallback(&mut config, cfg.doh_fallback_endpoints.is_some());
                config.network =
                    WakuNetworkConfig::tor_with_client_provider(tor_client, http_client.clone());
            }
            let waku = Arc::new(WakuNode::spawn(config).map_err(ClientError::SpawnNode)?);
            waku.add_additional_peers(
                cfg.direct_peers
                    .iter()
                    .map(|peer| {
                        Ok(DiscoveredPeer {
                            peer_id: parse_peer_id(&peer.peer_id)
                                .map_err(|_| ClientError::ParsePeerId)?,
                            addrs: peer
                                .addrs
                                .iter()
                                .map(|addr| {
                                    parse_multiaddr(addr).map_err(|_| ClientError::ParseMultiaddr)
                                })
                                .collect::<Result<Vec<_>, ClientError>>()?,
                        })
                    })
                    .collect::<Result<Vec<_>, ClientError>>()?,
            );
            Some(waku)
        };
        Ok(Self {
            http_client,
            nwaku_url: cfg.nwaku_url.clone(),
            pubsub_path: relay_shard_pubsub_path(cluster_id, shard_id),
            waku_fleet: waku,
            network_mode: mode,
            disabled_reason,
        })
    }

    fn build_waku_config(cfg: &ClientConfig) -> WakuConfig {
        let mut config = WakuConfig::default();
        if let Some(dns_enr_trees) = &cfg.dns_enr_trees {
            config.discovery.enr_trees.clone_from(dns_enr_trees);
        }
        if let Some(doh_endpoint) = &cfg.doh_endpoint {
            config.discovery.doh_endpoint.clone_from(doh_endpoint);
        }
        if let Some(doh_fallback_endpoints) = &cfg.doh_fallback_endpoints {
            config
                .discovery
                .doh_fallback_endpoints
                .clone_from(doh_fallback_endpoints);
        }
        config.cluster_id = configured_cluster_id(cfg);
        config.shard_id = configured_shard_id(cfg);
        if let Some(max_peers) = cfg.max_peers {
            config.node.connection_cap = max_peers;
        }
        if let Some(request_timeout) = cfg.peer_connection_timeout {
            config.node.request_timeout = request_timeout;
        }
        config
    }

    #[must_use]
    pub fn pubsub_path(&self) -> &str {
        &self.pubsub_path
    }

    #[must_use]
    pub const fn network_mode(&self) -> RelayNetworkMode {
        self.network_mode
    }

    #[must_use]
    pub const fn network_status_label(&self) -> &'static str {
        if self.disabled_reason.is_some() {
            return "Waku disabled";
        }
        match self.network_mode {
            RelayNetworkMode::Tor => "Tor-safe Waku",
            RelayNetworkMode::Proxy => "Waku disabled",
            RelayNetworkMode::Direct => "Direct Waku",
        }
    }

    #[must_use]
    pub fn disabled_reason(&self) -> Option<&str> {
        self.disabled_reason.as_deref()
    }

    #[must_use]
    pub fn refresh_network_session(&self) -> bool {
        if self.network_mode != RelayNetworkMode::Tor {
            return false;
        }
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            return false;
        };
        waku_fleet.refresh_network_session();
        true
    }

    /// Current aggregate peer statistics from the underlying Waku node.
    #[must_use]
    pub fn peer_stats(&self) -> PeerStats {
        self.waku_fleet
            .as_ref()
            .map_or_else(PeerStats::default, |waku| waku.get_stats())
    }

    /// Read-only per-peer snapshot rows from the underlying Waku node.
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.waku_fleet
            .as_ref()
            .map_or_else(Vec::new, |waku| waku.peer_snapshots())
    }

    pub async fn subscribe(
        &self,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        self.subscribe_internal(content_topics, None).await
    }

    pub async fn subscribe_with_fee_history(
        &self,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        let history_lookback = content_topics
            .iter()
            .all(|topic| is_fee_content_topic(topic))
            .then_some(FEE_HISTORY_LOOKBACK);
        if history_lookback.is_none() {
            tracing::warn!(
                pubsub_path = %self.pubsub_path,
                topics = ?content_topics,
                "fee history requested for non-fee topics; using live-only subscription"
            );
        }

        self.subscribe_internal(content_topics, history_lookback)
            .await
    }

    async fn subscribe_internal(
        &self,
        content_topics: Vec<String>,
        history_lookback: Option<Duration>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            let reason = self
                .disabled_reason
                .as_deref()
                .unwrap_or("Waku is unavailable for the selected network mode");
            return Err(ClientError::Disabled(reason.to_string()));
        };
        let mut rx = waku_fleet
            .filter_subscribe(self.pubsub_path.clone(), content_topics.clone())
            .await
            .map_err(ClientError::FleetSubscribe)?;
        if let Some(nwaku_url) = &self.nwaku_url {
            let url = format!("{nwaku_url}/relay/v1/subscriptions");
            if let Err(error) = self
                .http_client
                .post(url)
                .json(&[self.pubsub_path.as_str()])
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
            {
                tracing::warn!(%error, "failed to subscribe on nwaku");
            }
        }

        if self.nwaku_url.is_some() || history_lookback.is_some() {
            {
                let mut fleet_rx = rx;
                let (sink_tx, sink_rx) = mpsc::channel(1024);
                rx = sink_rx;
                let mut cache = LruCache::new(CACHE_SIZE);

                let pubsub_path = self.pubsub_path.clone();
                let nwaku_url = self.nwaku_url.clone();
                let waku_fleet = Arc::clone(waku_fleet);
                let http = self.http_client.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(Duration::from_secs(2));
                    let encoded_pubsub_path = urlencoding::encode(&pubsub_path);
                    let nwaku_messages_url = nwaku_url.as_ref().map(|nwaku_url| {
                        format!("{nwaku_url}/relay/v1/messages/{encoded_pubsub_path}")
                    });
                    let mut store_peer_rx =
                        history_lookback.map(|_| waku_fleet.subscribe_store_peers());
                    let mut pending_store_peers: VecDeque<_> = if history_lookback.is_some() {
                        waku_fleet.store_peers().into()
                    } else {
                        VecDeque::new()
                    };
                    let mut queried_store_peers = HashSet::new();
                    loop {
                        if relay_sink_is_closed(&sink_tx) {
                            return;
                        }

                        if let Some(lookback) = history_lookback
                            && let Some(peer_id) = pending_store_peers.pop_front()
                        {
                            if !queried_store_peers.insert(peer_id) {
                                continue;
                            }

                            let end = now_nanos();
                            let start = end.saturating_sub(duration_nanos(lookback));
                            let query = StoreQueryOptions {
                                pubsub_topic: pubsub_path.clone(),
                                content_topics: content_topics.clone(),
                                time_start: Some(start),
                                time_end: Some(end),
                                pagination_limit: Some(FEE_HISTORY_PAGE_LIMIT),
                            };

                            let query_result = tokio::select! {
                                () = wait_for_relay_sink_closed(&sink_tx) => return,
                                result = waku_fleet.store_query_peer(peer_id, query) => result,
                            };

                            match query_result {
                                Ok(messages) => {
                                    let returned = messages.len();
                                    let mut matching_topics = 0usize;
                                    let mut delivered = 0usize;
                                    let mut deduped = 0usize;
                                    let mut dropped = 0usize;
                                    for msg in messages {
                                        if !content_topics.contains(&msg.content_topic) {
                                            continue;
                                        }
                                        matching_topics += 1;
                                        tracing::debug!(
                                            %peer_id,
                                            msg.content_topic,
                                            hash = msg.hash_key(),
                                            "received historical message from store peer"
                                        );
                                        match handle_relay_message(&mut cache, &sink_tx, msg) {
                                            RelayMessageOutcome::Delivered => delivered += 1,
                                            RelayMessageOutcome::Duplicate => deduped += 1,
                                            RelayMessageOutcome::Dropped => dropped += 1,
                                            RelayMessageOutcome::SinkClosed => return,
                                        }
                                    }
                                    tracing::debug!(
                                        %peer_id,
                                        returned,
                                        matching_topics,
                                        delivered,
                                        deduped,
                                        dropped,
                                        lookback_secs = lookback.as_secs(),
                                        "queried historical fee messages from store peer"
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(%peer_id, %error, "failed to query historical fee messages from store peer");
                                }
                            }
                            continue;
                        }

                        tokio::select! {
                            () = wait_for_relay_sink_closed(&sink_tx) => return,
                            _ = tick.tick(), if nwaku_messages_url.is_some() => {
                                let Some(url) = &nwaku_messages_url else { continue };
                                let response = tokio::select! {
                                    () = wait_for_relay_sink_closed(&sink_tx) => return,
                                    response = http.get(url).send() => response.and_then(reqwest::Response::error_for_status),
                                };
                                match response {
                                    Ok(resp) => {
                                        let messages = tokio::select! {
                                            () = wait_for_relay_sink_closed(&sink_tx) => return,
                                            messages = resp.json::<Vec<Message>>() => messages,
                                        };
                                        match messages {
                                            Ok(messages) => {
                                                for msg in messages {
                                                    if !content_topics.contains(&msg.content_topic) {
                                                        continue;
                                                    }
                                                    match general_purpose::STANDARD.decode(msg.payload.as_bytes()) {
                                                        Ok(payload) => {
                                                            let msg = WakuMessage {
                                                                content_topic: msg.content_topic,
                                                                payload,
                                                                ..Default::default()
                                                            };
                                                            tracing::debug!(msg.content_topic, hash=msg.hash_key(), "received message from nwaku");
                                                            if matches!(handle_relay_message(&mut cache, &sink_tx, msg), RelayMessageOutcome::SinkClosed) {
                                                                return;
                                                            }
                                                        }
                                                        Err(error) => {
                                                            tracing::warn!(%error, "failed to decode message payload");
                                                        }
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                tracing::warn!(%error, "failed to decode messages from nwaku");
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(?error, "failed to poll messages from nwaku");
                                    }
                                }
                            }
                            msg = fleet_rx.recv() => {
                                if let Some(msg) = msg {
                                    tracing::debug!(msg.content_topic, hash=msg.hash_key(), "received message from fleet");
                                    if matches!(handle_relay_message(&mut cache, &sink_tx, msg), RelayMessageOutcome::SinkClosed) {
                                        return;
                                    }
                                } else {
                                    tracing::warn!("fleet subscription channel closed");
                                    break;
                                }
                            }
                            store_peer = async {
                                match store_peer_rx.as_mut() {
                                    Some(rx) => Some(rx.recv().await),
                                    None => None,
                                }
                            }, if store_peer_rx.is_some() => {
                                match store_peer {
                                    Some(Ok(peer_id)) => {
                                        tracing::debug!(%peer_id, "queueing store peer for fee history query");
                                        pending_store_peers.push_back(peer_id);
                                    }
                                    Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                                        tracing::warn!(skipped, "missed store peer notifications");
                                        pending_store_peers.extend(waku_fleet.store_peers());
                                    }
                                    Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                        tracing::warn!("store peer notification channel closed");
                                        store_peer_rx = None;
                                    }
                                    None => {}
                                }
                            }
                        }
                    }
                });
            }
        }

        Ok(rx)
    }

    pub async fn publish(
        &self,
        content_topic: &str,
        json_payload_utf8: &[u8],
    ) -> Result<(), ClientError> {
        let pubsub_path = self.pubsub_path.as_str();
        tracing::debug!(
            pubsub_path,
            content_topic,
            payload_len = json_payload_utf8.len(),
            nwaku_configured = self.nwaku_url.is_some(),
            "publishing Waku message"
        );
        tracing::debug!(
            pubsub_path,
            content_topic,
            "publishing Waku message to fleet"
        );
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            let reason = self
                .disabled_reason
                .as_deref()
                .unwrap_or("Waku is unavailable for the selected network mode");
            return Err(ClientError::Disabled(reason.to_string()));
        };
        if let Err(error) = waku_fleet
            .lightpush_all(
                self.pubsub_path.clone(),
                content_topic.to_string(),
                json_payload_utf8.to_vec(),
            )
            .await
        {
            tracing::warn!(%error, pubsub_path, content_topic, "failed to publish message to waku fleet");
        } else {
            tracing::debug!(
                pubsub_path,
                content_topic,
                "published Waku message to fleet"
            );
        }
        if let Some(nwaku_url) = &self.nwaku_url {
            #[derive(Debug, serde::Serialize)]
            struct PublishBody<'a> {
                payload: &'a str,
                timestamp: u64,
                version: u32,
                #[serde(rename = "contentTopic")]
                content_topic: &'a str,
            }
            let pubsub_path = urlencoding::encode(pubsub_path);

            let payload_b64 = general_purpose::STANDARD.encode(json_payload_utf8);
            let body = PublishBody {
                payload: &payload_b64,
                timestamp: now_micros() * 1000,
                version: 0,
                content_topic,
            };
            let url = format!("{nwaku_url}/relay/v1/messages/{pubsub_path}");
            tracing::debug!(
                url = %url,
                content_topic,
                payload_len = json_payload_utf8.len(),
                "publishing Waku message to nwaku"
            );
            let res = self.http_client.post(url).json(&body).send().await?;
            let status = res.status();
            if status != reqwest::StatusCode::OK {
                let body = res.text().await?;
                tracing::warn!(
                    %status,
                    body_len = body.len(),
                    content_topic,
                    "nwaku publish returned non-OK status"
                );
                return Err(ClientError::NwakuStatus { body });
            }
            tracing::debug!(%status, content_topic, "published Waku message to nwaku");
        } else {
            tracing::debug!(
                pubsub_path,
                content_topic,
                "nwaku publish skipped because nwaku_url is not configured"
            );
        }
        Ok(())
    }
}

#[must_use]
pub fn relay_shard_pubsub_path(cluster_id: u32, shard_id: u32) -> String {
    format!("/waku/2/rs/{cluster_id}/{shard_id}")
}

fn now_micros() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_micros() as u64,
        Err(error) => {
            tracing::warn!(?error, "system time before unix epoch");
            0
        }
    }
}

fn now_nanos() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        Err(error) => {
            tracing::warn!(?error, "system time before unix epoch");
            0
        }
    }
}

fn duration_nanos(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn is_fee_content_topic(topic: &str) -> bool {
    matches!(ContentTopic::parse(topic), ContentTopic::Fees(_))
}

fn configured_cluster_id(cfg: &ClientConfig) -> u32 {
    cfg.cluster_id.unwrap_or(DEFAULT_CLUSTER_ID)
}

fn configured_shard_id(cfg: &ClientConfig) -> u32 {
    cfg.shard_id.unwrap_or(DEFAULT_SHARD_ID)
}

fn add_tor_doh_fallback(config: &mut WakuConfig, fallback_endpoints_configured: bool) {
    if !fallback_endpoints_configured
        && config.discovery.doh_endpoint != DEFAULT_CLEARNET_DOH_ENDPOINT
        && !config
            .discovery
            .doh_fallback_endpoints
            .iter()
            .any(|endpoint| endpoint == DEFAULT_CLEARNET_DOH_ENDPOINT)
    {
        config
            .discovery
            .doh_fallback_endpoints
            .push(DEFAULT_CLEARNET_DOH_ENDPOINT.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_SIZE, Client, ClientConfig, DEFAULT_CLUSTER_ID, DEFAULT_SHARD_ID,
        RelayMessageOutcome, add_tor_doh_fallback, handle_relay_message, is_fee_content_topic,
        relay_shard_pubsub_path, relay_sink_is_closed, wait_for_relay_sink_closed,
    };
    use lru::LruCache;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use waku::proto::WakuMessage;
    use waku::{DEFAULT_CLEARNET_DOH_ENDPOINT, DEFAULT_TOR_DOH_ENDPOINT};

    #[test]
    fn relay_shard_pubsub_path_uses_static_sharding_format() {
        assert_eq!(relay_shard_pubsub_path(5, 1), "/waku/2/rs/5/1");
        assert_eq!(relay_shard_pubsub_path(7, 2), "/waku/2/rs/7/2");
    }

    #[test]
    fn fee_history_topic_detection_only_matches_fees() {
        assert!(is_fee_content_topic("/railgun/v2/0-1-fees/json"));
        assert!(is_fee_content_topic("/railgun/v2/0-42161-fees/json"));
        assert!(!is_fee_content_topic("/railgun/v2/0-1-transact/json"));
        assert!(!is_fee_content_topic(
            "/railgun/v2/0-1-transact-response/json"
        ));
        assert!(!is_fee_content_topic("/other/v2/0-1-fees/json"));
    }

    #[test]
    fn relay_message_delivery_reports_closed_sink() {
        let (sink_tx, sink_rx) = mpsc::channel(1);
        drop(sink_rx);
        let mut cache = LruCache::new(CACHE_SIZE);
        let msg = WakuMessage {
            content_topic: "/railgun/v2/0-1-fees/json".to_string(),
            payload: vec![1, 2, 3],
            ..Default::default()
        };

        assert_eq!(
            handle_relay_message(&mut cache, &sink_tx, msg),
            RelayMessageOutcome::SinkClosed
        );
    }

    #[tokio::test]
    async fn relay_sink_closed_wait_completes_without_messages() {
        let (sink_tx, sink_rx) = mpsc::channel::<WakuMessage>(1);
        assert!(!relay_sink_is_closed(&sink_tx));

        drop(sink_rx);

        tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_relay_sink_closed(&sink_tx),
        )
        .await
        .expect("closed sink should wake relay task promptly");
        assert!(relay_sink_is_closed(&sink_tx));
    }

    #[test]
    fn waku_client_config_applies_schema_fields() {
        let cfg = ClientConfig {
            nwaku_url: None,
            shard_id: Some(3),
            direct_peers: Vec::new(),
            dns_enr_trees: Some(vec!["enrtree://example".to_string()]),
            doh_endpoint: Some("https://example.invalid/dns-query".to_string()),
            doh_fallback_endpoints: Some(vec![
                "https://fallback.example.invalid/dns-query".to_string(),
            ]),
            cluster_id: Some(7),
            max_peers: Some(42),
            peer_connection_timeout: Some(Duration::from_secs(7)),
        };

        let waku = super::Client::build_waku_config(&cfg);

        assert_eq!(waku.cluster_id, 7);
        assert_eq!(waku.shard_id, 3);
        assert_eq!(waku.discovery.enr_trees, vec!["enrtree://example"]);
        assert_eq!(
            waku.discovery.doh_endpoint,
            "https://example.invalid/dns-query"
        );
        assert_eq!(
            waku.discovery.doh_fallback_endpoints,
            vec!["https://fallback.example.invalid/dns-query".to_string()]
        );
        assert_eq!(waku.node.connection_cap, 42);
        assert_eq!(waku.node.request_timeout, Duration::from_secs(7));
    }

    #[test]
    fn waku_client_config_uses_relay_defaults() {
        let cfg = ClientConfig {
            nwaku_url: None,
            shard_id: None,
            direct_peers: Vec::new(),
            dns_enr_trees: None,
            doh_endpoint: None,
            doh_fallback_endpoints: None,
            cluster_id: None,
            max_peers: None,
            peer_connection_timeout: None,
        };

        let waku = super::Client::build_waku_config(&cfg);

        assert_eq!(waku.cluster_id, DEFAULT_CLUSTER_ID);
        assert_eq!(waku.shard_id, DEFAULT_SHARD_ID);
    }

    #[test]
    fn tor_doh_fallback_adds_clearnet_endpoint() {
        let mut waku = waku::WakuConfig::default();
        waku.discovery.doh_endpoint = DEFAULT_TOR_DOH_ENDPOINT.to_string();

        add_tor_doh_fallback(&mut waku, false);

        assert_eq!(waku.discovery.doh_endpoint, DEFAULT_TOR_DOH_ENDPOINT);
        assert_eq!(
            waku.discovery.doh_fallback_endpoints,
            vec![DEFAULT_CLEARNET_DOH_ENDPOINT.to_string()]
        );
    }

    #[test]
    fn tor_doh_fallback_respects_explicit_empty_list() {
        let mut waku = waku::WakuConfig::default();
        waku.discovery.doh_endpoint = DEFAULT_TOR_DOH_ENDPOINT.to_string();

        add_tor_doh_fallback(&mut waku, true);

        assert!(waku.discovery.doh_fallback_endpoints.is_empty());
    }

    #[tokio::test]
    async fn client_drop_shuts_down_embedded_waku_node() {
        let cfg = ClientConfig {
            nwaku_url: None,
            shard_id: None,
            direct_peers: Vec::new(),
            dns_enr_trees: Some(Vec::new()),
            doh_endpoint: None,
            doh_fallback_endpoints: None,
            cluster_id: None,
            max_peers: None,
            peer_connection_timeout: None,
        };
        let client = Client::new(&cfg).expect("client starts");
        let node = Arc::clone(client.waku_fleet.as_ref().expect("Waku node enabled"));
        assert!(!node.is_shutdown());

        drop(client);

        assert!(node.is_shutdown());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
