use crate::error::ClientError;
use crate::msg::Message;
use base64::Engine;
use base64::engine::general_purpose;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use waku::discovery::DiscoveredPeer;
use waku::proto::{HashKey, WakuMessage};
use waku::types::{parse_multiaddr, parse_peer_id};
use waku::{WakuConfig, WakuNode};

pub const PUBSUB_PATH: &str = "/waku/2/rs/1/1";
const CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(500) {
    Some(n) => n,
    None => panic!("cache size must be non-zero"),
};

pub struct Client {
    http_client: reqwest::Client,
    nwaku_url: Option<String>,
    waku_fleet: Arc<WakuNode>,
}

impl Client {
    pub fn new(cfg: &config::Waku) -> Result<Self, ClientError> {
        let mut config = WakuConfig::default();
        if let Some(dns_enr_trees) = &cfg.dns_enr_trees {
            config.discovery.enr_trees.clone_from(dns_enr_trees);
        }
        if let Some(doh_endpoint) = &cfg.doh_endpoint {
            config.discovery.doh_endpoint.clone_from(doh_endpoint);
        }
        if let Some(cluster_id) = cfg.cluster_id {
            config.cluster_id = cluster_id;
        }
        if let Some(max_peers) = cfg.max_peers {
            config.node.connection_cap = max_peers;
        }
        if let Some(request_timeout) = cfg.peer_connection_timeout {
           config.node.request_timeout = request_timeout.into_inner();
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
        Ok(Self {
            http_client: reqwest::Client::new(),
            nwaku_url: cfg.nwaku_url.clone(),
            waku_fleet: waku,
        })
    }

    pub async fn subscribe(
        &self,
        topic: &str,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        let mut rx = self
            .waku_fleet
            .filter_subscribe(topic.to_string(), content_topics.clone())
            .await
            .map_err(ClientError::FleetSubscribe)?;
        if let Some(nwaku_url) = &self.nwaku_url {
            let url = format!("{nwaku_url}/relay/v1/subscriptions");
            if let Err(error) = self
                .http_client
                .post(url)
                .json(&vec![topic])
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
            {
                tracing::warn!(%error, "failed to subscribe on nwaku");
            }
            {
                let mut fleet_rx = rx;
                let (sink_tx, sink_rx) = mpsc::channel(64);
                rx = sink_rx;
                let mut cache = LruCache::new(CACHE_SIZE);

                let topic = topic.to_string();
                let nwaku_url = nwaku_url.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                    let pubsub_path = urlencoding::encode(&topic);
                    let url = format!("{nwaku_url}/relay/v1/messages/{pubsub_path}");
                    let http = reqwest::Client::new();
                    let mut handle_message = |message: WakuMessage| {
                        let hash = message.hash_key();

                        if cache.contains(&hash) {
                            tracing::debug!(hash, "duplicate message, ignoring");
                            return;
                        }
                        cache.put(hash, ());
                        if let Err(error) = sink_tx.try_send(message) {
                            tracing::warn!(%error, "failed to send message to sink");
                        }
                    };
                    loop {
                        tokio::select! {
                            _ = tick.tick() => {
                                match http.get(&url).send().await.and_then(reqwest::Response::error_for_status) {
                                    Ok(resp) => {
                                        match resp.json::<Vec<Message>>().await {
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
                                                            handle_message(msg);
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
                                    handle_message(msg);
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
        pubsub_path: &str,
        content_topic: &str,
        json_payload_utf8: &[u8],
    ) -> Result<(), ClientError> {
        tracing::debug!(payload=%String::from_utf8_lossy(json_payload_utf8), "publishing message");
        if let Err(error) = self
            .waku_fleet
            .lightpush_all(
                PUBSUB_PATH.to_string(),
                content_topic.to_string(),
                json_payload_utf8.to_vec(),
            )
            .await
        {
            tracing::warn!("failed to publish message to waku fleet: {error}");
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
            // tracing::debug!(body=alloy::consensus::private::serde_json::to_string(&body).unwrap(), "publishing message to nwaku");
            let res = self.http_client.post(url).json(&body).send().await?;
            if res.status() != reqwest::StatusCode::OK {
                let body = res.text().await?;
                return Err(ClientError::NwakuStatus { body });
            }
        }
        Ok(())
    }
}
fn now_micros() -> u64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    d.as_micros() as u64
}
