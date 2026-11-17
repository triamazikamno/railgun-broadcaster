//! The task that refreshes prices and publishes this broadcaster's signed
//! fees over Waku on every refresh interval.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Address, ChainId, FixedBytes};
use broadcaster_core::crypto::railgun::Address as RailgunAddress;
use fees::Manager as FeesManager;
use tracing::{Instrument, debug, error, info_span, warn};
use waku_relay::client::Client;
use waku_relay::msg::ContentTopic;

use crate::{API_VERSION, BroadcasterService};

impl BroadcasterService {
    /// # Panics
    ///
    /// Will panic if time goes backwards
    pub fn spawn_fees_publisher(&self) {
        let chain_id = self.chain_id;
        let publisher = FeesPublisher {
            fees_manager: self.fees_manager.clone(),
            push_interval: self.fees_refresh_interval,
            fee_ttl: self.fees_ttl,
            required_poi_list: self.required_poi_list.clone(),
            railgun_address: self.advertised_addr.clone(),
            relay_adapt: self.relay_adapt_contract,
            relay_adapt_7702: self.relay_adapt_7702_contract,
            identifier: self.identifier.clone(),
            client: self.client.clone(),
            key: self.key,
            chain_id,
            count_transact_requests: self.count_transact_requests.clone(),
            count_txs_landed: self.count_txs_landed.clone(),
            available_wallets: self.evm_wallets.len() as u32,
        };

        tokio::spawn(publisher.run().instrument(info_span!("fees", chain_id)));
    }
}

struct FeesPublisher {
    fees_manager: Arc<FeesManager>,
    push_interval: Duration,
    fee_ttl: Duration,
    required_poi_list: Vec<FixedBytes<32>>,
    railgun_address: RailgunAddress,
    relay_adapt: Option<Address>,
    relay_adapt_7702: Option<Address>,
    identifier: Option<String>,
    client: Arc<Client>,
    key: [u8; 32],
    chain_id: ChainId,
    count_transact_requests: Arc<AtomicU32>,
    count_txs_landed: Arc<AtomicU32>,
    available_wallets: u32,
}

impl FeesPublisher {
    async fn run(self) {
        let mut interval = tokio::time::interval(self.push_interval);
        loop {
            interval.tick().await;
            self.publish_once().await;
        }
    }

    async fn publish_once(&self) {
        if let Err(error) = self.fees_manager.update_prices().await {
            error!(?error, "update prices failed");
        }
        let reliability = fee_reliability(
            self.count_transact_requests.load(Ordering::Relaxed),
            self.count_txs_landed.load(Ordering::Relaxed),
        );
        let fee_expiration = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration
                .as_millis()
                .saturating_add(self.fee_ttl.as_millis()),
            Err(error) => {
                warn!(?error, "system time before unix epoch");
                return;
            }
        };
        let fee_expiration = u64::try_from(fee_expiration).unwrap_or(u64::MAX);
        let (fees_id, fees) = self.fees_manager.create_fees().await;
        let fees = fees::Body {
            fees,
            fee_expiration,
            fees_id,
            railgun_address: self.railgun_address.clone(),
            available_wallets: self.available_wallets,
            version: API_VERSION.to_string(),
            relay_adapt: self.relay_adapt,
            relay_adapt_7702: self.relay_adapt_7702,
            required_poi_list_keys: self.required_poi_list.iter().map(hex::encode).collect(),
            reliability,
            identifier: self.identifier.clone(),
        };
        debug!(payload=?serde_json::to_string(&fees), "our fees");
        match fees.into_signed_payload(self.key) {
            Ok(payload) => self.publish_signed(&payload).await,
            Err(error) => {
                error!(%error, "sign fees failed");
            }
        }
    }

    /// Publishes `payload` once its signature verifies.
    async fn publish_signed(&self, payload: &fees::Payload) {
        let (decoded_payload, is_valid) = match payload.decode_and_verify() {
            Ok(result) => result,
            Err(error) => {
                warn!(?error, "verify fees signature failed");
                return;
            }
        };
        if !is_valid {
            warn!(?decoded_payload, "fees signature invalid");
            return;
        }
        match serde_json::to_string(payload) {
            Ok(payload) => {
                let content_topic = ContentTopic::fees_topic(self.chain_id);
                if let Err(error) = self
                    .client
                    .publish(&content_topic, payload.as_bytes())
                    .await
                {
                    warn!(%error, "publish fees failed");
                }
            }
            Err(error) => {
                error!(%error, "serialize fees failed");
            }
        }
    }
}

/// The advertised share of transact requests that landed, rounded to two
/// places. Fewer than 10 requests, or none lost, advertise 0.99.
fn fee_reliability(count_transact_requests: u32, count_txs_landed: u32) -> f64 {
    if count_transact_requests < 10 || count_transact_requests == count_txs_landed {
        0.99
    } else {
        let ratio = f64::from(count_txs_landed) / f64::from(count_transact_requests);
        (ratio * 100.0).round() / 100.0
    }
}
