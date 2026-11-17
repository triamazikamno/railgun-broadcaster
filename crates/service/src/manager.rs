//! The Waku message loop that routes fee and transact messages to each
//! chain's `BroadcasterService`.

use std::collections::HashSet;
use std::sync::Arc;

use alloy::primitives::{Bytes, ChainId, FixedBytes};
use serde::{Deserialize, Serialize};
use tracing::{Instrument, info, info_span, warn};
use waku_relay::client::Client;
use waku_relay::msg::ContentTopic;

use crate::{BroadcasterManagerError, BroadcasterService, HandleTransactError};

/// Payload format for transact messages received over Waku.
#[derive(Serialize, Deserialize, Debug)]
struct TransactParams {
    pub pubkey: FixedBytes<32>,
    #[serde(rename = "encryptedData")]
    pub encrypted_data: [Bytes; 2],
}

/// Root envelope for transact messages.
#[derive(Serialize, Deserialize, Debug)]
struct TransactEnvelope {
    pub method: String,
    pub params: TransactParams,
}

/// Manages multiple `BroadcasterService` instances and runs the Waku message loop.
pub struct BroadcasterManager {
    services: Vec<BroadcasterService>,
    waku: Arc<Client>,
    trusted_signers: HashSet<String>,
}

impl BroadcasterManager {
    /// Creates a new manager from pre-initialized services and a Waku client.
    #[must_use]
    pub const fn new(
        services: Vec<BroadcasterService>,
        waku: Arc<Client>,
        trusted_signers: HashSet<String>,
    ) -> Self {
        Self {
            services,
            waku,
            trusted_signers,
        }
    }

    /// Subscribes to Waku and runs the message processing loop.
    pub async fn run(&self) -> Result<(), BroadcasterManagerError> {
        let chain_ids: Vec<ChainId> = self
            .services
            .iter()
            .map(BroadcasterService::chain_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let transact_content_topics: Vec<String> = chain_ids
            .iter()
            .map(|chain_id| ContentTopic::transact_topic(*chain_id))
            .collect();
        let fee_content_topics: Vec<String> = chain_ids
            .iter()
            .map(|chain_id| ContentTopic::fees_topic(*chain_id))
            .collect();

        let mut transact_rx = self.waku.subscribe(transact_content_topics).await?;
        let mut fee_rx = self
            .waku
            .subscribe_with_fee_history(fee_content_topics)
            .await?;

        loop {
            let msg = tokio::select! {
                msg = transact_rx.recv() => msg,
                msg = fee_rx.recv() => msg,
            };
            let Some(msg) = msg else {
                warn!("get message failed, retrying...");
                continue;
            };

            let topic = ContentTopic::from(msg.content_topic.clone());
            match topic {
                ContentTopic::Pong | ContentTopic::TransactResponse | ContentTopic::Noop => {}
                ContentTopic::Fees(chain_id) => {
                    self.handle_fees_message(chain_id, &msg.payload).await;
                }
                ContentTopic::Transact(chain_id) => {
                    self.handle_transact_message(chain_id, &msg.payload).await;
                }

                ContentTopic::Unknown(topic) => {
                    info!(payload=%String::from_utf8_lossy(&msg.payload), %topic, "unhandled topic");
                }
            }
        }
    }

    /// Hands a trusted signer's fees to every service on `chain_id`.
    async fn handle_fees_message(&self, chain_id: ChainId, payload: &[u8]) {
        let payload = match serde_json::from_slice::<fees::Payload>(payload) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(%error, "parse fees failed");
                return;
            }
        };
        let body = match serde_json::from_slice::<fees::Body>(payload.data.as_ref()) {
            Ok(body) => body,
            Err(error) => {
                warn!(
                    %error,
                    chain_id,
                    payload = %String::from_utf8_lossy(payload.data.as_ref()),
                    "Failed to deserialize fees message",
                );
                return;
            }
        };
        if !self.trusted_signers.contains(body.railgun_address.as_ref()) {
            return;
        }
        for service in &self.services {
            if service.chain_id == chain_id {
                service
                    .handle_trusted_signer_fees(
                        body.railgun_address.as_ref().to_string(),
                        body.fees.clone(),
                    )
                    .await;
            }
        }
    }

    /// Offers a transact request to every service on `chain_id`.
    async fn handle_transact_message(&self, chain_id: ChainId, payload: &[u8]) {
        if payload.len() < 64 {
            return;
        }
        let payload = match serde_json::from_slice::<TransactEnvelope>(payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(
                    %error,
                    payload=%String::from_utf8_lossy(payload),
                    "decode payload failed",
                );
                return;
            }
        };
        if payload.method != "transact" {
            return;
        }
        for service in self
            .services
            .iter()
            .filter(|service| service.chain_id() == chain_id)
        {
            if let Err(error) = service
                .handle_transact_request(payload.params.pubkey.0, &payload.params.encrypted_data)
                .instrument(info_span!("transact", chain_id))
                .await
                && !matches!(error, HandleTransactError::NotForUs)
            {
                warn!(?error, "failed to handle transact request");
            }
        }
    }
}
