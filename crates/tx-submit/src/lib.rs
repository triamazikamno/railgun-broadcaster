use alloy::primitives::{TxHash, keccak256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::Signer;
use alloy::signers::k256::ecdsa::{SigningKey, signature};
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use config::{Chain, Rpc};
use reqwest::StatusCode;
use reqwest::Url;
use serde_json::json;
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone)]
enum RpcClient {
    Regular(RootProvider),
    Flashbots {
        url: Url,
        http_client: reqwest::Client,
        signer: LocalSigner<SigningKey>,
        num_blocks: u64,
        query_rpc_pool: Arc<QueryRpcPool>,
    },
    BloxrouteBackrunme {
        url: Url,
        http_client: reqwest::Client,
        api_key: String,
    },
}

impl RpcClient {
    async fn broadcast(
        &self,
        tx: &[u8],
        additional_txs: Option<&[Vec<u8>]>,
    ) -> Result<Option<TxHash>, TxSubmitError> {
        match self {
            Self::Regular(provider) => {
                let pending = provider.send_raw_transaction(tx).await.map_err(|source| {
                    TxSubmitError::Provider {
                        queue: "regular",
                        source,
                    }
                })?;
                Ok(Some(*pending.tx_hash()))
            }
            Self::Flashbots {
                http_client,
                signer,
                num_blocks,
                url,
                query_rpc_pool,
            } => {
                #[derive(serde::Deserialize)]
                struct Response {
                    result: BundleResult,
                }
                #[derive(serde::Deserialize)]
                struct BundleResult {
                    #[serde(rename = "bundleHash")]
                    bundle_hash: TxHash,
                }
                let mut txs = vec![alloy::hex::encode_prefixed(tx)];
                if let Some(additional_txs) = additional_txs {
                    txs.extend(additional_txs.iter().map(alloy::hex::encode_prefixed));
                }
                let Some(provider_handle) = query_rpc_pool.random_provider() else {
                    return Err(TxSubmitError::NoQueryRpc);
                };
                let block =
                    provider_handle
                        .provider
                        .get_block_number()
                        .await
                        .map_err(|source| {
                            query_rpc_pool.mark_bad_provider(&provider_handle);
                            TxSubmitError::Provider {
                                queue: "flashbots",
                                source,
                            }
                        })?;
                for i in 1..=*num_blocks {
                    let bundle = json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "eth_sendBundle",
                            "params": [{
                              "txs": txs,
                              "blockNumber": format!("0x{:x}", block + i),
                          }]

                    });
                    let payload = serde_json::to_vec(&bundle)?;
                    let signature = signer
                        .sign_message(format!("0x{:x}", keccak256(&payload)).as_bytes())
                        .await
                        .map_err(|source| TxSubmitError::Signer {
                            message: source.to_string(),
                        })?
                        .as_bytes();
                    let signature = format!(
                        "{:?}:{}",
                        signer.address(),
                        alloy::hex::encode_prefixed(signature)
                    );
                    let res = http_client
                        .post(url.clone())
                        .header("X-Flashbots-Signature", signature)
                        .json(&bundle)
                        .send()
                        .await
                        .map_err(|source| TxSubmitError::FlashbotsBundle {
                            block: block + i,
                            source,
                        })?;
                    if !res.status().is_success() {
                        let status = res.status();
                        let body = res.text().await.unwrap_or_default();
                        return Err(TxSubmitError::HttpStatus { status, body });
                    }
                    let bundle_hash = res.json::<Response>().await?.result.bundle_hash;
                    tracing::debug!("bundle sent for block {}: {bundle_hash:?}", block + i);
                }
                Ok(None)
            }
            Self::BloxrouteBackrunme {
                http_client,
                api_key,
                url,
            } => {
                #[derive(serde::Deserialize)]
                struct Response {
                    result: Option<TxHash>,
                }
                let res = http_client
                    .post(url.clone())
                    .header("Authorization", api_key)
                    .json(&json!({"id": "1", "method": "blxr_private_tx", "params": {"transaction": alloy::hex::encode(tx)}}))
                    .send()
                    .await?;
                if !res.status().is_success() {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    return Err(TxSubmitError::HttpStatus { status, body });
                }
                Ok(res.json::<Response>().await?.result)
            }
        }
    }
    const fn name(&self) -> &'static str {
        match self {
            Self::Regular(_) => "regular",
            Self::Flashbots { .. } => "flashbots",
            Self::BloxrouteBackrunme { .. } => "bloxroute-backrunme",
        }
    }
}

#[derive(Default)]
pub struct TxBroadcaster {
    mev_rpcs: Vec<RpcClient>,
    mempool_rpcs: Vec<RpcClient>,
    private_rpcs: Vec<RpcClient>,
}

#[derive(Debug, Error)]
pub enum BroadcasterInitError {
    #[error("could not find evm wallet")]
    NoEvmWallets,
    #[error(transparent)]
    InitSignature(#[from] signature::Error),
}

#[derive(Debug, Error)]
pub enum TxSubmitError {
    #[error("provider error ({queue})")]
    Provider {
        queue: &'static str,
        #[source]
        source: alloy::transports::TransportError,
    },
    #[error("no query rpc available")]
    NoQueryRpc,
    #[error("flashbots bundle error")]
    FlashbotsBundle {
        block: u64,
        #[source]
        source: reqwest::Error,
    },
    #[error("http error")]
    Http(#[from] reqwest::Error),
    #[error("http status {status}")]
    HttpStatus { status: StatusCode, body: String },
    #[error("signer error: {message}")]
    Signer { message: String },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl TxSubmitError {
    #[must_use]
    pub fn is_tx_already_known(&self) -> bool {
        matches!(self, Self::Provider { source, .. }
            if source.as_error_resp().is_some_and(|resp| {
                resp.message.contains("already known")
                    || resp.message.contains("already in mempool")
                    || resp.message.contains("invalid sequence")
                    || resp.message.contains("nonce too low")
            })
        )
    }
}

impl TryFrom<(Chain, Arc<QueryRpcPool>)> for TxBroadcaster {
    type Error = BroadcasterInitError;
    fn try_from((cfg, query_rpc_pool): (Chain, Arc<QueryRpcPool>)) -> Result<Self, Self::Error> {
        let rpc_count = cfg.submit_rpcs.len();
        let mut mev_rpcs = Vec::with_capacity(rpc_count);
        let mut mempool_rpcs = Vec::with_capacity(rpc_count);
        let mut private_rpcs = Vec::with_capacity(rpc_count);
        let signer = PrivateKeySigner::from(
            SigningKey::from_bytes(
                cfg.evm_wallets
                    .first()
                    .ok_or(Self::Error::NoEvmWallets)?
                    .as_ref()
                    .into(),
            )
            .map_err(BroadcasterInitError::InitSignature)?,
        );
        for rpc in cfg.submit_rpcs {
            match rpc {
                Rpc::Flashbots { url, num_blocks } => {
                    let rpc = RpcClient::Flashbots {
                        url,
                        http_client: reqwest::Client::new(),
                        signer: signer.clone(),
                        num_blocks,
                        query_rpc_pool: query_rpc_pool.clone(),
                    };
                    private_rpcs.push(rpc.clone());
                    mempool_rpcs.push(rpc.clone());
                }
                Rpc::Normal(url) => {
                    let provider = ProviderBuilder::new()
                        .connect_http(url.clone())
                        .root()
                        .clone();
                    mempool_rpcs.push(RpcClient::Regular(provider));
                }
                Rpc::Private { url, has_mev } => {
                    let provider = ProviderBuilder::new()
                        .connect_http(url.clone())
                        .root()
                        .clone();
                    if has_mev {
                        mev_rpcs.push(RpcClient::Regular(provider.clone()));
                    }
                    private_rpcs.push(RpcClient::Regular(provider.clone()));
                    mempool_rpcs.push(RpcClient::Regular(provider));
                }
                Rpc::BloxrouteBackrunme { url, api_key } => {
                    mev_rpcs.push(RpcClient::BloxrouteBackrunme {
                        http_client: reqwest::Client::new(),
                        api_key,
                        url,
                    });
                }
            }
        }

        if mev_rpcs.is_empty() {
            mev_rpcs.clone_from(&mempool_rpcs);
        }
        if private_rpcs.is_empty() {
            private_rpcs.clone_from(&mev_rpcs);
        }

        Ok(Self {
            mev_rpcs,
            mempool_rpcs,
            private_rpcs,
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Queue {
    Mempool,
    Mev,
    Private,
}

impl TxBroadcaster {
    pub async fn broadcast(
        &self,
        tx: Vec<u8>,
        additional_txs: Option<Vec<Vec<u8>>>,
        queue: Queue,
    ) -> Result<Option<TxHash>, TxSubmitError> {
        let (_queue_label, rpcs) = match queue {
            Queue::Mempool => ("mempool", &self.mempool_rpcs),
            Queue::Mev => ("mev", &self.mev_rpcs),
            Queue::Private => ("private", &self.private_rpcs),
        };
        let mut result_tx_hash = None;
        let mut result_error = None;
        for rpc in rpcs {
            match rpc.broadcast(&tx, additional_txs.as_deref()).await {
                Ok(tx_hash) => {
                    match tx_hash {
                        None => tracing::info!(rpc = rpc.name(), "tx broadcasted"),
                        Some(tx_hash) => {
                            tracing::info!(rpc = rpc.name(), ?tx_hash, "tx broadcasted");
                        }
                    }
                    if tx_hash.is_some() {
                        result_tx_hash = tx_hash;
                    }
                }
                Err(error) => {
                    if error.is_tx_already_known() {
                        continue;
                    }
                    tracing::warn!("failed to broadcast tx: {error:?}");
                    result_error = Some(error);
                }
            }
        }
        match result_tx_hash {
            Some(_) => Ok(result_tx_hash),
            None => result_error.map_or(Ok(None), Err),
        }
    }
}
