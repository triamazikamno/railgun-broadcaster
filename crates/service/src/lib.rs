use alloy::eips::Encodable2718;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, TxHash, U256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use alloy::transports::TransportErrorKind;
use alloy::{hex, sol, uint};
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, PrivateKey, RailgunError};
use broadcaster_core::transact::{
    DecryptedTransact, ParsedTransactCalldata, TransactError, parse_transact_calldata,
    try_decrypt_transact_request,
};
use broadcaster_core::transact_response::{
    build_transact_response_error, build_transact_response_txhash,
};
use config::Chain;
use fees::{FeesError, Manager as FeesManager};
use poi::poi::Poi;
use rand::seq::IndexedRandom;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{Instrument, debug, error, info, info_span, warn};
use tx_submit::{Queue, TxBroadcaster};
use waku_relay::client::{Client, PUBSUB_PATH};

use poi::error::PoiError;
use serde::{Deserialize, Serialize};
use waku_relay::msg::ContentTopic;

sol! {
    function balanceOf(address account) external view returns (uint256);
    struct Call {
        address to;
        bytes data;
        uint256 value;
    }
    function multicall(bool _requireSuccess, Call[] calldata _calls) external payable;
    function transfer(address recipient, uint256 amount) external;
}

pub const API_VERSION: &str = "8.2.3";

#[derive(Debug, Error)]
pub enum HandleTransactError {
    #[error("failed to decrypt transact request: {0}")]
    Decrypt(#[from] TransactError),
    #[error("transact is not for us")]
    NotForUs,
    #[error("failed to parse transact calldata: {0}")]
    Parse(#[source] TransactError),
    #[error("validate pre tx poi: {0}")]
    Poi(#[from] PoiError),
    #[error("enqueue tx for submission: {0}")]
    Enqueue(#[from] kanal::SendError),
}

#[derive(Debug, Error)]
pub enum BroadcasterServiceError {
    #[error("derive railgun address failed: {0}")]
    DeriveAddress(#[from] RailgunError),
    #[error("invalid viewing privkey")]
    InvalidViewingPrivkey,
    #[error("init tx broadcaster failed: {0}")]
    InitBroadcaster(#[from] tx_submit::BroadcasterInitError),
    #[error("missing multicall_contract")]
    MissingMulticallContract,
    #[error("simulation failed: {0}")]
    SimulationFailed(#[from] alloy::transports::RpcError<TransportErrorKind>),
    #[error("failed to decode EVM private key: {0}")]
    DecodePrivateKey(#[from] alloy::signers::k256::ecdsa::signature::Error),
}

#[derive(Debug, Error)]
pub enum SubmitTxError {
    #[error("sign tx request: {0}")]
    Sign(#[from] alloy::network::TransactionBuilderError<alloy::network::Ethereum>),
    #[error("broadcast transaction: {0}")]
    Broadcast(#[from] tx_submit::TxSubmitError),
    #[error("no tx hash found")]
    MissingHash,
}

#[derive(Debug, Error)]
pub enum BroadcasterManagerError {
    #[error("waku subscribe failed: {0}")]
    Subscribe(#[from] waku_relay::ClientError),
}

type FeesProvider = FillProvider<
    JoinFill<
        alloy::providers::Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

type FeesManagerClient = FeesManager<FeesProvider>;

type ResponseSender = kanal::AsyncSender<(DecryptedTransact, ParsedTransactCalldata)>;
type ResponseReceiver = kanal::AsyncReceiver<(DecryptedTransact, ParsedTransactCalldata)>;

pub struct BroadcasterService {
    chain_id: ChainId,
    key: [u8; 32],
    addr: RailgunAddress,
    tx: ResponseSender,
    rx: ResponseReceiver,
    broadcaster: Arc<TxBroadcaster>,
    fees_manager: Arc<FeesManagerClient>,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    count_transact_requests: Arc<AtomicU32>,
    count_txs_landed: Arc<AtomicU32>,
    client: Arc<Client>,
    poi: Option<Arc<Poi>>,
    required_poi_list: Vec<FixedBytes<32>>,
    rpc: RootProvider,
    relay_adapt_contract: Address,
    identifier: Option<String>,
    fees_refresh_interval: Duration,
    fees_ttl: Duration,
}

impl BroadcasterService {
    pub fn new(
        chain_cfg: Chain,
        client: Arc<Client>,
        poi: Option<Arc<Poi>>,
        required_poi_list: Vec<FixedBytes<32>>,
    ) -> Result<Self, BroadcasterServiceError> {
        let (tx, rx) = kanal::bounded_async::<(DecryptedTransact, ParsedTransactCalldata)>(20);
        let count_transact_requests = Arc::new(AtomicU32::new(0));
        let count_txs_landed = Arc::new(AtomicU32::new(0));
        let viewing_privkey: PrivateKey = chain_cfg.viewing_privkey.clone().into();
        let addr = viewing_privkey.derive_address(None)?;
        let key = viewing_privkey
            .decode_vpriv()
            .map_err(|_| BroadcasterServiceError::InvalidViewingPrivkey)?;
        let broadcaster = Arc::new(TxBroadcaster::try_from(chain_cfg.clone())?);
        let rpc = ProviderBuilder::new().connect_http(chain_cfg.query_rpc);
        let multicall_contract = chain_cfg
            .multicall_contract
            .ok_or(BroadcasterServiceError::MissingMulticallContract)?;
        let fee_bonus = uint!(1000000000000000000_U256)
            + U256::from(chain_cfg.fee_bonus * 1000.0) * uint!(10000000000000_U256);
        let fees_manager = Arc::new(FeesManager::new(
            &chain_cfg.fees,
            fee_bonus,
            rpc.clone(),
            multicall_contract,
        ));
        let evm_wallets = chain_cfg
            .evm_wallets
            .iter()
            .map(|key| {
                let signer = PrivateKeySigner::from(SigningKey::from_bytes(key.as_ref().into())?);
                Ok((EthereumWallet::from(signer.clone()), signer))
            })
            .collect::<Result<Vec<_>, BroadcasterServiceError>>()?;

        Ok(Self {
            chain_id: chain_cfg.chain_id,
            key,
            addr,
            tx,
            rx,
            broadcaster,
            fees_manager,
            evm_wallets,
            count_transact_requests,
            count_txs_landed,
            client,
            poi,
            required_poi_list,
            rpc: rpc.root().clone(),
            relay_adapt_contract: chain_cfg.relay_adapt_contract,
            identifier: chain_cfg.identifier,
            fees_refresh_interval: chain_cfg.fees_refresh_interval.into_inner(),
            fees_ttl: chain_cfg.fees_ttl.into_inner(),
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn addr(&self) -> &RailgunAddress {
        &self.addr
    }

    pub async fn update_prices(&self) -> Result<(), FeesError> {
        self.fees_manager.update_prices().await
    }

    /// # Panics
    ///
    /// Will panic if time goes backwards
    pub fn spawn_fees_publisher(&self) {
        let fees_manager = self.fees_manager.clone();
        let push_interval = self.fees_refresh_interval;
        let fee_ttl = self.fees_ttl;
        let required_poi_list = self.required_poi_list.clone();
        let railgun_address = self.addr.clone();
        let relay_adapt = self.relay_adapt_contract;
        let identifier = self.identifier.clone();
        let client = self.client.clone();
        let key = self.key;
        let chain_id = self.chain_id;
        let count_transact_requests = self.count_transact_requests.clone();
        let count_txs_landed = self.count_txs_landed.clone();
        let available_wallets = self.evm_wallets.len() as u32;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(push_interval);
            loop {
                interval.tick().await;
                if let Err(error) = fees_manager.update_prices().await {
                    error!(?error, "update prices failed");
                }
                let reliability = {
                    let count_transact_requests = count_transact_requests.load(Ordering::Relaxed);
                    let count_txs_landed = count_txs_landed.load(Ordering::Relaxed);
                    if count_transact_requests < 10 || count_transact_requests == count_txs_landed {
                        0.99
                    } else {
                        let ratio =
                            f64::from(count_txs_landed) / f64::from(count_transact_requests);
                        (ratio * 100.0).round() / 100.0
                    }
                };
                let fee_expiration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards")
                    .as_millis()
                    + fee_ttl.as_millis();
                let (fees_id, fees) = fees_manager.create_fees().await;
                let fees = fees::Body {
                    fees,
                    fee_expiration: fee_expiration as u64,
                    fees_id,
                    railgun_address: railgun_address.clone(),
                    available_wallets,
                    version: API_VERSION.to_string(),
                    relay_adapt,
                    required_poi_list_keys: required_poi_list.iter().map(hex::encode).collect(),
                    reliability,
                    identifier: identifier.clone(),
                };
                debug!(payload=?serde_json::to_string(&fees), "our fees");
                match fees.into_signed_payload(key) {
                    Ok(payload) => {
                        let (decoded_payload, is_valid) = payload
                            .decode_and_verify()
                            .expect("verify fees signature failed");

                        if is_valid {
                            match serde_json::to_string(&payload) {
                                Ok(payload) => {
                                    if let Err(error) = client
                                        .publish(
                                            PUBSUB_PATH,
                                            &format!("/railgun/v2/0-{chain_id}-fees/json"),
                                            payload.as_bytes(),
                                        )
                                        .await
                                    {
                                        warn!(%error, "publish fees failed");
                                    }
                                }
                                Err(error) => {
                                    error!(%error, "serialize fees failed");
                                }
                            }
                        } else {
                            warn!(?decoded_payload, "fees signature invalid");
                        }
                    }
                    Err(error) => {
                        error!(%error, "sign fees failed");
                    }
                }
            }
        });
    }

    pub async fn handle_transact_request(
        &self,
        pubkey: [u8; 32],
        encrypted_data: &[Bytes; 2],
    ) -> Result<(), HandleTransactError> {
        let req = try_decrypt_transact_request(&self.key, pubkey, encrypted_data)?
            .ok_or(HandleTransactError::NotForUs)?;

        let parsed_transact = parse_transact_calldata(req.params.data.as_ref(), &self.key)
            .map_err(HandleTransactError::Parse)?;

        info!(data=?parsed_transact, "parsed");

        if let Some(poi) = self.poi.as_ref() {
            poi.validate_all(&parsed_transact, &req.params).await?;
        }

        self.tx.send((req, parsed_transact)).await?;
        Ok(())
    }

    pub fn spawn_tx_submitter(&self) {
        let rx = self.rx.clone();
        let rpc = self.rpc.clone();
        let count_transact_requests = self.count_transact_requests.clone();
        let count_txs_landed = self.count_txs_landed.clone();
        let fees_manager = self.fees_manager.clone();
        let chain_id = self.chain_id;
        let evm_wallets = self.evm_wallets.clone();
        let broadcaster = self.broadcaster.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            loop {
                if let Ok((decrypted_payload, calldata)) = rx
                    .recv()
                    .await
                    .inspect_err(|error| warn!(%error, "failed to receive transact request"))
                {
                    if chain_id != decrypted_payload.params.chain_id {
                        warn!(?decrypted_payload, "wrong chain_id");
                        continue;
                    }
                    if decrypted_payload
                        .params
                        .fees_id
                        .as_ref()
                        .is_none_or(|fees_id| !fees_manager.is_fees_id_valid(fees_id))
                    {
                        warn!(
                            ?decrypted_payload.params.fees_id,
                            "cached fees id not found"
                        );
                    }

                    count_transact_requests.fetch_add(1, Ordering::Relaxed);

                    let Some((_wallet, signer)) = evm_wallets.choose(&mut rand::rng()) else {
                        warn!("no wallets available");
                        continue;
                    };

                    let min_gas_price = decrypted_payload.params.min_gas_price.to();
                    let gas_price = rpc
                        .get_gas_price()
                        .await
                        .unwrap_or(min_gas_price)
                        .max(min_gas_price)
                        * 101
                        / 100;

                    let tx_req = TransactionRequest::default()
                        .with_chain_id(chain_id)
                        .with_from(signer.address())
                        .with_to(decrypted_payload.params.to)
                        .with_input(decrypted_payload.params.data)
                        .with_gas_price(gas_price)
                        .with_nonce(
                            rpc.get_transaction_count(signer.address())
                                .await
                                .unwrap_or(0),
                        );
                    if let Ok(gas) = rpc
                        .estimate_gas(tx_req.clone())
                        .await
                        .inspect_err(|error| warn!(%error, "estimate gas failed"))
                    {
                        let gas = gas + 100_000;
                        let tx_req = tx_req.with_gas_limit(gas);
                        let cost = U256::from(gas * gas_price as u64);
                        let refund = fees_manager.convert_to_eth(&calldata).await;

                        info!(
                            gas,
                            cost = pretty_number(&cost, 18),
                            refund = pretty_number(&refund, 18),
                            "estimated gas"
                        );

                        if refund < cost {
                            warn!("gas cost is too high, ignoring the transact request...");
                            if let Ok(transact_response) = build_transact_response_error(
                                None,
                                &decrypted_payload.shared_key,
                                "Gas cost is too high, please refresh and try again",
                            )
                            .inspect_err(
                                |error| error!(%error, "build error transact response failed"),
                            ) && let Err(error) = client
                                .publish(
                                    PUBSUB_PATH,
                                    &format!("/railgun/v2/0-{chain_id}-transact-response/json"),
                                    &transact_response,
                                )
                                .await
                            {
                                error!(%error, "publish error transact response failed");
                            }
                            continue;
                        }

                        let queue = if calldata.action_data.is_some() {
                            Queue::Mev
                        } else {
                            Queue::Mempool
                        };
                        if let Ok(tx_hash) =
                            submit_tx(&broadcaster, signer.clone(), tx_req, None, queue)
                                .await
                                .inspect_err(|error| error!(%error, "submit tx failed"))
                        {
                            info!(?tx_hash, shared_key=%hex::encode(decrypted_payload.shared_key), "submitted tx");
                            count_txs_landed.fetch_add(1, Ordering::Relaxed);
                            if let Ok(transact_response) = build_transact_response_txhash(
                                None,
                                &decrypted_payload.shared_key,
                                tx_hash,
                            )
                            .inspect_err(|error| error!(%error, "build transact response failed"))
                                && let Err(error) = client
                                    .publish(
                                        PUBSUB_PATH,
                                        &format!("/railgun/v2/0-{chain_id}-transact-response/json"),
                                        &transact_response,
                                    )
                                    .await
                            {
                                error!(%error, "publish transact response failed");
                            }
                        }
                    }
                }
            }
        }
            .instrument(info_span!("tx", chain_id))
        );
    }
}

async fn submit_tx(
    broadcaster: &TxBroadcaster,
    signer: LocalSigner<SigningKey>,
    tx_req: TransactionRequest,
    additional_txs: Option<Vec<Vec<u8>>>,
    queue: Queue,
) -> Result<TxHash, SubmitTxError> {
    let signed_tx = tx_req
        .build(&EthereumWallet::from(signer))
        .await?
        .encoded_2718();
    let tx_hash = broadcaster
        .broadcast(signed_tx, additional_txs, queue)
        .await?;
    tx_hash.ok_or(SubmitTxError::MissingHash)
}

fn pretty_number(num: &U256, decimals: usize) -> String {
    let div = U256::from(10).pow(U256::from(decimals));
    let q = num / div;
    let mut r = num % div;

    let mut frac = Vec::with_capacity(decimals);
    for _ in 0..decimals {
        let digit = (r * U256::from(10)) / div;
        r = (r * U256::from(10)) % div;
        frac.push((digit.to::<u8>() + b'0') as char);
    }

    while frac.len() > 2 && frac.last() == Some(&'0') {
        frac.pop();
    }

    format!("{q}.{}", frac.iter().collect::<String>())
}

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
}

impl BroadcasterManager {
    /// Creates a new manager from pre-initialized services and a Waku client.
    #[must_use]
    pub const fn new(services: Vec<BroadcasterService>, waku: Arc<Client>) -> Self {
        Self { services, waku }
    }

    /// Subscribes to Waku and runs the message processing loop.
    pub async fn run(&self) -> Result<(), BroadcasterManagerError> {
        let chain_ids: HashSet<ChainId> = self
            .services
            .iter()
            .map(BroadcasterService::chain_id)
            .collect();

        let content_topics: Vec<String> = chain_ids
            .into_iter()
            // .map(|chain_id| {
            //     vec![
            //         format!("/railgun/v2/0-{chain_id}-transact/json"),
            //         format!("/railgun/v2/0-56-fees/json"),
            //     ]
            // })
            // .flatten()
            .map(|chain_id| format!("/railgun/v2/0-{chain_id}-transact/json"))
            .collect();

        let mut msg_rx = self.waku.subscribe(PUBSUB_PATH, content_topics).await?;

        loop {
            let Some(msg) = msg_rx.recv().await else {
                warn!("get message failed, retrying...");
                continue;
            };

            let topic = ContentTopic::from(msg.content_topic);
            match topic {
                ContentTopic::Pong
                | ContentTopic::TransactResponse()
                | ContentTopic::Noop
                | ContentTopic::Fees => {}
                ContentTopic::Transact(chain_id) => {
                    match serde_json::from_slice::<TransactEnvelope>(msg.payload.as_slice()) {
                        Ok(payload) => {
                            if payload.method != "transact" {
                                continue;
                            }
                            for service in self
                                .services
                                .iter()
                                .filter(|service| service.chain_id() == chain_id)
                            {
                                if let Err(error) = service
                                    .handle_transact_request(
                                        payload.params.pubkey.0,
                                        &payload.params.encrypted_data,
                                    )
                                    .instrument(info_span!("transact", chain_id))
                                    .await
                                    && !matches!(error, HandleTransactError::NotForUs)
                                {
                                    warn!(?error, "failed to handle transact request");
                                }
                            }
                        }
                        Err(error) => {
                            warn!(
                                %error,
                                payload=%String::from_utf8_lossy(msg.payload.as_slice()),
                                "decode payload failed",
                            );
                        }
                    }
                }

                ContentTopic::Unknown(topic) => {
                    info!(payload=%String::from_utf8_lossy(&msg.payload), %topic, "unhandled topic");
                }
            }
        }
    }
}
