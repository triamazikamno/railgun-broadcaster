mod auto_refill;
mod fee_note_assurance;
mod utxo_consolidation;

use alloy::eips::Encodable2718;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, TxHash, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::{LocalSigner, LocalSignerError, MnemonicBuilder, PrivateKeySigner};
use alloy::transports::TransportErrorKind;
use alloy::{hex, sol, uint};
use broadcaster_core::crypto::railgun::{
    Address as RailgunAddress, RailgunError, ShareableViewingKey,
};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    DecryptedTransact, ParsedTransactCalldata, TransactError, attach_fee_note_assurance_context,
    parse_transact_calldata, try_decrypt_transact_request,
};
use broadcaster_core::transact_response::{
    build_transact_response_error, build_transact_response_txhash,
};
use config::{Chain, Key};
use fees::{FeesError, Manager as FeesManager};
use local_db::{DbStore, PendingFeeNoteAssuranceRecord};
use poi::poi::Poi;
use rand::seq::IndexedRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{Instrument, debug, error, info, info_span, warn};
use tx_submit::{Queue, TxBroadcaster};
use waku_relay::client::{Client, PUBSUB_PATH};

use crate::auto_refill::{AutoRefillConfig, AutoRefillService};
use crate::fee_note_assurance::{FeeNoteAssuranceRecordOutcome, process_fee_note_assurance_record};
use crate::utxo_consolidation::{UtxoConsolidationConfig, UtxoConsolidationService};
use poi::error::PoiError;
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{ProverService, WalletKeys};
use serde::{Deserialize, Serialize};
use sync_service::manager::SyncManagerError;
use sync_service::{ChainConfig, ChainConfigDefaults, ChainKey, SyncManager, WalletConfig};
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
    #[error("local db failed: {0}")]
    Db(#[from] local_db::DbError),
    #[error("derive railgun address failed: {0}")]
    DeriveAddress(#[from] RailgunError),
    #[error("sync manager failed: {0}")]
    SyncManager(#[from] SyncManagerError),
    #[error("invalid viewing privkey")]
    InvalidViewingPrivkey,
    #[error("init tx broadcaster failed: {0}")]
    InitBroadcaster(#[from] tx_submit::BroadcasterInitError),
    #[error("missing multicall_contract")]
    MissingMulticallContract,
    #[error("missing query_rpc endpoints")]
    MissingQueryRpc,
    #[error("simulation failed: {0}")]
    SimulationFailed(#[from] alloy::transports::RpcError<TransportErrorKind>),
    #[error("failed to decode EVM private key: {0}")]
    DecodePrivateKey(#[from] alloy::signers::k256::ecdsa::signature::Error),
    #[error("mnemonic signer failed: {0}")]
    MnemonicSigner(#[from] LocalSignerError),
    #[error("failed to derive keys: {0}")]
    DeriveKeys(#[from] railgun_wallet::keys::KeyError),
    #[error("railgun_contract is not defined for this chain")]
    RailgunContractMissing,
    #[error("finality_depth is not defined for this chain")]
    FinalityDepthMissing,
    #[error("anchor_interval is not defined for this chain")]
    AnchorIntervalMissing,
    #[error("archive_until_block is not defined for this chain")]
    ArchiveUntilBlockMissing,
    #[error("v2_start_block is not defined for this chain")]
    V2StartBlockMissing,
    #[error("legacy_shield_block is not defined for this chain")]
    LegacyShieldBlockMissing,
    #[error("deployment_block is not defined for this chain")]
    DeploymentBlockMissing,
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

fn derive_evm_wallet_keys(
    seed_phrase: &str,
    count: usize,
) -> Result<Vec<Bytes>, BroadcasterServiceError> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let builder = MnemonicBuilder::from_phrase(seed_phrase);
    (0..count)
        .map(|index| {
            let signer = builder.clone().index(index as u32)?.build()?;
            Ok(Bytes::from(signer.to_bytes()))
        })
        .collect()
}

type ResponseSender = kanal::AsyncSender<(DecryptedTransact, ParsedTransactCalldata)>;
type ResponseReceiver = kanal::AsyncReceiver<(DecryptedTransact, ParsedTransactCalldata)>;

pub struct BroadcasterService {
    chain_id: ChainId,
    db: Arc<DbStore>,
    pending_fee_note_assurance_fallback:
        Arc<Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>>,
    logged_fee_note_assurance_submissions: Arc<Mutex<HashSet<FixedBytes<32>>>>,
    fee_note_assurance_submission_attempts: Arc<Mutex<HashMap<FixedBytes<32>, Instant>>>,
    key: [u8; 32],
    master_public_key: U256,
    addr: RailgunAddress,
    tx: ResponseSender,
    rx: ResponseReceiver,
    broadcaster: Arc<TxBroadcaster>,
    fees_manager: Arc<FeesManager>,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    count_transact_requests: Arc<AtomicU32>,
    count_txs_landed: Arc<AtomicU32>,
    client: Arc<Client>,
    poi: Option<Arc<Poi>>,
    required_poi_list: Vec<FixedBytes<32>>,
    query_rpc_pool: Arc<QueryRpcPool>,
    railgun_contract: Option<Address>,
    finality_depth: Option<u64>,
    receipt_poll_interval: Duration,
    relay_adapt_contract: Address,
    relay_adapt_7702_contract: Option<Address>,
    identifier: Option<String>,
    fees_refresh_interval: Duration,
    fees_ttl: Duration,
}

const fn fee_note_assurance_required(
    poi_enabled: bool,
    required_poi_list: &[FixedBytes<32>],
    has_pending_jobs: bool,
) -> bool {
    poi_enabled && (!required_poi_list.is_empty() || has_pending_jobs)
}

impl BroadcasterService {
    pub async fn new(
        chain_cfg: Chain,
        db: Arc<DbStore>,
        client: Arc<Client>,
        poi: Option<Arc<Poi>>,
        required_poi_list: Vec<FixedBytes<32>>,
        sync_manager: Arc<SyncManager>,
        prover: Arc<ProverService>,
        query_rpc_cooldown: Duration,
    ) -> Result<Self, BroadcasterServiceError> {
        let (tx, rx) = kanal::bounded_async::<(DecryptedTransact, ParsedTransactCalldata)>(20);
        let pending_fee_note_assurance_fallback = Arc::new(Mutex::new(HashMap::new()));
        let logged_fee_note_assurance_submissions = Arc::new(Mutex::new(HashSet::new()));
        let fee_note_assurance_submission_attempts = Arc::new(Mutex::new(HashMap::new()));
        let count_transact_requests = Arc::new(AtomicU32::new(0));
        let count_txs_landed = Arc::new(AtomicU32::new(0));
        let defaults = ChainConfigDefaults::for_chain(chain_cfg.chain_id);
        let resolved_railgun_contract = chain_cfg
            .sync
            .as_ref()
            .and_then(|sync| sync.railgun_contract)
            .or_else(|| defaults.as_ref().map(|config| config.contract));
        let resolved_finality_depth = chain_cfg
            .sync
            .as_ref()
            .and_then(|sync| sync.finality_depth)
            .or_else(|| defaults.as_ref().map(|config| config.finality_depth));
        #[allow(clippy::redundant_closure_for_method_calls)]
        let receipt_poll_interval = chain_cfg
            .sync
            .as_ref()
            .and_then(|sync| sync.poll_interval)
            .map_or(Duration::from_secs(15), |value| value.into_inner());
        let derived_wallets = if let Key::Mnemonic(mnemonic) = &chain_cfg.key
            && mnemonic.num_derived_evm_wallets > 0
        {
            derive_evm_wallet_keys(&mnemonic.seed_phrase, mnemonic.num_derived_evm_wallets)?
        } else {
            vec![]
        };
        let has_pending_fee_note_assurance = if poi.is_some() {
            !db.list_pending_fee_note_assurance(chain_cfg.chain_id)?
                .is_empty()
        } else {
            false
        };
        if fee_note_assurance_required(
            poi.is_some(),
            &required_poi_list,
            has_pending_fee_note_assurance,
        ) {
            resolved_railgun_contract.ok_or(BroadcasterServiceError::RailgunContractMissing)?;
            resolved_finality_depth.ok_or(BroadcasterServiceError::FinalityDepthMissing)?;
        }
        let evm_wallets = chain_cfg
            .evm_wallets
            .iter()
            .chain(derived_wallets.iter())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|key| {
                let signer = PrivateKeySigner::from(SigningKey::from_bytes(key.as_ref().into())?);
                info!(addr=?signer.address(), "using EVM wallet");
                Ok((EthereumWallet::from(signer.clone()), signer))
            })
            .collect::<Result<Vec<_>, BroadcasterServiceError>>()?;
        let query_rpc_pool = Arc::new(QueryRpcPool::new(
            chain_cfg.query_rpcs.clone(),
            query_rpc_cooldown,
        ));
        let broadcaster = Arc::new(TxBroadcaster::try_from((
            chain_cfg.clone(),
            query_rpc_pool.clone(),
        ))?);
        let multicall_contract = chain_cfg
            .multicall_contract
            .ok_or(BroadcasterServiceError::MissingMulticallContract)?;
        let fee_bonus = uint!(1000000000000000000_U256)
            + U256::from(chain_cfg.fee_bonus * 1000.0) * uint!(10000000000000_U256);
        let fees_manager = Arc::new(FeesManager::new(
            &chain_cfg.fees,
            fee_bonus,
            query_rpc_pool.clone(),
            multicall_contract,
            chain_cfg.wrapped_native_token,
        ));

        let (key, master_public_key, addr) = match &chain_cfg.key {
            Key::ViewingPrivkey(key) => {
                let viewing_key: ShareableViewingKey = key.clone().into();
                let viewing_key_data = viewing_key
                    .decode_viewing_key_data()
                    .map_err(|_| BroadcasterServiceError::InvalidViewingPrivkey)?;
                let addr = viewing_key_data.derive_address(None)?;
                (
                    viewing_key_data.viewing_private_key,
                    viewing_key_data.master_public_key,
                    addr,
                )
            }
            Key::Mnemonic(mnemonic) => {
                let config::MnemonicSettings {
                    seed_phrase,
                    init_block_number,
                    auto_refill,
                    utxo_consolidation,
                    ..
                } = mnemonic.as_ref();
                let chain_id = chain_cfg.chain_id;
                let wallet = WalletKeys::from_mnemonic(seed_phrase, 0)?;
                let key = wallet.viewing.viewing_private_key;
                let master_public_key = wallet.viewing.master_public_key;
                let addr = wallet.viewing.derive_address(None)?;
                let railgun_contract = resolved_railgun_contract
                    .ok_or(BroadcasterServiceError::RailgunContractMissing)?;
                let finality_depth =
                    resolved_finality_depth.ok_or(BroadcasterServiceError::FinalityDepthMissing)?;
                let anchor_interval = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.anchor_interval)
                    .or_else(|| defaults.as_ref().map(|config| config.anchor_interval))
                    .ok_or(BroadcasterServiceError::AnchorIntervalMissing)?;
                let anchor_retention = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.anchor_retention)
                    .or_else(|| defaults.as_ref().map(|config| config.anchor_retention))
                    .unwrap_or(5);
                let archive_until_block = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.archive_until_block)
                    .or_else(|| defaults.as_ref().map(|config| config.archive_until_block))
                    .ok_or(BroadcasterServiceError::ArchiveUntilBlockMissing)?;
                let v2_start_block = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.v2_start_block)
                    .or_else(|| defaults.as_ref().map(|config| config.v2_start_block))
                    .ok_or(BroadcasterServiceError::V2StartBlockMissing)?;
                let legacy_shield_block = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.legacy_shield_block)
                    .or_else(|| defaults.as_ref().map(|config| config.legacy_shield_block))
                    .ok_or(BroadcasterServiceError::LegacyShieldBlockMissing)?;
                let deployment_block = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.deployment_block)
                    .or_else(|| defaults.as_ref().map(|config| config.deployment_block))
                    .ok_or(BroadcasterServiceError::DeploymentBlockMissing)?;
                let quick_sync_endpoint = if chain_cfg
                    .sync
                    .as_ref()
                    .is_some_and(|sync| sync.disable_quick_sync)
                {
                    None
                } else {
                    chain_cfg
                        .sync
                        .as_ref()
                        .and_then(|sync| sync.quick_sync_endpoint.clone())
                        .or_else(|| {
                            defaults
                                .as_ref()
                                .and_then(|config| config.quick_sync_endpoint.clone())
                        })
                };
                let block_range = chain_cfg
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.block_range)
                    .unwrap_or(500);
                let chain_config = ChainConfig {
                    chain_id,
                    contract: railgun_contract,
                    rpcs: query_rpc_pool.clone(),
                    archive_rpc_url: chain_cfg
                        .sync
                        .as_ref()
                        .and_then(|sync| sync.archive_rpc_url.clone()),
                    archive_until_block,
                    deployment_block,
                    v2_start_block,
                    legacy_shield_block,
                    block_range,
                    poll_interval: receipt_poll_interval,
                    finality_depth,
                    quick_sync_endpoint,
                    anchor_interval,
                    anchor_retention,
                };
                let chain_service = sync_manager.add_chain(chain_config).await?;
                let chain_key = ChainKey {
                    chain_id,
                    contract: railgun_contract,
                };
                let scan_keys = wallet.viewing;
                let wallet_id = wallet.viewing.derive_address(None)?;
                let cache_key = wallet_cache_key(wallet_id.as_ref(), chain_id, railgun_contract);
                let wallet_cfg = WalletConfig {
                    chain: chain_key,
                    cache_key: cache_key.clone(),
                    start_block: Some(*init_block_number),
                    scan_keys,
                };
                let handle = sync_manager.add_wallet(wallet_cfg).await?;
                if let Some(auto_refill) = auto_refill.clone() {
                    let query_rpc_pool = query_rpc_pool.clone();
                    let evm_wallets = evm_wallets.clone();
                    let broadcaster = broadcaster.clone();
                    let prover = prover.clone();
                    let wallet = wallet.clone();
                    let mut auto_refill_handle = handle.clone();
                    let cache_key = cache_key.clone();
                    let chain_handle = chain_service.handle();
                    tokio::spawn(
                        async move {
                            auto_refill_handle.wait_until_ready().await;
                            let cfg = AutoRefillConfig {
                                chain_id,
                                railgun_contract,
                                relay_adapt_contract: chain_cfg.relay_adapt_contract,
                                wrapped_native_token: chain_cfg.wrapped_native_token,
                                wallet,
                                wallet_handle: auto_refill_handle,
                                chain_handle,
                                auto_refill,
                            };
                            let auto_refill_service = AutoRefillService::new(
                                cfg,
                                evm_wallets,
                                query_rpc_pool,
                                broadcaster,
                                prover,
                            );
                            info!(cache_key = cache_key, "wallet sync ready for auto-refill");
                            auto_refill_service.run().await;
                        }
                        .instrument(info_span!("auto_refill")),
                    );
                }
                if let Some(utxo_consolidation) = utxo_consolidation.clone() {
                    let query_rpc_pool = query_rpc_pool.clone();
                    let evm_wallets = evm_wallets.clone();
                    let broadcaster = broadcaster.clone();
                    let prover = prover.clone();
                    let wallet = wallet.clone();
                    let mut consolidation_handle = handle;
                    let cache_key = cache_key.clone();
                    let chain_handle = chain_service.handle();
                    tokio::spawn(
                        async move {
                            consolidation_handle.wait_until_ready().await;
                            let cfg = UtxoConsolidationConfig {
                                chain_id,
                                railgun_contract,
                                relay_adapt_contract: chain_cfg.relay_adapt_contract,
                                wallet,
                                wallet_handle: consolidation_handle,
                                chain_handle,
                                settings: utxo_consolidation,
                            };
                            let consolidation_service = UtxoConsolidationService::new(
                                cfg,
                                evm_wallets,
                                query_rpc_pool,
                                broadcaster,
                                prover,
                            );
                            info!(
                                cache_key = cache_key,
                                "wallet sync ready for utxo consolidation"
                            );
                            consolidation_service.run().await;
                        }
                        .instrument(info_span!("utxo_consolidation")),
                    );
                }
                (key, master_public_key, addr)
            }
        };

        Ok(Self {
            chain_id: chain_cfg.chain_id,
            db,
            pending_fee_note_assurance_fallback,
            logged_fee_note_assurance_submissions,
            fee_note_assurance_submission_attempts,
            key,
            master_public_key,
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
            query_rpc_pool,
            railgun_contract: resolved_railgun_contract,
            finality_depth: resolved_finality_depth,
            receipt_poll_interval,
            relay_adapt_contract: chain_cfg.relay_adapt_contract,
            relay_adapt_7702_contract: chain_cfg.relay_adapt_7702_contract,
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
        let relay_adapt_7702 = self.relay_adapt_7702_contract;
        let identifier = self.identifier.clone();
        let client = self.client.clone();
        let key = self.key;
        let chain_id = self.chain_id;
        let count_transact_requests = self.count_transact_requests.clone();
        let count_txs_landed = self.count_txs_landed.clone();
        let available_wallets = self.evm_wallets.len() as u32;

        tokio::spawn(
            async move {
                let mut interval = tokio::time::interval(push_interval);
                loop {
                    interval.tick().await;
                    if let Err(error) = fees_manager.update_prices().await {
                        error!(?error, "update prices failed");
                    }
                    let reliability = {
                        let count_transact_requests =
                            count_transact_requests.load(Ordering::Relaxed);
                        let count_txs_landed = count_txs_landed.load(Ordering::Relaxed);
                        if count_transact_requests < 10
                            || count_transact_requests == count_txs_landed
                        {
                            0.99
                        } else {
                            let ratio =
                                f64::from(count_txs_landed) / f64::from(count_transact_requests);
                            (ratio * 100.0).round() / 100.0
                        }
                    };
                    let fee_expiration = match SystemTime::now().duration_since(UNIX_EPOCH) {
                        Ok(duration) => duration.as_millis().saturating_add(fee_ttl.as_millis()),
                        Err(error) => {
                            warn!(?error, "system time before unix epoch");
                            continue;
                        }
                    };
                    let fee_expiration = u64::try_from(fee_expiration).unwrap_or(u64::MAX);
                    let (fees_id, fees) = fees_manager.create_fees().await;
                    let fees = fees::Body {
                        fees,
                        fee_expiration,
                        fees_id,
                        railgun_address: railgun_address.clone(),
                        available_wallets,
                        version: API_VERSION.to_string(),
                        relay_adapt,
                        relay_adapt_7702,
                        required_poi_list_keys: required_poi_list.iter().map(hex::encode).collect(),
                        reliability,
                        identifier: identifier.clone(),
                    };
                    debug!(payload=?serde_json::to_string(&fees), "our fees");
                    match fees.into_signed_payload(key) {
                        Ok(payload) => {
                            let (decoded_payload, is_valid) = match payload.decode_and_verify() {
                                Ok(result) => result,
                                Err(error) => {
                                    warn!(?error, "verify fees signature failed");
                                    continue;
                                }
                            };

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
            }
            .instrument(info_span!("fees", chain_id)),
        );
    }

    pub async fn handle_transact_request(
        &self,
        pubkey: [u8; 32],
        encrypted_data: &[Bytes; 2],
    ) -> Result<(), HandleTransactError> {
        let req = try_decrypt_transact_request(&self.key, pubkey, encrypted_data)?
            .ok_or(HandleTransactError::NotForUs)?;

        let mut parsed_transact = parse_transact_calldata(
            req.params.data.as_ref(),
            &self.key,
            self.master_public_key,
            req.params.txid_version.as_deref(),
        )
        .map_err(HandleTransactError::Parse)?;

        info!(
            fee_token = ?parsed_transact.fee_token,
            fee_amount = ?parsed_transact.fee_amount,
            railgun_txid = ?parsed_transact.railgun_txid,
            utxo_tree_in = parsed_transact.utxo_tree_in,
            "parsed transact calldata"
        );

        if let Some(poi) = self.poi.as_ref() {
            poi.validate_all(&parsed_transact, &req.params).await?;
            attach_fee_note_assurance_context(
                &mut parsed_transact,
                &req.params,
                &self.required_poi_list,
            )
            .map_err(HandleTransactError::Parse)?;
        }

        self.tx.send((req, parsed_transact)).await?;
        Ok(())
    }

    pub fn spawn_tx_submitter(&self) {
        let rx = self.rx.clone();
        let db = self.db.clone();
        let pending_fee_note_assurance_fallback = self.pending_fee_note_assurance_fallback.clone();
        let query_rpc_pool = self.query_rpc_pool.clone();
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

                    let Some(provider_handle) = query_rpc_pool.random_provider() else {
                        warn!("no query rpc available");
                        continue;
                    };
                    let rpc = provider_handle.provider.clone();

                    let min_gas_price = decrypted_payload.params.min_gas_price.to();
                    let gas_price = match rpc.get_gas_price().await {
                        Ok(gas_price) => gas_price.max(min_gas_price) * 101 / 100,
                        Err(error) => {
                            warn!(
                                %error,
                                rpc = %provider_handle.url,
                                "fetch gas price failed",
                            );
                            query_rpc_pool.mark_bad_provider(&provider_handle);
                            continue;
                        }
                    };

                    let tx_req = TransactionRequest::default()
                        .with_chain_id(chain_id)
                        .with_from(signer.address())
                        .with_to(decrypted_payload.params.to)
                        .with_input(decrypted_payload.params.data)
                        .with_gas_price(gas_price)
                        .with_nonce(match rpc.get_transaction_count(signer.address()).await {
                            Ok(nonce) => nonce,
                            Err(error) => {
                                warn!(
                                    %error,
                                    rpc = %provider_handle.url,
                                    "fetch nonce failed",
                                );
                                query_rpc_pool.mark_bad_provider(&provider_handle);
                                continue;
                            }
                        });
                    if let Ok(gas) = rpc
                        .estimate_gas(tx_req.clone())
                        .await
                        .inspect_err(|error| {
                            warn!(%error, rpc = %provider_handle.url, "estimate gas failed");
                        })
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
                            if let Some(context) = calldata.fee_note_assurance.as_ref() {
                                let record = PendingFeeNoteAssuranceRecord {
                                    chain_id,
                                    public_tx_hash: tx_hash,
                                    context: context.clone(),
                                };
                                if let Err(error) = db.put_pending_fee_note_assurance(&record) {
                                    error!(
                                        ?error,
                                        chain_id,
                                        tx_hash = %tx_hash,
                                        "persist fee-note assurance record failed"
                                    );
                                    queue_fee_note_assurance_fallback(
                                        pending_fee_note_assurance_fallback.as_ref(),
                                        record,
                                    );
                                }
                            }
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

    pub fn spawn_fee_note_assurance_worker(&self) {
        let Some(poi) = self.poi.clone() else {
            return;
        };
        let Some(railgun_contract) = self.railgun_contract else {
            return;
        };
        let Some(finality_depth) = self.finality_depth else {
            return;
        };

        let db = self.db.clone();
        let pending_fee_note_assurance_fallback = self.pending_fee_note_assurance_fallback.clone();
        let logged_fee_note_assurance_submissions =
            self.logged_fee_note_assurance_submissions.clone();
        let fee_note_assurance_submission_attempts =
            self.fee_note_assurance_submission_attempts.clone();
        let query_rpc_pool = self.query_rpc_pool.clone();
        let chain_id = self.chain_id;
        let poll_interval = self.receipt_poll_interval;

        tokio::spawn(
            async move {
                let mut interval = tokio::time::interval(poll_interval);
                loop {
                    interval.tick().await;
                    try_persist_fee_note_assurance_fallback(
                        db.as_ref(),
                        pending_fee_note_assurance_fallback.as_ref(),
                        chain_id,
                    );

                    let db_records = match db.list_pending_fee_note_assurance(chain_id) {
                        Ok(records) => records,
                        Err(error) => {
                            error!(?error, chain_id, "list fee-note assurance records failed");
                            continue;
                        }
                    };
                    let records = collect_pending_fee_note_assurance_records(
                        db_records,
                        snapshot_fee_note_assurance_fallback(
                            pending_fee_note_assurance_fallback.as_ref(),
                        ),
                    );

                    for (record, was_fallback_only) in records {
                        let outcome = process_fee_note_assurance_record(
                            db.as_ref(),
                            query_rpc_pool.as_ref(),
                            poi.as_ref(),
                            logged_fee_note_assurance_submissions.as_ref(),
                            fee_note_assurance_submission_attempts.as_ref(),
                            railgun_contract,
                            finality_depth,
                            record.clone(),
                        )
                        .await;
                        if should_remove_fee_note_assurance_fallback(outcome, was_fallback_only) {
                            remove_fee_note_assurance_fallback(
                                pending_fee_note_assurance_fallback.as_ref(),
                                &record.public_tx_hash,
                            );
                        }
                    }
                }
            }
            .instrument(info_span!("fee_note_assurance", chain_id)),
        );
    }

    pub async fn handle_trusted_signer_fees(
        &self,
        railgun_address: String,
        fees: HashMap<Address, U256>,
    ) {
        self.fees_manager
            .handle_trusted_signer_fees(railgun_address, fees)
            .await;
    }
}

fn queue_fee_note_assurance_fallback(
    fallback: &Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>,
    record: PendingFeeNoteAssuranceRecord,
) {
    let mut fallback = fallback
        .lock()
        .expect("fee-note assurance fallback poisoned");
    fallback.insert(record.public_tx_hash, record);
}

fn snapshot_fee_note_assurance_fallback(
    fallback: &Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>,
) -> Vec<PendingFeeNoteAssuranceRecord> {
    let fallback = fallback
        .lock()
        .expect("fee-note assurance fallback poisoned");
    fallback.values().cloned().collect()
}

fn remove_fee_note_assurance_fallback(
    fallback: &Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>,
    public_tx_hash: &FixedBytes<32>,
) {
    let mut fallback = fallback
        .lock()
        .expect("fee-note assurance fallback poisoned");
    fallback.remove(public_tx_hash);
}

fn try_persist_fee_note_assurance_fallback(
    db: &DbStore,
    fallback: &Mutex<HashMap<FixedBytes<32>, PendingFeeNoteAssuranceRecord>>,
    chain_id: u64,
) {
    for record in snapshot_fee_note_assurance_fallback(fallback) {
        match db.put_pending_fee_note_assurance(&record) {
            Ok(()) => {
                info!(
                    chain_id,
                    tx_hash = %record.public_tx_hash,
                    "persisted fallback fee-note assurance record"
                );
                remove_fee_note_assurance_fallback(fallback, &record.public_tx_hash);
            }
            Err(error) => {
                warn!(
                    ?error,
                    chain_id,
                    tx_hash = %record.public_tx_hash,
                    "persist fallback fee-note assurance record failed"
                );
            }
        }
    }
}

fn collect_pending_fee_note_assurance_records(
    db_records: Vec<PendingFeeNoteAssuranceRecord>,
    fallback_records: Vec<PendingFeeNoteAssuranceRecord>,
) -> Vec<(PendingFeeNoteAssuranceRecord, bool)> {
    let mut records = HashMap::with_capacity(db_records.len() + fallback_records.len());
    for record in fallback_records {
        records.insert(record.public_tx_hash, (record, true));
    }
    for record in db_records {
        records.insert(record.public_tx_hash, (record, false));
    }
    records.into_values().collect()
}

const fn should_remove_fee_note_assurance_fallback(
    record_outcome: FeeNoteAssuranceRecordOutcome,
    was_fallback_only: bool,
) -> bool {
    was_fallback_only
        && matches!(
            record_outcome,
            FeeNoteAssuranceRecordOutcome::Completed | FeeNoteAssuranceRecordOutcome::Terminal
        )
}

#[cfg(test)]
mod tests {
    use super::{
        collect_pending_fee_note_assurance_records, fee_note_assurance_required,
        queue_fee_note_assurance_fallback, remove_fee_note_assurance_fallback,
        should_remove_fee_note_assurance_fallback, snapshot_fee_note_assurance_fallback,
    };
    use crate::fee_note_assurance::FeeNoteAssuranceRecordOutcome;
    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::FeeNoteAssuranceContext;
    use local_db::PendingFeeNoteAssuranceRecord;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    #[test]
    fn fee_note_assurance_is_not_required_without_poi() {
        assert!(!fee_note_assurance_required(
            false,
            &[FixedBytes::from([0x11; 32])],
            true,
        ));
    }

    #[test]
    fn fee_note_assurance_is_not_required_without_lists_or_pending_jobs() {
        assert!(!fee_note_assurance_required(true, &[], false));
    }

    #[test]
    fn fee_note_assurance_is_required_with_required_lists() {
        assert!(fee_note_assurance_required(
            true,
            &[FixedBytes::from([0x11; 32])],
            false,
        ));
    }

    #[test]
    fn fee_note_assurance_is_required_with_pending_jobs() {
        assert!(fee_note_assurance_required(true, &[], true));
    }

    fn sample_record(chain_id: u64, tx_hash: [u8; 32]) -> PendingFeeNoteAssuranceRecord {
        PendingFeeNoteAssuranceRecord {
            chain_id,
            public_tx_hash: FixedBytes::from(tx_hash),
            context: FeeNoteAssuranceContext {
                chain_type: 0,
                txid_version: "V2_PoseidonMerkle".to_string(),
                railgun_txid: U256::from(5_u8),
                utxo_tree_in: 9,
                fee_commitment: FixedBytes::from([1u8; 32]),
                fee_note_npk: FixedBytes::from([2u8; 32]),
                pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
                required_poi_list_keys: vec![FixedBytes::from([4u8; 32])],
            },
        }
    }

    #[test]
    fn fallback_queue_roundtrips_records() {
        let fallback = Mutex::new(HashMap::new());
        let record = sample_record(1, [0x11; 32]);

        queue_fee_note_assurance_fallback(&fallback, record.clone());

        let snapshot = snapshot_fee_note_assurance_fallback(&fallback);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].public_tx_hash, record.public_tx_hash);
        assert_eq!(
            snapshot[0].context.railgun_txid,
            record.context.railgun_txid
        );

        remove_fee_note_assurance_fallback(&fallback, &record.public_tx_hash);
        assert!(snapshot_fee_note_assurance_fallback(&fallback).is_empty());
    }

    #[test]
    fn collect_pending_fee_note_assurance_records_prefers_db_record() {
        let fallback_record = sample_record(1, [0x22; 32]);
        let mut db_record = fallback_record.clone();
        db_record.context.railgun_txid = U256::from(9_u8);

        let records = collect_pending_fee_note_assurance_records(
            vec![db_record.clone()],
            vec![fallback_record, sample_record(1, [0x33; 32])],
        );
        let by_hash = records
            .into_iter()
            .map(|(record, was_fallback_only)| (record.public_tx_hash, (record, was_fallback_only)))
            .collect::<HashMap<_, _>>();

        assert_eq!(by_hash.len(), 2);
        assert_eq!(
            by_hash[&FixedBytes::from([0x22; 32])]
                .0
                .context
                .railgun_txid,
            db_record.context.railgun_txid
        );
        assert!(!by_hash[&FixedBytes::from([0x22; 32])].1);
        assert!(by_hash[&FixedBytes::from([0x33; 32])].1);
    }

    #[test]
    fn completed_fallback_record_is_removed() {
        assert!(should_remove_fee_note_assurance_fallback(
            FeeNoteAssuranceRecordOutcome::Completed,
            true,
        ));
    }

    #[test]
    fn terminal_fallback_record_is_removed() {
        assert!(should_remove_fee_note_assurance_fallback(
            FeeNoteAssuranceRecordOutcome::Terminal,
            true,
        ));
    }

    #[test]
    fn pending_fallback_record_is_kept() {
        assert!(!should_remove_fee_note_assurance_fallback(
            FeeNoteAssuranceRecordOutcome::Pending,
            true,
        ));
    }

    #[test]
    fn db_backed_record_is_never_removed_from_fallback() {
        assert!(!should_remove_fee_note_assurance_fallback(
            FeeNoteAssuranceRecordOutcome::Completed,
            false,
        ));
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
        let chain_ids: HashSet<ChainId> = self
            .services
            .iter()
            .map(BroadcasterService::chain_id)
            .collect();

        let content_topics: Vec<String> = chain_ids
            .into_iter()
            .flat_map(|chain_id| {
                vec![
                    format!("/railgun/v2/0-{chain_id}-transact/json"),
                    format!("/railgun/v2/0-{chain_id}-fees/json"),
                ]
            })
            .collect();

        let mut msg_rx = self.waku.subscribe(PUBSUB_PATH, content_topics).await?;

        loop {
            let Some(msg) = msg_rx.recv().await else {
                warn!("get message failed, retrying...");
                continue;
            };

            let topic = ContentTopic::from(msg.content_topic.clone());
            match topic {
                ContentTopic::Pong | ContentTopic::TransactResponse() | ContentTopic::Noop => {}
                ContentTopic::Fees(chain_id) => {
                    match serde_json::from_slice::<fees::Payload>(&msg.payload) {
                        Ok(payload) => {
                            match serde_json::from_slice::<fees::Body>(payload.data.as_ref()) {
                                Ok(body) => {
                                    if self.trusted_signers.contains(body.railgun_address.as_ref())
                                    {
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
                                }
                                Err(error) => {
                                    warn!("Failed to deserialize fees message: {error}");
                                }
                            }
                        }
                        Err(error) => {
                            warn!(%error, "parse fees failed");
                        }
                    }
                }
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
