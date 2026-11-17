//! Building a chain's `BroadcasterService`: resolving its chain settings,
//! registering the chain and wallet with sync, and starting the wallet's
//! maintenance services.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::{LocalSigner, MnemonicBuilder, PrivateKeySigner};
use alloy::transports::http::Client as HttpClient;
use alloy::uint;
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, ShareableViewingKey};
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::deployment::RailgunDeployment;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{DecryptedTransact, ParsedTransactCalldata};
use config::{AutoRefillSettings, Chain, Key, MnemonicSettings, UtxoConsolidationSettings};
use fees::Manager as FeesManager;
use local_db::{DbStore, WalletCacheKey};
use railgun_wallet::{ProverService, WalletKeys};
use sync_service::{
    ChainConfig, ChainKey, ChainService, DEFAULT_INDEXED_WALLET_BLOCK_RANGE,
    IndexedArtifactSourceConfig, RailgunSyncOptions, SyncManager, WalletConfig, WalletHandle,
};
use tracing::{Instrument, info, info_span, warn};
use tx_submit::TxBroadcaster;
use waku_relay::client::Client;

use crate::auto_refill::{AutoRefillConfig, AutoRefillService};
use crate::fee_note_assurance::FeeNoteAssuranceSubmissionTracker;
use crate::fee_note_worker::FeeNoteAssuranceFallback;
use crate::utxo_consolidation::{UtxoConsolidationConfig, UtxoConsolidationService};
use crate::{BroadcasterPoiValidator, BroadcasterService, BroadcasterServiceError, WAD};

const FEE_BONUS_BPS_DENOMINATOR: U256 = uint!(10_000_U256);

type EvmWallets = Vec<(EthereumWallet, LocalSigner<SigningKey>)>;

/// The values every chain's `BroadcasterService` shares.
pub struct BroadcasterServiceDeps {
    pub db: Arc<DbStore>,
    pub client: Arc<Client>,
    pub poi_rpc_url: Option<url::Url>,
    pub snark_prover: Arc<Prover>,
    pub required_poi_list: Vec<FixedBytes<32>>,
    pub sync_manager: Arc<SyncManager>,
    pub prover: Arc<ProverService>,
    pub poi_recovery_prover: Arc<ProverService>,
    pub query_rpc_cooldown: Duration,
    pub indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
}

impl BroadcasterService {
    pub async fn new(
        chain_cfg: Chain,
        deps: &BroadcasterServiceDeps,
    ) -> Result<Self, BroadcasterServiceError> {
        let (tx, rx) = kanal::bounded_async::<(DecryptedTransact, ParsedTransactCalldata)>(20);
        let settings = ResolvedChainSettings::resolve(&chain_cfg)?;
        let evm_wallets = load_evm_wallets(&chain_cfg)?;
        let query_rpc_pool = Arc::new(QueryRpcPool::new(
            chain_cfg.query_rpcs.clone(),
            deps.query_rpc_cooldown,
        ));
        let chain_config = settings.chain_config(
            &chain_cfg,
            &query_rpc_pool,
            deps.indexed_artifact_source.clone(),
        )?;
        let railgun_contract = chain_config.deployment.contract;
        let quick_sync_endpoint = chain_config.sync.quick_sync_endpoint.clone();
        let chain_service = deps.sync_manager.add_chain(chain_config).await?;
        let poi = deps.poi_rpc_url.as_ref().map(|poi_rpc_url| {
            let proxy = Arc::new(poi::poi::Poi::new(
                poi::poi::PoiRpcClient::new(poi_rpc_url.clone()),
                deps.snark_prover.clone(),
                deps.required_poi_list.clone(),
            ));
            Arc::new(BroadcasterPoiValidator::new(
                proxy,
                poi::poi::PoiRpcClient::new(poi_rpc_url.clone()),
                deps.snark_prover.clone(),
                deps.required_poi_list.clone(),
                Some(chain_service.public_data_plane()),
            ))
        });
        let broadcaster = Arc::new(TxBroadcaster::try_from((
            chain_cfg.clone(),
            query_rpc_pool.clone(),
        ))?);
        let fees_ttl = chain_cfg.fees_ttl.into_inner();
        let fees_manager = fees_manager(&chain_cfg, &query_rpc_pool, fees_ttl)?;
        let advertised_address_scope = chain_cfg
            .advertised_railgun_address_scope
            .derivation_scope(chain_cfg.chain_id);

        let identity = match &chain_cfg.key {
            Key::ViewingPrivkey(key) => {
                ServiceIdentity::from_viewing_key(key, advertised_address_scope)?
            }
            Key::Mnemonic(mnemonic) => {
                let maintenance = WalletMaintenanceDeps {
                    chain_id: chain_cfg.chain_id,
                    railgun_contract,
                    wrapped_native_token: chain_cfg.wrapped_native_token,
                    query_rpc_pool: &query_rpc_pool,
                    evm_wallets: &evm_wallets,
                    broadcaster: &broadcaster,
                    prover: &deps.prover,
                    chain_service: &chain_service,
                };
                register_mnemonic_wallet(
                    mnemonic,
                    WalletRegistration {
                        advertised_address_scope,
                        quick_sync_endpoint,
                        relay_adapt_contract: settings.relay_adapt_contract,
                    },
                    deps,
                    &maintenance,
                )
                .await?
            }
        };

        Ok(Self {
            chain_id: chain_cfg.chain_id,
            db: deps.db.clone(),
            pending_fee_note_assurance_fallback: Arc::new(FeeNoteAssuranceFallback::default()),
            fee_note_assurance_submission_tracker: Arc::new(
                FeeNoteAssuranceSubmissionTracker::default(),
            ),
            key: identity.key,
            master_public_key: identity.master_public_key,
            addr: identity.addr,
            advertised_addr: identity.advertised_addr,
            tx,
            rx,
            broadcaster,
            fees_manager,
            evm_wallets,
            count_transact_requests: Arc::new(AtomicU32::new(0)),
            count_txs_landed: Arc::new(AtomicU32::new(0)),
            client: deps.client.clone(),
            poi,
            required_poi_list: deps.required_poi_list.clone(),
            query_rpc_pool,
            railgun_contract: settings.railgun_contract,
            finality_depth: settings.finality_depth,
            receipt_poll_interval: settings.receipt_poll_interval,
            relay_adapt_contract: settings.relay_adapt_contract,
            relay_adapt_7702_contract: settings.relay_adapt_7702_contract,
            identifier: chain_cfg.identifier,
            fees_refresh_interval: chain_cfg.fees_refresh_interval.into_inner(),
            fees_ttl,
        })
    }
}

/// Chain settings resolved from the config and the chain's built-in
/// defaults before the EVM wallets load. The railgun contract and finality
/// depth stay optional here; `chain_config` requires them.
struct ResolvedChainSettings {
    deployment_defaults: Option<RailgunDeployment>,
    relay_adapt_contract: Option<Address>,
    relay_adapt_7702_contract: Option<Address>,
    railgun_contract: Option<Address>,
    finality_depth: Option<u64>,
    block_time: Duration,
    receipt_poll_interval: Duration,
}

impl ResolvedChainSettings {
    fn resolve(chain_cfg: &Chain) -> Result<Self, BroadcasterServiceError> {
        let deployment_defaults = RailgunDeployment::for_chain(chain_cfg.chain_id);
        let timing_defaults = chain_timing_defaults(chain_cfg.chain_id);
        let relay_adapt_contract =
            resolve_relay_adapt_contract(chain_cfg, deployment_defaults.as_ref())?;
        let relay_adapt_7702_contract = chain_cfg
            .relay_adapt_7702_contract
            .or_else(|| deployment_defaults.map(|config| config.relay_adapt_7702_contract));
        let sync = chain_cfg.sync.as_ref();
        let railgun_contract = sync
            .and_then(|sync| sync.railgun_contract)
            .or_else(|| deployment_defaults.as_ref().map(|config| config.contract));
        let finality_depth = sync
            .and_then(|sync| sync.finality_depth)
            .or_else(|| timing_defaults.map(|(_, finality_depth)| finality_depth));
        let block_time = sync
            .and_then(|sync| sync.block_time)
            .map(|value| *value)
            .or_else(|| timing_defaults.map(|(block_time, _)| block_time))
            .ok_or(BroadcasterServiceError::BlockTimeMissing)?;
        #[allow(clippy::redundant_closure_for_method_calls)]
        let receipt_poll_interval = sync
            .and_then(|sync| sync.poll_interval)
            .map_or(Duration::from_secs(15), |value| value.into_inner());
        Ok(Self {
            deployment_defaults,
            relay_adapt_contract,
            relay_adapt_7702_contract,
            railgun_contract,
            finality_depth,
            block_time,
            receipt_poll_interval,
        })
    }

    /// The sync configuration for this chain. Errors when the railgun
    /// contract, finality depth or a sync or deployment setting has neither a
    /// configured nor a default value.
    fn chain_config(
        &self,
        chain_cfg: &Chain,
        query_rpc_pool: &Arc<QueryRpcPool>,
        indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    ) -> Result<ChainConfig, BroadcasterServiceError> {
        let railgun_contract = self
            .railgun_contract
            .ok_or(BroadcasterServiceError::RailgunContractMissing)?;
        let finality_depth = self
            .finality_depth
            .ok_or(BroadcasterServiceError::FinalityDepthMissing)?;
        let sync = self.sync_options(chain_cfg, indexed_artifact_source)?;
        let deployment = self.deployment(chain_cfg, railgun_contract)?;
        Ok(ChainConfig {
            deployment,
            sync,
            rpcs: query_rpc_pool.clone(),
            archive_rpc_url: chain_cfg
                .sync
                .as_ref()
                .and_then(|sync| sync.archive_rpc_url.clone()),
            archive_rpc_http_client: None,
            block_time: self.block_time,
            finality_depth,
            http_client: HttpClient::default(),
            progress_tx: None,
            poi_submission_routes: None,
        })
    }

    fn sync_options(
        &self,
        chain_cfg: &Chain,
        indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    ) -> Result<RailgunSyncOptions, BroadcasterServiceError> {
        let sync = chain_cfg.sync.as_ref();
        let block_range = sync.and_then(|sync| sync.block_range).unwrap_or(500);
        let defaults = RailgunSyncOptions::for_chain(
            chain_cfg.chain_id,
            block_range,
            self.receipt_poll_interval,
        );
        let anchor_interval = sync
            .and_then(|sync| sync.anchor_interval)
            .or_else(|| defaults.as_ref().map(|config| config.anchor_interval))
            .ok_or(BroadcasterServiceError::AnchorIntervalMissing)?;
        let anchor_retention = sync
            .and_then(|sync| sync.anchor_retention)
            .or_else(|| defaults.as_ref().map(|config| config.anchor_retention))
            .unwrap_or(5);
        let archive_until_block = sync
            .and_then(|sync| sync.archive_until_block)
            .or_else(|| defaults.as_ref().map(|config| config.archive_until_block))
            .ok_or(BroadcasterServiceError::ArchiveUntilBlockMissing)?;
        let quick_sync_endpoint = if sync.is_some_and(|sync| sync.disable_quick_sync) {
            None
        } else {
            sync.and_then(|sync| sync.quick_sync_endpoint.clone())
                .or_else(|| {
                    defaults
                        .as_ref()
                        .and_then(|config| config.quick_sync_endpoint.clone())
                })
        };
        let indexed_wallet_block_range = sync
            .and_then(|sync| sync.indexed_wallet_block_range)
            .or_else(|| {
                defaults
                    .as_ref()
                    .map(|config| config.indexed_wallet_block_range)
            })
            .unwrap_or(DEFAULT_INDEXED_WALLET_BLOCK_RANGE);
        Ok(RailgunSyncOptions {
            archive_until_block,
            block_range,
            indexed_wallet_block_range,
            poll_interval: self.receipt_poll_interval,
            quick_sync_endpoint,
            indexed_artifact_source,
            anchor_interval,
            anchor_retention,
        })
    }

    fn deployment(
        &self,
        chain_cfg: &Chain,
        railgun_contract: Address,
    ) -> Result<RailgunDeployment, BroadcasterServiceError> {
        let sync = chain_cfg.sync.as_ref();
        let defaults = self.deployment_defaults.as_ref();
        let v2_start_block = sync
            .and_then(|sync| sync.v2_start_block)
            .or_else(|| defaults.map(|config| config.v2_start_block))
            .ok_or(BroadcasterServiceError::V2StartBlockMissing)?;
        let legacy_shield_block = sync
            .and_then(|sync| sync.legacy_shield_block)
            .or_else(|| defaults.map(|config| config.legacy_shield_block))
            .ok_or(BroadcasterServiceError::LegacyShieldBlockMissing)?;
        let deployment_block = sync
            .and_then(|sync| sync.deployment_block)
            .or_else(|| defaults.map(|config| config.deployment_block))
            .ok_or(BroadcasterServiceError::DeploymentBlockMissing)?;
        Ok(RailgunDeployment {
            chain_id: chain_cfg.chain_id,
            contract: railgun_contract,
            relay_adapt_contract: self.relay_adapt_contract,
            relay_adapt_7702_contract: self.relay_adapt_7702_contract.unwrap_or_default(),
            relay_adapt_7702_delegates: defaults
                .map_or(&[], |config| config.relay_adapt_7702_delegates),
            relay_adapt_history: defaults.map_or(&[], |config| config.relay_adapt_history),
            deployment_block,
            v2_start_block,
            legacy_shield_block,
        })
    }
}

/// Built-in block time and finality depth for chains that have them.
const fn chain_timing_defaults(chain_id: ChainId) -> Option<(Duration, u64)> {
    match chain_id {
        1 => Some((Duration::from_secs(12), 12)),
        56 => Some((Duration::from_millis(450), 15)),
        137 => Some((Duration::from_secs(1), 256)),
        42161 => Some((Duration::from_millis(250), 64)),
        8453 => Some((Duration::from_secs(2), 10)),
        _ => None,
    }
}

/// The configured EVM wallets plus any derived from the mnemonic, without
/// duplicates.
fn load_evm_wallets(chain_cfg: &Chain) -> Result<EvmWallets, BroadcasterServiceError> {
    let derived_wallets = if let Key::Mnemonic(mnemonic) = &chain_cfg.key
        && mnemonic.num_derived_evm_wallets > 0
    {
        derive_evm_wallet_keys(&mnemonic.seed_phrase, mnemonic.num_derived_evm_wallets)?
    } else {
        vec![]
    };
    chain_cfg
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
        .collect::<Result<Vec<_>, BroadcasterServiceError>>()
}

fn fees_manager(
    chain_cfg: &Chain,
    query_rpc_pool: &Arc<QueryRpcPool>,
    fees_ttl: Duration,
) -> Result<Arc<FeesManager>, BroadcasterServiceError> {
    let multicall_contract = chain_cfg
        .multicall_contract
        .ok_or(BroadcasterServiceError::MissingMulticallContract)?;
    let fee_bonus = WAD + U256::from(chain_cfg.fee_bonus.bps()) * WAD / FEE_BONUS_BPS_DENOMINATOR;
    Ok(Arc::new(FeesManager::new(
        &chain_cfg.fees,
        fee_bonus,
        query_rpc_pool.clone(),
        multicall_contract,
        chain_cfg.wrapped_native_token,
        fees_ttl.saturating_mul(5),
    )))
}

/// The viewing key and addresses a service decrypts and advertises with.
struct ServiceIdentity {
    key: [u8; 32],
    master_public_key: U256,
    addr: RailgunAddress,
    advertised_addr: RailgunAddress,
}

impl ServiceIdentity {
    fn from_viewing_key(
        key: &Bytes,
        advertised_address_scope: Option<(u8, ChainId)>,
    ) -> Result<Self, BroadcasterServiceError> {
        let viewing_key: ShareableViewingKey = key.clone().into();
        let viewing_key_data = viewing_key
            .decode_viewing_key_data()
            .map_err(|_| BroadcasterServiceError::InvalidViewingPrivkey)?;
        let addr = viewing_key_data.derive_address(None)?;
        let advertised_addr = viewing_key_data.derive_address(advertised_address_scope)?;
        Ok(Self {
            key: viewing_key_data.viewing_private_key,
            master_public_key: viewing_key_data.master_public_key,
            addr,
            advertised_addr,
        })
    }
}

/// What registering a mnemonic wallet needs beyond the shared deps.
struct WalletRegistration {
    advertised_address_scope: Option<(u8, ChainId)>,
    quick_sync_endpoint: Option<url::Url>,
    relay_adapt_contract: Option<Address>,
}

/// Derives the mnemonic wallet's keys, registers it with sync and starts its
/// auto-refill and UTXO-consolidation services when they are configured.
async fn register_mnemonic_wallet(
    mnemonic: &MnemonicSettings,
    registration: WalletRegistration,
    deps: &BroadcasterServiceDeps,
    maintenance: &WalletMaintenanceDeps<'_>,
) -> Result<ServiceIdentity, BroadcasterServiceError> {
    let MnemonicSettings {
        seed_phrase,
        init_block_number,
        auto_refill,
        utxo_consolidation,
        ..
    } = mnemonic;
    let chain_id = maintenance.chain_id;
    let railgun_contract = maintenance.railgun_contract;
    let wallet = WalletKeys::from_mnemonic(seed_phrase, 0)?;
    let identity = ServiceIdentity {
        key: wallet.viewing.viewing_private_key,
        master_public_key: wallet.viewing.master_public_key,
        addr: wallet.viewing.derive_address(None)?,
        advertised_addr: wallet
            .viewing
            .derive_address(registration.advertised_address_scope)?,
    };
    let chain_key = ChainKey {
        chain_id,
        contract: railgun_contract,
    };
    let wallet_id = wallet.viewing.derive_address(None)?;
    let cache_key = WalletCacheKey::new(wallet_id.as_ref(), chain_id, railgun_contract);
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key: cache_key.clone(),
        start_block: Some(*init_block_number),
        sync_to_block: None,
        quick_sync_endpoint: registration.quick_sync_endpoint,
        scan_keys: wallet.viewing,
        spending_public_key: Some(wallet.spending_public_key),
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: Some((*deps.poi_recovery_prover).clone()),
        use_indexed_wallet_catch_up: true,
    };
    let handle = deps.sync_manager.add_wallet(wallet_cfg).await?;
    if let Some(auto_refill) = auto_refill.clone()
        && let Some(relay_adapt_contract) = registration.relay_adapt_contract
    {
        maintenance.spawn_auto_refill(
            auto_refill,
            relay_adapt_contract,
            WalletTask {
                wallet: wallet.clone(),
                wallet_handle: handle.clone(),
                cache_key: cache_key.clone(),
            },
        );
    }
    if let Some(utxo_consolidation) = utxo_consolidation.clone() {
        maintenance.spawn_utxo_consolidation(
            utxo_consolidation,
            WalletTask {
                wallet: wallet.clone(),
                wallet_handle: handle,
                cache_key: cache_key.clone(),
            },
        );
    }
    Ok(identity)
}

/// The chain-level values the wallet maintenance services start with.
struct WalletMaintenanceDeps<'a> {
    chain_id: ChainId,
    railgun_contract: Address,
    wrapped_native_token: Address,
    query_rpc_pool: &'a Arc<QueryRpcPool>,
    evm_wallets: &'a EvmWallets,
    broadcaster: &'a Arc<TxBroadcaster>,
    prover: &'a Arc<ProverService>,
    chain_service: &'a Arc<ChainService>,
}

/// The wallet a maintenance task runs for, with the handle it waits on and
/// the cache key it logs.
struct WalletTask {
    wallet: WalletKeys,
    wallet_handle: WalletHandle,
    cache_key: WalletCacheKey,
}

impl WalletMaintenanceDeps<'_> {
    fn spawn_auto_refill(
        &self,
        auto_refill: AutoRefillSettings,
        relay_adapt_contract: Address,
        task: WalletTask,
    ) {
        let chain_id = self.chain_id;
        let railgun_contract = self.railgun_contract;
        let wrapped_native_token = self.wrapped_native_token;
        let query_rpc_pool = self.query_rpc_pool.clone();
        let evm_wallets = self.evm_wallets.clone();
        let broadcaster = self.broadcaster.clone();
        let prover = self.prover.clone();
        let WalletTask {
            wallet,
            wallet_handle: auto_refill_handle,
            cache_key,
        } = task;
        let chain_handle = self.chain_service.handle();
        tokio::spawn(
            async move {
                if let Err(error) = auto_refill_handle.wait_until_ready_or_shutdown().await {
                    warn!(%error, %cache_key, "wallet sync unavailable for auto-refill");
                    return;
                }
                let cfg = AutoRefillConfig {
                    chain_id,
                    railgun_contract,
                    relay_adapt_contract,
                    wrapped_native_token,
                    wallet,
                    wallet_handle: auto_refill_handle,
                    chain_handle,
                    auto_refill,
                };
                let auto_refill_service =
                    AutoRefillService::new(cfg, evm_wallets, query_rpc_pool, broadcaster, prover);
                info!(%cache_key, "wallet sync ready for auto-refill");
                auto_refill_service.run().await;
            }
            .instrument(info_span!("auto_refill")),
        );
    }

    fn spawn_utxo_consolidation(
        &self,
        utxo_consolidation: UtxoConsolidationSettings,
        task: WalletTask,
    ) {
        let chain_id = self.chain_id;
        let railgun_contract = self.railgun_contract;
        let query_rpc_pool = self.query_rpc_pool.clone();
        let evm_wallets = self.evm_wallets.clone();
        let broadcaster = self.broadcaster.clone();
        let prover = self.prover.clone();
        let WalletTask {
            wallet,
            wallet_handle: consolidation_handle,
            cache_key,
        } = task;
        let chain_handle = self.chain_service.handle();
        tokio::spawn(
            async move {
                if let Err(error) = consolidation_handle.wait_until_ready_or_shutdown().await {
                    warn!(%error, %cache_key, "wallet sync unavailable for UTXO consolidation");
                    return;
                }
                let cfg = UtxoConsolidationConfig {
                    chain_id,
                    railgun_contract,
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
                info!(%cache_key, "wallet sync ready for utxo consolidation");
                consolidation_service.run().await;
            }
            .instrument(info_span!("utxo_consolidation")),
        );
    }
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

/// Resolve the legacy `RelayAdapt`, which auto-refill needs to unwrap and send native funds.
fn resolve_relay_adapt_contract(
    chain_cfg: &Chain,
    deployment_defaults: Option<&RailgunDeployment>,
) -> Result<Option<Address>, BroadcasterServiceError> {
    let relay_adapt_contract = chain_cfg
        .relay_adapt_contract
        .or_else(|| deployment_defaults.and_then(|config| config.relay_adapt_contract));
    if relay_adapt_contract.is_none()
        && matches!(&chain_cfg.key, Key::Mnemonic(mnemonic) if mnemonic.auto_refill.is_some())
    {
        return Err(BroadcasterServiceError::AutoRefillRequiresRelayAdapt);
    }
    Ok(relay_adapt_contract)
}

#[cfg(test)]
mod tests;
