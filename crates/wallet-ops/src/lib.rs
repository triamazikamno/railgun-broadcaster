use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use alloy::eips::BlockNumberOrTag;
use alloy::eips::Encodable2718;
use alloy::hex;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder as _};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, address, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::{FeeHistory, TransactionReceipt, TransactionRequest};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use alloy::uint;
use broadcaster_core::contracts::shield::derive_shield_private_key;
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData};
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, EncryptedTransactRequest,
    railgun_txid_leaf_hash,
};
use broadcaster_core::transact_response::DecryptedTransactResponse;
use broadcaster_monitor::FeeRow;
use eyre::{Report, Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore, PendingOutputPoiContextRecord, PendingOutputPoiRole};
use merkletree::tree::MerkleForest;
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::prover::build_prover_cache_with_progress;
pub use railgun_wallet::prover::{
    ProverCacheBuildProgress, ProverCacheBuildReport, ProverCacheBuildStage,
};
use railgun_wallet::tx::{
    BroadcasterFeeOutput, BuildError, PoiMerkleProofSource, PreTransactionPoiGenerationRequest,
    PreTransactionPoiMap, SendPlan, SendRequest as RailgunSendRequest, TransactionPlanChunk,
    UnshieldMode, UnshieldPlan, UnshieldRequest as RailgunUnshieldRequest,
    generate_pre_transaction_pois, max_broadcaster_fee_token_spendable, max_send_spendable,
    max_unshield_spendable, send_selection_info, send_selection_info_with_broadcaster_fee_token,
    send_selection_info_with_separate_broadcaster_fee_seed, unshield_selection_info,
    unshield_selection_info_with_broadcaster_fee_token,
    unshield_selection_info_with_separate_broadcaster_fee_seed,
};
use railgun_wallet::{
    Note, PoiStatus, ProverService, TransactionBuilder, Utxo, UtxoCommitmentKind, UtxoSource,
    WalletUtxo,
};
use rand::seq::IndexedRandom;
use reqwest::Url;
use serde::Serialize;
use sync_service::{
    ChainConfig, ChainConfigDefaults, ChainKey, LocalPoiMerkleProofSource, SyncManager,
    SyncProgressSender, WalletConfig, WalletHandle, WalletLocalPoiCaches, WalletPendingOverlay,
    WalletPendingSpent,
};
pub use sync_service::{
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiCacheService, PoiReadSource,
    SyncProgressStage, SyncProgressUpdate,
};
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use waku_relay::client::Client as WakuClient;
use waku_relay::msg::ContentTopic;
use zeroize::{Zeroize, Zeroizing};

pub use local_db::DbStore as WalletDbStore;
pub use waku_relay::client::Client as PublicBroadcasterWakuClient;

static ACTIVE_PROVER_CACHE_BUILDS: LazyLock<
    Mutex<HashMap<PathBuf, watch::Sender<Option<ProverCacheBuildProgress>>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

mod amounts;
mod anchors;
mod http;
mod poi_contexts;
mod public_wallet;
mod signer;
mod utxos;

pub mod settings;
pub mod vault;

pub use amounts::{
    is_wrapped_native_token, parse_railgun_recipient, parse_send_amount, parse_unshield_amount,
};
pub use anchors::{
    BroadcasterFeePolicy, BroadcasterFeePolicyStatus, TokenAnchorRateCache,
    TokenAnchorRefreshHandle, average_non_outlier_anchor_rates, fixed_token_anchor_rate,
    known_token_anchor_sources, oracle_answer_to_anchor_rate, refresh_token_anchor_rates,
    spawn_token_anchor_refresh_worker,
};
pub use http::{
    HttpContext, WalletNetworkConfig, WalletNetworkHealth, WalletNetworkHealthState,
    WalletNetworkMode, WalletNetworkProgress, WalletNetworkProgressStage, WalletTorClient,
    WalletTorClientProvider, build_http_client, build_wallet_network_context,
    build_wallet_network_context_with_progress, request_tor_state_reset,
    resolve_wallet_network_mode,
};
use public_wallet::vaulted_public_signer;
pub use public_wallet::{
    PublicAccountBalance, PublicActionAttemptInfo, PublicActionCommand, PublicActionCommandKind,
    PublicActionCommandReceiver, PublicActionCommandSender, PublicActionGasFeeQuote,
    PublicActionGasFeeSelection, PublicActionProgressStatus, PublicActionProgressStep,
    PublicActionProgressUpdate, PublicActionSessionEvent, PublicActionSessionEventSender,
    PublicAssetId, PublicBalanceAmount, PublicBalanceAsset, PublicBalanceEntry,
    PublicBalanceRefreshCoordinator, PublicBalanceSnapshot, PublicSendRequest, PublicSendResult,
    PublicShieldRequest, estimate_public_native_action_gas_reserve,
    public_action_replacement_bumped_fee, public_balance_assets_for_chain,
    public_balance_refresh_interval_secs, public_native_action_gas_reserve,
    public_native_action_gas_units, quote_public_action_gas_fee, refresh_public_balances,
    submit_public_send, submit_public_send_with_progress, submit_public_shield,
    submit_public_shield_with_progress,
};
use signer::EvmTransactionSigner;
use utxos::apply_pending_overlay_to_outputs;
pub use utxos::{
    ListUtxosOutput, TokenTotal, UtxoOutput, max_broadcaster_fee_token_amount_from_outputs,
    max_send_amount_from_outputs, max_unshield_amount_from_outputs,
};

#[derive(Debug, Clone)]
pub struct BuildCacheRequest {
    pub db_path: PathBuf,
    pub network_mode: Option<WalletNetworkMode>,
    pub proxy: Option<Url>,
}

pub struct ProverCacheBuildSession {
    db_path: PathBuf,
    progress_tx: watch::Sender<Option<ProverCacheBuildProgress>>,
}

impl Drop for ProverCacheBuildSession {
    fn drop(&mut self) {
        let _ = self.progress_tx.send(None);
        let mut active = ACTIVE_PROVER_CACHE_BUILDS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.remove(&self.db_path);
    }
}

impl ProverCacheBuildSession {
    fn publish(&self, progress: ProverCacheBuildProgress) {
        let _ = self.progress_tx.send(Some(progress));
    }
}

fn prover_cache_build_key(db_path: &Path) -> PathBuf {
    db_path
        .canonicalize()
        .unwrap_or_else(|_| db_path.to_path_buf())
}

pub fn begin_prover_cache_build(db_path: &Path) -> Result<ProverCacheBuildSession> {
    let db_path = prover_cache_build_key(db_path);
    let (progress_tx, _) = watch::channel(Some(ProverCacheBuildProgress::preparing()));
    {
        let mut active = ACTIVE_PROVER_CACHE_BUILDS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.contains_key(&db_path) {
            return Err(eyre!(
                "prover cache build is already running for {}",
                db_path.display()
            ));
        }
        active.insert(db_path.clone(), progress_tx.clone());
    }
    Ok(ProverCacheBuildSession {
        db_path,
        progress_tx,
    })
}

pub fn subscribe_prover_cache_build(
    db_path: &Path,
) -> Option<watch::Receiver<Option<ProverCacheBuildProgress>>> {
    let db_path = prover_cache_build_key(db_path);
    let active = ACTIVE_PROVER_CACHE_BUILDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    active.get(&db_path).map(watch::Sender::subscribe)
}

pub async fn build_cache(request: BuildCacheRequest) -> Result<ProverCacheBuildReport> {
    let session = begin_prover_cache_build(&request.db_path)?;
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: request.db_path.clone(),
        })
        .wrap_err("open local db")?,
    );
    let http = build_wallet_network_context(WalletNetworkConfig {
        network_mode: request.network_mode,
        proxy: request.proxy.as_ref(),
        data_dir: &request.db_path,
    })
    .await?;
    build_cache_with_context_and_progress_with_session(db, &http, session, |_| {}).await
}

pub async fn build_cache_with_context(
    db: Arc<DbStore>,
    http: &HttpContext,
) -> Result<ProverCacheBuildReport> {
    build_cache_with_context_and_progress(db, http, |_| {}).await
}

pub async fn build_cache_with_context_and_progress(
    db: Arc<DbStore>,
    http: &HttpContext,
    mut on_progress: impl FnMut(ProverCacheBuildProgress) + Send + 'static,
) -> Result<ProverCacheBuildReport> {
    let session = begin_prover_cache_build(db.root_dir())?;
    build_cache_with_context_and_progress_with_session(db, http, session, move |progress| {
        on_progress(progress);
    })
    .await
}

pub async fn build_cache_with_context_and_progress_with_session(
    db: Arc<DbStore>,
    http: &HttpContext,
    session: ProverCacheBuildSession,
    mut on_progress: impl FnMut(ProverCacheBuildProgress) + Send + 'static,
) -> Result<ProverCacheBuildReport> {
    let source = artifact_source(http);
    let db_path = db.root_dir().to_path_buf();
    tracing::info!(
        db_path = %db_path.display(),
        network_mode = %http.network_mode(),
        artifact_dir = %source.out_dir.display(),
        "starting wallet cache build"
    );
    let report = tokio::task::spawn_blocking(move || {
        build_prover_cache_with_progress(&source, Some(db.as_ref()), |progress| {
            session.publish(progress.clone());
            on_progress(progress);
        })
    })
    .await
    .wrap_err("join prover cache build task")??;
    tracing::info!(
        railgun_variants = report.railgun_variants,
        poi_variants = report.poi_variants,
        total_variants = report.total_variants,
        succeeded_variants = report.succeeded_variants,
        failed_variants = report.failed_variants,
        elapsed_ms = report.elapsed_ms,
        "wallet cache build complete"
    );
    Ok(report)
}

pub(crate) use poi_contexts::{
    active_list_pre_transaction_pois, persist_pending_send_output_poi_contexts,
    persist_pending_unshield_output_poi_contexts, public_broadcaster_pre_transaction_pois,
};
pub(crate) use utxos::utxo_outputs_from_utxos;

pub(crate) use amounts::wrapped_native_token_for_chain;
#[cfg(test)]
pub(crate) use poi_contexts::{
    build_pending_output_poi_context_records, pending_send_output_role_plans,
    pending_unshield_output_role_plans,
};

const DEFAULT_QUERY_RPC_COOLDOWN: Duration = Duration::from_secs(5);
const DEFAULT_BLOCK_RANGE: u64 = 500;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);
const GAS_LIMIT_BUFFER: u64 = 100_000;
const GAS_PRICE_BUFFER_NUMERATOR: u128 = 105;
const GAS_PRICE_BUFFER_DENOMINATOR: u128 = 100;
const PUBLIC_BROADCASTER_FEE_ATTEMPTS: usize = 5;
const PUBLIC_BROADCASTER_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5);
const PUBLIC_BROADCASTER_FEE_BUFFER_DIVISOR: U256 = uint!(100_U256);
const APPROX_BASE_GAS: u64 = 650_000;
const APPROX_GAS_PER_INPUT: u64 = 155_000;
const APPROX_GAS_PER_PRIVATE_OUTPUT: u64 = 85_000;
const APPROX_GAS_PER_PUBLIC_OUTPUT: u64 = 65_000;
const APPROX_GAS_PER_TRANSACTION: u64 = 120_000;
const APPROX_SEND_EXTRA_GAS: u64 = 40_000;
const APPROX_UNWRAP_EXTRA_GAS: u64 = 50_000;
const APPROX_SAFETY_GAS: u64 = 150_000;
const APPROX_GAS_UPLIFT_NUMERATOR: u64 = 112;
const APPROX_GAS_UPLIFT_DENOMINATOR: u64 = 100;
const PUBLIC_BROADCASTER_MAX_ENTERED_AMOUNT_ERROR: &str = "public broadcaster max entered amount: ";
const PUBLIC_BROADCASTER_FEE_TOKEN_MAX_SPENDABLE_ERROR: &str =
    "public broadcaster fee-token max spendable: ";
const FEE_BASIS_POINTS_DENOMINATOR: U256 = uint!(10_000_U256);
pub const RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS: U256 = uint!(25_U256);

/// WETH `deposit()` function selector - no arguments, ETH value is the deposit
/// amount.
const WETH_DEPOSIT_SELECTOR: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopWalletSyncStartPolicy {
    ImportedHistoricalBackfill,
    CurrentSafeHeadNoBackfill,
}

impl From<vault::WalletSource> for DesktopWalletSyncStartPolicy {
    fn from(value: vault::WalletSource) -> Self {
        match value {
            vault::WalletSource::Generated => Self::CurrentSafeHeadNoBackfill,
            vault::WalletSource::Imported => Self::ImportedHistoricalBackfill,
        }
    }
}

pub struct ViewWalletChainSessionRequest {
    pub view_session: Arc<vault::DesktopViewSession>,
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub sync_start_policy: DesktopWalletSyncStartPolicy,
    pub init_block_number: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub use_indexed_wallet_catch_up: bool,
    pub poi_read_source: PoiReadSource,
    pub local_poi_caches: Option<WalletLocalPoiCaches>,
    pub rewind_wallet_cache: bool,
    pub progress_tx: Option<SyncProgressSender>,
}

pub struct DesktopUnshieldCalldataRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub verify_proof: bool,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopSendCalldataRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: String,
    pub verify_proof: bool,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub const SELF_BROADCAST_AUTO_MAX_FEE_NUMERATOR: u128 = 120;
pub const SELF_BROADCAST_AUTO_MAX_FEE_DENOMINATOR: u128 = 100;
pub const SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS: u128 = 1;
pub const SELF_BROADCAST_REPLACEMENT_BUMP_NUMERATOR: u128 = 9;
pub const SELF_BROADCAST_REPLACEMENT_BUMP_DENOMINATOR: u128 = 8;
const SELF_BROADCAST_FEE_HISTORY_BLOCKS: u64 = 5;
const SELF_BROADCAST_FEE_HISTORY_REWARD_PERCENTILES: [f64; 3] = [25.0, 50.0, 75.0];
const SELF_BROADCAST_DIRECT_FEE_QUOTE_GRACE: Duration = Duration::from_millis(750);
const SELF_BROADCAST_DIRECT_FEE_QUOTE_DEADLINE: Duration = Duration::from_secs(8);
const SELF_BROADCAST_TOR_FEE_QUOTE_GRACE: Duration = Duration::from_secs(2);
const SELF_BROADCAST_TOR_FEE_QUOTE_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfBroadcastTipFallback {
    Minimum,
    RpcGasPrice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfBroadcastGasFeeQuote {
    pub rpc_gas_price: u128,
    pub suggested_max_fee_per_gas: u128,
    pub suggested_max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SelfBroadcastGasFeeSelection {
    #[default]
    Auto,
    Custom {
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfBroadcastCommandKind {
    Retry,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfBroadcastCommand {
    pub kind: SelfBroadcastCommandKind,
    pub gas_fee: SelfBroadcastGasFeeSelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfBroadcastAttemptInfo {
    pub tx_hash: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfBroadcastSessionEvent {
    StepFailed {
        stage: TransactionGenerationStage,
        message: String,
    },
    AttemptSubmitted(SelfBroadcastAttemptInfo),
    AttemptRejected {
        stage: TransactionGenerationStage,
        message: String,
    },
}

pub type SelfBroadcastCommandSender = mpsc::UnboundedSender<SelfBroadcastCommand>;
pub type SelfBroadcastCommandReceiver = mpsc::UnboundedReceiver<SelfBroadcastCommand>;
pub type SelfBroadcastSessionEventSender = mpsc::UnboundedSender<SelfBroadcastSessionEvent>;

impl SelfBroadcastGasFeeQuote {
    #[must_use]
    pub const fn from_rpc_gas_price(rpc_gas_price: u128) -> Self {
        let suggested_max_fee_per_gas = self_broadcast_auto_max_fee_per_gas(rpc_gas_price);
        let suggested_max_fee_per_gas = if suggested_max_fee_per_gas > 0 {
            suggested_max_fee_per_gas
        } else {
            SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS
        };
        Self {
            rpc_gas_price,
            suggested_max_fee_per_gas,
            suggested_max_priority_fee_per_gas: SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS,
        }
    }
}

#[must_use]
pub const fn self_broadcast_auto_max_fee_per_gas(rpc_gas_price: u128) -> u128 {
    rpc_gas_price.saturating_mul(SELF_BROADCAST_AUTO_MAX_FEE_NUMERATOR)
        / SELF_BROADCAST_AUTO_MAX_FEE_DENOMINATOR
}

#[must_use]
pub const fn self_broadcast_replacement_bumped_fee(value: u128) -> u128 {
    value
        .saturating_mul(SELF_BROADCAST_REPLACEMENT_BUMP_NUMERATOR)
        .saturating_add(SELF_BROADCAST_REPLACEMENT_BUMP_DENOMINATOR - 1)
        / SELF_BROADCAST_REPLACEMENT_BUMP_DENOMINATOR
}

pub async fn quote_desktop_self_broadcast_gas_fee(
    chain_id: u64,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    http: &HttpContext,
) -> Result<SelfBroadcastGasFeeQuote> {
    let chain = effective_desktop_chain_config(chain_id, effective_chain)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    self_broadcast_gas_fee_quote_from_rpc_pool(&query_rpc_pool, http.network_mode()).await
}

pub struct DesktopUnshieldSelfBroadcastRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub public_account_uuid: String,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub verify_proof: bool,
    pub gas_fee: SelfBroadcastGasFeeSelection,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
    pub command_rx: Option<SelfBroadcastCommandReceiver>,
    pub event_tx: Option<SelfBroadcastSessionEventSender>,
}

pub struct DesktopSendSelfBroadcastRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub public_account_uuid: String,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: String,
    pub verify_proof: bool,
    pub gas_fee: SelfBroadcastGasFeeSelection,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
    pub command_rx: Option<SelfBroadcastCommandReceiver>,
    pub event_tx: Option<SelfBroadcastSessionEventSender>,
}

#[derive(Debug, Clone)]
pub struct PublicBroadcasterCandidate {
    pub chain_id: u64,
    pub railgun_address: String,
    pub identifier: Option<String>,
    pub token: Address,
    pub fee: U256,
    pub fees_id: String,
    pub fee_expiration: SystemTime,
    pub reliability: f64,
    pub available_wallets: u32,
    pub version: String,
    pub relay_adapt: Address,
    pub relay_adapt_7702: Option<Address>,
    pub required_poi_list_keys: Vec<String>,
    pub viewing_public_key: [u8; 32],
    pub address_data: AddressData,
    pub fee_policy_status: BroadcasterFeePolicyStatus,
}

impl PublicBroadcasterCandidate {
    #[must_use]
    pub const fn is_allowed_by_fee_policy(&self, policy: BroadcasterFeePolicy) -> bool {
        policy.allows_status(self.fee_policy_status)
    }

    #[must_use]
    pub const fn is_fee_suspicious(&self) -> bool {
        self.fee_policy_status.is_suspicious()
    }

    pub fn parsed_required_poi_list_keys(&self) -> Result<Vec<FixedBytes<32>>> {
        self.required_poi_list_keys
            .iter()
            .map(|list_key| {
                let bare = list_key.strip_prefix("0x").unwrap_or(list_key);
                if bare.len() != 64 {
                    return Err(eyre!(
                        "invalid required POI list key {list_key}: expected 32-byte hex"
                    ));
                }
                let bytes = hex::decode_to_array(bare)
                    .wrap_err_with(|| format!("invalid required POI list key {list_key}"))?;
                Ok(FixedBytes::from(bytes))
            })
            .collect()
    }

    fn from_fee_row(row: &FeeRow) -> Option<Self> {
        Self::from_fee_row_with_policy_status(row, BroadcasterFeePolicyStatus::UnknownAnchor)
    }

    fn from_fee_row_with_policy_status(
        row: &FeeRow,
        fee_policy_status: BroadcasterFeePolicyStatus,
    ) -> Option<Self> {
        let railgun_address = RailgunAddress::from(row.railgun_address.as_ref());
        let address_data = AddressData::try_from(&railgun_address).ok()?;
        Some(Self {
            chain_id: row.chain_id,
            railgun_address: row.railgun_address.to_string(),
            identifier: row.identifier.as_ref().map(ToString::to_string),
            token: row.token_address,
            fee: row.fee,
            fees_id: row.fees_id.to_string(),
            fee_expiration: row.fee_expiration,
            reliability: row.reliability,
            available_wallets: row.available_wallets,
            version: row.version.to_string(),
            relay_adapt: row.relay_adapt,
            relay_adapt_7702: row.relay_adapt_7702,
            required_poi_list_keys: row
                .required_poi_list_keys
                .iter()
                .map(ToString::to_string)
                .collect(),
            viewing_public_key: address_data.viewing_public_key,
            address_data,
            fee_policy_status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicBroadcasterSelection {
    Random,
    Specific { railgun_address: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublicBroadcasterFeeMode {
    #[default]
    DeductFromAmount,
    AddToAmount,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransactionGenerationStage {
    #[default]
    SelectingPrivateNotes,
    ProvingTransaction,
    EstimatingBroadcasterFee,
    GeneratingPoiProofs,
    PublishingToBroadcaster,
    WaitingForBroadcasterResponse,
    EstimatingSelfBroadcastGas,
    SigningSelfBroadcast,
    WaitingForSelfBroadcastReceipt,
}

impl TransactionGenerationStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SelectingPrivateNotes => "Selecting private notes",
            Self::ProvingTransaction => "Proving transaction",
            Self::EstimatingBroadcasterFee => "Estimating broadcaster fee",
            Self::GeneratingPoiProofs => "Generating POI proofs",
            Self::PublishingToBroadcaster => "Publishing to broadcaster",
            Self::WaitingForBroadcasterResponse => "Waiting for broadcaster response",
            Self::EstimatingSelfBroadcastGas => "Estimating self-broadcast gas",
            Self::SigningSelfBroadcast => "Signing self-broadcast transaction",
            Self::WaitingForSelfBroadcastReceipt => "Waiting for self-broadcast receipt",
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::SelectingPrivateNotes => {
                "Finding POI-verified notes that cover the amount and fee."
            }
            Self::ProvingTransaction => {
                "Generating the zero-knowledge proof. This is usually the slowest step."
            }
            Self::EstimatingBroadcasterFee => "Checking gas cost and broadcaster fee requirements.",
            Self::GeneratingPoiProofs => "Generating POI proofs for transaction outputs.",
            Self::PublishingToBroadcaster => "Encrypting and publishing the request over Waku.",
            Self::WaitingForBroadcasterResponse => {
                "Waiting for the selected broadcaster to respond."
            }
            Self::EstimatingSelfBroadcastGas => {
                "Estimating direct transaction gas and checking the gas payer balance."
            }
            Self::SigningSelfBroadcast => "Unlocking the selected Public account and signing.",
            Self::WaitingForSelfBroadcastReceipt => {
                "Waiting for the submitted transaction receipt."
            }
        }
    }
}

pub type TransactionGenerationProgressSender = watch::Sender<TransactionGenerationStage>;

fn update_transaction_generation_stage(
    progress_tx: Option<&TransactionGenerationProgressSender>,
    stage: TransactionGenerationStage,
) {
    if let Some(progress_tx) = progress_tx {
        let _ = progress_tx.send(stage);
    }
}

pub struct DesktopUnshieldPublicBroadcasterRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub verify_proof: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub fee_policy: BroadcasterFeePolicy,
    pub anchor_cache: Option<Arc<TokenAnchorRateCache>>,
    pub waku: Arc<WakuClient>,
    pub response_timeout: Duration,
    pub republish_interval: Duration,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopSendPublicBroadcasterRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: String,
    pub verify_proof: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub fee_policy: BroadcasterFeePolicy,
    pub anchor_cache: Option<Arc<TokenAnchorRateCache>>,
    pub waku: Arc<WakuClient>,
    pub response_timeout: Duration,
    pub republish_interval: Duration,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopUnshieldPublicBroadcasterEstimateRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub session: Arc<WalletSession>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub fee_policy: BroadcasterFeePolicy,
    pub anchor_cache: Option<Arc<TokenAnchorRateCache>>,
}

pub struct DesktopSendPublicBroadcasterEstimateRequest {
    pub chain_id: u64,
    pub effective_chain: Option<settings::EffectiveChainConfig>,
    pub session: Arc<WalletSession>,
    pub token: Address,
    pub fee_token: Address,
    pub amount: U256,
    pub recipient: String,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub fee_policy: BroadcasterFeePolicy,
    pub anchor_cache: Option<Arc<TokenAnchorRateCache>>,
}

#[derive(Debug, Clone)]
pub struct PublicBroadcasterCostEstimate {
    pub broadcaster: PublicBroadcasterCandidate,
    pub action_token: Address,
    pub fee_token: Address,
    pub entered_amount: U256,
    pub receiver_amount: U256,
    pub recipient_amount: U256,
    pub total_private_spend: U256,
    pub fee_amount: U256,
    pub protocol_fee_amount: U256,
    pub protocol_fee_bps: U256,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub max_receiver_amount: U256,
    pub max_entered_amount: U256,
    pub gas_limit: u64,
    pub min_gas_price: u128,
    pub native_gas_cost: U256,
    pub transaction_count: usize,
    pub input_count: usize,
    pub private_output_count: usize,
    pub public_output_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicBroadcasterResultKind {
    Submitted { tx_hash: String },
    Failed { error: String },
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct PublicBroadcasterSubmissionResult {
    pub broadcaster: PublicBroadcasterCandidate,
    pub action_token: Address,
    pub fee_token: Address,
    pub entered_amount: U256,
    pub receiver_amount: U256,
    pub recipient_amount: U256,
    pub total_private_spend: U256,
    pub fee_amount: U256,
    pub protocol_fee_amount: U256,
    pub protocol_fee_bps: U256,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub gas_limit: u64,
    pub min_gas_price: u128,
    pub result: PublicBroadcasterResultKind,
}

#[derive(Debug, Clone)]
struct PreparedPublicBroadcasterPlan<P> {
    plan: P,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
    broadcaster: PublicBroadcasterCandidate,
    action_token: Address,
    fee_token: Address,
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: U256,
    fee_mode: PublicBroadcasterFeeMode,
    gas_limit: u64,
    min_gas_price: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedUnshieldCall {
    pub chain_id: u64,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub max_spendable: U256,
    pub transaction_count: usize,
    pub input_count: usize,
    pub private_output_count: usize,
    pub public_output_count: usize,
    pub to: Address,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSendCall {
    pub chain_id: u64,
    pub token: Address,
    pub amount: U256,
    pub recipient: String,
    pub max_spendable: U256,
    pub transaction_count: usize,
    pub input_count: usize,
    pub private_output_count: usize,
    pub public_output_count: usize,
    pub to: Address,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSelfBroadcastResult {
    pub chain_id: u64,
    pub public_account_uuid: String,
    pub gas_payer: Address,
    pub gas_limit: u64,
    pub rpc_gas_price: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub estimated_native_gas_cost: U256,
    pub live_native_balance: U256,
    pub tx: TxReceiptOutput,
    pub attempts: Vec<SelfBroadcastAttemptInfo>,
}

struct PreparedPrivatePlan<P> {
    plan: P,
    max_spendable: U256,
    prover: ProverService,
}

struct DesktopUnshieldPlanRequest<'a> {
    chain_id: u64,
    effective_chain: Option<&'a settings::EffectiveChainConfig>,
    view_session: &'a vault::DesktopViewSession,
    session: &'a WalletSession,
    vault_store: &'a vault::DesktopVaultStore,
    vault_password: &'a str,
    token: Address,
    amount: U256,
    recipient: Address,
    unwrap: bool,
    verify_proof: bool,
    progress_tx: Option<&'a TransactionGenerationProgressSender>,
}

struct DesktopSendPlanRequest<'a> {
    chain_id: u64,
    effective_chain: Option<&'a settings::EffectiveChainConfig>,
    view_session: &'a vault::DesktopViewSession,
    session: &'a WalletSession,
    vault_store: &'a vault::DesktopVaultStore,
    vault_password: &'a str,
    token: Address,
    amount: U256,
    recipient: &'a str,
    verify_proof: bool,
    progress_tx: Option<&'a TransactionGenerationProgressSender>,
}

struct SelfBroadcastPreflight {
    tx_req: TransactionRequest,
    nonce: u64,
    gas_limit: u64,
    rpc_gas_price: u128,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    estimated_native_gas_cost: U256,
    live_native_balance: U256,
}

struct SubmittedSelfBroadcastAttempt {
    provider_handles: Vec<ProviderHandle>,
    tx_hash: FixedBytes<32>,
    info: SelfBroadcastAttemptInfo,
    rpc_gas_price: u128,
    estimated_native_gas_cost: U256,
    live_native_balance: U256,
}

struct SelfBroadcastSentTx {
    tx_hash: FixedBytes<32>,
    tx_hash_string: String,
    provider_handles: Vec<ProviderHandle>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TxReceiptOutput {
    pub tx_hash: String,
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldSendOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap: Option<TxReceiptOutput>,
    pub approve: TxReceiptOutput,
    pub shield: TxReceiptOutput,
}

pub struct WalletSession {
    pub chain_id: u64,
    pub cache_key: String,
    pub start_block: u64,
    pub ready_rx: watch::Receiver<bool>,
    pub snapshots_rx: watch::Receiver<Arc<ListUtxosOutput>>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    handle: WalletHandle,
}

impl WalletSession {
    pub async fn stop(&self) -> Result<()> {
        self.sync_manager
            .remove_wallet(&self.chain_key, &self.cache_key)
            .await
            .wrap_err("remove wallet sync worker")
    }

    pub async fn unspent_utxos(&self) -> Vec<Utxo> {
        let utxos = self.handle.utxos.read().await.clone();
        let pending_overlay = self.handle.pending_overlay().await;
        poi_verified_unspent_utxos_from_records(&utxos, &pending_overlay)
    }

    async fn mark_pending_spent_utxos(&self, utxos: &[Utxo], tx_hash: Option<FixedBytes<32>>) {
        self.handle.mark_pending_spent_utxos(utxos, tx_hash).await;
    }

    pub async fn clear_local_pending_spent(&self) -> bool {
        self.handle.clear_local_pending_spent().await
    }

    pub async fn refresh_poi_statuses(&self) -> bool {
        self.handle.refresh_poi_statuses().await
    }
}

fn poi_verified_unspent_utxos_from_records(
    utxos: &[WalletUtxo],
    pending_overlay: &WalletPendingOverlay,
) -> Vec<Utxo> {
    let active_poi_list_keys = default_active_poi_list_keys();
    let pending_spent_keys = pending_spent_keys(pending_overlay);
    utxos
        .iter()
        .filter(|entry| !entry.is_spent())
        .filter(|entry| !pending_spent_keys.contains(&(entry.utxo.tree, entry.utxo.position)))
        .filter(|entry| entry.utxo.poi.is_valid_for_lists(&active_poi_list_keys))
        .map(|entry| entry.utxo.clone())
        .collect()
}

fn pending_spent_keys(pending_overlay: &WalletPendingOverlay) -> HashSet<(u32, u64)> {
    pending_overlay
        .pending_spent
        .iter()
        .chain(pending_overlay.local_pending_spent.iter())
        .map(WalletPendingSpent::key)
        .collect()
}

pub fn eligible_public_broadcasters_for_asset(
    rows: &[FeeRow],
    chain_id: u64,
    token: Address,
    required_relay_adapt: Option<Address>,
) -> Result<Vec<PublicBroadcasterCandidate>> {
    chain_defaults_for_chain(chain_id)?;
    Ok(eligible_public_broadcasters(
        rows,
        chain_id,
        token,
        required_relay_adapt,
        SystemTime::now(),
    ))
}

pub fn public_broadcaster_candidates_for_asset(
    rows: &[FeeRow],
    chain_id: u64,
    token: Address,
    required_relay_adapt: Option<Address>,
    policy: BroadcasterFeePolicy,
    anchor_rate: Option<U256>,
) -> Result<Vec<PublicBroadcasterCandidate>> {
    chain_defaults_for_chain(chain_id)?;
    Ok(public_broadcaster_candidates(
        rows,
        chain_id,
        token,
        required_relay_adapt,
        SystemTime::now(),
        policy,
        anchor_rate,
    ))
}

#[must_use]
pub fn eligible_public_broadcasters(
    rows: &[FeeRow],
    chain_id: u64,
    token: Address,
    required_relay_adapt: Option<Address>,
    now: SystemTime,
) -> Vec<PublicBroadcasterCandidate> {
    rows.iter()
        .filter(|row| row.chain_id == chain_id)
        .filter(|row| row.token_address == token)
        .filter(|row| row.signature_valid)
        .filter(|row| row.fee_expiration > now)
        .filter(|row| row.available_wallets > 0)
        .filter(|row| supported_broadcaster_version(&row.version))
        // Temporarily include POI-required broadcasters so the desktop picker can
        // be assessed against long live broadcaster lists.
        .filter(|row| required_relay_adapt.is_none_or(|relay| row.relay_adapt == relay))
        .filter_map(PublicBroadcasterCandidate::from_fee_row)
        .collect()
}

#[must_use]
pub fn public_broadcaster_candidates(
    rows: &[FeeRow],
    chain_id: u64,
    token: Address,
    required_relay_adapt: Option<Address>,
    now: SystemTime,
    policy: BroadcasterFeePolicy,
    anchor_rate: Option<U256>,
) -> Vec<PublicBroadcasterCandidate> {
    rows.iter()
        .filter(|row| row.chain_id == chain_id)
        .filter(|row| row.token_address == token)
        .filter(|row| row.signature_valid)
        .filter(|row| row.fee_expiration > now)
        .filter(|row| row.available_wallets > 0)
        .filter(|row| supported_broadcaster_version(&row.version))
        .filter(|row| required_relay_adapt.is_none_or(|relay| row.relay_adapt == relay))
        .filter_map(|row| {
            PublicBroadcasterCandidate::from_fee_row_with_policy_status(
                row,
                policy.classify_fee(row.fee, anchor_rate),
            )
        })
        .collect()
}

#[must_use]
pub fn fee_policy_eligible_public_broadcasters(
    candidates: &[PublicBroadcasterCandidate],
    policy: BroadcasterFeePolicy,
) -> Vec<PublicBroadcasterCandidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.is_allowed_by_fee_policy(policy))
        .cloned()
        .collect()
}

#[must_use]
pub fn sort_specific_public_broadcasters(
    mut candidates: Vec<PublicBroadcasterCandidate>,
) -> Vec<PublicBroadcasterCandidate> {
    candidates.sort_by(|a, b| {
        a.fee
            .cmp(&b.fee)
            .then_with(|| b.reliability.total_cmp(&a.reliability))
            .then_with(|| a.railgun_address.cmp(&b.railgun_address))
    });
    candidates
}

pub fn select_public_broadcaster(
    candidates: &[PublicBroadcasterCandidate],
    selection: &PublicBroadcasterSelection,
) -> Result<PublicBroadcasterCandidate> {
    select_public_broadcaster_with_policy(
        candidates,
        selection,
        BroadcasterFeePolicy::default().with_allow_suspicious_broadcasters(true),
    )
}

pub fn select_public_broadcaster_with_policy(
    candidates: &[PublicBroadcasterCandidate],
    selection: &PublicBroadcasterSelection,
    policy: BroadcasterFeePolicy,
) -> Result<PublicBroadcasterCandidate> {
    match selection {
        PublicBroadcasterSelection::Random => {
            let supported_candidates = candidates
                .iter()
                .filter(|candidate| candidate.is_allowed_by_fee_policy(policy))
                .filter(|candidate| candidate.required_poi_list_keys.is_empty())
                .collect::<Vec<_>>();
            let eligible_candidates = candidates
                .iter()
                .filter(|candidate| candidate.is_allowed_by_fee_policy(policy))
                .collect::<Vec<_>>();
            let selected = if supported_candidates.is_empty() {
                eligible_candidates
                    .choose(&mut rand::rng())
                    .copied()
                    .cloned()
            } else {
                supported_candidates
                    .choose(&mut rand::rng())
                    .copied()
                    .cloned()
            };
            selected.ok_or_else(|| eyre!("no eligible public broadcaster for selected token"))
        }
        PublicBroadcasterSelection::Specific { railgun_address } => {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.railgun_address == *railgun_address)
                .cloned()
                .ok_or_else(|| eyre!("selected public broadcaster is no longer eligible"))?;
            if candidate.is_allowed_by_fee_policy(policy) {
                Ok(candidate)
            } else {
                Err(eyre!(
                    "selected public broadcaster fee is outside the allowed range"
                ))
            }
        }
    }
}

#[must_use]
pub fn broadcaster_fee_amount(
    token_fee_per_unit_gas: U256,
    gas_limit: u64,
    gas_price: u128,
) -> U256 {
    const FEE_SCALE: U256 = uint!(1_000_000_000_000_000_000_U256);
    token_fee_per_unit_gas * U256::from(gas_limit) * U256::from(gas_price) / FEE_SCALE
}

#[must_use]
pub const fn public_broadcaster_service_gas_price(min_gas_price: u128) -> u128 {
    min_gas_price * 101 / 100
}

#[must_use]
pub fn public_broadcaster_native_gas_cost(gas_limit: u64, min_gas_price: u128) -> U256 {
    U256::from(gas_limit) * U256::from(public_broadcaster_service_gas_price(min_gas_price))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicBroadcasterFeeMargin {
    Zero,
    Positive(U256),
    Negative(U256),
}

impl PublicBroadcasterFeeMargin {
    #[must_use]
    pub fn from_total_and_gas(total_fee: U256, gas_cost: U256) -> Self {
        if total_fee >= gas_cost {
            let margin = total_fee - gas_cost;
            if margin.is_zero() {
                Self::Zero
            } else {
                Self::Positive(margin)
            }
        } else {
            Self::Negative(gas_cost - total_fee)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicBroadcasterFeeBreakdown {
    pub native_gas_cost: U256,
    pub fee_token_gas_cost: Option<U256>,
    pub broadcaster_fee: Option<PublicBroadcasterFeeMargin>,
}

#[must_use]
pub fn public_broadcaster_fee_breakdown(
    total_fee: U256,
    gas_limit: u64,
    min_gas_price: u128,
    fee_token_anchor_rate: Option<U256>,
) -> PublicBroadcasterFeeBreakdown {
    let service_gas_price = public_broadcaster_service_gas_price(min_gas_price);
    let fee_token_gas_cost = fee_token_anchor_rate
        .filter(|anchor_rate| !anchor_rate.is_zero())
        .map(|anchor_rate| broadcaster_fee_amount(anchor_rate, gas_limit, service_gas_price));
    PublicBroadcasterFeeBreakdown {
        native_gas_cost: U256::from(gas_limit) * U256::from(service_gas_price),
        fee_token_gas_cost,
        broadcaster_fee: fee_token_gas_cost
            .map(|gas_cost| PublicBroadcasterFeeMargin::from_total_and_gas(total_fee, gas_cost)),
    }
}

fn broadcaster_fee_covers(available_fee: U256, required_fee: U256) -> bool {
    available_fee >= required_fee
}

fn buffered_public_broadcaster_fee(required_fee: U256) -> U256 {
    let buffer = required_fee / PUBLIC_BROADCASTER_FEE_BUFFER_DIVISOR;
    required_fee
        + if buffer.is_zero() {
            uint!(1_U256)
        } else {
            buffer
        }
}

#[derive(Debug, Clone, Copy)]
struct ApproximateTransactionShape {
    transaction_count: usize,
    input_count: usize,
    private_output_count: usize,
    public_output_count: usize,
    max_receiver_amount: U256,
    unwrap: bool,
    send: bool,
}

#[derive(Debug, Clone, Copy)]
struct PublicBroadcasterAmountSplit {
    entered_amount: U256,
    receiver_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
}

fn public_broadcaster_amount_split(
    entered_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
) -> Result<PublicBroadcasterAmountSplit> {
    let (receiver_amount, total_private_spend) = match fee_mode {
        PublicBroadcasterFeeMode::DeductFromAmount => {
            if entered_amount <= fee_amount {
                return Err(eyre!(
                    "entered amount must be greater than the broadcaster fee"
                ));
            }
            (entered_amount - fee_amount, entered_amount)
        }
        PublicBroadcasterFeeMode::AddToAmount => (entered_amount, entered_amount + fee_amount),
    };
    Ok(PublicBroadcasterAmountSplit {
        entered_amount,
        receiver_amount,
        total_private_spend,
        fee_amount,
        fee_mode,
    })
}

fn public_broadcaster_amount_split_for_tokens(
    entered_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
    same_token_fee: bool,
) -> Result<PublicBroadcasterAmountSplit> {
    if same_token_fee {
        return public_broadcaster_amount_split(entered_amount, fee_amount, fee_mode);
    }

    Ok(PublicBroadcasterAmountSplit {
        entered_amount,
        receiver_amount: entered_amount,
        total_private_spend: entered_amount,
        fee_amount,
        fee_mode: PublicBroadcasterFeeMode::AddToAmount,
    })
}

fn public_broadcaster_max_entered_amount(
    max_receiver_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
) -> U256 {
    match fee_mode {
        PublicBroadcasterFeeMode::DeductFromAmount => max_receiver_amount + fee_amount,
        PublicBroadcasterFeeMode::AddToAmount => max_receiver_amount,
    }
}

fn public_broadcaster_max_entered_amount_for_tokens(
    max_receiver_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
    same_token_fee: bool,
) -> U256 {
    if same_token_fee {
        public_broadcaster_max_entered_amount(max_receiver_amount, fee_amount, fee_mode)
    } else {
        max_receiver_amount
    }
}

fn railgun_protocol_fee_amount(amount: U256, fee_bps: U256) -> U256 {
    amount * fee_bps / FEE_BASIS_POINTS_DENOMINATOR
}

const fn recipient_amount_after_protocol_fee(amount: U256, protocol_fee_amount: U256) -> U256 {
    amount.saturating_sub(protocol_fee_amount)
}

fn public_broadcaster_build_error(
    error: BuildError,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
    same_token_fee: bool,
) -> Report {
    match error {
        BuildError::InsufficientBalance(max_receiver_amount) => eyre!(
            "{PUBLIC_BROADCASTER_MAX_ENTERED_AMOUNT_ERROR}{}",
            public_broadcaster_max_entered_amount_for_tokens(
                max_receiver_amount,
                fee_amount,
                fee_mode,
                same_token_fee
            )
        ),
        BuildError::InsufficientFeeTokenBalance(max_spendable) => {
            eyre!("{PUBLIC_BROADCASTER_FEE_TOKEN_MAX_SPENDABLE_ERROR}{max_spendable}")
        }
        other => Report::new(other),
    }
}

struct PublicBroadcasterSetup {
    chain: EffectiveDesktopChainConfig,
    broadcaster: PublicBroadcasterCandidate,
    query_rpc_pool: Arc<QueryRpcPool>,
    min_gas_price: u128,
    prover: ProverService,
    forest: MerkleForest,
    utxos: Vec<Utxo>,
}

#[derive(Clone)]
struct EffectiveDesktopChainConfig {
    rpc_urls: Vec<Url>,
    railgun_contract: Address,
    relay_adapt_contract: Address,
    wrapped_native_token: Option<Address>,
    gas: settings::EffectiveChainGasSettings,
}

fn effective_desktop_chain_config(
    chain_id: u64,
    effective_chain: Option<&settings::EffectiveChainConfig>,
) -> Result<EffectiveDesktopChainConfig> {
    let defaults = chain_defaults_for_chain(chain_id)?;
    let Some(effective_chain) = effective_chain else {
        return Ok(EffectiveDesktopChainConfig {
            rpc_urls: defaults.rpc_urls,
            railgun_contract: defaults.contract,
            relay_adapt_contract: defaults.relay_adapt_contract,
            wrapped_native_token: wrapped_native_token_for_chain(chain_id),
            gas: settings::EffectiveChainGasSettings {
                gas_limit_buffer: GAS_LIMIT_BUFFER,
                gas_price_buffer_numerator: GAS_PRICE_BUFFER_NUMERATOR as u64,
                gas_price_buffer_denominator: GAS_PRICE_BUFFER_DENOMINATOR as u64,
            },
        });
    };
    if effective_chain.chain_id != chain_id {
        return Err(eyre!(
            "effective chain config is for chain {}, not {chain_id}",
            effective_chain.chain_id
        ));
    }
    let rpc_urls = parse_effective_rpc_urls(chain_id, &effective_chain.rpc_endpoints)?;
    let railgun_contract =
        parse_effective_address("railgun contract", &effective_chain.railgun_contract)?;
    let relay_adapt_contract = parse_effective_address(
        "relay adapt contract",
        &effective_chain.relay_adapt_contract,
    )?;
    let wrapped_native_token = effective_chain
        .wrapped_native_token
        .as_deref()
        .map(|value| parse_effective_address("wrapped native token", value))
        .transpose()?
        .or_else(|| wrapped_native_token_for_chain(chain_id));
    Ok(EffectiveDesktopChainConfig {
        rpc_urls,
        railgun_contract,
        relay_adapt_contract,
        wrapped_native_token,
        gas: effective_chain.gas.clone(),
    })
}

pub(crate) fn parse_effective_rpc_urls(
    chain_id: u64,
    rpc_endpoints: &[String],
) -> Result<Vec<Url>> {
    if rpc_endpoints.is_empty() {
        return Err(eyre!("effective chain {chain_id} has no RPC endpoints"));
    }
    rpc_endpoints
        .iter()
        .map(|url| Url::parse(url).wrap_err_with(|| format!("parse RPC URL {url}")))
        .collect()
}

pub(crate) fn effective_rpc_urls_for_chain(
    defaults: &ChainConfigDefaults,
    effective_chain: Option<&settings::EffectiveChainConfig>,
) -> Result<Vec<Url>> {
    effective_chain.map_or_else(
        || Ok(defaults.rpc_urls.clone()),
        |chain| parse_effective_rpc_urls(defaults.chain_id, &chain.rpc_endpoints),
    )
}

pub(crate) fn query_rpc_pool_with_http_client(
    rpc_urls: Vec<Url>,
    http: &HttpContext,
) -> Arc<QueryRpcPool> {
    Arc::new(QueryRpcPool::with_http_client(
        rpc_urls,
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ))
}

pub(crate) async fn buffered_gas_price_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    gas: &settings::EffectiveChainGasSettings,
) -> Result<u128> {
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match buffered_gas_price_with_policy(
            &provider_handle.provider,
            u128::from(gas.gas_price_buffer_numerator),
            u128::from(gas.gas_price_buffer_denominator),
        )
        .await
        {
            Ok(gas_price) => return Ok(gas_price),
            Err(error) => {
                tracing::warn!(%error, rpc = %provider_handle.url, "fetch gas price failed");
                query_rpc_pool.mark_bad_provider(&provider_handle);
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all query RPC gas price attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

fn is_effective_wrapped_native_token(
    chain_id: u64,
    token: Address,
    chain: &EffectiveDesktopChainConfig,
) -> bool {
    chain.wrapped_native_token.map_or_else(
        || is_wrapped_native_token(chain_id, token),
        |wrapped| wrapped == token,
    )
}

fn public_broadcaster_anchor_rate_for_policy(
    anchor_cache: Option<&Arc<TokenAnchorRateCache>>,
    chain_id: u64,
    token: Address,
) -> Option<U256> {
    anchor_cache
        .and_then(|cache| cache.cached_rate(chain_id, token))
        .or_else(|| fixed_token_anchor_rate(chain_id, token))
}

async fn public_broadcaster_setup(
    session: &WalletSession,
    chain_id: u64,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    token: Address,
    fee_rows: &[FeeRow],
    selection: &PublicBroadcasterSelection,
    require_relay_adapt: bool,
    policy: BroadcasterFeePolicy,
    anchor_cache: Option<&Arc<TokenAnchorRateCache>>,
    http: &HttpContext,
) -> Result<PublicBroadcasterSetup> {
    let chain = effective_desktop_chain_config(chain_id, effective_chain)?;
    let anchor_rate = public_broadcaster_anchor_rate_for_policy(anchor_cache, chain_id, token);
    let candidates = public_broadcaster_candidates(
        fee_rows,
        chain_id,
        token,
        if require_relay_adapt {
            Some(chain.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
        policy,
        anchor_rate,
    );
    let broadcaster = select_public_broadcaster_with_policy(&candidates, selection, policy)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls.clone(), http);
    let min_gas_price = buffered_gas_price_from_rpc_pool(&query_rpc_pool, &chain.gas).await?;
    let artifact_source = artifact_source(http);
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&session.db));
    let chain_handle = session
        .sync_manager
        .chain_handle(&session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {chain_id}"))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();
    let utxos = session.unspent_utxos().await;

    Ok(PublicBroadcasterSetup {
        chain,
        broadcaster,
        query_rpc_pool,
        min_gas_price,
        prover,
        forest,
        utxos,
    })
}

const fn approximate_public_broadcaster_gas(shape: ApproximateTransactionShape) -> u64 {
    let raw = APPROX_BASE_GAS
        + APPROX_GAS_PER_TRANSACTION * shape.transaction_count.saturating_sub(1) as u64
        + APPROX_GAS_PER_INPUT * shape.input_count as u64
        + APPROX_GAS_PER_PRIVATE_OUTPUT * shape.private_output_count as u64
        + APPROX_GAS_PER_PUBLIC_OUTPUT * shape.public_output_count as u64
        + if shape.send { APPROX_SEND_EXTRA_GAS } else { 0 }
        + if shape.unwrap {
            APPROX_UNWRAP_EXTRA_GAS
        } else {
            0
        }
        + APPROX_SAFETY_GAS;
    raw.saturating_mul(APPROX_GAS_UPLIFT_NUMERATOR)
        .saturating_add(APPROX_GAS_UPLIFT_DENOMINATOR - 1)
        / APPROX_GAS_UPLIFT_DENOMINATOR
}

const fn gas_shortfall_bps(predicted_gas_limit: u64, actual_gas_limit: u64) -> Option<u64> {
    if predicted_gas_limit == 0 || actual_gas_limit <= predicted_gas_limit {
        return None;
    }
    Some((actual_gas_limit - predicted_gas_limit) * 10_000 / predicted_gas_limit)
}

fn log_public_broadcaster_fee_prediction_failure(
    action: &'static str,
    attempt: usize,
    available_fee: U256,
    computed_fee: U256,
    gas_limit: u64,
    estimate: Option<&PublicBroadcasterCostEstimate>,
    plan_transaction_count: usize,
    plan_input_count: usize,
    plan_private_output_count: usize,
    plan_public_output_count: usize,
    broadcaster: &PublicBroadcasterCandidate,
) {
    let predicted_gas_limit = estimate.map(|estimate| estimate.gas_limit);
    let gas_shortfall = predicted_gas_limit.map(|predicted| gas_limit.saturating_sub(predicted));
    let gas_shortfall_bps =
        predicted_gas_limit.and_then(|predicted| gas_shortfall_bps(predicted, gas_limit));
    let estimated_transaction_count = estimate.map(|estimate| estimate.transaction_count);
    let estimated_input_count = estimate.map(|estimate| estimate.input_count);
    let estimated_private_output_count = estimate.map(|estimate| estimate.private_output_count);
    let estimated_public_output_count = estimate.map(|estimate| estimate.public_output_count);
    tracing::warn!(
        action,
        attempt,
        available_fee = %available_fee,
        computed_fee = %computed_fee,
        fee_shortfall = %computed_fee.saturating_sub(available_fee),
        gas_limit,
        ?predicted_gas_limit,
        ?gas_shortfall,
        ?gas_shortfall_bps,
        plan_transaction_count,
        plan_input_count,
        plan_private_output_count,
        plan_public_output_count,
        ?estimated_transaction_count,
        ?estimated_input_count,
        ?estimated_private_output_count,
        ?estimated_public_output_count,
        broadcaster = %broadcaster.railgun_address,
        fees_id = %broadcaster.fees_id,
        "public broadcaster fee prediction failed; retrying with buffered fee"
    );
}

fn approximate_public_broadcaster_cost(
    broadcaster: PublicBroadcasterCandidate,
    action_token: Address,
    fee_token: Address,
    entered_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
    protocol_fee_bps: U256,
    min_gas_price: u128,
    initial_fee_amount: U256,
    mut select_shape: impl FnMut(PublicBroadcasterAmountSplit) -> Result<ApproximateTransactionShape>,
) -> Result<PublicBroadcasterCostEstimate> {
    let service_gas_price = public_broadcaster_service_gas_price(min_gas_price);
    let mut fee_amount = initial_fee_amount;
    let mut latest_shape = None;
    let mut latest_split = None;
    let mut latest_gas_limit = 0;
    let same_token_fee = action_token == fee_token;

    for _ in 0..PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split_for_tokens(
            entered_amount,
            fee_amount,
            fee_mode,
            same_token_fee,
        )?;
        let shape = select_shape(split)?;
        let gas_limit = approximate_public_broadcaster_gas(shape);
        let computed_fee = broadcaster_fee_amount(broadcaster.fee, gas_limit, service_gas_price);
        latest_shape = Some(shape);
        latest_split = Some(split);
        latest_gas_limit = gas_limit;
        if broadcaster_fee_covers(fee_amount, computed_fee) {
            let protocol_fee_amount =
                railgun_protocol_fee_amount(split.receiver_amount, protocol_fee_bps);
            return Ok(PublicBroadcasterCostEstimate {
                broadcaster,
                action_token,
                fee_token,
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps,
                fee_mode: split.fee_mode,
                max_receiver_amount: shape.max_receiver_amount,
                max_entered_amount: public_broadcaster_max_entered_amount_for_tokens(
                    shape.max_receiver_amount,
                    fee_amount,
                    split.fee_mode,
                    same_token_fee,
                ),
                gas_limit,
                min_gas_price,
                native_gas_cost: public_broadcaster_native_gas_cost(gas_limit, min_gas_price),
                transaction_count: shape.transaction_count,
                input_count: shape.input_count,
                private_output_count: shape.private_output_count,
                public_output_count: shape.public_output_count,
            });
        }
        fee_amount = buffered_public_broadcaster_fee(computed_fee);
    }

    let shape = latest_shape.ok_or_else(|| eyre!("could not estimate public broadcaster cost"))?;
    let split = latest_split.ok_or_else(|| eyre!("could not estimate public broadcaster cost"))?;
    let protocol_fee_amount = railgun_protocol_fee_amount(split.receiver_amount, protocol_fee_bps);
    Ok(PublicBroadcasterCostEstimate {
        broadcaster,
        action_token,
        fee_token,
        entered_amount: split.entered_amount,
        receiver_amount: split.receiver_amount,
        recipient_amount: recipient_amount_after_protocol_fee(
            split.receiver_amount,
            protocol_fee_amount,
        ),
        total_private_spend: split.total_private_spend,
        fee_amount: split.fee_amount,
        protocol_fee_amount,
        protocol_fee_bps,
        fee_mode: split.fee_mode,
        max_receiver_amount: shape.max_receiver_amount,
        max_entered_amount: public_broadcaster_max_entered_amount_for_tokens(
            shape.max_receiver_amount,
            split.fee_amount,
            split.fee_mode,
            same_token_fee,
        ),
        gas_limit: latest_gas_limit,
        min_gas_price,
        native_gas_cost: public_broadcaster_native_gas_cost(latest_gas_limit, min_gas_price),
        transaction_count: shape.transaction_count,
        input_count: shape.input_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
    })
}

fn initial_separate_token_public_broadcaster_fee(
    broadcaster: &PublicBroadcasterCandidate,
    min_gas_price: u128,
    seed_shape: ApproximateTransactionShape,
) -> U256 {
    let service_gas_price = public_broadcaster_service_gas_price(min_gas_price);
    let gas_limit = approximate_public_broadcaster_gas(seed_shape);
    buffered_public_broadcaster_fee(broadcaster_fee_amount(
        broadcaster.fee,
        gas_limit,
        service_gas_price,
    ))
}

fn initial_public_broadcaster_fee_amount(
    broadcaster: &PublicBroadcasterCandidate,
    min_gas_price: u128,
    same_token_fee: bool,
    seed_shape: impl FnOnce() -> Result<ApproximateTransactionShape>,
) -> Result<U256> {
    if same_token_fee {
        Ok(U256::ZERO)
    } else {
        Ok(initial_separate_token_public_broadcaster_fee(
            broadcaster,
            min_gas_price,
            seed_shape()?,
        ))
    }
}

const fn send_approximate_shape(
    selection: &railgun_wallet::tx::UnshieldSelectionInfo,
    max_receiver_amount: U256,
) -> ApproximateTransactionShape {
    ApproximateTransactionShape {
        transaction_count: selection.transaction_count,
        input_count: selection.input_count,
        private_output_count: selection.private_output_count,
        public_output_count: 0,
        max_receiver_amount,
        unwrap: false,
        send: true,
    }
}

const fn unshield_approximate_shape(
    selection: &railgun_wallet::tx::UnshieldSelectionInfo,
    max_receiver_amount: U256,
    unwrap: bool,
) -> ApproximateTransactionShape {
    ApproximateTransactionShape {
        transaction_count: selection.transaction_count,
        input_count: selection.input_count,
        private_output_count: selection.private_output_count,
        public_output_count: selection.public_output_count,
        max_receiver_amount,
        unwrap,
        send: false,
    }
}

#[must_use]
pub fn transact_topic(chain_id: u64) -> String {
    ContentTopic::transact_topic(chain_id)
}

#[must_use]
pub fn transact_response_topic(chain_id: u64) -> String {
    ContentTopic::transact_response_topic(chain_id)
}

pub fn decode_public_broadcaster_response(
    shared_key: &[u8; 32],
    payload: &[u8],
) -> Result<Option<PublicBroadcasterResultKind>> {
    Ok(
        match DecryptedTransactResponse::try_decrypt_message(shared_key, payload)? {
            Some(DecryptedTransactResponse::TxHash(tx_hash)) => {
                Some(PublicBroadcasterResultKind::Submitted { tx_hash })
            }
            Some(DecryptedTransactResponse::Error(error)) => {
                Some(PublicBroadcasterResultKind::Failed { error })
            }
            None => None,
        },
    )
}

fn supported_broadcaster_version(version: &str) -> bool {
    version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        == Some(8)
}

pub struct WalletSessionStore {
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
}

impl WalletSessionStore {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        let db = Arc::new(DbStore::open(DbConfig { root_dir: db_path }).wrap_err("open local db")?);
        Ok(Self::from_db(db))
    }

    #[must_use]
    pub fn from_db(db: Arc<DbStore>) -> Self {
        let sync_manager = Arc::new(SyncManager::new(Arc::clone(&db)));

        Self { db, sync_manager }
    }

    pub async fn start_view_wallet_session(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
    ) -> Result<WalletSession> {
        self.start_view_wallet_session_with_wait(request, rpc_url_override, http, true)
            .await
    }

    pub async fn start_view_wallet_session_immediate(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
    ) -> Result<WalletSession> {
        self.start_view_wallet_session_with_wait(request, rpc_url_override, http, false)
            .await
    }

    async fn start_view_wallet_session_with_wait(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
        wait_until_ready: bool,
    ) -> Result<WalletSession> {
        let chain_id = request.chain_id;
        let synced = setup_synced_view_wallet_with_store(
            request.view_session,
            chain_id,
            request.sync_start_policy,
            request.init_block_number,
            request.sync_to_block,
            request.use_indexed_wallet_catch_up,
            request.effective_chain.clone(),
            request.poi_read_source.clone(),
            request.local_poi_caches.clone(),
            request.rewind_wallet_cache,
            rpc_url_override,
            http,
            request.progress_tx.clone(),
            wait_until_ready,
            Arc::clone(&self.db),
            Arc::clone(&self.sync_manager),
        )
        .await?;

        wallet_session_from_view_synced(chain_id, synced).await
    }

    pub async fn shutdown(&self) {
        self.sync_manager.shutdown().await;
    }
}

async fn wallet_session_from_view_synced(
    chain_id: u64,
    synced: SyncedViewWallet,
) -> Result<WalletSession> {
    wallet_session_from_parts(
        chain_id,
        synced.db,
        synced.sync_manager,
        synced.chain_key,
        synced.start_block,
        synced.handle,
    )
    .await
}

async fn wallet_session_from_parts(
    chain_id: u64,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    start_block: u64,
    handle: WalletHandle,
) -> Result<WalletSession> {
    let mut rev_rx = handle.rev_rx.clone();
    let initial_snapshot = Arc::new(snapshot_from_handle(chain_id, &handle).await);
    let (snapshots_tx, snapshots_rx) = watch::channel(initial_snapshot);
    let cache_key = handle.cache_key.clone();
    let ready_rx = handle.ready_rx.clone();
    let poi_refreshing_rx = handle.poi_refreshing_rx.clone();
    let snapshot_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            if rev_rx.changed().await.is_err() {
                break;
            }
            let snapshot = Arc::new(snapshot_from_handle(chain_id, &snapshot_handle).await);
            if snapshots_tx.send(snapshot).is_err() {
                break;
            }
        }
    });

    Ok(WalletSession {
        chain_id,
        cache_key,
        start_block,
        ready_rx,
        snapshots_rx,
        poi_refreshing_rx,
        db,
        sync_manager,
        chain_key,
        handle,
    })
}

async fn prepare_desktop_unshield_plan_without_broadcaster_fee(
    request: DesktopUnshieldPlanRequest<'_>,
    http: &HttpContext,
) -> Result<PreparedPrivatePlan<UnshieldPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain)?;
    if request.unwrap && !is_effective_wrapped_native_token(request.chain_id, request.token, &chain)
    {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let artifact_source = artifact_source(http);
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session.db));
    let chain_handle = request
        .session
        .sync_manager
        .chain_handle(&request.session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let utxos = request.session.unspent_utxos().await;
    let mode = if request.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };
    let unshield_request = RailgunUnshieldRequest {
        token_address: request.token,
        amount: request.amount,
        recipient: request.recipient,
        mode,
        verify_proof: request.verify_proof,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };
    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = unshield_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select POI-verified unshield notes")?;

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password)
        .wrap_err("authorize unshield spend")?;
    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load unshield spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::ProvingTransaction,
    );
    let plan = tx_builder
        .build_unshield_plan_with_signer(
            &request.view_session.scan_keys(),
            &signer,
            &forest,
            &utxos,
            unshield_request,
            &prover,
        )
        .await
        .wrap_err("build desktop unshield calldata")?;

    Ok(PreparedPrivatePlan {
        plan,
        max_spendable: selection_info.max_spendable,
        prover,
    })
}

async fn prepare_desktop_send_plan_without_broadcaster_fee(
    request: DesktopSendPlanRequest<'_>,
    http: &HttpContext,
) -> Result<PreparedPrivatePlan<SendPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }

    let recipient = request.recipient.trim();
    let recipient_data = parse_railgun_recipient(recipient)?;
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain)?;
    let artifact_source = artifact_source(http);
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session.db));
    let chain_handle = request
        .session
        .sync_manager
        .chain_handle(&request.session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let utxos = request.session.unspent_utxos().await;
    let send_request = RailgunSendRequest {
        token_address: request.token,
        amount: request.amount,
        recipient: recipient_data,
        verify_proof: request.verify_proof,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };
    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = send_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select POI-verified send notes")?;

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password)
        .wrap_err("authorize send spend")?;
    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load send spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::ProvingTransaction,
    );
    let plan = tx_builder
        .build_send_plan_with_signer(
            &request.view_session.scan_keys(),
            &signer,
            &forest,
            &utxos,
            send_request,
            &prover,
        )
        .await
        .wrap_err("build desktop send calldata")?;

    Ok(PreparedPrivatePlan {
        plan,
        max_spendable: selection_info.max_spendable,
        prover,
    })
}

async fn persist_manual_unshield_pending_pois(
    plan: &UnshieldPlan,
    session: &WalletSession,
    chain_id: u64,
    wallet_id: &str,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    operation_label: &'static str,
) -> Result<()> {
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        session,
        chain_id,
        prover,
        verify_proof,
        http,
        operation_label,
    )
    .await?;
    persist_pending_unshield_output_poi_contexts(
        session.db.as_ref(),
        chain_id,
        wallet_id,
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
        false,
    )?;
    Ok(())
}

async fn persist_manual_send_pending_pois(
    plan: &SendPlan,
    session: &WalletSession,
    chain_id: u64,
    wallet_id: &str,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    operation_label: &'static str,
) -> Result<()> {
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        session,
        chain_id,
        prover,
        verify_proof,
        http,
        operation_label,
    )
    .await?;
    persist_pending_send_output_poi_contexts(
        session.db.as_ref(),
        chain_id,
        wallet_id,
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
        false,
    )?;
    Ok(())
}

fn prepared_unshield_call_from_plan(
    chain_id: u64,
    token: Address,
    amount: U256,
    recipient: Address,
    unwrap: bool,
    max_spendable: U256,
    plan: &UnshieldPlan,
) -> PreparedUnshieldCall {
    PreparedUnshieldCall {
        chain_id,
        token,
        amount,
        recipient,
        unwrap,
        max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: hex::encode_prefixed(&plan.call.data),
    }
}

fn prepared_send_call_from_plan(
    chain_id: u64,
    token: Address,
    amount: U256,
    recipient: String,
    max_spendable: U256,
    plan: &SendPlan,
) -> PreparedSendCall {
    PreparedSendCall {
        chain_id,
        token,
        amount,
        recipient,
        max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: hex::encode_prefixed(&plan.call.data),
    }
}

pub async fn prepare_desktop_unshield_calldata(
    request: DesktopUnshieldCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedUnshieldCall> {
    let prepared = prepare_desktop_unshield_plan_without_broadcaster_fee(
        DesktopUnshieldPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            vault_password: request.vault_password.as_str(),
            token: request.token,
            amount: request.amount,
            recipient: request.recipient,
            unwrap: request.unwrap,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_unshield_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate manual unshield pending output pre-transaction POI",
    )
    .await?;

    Ok(prepared_unshield_call_from_plan(
        request.chain_id,
        request.token,
        request.amount,
        request.recipient,
        request.unwrap,
        prepared.max_spendable,
        &prepared.plan,
    ))
}

pub async fn prepare_desktop_send_calldata(
    request: DesktopSendCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedSendCall> {
    let recipient = request.recipient.trim().to_string();
    let prepared = prepare_desktop_send_plan_without_broadcaster_fee(
        DesktopSendPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            vault_password: request.vault_password.as_str(),
            token: request.token,
            amount: request.amount,
            recipient: &recipient,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_send_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate manual send pending output pre-transaction POI",
    )
    .await?;

    Ok(prepared_send_call_from_plan(
        request.chain_id,
        request.token,
        request.amount,
        recipient,
        prepared.max_spendable,
        &prepared.plan,
    ))
}

pub async fn estimate_desktop_unshield_public_broadcaster_cost(
    request: DesktopUnshieldPublicBroadcasterEstimateRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterCostEstimate> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    if request.unwrap && !is_effective_wrapped_native_token(request.chain_id, request.token, &chain)
    {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let policy = request.fee_policy;
    let anchor_rate = public_broadcaster_anchor_rate_for_policy(
        request.anchor_cache.as_ref(),
        request.chain_id,
        request.fee_token,
    );
    let candidates = public_broadcaster_candidates(
        &request.fee_rows,
        request.chain_id,
        request.fee_token,
        if request.unwrap {
            Some(chain.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
        policy,
        anchor_rate,
    );
    let broadcaster =
        select_public_broadcaster_with_policy(&candidates, &request.selection, policy)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls.clone(), http);
    let min_gas_price = buffered_gas_price_from_rpc_pool(&query_rpc_pool, &chain.gas).await?;
    let utxos = request.session.unspent_utxos().await;
    let same_token_fee = request.fee_token == request.token;
    let initial_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let selection = unshield_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                request.amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    PublicBroadcasterFeeMode::AddToAmount,
                    same_token_fee,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        })?;

    approximate_public_broadcaster_cost(
        broadcaster,
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        initial_fee_amount,
        |split| {
            let selection = unshield_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        },
    )
}

pub async fn estimate_desktop_send_public_broadcaster_cost(
    request: DesktopSendPublicBroadcasterEstimateRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterCostEstimate> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    parse_railgun_recipient(&request.recipient)?;

    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    let policy = request.fee_policy;
    let anchor_rate = public_broadcaster_anchor_rate_for_policy(
        request.anchor_cache.as_ref(),
        request.chain_id,
        request.fee_token,
    );
    let candidates = public_broadcaster_candidates(
        &request.fee_rows,
        request.chain_id,
        request.fee_token,
        None,
        SystemTime::now(),
        policy,
        anchor_rate,
    );
    let broadcaster =
        select_public_broadcaster_with_policy(&candidates, &request.selection, policy)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls.clone(), http);
    let min_gas_price = buffered_gas_price_from_rpc_pool(&query_rpc_pool, &chain.gas).await?;
    let utxos = request.session.unspent_utxos().await;
    let same_token_fee = request.fee_token == request.token;
    let initial_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let selection = send_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                request.amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    PublicBroadcasterFeeMode::AddToAmount,
                    same_token_fee,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        })?;

    approximate_public_broadcaster_cost(
        broadcaster,
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        U256::ZERO,
        min_gas_price,
        initial_fee_amount,
        |split| {
            let selection = send_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        },
    )
}

pub async fn submit_desktop_unshield_public_broadcaster(
    request: DesktopUnshieldPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterSubmissionResult> {
    let waku = Arc::clone(&request.waku);
    let timeout = request.response_timeout;
    let republish_interval = request.republish_interval;
    let progress_tx = request.progress_tx.clone();
    let session = Arc::clone(&request.session);
    let prepared = prepare_desktop_unshield_public_broadcaster(request, http).await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    let result = submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
        prepared.action_token,
        prepared.fee_token,
        prepared.entered_amount,
        prepared.receiver_amount,
        prepared.recipient_amount,
        prepared.total_private_spend,
        prepared.fee_amount,
        prepared.protocol_fee_amount,
        prepared.protocol_fee_bps,
        prepared.fee_mode,
        prepared.gas_limit,
        prepared.min_gas_price,
        progress_tx,
        timeout,
        republish_interval,
    )
    .await?;
    mark_submitted_inputs_pending_spent(&session, &pending_spent_inputs, &result).await;
    Ok(result)
}

pub async fn submit_desktop_send_public_broadcaster(
    request: DesktopSendPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterSubmissionResult> {
    let waku = Arc::clone(&request.waku);
    let timeout = request.response_timeout;
    let republish_interval = request.republish_interval;
    let progress_tx = request.progress_tx.clone();
    let session = Arc::clone(&request.session);
    let prepared = prepare_desktop_send_public_broadcaster(request, http).await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    let result = submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
        prepared.action_token,
        prepared.fee_token,
        prepared.entered_amount,
        prepared.receiver_amount,
        prepared.recipient_amount,
        prepared.total_private_spend,
        prepared.fee_amount,
        prepared.protocol_fee_amount,
        prepared.protocol_fee_bps,
        prepared.fee_mode,
        prepared.gas_limit,
        prepared.min_gas_price,
        progress_tx,
        timeout,
        republish_interval,
    )
    .await?;
    mark_submitted_inputs_pending_spent(&session, &pending_spent_inputs, &result).await;
    Ok(result)
}

pub async fn submit_desktop_unshield_self_broadcast(
    request: DesktopUnshieldSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let prepared = prepare_desktop_unshield_plan_without_broadcaster_fee(
        DesktopUnshieldPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            vault_password: request.vault_password.as_str(),
            token: request.token,
            amount: request.amount,
            recipient: request.recipient,
            unwrap: request.unwrap,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_unshield_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate self-broadcast unshield pending output pre-transaction POI",
    )
    .await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    submit_self_broadcast_plan(
        request.chain_id,
        request.effective_chain.as_ref(),
        request.view_session.as_ref(),
        request.vault_store.as_ref(),
        request.vault_password.as_str(),
        request.public_account_uuid,
        Arc::clone(&request.session),
        prepared.plan.call.to,
        prepared.plan.call.data,
        pending_spent_inputs,
        request.gas_fee,
        request.progress_tx,
        request.command_rx,
        request.event_tx,
        http,
    )
    .await
}

pub async fn submit_desktop_send_self_broadcast(
    request: DesktopSendSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let recipient = request.recipient.trim().to_string();
    let prepared = prepare_desktop_send_plan_without_broadcaster_fee(
        DesktopSendPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            vault_password: request.vault_password.as_str(),
            token: request.token,
            amount: request.amount,
            recipient: &recipient,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_send_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate self-broadcast send pending output pre-transaction POI",
    )
    .await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    submit_self_broadcast_plan(
        request.chain_id,
        request.effective_chain.as_ref(),
        request.view_session.as_ref(),
        request.vault_store.as_ref(),
        request.vault_password.as_str(),
        request.public_account_uuid,
        Arc::clone(&request.session),
        prepared.plan.call.to,
        prepared.plan.call.data,
        pending_spent_inputs,
        request.gas_fee,
        request.progress_tx,
        request.command_rx,
        request.event_tx,
        http,
    )
    .await
}

async fn submit_self_broadcast_plan(
    chain_id: u64,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    view_session: &vault::DesktopViewSession,
    vault_store: &vault::DesktopVaultStore,
    vault_password: &str,
    public_account_uuid: String,
    session: Arc<WalletSession>,
    to: Address,
    data: Bytes,
    pending_spent_inputs: Vec<Utxo>,
    gas_fee: SelfBroadcastGasFeeSelection,
    progress_tx: Option<TransactionGenerationProgressSender>,
    mut command_rx: Option<SelfBroadcastCommandReceiver>,
    event_tx: Option<SelfBroadcastSessionEventSender>,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let chain = effective_desktop_chain_config(chain_id, effective_chain)?;
    let gas_payer = self_broadcast_gas_payer(vault_store, view_session, &public_account_uuid)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    let signer = vaulted_public_signer(
        vault_store,
        view_session,
        vault_password,
        &public_account_uuid,
    )?;
    if signer.address() != gas_payer {
        return Err(eyre!(
            "selected public account signer address does not match account metadata"
        ));
    }
    let wallet = signer.ethereum_wallet();
    let mut next_gas_fee = gas_fee;
    let mut submitted_attempts = Vec::new();
    let mut nonce = None;

    loop {
        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingSelfBroadcastGas,
        );
        let preflight = match self_broadcast_preflight_from_rpc_pool(
            &query_rpc_pool,
            chain_id,
            gas_payer,
            to,
            data.clone(),
            next_gas_fee,
            &chain.gas,
            nonce,
            http.network_mode(),
        )
        .await
        {
            Ok(preflight) => preflight,
            Err(error) => {
                let message = report_chain_string(&error);
                emit_self_broadcast_event(
                    event_tx.as_ref(),
                    SelfBroadcastSessionEvent::StepFailed {
                        stage: TransactionGenerationStage::EstimatingSelfBroadcastGas,
                        message,
                    },
                );
                let Some(command) = recv_self_broadcast_command(&mut command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        nonce = Some(preflight.nonce);

        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::SigningSelfBroadcast,
        );
        let attempt = match submit_self_broadcast_attempt(
            preflight,
            &query_rpc_pool,
            http.network_mode(),
            &wallet,
            &session,
            &pending_spent_inputs,
            event_tx.as_ref(),
        )
        .await
        {
            Ok(attempt) => attempt,
            Err(error) => {
                let message = report_chain_string(&error);
                emit_self_broadcast_event(
                    event_tx.as_ref(),
                    SelfBroadcastSessionEvent::StepFailed {
                        stage: TransactionGenerationStage::SigningSelfBroadcast,
                        message,
                    },
                );
                let Some(command) = recv_self_broadcast_command(&mut command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        submitted_attempts.push(attempt);
        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        );

        loop {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(3)) => {
                    if let Some((winner_index, receipt)) = poll_self_broadcast_attempt_receipts(&submitted_attempts).await? {
                        let winner = &submitted_attempts[winner_index];
                        session
                            .mark_pending_spent_utxos(
                                &pending_spent_inputs,
                                parse_submitted_tx_hash(&receipt.tx_hash),
                            )
                            .await;
                        return Ok(DesktopSelfBroadcastResult {
                            chain_id,
                            public_account_uuid,
                            gas_payer,
                            gas_limit: winner.info.gas_limit,
                            rpc_gas_price: winner.rpc_gas_price,
                            max_fee_per_gas: winner.info.max_fee_per_gas,
                            max_priority_fee_per_gas: winner.info.max_priority_fee_per_gas,
                            estimated_native_gas_cost: winner.estimated_native_gas_cost,
                            live_native_balance: winner.live_native_balance,
                            tx: receipt,
                            attempts: submitted_attempts
                                .iter()
                                .map(|attempt| attempt.info.clone())
                                .collect(),
                        });
                    }
                }
                command = recv_self_broadcast_command(&mut command_rx) => {
                    let Some(command) = command else {
                        continue;
                    };
                    let Some(nonce) = nonce else {
                        next_gas_fee = command.gas_fee;
                        break;
                    };
                    let gas_limit = submitted_attempts
                        .last()
                        .map_or(0, |attempt| attempt.info.gas_limit);
                    let replacement = match self_broadcast_replacement_preflight_from_rpc_pool(
                        &query_rpc_pool,
                        chain_id,
                        gas_payer,
                        to,
                        data.clone(),
                        command.gas_fee,
                        gas_limit,
                        nonce,
                    )
                    .await
                    {
                        Ok(preflight) => preflight,
                        Err(error) => {
                            emit_self_broadcast_event(
                                event_tx.as_ref(),
                                SelfBroadcastSessionEvent::AttemptRejected {
                                    stage: TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
                                    message: report_chain_string(&error),
                                },
                            );
                            continue;
                        }
                    };
                    update_transaction_generation_stage(
                        progress_tx.as_ref(),
                        TransactionGenerationStage::SigningSelfBroadcast,
                    );
                    match submit_self_broadcast_attempt(
                        replacement,
                        &query_rpc_pool,
                        http.network_mode(),
                        &wallet,
                        &session,
                        &pending_spent_inputs,
                        event_tx.as_ref(),
                    )
                    .await
                    {
                        Ok(attempt) => submitted_attempts.push(attempt),
                        Err(error) => emit_self_broadcast_event(
                            event_tx.as_ref(),
                            SelfBroadcastSessionEvent::AttemptRejected {
                                stage: TransactionGenerationStage::SigningSelfBroadcast,
                                message: report_chain_string(&error),
                            },
                        ),
                    }
                    update_transaction_generation_stage(
                        progress_tx.as_ref(),
                        TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
                    );
                }
            }
        }
    }
}

fn emit_self_broadcast_event(
    event_tx: Option<&SelfBroadcastSessionEventSender>,
    event: SelfBroadcastSessionEvent,
) {
    if let Some(event_tx) = event_tx {
        let _ = event_tx.send(event);
    }
}

fn report_chain_string(error: &Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

async fn recv_self_broadcast_command(
    command_rx: &mut Option<SelfBroadcastCommandReceiver>,
) -> Option<SelfBroadcastCommand> {
    let command_rx = command_rx.as_mut()?;
    command_rx.recv().await
}

async fn submit_self_broadcast_attempt(
    preflight: SelfBroadcastPreflight,
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    wallet: &EthereumWallet,
    session: &WalletSession,
    pending_spent_inputs: &[Utxo],
    event_tx: Option<&SelfBroadcastSessionEventSender>,
) -> Result<SubmittedSelfBroadcastAttempt> {
    let sent = sign_send_self_broadcast_transaction(
        query_rpc_pool,
        network_mode,
        wallet,
        preflight.tx_req,
        session,
        pending_spent_inputs,
    )
    .await?;
    let info = SelfBroadcastAttemptInfo {
        tx_hash: sent.tx_hash_string,
        nonce: preflight.nonce,
        gas_limit: preflight.gas_limit,
        max_fee_per_gas: preflight.max_fee_per_gas,
        max_priority_fee_per_gas: preflight.max_priority_fee_per_gas,
    };
    emit_self_broadcast_event(
        event_tx,
        SelfBroadcastSessionEvent::AttemptSubmitted(info.clone()),
    );
    Ok(SubmittedSelfBroadcastAttempt {
        provider_handles: sent.provider_handles,
        tx_hash: sent.tx_hash,
        info,
        rpc_gas_price: preflight.rpc_gas_price,
        estimated_native_gas_cost: preflight.estimated_native_gas_cost,
        live_native_balance: preflight.live_native_balance,
    })
}

async fn poll_self_broadcast_attempt_receipts(
    attempts: &[SubmittedSelfBroadcastAttempt],
) -> Result<Option<(usize, TxReceiptOutput)>> {
    for (index, attempt) in attempts.iter().enumerate() {
        for provider_handle in &attempt.provider_handles {
            match provider_handle
                .provider
                .get_transaction_receipt(attempt.tx_hash)
                .await
            {
                Ok(Some(receipt)) => {
                    return Ok(Some((index, tx_receipt_output(attempt.tx_hash, &receipt))));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        url = %provider_handle.url,
                        %error,
                        "self-broadcast receipt fetch failed"
                    );
                }
            }
        }
    }
    Ok(None)
}

async fn self_broadcast_replacement_preflight_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas_limit: u64,
    nonce: u64,
) -> Result<SelfBroadcastPreflight> {
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match self_broadcast_replacement_preflight(
            provider_handle,
            chain_id,
            from,
            to,
            data.clone(),
            gas_fee,
            gas_limit,
            nonce,
        )
        .await
        {
            Ok(preflight) => return Ok(preflight),
            Err(error) if is_self_broadcast_insufficient_native_gas_error(&error) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(%error, "self-broadcast replacement preflight failed");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all self-broadcast replacement RPC attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

async fn self_broadcast_replacement_preflight(
    provider_handle: ProviderHandle,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas_limit: u64,
    nonce: u64,
) -> Result<SelfBroadcastPreflight> {
    let provider = &provider_handle.provider;
    let quote = self_broadcast_gas_fee_quote(provider)
        .await
        .wrap_err("fetch self-broadcast gas price")?;
    let SelfBroadcastResolvedGasFee {
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    } = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    let estimated_native_gas_cost = self_broadcast_native_gas_cost(gas_limit, max_fee_per_gas);
    let live_native_balance = provider
        .get_balance(from)
        .await
        .wrap_err("fetch self-broadcast native balance")?;
    if live_native_balance < estimated_native_gas_cost {
        return Err(self_broadcast_insufficient_native_gas_error(
            live_native_balance,
            estimated_native_gas_cost,
        ));
    }
    Ok(SelfBroadcastPreflight {
        tx_req: self_broadcast_transaction_request(
            chain_id,
            from,
            to,
            data,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            nonce,
        )
        .with_gas_limit(gas_limit),
        nonce,
        gas_limit,
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        estimated_native_gas_cost,
        live_native_balance,
    })
}

fn self_broadcast_gas_payer(
    vault_store: &vault::DesktopVaultStore,
    view_session: &vault::DesktopViewSession,
    public_account_uuid: &str,
) -> Result<Address> {
    vault_store
        .list_active_public_accounts_for_session(view_session)
        .wrap_err("load active public accounts")?
        .into_iter()
        .find(|account| account.public_account_uuid == public_account_uuid)
        .map(|account| account.address)
        .ok_or_else(|| eyre!("selected gas payer is not an active Public account"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelfBroadcastResolvedGasFee {
    rpc_gas_price: u128,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, Copy)]
struct SelfBroadcastFeeQuoteTimeoutPolicy {
    grace_after_first_usable: Duration,
    hard_deadline: Duration,
}

impl SelfBroadcastFeeQuoteTimeoutPolicy {
    const fn for_network_mode(network_mode: WalletNetworkMode) -> Self {
        match network_mode {
            WalletNetworkMode::Tor => Self {
                grace_after_first_usable: SELF_BROADCAST_TOR_FEE_QUOTE_GRACE,
                hard_deadline: SELF_BROADCAST_TOR_FEE_QUOTE_DEADLINE,
            },
            WalletNetworkMode::Proxy | WalletNetworkMode::Direct => Self {
                grace_after_first_usable: SELF_BROADCAST_DIRECT_FEE_QUOTE_GRACE,
                hard_deadline: SELF_BROADCAST_DIRECT_FEE_QUOTE_DEADLINE,
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SelfBroadcastFeeSample {
    rpc_gas_price: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
    next_base_fee_per_gas: Option<u128>,
    priority_fee_rewards: Vec<u128>,
}

impl SelfBroadcastFeeSample {
    fn from_parts(
        rpc_gas_price: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
        fee_history: Option<FeeHistory>,
    ) -> Self {
        let Some(fee_history) = fee_history else {
            return Self {
                rpc_gas_price,
                max_priority_fee_per_gas,
                next_base_fee_per_gas: None,
                priority_fee_rewards: Vec::new(),
            };
        };
        let next_base_fee_per_gas = fee_history.base_fee_per_gas.last().copied();
        let priority_fee_rewards = fee_history
            .reward
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect();
        Self {
            rpc_gas_price,
            max_priority_fee_per_gas,
            next_base_fee_per_gas,
            priority_fee_rewards,
        }
    }

    fn has_non_zero_fee_history_tip(&self) -> bool {
        self.priority_fee_rewards.iter().any(|value| *value > 0)
    }

    const fn has_non_zero_priority_tip(&self) -> bool {
        matches!(self.max_priority_fee_per_gas, Some(value) if value > 0)
    }

    fn has_usable_tip(&self) -> bool {
        self.has_non_zero_fee_history_tip() || self.has_non_zero_priority_tip()
    }
}

async fn self_broadcast_parallel_fee_samples(
    providers: Vec<ProviderHandle>,
    policy: SelfBroadcastFeeQuoteTimeoutPolicy,
) -> Vec<SelfBroadcastFeeSample> {
    let started_at = Instant::now();
    let mut join_set = JoinSet::new();
    for provider_handle in providers {
        join_set.spawn(self_broadcast_provider_fee_sample(
            provider_handle,
            policy.hard_deadline,
        ));
    }

    let mut samples = Vec::new();
    let mut grace_deadline = None;
    while !join_set.is_empty() {
        let now = Instant::now();
        let Some(hard_remaining) = policy
            .hard_deadline
            .checked_sub(now.saturating_duration_since(started_at))
        else {
            break;
        };
        let wait_for = grace_deadline.map_or(hard_remaining, |deadline: Instant| {
            deadline.saturating_duration_since(now).min(hard_remaining)
        });
        if wait_for.is_zero() {
            break;
        }
        match tokio::time::timeout(wait_for, join_set.join_next()).await {
            Ok(Some(Ok(sample))) => {
                let usable_tip = sample.has_usable_tip();
                samples.push(sample);
                if usable_tip && grace_deadline.is_none() {
                    grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                }
                let non_zero_fee_history_sources = samples
                    .iter()
                    .filter(|sample| sample.has_non_zero_fee_history_tip())
                    .count();
                if non_zero_fee_history_sources >= 2 {
                    break;
                }
            }
            Ok(Some(Err(error))) => {
                tracing::warn!(%error, "self-broadcast gas fee quote task failed");
            }
            Ok(None) | Err(_) => break,
        }
    }
    join_set.abort_all();
    samples
}

async fn self_broadcast_provider_fee_sample(
    provider_handle: ProviderHandle,
    timeout: Duration,
) -> SelfBroadcastFeeSample {
    let provider = provider_handle.provider;
    let gas_price = tokio::time::timeout(timeout, provider.get_gas_price());
    let max_priority_fee = tokio::time::timeout(timeout, provider.get_max_priority_fee_per_gas());
    let fee_history = tokio::time::timeout(
        timeout,
        provider.get_fee_history(
            SELF_BROADCAST_FEE_HISTORY_BLOCKS,
            BlockNumberOrTag::Latest,
            &SELF_BROADCAST_FEE_HISTORY_REWARD_PERCENTILES,
        ),
    );
    let (gas_price, max_priority_fee, fee_history) =
        tokio::join!(gas_price, max_priority_fee, fee_history);
    let rpc_gas_price = match gas_price {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::warn!(url = %provider_handle.url, %error, "self-broadcast eth_gasPrice failed");
            None
        }
        Err(_) => {
            tracing::warn!(url = %provider_handle.url, "self-broadcast eth_gasPrice timed out");
            None
        }
    };
    let max_priority_fee_per_gas = match max_priority_fee {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::debug!(url = %provider_handle.url, %error, "self-broadcast eth_maxPriorityFeePerGas failed");
            None
        }
        Err(_) => {
            tracing::debug!(url = %provider_handle.url, "self-broadcast eth_maxPriorityFeePerGas timed out");
            None
        }
    };
    let fee_history = match fee_history {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::debug!(url = %provider_handle.url, %error, "self-broadcast eth_feeHistory failed");
            None
        }
        Err(_) => {
            tracing::debug!(url = %provider_handle.url, "self-broadcast eth_feeHistory timed out");
            None
        }
    };
    SelfBroadcastFeeSample::from_parts(rpc_gas_price, max_priority_fee_per_gas, fee_history)
}

fn self_broadcast_quote_from_fee_samples(
    samples: &[SelfBroadcastFeeSample],
) -> Option<SelfBroadcastGasFeeQuote> {
    self_broadcast_quote_from_fee_samples_with_tip_fallback(
        samples,
        SelfBroadcastTipFallback::Minimum,
    )
}

fn self_broadcast_quote_from_fee_samples_with_tip_fallback(
    samples: &[SelfBroadcastFeeSample],
    tip_fallback: SelfBroadcastTipFallback,
) -> Option<SelfBroadcastGasFeeQuote> {
    if samples.is_empty() {
        return None;
    }
    let mut gas_prices = non_zero_values(samples.iter().filter_map(|sample| sample.rpc_gas_price));
    let mut fee_history_rewards = non_zero_values(
        samples
            .iter()
            .flat_map(|sample| sample.priority_fee_rewards.iter().copied()),
    );
    let mut priority_fee_suggestions = non_zero_values(
        samples
            .iter()
            .filter_map(|sample| sample.max_priority_fee_per_gas),
    );
    let mut next_base_fees = non_zero_values(
        samples
            .iter()
            .filter_map(|sample| sample.next_base_fee_per_gas),
    );

    let rpc_gas_price = upper_quartile(&mut gas_prices);
    let fallback_tip = match tip_fallback {
        SelfBroadcastTipFallback::Minimum => SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS,
        SelfBroadcastTipFallback::RpcGasPrice => rpc_gas_price
            .unwrap_or(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS)
            .max(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS),
    };
    let selected_tip = upper_quartile(&mut fee_history_rewards)
        .or_else(|| upper_quartile(&mut priority_fee_suggestions))
        .unwrap_or(fallback_tip)
        .max(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS);
    let gas_price_max_fee = rpc_gas_price.map_or(0, self_broadcast_auto_max_fee_per_gas);
    let fee_history_max_fee = upper_quartile(&mut next_base_fees).map_or(0, |base_fee| {
        self_broadcast_auto_max_fee_per_gas(base_fee).saturating_add(selected_tip)
    });
    let suggested_max_fee_per_gas = gas_price_max_fee.max(fee_history_max_fee).max(selected_tip);
    Some(SelfBroadcastGasFeeQuote {
        rpc_gas_price: rpc_gas_price.unwrap_or(suggested_max_fee_per_gas),
        suggested_max_fee_per_gas,
        suggested_max_priority_fee_per_gas: selected_tip.min(suggested_max_fee_per_gas),
    })
}

fn non_zero_values(values: impl IntoIterator<Item = u128>) -> Vec<u128> {
    values.into_iter().filter(|value| *value > 0).collect()
}

fn upper_quartile(values: &mut [u128]) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let index = values.len().saturating_mul(3).saturating_sub(1) / 4;
    values.get(index).copied()
}

async fn self_broadcast_gas_fee_quote_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
) -> Result<SelfBroadcastGasFeeQuote> {
    self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback(
        query_rpc_pool,
        network_mode,
        SelfBroadcastTipFallback::Minimum,
    )
    .await
}

async fn self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    tip_fallback: SelfBroadcastTipFallback,
) -> Result<SelfBroadcastGasFeeQuote> {
    let providers = query_rpc_pool.available_providers();
    if providers.is_empty() {
        return Err(eyre!("no healthy query RPC available"));
    }
    let policy = SelfBroadcastFeeQuoteTimeoutPolicy::for_network_mode(network_mode);
    let samples = self_broadcast_parallel_fee_samples(providers, policy).await;
    if let Some(quote) =
        self_broadcast_quote_from_fee_samples_with_tip_fallback(&samples, tip_fallback)
    {
        return Ok(quote);
    }

    Err(eyre!("all self-broadcast gas quote RPC attempts failed"))
}

async fn self_broadcast_gas_fee_quote(
    provider: &impl Provider,
) -> Result<SelfBroadcastGasFeeQuote> {
    let rpc_gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")?;
    let max_priority_fee_per_gas = provider.get_max_priority_fee_per_gas().await.ok();
    let fee_history = provider
        .get_fee_history(
            SELF_BROADCAST_FEE_HISTORY_BLOCKS,
            BlockNumberOrTag::Latest,
            &SELF_BROADCAST_FEE_HISTORY_REWARD_PERCENTILES,
        )
        .await
        .ok();
    let sample = SelfBroadcastFeeSample::from_parts(
        Some(rpc_gas_price),
        max_priority_fee_per_gas,
        fee_history,
    );
    self_broadcast_quote_from_fee_samples(&[sample])
        .ok_or_else(|| eyre!("self-broadcast gas fee quote returned no usable values"))
}

fn resolve_self_broadcast_gas_fee(
    selection: SelfBroadcastGasFeeSelection,
    quote: SelfBroadcastGasFeeQuote,
) -> Result<SelfBroadcastResolvedGasFee> {
    let (max_fee_per_gas, max_priority_fee_per_gas) = match selection {
        SelfBroadcastGasFeeSelection::Auto => (
            quote.suggested_max_fee_per_gas,
            quote.suggested_max_priority_fee_per_gas,
        ),
        SelfBroadcastGasFeeSelection::Custom {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => (max_fee_per_gas, max_priority_fee_per_gas),
    };
    validate_self_broadcast_gas_fee(max_fee_per_gas, max_priority_fee_per_gas)?;
    Ok(SelfBroadcastResolvedGasFee {
        rpc_gas_price: quote.rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    })
}

fn validate_self_broadcast_gas_fee(
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<()> {
    if max_fee_per_gas == 0 {
        return Err(eyre!(
            "self-broadcast max fee per gas must be greater than zero"
        ));
    }
    if max_priority_fee_per_gas > max_fee_per_gas {
        return Err(eyre!(
            "self-broadcast max priority fee per gas cannot exceed max fee per gas"
        ));
    }
    Ok(())
}

async fn self_broadcast_preflight_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas: &settings::EffectiveChainGasSettings,
    nonce: Option<u64>,
    network_mode: WalletNetworkMode,
) -> Result<SelfBroadcastPreflight> {
    let quote = self_broadcast_gas_fee_quote_from_rpc_pool(query_rpc_pool, network_mode)
        .await
        .wrap_err("fetch self-broadcast gas price")?;
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match self_broadcast_preflight(
            provider_handle,
            chain_id,
            from,
            to,
            data.clone(),
            gas_fee,
            quote,
            gas,
            nonce,
        )
        .await
        {
            Ok(preflight) => return Ok(preflight),
            Err(error) if is_self_broadcast_insufficient_native_gas_error(&error) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(?error, "self-broadcast preflight failed");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all self-broadcast query RPC attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

async fn self_broadcast_preflight(
    provider_handle: ProviderHandle,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    quote: SelfBroadcastGasFeeQuote,
    gas: &settings::EffectiveChainGasSettings,
    nonce: Option<u64>,
) -> Result<SelfBroadcastPreflight> {
    let provider = &provider_handle.provider;
    let SelfBroadcastResolvedGasFee {
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    } = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    let nonce = if let Some(nonce) = nonce {
        nonce
    } else {
        provider
            .get_transaction_count(from)
            .await
            .wrap_err("fetch self-broadcast nonce")?
    };
    let tx_req = self_broadcast_transaction_request(
        chain_id,
        from,
        to,
        data,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        nonce,
    );
    let estimated_gas = provider
        .estimate_gas(tx_req.clone())
        .await
        .wrap_err("estimate self-broadcast gas")?;
    let gas_limit = self_broadcast_gas_limit_with_buffer(estimated_gas, gas.gas_limit_buffer);
    let estimated_native_gas_cost = self_broadcast_native_gas_cost(gas_limit, max_fee_per_gas);
    let live_native_balance = provider
        .get_balance(from)
        .await
        .wrap_err("fetch self-broadcast native balance")?;
    if live_native_balance < estimated_native_gas_cost {
        return Err(self_broadcast_insufficient_native_gas_error(
            live_native_balance,
            estimated_native_gas_cost,
        ));
    }
    Ok(SelfBroadcastPreflight {
        tx_req: tx_req.with_gas_limit(gas_limit),
        nonce,
        gas_limit,
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        estimated_native_gas_cost,
        live_native_balance,
    })
}

fn self_broadcast_transaction_request(
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    nonce: u64,
) -> TransactionRequest {
    TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from)
        .with_to(to)
        .with_input(data)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
        .with_nonce(nonce)
}

const fn self_broadcast_gas_limit_with_buffer(estimated_gas: u64, gas_limit_buffer: u64) -> u64 {
    estimated_gas.saturating_add(gas_limit_buffer)
}

fn self_broadcast_native_gas_cost(gas_limit: u64, max_fee_per_gas: u128) -> U256 {
    U256::from(gas_limit) * U256::from(max_fee_per_gas)
}

fn self_broadcast_insufficient_native_gas_error(balance: U256, estimated_cost: U256) -> Report {
    eyre!(
        "insufficient native gas for self-broadcast: live balance {balance}, estimated cost {estimated_cost}"
    )
}

fn is_self_broadcast_insufficient_native_gas_error(error: &Report) -> bool {
    error
        .to_string()
        .starts_with("insufficient native gas for self-broadcast:")
}

enum SelfBroadcastRawTxBroadcastOutcome {
    Accepted,
    AlreadyKnown,
    Rejected(String),
}

struct SelfBroadcastRawTxBroadcastResult {
    provider_handle: ProviderHandle,
    outcome: SelfBroadcastRawTxBroadcastOutcome,
}

async fn sign_send_self_broadcast_transaction(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    wallet: &EthereumWallet,
    tx_req: TransactionRequest,
    session: &WalletSession,
    pending_spent_inputs: &[Utxo],
) -> Result<SelfBroadcastSentTx> {
    tracing::info!(
        from = %tx_req.from.unwrap_or_default(),
        to = ?tx_req.to,
        gas = ?tx_req.gas,
        "signing and sending self-broadcast transaction",
    );
    let signed_tx = tx_req
        .build(wallet)
        .await
        .wrap_err("self-broadcast: sign")?
        .encoded_2718();
    let tx_hash = keccak256(&signed_tx);
    let provider_handles = self_broadcast_send_raw_transaction_to_rpc_pool(
        query_rpc_pool,
        network_mode,
        signed_tx,
        tx_hash,
    )
    .await
    .wrap_err("self-broadcast: send")?;
    let tx_hash_string = hex::encode_prefixed(tx_hash);
    session
        .mark_pending_spent_utxos(
            pending_spent_inputs,
            parse_submitted_tx_hash(&tx_hash_string),
        )
        .await;
    tracing::info!(%tx_hash, providers = provider_handles.len(), "sent self-broadcast transaction");
    Ok(SelfBroadcastSentTx {
        tx_hash,
        tx_hash_string,
        provider_handles,
    })
}

async fn self_broadcast_send_raw_transaction_to_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    signed_tx: Vec<u8>,
    tx_hash: FixedBytes<32>,
) -> Result<Vec<ProviderHandle>> {
    let providers = query_rpc_pool.available_providers();
    if providers.is_empty() {
        return Err(eyre!("no healthy query RPC available"));
    }

    let policy = SelfBroadcastFeeQuoteTimeoutPolicy::for_network_mode(network_mode);
    let started_at = Instant::now();
    let mut join_set = JoinSet::new();
    for provider_handle in providers {
        join_set.spawn(self_broadcast_send_raw_transaction_to_provider(
            provider_handle,
            signed_tx.clone(),
            tx_hash,
            policy.hard_deadline,
        ));
    }

    let mut accepted_provider_handles = Vec::new();
    let mut last_error = None;
    let mut grace_deadline = None;
    while !join_set.is_empty() {
        let now = Instant::now();
        let Some(hard_remaining) = policy
            .hard_deadline
            .checked_sub(now.saturating_duration_since(started_at))
        else {
            break;
        };
        let wait_for = grace_deadline.map_or(hard_remaining, |deadline: Instant| {
            deadline.saturating_duration_since(now).min(hard_remaining)
        });
        if wait_for.is_zero() {
            break;
        }

        match tokio::time::timeout(wait_for, join_set.join_next()).await {
            Ok(Some(Ok(result))) => match result.outcome {
                SelfBroadcastRawTxBroadcastOutcome::Accepted => {
                    tracing::info!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        "self-broadcast tx accepted by RPC"
                    );
                    accepted_provider_handles.push(result.provider_handle);
                    if grace_deadline.is_none() {
                        grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                    }
                }
                SelfBroadcastRawTxBroadcastOutcome::AlreadyKnown => {
                    tracing::info!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        "self-broadcast tx already known by RPC"
                    );
                    accepted_provider_handles.push(result.provider_handle);
                    if grace_deadline.is_none() {
                        grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                    }
                }
                SelfBroadcastRawTxBroadcastOutcome::Rejected(message) => {
                    tracing::warn!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        message,
                        "self-broadcast tx rejected by RPC"
                    );
                    last_error = Some(message);
                }
            },
            Ok(Some(Err(error))) => {
                last_error = Some(error.to_string());
            }
            Ok(None) | Err(_) => break,
        }
    }
    join_set.abort_all();

    if accepted_provider_handles.is_empty() {
        return Err(eyre!(last_error.unwrap_or_else(|| {
            "self-broadcast transaction was not accepted by any RPC before the deadline".to_string()
        })));
    }
    Ok(accepted_provider_handles)
}

async fn self_broadcast_send_raw_transaction_to_provider(
    provider_handle: ProviderHandle,
    signed_tx: Vec<u8>,
    tx_hash: FixedBytes<32>,
    timeout: Duration,
) -> SelfBroadcastRawTxBroadcastResult {
    let send_result = tokio::time::timeout(
        timeout,
        provider_handle.provider.send_raw_transaction(&signed_tx),
    )
    .await;
    let outcome = match send_result {
        Ok(Ok(pending)) => {
            let returned_hash = pending.tx_hash().to_owned();
            if returned_hash == tx_hash {
                SelfBroadcastRawTxBroadcastOutcome::Accepted
            } else {
                SelfBroadcastRawTxBroadcastOutcome::Rejected(format!(
                    "RPC returned unexpected transaction hash {returned_hash}; expected {tx_hash}"
                ))
            }
        }
        Ok(Err(error)) if is_self_broadcast_tx_already_known_error(&error) => {
            SelfBroadcastRawTxBroadcastOutcome::AlreadyKnown
        }
        Ok(Err(error)) => SelfBroadcastRawTxBroadcastOutcome::Rejected(error.to_string()),
        Err(_) => SelfBroadcastRawTxBroadcastOutcome::Rejected(
            "self-broadcast send timed out".to_string(),
        ),
    };
    SelfBroadcastRawTxBroadcastResult {
        provider_handle,
        outcome,
    }
}

fn is_self_broadcast_tx_already_known_error(error: &alloy::transports::TransportError) -> bool {
    error
        .as_error_resp()
        .is_some_and(|response| is_self_broadcast_tx_already_known_message(&response.message))
}

fn is_self_broadcast_tx_already_known_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("already known")
        || message.contains("already in mempool")
        || message.contains("known transaction")
        || message.contains("already imported")
        || message.contains("already have")
        || message.contains("already exists")
        || message.contains("transaction already")
}

fn tx_receipt_output(tx_hash: FixedBytes<32>, receipt: &TransactionReceipt) -> TxReceiptOutput {
    let status = receipt.status();
    let block_number = receipt.block_number.unwrap_or(0);
    let gas_used = receipt.gas_used;
    if status {
        tracing::info!(%tx_hash, block_number, gas_used, "self-broadcast transaction confirmed");
    } else {
        tracing::warn!(%tx_hash, block_number, gas_used, "self-broadcast transaction reverted");
    }
    TxReceiptOutput {
        tx_hash: hex::encode_prefixed(tx_hash),
        status,
        block_number,
        gas_used,
    }
}

async fn mark_submitted_inputs_pending_spent(
    session: &WalletSession,
    inputs: &[Utxo],
    result: &PublicBroadcasterSubmissionResult,
) {
    let PublicBroadcasterResultKind::Submitted { tx_hash } = &result.result else {
        return;
    };
    session
        .mark_pending_spent_utxos(inputs, parse_submitted_tx_hash(tx_hash))
        .await;
}

fn parse_submitted_tx_hash(tx_hash: &str) -> Option<FixedBytes<32>> {
    tx_hash.parse().ok()
}

async fn prepare_desktop_unshield_public_broadcaster(
    request: DesktopUnshieldPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PreparedPublicBroadcasterPlan<UnshieldPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    if request.unwrap && !is_effective_wrapped_native_token(request.chain_id, request.token, &chain)
    {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster unshield spend")?;

    let PublicBroadcasterSetup {
        chain,
        broadcaster,
        query_rpc_pool,
        min_gas_price,
        prover,
        forest,
        utxos,
    } = public_broadcaster_setup(
        &request.session,
        request.chain_id,
        request.effective_chain.as_ref(),
        request.fee_token,
        &request.fee_rows,
        &request.selection,
        request.unwrap,
        request.fee_policy,
        request.anchor_cache.as_ref(),
        http,
    )
    .await?;
    let same_token_fee = request.fee_token == request.token;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let seeded_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let selection = unshield_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                request.amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    PublicBroadcasterFeeMode::AddToAmount,
                    same_token_fee,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        })?;
    let initial_fee_estimate = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        seeded_fee_amount,
        |split| {
            let selection = unshield_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        },
    ) {
        Ok(estimate) => {
            tracing::info!(
                fee_amount = %estimate.fee_amount,
                gas_limit = estimate.gas_limit,
                min_gas_price,
                transaction_count = estimate.transaction_count,
                input_count = estimate.input_count,
                private_output_count = estimate.private_output_count,
                public_output_count = estimate.public_output_count,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "using approximate public broadcaster unshield fee for first proof"
            );
            Some(estimate)
        }
        Err(err) => {
            if !same_token_fee {
                return Err(err).wrap_err("estimate initial public broadcaster unshield fee");
            }
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial same-token public broadcaster unshield fee; starting at zero"
            );
            None
        }
    };
    let initial_fee_amount = initial_fee_estimate
        .as_ref()
        .map_or(U256::ZERO, |estimate| estimate.fee_amount);

    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load public broadcaster unshield spend signer")?;

    let mode = if request.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };
    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split_for_tokens(
            request.amount,
            fee_amount,
            request.fee_mode,
            same_token_fee,
        )?;
        let unshield_request = RailgunUnshieldRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient: request.recipient,
            mode,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
                token_address: request.fee_token,
                amount: fee_amount,
            }),
            min_gas_price,
        };
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::ProvingTransaction,
        );
        let proof_started = Instant::now();
        let plan = tx_builder
            .build_unshield_plan_with_signer(
                &request.view_session.scan_keys(),
                &signer,
                &forest,
                &utxos,
                unshield_request,
                &prover,
            )
            .await
            .map_err(|error| {
                public_broadcaster_build_error(error, fee_amount, split.fee_mode, same_token_fee)
            })
            .wrap_err("build public broadcaster unshield proof")?;
        tracing::info!(
            attempt,
            fee_amount = %fee_amount,
            elapsed_ms = proof_started.elapsed().as_millis(),
            transaction_count = plan.transaction_count(),
            input_count = plan.input_count(),
            private_output_count = plan.private_output_count(),
            public_output_count = plan.public_output_count(),
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "built public broadcaster unshield proof"
        );
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingBroadcasterFee,
        );
        let gas_started = Instant::now();
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee_from_rpc_pool(
            &query_rpc_pool,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
            chain.gas.gas_limit_buffer,
        )
        .await?;
        let gas_elapsed_ms = gas_started.elapsed().as_millis();
        tracing::info!(
            attempt,
            available_fee = %fee_amount,
            computed_fee = %computed_fee,
            gas_limit,
            min_gas_price,
            gas_elapsed_ms,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "estimated public broadcaster unshield fee"
        );
        if broadcaster_fee_covers(fee_amount, computed_fee) {
            let protocol_fee_amount = railgun_protocol_fee_amount(
                split.receiver_amount,
                RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
            );
            tracing::info!(
                attempt,
                fee_amount = %fee_amount,
                computed_fee = %computed_fee,
                gas_limit,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "public broadcaster unshield fee stabilized"
            );
            update_transaction_generation_stage(
                request.progress_tx.as_ref(),
                TransactionGenerationStage::GeneratingPoiProofs,
            );
            let pre_transaction_pois = public_broadcaster_pre_transaction_pois(
                &plan.chunks,
                &broadcaster,
                request.session.as_ref(),
                request.chain_id,
                &prover,
                request.verify_proof,
                http,
            )
            .await?;
            let pending_persist_started = Instant::now();
            let pending_contexts = persist_pending_unshield_output_poi_contexts(
                request.session.db.as_ref(),
                request.chain_id,
                request.view_session.wallet_id(),
                &plan.chunks,
                &pre_transaction_pois.pending_pois,
                &pre_transaction_pois.pending_poi_list_keys,
                true,
                !same_token_fee,
            )?;
            tracing::info!(
                chain_id = request.chain_id,
                pending_contexts,
                elapsed_ms = pending_persist_started.elapsed().as_millis(),
                "persisted public broadcaster unshield pending output POI contexts"
            );
            return Ok(PreparedPublicBroadcasterPlan {
                plan,
                pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois.request_pois,
                broadcaster,
                action_token: request.token,
                fee_token: request.fee_token,
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps: RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
                fee_mode: split.fee_mode,
                gas_limit,
                min_gas_price,
            });
        }
        let next_fee = buffered_public_broadcaster_fee(computed_fee);
        log_public_broadcaster_fee_prediction_failure(
            "unshield",
            attempt,
            fee_amount,
            computed_fee,
            gas_limit,
            initial_fee_estimate.as_ref(),
            plan.transaction_count(),
            plan.input_count(),
            plan.private_output_count(),
            plan.public_output_count(),
            &broadcaster,
        );
        tracing::info!(
            attempt,
            previous_fee = %fee_amount,
            computed_fee = %computed_fee,
            next_fee = %next_fee,
            "retrying public broadcaster unshield proof with buffered fee"
        );
        fee_amount = next_fee;
    }

    Err(eyre!(
        "public broadcaster fee did not stabilize after bounded retries"
    ))
}

async fn prepare_desktop_send_public_broadcaster(
    request: DesktopSendPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PreparedPublicBroadcasterPlan<SendPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster send spend")?;

    let recipient = parse_railgun_recipient(&request.recipient)?;
    let PublicBroadcasterSetup {
        chain,
        broadcaster,
        query_rpc_pool,
        min_gas_price,
        prover,
        forest,
        utxos,
    } = public_broadcaster_setup(
        &request.session,
        request.chain_id,
        request.effective_chain.as_ref(),
        request.fee_token,
        &request.fee_rows,
        &request.selection,
        false,
        request.fee_policy,
        request.anchor_cache.as_ref(),
        http,
    )
    .await?;
    let same_token_fee = request.fee_token == request.token;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let seeded_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let selection = send_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                request.amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    PublicBroadcasterFeeMode::AddToAmount,
                    same_token_fee,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        })?;
    let initial_fee_estimate = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        U256::ZERO,
        min_gas_price,
        seeded_fee_amount,
        |split| {
            let selection = send_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        },
    ) {
        Ok(estimate) => {
            tracing::info!(
                fee_amount = %estimate.fee_amount,
                gas_limit = estimate.gas_limit,
                min_gas_price,
                transaction_count = estimate.transaction_count,
                input_count = estimate.input_count,
                private_output_count = estimate.private_output_count,
                public_output_count = estimate.public_output_count,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "using approximate public broadcaster send fee for first proof"
            );
            Some(estimate)
        }
        Err(err) => {
            if !same_token_fee {
                return Err(err).wrap_err("estimate initial public broadcaster send fee");
            }
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial same-token public broadcaster send fee; starting at zero"
            );
            None
        }
    };
    let initial_fee_amount = initial_fee_estimate
        .as_ref()
        .map_or(U256::ZERO, |estimate| estimate.fee_amount);

    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load public broadcaster send spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split_for_tokens(
            request.amount,
            fee_amount,
            request.fee_mode,
            same_token_fee,
        )?;
        let send_request = RailgunSendRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
                token_address: request.fee_token,
                amount: fee_amount,
            }),
            min_gas_price,
        };
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::ProvingTransaction,
        );
        let proof_started = Instant::now();
        let plan = tx_builder
            .build_send_plan_with_signer(
                &request.view_session.scan_keys(),
                &signer,
                &forest,
                &utxos,
                send_request,
                &prover,
            )
            .await
            .map_err(|error| {
                public_broadcaster_build_error(error, fee_amount, split.fee_mode, same_token_fee)
            })
            .wrap_err("build public broadcaster send proof")?;
        let chunk_input_counts = plan
            .chunks
            .iter()
            .map(|chunk| chunk.inputs.len())
            .collect::<Vec<_>>();
        let chunk_output_counts = plan
            .chunks
            .iter()
            .map(|chunk| chunk.outputs.len())
            .collect::<Vec<_>>();
        let chunk_tree_numbers = plan
            .chunks
            .iter()
            .map(|chunk| chunk.tree_number)
            .collect::<Vec<_>>();
        tracing::info!(
            attempt,
            fee_amount = %fee_amount,
            elapsed_ms = proof_started.elapsed().as_millis(),
            transaction_count = plan.transaction_count(),
            input_count = plan.input_count(),
            private_output_count = plan.private_output_count(),
            public_output_count = plan.public_output_count(),
            same_token_fee,
            ?chunk_input_counts,
            ?chunk_output_counts,
            ?chunk_tree_numbers,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "built public broadcaster send proof"
        );
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingBroadcasterFee,
        );
        let gas_started = Instant::now();
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee_from_rpc_pool(
            &query_rpc_pool,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
            chain.gas.gas_limit_buffer,
        )
        .await?;
        let gas_elapsed_ms = gas_started.elapsed().as_millis();
        tracing::info!(
            attempt,
            available_fee = %fee_amount,
            computed_fee = %computed_fee,
            gas_limit,
            min_gas_price,
            gas_elapsed_ms,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "estimated public broadcaster send fee"
        );
        if broadcaster_fee_covers(fee_amount, computed_fee) {
            let protocol_fee_amount = U256::ZERO;
            tracing::info!(
                attempt,
                fee_amount = %fee_amount,
                computed_fee = %computed_fee,
                gas_limit,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "public broadcaster send fee stabilized"
            );
            update_transaction_generation_stage(
                request.progress_tx.as_ref(),
                TransactionGenerationStage::GeneratingPoiProofs,
            );
            let pre_transaction_pois = public_broadcaster_pre_transaction_pois(
                &plan.chunks,
                &broadcaster,
                request.session.as_ref(),
                request.chain_id,
                &prover,
                request.verify_proof,
                http,
            )
            .await?;
            let pending_persist_started = Instant::now();
            let pending_contexts = persist_pending_send_output_poi_contexts(
                request.session.db.as_ref(),
                request.chain_id,
                request.view_session.wallet_id(),
                &plan.chunks,
                &pre_transaction_pois.pending_pois,
                &pre_transaction_pois.pending_poi_list_keys,
                true,
                !same_token_fee,
            )?;
            tracing::info!(
                chain_id = request.chain_id,
                pending_contexts,
                elapsed_ms = pending_persist_started.elapsed().as_millis(),
                "persisted public broadcaster send pending output POI contexts"
            );
            return Ok(PreparedPublicBroadcasterPlan {
                plan,
                pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois.request_pois,
                broadcaster,
                action_token: request.token,
                fee_token: request.fee_token,
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps: U256::ZERO,
                fee_mode: split.fee_mode,
                gas_limit,
                min_gas_price,
            });
        }
        let next_fee = buffered_public_broadcaster_fee(computed_fee);
        log_public_broadcaster_fee_prediction_failure(
            "send",
            attempt,
            fee_amount,
            computed_fee,
            gas_limit,
            initial_fee_estimate.as_ref(),
            plan.transaction_count(),
            plan.input_count(),
            plan.private_output_count(),
            plan.public_output_count(),
            &broadcaster,
        );
        tracing::info!(
            attempt,
            previous_fee = %fee_amount,
            computed_fee = %computed_fee,
            next_fee = %next_fee,
            "retrying public broadcaster send proof with buffered fee"
        );
        fee_amount = next_fee;
    }

    Err(eyre!(
        "public broadcaster fee did not stabilize after bounded retries"
    ))
}

async fn estimate_public_broadcaster_fee(
    provider: &(impl Provider + Clone),
    chain_id: u64,
    to: Address,
    data: &Bytes,
    token_fee_per_unit_gas: U256,
    min_gas_price: u128,
    gas_limit_buffer: u64,
) -> Result<(u64, U256)> {
    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_to(to)
        .with_input(data.clone())
        .with_gas_price(min_gas_price);
    let estimated_gas = provider
        .estimate_gas(tx_req)
        .await
        .wrap_err("estimate public broadcaster gas")?;
    let gas_limit = public_broadcaster_gas_limit_with_buffer(estimated_gas, gas_limit_buffer);
    let service_gas_price = public_broadcaster_service_gas_price(min_gas_price);
    Ok((
        gas_limit,
        broadcaster_fee_amount(token_fee_per_unit_gas, gas_limit, service_gas_price),
    ))
}

async fn estimate_public_broadcaster_fee_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    to: Address,
    data: &Bytes,
    token_fee_per_unit_gas: U256,
    min_gas_price: u128,
    gas_limit_buffer: u64,
) -> Result<(u64, U256)> {
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match estimate_public_broadcaster_fee(
            &provider_handle.provider,
            chain_id,
            to,
            data,
            token_fee_per_unit_gas,
            min_gas_price,
            gas_limit_buffer,
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(error) => {
                tracing::warn!(%error, rpc = %provider_handle.url, "estimate public broadcaster gas failed");
                query_rpc_pool.mark_bad_provider(&provider_handle);
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all query RPC public broadcaster gas estimate attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

const fn public_broadcaster_gas_limit_with_buffer(
    estimated_gas: u64,
    gas_limit_buffer: u64,
) -> u64 {
    estimated_gas.saturating_add(gas_limit_buffer)
}

fn public_broadcaster_transact_params(
    broadcaster: &PublicBroadcasterCandidate,
    to: Address,
    data: Bytes,
    min_gas_price: u128,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
) -> BroadcasterRawParamsTransact {
    BroadcasterRawParamsTransact {
        chain_type: 0,
        chain_id: broadcaster.chain_id,
        min_gas_price: Some(U256::from(min_gas_price)),
        fees_id: Some(broadcaster.fees_id.clone()),
        to,
        data,
        broadcaster_viewing_key: FixedBytes::from(broadcaster.viewing_public_key),
        txid_version: Some(DEFAULT_TXID_VERSION.to_string()),
        pre_transaction_pois_per_txid_leaf_per_list,
    }
}

async fn publish_public_broadcaster_payload(
    waku: &WakuClient,
    pubsub_path: &str,
    transact_topic: &str,
    payload: &[u8],
    attempt: usize,
) -> Result<()> {
    tracing::info!(
        pubsub_path = %pubsub_path,
        transact_topic = %transact_topic,
        payload_len = payload.len(),
        attempt,
        "publishing public broadcaster transact request"
    );
    let publish_started = Instant::now();
    waku.publish(transact_topic, payload)
        .await
        .wrap_err("publish public broadcaster transact request")?;
    tracing::info!(
        pubsub_path = %pubsub_path,
        transact_topic = %transact_topic,
        elapsed_ms = publish_started.elapsed().as_millis(),
        attempt,
        "published public broadcaster transact request"
    );
    Ok(())
}

async fn public_broadcaster_republish_loop<F, Fut>(
    mut stop_rx: oneshot::Receiver<()>,
    republish_interval: Duration,
    mut publish: F,
) where
    F: FnMut(usize) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    let mut attempt = 1usize;
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            () = tokio::time::sleep(republish_interval) => {
                attempt = attempt.saturating_add(1);
                if let Err(error) = publish(attempt).await {
                    tracing::warn!(%error, attempt, "republish public broadcaster transact request failed");
                }
            }
        }
    }
}

async fn submit_public_broadcaster_plan(
    waku: Arc<WakuClient>,
    to: Address,
    data: Bytes,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
    broadcaster: PublicBroadcasterCandidate,
    action_token: Address,
    fee_token: Address,
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: U256,
    fee_mode: PublicBroadcasterFeeMode,
    gas_limit: u64,
    min_gas_price: u128,
    progress_tx: Option<TransactionGenerationProgressSender>,
    timeout: Duration,
    republish_interval: Duration,
) -> Result<PublicBroadcasterSubmissionResult> {
    let transact_topic = transact_topic(broadcaster.chain_id);
    let response_topic = transact_response_topic(broadcaster.chain_id);
    tracing::info!(
        chain_id = broadcaster.chain_id,
        broadcaster = %broadcaster.railgun_address,
        broadcaster_identifier = ?broadcaster.identifier.as_deref(),
        fees_id = %broadcaster.fees_id,
        token = ?broadcaster.token,
        to = ?to,
        fee_amount = %fee_amount,
        gas_limit,
        min_gas_price,
        data_len = data.len(),
        transact_topic = %transact_topic,
        response_topic = %response_topic,
        "preparing public broadcaster transact request"
    );
    update_transaction_generation_stage(
        progress_tx.as_ref(),
        TransactionGenerationStage::PublishingToBroadcaster,
    );
    let params = public_broadcaster_transact_params(
        &broadcaster,
        to,
        data,
        min_gas_price,
        pre_transaction_pois_per_txid_leaf_per_list,
    );
    let encrypt_started = Instant::now();
    let encrypted = EncryptedTransactRequest::encrypt(broadcaster.viewing_public_key, &params)
        .wrap_err("encrypt public broadcaster transact request")?;
    let payload = encrypted
        .to_transact_payload()
        .wrap_err("serialize public broadcaster transact request")?;
    tracing::info!(
        chain_id = broadcaster.chain_id,
        broadcaster = %broadcaster.railgun_address,
        fees_id = %broadcaster.fees_id,
        payload_len = payload.len(),
        elapsed_ms = encrypt_started.elapsed().as_millis(),
        "built public broadcaster encrypted Waku payload"
    );
    let pubsub_path = waku.pubsub_path().to_string();
    tracing::info!(
        pubsub_path = %pubsub_path,
        response_topic = %response_topic,
        "subscribing to public broadcaster response topic"
    );
    let subscribe_started = Instant::now();
    let mut response_rx = waku
        .subscribe(vec![response_topic.clone()])
        .await
        .wrap_err("subscribe to public broadcaster response topic")?;
    tracing::info!(
        response_topic = %response_topic,
        elapsed_ms = subscribe_started.elapsed().as_millis(),
        "subscribed to public broadcaster response topic"
    );
    publish_public_broadcaster_payload(&waku, &pubsub_path, &transact_topic, &payload, 1)
        .await
        .wrap_err("publish initial public broadcaster transact request")?;
    update_transaction_generation_stage(
        progress_tx.as_ref(),
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    let (republish_stop_tx, republish_stop_rx) = oneshot::channel();
    let republish_waku = Arc::clone(&waku);
    let republish_pubsub_path = pubsub_path.clone();
    let republish_transact_topic = transact_topic.clone();
    let republish_payload = payload.clone();
    let republish_handle = tokio::spawn(public_broadcaster_republish_loop(
        republish_stop_rx,
        republish_interval,
        move |attempt| {
            let waku = Arc::clone(&republish_waku);
            let pubsub_path = republish_pubsub_path.clone();
            let transact_topic = republish_transact_topic.clone();
            let payload = republish_payload.clone();
            async move {
                publish_public_broadcaster_payload(
                    &waku,
                    &pubsub_path,
                    &transact_topic,
                    &payload,
                    attempt,
                )
                .await
            }
        },
    ));

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let result = loop {
        tokio::select! {
            () = &mut sleep => {
                tracing::warn!(
                    chain_id = broadcaster.chain_id,
                    broadcaster = %broadcaster.railgun_address,
                    fees_id = %broadcaster.fees_id,
                    response_topic = %response_topic,
                    timeout_ms = timeout.as_millis(),
                    "timed out waiting for public broadcaster response"
                );
                break PublicBroadcasterResultKind::TimedOut;
            },
            msg = response_rx.recv() => {
                let Some(msg) = msg else {
                    tracing::warn!(response_topic = %response_topic, "public broadcaster response channel closed");
                    break PublicBroadcasterResultKind::TimedOut;
                };
                tracing::info!(
                    content_topic = %msg.content_topic,
                    payload_len = msg.payload.len(),
                    "received public broadcaster response candidate"
                );
                match decode_public_broadcaster_response(&encrypted.shared_key, &msg.payload) {
                    Ok(Some(result)) => {
                        tracing::info!(?result, "decrypted public broadcaster response");
                        break result;
                    }
                    Ok(None) => tracing::debug!("public broadcaster response was not decryptable with request key"),
                    Err(error) => tracing::debug!(%error, "ignoring undecryptable public broadcaster response"),
                }
            }
        }
    };
    let _ = republish_stop_tx.send(());
    republish_handle.abort();

    Ok(PublicBroadcasterSubmissionResult {
        broadcaster,
        action_token,
        fee_token,
        entered_amount,
        receiver_amount,
        recipient_amount,
        total_private_spend,
        fee_amount,
        protocol_fee_amount,
        protocol_fee_bps,
        fee_mode,
        gas_limit,
        min_gas_price,
        result,
    })
}

async fn snapshot_from_handle(chain_id: u64, handle: &WalletHandle) -> ListUtxosOutput {
    let utxos = handle.utxos.read().await.clone();
    let pending_overlay = handle.pending_overlay().await;
    let local_pending_spent_count = pending_overlay.local_pending_spent.len();
    let confirmed_utxos = utxos.clone();
    let (utxo_outputs, totals) = utxo_outputs_from_utxos(utxos);
    let mut utxo_outputs = utxo_outputs;
    apply_pending_overlay_to_outputs(&confirmed_utxos, pending_overlay, &mut utxo_outputs);
    let unspent_count = utxo_outputs.iter().filter(|utxo| !utxo.is_spent).count();
    let spent_count = utxo_outputs.len().saturating_sub(unspent_count);

    ListUtxosOutput {
        chain_id,
        cache_key: handle.cache_key.clone(),
        utxo_count: utxo_outputs.len(),
        unspent_count,
        spent_count,
        local_pending_spent_count,
        utxos: utxo_outputs,
        totals,
    }
}

struct SyncedViewWallet {
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    start_block: u64,
    handle: WalletHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DesktopWalletChainStart {
    start_block: u64,
    last_scanned_block: u64,
}

fn resolve_desktop_wallet_chain_start(
    policy: DesktopWalletSyncStartPolicy,
    existing_metadata: Option<&vault::WalletChainMetadataBundle>,
    init_block_number: Option<u64>,
    deployment_block: u64,
    safe_head: Option<u64>,
    rewind_wallet_cache: bool,
) -> Result<DesktopWalletChainStart> {
    if let Some(metadata) = existing_metadata
        && !rewind_wallet_cache
    {
        return Ok(DesktopWalletChainStart {
            start_block: metadata.start_block,
            last_scanned_block: metadata.last_scanned_block,
        });
    }

    if rewind_wallet_cache {
        let start_block = init_block_number.unwrap_or(deployment_block);
        return Ok(DesktopWalletChainStart {
            start_block,
            last_scanned_block: start_block.saturating_sub(1),
        });
    }

    match policy {
        DesktopWalletSyncStartPolicy::ImportedHistoricalBackfill => {
            let start_block = init_block_number.unwrap_or(deployment_block);
            Ok(DesktopWalletChainStart {
                start_block,
                last_scanned_block: start_block.saturating_sub(1),
            })
        }
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill => {
            let safe_head = safe_head.ok_or_else(|| {
                eyre!("chain safe head unavailable for generated wallet; retry sync later")
            })?;
            let start_block = safe_head
                .checked_add(1)
                .ok_or_else(|| eyre!("chain safe head overflow for generated wallet"))?;
            Ok(DesktopWalletChainStart {
                start_block,
                last_scanned_block: safe_head,
            })
        }
    }
}

async fn setup_synced_view_wallet_with_store(
    view_session: Arc<vault::DesktopViewSession>,
    chain_id: u64,
    sync_start_policy: DesktopWalletSyncStartPolicy,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    effective_chain: Option<settings::EffectiveChainConfig>,
    poi_read_source: PoiReadSource,
    shared_local_poi_caches: Option<WalletLocalPoiCaches>,
    rewind_wallet_cache: bool,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    progress_tx: Option<SyncProgressSender>,
    wait_until_ready: bool,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
) -> Result<SyncedViewWallet> {
    let chain_defaults = chain_defaults_for_chain(chain_id)?;
    let effective_contract = effective_chain
        .as_ref()
        .map(|chain| parse_effective_address("railgun contract", &chain.railgun_contract))
        .transpose()?;
    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: effective_contract.unwrap_or(chain_defaults.contract),
    };

    let effective_use_indexed_wallet_catch_up = effective_chain
        .as_ref()
        .map_or(use_indexed_wallet_catch_up, |chain| {
            use_indexed_wallet_catch_up && chain.quick_sync_enabled
        });
    let chain_cfg = chain_config(
        &chain_defaults,
        rpc_url_override,
        effective_chain.as_ref(),
        http,
        progress_tx.clone(),
    )?;
    let wallet_quick_sync_endpoint = chain_cfg.quick_sync_endpoint.clone();
    let chain_service = sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let vault_store = vault::DesktopVaultStore::from_db(Arc::clone(&db));
    let contract = chain_key.contract.to_checksum(None);
    let existing_wallet_chain_metadata = vault_store
        .find_wallet_chain_metadata_for_session(view_session.as_ref(), 0, chain_id, &contract)
        .wrap_err("load encrypted wallet chain metadata")?;
    let chain_handle = chain_service.handle();
    let safe_head = *chain_handle.safe_head_rx.borrow();
    let safe_head = (safe_head > 0).then_some(safe_head);
    let deployment_block = effective_chain
        .as_ref()
        .map_or(chain_defaults.deployment_block, |chain| {
            chain.deployment_block
        });
    let resolved_start = resolve_desktop_wallet_chain_start(
        sync_start_policy,
        existing_wallet_chain_metadata.as_ref(),
        init_block_number,
        deployment_block,
        safe_head,
        rewind_wallet_cache,
    )?;
    tracing::info!(
        chain_id,
        start_block = resolved_start.start_block,
        last_scanned_block = resolved_start.last_scanned_block,
        sync_to_block,
        effective_use_indexed_wallet_catch_up,
        poi_read_source = ?poi_read_source,
        sync_start_policy = ?sync_start_policy,
        "starting desktop view wallet sync"
    );
    let mut wallet_chain_metadata = match existing_wallet_chain_metadata {
        Some(metadata) => metadata,
        None => vault_store
            .create_wallet_chain_metadata_for_session(
                view_session.as_ref(),
                0,
                chain_id,
                &contract,
                resolved_start.start_block,
                resolved_start.last_scanned_block,
            )
            .wrap_err("create encrypted wallet chain metadata")?,
    };
    let start_block = resolved_start.start_block;
    if rewind_wallet_cache {
        wallet_chain_metadata.start_block = start_block;
        vault_store
            .rewind_wallet_chain_cache_with_session(
                view_session.as_ref(),
                &mut wallet_chain_metadata,
                start_block,
            )
            .wrap_err("rewind encrypted wallet cache")?;
        tracing::info!(
            chain_id,
            start_block,
            wallet_chain_uuid = %wallet_chain_metadata.wallet_chain_uuid,
            "rewound encrypted desktop wallet cache"
        );
    }
    let selected_poi_read_source = poi_read_source_label(&poi_read_source);
    if wallet_chain_metadata.poi_read_source.as_deref() != Some(selected_poi_read_source) {
        wallet_chain_metadata.poi_read_source = Some(selected_poi_read_source.to_string());
        vault_store
            .store_wallet_chain_metadata_with_session(view_session.as_ref(), &wallet_chain_metadata)
            .wrap_err("persist selected POI read source")?;
    }
    let cache_key = wallet_chain_metadata.wallet_chain_uuid.clone();
    let (local_poi_caches, manage_local_poi_cache) = wallet_local_poi_caches(
        &poi_read_source,
        chain_id,
        &cache_key,
        shared_local_poi_caches,
    );
    let cache_store = Arc::new(
        vault::DesktopEncryptedWalletCacheStore::new(
            Arc::clone(&db),
            Arc::clone(&view_session),
            wallet_chain_metadata,
        )
        .wrap_err("create encrypted wallet cache")?,
    );
    let scan_keys = view_session.scan_keys();
    let poi_recovery_prover = ProverService::new_with_db(artifact_source(http), Arc::clone(&db));
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key,
        start_block: Some(start_block),
        sync_to_block,
        quick_sync_endpoint: wallet_quick_sync_endpoint,
        scan_keys,
        spending_public_key: Some(view_session.spending_public_key()),
        progress_tx,
        cache_store: Some(cache_store),
        poi_recovery_prover: Some(poi_recovery_prover),
        poi_read_source,
        local_poi_caches,
        manage_local_poi_cache,
        use_indexed_wallet_catch_up: effective_use_indexed_wallet_catch_up,
    };

    let mut handle = sync_manager
        .add_wallet(wallet_cfg)
        .await
        .wrap_err("register wallet sync worker")?;
    if wait_until_ready {
        handle.wait_until_ready().await;
    }

    Ok(SyncedViewWallet {
        db,
        sync_manager,
        chain_key,
        start_block,
        handle,
    })
}

fn chain_defaults_for_chain(chain_id: u64) -> Result<ChainConfigDefaults> {
    ChainConfigDefaults::for_chain(chain_id).ok_or_else(|| eyre!("unsupported chain id {chain_id}"))
}

fn chain_config(
    defaults: &ChainConfigDefaults,
    rpc_url_override: Option<Url>,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    http: &HttpContext,
    progress_tx: Option<SyncProgressSender>,
) -> Result<ChainConfig> {
    let rpc_urls = if effective_chain.is_some() {
        effective_rpc_urls_for_chain(defaults, effective_chain)?
    } else if let Some(rpc_url) = rpc_url_override {
        vec![rpc_url]
    } else {
        defaults.rpc_urls.clone()
    };
    let quick_sync_endpoint = effective_chain
        .filter(|chain| chain.quick_sync_enabled)
        .and_then(|chain| chain.quick_sync_endpoint.as_ref())
        .map(|url| Url::parse(url).wrap_err_with(|| format!("parse quick-sync URL {url}")))
        .transpose()?
        .or_else(|| {
            effective_chain
                .is_none()
                .then(|| defaults.quick_sync_endpoint.clone())
                .flatten()
        });
    let contract = effective_chain
        .map(|chain| parse_effective_address("railgun contract", &chain.railgun_contract))
        .transpose()?
        .unwrap_or(defaults.contract);
    let archive_rpc_url = effective_chain
        .and_then(|chain| chain.archive_rpc_url.as_ref())
        .map(|url| Url::parse(url).wrap_err_with(|| format!("parse archive RPC URL {url}")))
        .transpose()?;
    let query_rpc_pool = Arc::new(QueryRpcPool::with_http_client(
        rpc_urls,
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ));

    Ok(ChainConfig {
        chain_id: defaults.chain_id,
        contract,
        rpcs: query_rpc_pool,
        archive_rpc_url,
        archive_until_block: effective_chain.map_or(defaults.archive_until_block, |chain| {
            chain.archive_until_block
        }),
        deployment_block: effective_chain
            .map_or(defaults.deployment_block, |chain| chain.deployment_block),
        v2_start_block: effective_chain
            .map_or(defaults.v2_start_block, |chain| chain.v2_start_block),
        legacy_shield_block: effective_chain.map_or(defaults.legacy_shield_block, |chain| {
            chain.legacy_shield_block
        }),
        block_range: effective_chain
            .and_then(|chain| chain.block_range)
            .unwrap_or(DEFAULT_BLOCK_RANGE),
        indexed_wallet_block_range: effective_chain
            .map_or(defaults.indexed_wallet_block_range, |chain| {
                chain.indexed_wallet_block_range
            }),
        poll_interval: effective_chain
            .and_then(|chain| chain.poll_interval_secs)
            .map_or(DEFAULT_POLL_INTERVAL, Duration::from_secs),
        finality_depth: effective_chain
            .map_or(defaults.finality_depth, |chain| chain.finality_depth),
        quick_sync_endpoint,
        anchor_interval: defaults.anchor_interval,
        anchor_retention: defaults.anchor_retention,
        http_client: Some(http.client.clone()),
        progress_tx,
    })
}

fn parse_effective_address(label: &str, value: &str) -> Result<Address> {
    Address::from_str(value).wrap_err_with(|| format!("parse effective {label} address"))
}

fn wallet_local_poi_caches(
    poi_read_source: &PoiReadSource,
    chain_id: u64,
    cache_key: &str,
    shared_local_poi_caches: Option<WalletLocalPoiCaches>,
) -> (Option<WalletLocalPoiCaches>, bool) {
    if !matches!(poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return (None, false);
    }

    if let Some(local_poi_caches) = shared_local_poi_caches {
        tracing::info!(
            chain_id,
            cache_key,
            "using shared chain-scoped local POI cache for wallet session"
        );
        return (Some(local_poi_caches), false);
    }

    tracing::info!(
        chain_id,
        cache_key,
        "local POI cache enabled for wallet session"
    );
    (Some(Arc::new(RwLock::new(BTreeMap::new()))), true)
}

const fn poi_read_source_label(poi_read_source: &PoiReadSource) -> &'static str {
    match poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => "indexed-artifacts",
        PoiReadSource::PoiProxy => "poi-proxy",
    }
}

fn artifact_source(http: &HttpContext) -> ArtifactSource {
    match http.proxy_url.as_ref() {
        Some(url) => ArtifactSource::default().with_proxy(url.clone()),
        None => ArtifactSource::default(),
    }
}

async fn buffered_gas_price_with_policy(
    provider: &(impl Provider + Clone),
    numerator: u128,
    denominator: u128,
) -> Result<u128> {
    if denominator == 0 {
        return Err(eyre!(
            "gas price buffer denominator must be greater than zero"
        ));
    }
    let gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")?;
    Ok(gas_price * numerator / denominator)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    use alloy::hex;
    use alloy::primitives::{Address, Bytes, FixedBytes, TxHash, U256};
    use alloy::uint;
    use broadcaster_core::crypto::railgun::{
        Address as RailgunAddress, AddressData, ViewingKeyData,
    };
    use broadcaster_core::notes::Note;
    use broadcaster_core::transact::{
        EncryptedTransactRequest, PreTxPoi, SnarkJsProof, railgun_txid_leaf_hash,
        try_decrypt_transact_request,
    };
    use broadcaster_core::transact_response::DecryptedTransactResponse;
    use broadcaster_monitor::FeeRow;
    use local_db::{DbConfig, DbStore, PendingOutputPoiRole};
    use poi::poi::default_active_poi_list_keys;
    use railgun_wallet::tx::{
        BuildError, PrivateInputs, PublicInputs, TransactionPlanChunk, UnshieldSelectionInfo,
    };
    use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletKeys, WalletUtxo};
    use serde_json::json;
    use sync_service::ChainConfigDefaults;

    use super::signer::{EvmMessageSigner, EvmTransactionSigner, SoftwareEvmSigner};
    use super::{
        ApproximateTransactionShape, BroadcasterFeePolicy, BroadcasterFeePolicyStatus,
        DesktopWalletChainStart, DesktopWalletSyncStartPolicy, ListUtxosOutput,
        PublicBroadcasterCandidate, PublicBroadcasterFeeMargin, PublicBroadcasterFeeMode,
        PublicBroadcasterResultKind, PublicBroadcasterSelection, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        SelfBroadcastFeeSample, SelfBroadcastGasFeeQuote, SelfBroadcastGasFeeSelection,
        SelfBroadcastTipFallback, TokenTotal, UtxoOutput, WalletPendingOverlay, WalletPendingSpent,
        apply_pending_overlay_to_outputs, approximate_public_broadcaster_cost,
        approximate_public_broadcaster_gas, broadcaster_fee_amount, broadcaster_fee_covers,
        buffered_public_broadcaster_fee, decode_public_broadcaster_response,
        eligible_public_broadcasters, fee_policy_eligible_public_broadcasters,
        fixed_token_anchor_rate, initial_separate_token_public_broadcaster_fee,
        is_self_broadcast_insufficient_native_gas_error,
        is_self_broadcast_tx_already_known_message, is_wrapped_native_token,
        max_broadcaster_fee_token_amount_from_outputs, max_send_amount_from_outputs,
        max_unshield_amount_from_outputs, parse_railgun_recipient, parse_send_amount,
        parse_submitted_tx_hash, parse_unshield_amount, public_broadcaster_amount_split,
        public_broadcaster_amount_split_for_tokens, public_broadcaster_anchor_rate_for_policy,
        public_broadcaster_build_error, public_broadcaster_candidates,
        public_broadcaster_fee_breakdown, public_broadcaster_gas_limit_with_buffer,
        public_broadcaster_max_entered_amount, public_broadcaster_max_entered_amount_for_tokens,
        public_broadcaster_republish_loop, public_broadcaster_transact_params,
        resolve_desktop_wallet_chain_start, resolve_self_broadcast_gas_fee,
        select_public_broadcaster, select_public_broadcaster_with_policy,
        self_broadcast_gas_limit_with_buffer, self_broadcast_insufficient_native_gas_error,
        self_broadcast_native_gas_cost, self_broadcast_quote_from_fee_samples,
        self_broadcast_quote_from_fee_samples_with_tip_fallback,
        self_broadcast_transaction_request, send_approximate_shape,
        sort_specific_public_broadcasters, transact_topic, unshield_approximate_shape,
        utxo_outputs_from_utxos, validate_self_broadcast_gas_fee, wrapped_native_token_for_chain,
    };

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn address(byte: u8) -> Address {
        Address::from_slice(&[byte; 20])
    }

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-ops-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

    fn source(byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number: u64::from(byte),
            block_timestamp: 1_700_000_000 + u64::from(byte),
        }
    }

    fn selection_info(
        total: U256,
        input_count: usize,
        transaction_count: usize,
        private_output_count: usize,
        public_output_count: usize,
        max_spendable: U256,
    ) -> UnshieldSelectionInfo {
        UnshieldSelectionInfo {
            total,
            input_count,
            transaction_count,
            private_output_count,
            public_output_count,
            max_spendable,
        }
    }

    fn sample_railgun_address(seed: u8) -> String {
        let viewing = ViewingKeyData::from_spending_public_key(
            [seed; 32],
            [U256::from(seed), U256::from(seed + 1)],
        );
        viewing
            .derive_address(None)
            .expect("derive railgun address")
            .to_string()
    }

    fn sample_public_broadcaster_candidate(
        seed: u8,
    ) -> (PublicBroadcasterCandidate, ViewingKeyData) {
        let viewing = ViewingKeyData::from_spending_public_key(
            [seed; 32],
            [U256::from(seed), U256::from(seed + 1)],
        );
        let railgun_address = viewing.derive_address(None).expect("derive address");
        let address_data = AddressData::try_from(&RailgunAddress::from(railgun_address.as_ref()))
            .expect("address data");
        (
            PublicBroadcasterCandidate {
                chain_id: 1,
                railgun_address: railgun_address.to_string(),
                identifier: None,
                token: address(0x33),
                fee: uint!(10_U256),
                fees_id: "fees-id".to_string(),
                fee_expiration: SystemTime::now() + Duration::from_secs(60),
                reliability: 0.9,
                available_wallets: 1,
                version: "8.2.3".to_string(),
                relay_adapt: address(0x44),
                relay_adapt_7702: None,
                required_poi_list_keys: Vec::new(),
                viewing_public_key: address_data.viewing_public_key,
                address_data,
                fee_policy_status: BroadcasterFeePolicyStatus::UnknownAnchor,
            },
            viewing,
        )
    }

    fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
        PreTxPoi {
            snark_proof: SnarkJsProof {
                pi_a: [U256::from(byte), U256::from(byte + 1)],
                pi_b: [
                    [U256::from(byte + 2), U256::from(byte + 3)],
                    [U256::from(byte + 4), U256::from(byte + 5)],
                ],
                pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
            },
            txid_merkleroot: FixedBytes::from([byte; 32]),
            poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
            blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
            railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
        }
    }

    #[test]
    fn desktop_wallet_start_policy_generated_uses_safe_head_no_backfill() {
        let resolved = resolve_desktop_wallet_chain_start(
            DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
            None,
            None,
            100,
            Some(250),
            false,
        )
        .expect("resolve generated start");

        assert_eq!(
            resolved,
            DesktopWalletChainStart {
                start_block: 251,
                last_scanned_block: 250,
            }
        );
    }

    #[test]
    fn desktop_wallet_start_policy_imported_uses_deployment_block() {
        let resolved = resolve_desktop_wallet_chain_start(
            DesktopWalletSyncStartPolicy::ImportedHistoricalBackfill,
            None,
            None,
            100,
            Some(250),
            false,
        )
        .expect("resolve imported start");

        assert_eq!(
            resolved,
            DesktopWalletChainStart {
                start_block: 100,
                last_scanned_block: 99,
            }
        );
    }

    #[test]
    fn chain_config_uses_effective_rpc_pool_and_sync_tuning() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let root_dir = temp_db_root();
        let http = runtime
            .block_on(super::build_wallet_network_context(
                super::WalletNetworkConfig {
                    network_mode: Some(super::WalletNetworkMode::Direct),
                    proxy: None,
                    data_dir: &root_dir,
                },
            ))
            .expect("direct HTTP context");
        let defaults = ChainConfigDefaults::for_chain(1).expect("ethereum defaults");
        let effective = super::settings::EffectiveChainConfig {
            chain_id: 1,
            enabled: true,
            rpc_endpoints: vec![
                "https://rpc-a.example".to_string(),
                "https://rpc-b.example".to_string(),
            ],
            archive_rpc_url: Some("https://archive.example".to_string()),
            quick_sync_enabled: false,
            quick_sync_endpoint: Some("https://quick.example/graphql".to_string()),
            indexed_wallet_block_range: 12_345,
            deployment_block: 12_000,
            v2_start_block: 13_000,
            legacy_shield_block: 14_000,
            archive_until_block: 12_500,
            railgun_contract: defaults.contract.to_string(),
            relay_adapt_contract: defaults.relay_adapt_contract.to_string(),
            relay_adapt_7702_contract: defaults.relay_adapt_7702_contract.to_string(),
            wrapped_native_token: wrapped_native_token_for_chain(1).map(|token| token.to_string()),
            multicall_contract: defaults.multicall_contract.to_string(),
            finality_depth: 99,
            block_range: Some(2_000),
            poll_interval_secs: Some(30),
            gas: super::settings::EffectiveChainGasSettings {
                gas_limit_buffer: 250_000,
                gas_price_buffer_numerator: 110,
                gas_price_buffer_denominator: 100,
            },
        };

        let cfg = super::chain_config(
            &defaults,
            Some(reqwest::Url::parse("https://ignored.example").expect("url")),
            Some(&effective),
            &http,
            None,
        )
        .expect("chain config");

        assert_eq!(cfg.quick_sync_endpoint, None);
        assert_eq!(cfg.indexed_wallet_block_range, 12_345);
        assert_eq!(cfg.finality_depth, 99);
        assert_eq!(cfg.block_range, 2_000);
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
        assert_eq!(
            cfg.archive_rpc_url.as_ref().map(reqwest::Url::as_str),
            Some("https://archive.example/")
        );
        assert_eq!(cfg.deployment_block, 12_000);
        assert_eq!(cfg.v2_start_block, 13_000);
        assert_eq!(cfg.legacy_shield_block, 14_000);
        assert_eq!(cfg.archive_until_block, 12_500);

        let first = cfg.rpcs.random_provider().expect("first provider");
        cfg.rpcs.mark_bad_provider(&first);
        let second = cfg.rpcs.random_provider().expect("fallback provider");
        assert_ne!(first.url, second.url);

        drop(http);
        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn desktop_wallet_start_policy_reuses_existing_metadata() {
        let existing = super::vault::WalletChainMetadataBundle {
            wallet_chain_uuid: "wallet-chain".to_string(),
            wallet_uuid: "wallet".to_string(),
            chain_type: 0,
            chain_id: 1,
            contract: "0x1111111111111111111111111111111111111111".to_string(),
            start_block: 251,
            last_scanned_block: 300,
            last_scanned_block_hash: None,
            poi_read_source: None,
        };

        let resolved = resolve_desktop_wallet_chain_start(
            DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
            Some(&existing),
            None,
            100,
            None,
            false,
        )
        .expect("resolve existing start");

        assert_eq!(
            resolved,
            DesktopWalletChainStart {
                start_block: 251,
                last_scanned_block: 300,
            }
        );
    }

    #[test]
    fn desktop_wallet_start_policy_generated_requires_safe_head() {
        let error = resolve_desktop_wallet_chain_start(
            DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
            None,
            None,
            100,
            None,
            false,
        )
        .expect_err("safe head required");

        assert!(error.to_string().contains("safe head unavailable"));
    }

    #[test]
    fn desktop_wallet_rewind_uses_explicit_init_block() {
        let existing = super::vault::WalletChainMetadataBundle {
            wallet_chain_uuid: "wallet-chain".to_string(),
            wallet_uuid: "wallet".to_string(),
            chain_type: 0,
            chain_id: 1,
            contract: "0x1111111111111111111111111111111111111111".to_string(),
            start_block: 251,
            last_scanned_block: 300,
            last_scanned_block_hash: None,
            poi_read_source: None,
        };

        let resolved = resolve_desktop_wallet_chain_start(
            DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
            Some(&existing),
            Some(existing.start_block),
            100,
            None,
            true,
        )
        .expect("resolve explicit rewind start");

        assert_eq!(
            resolved,
            DesktopWalletChainStart {
                start_block: existing.start_block,
                last_scanned_block: existing.start_block.saturating_sub(1),
            }
        );
    }

    fn sample_poi_map(
        list_keys: &[FixedBytes<32>],
        txid_leaf_hashes: &[FixedBytes<32>],
    ) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
        list_keys
            .iter()
            .enumerate()
            .map(|(list_index, list_key)| {
                let per_leaf = txid_leaf_hashes
                    .iter()
                    .enumerate()
                    .map(|(leaf_index, leaf)| {
                        (
                            *leaf,
                            sample_pre_tx_poi(10 + (list_index * 4 + leaf_index) as u8),
                        )
                    })
                    .collect();
                (*list_key, per_leaf)
            })
            .collect()
    }

    fn sample_note(seed: u8, token: Address, value: u64) -> Note {
        Note::new_change(U256::from(seed), token, U256::from(value), [seed; 16])
    }

    fn sample_chunk(
        tree_number: u32,
        bound_seed: u8,
        outputs: Vec<Note>,
        has_unshield: bool,
    ) -> TransactionPlanChunk {
        TransactionPlanChunk {
            tree_number,
            merkle_root: U256::from(bound_seed),
            inputs: Vec::new(),
            public_inputs: PublicInputs {
                merkle_root: U256::from(bound_seed),
                bound_params_hash: U256::from(bound_seed + 1),
                nullifiers: Vec::new(),
                commitments_out: outputs.iter().map(Note::commitment).collect(),
            },
            private_inputs: PrivateInputs {
                token_address: U256::from(bound_seed + 2),
                random_in: Vec::new(),
                value_in: Vec::new(),
                path_elements: Vec::new(),
                leaves_indices: Vec::new(),
                value_out: outputs.iter().map(|note| note.value).collect(),
                public_key: [U256::from(bound_seed + 3), U256::from(bound_seed + 4)],
                npk_out: outputs.iter().map(|note| note.npk).collect(),
                nullifying_key: U256::from(bound_seed + 5),
            },
            outputs,
            has_unshield,
            signature: [U256::ZERO; 3],
        }
    }

    fn poi_map_for_chunks(
        list_keys: &[FixedBytes<32>],
        chunks: &[TransactionPlanChunk],
    ) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
        let leaves = chunks
            .iter()
            .map(|chunk| {
                FixedBytes::from(
                    railgun_txid_leaf_hash(chunk.railgun_txid(), u64::from(chunk.tree_number))
                        .to_be_bytes::<32>(),
                )
            })
            .collect::<Vec<_>>();
        sample_poi_map(list_keys, &leaves)
    }

    fn fee_row(chain_id: u64, token: Address, fee: u64, reliability: f64, fees_id: &str) -> FeeRow {
        fee_row_with_broadcaster_seed(chain_id, token, fee, reliability, fees_id, 7)
    }

    fn fee_row_with_broadcaster_seed(
        chain_id: u64,
        token: Address,
        fee: u64,
        reliability: f64,
        fees_id: &str,
        broadcaster_seed: u8,
    ) -> FeeRow {
        FeeRow {
            chain_id,
            railgun_address: Arc::from(sample_railgun_address(broadcaster_seed)),
            token_address: token,
            fee: U256::from(fee),
            signature_valid: true,
            fees_id: Arc::from(fees_id),
            fee_expiration: SystemTime::now() + Duration::from_secs(60),
            available_wallets: 1,
            version: Arc::from("8.2.3"),
            relay_adapt: address(0x44),
            relay_adapt_7702: None,
            required_poi_list_keys: Vec::new(),
            identifier: None,
            last_seen: SystemTime::now(),
            reliability,
        }
    }

    fn utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
        let mut wallet_utxo = WalletUtxo::new(Utxo::new(
            Note::new_unshield(Address::ZERO, token, U256::from(value)),
            tree,
            position,
            source(position as u8 + 1),
            UtxoCommitmentKind::Transact,
        ));
        for list_key in default_active_poi_list_keys() {
            wallet_utxo
                .utxo
                .poi
                .statuses
                .insert(list_key, PoiStatus::Valid);
        }
        wallet_utxo
    }

    fn spent_utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
        let mut wallet_utxo = utxo(token, value, tree, position);
        wallet_utxo.spent = Some(source(9));
        wallet_utxo
    }

    #[test]
    fn poi_verified_unspent_utxos_filter_planner_inputs() {
        let token = address(0x11);
        let valid = utxo(token, 5, 0, 1);
        let mut unknown = utxo(token, 100, 0, 2);
        unknown.utxo.poi.statuses.clear();
        let mut blocked = utxo(token, 7, 0, 3);
        blocked
            .utxo
            .poi
            .statuses
            .insert(default_active_poi_list_keys()[0], PoiStatus::ShieldBlocked);
        let spent = spent_utxo(token, 9, 0, 4);

        let selected = super::poi_verified_unspent_utxos_from_records(
            &[valid, unknown, blocked, spent],
            &WalletPendingOverlay::default(),
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].note.value, uint!(5_U256));
    }

    #[test]
    fn pending_spent_utxos_filter_planner_inputs() {
        let token = address(0x11);
        let valid = utxo(token, 5, 0, 1);
        let pending = WalletPendingOverlay {
            pending_spent: vec![WalletPendingSpent {
                tree: 0,
                position: 1,
                tx_hash: Some(FixedBytes::from([0x99; 32])),
                block_number: Some(20),
                block_timestamp: Some(1_700_000_020),
            }],
            ..WalletPendingOverlay::default()
        };

        let selected = super::poi_verified_unspent_utxos_from_records(&[valid], &pending);

        assert!(selected.is_empty());
    }

    #[test]
    fn pending_overlay_rows_are_not_spendable() {
        let token = address(0x11);
        let confirmed = utxo(token, 5, 0, 1);
        let pending_new = utxo(token, 7, 0, 2);
        let mut pending_spent_overlay = WalletPendingOverlay {
            pending_spent: vec![WalletPendingSpent {
                tree: 0,
                position: 1,
                tx_hash: Some(FixedBytes::from([0x99; 32])),
                block_number: Some(20),
                block_timestamp: Some(1_700_000_020),
            }],
            ..WalletPendingOverlay::default()
        };
        pending_spent_overlay.new_utxos.push(pending_new);
        let (mut outputs, _) = utxo_outputs_from_utxos(vec![confirmed.clone()]);

        apply_pending_overlay_to_outputs(&[confirmed], pending_spent_overlay, &mut outputs);

        assert_eq!(outputs.len(), 2);
        assert!(outputs.iter().any(|output| output.pending_spent));
        assert!(outputs.iter().any(|output| output.pending_new));
        assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            U256::ZERO
        );
    }

    #[test]
    fn local_pending_spent_rows_are_not_spendable() {
        let token = address(0x11);
        let confirmed = utxo(token, 5, 0, 1);
        let local_pending_overlay = WalletPendingOverlay {
            local_pending_spent: vec![WalletPendingSpent {
                tree: 0,
                position: 1,
                tx_hash: Some(FixedBytes::from([0x99; 32])),
                block_number: None,
                block_timestamp: Some(1_700_000_020),
            }],
            ..WalletPendingOverlay::default()
        };
        let (mut outputs, _) = utxo_outputs_from_utxos(vec![confirmed.clone()]);

        apply_pending_overlay_to_outputs(&[confirmed], local_pending_overlay, &mut outputs);

        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].local_pending_spent);
        assert!(!outputs[0].pending_spent);
        assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            U256::ZERO
        );
    }

    #[test]
    fn self_broadcast_transaction_request_sets_outer_evm_fields() {
        let from = address(0x11);
        let to = address(0x22);
        let calldata = Bytes::from_static(&[0xaa, 0xbb, 0xcc]);

        let tx_req = self_broadcast_transaction_request(5, from, to, calldata.clone(), 42, 0, 7);

        assert_eq!(tx_req.chain_id, Some(5));
        assert_eq!(tx_req.from, Some(from));
        assert_eq!(tx_req.to, Some(to.into()));
        assert_eq!(tx_req.max_fee_per_gas, Some(42));
        assert_eq!(tx_req.max_priority_fee_per_gas, Some(0));
        assert_eq!(tx_req.nonce, Some(7));
        assert_eq!(
            tx_req.input.input().expect("self-broadcast input"),
            calldata.as_ref()
        );
    }

    #[test]
    fn self_broadcast_auto_gas_fee_uses_rpc_gas_price_with_min_tip() {
        let quote = SelfBroadcastGasFeeQuote::from_rpc_gas_price(100);
        let resolved = resolve_self_broadcast_gas_fee(SelfBroadcastGasFeeSelection::Auto, quote)
            .expect("resolve auto gas fee");

        assert_eq!(quote.suggested_max_fee_per_gas, 120);
        assert_eq!(quote.suggested_max_priority_fee_per_gas, 1);
        assert_eq!(resolved.rpc_gas_price, 100);
        assert_eq!(resolved.max_fee_per_gas, 120);
        assert_eq!(resolved.max_priority_fee_per_gas, 1);
    }

    #[test]
    fn self_broadcast_fee_samples_ignore_zero_tips_when_non_zero_exists() {
        let samples = [
            SelfBroadcastFeeSample {
                rpc_gas_price: Some(100),
                max_priority_fee_per_gas: Some(0),
                next_base_fee_per_gas: Some(80),
                priority_fee_rewards: vec![0, 0, 0],
            },
            SelfBroadcastFeeSample {
                rpc_gas_price: Some(110),
                max_priority_fee_per_gas: Some(0),
                next_base_fee_per_gas: Some(90),
                priority_fee_rewards: vec![0, 5, 7],
            },
        ];

        let quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");

        assert_eq!(quote.suggested_max_priority_fee_per_gas, 7);
        assert_eq!(quote.rpc_gas_price, 110);
        assert_eq!(quote.suggested_max_fee_per_gas, 132);
    }

    #[test]
    fn self_broadcast_fee_samples_can_use_rpc_gas_price_as_tip_fallback() {
        let samples = [SelfBroadcastFeeSample {
            rpc_gas_price: Some(100),
            max_priority_fee_per_gas: Some(0),
            next_base_fee_per_gas: None,
            priority_fee_rewards: vec![0],
        }];

        let default_quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");
        let rpc_fallback_quote = self_broadcast_quote_from_fee_samples_with_tip_fallback(
            &samples,
            SelfBroadcastTipFallback::RpcGasPrice,
        )
        .expect("fee quote with rpc gas price fallback");

        assert_eq!(default_quote.suggested_max_priority_fee_per_gas, 1);
        assert_eq!(rpc_fallback_quote.suggested_max_fee_per_gas, 120);
        assert_eq!(rpc_fallback_quote.suggested_max_priority_fee_per_gas, 100);
    }

    #[test]
    fn self_broadcast_fee_samples_prefer_non_zero_tip_over_rpc_gas_price_fallback() {
        let samples = [SelfBroadcastFeeSample {
            rpc_gas_price: Some(100),
            max_priority_fee_per_gas: Some(5),
            next_base_fee_per_gas: None,
            priority_fee_rewards: vec![0],
        }];

        let quote = self_broadcast_quote_from_fee_samples_with_tip_fallback(
            &samples,
            SelfBroadcastTipFallback::RpcGasPrice,
        )
        .expect("fee quote");

        assert_eq!(quote.suggested_max_fee_per_gas, 120);
        assert_eq!(quote.suggested_max_priority_fee_per_gas, 5);
    }

    #[test]
    fn self_broadcast_fee_samples_include_fee_history_base_fee_cap() {
        let samples = [SelfBroadcastFeeSample {
            rpc_gas_price: Some(100),
            max_priority_fee_per_gas: Some(1),
            next_base_fee_per_gas: Some(200),
            priority_fee_rewards: vec![10],
        }];

        let quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");

        assert_eq!(quote.suggested_max_priority_fee_per_gas, 10);
        assert_eq!(quote.suggested_max_fee_per_gas, 250);
    }

    #[test]
    fn self_broadcast_already_known_classifier_excludes_nonce_errors() {
        for message in [
            "already known",
            "already in mempool",
            "known transaction: 0xabc",
            "transaction already imported",
            "Transaction already exists",
        ] {
            assert!(
                is_self_broadcast_tx_already_known_message(message),
                "expected {message:?} to be classified as already known"
            );
        }

        for message in [
            "nonce too low",
            "replacement transaction underpriced",
            "transaction gas price below minimum",
        ] {
            assert!(
                !is_self_broadcast_tx_already_known_message(message),
                "expected {message:?} to remain retryable"
            );
        }
    }

    #[test]
    fn self_broadcast_custom_gas_fee_validates_caps() {
        assert!(validate_self_broadcast_gas_fee(1, 0).is_ok());
        assert!(validate_self_broadcast_gas_fee(1, 1).is_ok());
        assert!(validate_self_broadcast_gas_fee(0, 0).is_err());
        assert!(validate_self_broadcast_gas_fee(1, 2).is_err());
    }

    #[test]
    fn self_broadcast_replacement_bump_uses_ceil_twelve_point_five_percent() {
        assert_eq!(super::self_broadcast_replacement_bumped_fee(0), 0);
        assert_eq!(super::self_broadcast_replacement_bumped_fee(1), 2);
        assert_eq!(super::self_broadcast_replacement_bumped_fee(8), 9);
        assert_eq!(super::self_broadcast_replacement_bumped_fee(100), 113);
    }

    #[test]
    fn self_broadcast_gas_cost_uses_max_fee_cap() {
        assert_eq!(self_broadcast_gas_limit_with_buffer(21_000, 5_000), 26_000);
        assert_eq!(self_broadcast_gas_limit_with_buffer(u64::MAX, 1), u64::MAX);
        assert_eq!(
            self_broadcast_native_gas_cost(26_000, 2_000_000_000),
            U256::from(52_000_000_000_000_u128)
        );
    }

    #[test]
    fn self_broadcast_insufficient_gas_error_is_terminal_and_formatted() {
        let error =
            self_broadcast_insufficient_native_gas_error(U256::from(7_u64), U256::from(9_u64));

        assert!(is_self_broadcast_insufficient_native_gas_error(&error));
        assert_eq!(
            error.to_string(),
            "insufficient native gas for self-broadcast: live balance 7, estimated cost 9"
        );
    }

    #[test]
    fn self_broadcast_pending_spent_hash_parsing_accepts_submitted_tx_hash() {
        let hash = "0x1111111111111111111111111111111111111111111111111111111111111111";

        assert_eq!(
            parse_submitted_tx_hash(hash),
            Some(FixedBytes::from([0x11; 32]))
        );
        assert_eq!(parse_submitted_tx_hash("not-a-hash"), None);
    }

    #[test]
    fn manual_send_pending_output_contexts_persist_without_tx_hash() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let token = address(0x33);
        let recipient_note = sample_note(1, token, 5);
        let change_note = sample_note(2, token, 3);
        let chunk = sample_chunk(
            4,
            0x20,
            vec![recipient_note.clone(), change_note.clone()],
            false,
        );
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let count = super::persist_pending_send_output_poi_contexts(
            &store,
            1,
            "wallet-1",
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            false,
            false,
        )
        .expect("persist pending send output contexts");

        assert_eq!(count, 2);
        let records = store
            .list_pending_output_poi_contexts(1)
            .expect("list pending output POI contexts");
        assert_eq!(records.len(), 2);
        let recipient = records
            .iter()
            .find(|record| record.output_role == PendingOutputPoiRole::Recipient)
            .expect("recipient context");
        assert_eq!(recipient.wallet_id, "wallet-1");
        assert_eq!(
            recipient.output_commitment,
            FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
        );
        assert!(recipient.source_operation_id.is_none());
        assert!(recipient.observation.is_none());
        assert_eq!(recipient.required_poi_list_keys, poi_list_keys);
        let change = records
            .iter()
            .find(|record| record.output_role == PendingOutputPoiRole::Change)
            .expect("change context");
        assert_eq!(
            change.output_commitment,
            FixedBytes::from(change_note.commitment().to_be_bytes::<32>())
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn manual_unshield_pending_output_contexts_skip_public_output_without_tx_hash() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let token = address(0x34);
        let change_note = sample_note(3, token, 7);
        let unshield_note = Note::new_unshield(address(0xaa), token, uint!(5_U256));
        let chunk = sample_chunk(
            5,
            0x30,
            vec![change_note.clone(), unshield_note.clone()],
            true,
        );
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let count = super::persist_pending_unshield_output_poi_contexts(
            &store,
            1,
            "wallet-1",
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            false,
            false,
        )
        .expect("persist pending unshield output contexts");

        assert_eq!(count, 1);
        let records = store
            .list_pending_output_poi_contexts(1)
            .expect("list pending output POI contexts");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].output_role, PendingOutputPoiRole::Change);
        assert_eq!(
            records[0].output_commitment,
            FixedBytes::from(change_note.commitment().to_be_bytes::<32>())
        );
        assert_ne!(
            records[0].output_commitment,
            FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())
        );
        assert!(records[0].source_operation_id.is_none());
        assert!(records[0].observation.is_none());

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn public_broadcaster_pending_output_contexts_include_fee_outputs() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let token = address(0x35);
        let fee_note = sample_note(4, token, 1);
        let recipient_note = sample_note(5, token, 8);
        let change_note = sample_note(6, token, 2);
        let chunk = sample_chunk(
            6,
            0x40,
            vec![fee_note.clone(), recipient_note, change_note],
            false,
        );
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let count = super::persist_pending_send_output_poi_contexts(
            &store,
            1,
            "wallet-1",
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            true,
            false,
        )
        .expect("persist public broadcaster send output contexts");

        assert_eq!(count, 3);
        let records = store
            .list_pending_output_poi_contexts(1)
            .expect("list pending output POI contexts");
        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|record| record.output_role
            == PendingOutputPoiRole::BroadcasterFee
            && record.output_commitment
                == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn public_broadcaster_unshield_pending_output_contexts_skip_public_output() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let token = address(0x36);
        let fee_note = sample_note(7, token, 1);
        let change_note = sample_note(8, token, 4);
        let unshield_note = Note::new_unshield(address(0xbb), token, uint!(6_U256));
        let chunk = sample_chunk(
            7,
            0x50,
            vec![fee_note, change_note, unshield_note.clone()],
            true,
        );
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let count = super::persist_pending_unshield_output_poi_contexts(
            &store,
            1,
            "wallet-1",
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            true,
            false,
        )
        .expect("persist public broadcaster unshield output contexts");

        assert_eq!(count, 2);
        let records = store
            .list_pending_output_poi_contexts(1)
            .expect("list pending output POI contexts");
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::BroadcasterFee)
        );
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::Change)
        );
        assert!(records.iter().all(|record| record.output_commitment
            != FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())));

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn separate_fee_token_send_pending_output_contexts_keep_fee_change_role() {
        let fee_token = address(0x39);
        let action_token = address(0x3a);
        let fee_note = sample_note(11, fee_token, 1);
        let fee_change_note = sample_note(12, fee_token, 4);
        let recipient_note = sample_note(13, action_token, 8);
        let action_change_note = sample_note(14, action_token, 2);
        let chunks = vec![
            sample_chunk(
                10,
                0x80,
                vec![fee_note.clone(), fee_change_note.clone()],
                false,
            ),
            sample_chunk(
                11,
                0x81,
                vec![recipient_note.clone(), action_change_note.clone()],
                false,
            ),
        ];
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, &chunks);

        let records = super::build_pending_output_poi_context_records(
            1,
            "wallet-1",
            123,
            &chunks,
            &pre_transaction_pois,
            &poi_list_keys,
            &super::pending_send_output_role_plans(true, true),
        )
        .expect("build separate fee send records");

        assert_eq!(records.len(), 4);
        assert!(records.iter().any(|record| record.output_role
            == PendingOutputPoiRole::BroadcasterFee
            && record.output_commitment
                == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::Change
                    && record.output_commitment
                        == FixedBytes::from(fee_change_note.commitment().to_be_bytes::<32>()))
        );
        assert!(records.iter().any(
            |record| record.output_role == PendingOutputPoiRole::Recipient
                && record.output_commitment
                    == FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
        ));
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::Change
                    && record.output_commitment
                        == FixedBytes::from(action_change_note.commitment().to_be_bytes::<32>()))
        );
    }

    #[test]
    fn separate_fee_token_unshield_pending_output_contexts_skip_action_public_output() {
        let fee_token = address(0x3b);
        let action_token = address(0x3c);
        let fee_note = sample_note(15, fee_token, 1);
        let fee_change_note = sample_note(16, fee_token, 4);
        let action_change_note = sample_note(17, action_token, 2);
        let unshield_note = Note::new_unshield(address(0xdd), action_token, uint!(6_U256));
        let chunks = vec![
            sample_chunk(
                12,
                0x82,
                vec![fee_note.clone(), fee_change_note.clone()],
                false,
            ),
            sample_chunk(
                13,
                0x83,
                vec![action_change_note.clone(), unshield_note.clone()],
                true,
            ),
        ];
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, &chunks);

        let records = super::build_pending_output_poi_context_records(
            1,
            "wallet-1",
            123,
            &chunks,
            &pre_transaction_pois,
            &poi_list_keys,
            &super::pending_unshield_output_role_plans(true, true),
        )
        .expect("build separate fee unshield records");

        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|record| record.output_role
            == PendingOutputPoiRole::BroadcasterFee
            && record.output_commitment
                == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::Change
                    && record.output_commitment
                        == FixedBytes::from(fee_change_note.commitment().to_be_bytes::<32>()))
        );
        assert!(
            records
                .iter()
                .any(|record| record.output_role == PendingOutputPoiRole::Change
                    && record.output_commitment
                        == FixedBytes::from(action_change_note.commitment().to_be_bytes::<32>()))
        );
        assert!(records.iter().all(|record| record.output_commitment
            != FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())));
    }

    #[test]
    fn send_pending_output_role_plan_omits_absent_change() {
        let token = address(0x37);
        let recipient_note = sample_note(9, token, 11);
        let chunk = sample_chunk(8, 0x60, vec![recipient_note.clone()], false);
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let records = super::build_pending_output_poi_context_records(
            1,
            "wallet-1",
            123,
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            &super::pending_send_output_role_plans(false, false),
        )
        .expect("build pending send records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].output_role, PendingOutputPoiRole::Recipient);
        assert_eq!(
            records[0].output_commitment,
            FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
        );
    }

    #[test]
    fn unshield_pending_output_role_plan_skips_public_output_without_change() {
        let token = address(0x38);
        let fee_note = sample_note(10, token, 2);
        let unshield_note = Note::new_unshield(address(0xcc), token, uint!(9_U256));
        let chunk = sample_chunk(9, 0x70, vec![fee_note.clone(), unshield_note.clone()], true);
        let poi_list_keys = default_active_poi_list_keys();
        let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

        let records = super::build_pending_output_poi_context_records(
            1,
            "wallet-1",
            123,
            &[chunk],
            &pre_transaction_pois,
            &poi_list_keys,
            &super::pending_unshield_output_role_plans(true, false),
        )
        .expect("build pending unshield records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].output_role, PendingOutputPoiRole::BroadcasterFee);
        assert_eq!(
            records[0].output_commitment,
            FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())
        );
        assert_ne!(
            records[0].output_commitment,
            FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())
        );
    }

    #[test]
    fn utxo_outputs_are_sorted_by_tree_then_position() {
        let token = address(0x11);
        let (outputs, _) = utxo_outputs_from_utxos(vec![
            utxo(token, 1, 2, 1),
            utxo(token, 1, 1, 2),
            utxo(token, 1, 1, 1),
        ]);

        let positions: Vec<(u32, u64)> = outputs
            .into_iter()
            .map(|output| (output.tree, output.position))
            .collect();
        assert_eq!(positions, vec![(1, 1), (1, 2), (2, 1)]);
    }

    #[test]
    fn fee_token_amount_from_outputs_matches_single_fee_transaction_limit() {
        let token = address(0x12);
        let (outputs, _) = utxo_outputs_from_utxos(
            (0..20)
                .map(|position| utxo(token, 1, 0, position))
                .collect(),
        );

        assert_eq!(
            max_broadcaster_fee_token_amount_from_outputs(&outputs, token),
            uint!(13_U256)
        );
    }

    #[test]
    fn token_totals_are_accumulated_by_token_address() {
        let token_a = address(0x11);
        let token_b = address(0x22);
        let (_, totals) = utxo_outputs_from_utxos(vec![
            utxo(token_b, 7, 0, 0),
            utxo(token_a, 3, 0, 1),
            utxo(token_a, 4, 0, 2),
            spent_utxo(token_a, 100, 0, 3),
        ]);

        assert_eq!(
            totals,
            vec![
                TokenTotal {
                    token: token_a.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
                TokenTotal {
                    token: token_b.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
            ]
        );
    }

    #[test]
    fn token_totals_include_poi_verified_balance() {
        let token = address(0x11);
        let active_list_key = default_active_poi_list_keys()[0];
        let mut valid = utxo(token, 5, 0, 1);
        valid
            .utxo
            .poi
            .statuses
            .insert(active_list_key, PoiStatus::Valid);
        let mut missing = utxo(token, 7, 0, 2);
        missing.utxo.poi.statuses.clear();

        let (outputs, totals) = utxo_outputs_from_utxos(vec![valid, missing]);

        assert!(outputs[0].poi_spendable);
        assert_eq!(
            outputs[0].poi_statuses[&hex::encode(active_list_key)],
            "Valid"
        );
        assert!(!outputs[1].poi_spendable);
        assert_eq!(
            outputs[1].poi_statuses[&hex::encode(active_list_key)],
            "Unknown"
        );
        assert_eq!(totals[0].total, "12");
        assert_eq!(totals[0].poi_verified_total, "5");
    }

    #[test]
    fn max_amount_from_outputs_uses_planner_batched_selection() {
        let token = address(0x11);
        let other = address(0x22);
        let mut wallet_utxos = (0..20)
            .map(|position| utxo(token, 1, 0, position))
            .collect::<Vec<_>>();
        wallet_utxos.extend((0..5).map(|position| utxo(token, 3, 1, position)));
        wallet_utxos.push(utxo(other, 100, 1, 99));
        wallet_utxos.push(spent_utxo(token, 100, 2, 0));
        let (outputs, _) = utxo_outputs_from_utxos(wallet_utxos);

        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            uint!(35_U256)
        );
        assert_eq!(
            max_send_amount_from_outputs(&outputs, token),
            uint!(35_U256)
        );
    }

    #[test]
    fn max_amount_from_outputs_excludes_non_poi_verified_utxos() {
        let token = address(0x11);
        let mut valid = utxo(token, 5, 0, 1);
        let mut unknown = utxo(token, 100, 0, 2);
        unknown.utxo.poi.statuses.clear();
        let (outputs, _) = utxo_outputs_from_utxos(vec![valid.clone(), unknown]);

        assert_eq!(max_send_amount_from_outputs(&outputs, token), uint!(5_U256));
        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            uint!(5_U256)
        );

        valid.spent = Some(source(9));
        let (outputs, _) = utxo_outputs_from_utxos(vec![valid]);
        assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            U256::ZERO
        );
    }

    #[test]
    fn utxo_outputs_include_generation_timestamp() {
        let token = address(0x11);
        let (outputs, _) = utxo_outputs_from_utxos(vec![utxo(token, 1, 0, 7)]);

        assert_eq!(outputs[0].source_block_timestamp, 1_700_000_008);
    }

    #[test]
    fn list_utxos_output_serializes_existing_field_names() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 0,
            spent_count: 1,
            local_pending_spent_count: 0,
            utxos: vec![UtxoOutput {
                tree: 2,
                position: 3,
                token: "0x0000000000000000000000000000000000000001".to_string(),
                value: "4".to_string(),
                commitment_kind: "Transact".to_string(),
                commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                blinded_commitment:
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
                poi_statuses: BTreeMap::from([(
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                    "Unknown".to_string(),
                )]),
                poi_spendable: false,
                source_tx_hash:
                    "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                source_block_number: 11,
                source_block_timestamp: 1_700_000_011,
                is_spent: true,
                pending_new: false,
                pending_spent: false,
                local_pending_spent: false,
                spent_tx_hash: Some(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                spent_block_number: Some(21),
            }],
            totals: vec![TokenTotal {
                token: "0x0000000000000000000000000000000000000001".to_string(),
                total: "4".to_string(),
                poi_verified_total: "0".to_string(),
            }],
        };

        assert_eq!(
            serde_json::to_value(output).expect("serialize output"),
            json!({
                "chain_id": 1,
                "cache_key": "cache",
                "utxo_count": 1,
                "unspent_count": 0,
                "spent_count": 1,
                "local_pending_spent_count": 0,
                "utxos": [{
                    "tree": 2,
                    "position": 3,
                    "token": "0x0000000000000000000000000000000000000001",
                    "value": "4",
                    "commitment_kind": "Transact",
                    "commitment": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "npk": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "blinded_commitment": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "poi_statuses": {
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd": "Unknown",
                    },
                    "poi_spendable": false,
                    "source_tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source_block_number": 11,
                    "source_block_timestamp": 1_700_000_011,
                    "is_spent": true,
                    "pending_new": false,
                    "pending_spent": false,
                    "local_pending_spent": false,
                    "spent_tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "spent_block_number": 21,
                }],
                "totals": [{
                    "token": "0x0000000000000000000000000000000000000001",
                    "total": "4",
                    "poi_verified_total": "0",
                }],
            })
        );
    }

    #[test]
    fn software_evm_signer_uses_separate_transaction_and_message_boundaries() {
        fn exercise_boundaries(signer: &(impl EvmTransactionSigner + EvmMessageSigner)) {
            let address = signer.address();
            let shield_key = signer
                .derive_shield_private_key()
                .expect("derive shield key through EVM message boundary");
            let _wallet = signer.ethereum_wallet();

            assert_ne!(address, Address::ZERO);
            assert_ne!(shield_key, [0u8; 32]);
        }

        let signer = SoftwareEvmSigner::from_private_key([1; 32]).expect("software EVM signer");

        exercise_boundaries(&signer);
    }

    #[test]
    fn parse_unshield_amount_scales_known_token_decimals() {
        assert_eq!(
            parse_unshield_amount("1.23", Some(6)).expect("parsed amount"),
            uint!(1_230_000_U256)
        );
        assert_eq!(
            parse_unshield_amount(".5", Some(18)).expect("parsed amount"),
            uint!(5_U256) * uint!(10_U256).pow(uint!(17_U256))
        );
    }

    #[test]
    fn parse_unshield_amount_rejects_too_much_precision() {
        assert!(parse_unshield_amount("1.2345678", Some(6)).is_err());
    }

    #[test]
    fn parse_unshield_amount_requires_raw_units_for_unknown_tokens() {
        assert_eq!(
            parse_unshield_amount("123", None).expect("parsed raw amount"),
            uint!(123_U256)
        );
        assert!(parse_unshield_amount("1.23", None).is_err());
    }

    #[test]
    fn parse_send_amount_reuses_token_aware_amount_parsing() {
        assert_eq!(
            parse_send_amount("1.23", Some(6)).expect("parsed amount"),
            uint!(1_230_000_U256)
        );
        assert_eq!(
            parse_send_amount("123", None).expect("parsed raw amount"),
            uint!(123_U256)
        );
        assert!(parse_send_amount("1.23", None).is_err());
    }

    #[test]
    fn parse_railgun_recipient_accepts_valid_0zk_address() {
        let wallet = WalletKeys::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            0,
        )
        .expect("derive wallet");
        let address = wallet
            .viewing
            .derive_address(None)
            .expect("derive all-chain address")
            .to_string();

        let recipient = parse_railgun_recipient(&address).expect("valid 0zk recipient");

        assert_eq!(
            recipient.master_public_key,
            wallet.viewing.master_public_key
        );
        assert_eq!(
            recipient.viewing_public_key,
            wallet.viewing.viewing_public_key
        );
    }

    #[test]
    fn parse_railgun_recipient_rejects_invalid_address() {
        assert!(parse_railgun_recipient("0x0000000000000000000000000000000000000000").is_err());
        assert!(parse_railgun_recipient("").is_err());
    }

    #[test]
    fn public_broadcaster_candidates_filter_unsupported_rows_but_allow_poi_required_temporarily() {
        let token = address(0x21);
        let relay_adapt = address(0x44);
        let mut rows = vec![fee_row(1, token, 10, 0.9, "ok")];

        let mut invalid_signature = fee_row(1, token, 10, 0.9, "invalid-signature");
        invalid_signature.signature_valid = false;
        rows.push(invalid_signature);

        let mut expired = fee_row(1, token, 10, 0.9, "expired");
        expired.fee_expiration = SystemTime::now() - Duration::from_secs(1);
        rows.push(expired);

        let mut unavailable = fee_row(1, token, 10, 0.9, "unavailable");
        unavailable.available_wallets = 0;
        rows.push(unavailable);

        let mut unsupported_version = fee_row(1, token, 10, 0.9, "version");
        unsupported_version.version = Arc::from("9.0.0");
        rows.push(unsupported_version);

        let mut poi_required = fee_row(1, token, 10, 0.9, "poi");
        poi_required.required_poi_list_keys = vec![Arc::from("poi-list")];
        rows.push(poi_required);

        rows.push(fee_row(2, token, 10, 0.9, "chain"));
        rows.push(fee_row(1, address(0x22), 10, 0.9, "token"));

        let mut relay_mismatch = fee_row(1, token, 10, 0.9, "relay");
        relay_mismatch.relay_adapt = address(0x55);
        rows.push(relay_mismatch);

        let candidates =
            eligible_public_broadcasters(&rows, 1, token, Some(relay_adapt), SystemTime::now());

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].fees_id, "ok");
        assert_eq!(candidates[1].fees_id, "poi");
    }

    #[test]
    fn public_broadcaster_candidates_are_keyed_by_selected_fee_token() {
        let action_token = address(0x43);
        let fee_token = address(0x44);
        let candidates = public_broadcaster_candidates(
            &[
                fee_row(1, action_token, 10, 0.9, "action-token"),
                fee_row(1, fee_token, 11, 0.9, "fee-token"),
            ],
            1,
            fee_token,
            None,
            SystemTime::now(),
            BroadcasterFeePolicy::default(),
            None,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fees_id, "fee-token");
        assert_eq!(candidates[0].token, fee_token);
    }

    #[test]
    fn specific_public_broadcaster_fails_when_not_available_for_fee_token() {
        let action_token = address(0x45);
        let fee_token = address(0x46);
        let railgun_address = sample_railgun_address(51);
        let candidates = public_broadcaster_candidates(
            &[fee_row_with_broadcaster_seed(
                1,
                action_token,
                10,
                0.9,
                "action-only",
                51,
            )],
            1,
            fee_token,
            None,
            SystemTime::now(),
            BroadcasterFeePolicy::default(),
            None,
        );

        let error = select_public_broadcaster_with_policy(
            &candidates,
            &PublicBroadcasterSelection::Specific { railgun_address },
            BroadcasterFeePolicy::default(),
        )
        .expect_err("specific broadcaster should not match action-token row");

        assert!(error.to_string().contains("no longer eligible"));
    }

    #[test]
    fn public_broadcaster_selection_sorts_by_fee_then_reliability() {
        let token = address(0x23);
        let candidates = eligible_public_broadcasters(
            &[
                fee_row_with_broadcaster_seed(1, token, 20, 0.99, "expensive", 11),
                fee_row_with_broadcaster_seed(1, token, 10, 0.50, "cheap-low-rel", 12),
                fee_row_with_broadcaster_seed(1, token, 10, 0.90, "cheap-high-rel", 13),
            ],
            1,
            token,
            None,
            SystemTime::now(),
        );

        let sorted = sort_specific_public_broadcasters(candidates.clone());
        let ids: Vec<_> = sorted
            .iter()
            .map(|candidate| candidate.fees_id.as_str())
            .collect();
        assert_eq!(ids, vec!["cheap-high-rel", "cheap-low-rel", "expensive"]);
        let cheap_low_rel_address = candidates
            .iter()
            .find(|candidate| candidate.fees_id == "cheap-low-rel")
            .expect("cheap-low-rel candidate")
            .railgun_address
            .clone();

        let selected = select_public_broadcaster(
            &candidates,
            &PublicBroadcasterSelection::Specific {
                railgun_address: cheap_low_rel_address,
            },
        )
        .expect("specific candidate");
        assert_eq!(selected.fees_id, "cheap-low-rel");
        assert!(
            select_public_broadcaster(&candidates, &PublicBroadcasterSelection::Random).is_ok()
        );
    }

    #[test]
    fn random_public_broadcaster_selection_prefers_non_poi_required_candidate() {
        let token = address(0x27);
        let mut poi_required = fee_row_with_broadcaster_seed(1, token, 10, 0.9, "poi", 31);
        poi_required.required_poi_list_keys = vec![Arc::from("poi-list")];
        let candidates = eligible_public_broadcasters(
            &[
                poi_required,
                fee_row_with_broadcaster_seed(1, token, 10, 0.9, "supported", 32),
            ],
            1,
            token,
            None,
            SystemTime::now(),
        );

        let selected = select_public_broadcaster(&candidates, &PublicBroadcasterSelection::Random)
            .expect("random supported candidate");

        assert_eq!(selected.fees_id, "supported");
        assert!(selected.required_poi_list_keys.is_empty());
    }

    #[test]
    fn public_broadcaster_specific_selection_survives_fees_id_refresh() {
        let token = address(0x24);
        let railgun_address = sample_railgun_address(21);
        let candidates = eligible_public_broadcasters(
            &[fee_row_with_broadcaster_seed(
                1,
                token,
                10,
                0.9,
                "fresh-fees-id",
                21,
            )],
            1,
            token,
            None,
            SystemTime::now(),
        );

        let selected = select_public_broadcaster(
            &candidates,
            &PublicBroadcasterSelection::Specific { railgun_address },
        )
        .expect("specific candidate by stable address");

        assert_eq!(selected.fees_id, "fresh-fees-id");
    }

    #[test]
    fn public_broadcaster_fee_policy_classifies_anchor_bounds() {
        let token = address(0x28);
        let policy = BroadcasterFeePolicy::default();
        let candidates = public_broadcaster_candidates(
            &[
                fee_row(1, token, 89, 0.9, "below"),
                fee_row(1, token, 90, 0.9, "lower-bound"),
                fee_row(1, token, 150, 0.9, "upper-bound"),
                fee_row(1, token, 151, 0.9, "above"),
            ],
            1,
            token,
            None,
            SystemTime::now(),
            policy,
            Some(uint!(100_U256)),
        );

        let eligible_ids = fee_policy_eligible_public_broadcasters(&candidates, policy)
            .into_iter()
            .map(|candidate| candidate.fees_id)
            .collect::<Vec<_>>();
        assert_eq!(eligible_ids, vec!["lower-bound", "upper-bound"]);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.fees_id == "below"
                    && matches!(
                        candidate.fee_policy_status,
                        BroadcasterFeePolicyStatus::Suspicious {
                            premium_bps: Some(-1100),
                            ..
                        }
                    ))
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.fees_id == "above"
                    && matches!(
                        candidate.fee_policy_status,
                        BroadcasterFeePolicyStatus::Suspicious {
                            premium_bps: Some(5100),
                            ..
                        }
                    ))
        );
    }

    #[test]
    fn public_broadcaster_fee_policy_allows_unknown_anchor_rows() {
        let token = address(0x29);
        let policy = BroadcasterFeePolicy::default();
        let candidates = public_broadcaster_candidates(
            &[fee_row(1, token, 1_000_000, 0.9, "raw")],
            1,
            token,
            None,
            SystemTime::now(),
            policy,
            None,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].fee_policy_status,
            BroadcasterFeePolicyStatus::UnknownAnchor
        );
        assert_eq!(
            fee_policy_eligible_public_broadcasters(&candidates, policy).len(),
            1
        );
    }

    #[test]
    fn public_broadcaster_policy_uses_fixed_anchor_without_cache() {
        let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");

        assert_eq!(
            fixed_token_anchor_rate(1, weth),
            Some(uint!(1_000_000_000_000_000_000_U256))
        );
        assert_eq!(
            public_broadcaster_anchor_rate_for_policy(None, 1, weth),
            Some(uint!(1_000_000_000_000_000_000_U256))
        );
    }

    #[test]
    fn public_broadcaster_fee_breakdown_splits_gas_and_margin() {
        let breakdown = public_broadcaster_fee_breakdown(
            uint!(2_500_U256),
            10,
            100,
            Some(uint!(2_000_000_000_000_000_000_U256)),
        );

        assert_eq!(breakdown.native_gas_cost, uint!(1_010_U256));
        assert_eq!(breakdown.fee_token_gas_cost, Some(uint!(2_020_U256)));
        assert_eq!(
            breakdown.broadcaster_fee,
            Some(PublicBroadcasterFeeMargin::Positive(uint!(480_U256)))
        );
    }

    #[test]
    fn public_broadcaster_fee_breakdown_handles_negative_and_missing_anchor() {
        let negative = public_broadcaster_fee_breakdown(
            uint!(1_000_U256),
            10,
            100,
            Some(uint!(2_000_000_000_000_000_000_U256)),
        );
        let missing = public_broadcaster_fee_breakdown(uint!(1_000_U256), 10, 100, None);

        assert_eq!(
            negative.broadcaster_fee,
            Some(PublicBroadcasterFeeMargin::Negative(uint!(1_020_U256)))
        );
        assert_eq!(missing.native_gas_cost, uint!(1_010_U256));
        assert_eq!(missing.fee_token_gas_cost, None);
        assert_eq!(missing.broadcaster_fee, None);
    }

    #[test]
    fn public_broadcaster_fee_policy_override_includes_suspicious_rows() {
        let token = address(0x2a);
        let policy = BroadcasterFeePolicy::default();
        let allow_policy = policy.with_allow_suspicious_broadcasters(true);
        let candidates = public_broadcaster_candidates(
            &[fee_row(1, token, 151, 0.9, "above")],
            1,
            token,
            None,
            SystemTime::now(),
            policy,
            Some(uint!(100_U256)),
        );

        assert!(
            select_public_broadcaster_with_policy(
                &candidates,
                &PublicBroadcasterSelection::Random,
                policy
            )
            .is_err()
        );
        assert!(
            select_public_broadcaster_with_policy(
                &candidates,
                &PublicBroadcasterSelection::Random,
                allow_policy
            )
            .is_ok()
        );
    }

    #[test]
    fn specific_public_broadcaster_drift_rechecks_latest_fee_policy() {
        let token = address(0x2b);
        let railgun_address = sample_railgun_address(41);
        let policy = BroadcasterFeePolicy::default();
        let initial = public_broadcaster_candidates(
            &[fee_row_with_broadcaster_seed(
                1, token, 100, 0.9, "initial", 41,
            )],
            1,
            token,
            None,
            SystemTime::now(),
            policy,
            Some(uint!(100_U256)),
        );
        let selection = PublicBroadcasterSelection::Specific { railgun_address };
        assert!(select_public_broadcaster_with_policy(&initial, &selection, policy).is_ok());

        let drifted = public_broadcaster_candidates(
            &[fee_row_with_broadcaster_seed(
                1, token, 151, 0.9, "drifted", 41,
            )],
            1,
            token,
            None,
            SystemTime::now(),
            policy,
            Some(uint!(100_U256)),
        );
        let error = select_public_broadcaster_with_policy(&drifted, &selection, policy)
            .expect_err("drifted broadcaster should be blocked");
        assert!(error.to_string().contains("outside the allowed range"));
        assert!(
            select_public_broadcaster_with_policy(
                &drifted,
                &selection,
                policy.with_allow_suspicious_broadcasters(true)
            )
            .is_ok()
        );
    }

    #[test]
    fn broadcaster_fee_amount_uses_same_token_fee_rate() {
        let fee = broadcaster_fee_amount(
            uint!(2_000_000_000_000_000_000_U256),
            150_000,
            20_000_000_000,
        );

        assert_eq!(fee, uint!(6_000_000_000_000_000_U256));
    }

    #[test]
    fn railgun_protocol_fee_uses_hardcoded_unshield_bps() {
        let amount = uint!(1_000_000_U256);

        assert_eq!(
            super::railgun_protocol_fee_amount(amount, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS),
            uint!(2_500_U256)
        );
        assert_eq!(
            super::railgun_protocol_fee_amount(amount, U256::ZERO),
            U256::ZERO
        );
    }

    #[test]
    fn public_broadcaster_fee_stabilization_accepts_covering_fee() {
        let required = uint!(1_000_U256);

        assert!(broadcaster_fee_covers(required, required));
        assert!(broadcaster_fee_covers(required + uint!(1_U256), required));
        assert!(!broadcaster_fee_covers(required - uint!(1_U256), required));
    }

    #[test]
    fn public_broadcaster_fee_stabilization_buffers_retries() {
        assert_eq!(
            buffered_public_broadcaster_fee(uint!(10_000_U256)),
            uint!(10_100_U256)
        );
        assert_eq!(
            buffered_public_broadcaster_fee(uint!(1_U256)),
            uint!(2_U256)
        );
    }

    #[test]
    fn public_broadcaster_fee_mode_deducts_or_adds_fee() {
        let entered = uint!(100_U256);
        let fee = uint!(7_U256);

        let deducted = public_broadcaster_amount_split(
            entered,
            fee,
            PublicBroadcasterFeeMode::DeductFromAmount,
        )
        .expect("deduct split");
        assert_eq!(deducted.receiver_amount, uint!(93_U256));
        assert_eq!(deducted.total_private_spend, entered);

        let added =
            public_broadcaster_amount_split(entered, fee, PublicBroadcasterFeeMode::AddToAmount)
                .expect("add split");
        assert_eq!(added.receiver_amount, entered);
        assert_eq!(added.total_private_spend, uint!(107_U256));
    }

    #[test]
    fn different_token_public_broadcaster_fee_mode_is_separate_add_on() {
        let entered = uint!(100_U256);
        let fee = uint!(7_U256);

        let split = public_broadcaster_amount_split_for_tokens(
            entered,
            fee,
            PublicBroadcasterFeeMode::DeductFromAmount,
            false,
        )
        .expect("different-token split");

        assert_eq!(split.entered_amount, entered);
        assert_eq!(split.receiver_amount, entered);
        assert_eq!(split.total_private_spend, entered);
        assert_eq!(split.fee_amount, fee);
        assert_eq!(split.fee_mode, PublicBroadcasterFeeMode::AddToAmount);
        assert_eq!(
            public_broadcaster_max_entered_amount_for_tokens(
                uint!(123_U256),
                fee,
                PublicBroadcasterFeeMode::DeductFromAmount,
                false,
            ),
            uint!(123_U256)
        );
    }

    #[test]
    fn public_broadcaster_build_error_distinguishes_fee_token_balance() {
        let report = public_broadcaster_build_error(
            BuildError::InsufficientFeeTokenBalance(uint!(123_U256)),
            uint!(7_U256),
            PublicBroadcasterFeeMode::AddToAmount,
            false,
        );

        assert_eq!(
            report.to_string(),
            "public broadcaster fee-token max spendable: 123"
        );
    }

    #[test]
    fn public_broadcaster_fee_mode_rejects_deducting_full_amount() {
        assert!(
            public_broadcaster_amount_split(
                uint!(7_U256),
                uint!(7_U256),
                PublicBroadcasterFeeMode::DeductFromAmount,
            )
            .is_err()
        );
    }

    #[test]
    fn public_broadcaster_max_entered_amount_depends_on_fee_mode() {
        let max_receiver_amount = uint!(100_U256);
        let fee = uint!(7_U256);

        assert_eq!(
            public_broadcaster_max_entered_amount(
                max_receiver_amount,
                fee,
                PublicBroadcasterFeeMode::DeductFromAmount,
            ),
            uint!(107_U256)
        );
        assert_eq!(
            public_broadcaster_max_entered_amount(
                max_receiver_amount,
                fee,
                PublicBroadcasterFeeMode::AddToAmount,
            ),
            max_receiver_amount
        );
    }

    #[test]
    fn public_broadcaster_estimate_preserves_fee_mode_amount_split() {
        let token = address(0x25);
        let broadcaster = eligible_public_broadcasters(
            &[fee_row(
                1,
                token,
                1_000_000_000_000_000_000,
                0.9,
                "fee-mode",
            )],
            1,
            token,
            None,
            SystemTime::now(),
        )
        .into_iter()
        .next()
        .expect("candidate");
        let entered = uint!(1_000_000_000_U256);
        let selected_total = uint!(2_000_000_000_U256);

        let deducted = approximate_public_broadcaster_cost(
            broadcaster.clone(),
            token,
            token,
            entered,
            PublicBroadcasterFeeMode::DeductFromAmount,
            U256::ZERO,
            100,
            U256::ZERO,
            |_split| {
                let selection = selection_info(selected_total, 1, 1, 2, 0, selected_total);
                Ok(send_approximate_shape(&selection, selected_total))
            },
        )
        .expect("deduct estimate");
        assert_eq!(deducted.entered_amount, entered);
        assert_eq!(deducted.total_private_spend, entered);
        assert_eq!(deducted.receiver_amount + deducted.fee_amount, entered);
        assert_eq!(deducted.protocol_fee_amount, U256::ZERO);
        assert_eq!(deducted.recipient_amount, deducted.receiver_amount);
        assert_eq!(
            deducted.fee_mode,
            PublicBroadcasterFeeMode::DeductFromAmount
        );

        let added = approximate_public_broadcaster_cost(
            broadcaster,
            token,
            token,
            entered,
            PublicBroadcasterFeeMode::AddToAmount,
            U256::ZERO,
            100,
            U256::ZERO,
            |_split| {
                let selection = selection_info(selected_total, 1, 1, 2, 0, selected_total);
                Ok(send_approximate_shape(&selection, selected_total))
            },
        )
        .expect("add estimate");
        assert_eq!(added.entered_amount, entered);
        assert_eq!(added.receiver_amount, entered);
        assert_eq!(added.total_private_spend, entered + added.fee_amount);
        assert_eq!(added.protocol_fee_amount, U256::ZERO);
        assert_eq!(added.recipient_amount, added.receiver_amount);
        assert_eq!(added.fee_mode, PublicBroadcasterFeeMode::AddToAmount);
    }

    #[test]
    fn public_broadcaster_estimate_reports_separate_fee_token_amounts() {
        let action_token = address(0x41);
        let fee_token = address(0x42);
        let broadcaster = eligible_public_broadcasters(
            &[fee_row(
                1,
                fee_token,
                1_000_000_000_000_000_000,
                0.9,
                "separate-fee",
            )],
            1,
            fee_token,
            None,
            SystemTime::now(),
        )
        .into_iter()
        .next()
        .expect("candidate");
        let entered = uint!(1_000_000_000_U256);
        let max_receiver = uint!(2_000_000_000_U256);
        let seed_shape = ApproximateTransactionShape {
            transaction_count: 2,
            input_count: 2,
            private_output_count: 3,
            public_output_count: 0,
            max_receiver_amount: max_receiver,
            unwrap: false,
            send: true,
        };
        let initial_fee_amount =
            initial_separate_token_public_broadcaster_fee(&broadcaster, 100, seed_shape);
        let mut observed_fee_amounts = Vec::new();

        let estimate = approximate_public_broadcaster_cost(
            broadcaster,
            action_token,
            fee_token,
            entered,
            PublicBroadcasterFeeMode::DeductFromAmount,
            U256::ZERO,
            100,
            initial_fee_amount,
            |split| {
                observed_fee_amounts.push(split.fee_amount);
                let selection = selection_info(max_receiver, 2, 2, 3, 0, max_receiver);
                Ok(send_approximate_shape(&selection, max_receiver))
            },
        )
        .expect("separate-token estimate");

        assert_eq!(estimate.action_token, action_token);
        assert_eq!(estimate.fee_token, fee_token);
        assert_eq!(estimate.entered_amount, entered);
        assert_eq!(estimate.receiver_amount, entered);
        assert_eq!(estimate.total_private_spend, entered);
        assert_eq!(estimate.recipient_amount, entered);
        assert_eq!(estimate.fee_mode, PublicBroadcasterFeeMode::AddToAmount);
        assert_eq!(estimate.max_receiver_amount, max_receiver);
        assert_eq!(estimate.max_entered_amount, max_receiver);
        assert_eq!(estimate.transaction_count, 2);
        assert!(!initial_fee_amount.is_zero());
        assert_eq!(observed_fee_amounts.first(), Some(&initial_fee_amount));
        assert!(observed_fee_amounts.iter().all(|fee| !fee.is_zero()));
    }

    #[test]
    fn public_broadcaster_unshield_estimate_includes_protocol_fee() {
        let token = address(0x26);
        let broadcaster = eligible_public_broadcasters(
            &[fee_row(
                1,
                token,
                1_000_000_000_000_000_000,
                0.9,
                "unshield-fee",
            )],
            1,
            token,
            None,
            SystemTime::now(),
        )
        .into_iter()
        .next()
        .expect("candidate");
        let entered = uint!(1_000_000_U256);
        let selected_total = uint!(2_000_000_U256);

        let estimate = approximate_public_broadcaster_cost(
            broadcaster,
            token,
            token,
            entered,
            PublicBroadcasterFeeMode::AddToAmount,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
            100,
            U256::ZERO,
            |_split| {
                let selection = selection_info(selected_total, 1, 1, 1, 1, selected_total);
                Ok(unshield_approximate_shape(
                    &selection,
                    selected_total,
                    false,
                ))
            },
        )
        .expect("unshield estimate");

        let expected_fee = estimate.receiver_amount * uint!(25_U256) / uint!(10_000_U256);
        assert_eq!(estimate.protocol_fee_bps, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS);
        assert_eq!(estimate.protocol_fee_amount, expected_fee);
        assert_eq!(
            estimate.recipient_amount,
            estimate.receiver_amount - expected_fee
        );
    }

    #[test]
    fn approximate_public_broadcaster_gas_tracks_transaction_shape() {
        let base = approximate_public_broadcaster_gas(ApproximateTransactionShape {
            transaction_count: 1,
            input_count: 1,
            private_output_count: 2,
            public_output_count: 0,
            max_receiver_amount: U256::ZERO,
            unwrap: false,
            send: true,
        });
        let larger = approximate_public_broadcaster_gas(ApproximateTransactionShape {
            transaction_count: 2,
            input_count: 2,
            private_output_count: 3,
            public_output_count: 1,
            max_receiver_amount: U256::ZERO,
            unwrap: true,
            send: false,
        });

        assert!(larger > base);
    }

    #[test]
    fn approximate_public_broadcaster_gas_applies_safety_uplift() {
        let gas = approximate_public_broadcaster_gas(ApproximateTransactionShape {
            transaction_count: 2,
            input_count: 2,
            private_output_count: 4,
            public_output_count: 0,
            max_receiver_amount: U256::ZERO,
            unwrap: false,
            send: true,
        });

        assert_eq!(gas, 1_803_200);
    }

    #[test]
    fn public_broadcaster_gas_limit_uses_configured_buffer() {
        assert_eq!(
            public_broadcaster_gas_limit_with_buffer(210_000, 250_000),
            460_000
        );
    }

    #[test]
    fn approximate_shapes_include_broadcaster_fee_output_and_change() {
        let send_selection = selection_info(uint!(15_U256), 2, 1, 3, 0, uint!(13_U256));
        let send = send_approximate_shape(&send_selection, uint!(13_U256));
        assert_eq!(send.input_count, 2);
        assert_eq!(send.transaction_count, 1);
        assert_eq!(send.private_output_count, 3);
        assert_eq!(send.public_output_count, 0);

        let unshield_selection = selection_info(uint!(12_U256), 1, 1, 1, 1, uint!(10_U256));
        let unshield = unshield_approximate_shape(&unshield_selection, uint!(10_U256), true);
        assert_eq!(unshield.input_count, 1);
        assert_eq!(unshield.transaction_count, 1);
        assert_eq!(unshield.private_output_count, 1);
        assert_eq!(unshield.public_output_count, 1);
        assert!(unshield.unwrap);
    }

    #[test]
    fn public_broadcaster_transact_envelope_roundtrips() {
        let (candidate, broadcaster) = sample_public_broadcaster_candidate(9);
        let params = public_broadcaster_transact_params(
            &candidate,
            address(0x33),
            Bytes::from(vec![1, 2, 3, 4]),
            20_000_000_000,
            BTreeMap::new(),
        );

        let encrypted = EncryptedTransactRequest::encrypt_with_seed(
            candidate.viewing_public_key,
            &params,
            [8u8; 32],
        )
        .expect("encrypt request");
        let payload = encrypted.to_transact_payload().expect("serialize envelope");
        let value: serde_json::Value = serde_json::from_slice(&payload).expect("json envelope");
        assert_eq!(value["method"], "transact");
        assert!(value["params"]["encryptedData"].is_array());
        assert_eq!(transact_topic(1), "/railgun/v2/0-1-transact/json");

        let decrypted = try_decrypt_transact_request(
            &broadcaster.viewing_private_key,
            encrypted.pubkey,
            &encrypted.encrypted_data,
        )
        .expect("decrypt request")
        .expect("request for broadcaster");
        assert_eq!(decrypted.params.fees_id.as_deref(), Some("fees-id"));
        assert_eq!(
            decrypted.params.min_gas_price,
            Some(uint!(20_000_000_000_U256))
        );
        assert!(
            decrypted
                .params
                .pre_transaction_pois_per_txid_leaf_per_list
                .is_empty()
        );
    }

    #[test]
    fn public_broadcaster_transact_payload_includes_single_chunk_poi() {
        let (mut candidate, broadcaster) = sample_public_broadcaster_candidate(10);
        let list_key = FixedBytes::from([0x88; 32]);
        let txid_leaf = FixedBytes::from([0x99; 32]);
        candidate.required_poi_list_keys = vec![hex::encode(list_key)];
        let required_keys = candidate
            .parsed_required_poi_list_keys()
            .expect("required list keys");
        let params = public_broadcaster_transact_params(
            &candidate,
            address(0x33),
            Bytes::from(vec![1, 2, 3, 4]),
            20_000_000_000,
            sample_poi_map(&required_keys, &[txid_leaf]),
        );

        let encrypted = EncryptedTransactRequest::encrypt_with_seed(
            candidate.viewing_public_key,
            &params,
            [8u8; 32],
        )
        .expect("encrypt request");
        let decrypted = try_decrypt_transact_request(
            &broadcaster.viewing_private_key,
            encrypted.pubkey,
            &encrypted.encrypted_data,
        )
        .expect("decrypt request")
        .expect("request for broadcaster");

        let per_leaf = decrypted
            .params
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&list_key)
            .expect("list key");
        assert_eq!(per_leaf.len(), 1);
        assert!(per_leaf.contains_key(&txid_leaf));
    }

    #[test]
    fn public_broadcaster_transact_payload_includes_batched_poi() {
        let (mut candidate, broadcaster) = sample_public_broadcaster_candidate(11);
        let list_keys = [FixedBytes::from([0x81; 32]), FixedBytes::from([0x82; 32])];
        let leaves = [FixedBytes::from([0x91; 32]), FixedBytes::from([0x92; 32])];
        candidate.required_poi_list_keys = list_keys.iter().map(hex::encode).collect();
        let required_keys = candidate
            .parsed_required_poi_list_keys()
            .expect("required list keys");
        let params = public_broadcaster_transact_params(
            &candidate,
            address(0x33),
            Bytes::from(vec![1, 2, 3, 4]),
            20_000_000_000,
            sample_poi_map(&required_keys, &leaves),
        );

        let encrypted = EncryptedTransactRequest::encrypt_with_seed(
            candidate.viewing_public_key,
            &params,
            [8u8; 32],
        )
        .expect("encrypt request");
        let decrypted = try_decrypt_transact_request(
            &broadcaster.viewing_private_key,
            encrypted.pubkey,
            &encrypted.encrypted_data,
        )
        .expect("decrypt request")
        .expect("request for broadcaster");

        let poi_map = decrypted.params.pre_transaction_pois_per_txid_leaf_per_list;
        assert_eq!(poi_map.len(), 2);
        for list_key in list_keys {
            let per_leaf = poi_map.get(&list_key).expect("list key");
            assert_eq!(per_leaf.len(), 2);
            for leaf in leaves {
                assert!(per_leaf.contains_key(&leaf));
            }
        }
    }

    #[test]
    fn public_broadcaster_invalid_poi_list_key_fails_preparation() {
        let (mut candidate, _) = sample_public_broadcaster_candidate(12);
        candidate.required_poi_list_keys = vec!["poi-list".to_string()];

        let error = candidate
            .parsed_required_poi_list_keys()
            .expect_err("invalid POI list key should fail");

        assert!(error.to_string().contains("invalid required POI list key"));
    }

    #[test]
    fn public_broadcaster_response_decodes_tx_hash() {
        let shared_key = [7u8; 32];
        let tx_hash = TxHash::from([3u8; 32]);
        let response =
            DecryptedTransactResponse::encrypted_tx_hash_message(None, &shared_key, tx_hash)
                .expect("response payload");

        let decoded = decode_public_broadcaster_response(&shared_key, &response)
            .expect("decode response")
            .expect("decryptable response");

        assert_eq!(
            decoded,
            PublicBroadcasterResultKind::Submitted {
                tx_hash: tx_hash.to_string()
            }
        );
    }

    #[test]
    fn public_broadcaster_republish_loop_retries_until_stopped() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        runtime.block_on(async {
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
            let handle = tokio::spawn(public_broadcaster_republish_loop(
                stop_rx,
                Duration::from_millis(10),
                move |attempt| {
                    let attempt_tx = attempt_tx.clone();
                    async move {
                        attempt_tx.send(attempt).expect("record attempt");
                        Ok(())
                    }
                },
            ));

            let first = tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .expect("first retry timed out")
                .expect("first retry attempt");
            let second = tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .expect("second retry timed out")
                .expect("second retry attempt");
            let _ = stop_tx.send(());
            handle.await.expect("republish loop joined");

            assert_eq!(first, 2);
            assert_eq!(second, 3);
        });
    }

    #[test]
    fn public_broadcaster_republish_loop_stops_before_first_retry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        runtime.block_on(async {
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
            let handle = tokio::spawn(public_broadcaster_republish_loop(
                stop_rx,
                Duration::from_millis(50),
                move |attempt| {
                    let attempt_tx = attempt_tx.clone();
                    async move {
                        attempt_tx.send(attempt).expect("record attempt");
                        Ok(())
                    }
                },
            ));
            let _ = stop_tx.send(());
            handle.await.expect("republish loop joined");

            assert!(attempt_rx.try_recv().is_err());
        });
    }

    #[test]
    fn wrapped_native_detection_matches_supported_chains() {
        let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");
        assert!(is_wrapped_native_token(1, weth));
        assert!(!is_wrapped_native_token(1, address(0x11)));
        assert!(wrapped_native_token_for_chain(999_999).is_none());
    }
}
