use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use alloy::eips::Encodable2718;
use alloy::hex;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder as _};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, address};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use broadcaster_core::contracts::shield::{
    build_approve_calldata, build_shield_calldata, derive_shield_private_key,
};
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, build_transact_request_payload,
    encrypt_transact_request, railgun_txid_leaf_hash,
};
use broadcaster_core::transact_response::{
    DecryptedTransactResponse, try_decrypt_transact_response_message,
};
use broadcaster_monitor::FeeRow;
use eyre::{Report, Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore, PendingOutputPoiContextRecord, PendingOutputPoiRole};
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::tx::{
    BroadcasterFeeOutput, BuildError, PreTransactionPoiGenerationRequest, PreTransactionPoiMap,
    SendPlan, SendRequest as RailgunSendRequest, TransactionPlanChunk, UnshieldMode, UnshieldPlan,
    UnshieldRequest as RailgunUnshieldRequest, generate_pre_transaction_pois, max_send_spendable,
    max_unshield_spendable, send_selection_info, send_selection_info_with_broadcaster_fee,
    unshield_selection_info, unshield_selection_info_with_broadcaster_fee,
};
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{
    Note, PoiStatus, ProverService, TransactionBuilder, Utxo, UtxoCommitmentKind, UtxoSource,
    WalletKeys, WalletUtxo,
};
use rand::seq::IndexedRandom;
use reqwest::Url;
use serde::Serialize;
use sync_service::{
    ChainConfig, ChainConfigDefaults, ChainKey, SyncManager, SyncProgressSender, WalletConfig,
    WalletHandle,
};
pub use sync_service::{SyncProgressStage, SyncProgressUpdate};
use tokio::sync::watch;
use waku_relay::client::{Client as WakuClient, PUBSUB_PATH};
use zeroize::{Zeroize, Zeroizing};

pub use waku_relay::client::Client as PublicBroadcasterWakuClient;

pub mod vault;

const DEFAULT_QUERY_RPC_COOLDOWN: Duration = Duration::from_secs(5);
const DEFAULT_BLOCK_RANGE: u64 = 500;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);
const GAS_LIMIT_BUFFER: u64 = 100_000;
const GAS_PRICE_BUFFER_NUMERATOR: u128 = 105;
const GAS_PRICE_BUFFER_DENOMINATOR: u128 = 100;
const PUBLIC_BROADCASTER_FEE_ATTEMPTS: usize = 5;
const PUBLIC_BROADCASTER_FEE_BUFFER_DIVISOR: u64 = 100;
const APPROX_BASE_GAS: u64 = 650_000;
const APPROX_GAS_PER_INPUT: u64 = 155_000;
const APPROX_GAS_PER_PRIVATE_OUTPUT: u64 = 85_000;
const APPROX_GAS_PER_PUBLIC_OUTPUT: u64 = 65_000;
const APPROX_GAS_PER_TRANSACTION: u64 = 120_000;
const APPROX_SEND_EXTRA_GAS: u64 = 40_000;
const APPROX_UNWRAP_EXTRA_GAS: u64 = 50_000;
const APPROX_SAFETY_GAS: u64 = 150_000;
const PUBLIC_BROADCASTER_MAX_ENTERED_AMOUNT_ERROR: &str = "public broadcaster max entered amount: ";
const FEE_BASIS_POINTS_DENOMINATOR: u16 = 10_000;
pub const RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS: u16 = 25;

/// WETH `deposit()` function selector - no arguments, ETH value is the deposit
/// amount.
const WETH_DEPOSIT_SELECTOR: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];

/// Shared HTTP context built once from an optional proxy and passed into wallet
/// operations that issue network requests.
#[derive(Clone)]
pub struct HttpContext {
    /// Async HTTP client for reqwest and alloy usage.
    pub client: reqwest::Client,
    /// Proxy URL for components that build their own client, such as the
    /// blocking artifact downloader.
    pub proxy_url: Option<Url>,
}

pub fn build_http_client(proxy: Option<&Url>) -> Result<HttpContext> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = proxy {
        tracing::info!(%proxy_url, "routing all HTTP traffic through proxy");
        let p = reqwest::Proxy::all(proxy_url.as_str())
            .wrap_err_with(|| format!("invalid proxy URL {proxy_url}"))?;
        builder = builder.proxy(p);
    }
    let client = builder.build().wrap_err("build HTTP client")?;
    Ok(HttpContext {
        client,
        proxy_url: proxy.cloned(),
    })
}

pub struct ListUtxosRequest {
    pub mnemonic: String,
    pub chain_id: u64,
    pub db_path: PathBuf,
    pub init_block_number: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub use_indexed_wallet_catch_up: bool,
}

pub struct WalletSessionRequest {
    pub mnemonic: String,
    pub chain_id: u64,
    pub db_path: PathBuf,
    pub init_block_number: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub use_indexed_wallet_catch_up: bool,
    pub progress_tx: Option<SyncProgressSender>,
}

pub struct WalletChainSessionRequest {
    pub mnemonic: String,
    pub chain_id: u64,
    pub init_block_number: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub use_indexed_wallet_catch_up: bool,
    pub progress_tx: Option<SyncProgressSender>,
}

pub struct ViewWalletChainSessionRequest {
    pub view_session: Arc<vault::DesktopViewSession>,
    pub chain_id: u64,
    pub init_block_number: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub use_indexed_wallet_catch_up: bool,
    pub rewind_wallet_cache: bool,
    pub progress_tx: Option<SyncProgressSender>,
}

impl From<ListUtxosRequest> for WalletSessionRequest {
    fn from(value: ListUtxosRequest) -> Self {
        Self {
            mnemonic: value.mnemonic,
            chain_id: value.chain_id,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
            sync_to_block: value.sync_to_block,
            use_indexed_wallet_catch_up: value.use_indexed_wallet_catch_up,
            progress_tx: None,
        }
    }
}

impl From<WalletSessionRequest> for WalletChainSessionRequest {
    fn from(value: WalletSessionRequest) -> Self {
        Self {
            mnemonic: value.mnemonic,
            chain_id: value.chain_id,
            init_block_number: value.init_block_number,
            sync_to_block: value.sync_to_block,
            use_indexed_wallet_catch_up: value.use_indexed_wallet_catch_up,
            progress_tx: value.progress_tx,
        }
    }
}

pub struct ShieldRequest {
    pub chain_id: u64,
    pub token: Address,
    pub amount: String,
    pub recipient: String,
    pub private_key: String,
    pub wrap: bool,
    pub send: bool,
}

pub struct UnshieldRequest {
    pub mnemonic: String,
    pub chain_id: u64,
    pub token: Address,
    pub amount: String,
    pub recipient: Address,
    pub db_path: PathBuf,
    pub init_block_number: Option<u64>,
    pub unwrap: bool,
    pub private_key: Option<String>,
}

pub struct DesktopUnshieldCalldataRequest {
    pub chain_id: u64,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub verify_proof: bool,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopSendCalldataRequest {
    pub chain_id: u64,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub amount: U256,
    pub recipient: String,
    pub verify_proof: bool,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
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
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub verify_proof: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub waku: Arc<WakuClient>,
    pub response_timeout: Duration,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopSendPublicBroadcasterRequest {
    pub chain_id: u64,
    pub view_session: Arc<vault::DesktopViewSession>,
    pub session: Arc<WalletSession>,
    pub vault_store: Arc<vault::DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub token: Address,
    pub amount: U256,
    pub recipient: String,
    pub verify_proof: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
    pub waku: Arc<WakuClient>,
    pub response_timeout: Duration,
    pub progress_tx: Option<TransactionGenerationProgressSender>,
}

pub struct DesktopUnshieldPublicBroadcasterEstimateRequest {
    pub chain_id: u64,
    pub session: Arc<WalletSession>,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub unwrap: bool,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
}

pub struct DesktopSendPublicBroadcasterEstimateRequest {
    pub chain_id: u64,
    pub session: Arc<WalletSession>,
    pub token: Address,
    pub amount: U256,
    pub recipient: String,
    pub fee_rows: Vec<FeeRow>,
    pub selection: PublicBroadcasterSelection,
    pub fee_mode: PublicBroadcasterFeeMode,
}

#[derive(Debug, Clone)]
pub struct PublicBroadcasterCostEstimate {
    pub broadcaster: PublicBroadcasterCandidate,
    pub entered_amount: U256,
    pub receiver_amount: U256,
    pub recipient_amount: U256,
    pub total_private_spend: U256,
    pub fee_amount: U256,
    pub protocol_fee_amount: U256,
    pub protocol_fee_bps: u16,
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
    pub entered_amount: U256,
    pub receiver_amount: U256,
    pub recipient_amount: U256,
    pub total_private_spend: U256,
    pub fee_amount: U256,
    pub protocol_fee_amount: U256,
    pub protocol_fee_bps: u16,
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
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: u16,
    fee_mode: PublicBroadcasterFeeMode,
    gas_limit: u64,
    min_gas_price: u128,
}

pub trait EvmTransactionSigner {
    fn address(&self) -> Address;

    fn ethereum_wallet(&self) -> EthereumWallet;
}

pub trait EvmMessageSigner {
    fn derive_shield_private_key(&self) -> Result<[u8; 32]>;
}

pub struct SoftwareEvmSigner {
    private_key: [u8; 32],
    signer: PrivateKeySigner,
}

impl SoftwareEvmSigner {
    pub fn from_private_key_hex(private_key: &str) -> Result<Self> {
        let private_key = parse_private_key(private_key)?;
        let signer = PrivateKeySigner::from(
            SigningKey::from_bytes((&private_key).into()).wrap_err("invalid signing key")?,
        );
        Ok(Self {
            private_key,
            signer,
        })
    }
}

impl EvmTransactionSigner for SoftwareEvmSigner {
    fn address(&self) -> Address {
        self.signer.address()
    }

    fn ethereum_wallet(&self) -> EthereumWallet {
        EthereumWallet::from(self.signer.clone())
    }
}

impl EvmMessageSigner for SoftwareEvmSigner {
    fn derive_shield_private_key(&self) -> Result<[u8; 32]> {
        derive_shield_private_key(&self.private_key).wrap_err("derive shield private key")
    }
}

impl Drop for SoftwareEvmSigner {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UtxoOutput {
    pub tree: u32,
    pub position: u64,
    pub token: String,
    pub value: String,
    pub commitment_kind: String,
    pub commitment: String,
    pub npk: String,
    pub blinded_commitment: String,
    pub poi_statuses: BTreeMap<String, String>,
    pub poi_spendable: bool,
    pub source_tx_hash: String,
    pub source_block_number: u64,
    pub source_block_timestamp: u64,
    pub is_spent: bool,
    pub spent_tx_hash: Option<String>,
    pub spent_block_number: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenTotal {
    pub token: String,
    pub total: String,
    pub poi_verified_total: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListUtxosOutput {
    pub chain_id: u64,
    pub cache_key: String,
    pub utxo_count: usize,
    pub unspent_count: usize,
    pub spent_count: usize,
    pub utxos: Vec<UtxoOutput>,
    pub totals: Vec<TokenTotal>,
}

#[must_use]
pub fn max_unshield_amount_from_outputs(utxos: &[UtxoOutput], token: Address) -> U256 {
    let planner_utxos = planner_utxos_from_outputs(utxos, token);
    max_unshield_spendable(&planner_utxos, token)
}

#[must_use]
pub fn max_send_amount_from_outputs(utxos: &[UtxoOutput], token: Address) -> U256 {
    let planner_utxos = planner_utxos_from_outputs(utxos, token);
    max_send_spendable(&planner_utxos, token)
}

fn planner_utxos_from_outputs(utxos: &[UtxoOutput], token: Address) -> Vec<Utxo> {
    utxos
        .iter()
        .filter(|row| !row.is_spent)
        .filter(|row| row.poi_spendable)
        .filter_map(|row| {
            let row_token = row.token.parse::<Address>().ok()?;
            if row_token != token {
                return None;
            }
            let value = U256::from_str_radix(&row.value, 10).ok()?;
            if value.is_zero() {
                return None;
            }
            Some(Utxo::new(
                Note::new_unshield(Address::ZERO, token, value),
                row.tree,
                row.position,
                UtxoSource {
                    tx_hash: FixedBytes::ZERO,
                    block_number: row.source_block_number,
                    block_timestamp: row.source_block_timestamp,
                },
                UtxoCommitmentKind::Transact,
            ))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnshieldOutput {
    pub to: Address,
    pub data: String,
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnshieldSendOutput {
    pub tx_hash: String,
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TxOutput {
    pub to: Address,
    pub data: String,
    /// ETH value to send with the transaction, in wei as a decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldOutput {
    /// Present only when wrapping is requested: calls `WETH.deposit()` with ETH
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap: Option<TxOutput>,
    pub approve: TxOutput,
    pub shield: TxOutput,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldResult {
    Calldata(ShieldOutput),
    Sent(ShieldSendOutput),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnshieldResult {
    Calldata(UnshieldOutput),
    Sent(UnshieldSendOutput),
}

pub struct WalletSession {
    pub chain_id: u64,
    pub cache_key: String,
    pub ready_rx: watch::Receiver<bool>,
    pub snapshots_rx: watch::Receiver<Arc<ListUtxosOutput>>,
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
        let utxos = self.handle.utxos.read().await;
        poi_verified_unspent_utxos_from_records(&utxos)
    }
}

fn poi_verified_unspent_utxos_from_records(utxos: &[WalletUtxo]) -> Vec<Utxo> {
    let active_poi_list_keys = default_active_poi_list_keys();
    utxos
        .iter()
        .filter(|entry| !entry.is_spent())
        .filter(|entry| entry.utxo.poi.is_valid_for_lists(&active_poi_list_keys))
        .map(|entry| entry.utxo.clone())
        .collect()
}

pub fn parse_unshield_amount(input: &str, decimals: Option<u8>) -> Result<U256> {
    let input = input.trim();
    if input.is_empty() {
        return Err(eyre!("amount is required"));
    }

    if let Some(decimals) = decimals {
        parse_scaled_amount(input, decimals)
    } else {
        if !input.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(eyre!("unknown token amounts must be raw integer units"));
        }
        U256::from_str_radix(input, 10).wrap_err("invalid raw amount")
    }
}

pub fn parse_send_amount(input: &str, decimals: Option<u8>) -> Result<U256> {
    parse_unshield_amount(input, decimals)
}

pub fn parse_railgun_recipient(input: &str) -> Result<AddressData> {
    let input = input.trim();
    if input.is_empty() {
        return Err(eyre!("recipient 0zk address is required"));
    }
    let railgun_addr = RailgunAddress::from(input);
    AddressData::try_from(&railgun_addr).wrap_err("invalid recipient 0zk address")
}

pub fn eligible_public_broadcasters_for_asset(
    rows: &[FeeRow],
    chain_id: u64,
    token: Address,
    unwrap: bool,
) -> Result<Vec<PublicBroadcasterCandidate>> {
    let chain_defaults = chain_defaults_for_chain(chain_id, UnsupportedChainMessage::Generic)?;
    Ok(eligible_public_broadcasters(
        rows,
        chain_id,
        token,
        if unwrap {
            Some(chain_defaults.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
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
        .filter_map(candidate_from_fee_row)
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
    match selection {
        PublicBroadcasterSelection::Random => {
            let supported_candidates = candidates
                .iter()
                .filter(|candidate| candidate.required_poi_list_keys.is_empty())
                .collect::<Vec<_>>();
            let selected = if supported_candidates.is_empty() {
                candidates.choose(&mut rand::rng()).cloned()
            } else {
                supported_candidates
                    .choose(&mut rand::rng())
                    .copied()
                    .cloned()
            };
            selected.ok_or_else(|| eyre!("no eligible public broadcaster for selected token"))
        }
        PublicBroadcasterSelection::Specific { railgun_address } => candidates
            .iter()
            .find(|candidate| candidate.railgun_address == *railgun_address)
            .cloned()
            .ok_or_else(|| eyre!("selected public broadcaster is no longer eligible")),
    }
}

#[must_use]
pub fn broadcaster_fee_amount(
    token_fee_per_unit_gas: U256,
    gas_limit: u64,
    gas_price: u128,
) -> U256 {
    const FEE_SCALE: u128 = 1_000_000_000_000_000_000;
    token_fee_per_unit_gas * U256::from(gas_limit) * U256::from(gas_price) / U256::from(FEE_SCALE)
}

fn broadcaster_fee_covers(available_fee: U256, required_fee: U256) -> bool {
    available_fee >= required_fee
}

fn buffered_public_broadcaster_fee(required_fee: U256) -> U256 {
    let buffer = required_fee / U256::from(PUBLIC_BROADCASTER_FEE_BUFFER_DIVISOR);
    required_fee
        + if buffer.is_zero() {
            U256::from(1_u8)
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

fn railgun_protocol_fee_amount(amount: U256, fee_bps: u16) -> U256 {
    amount * U256::from(fee_bps) / U256::from(FEE_BASIS_POINTS_DENOMINATOR)
}

const fn recipient_amount_after_protocol_fee(amount: U256, protocol_fee_amount: U256) -> U256 {
    amount.saturating_sub(protocol_fee_amount)
}

fn public_broadcaster_build_error(
    error: BuildError,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
) -> Report {
    match error {
        BuildError::InsufficientBalance(max_receiver_amount) => eyre!(
            "{PUBLIC_BROADCASTER_MAX_ENTERED_AMOUNT_ERROR}{}",
            public_broadcaster_max_entered_amount(max_receiver_amount, fee_amount, fee_mode)
        ),
        other => Report::new(other),
    }
}

fn parse_required_poi_list_keys(
    broadcaster: &PublicBroadcasterCandidate,
) -> Result<Vec<FixedBytes<32>>> {
    broadcaster
        .required_poi_list_keys
        .iter()
        .map(|list_key| {
            let bare = list_key.strip_prefix("0x").unwrap_or(list_key);
            if bare.len() != 64 {
                return Err(eyre!(
                    "invalid required POI list key {list_key}: expected 32-byte hex"
                ));
            }
            let bytes = hex::decode(bare)
                .wrap_err_with(|| format!("invalid required POI list key {list_key}"))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                eyre!("invalid required POI list key {list_key}: expected 32 bytes")
            })?;
            Ok(FixedBytes::from(bytes))
        })
        .collect()
}

struct PublicBroadcasterPreTransactionPois {
    request_pois: PreTransactionPoiMap,
    pending_poi_list_keys: Vec<FixedBytes<32>>,
    pending_pois: PreTransactionPoiMap,
}

async fn public_broadcaster_pre_transaction_pois(
    chunks: &[TransactionPlanChunk],
    broadcaster: &PublicBroadcasterCandidate,
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
) -> Result<PublicBroadcasterPreTransactionPois> {
    let required_poi_list_keys = parse_required_poi_list_keys(broadcaster)?;
    let pending_poi_list_keys: Vec<FixedBytes<32>> = default_active_poi_list_keys();
    let all_poi_list_keys = combined_poi_list_keys(&required_poi_list_keys, &pending_poi_list_keys);
    let poi_started = Instant::now();
    let all_pois = generate_pre_transaction_pois_for_lists(
        chunks,
        chain_id,
        prover,
        verify_proof,
        http,
        &all_poi_list_keys,
        "generate public broadcaster pre-transaction POI",
    )
    .await?;
    tracing::info!(
        chain_id,
        chunks = chunks.len(),
        required_list_keys = required_poi_list_keys.len(),
        pending_list_keys = pending_poi_list_keys.len(),
        total_list_keys = all_poi_list_keys.len(),
        elapsed_ms = poi_started.elapsed().as_millis(),
        "generated public broadcaster pre-transaction POIs"
    );
    let pending_pois = retain_pre_transaction_poi_lists(&all_pois, &pending_poi_list_keys);
    Ok(PublicBroadcasterPreTransactionPois {
        request_pois: retain_pre_transaction_poi_lists(&all_pois, &required_poi_list_keys),
        pending_poi_list_keys,
        pending_pois,
    })
}

async fn active_list_pre_transaction_pois(
    chunks: &[TransactionPlanChunk],
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    context: &'static str,
) -> Result<(Vec<FixedBytes<32>>, PreTransactionPoiMap)> {
    let poi_list_keys = default_active_poi_list_keys();
    let pois = generate_pre_transaction_pois_for_lists(
        chunks,
        chain_id,
        prover,
        verify_proof,
        http,
        &poi_list_keys,
        context,
    )
    .await?;
    Ok((poi_list_keys, pois))
}

async fn generate_pre_transaction_pois_for_lists(
    chunks: &[TransactionPlanChunk],
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    poi_list_keys: &[FixedBytes<32>],
    context: &'static str,
) -> Result<PreTransactionPoiMap> {
    if poi_list_keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    let poi_rpc_url =
        Url::parse(DEFAULT_WALLET_POI_RPC_URL).wrap_err("parse default POI RPC URL")?;
    let poi_client = PoiRpcClient::with_http_client(poi_rpc_url, http.client.clone());
    generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks,
        chain_type: 0,
        chain_id,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: poi_list_keys,
        poi_client: &poi_client,
        prover,
        verify_proof,
    })
    .await
    .wrap_err(context)
}

fn combined_poi_list_keys(
    first: &[FixedBytes<32>],
    second: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    let mut out = Vec::with_capacity(first.len() + second.len());
    for key in first.iter().chain(second.iter()) {
        if !out.contains(key) {
            out.push(*key);
        }
    }
    out
}

fn retain_pre_transaction_poi_lists(
    pois: &PreTransactionPoiMap,
    list_keys: &[FixedBytes<32>],
) -> PreTransactionPoiMap {
    list_keys
        .iter()
        .filter_map(|list_key| {
            pois.get(list_key)
                .cloned()
                .map(|per_leaf| (*list_key, per_leaf))
        })
        .collect()
}

fn persist_pending_send_output_poi_contexts(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    chunks: &[TransactionPlanChunk],
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
    include_broadcaster_fee: bool,
) -> Result<usize> {
    let created_at = now_epoch_secs()?;
    let mut count = 0;
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let chunk_context = pending_chunk_context(chunk, pre_transaction_pois, poi_list_keys)?;
        let private_output_count = pending_private_output_count(chunk)?;
        let mut output_index = 0;

        if include_broadcaster_fee && chunk_index == 0 {
            let note = chunk.outputs.get(output_index).ok_or_else(|| {
                eyre!("missing public broadcaster send fee output for pending POI")
            })?;
            put_pending_output_poi_context(
                db,
                chain_id,
                wallet_id,
                created_at,
                &chunk_context,
                note,
                PendingOutputPoiRole::BroadcasterFee,
            )?;
            count += 1;
            output_index += 1;
        }

        let note = chunk
            .outputs
            .get(output_index)
            .ok_or_else(|| eyre!("missing send recipient output for pending POI"))?;
        put_pending_output_poi_context(
            db,
            chain_id,
            wallet_id,
            created_at,
            &chunk_context,
            note,
            PendingOutputPoiRole::Recipient,
        )?;
        count += 1;
        output_index += 1;

        if output_index < private_output_count {
            let note = chunk
                .outputs
                .get(output_index)
                .ok_or_else(|| eyre!("missing send change output for pending POI"))?;
            put_pending_output_poi_context(
                db,
                chain_id,
                wallet_id,
                created_at,
                &chunk_context,
                note,
                PendingOutputPoiRole::Change,
            )?;
            count += 1;
        }
    }
    Ok(count)
}

fn persist_pending_unshield_output_poi_contexts(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    chunks: &[TransactionPlanChunk],
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
    include_broadcaster_fee: bool,
) -> Result<usize> {
    let created_at = now_epoch_secs()?;
    let mut count = 0;
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let chunk_context = pending_chunk_context(chunk, pre_transaction_pois, poi_list_keys)?;
        let private_output_count = pending_private_output_count(chunk)?;
        let mut output_index = 0;

        if include_broadcaster_fee && chunk_index == 0 {
            let note = chunk.outputs.get(output_index).ok_or_else(|| {
                eyre!("missing public broadcaster unshield fee output for pending POI")
            })?;
            put_pending_output_poi_context(
                db,
                chain_id,
                wallet_id,
                created_at,
                &chunk_context,
                note,
                PendingOutputPoiRole::BroadcasterFee,
            )?;
            count += 1;
            output_index += 1;
        }

        if output_index < private_output_count {
            let note = chunk
                .outputs
                .get(output_index)
                .ok_or_else(|| eyre!("missing unshield change output for pending POI"))?;
            put_pending_output_poi_context(
                db,
                chain_id,
                wallet_id,
                created_at,
                &chunk_context,
                note,
                PendingOutputPoiRole::Change,
            )?;
            count += 1;
        }
    }
    Ok(count)
}

struct PendingOutputPoiChunkContext {
    utxo_tree_in: u64,
    railgun_txid: U256,
    pre_transaction_pois: PreTransactionPoiMap,
    poi_list_keys: Vec<FixedBytes<32>>,
}

fn pending_chunk_context(
    chunk: &TransactionPlanChunk,
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
) -> Result<PendingOutputPoiChunkContext> {
    let railgun_txid = chunk.railgun_txid();
    let utxo_tree_in = u64::from(chunk.tree_number);
    let txid_leaf_hash = u256_to_fixed(railgun_txid_leaf_hash(railgun_txid, utxo_tree_in));
    let pre_transaction_pois = pre_transaction_pois
        .iter()
        .filter_map(|(list_key, per_leaf)| {
            per_leaf
                .get(&txid_leaf_hash)
                .cloned()
                .map(|poi| (*list_key, BTreeMap::from([(txid_leaf_hash, poi)])))
        })
        .collect::<PreTransactionPoiMap>();

    for list_key in poi_list_keys {
        let has_poi = pre_transaction_pois
            .get(list_key)
            .is_some_and(|per_leaf| per_leaf.contains_key(&txid_leaf_hash));
        if !has_poi {
            return Err(eyre!(
                "missing pending output pre-transaction POI for list key {}",
                hex::encode(list_key)
            ));
        }
    }

    Ok(PendingOutputPoiChunkContext {
        utxo_tree_in,
        railgun_txid,
        pre_transaction_pois,
        poi_list_keys: poi_list_keys.to_vec(),
    })
}

fn pending_private_output_count(chunk: &TransactionPlanChunk) -> Result<usize> {
    if chunk.has_unshield {
        chunk
            .outputs
            .len()
            .checked_sub(1)
            .ok_or_else(|| eyre!("unshield chunk is missing public output"))
    } else {
        Ok(chunk.outputs.len())
    }
}

fn put_pending_output_poi_context(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    created_at: u64,
    chunk_context: &PendingOutputPoiChunkContext,
    note: &Note,
    output_role: PendingOutputPoiRole,
) -> Result<()> {
    let record = PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: u256_to_fixed(note.commitment()),
        output_npk: u256_to_fixed(note.npk),
        utxo_tree_in: chunk_context.utxo_tree_in,
        railgun_txid: chunk_context.railgun_txid,
        pre_transaction_pois_per_txid_leaf_per_list: chunk_context.pre_transaction_pois.clone(),
        required_poi_list_keys: chunk_context.poi_list_keys.clone(),
        output_role,
        created_at,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    };
    db.put_pending_output_poi_context(&record)
        .wrap_err("persist pending output POI context")
}

fn u256_to_fixed(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

fn now_epoch_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .wrap_err("system clock is before unix epoch")?
        .as_secs())
}

const fn approximate_public_broadcaster_gas(shape: ApproximateTransactionShape) -> u64 {
    APPROX_BASE_GAS
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
        + APPROX_SAFETY_GAS
}

fn approximate_public_broadcaster_cost(
    broadcaster: PublicBroadcasterCandidate,
    entered_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
    protocol_fee_bps: u16,
    min_gas_price: u128,
    mut select_shape: impl FnMut(PublicBroadcasterAmountSplit) -> Result<ApproximateTransactionShape>,
) -> Result<PublicBroadcasterCostEstimate> {
    let service_gas_price = min_gas_price * 101 / 100;
    let mut fee_amount = U256::ZERO;
    let mut latest_shape = None;
    let mut latest_split = None;
    let mut latest_gas_limit = 0;

    for _ in 0..PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split(entered_amount, fee_amount, fee_mode)?;
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
                max_entered_amount: public_broadcaster_max_entered_amount(
                    shape.max_receiver_amount,
                    fee_amount,
                    split.fee_mode,
                ),
                gas_limit,
                min_gas_price,
                native_gas_cost: U256::from(gas_limit) * U256::from(min_gas_price),
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
        max_entered_amount: public_broadcaster_max_entered_amount(
            shape.max_receiver_amount,
            split.fee_amount,
            split.fee_mode,
        ),
        gas_limit: latest_gas_limit,
        min_gas_price,
        native_gas_cost: U256::from(latest_gas_limit) * U256::from(min_gas_price),
        transaction_count: shape.transaction_count,
        input_count: shape.input_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
    })
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
    format!("/railgun/v2/0-{chain_id}-transact/json")
}

#[must_use]
pub fn transact_response_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{chain_id}-transact-response/json")
}

pub fn decode_public_broadcaster_response(
    shared_key: &[u8; 32],
    payload: &[u8],
) -> Result<Option<PublicBroadcasterResultKind>> {
    Ok(
        match try_decrypt_transact_response_message(shared_key, payload)? {
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

fn candidate_from_fee_row(row: &FeeRow) -> Option<PublicBroadcasterCandidate> {
    let railgun_address = RailgunAddress::from(row.railgun_address.as_ref());
    let address_data = AddressData::try_from(&railgun_address).ok()?;
    Some(PublicBroadcasterCandidate {
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
    })
}

#[must_use]
pub const fn wrapped_native_token_for_chain(chain_id: u64) -> Option<Address> {
    match chain_id {
        1 => Some(address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")),
        56 => Some(address!("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")),
        137 => Some(address!("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")),
        42161 => Some(address!("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1")),
        _ => None,
    }
}

#[must_use]
pub fn is_wrapped_native_token(chain_id: u64, token: Address) -> bool {
    wrapped_native_token_for_chain(chain_id).is_some_and(|wrapped| wrapped == token)
}

fn parse_scaled_amount(input: &str, decimals: u8) -> Result<U256> {
    let (whole, fractional) = input
        .split_once('.')
        .map_or((input, ""), |(whole, fractional)| (whole, fractional));
    if whole.is_empty() && fractional.is_empty() {
        return Err(eyre!("amount is required"));
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(eyre!("amount must contain only decimal digits"));
    }
    if fractional.len() > usize::from(decimals) {
        return Err(eyre!("amount has too many decimal places"));
    }

    let whole_value = if whole.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(whole, 10).wrap_err("invalid whole amount")?
    };
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let fractional_value = if decimals == 0 || fractional.is_empty() {
        U256::ZERO
    } else {
        let mut padded = fractional.to_owned();
        padded.extend(std::iter::repeat_n(
            '0',
            usize::from(decimals) - fractional.len(),
        ));
        U256::from_str_radix(&padded, 10).wrap_err("invalid fractional amount")?
    };

    Ok(whole_value * scale + fractional_value)
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

    pub async fn start_wallet_session(
        &self,
        request: WalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
    ) -> Result<WalletSession> {
        let chain_id = request.chain_id;
        let synced = setup_synced_wallet_with_store(
            &request.mnemonic,
            chain_id,
            request.init_block_number,
            request.sync_to_block,
            request.use_indexed_wallet_catch_up,
            rpc_url_override,
            http,
            UnsupportedChainMessage::WalletCliV1,
            request.progress_tx.clone(),
            Arc::clone(&self.db),
            Arc::clone(&self.sync_manager),
        )
        .await?;

        wallet_session_from_synced(chain_id, synced).await
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
            request.init_block_number,
            request.sync_to_block,
            request.use_indexed_wallet_catch_up,
            request.rewind_wallet_cache,
            rpc_url_override,
            http,
            UnsupportedChainMessage::WalletCliV1,
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

pub async fn list_utxos(
    request: ListUtxosRequest,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<ListUtxosOutput> {
    let session = start_wallet_session(request.into(), rpc_url_override, http).await?;
    Ok(session.snapshots_rx.borrow().as_ref().clone())
}

pub async fn start_wallet_session(
    request: WalletSessionRequest,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<WalletSession> {
    let db_path = request.db_path.clone();
    let request = WalletChainSessionRequest::from(request);
    let store = WalletSessionStore::open(db_path)?;

    store
        .start_wallet_session(request, rpc_url_override, http)
        .await
}

async fn wallet_session_from_synced(chain_id: u64, synced: SyncedWallet) -> Result<WalletSession> {
    wallet_session_from_parts(
        chain_id,
        synced.db,
        synced.sync_manager,
        synced.chain_key,
        synced.handle,
    )
    .await
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
        synced.handle,
    )
    .await
}

async fn wallet_session_from_parts(
    chain_id: u64,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    handle: WalletHandle,
) -> Result<WalletSession> {
    let mut rev_rx = handle.rev_rx.clone();
    let initial_snapshot = Arc::new(snapshot_from_handle(chain_id, &handle).await);
    let (snapshots_tx, snapshots_rx) = watch::channel(initial_snapshot);
    let cache_key = handle.cache_key.clone();
    let ready_rx = handle.ready_rx.clone();
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
        ready_rx,
        snapshots_rx,
        db,
        sync_manager,
        chain_key,
        handle,
    })
}

pub async fn shield(
    request: ShieldRequest,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<ShieldResult> {
    let amount = U256::from_str_radix(&request.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", request.amount))?;

    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());

    let railgun_addr = RailgunAddress::from(request.recipient.as_str());
    let addr_data =
        AddressData::try_from(&railgun_addr).wrap_err("invalid recipient 0zk address")?;

    let evm_signer = SoftwareEvmSigner::from_private_key_hex(&request.private_key)?;
    let shield_private_key = evm_signer.derive_shield_private_key()?;

    let approve_data = build_approve_calldata(chain_defaults.contract, amount);
    let shield_data = build_shield_calldata(
        addr_data.master_public_key,
        &addr_data.viewing_public_key,
        request.token,
        amount,
        &shield_private_key,
    )
    .wrap_err("build shield calldata")?;

    if !request.send {
        let wrap = if request.wrap {
            Some(TxOutput {
                to: request.token,
                data: format!("0x{}", hex::encode(WETH_DEPOSIT_SELECTOR)),
                value: Some(amount.to_string()),
            })
        } else {
            None
        };

        return Ok(ShieldResult::Calldata(ShieldOutput {
            wrap,
            approve: TxOutput {
                to: request.token,
                data: format!("0x{}", hex::encode(&approve_data)),
                value: None,
            },
            shield: TxOutput {
                to: chain_defaults.contract,
                data: format!("0x{}", hex::encode(&shield_data)),
                value: None,
            },
        }));
    }

    let from_address = evm_signer.address();
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), rpc_url)
        .erased();

    let gas_price = buffered_gas_price(&provider).await?;
    let mut nonce = provider
        .get_transaction_count(from_address)
        .await
        .wrap_err("fetch nonce")?;
    let wallet = evm_signer.ethereum_wallet();

    let wrap_receipt = if request.wrap {
        let tx_req = TransactionRequest::default()
            .with_chain_id(request.chain_id)
            .with_from(from_address)
            .with_to(request.token)
            .with_input(WETH_DEPOSIT_SELECTOR.to_vec())
            .with_value(amount)
            .with_gas_price(gas_price)
            .with_nonce(nonce);

        let receipt = sign_send_wait(&provider, &wallet, tx_req, "wrap").await?;
        if !receipt.status {
            return Err(eyre!("wrap transaction reverted ({})", receipt.tx_hash));
        }
        nonce += 1;
        Some(receipt)
    } else {
        None
    };

    let approve_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(request.token)
        .with_input(approve_data)
        .with_gas_price(gas_price)
        .with_nonce(nonce);

    let approve_receipt = sign_send_wait(&provider, &wallet, approve_tx, "approve").await?;
    if !approve_receipt.status {
        return Err(eyre!(
            "approve transaction reverted ({})",
            approve_receipt.tx_hash
        ));
    }
    nonce += 1;

    let shield_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(chain_defaults.contract)
        .with_input(shield_data)
        .with_gas_price(gas_price)
        .with_nonce(nonce);

    let shield_receipt = sign_send_wait(&provider, &wallet, shield_tx, "shield").await?;
    if !shield_receipt.status {
        return Err(eyre!(
            "shield transaction reverted ({})",
            shield_receipt.tx_hash
        ));
    }

    Ok(ShieldResult::Sent(ShieldSendOutput {
        wrap: wrap_receipt,
        approve: approve_receipt,
        shield: shield_receipt,
    }))
}

pub async fn unshield(
    request: UnshieldRequest,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<UnshieldResult> {
    let amount = U256::from_str_radix(&request.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", request.amount))?;
    if request.unwrap && !is_wrapped_native_token(request.chain_id, request.token) {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let synced = setup_synced_wallet(
        &request.mnemonic,
        request.chain_id,
        request.db_path,
        request.init_block_number,
        None,
        true,
        rpc_url_override,
        http,
        UnsupportedChainMessage::Generic,
    )
    .await?;

    let artifact_source = artifact_source(http);
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&synced.db));

    let chain_handle = synced
        .sync_manager
        .chain_handle(&synced.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let wallet_utxos = synced.handle.utxos.read().await;
    let utxos = poi_verified_unspent_utxos_from_records(&wallet_utxos);
    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: synced.chain_defaults.contract,
        relay_adapt_contract: synced.chain_defaults.relay_adapt_contract,
    };

    let mode = if request.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };

    let unshield_request = RailgunUnshieldRequest {
        token_address: request.token,
        amount,
        recipient: request.recipient,
        mode,
        verify_proof: true,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };

    let plan = tx_builder
        .build_unshield_plan(&synced.wallet, &forest, &utxos, unshield_request, &prover)
        .await
        .wrap_err("build unshield plan")?;

    let Some(private_key) = request.private_key.as_deref() else {
        return Ok(UnshieldResult::Calldata(UnshieldOutput {
            to: plan.call.to,
            data: format!("0x{}", hex::encode(&plan.call.data)),
        }));
    };

    let evm_signer = SoftwareEvmSigner::from_private_key_hex(private_key)?;
    let from_address = evm_signer.address();
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), synced.rpc_url)
        .erased();

    let gas_price = buffered_gas_price(&provider).await?;
    let nonce = provider
        .get_transaction_count(from_address)
        .await
        .wrap_err("fetch nonce")?;

    let tx_req = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(plan.call.to)
        .with_input(plan.call.data.clone())
        .with_gas_price(gas_price)
        .with_nonce(nonce);

    let wallet = evm_signer.ethereum_wallet();
    let receipt = sign_send_wait(&provider, &wallet, tx_req, "unshield").await?;

    Ok(UnshieldResult::Sent(UnshieldSendOutput {
        tx_hash: receipt.tx_hash,
        status: receipt.status,
        block_number: receipt.block_number,
        gas_used: receipt.gas_used,
    }))
}

pub async fn prepare_desktop_unshield_calldata(
    request: DesktopUnshieldCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedUnshieldCall> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    if request.unwrap && !is_wrapped_native_token(request.chain_id, request.token) {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
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
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = unshield_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select POI-verified unshield notes")?;

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize unshield spend")?;
    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load unshield spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain_defaults.contract,
        relay_adapt_contract: chain_defaults.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
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

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        request.chain_id,
        &prover,
        request.verify_proof,
        http,
        "generate manual unshield pending output pre-transaction POI",
    )
    .await?;
    persist_pending_unshield_output_poi_contexts(
        request.session.db.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
    )?;

    Ok(PreparedUnshieldCall {
        chain_id: request.chain_id,
        token: request.token,
        amount: request.amount,
        recipient: request.recipient,
        unwrap: request.unwrap,
        max_spendable: selection_info.max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: format!("0x{}", hex::encode(&plan.call.data)),
    })
}

pub async fn prepare_desktop_send_calldata(
    request: DesktopSendCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedSendCall> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }

    let recipient = request.recipient.trim().to_string();
    let recipient_data = parse_railgun_recipient(&recipient)?;
    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
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
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = send_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select POI-verified send notes")?;

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize send spend")?;
    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load send spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain_defaults.contract,
        relay_adapt_contract: chain_defaults.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
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

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        request.chain_id,
        &prover,
        request.verify_proof,
        http,
        "generate manual send pending output pre-transaction POI",
    )
    .await?;
    persist_pending_send_output_poi_contexts(
        request.session.db.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
    )?;

    Ok(PreparedSendCall {
        chain_id: request.chain_id,
        token: request.token,
        amount: request.amount,
        recipient,
        max_spendable: selection_info.max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: format!("0x{}", hex::encode(&plan.call.data)),
    })
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
    if request.unwrap && !is_wrapped_native_token(request.chain_id, request.token) {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
    let candidates = eligible_public_broadcasters(
        &request.fee_rows,
        request.chain_id,
        request.token,
        if request.unwrap {
            Some(chain_defaults.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
    );
    let broadcaster = select_public_broadcaster(&candidates, &request.selection)?;
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), chain_defaults.rpc_url.clone())
        .erased();
    let min_gas_price = buffered_gas_price(&provider).await?;
    let utxos = request.session.unspent_utxos().await;

    approximate_public_broadcaster_cost(
        broadcaster,
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        |split| {
            let selection = unshield_selection_info_with_broadcaster_fee(
                &utxos,
                request.token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(error, split.fee_amount, split.fee_mode)
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

    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
    let candidates = eligible_public_broadcasters(
        &request.fee_rows,
        request.chain_id,
        request.token,
        None,
        SystemTime::now(),
    );
    let broadcaster = select_public_broadcaster(&candidates, &request.selection)?;
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), chain_defaults.rpc_url.clone())
        .erased();
    let min_gas_price = buffered_gas_price(&provider).await?;
    let utxos = request.session.unspent_utxos().await;

    approximate_public_broadcaster_cost(
        broadcaster,
        request.amount,
        request.fee_mode,
        0,
        min_gas_price,
        |split| {
            let selection = send_selection_info_with_broadcaster_fee(
                &utxos,
                request.token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(error, split.fee_amount, split.fee_mode)
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
    let progress_tx = request.progress_tx.clone();
    let prepared = prepare_desktop_unshield_public_broadcaster(request, http).await?;
    submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
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
    )
    .await
}

pub async fn submit_desktop_send_public_broadcaster(
    request: DesktopSendPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterSubmissionResult> {
    let waku = Arc::clone(&request.waku);
    let timeout = request.response_timeout;
    let progress_tx = request.progress_tx.clone();
    let prepared = prepare_desktop_send_public_broadcaster(request, http).await?;
    submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
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
    )
    .await
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
    if request.unwrap && !is_wrapped_native_token(request.chain_id, request.token) {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
    let candidates = eligible_public_broadcasters(
        &request.fee_rows,
        request.chain_id,
        request.token,
        if request.unwrap {
            Some(chain_defaults.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
    );
    let broadcaster = select_public_broadcaster(&candidates, &request.selection)?;

    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), chain_defaults.rpc_url.clone())
        .erased();
    let min_gas_price = buffered_gas_price(&provider).await?;
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
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let initial_fee_amount = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        |split| {
            let selection = unshield_selection_info_with_broadcaster_fee(
                &utxos,
                request.token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(error, split.fee_amount, split.fee_mode)
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
            estimate.fee_amount
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial public broadcaster unshield fee; starting at zero"
            );
            U256::ZERO
        }
    };

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster unshield spend")?;
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
        railgun_contract: chain_defaults.contract,
        relay_adapt_contract: chain_defaults.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split(request.amount, fee_amount, request.fee_mode)?;
        let unshield_request = RailgunUnshieldRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient: request.recipient,
            mode,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
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
            .map_err(|error| public_broadcaster_build_error(error, fee_amount, split.fee_mode))
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
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee(
            &provider,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
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

    let recipient = parse_railgun_recipient(&request.recipient)?;
    let chain_defaults =
        chain_defaults_for_chain(request.chain_id, UnsupportedChainMessage::Generic)?;
    let candidates = eligible_public_broadcasters(
        &request.fee_rows,
        request.chain_id,
        request.token,
        None,
        SystemTime::now(),
    );
    let broadcaster = select_public_broadcaster(&candidates, &request.selection)?;

    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), chain_defaults.rpc_url.clone())
        .erased();
    let min_gas_price = buffered_gas_price(&provider).await?;
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
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let initial_fee_amount = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.amount,
        request.fee_mode,
        0,
        min_gas_price,
        |split| {
            let selection = send_selection_info_with_broadcaster_fee(
                &utxos,
                request.token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(error, split.fee_amount, split.fee_mode)
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
            estimate.fee_amount
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial public broadcaster send fee; starting at zero"
            );
            U256::ZERO
        }
    };

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster send spend")?;
    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load public broadcaster send spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain_defaults.contract,
        relay_adapt_contract: chain_defaults.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split(request.amount, fee_amount, request.fee_mode)?;
        let send_request = RailgunSendRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
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
            .map_err(|error| public_broadcaster_build_error(error, fee_amount, split.fee_mode))
            .wrap_err("build public broadcaster send proof")?;
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
            "built public broadcaster send proof"
        );
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingBroadcasterFee,
        );
        let gas_started = Instant::now();
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee(
            &provider,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
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
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps: 0,
                fee_mode: split.fee_mode,
                gas_limit,
                min_gas_price,
            });
        }
        let next_fee = buffered_public_broadcaster_fee(computed_fee);
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
) -> Result<(u64, U256)> {
    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_to(to)
        .with_input(data.clone())
        .with_gas_price(min_gas_price);
    let gas_limit = provider
        .estimate_gas(tx_req)
        .await
        .wrap_err("estimate public broadcaster gas")?
        + GAS_LIMIT_BUFFER;
    let service_gas_price = min_gas_price * 101 / 100;
    Ok((
        gas_limit,
        broadcaster_fee_amount(token_fee_per_unit_gas, gas_limit, service_gas_price),
    ))
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

async fn submit_public_broadcaster_plan(
    waku: Arc<WakuClient>,
    to: Address,
    data: Bytes,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
    broadcaster: PublicBroadcasterCandidate,
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: u16,
    fee_mode: PublicBroadcasterFeeMode,
    gas_limit: u64,
    min_gas_price: u128,
    progress_tx: Option<TransactionGenerationProgressSender>,
    timeout: Duration,
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
    let encrypted = encrypt_transact_request(broadcaster.viewing_public_key, &params)
        .wrap_err("encrypt public broadcaster transact request")?;
    let payload = build_transact_request_payload(&encrypted)
        .wrap_err("serialize public broadcaster transact request")?;
    tracing::info!(
        chain_id = broadcaster.chain_id,
        broadcaster = %broadcaster.railgun_address,
        fees_id = %broadcaster.fees_id,
        payload_len = payload.len(),
        elapsed_ms = encrypt_started.elapsed().as_millis(),
        "built public broadcaster encrypted Waku payload"
    );
    tracing::info!(
        pubsub_path = PUBSUB_PATH,
        response_topic = %response_topic,
        "subscribing to public broadcaster response topic"
    );
    let subscribe_started = Instant::now();
    let mut response_rx = waku
        .subscribe(PUBSUB_PATH, vec![response_topic.clone()])
        .await
        .wrap_err("subscribe to public broadcaster response topic")?;
    tracing::info!(
        response_topic = %response_topic,
        elapsed_ms = subscribe_started.elapsed().as_millis(),
        "subscribed to public broadcaster response topic"
    );
    tracing::info!(
        pubsub_path = PUBSUB_PATH,
        transact_topic = %transact_topic,
        payload_len = payload.len(),
        "publishing public broadcaster transact request"
    );
    let publish_started = Instant::now();
    waku.publish(PUBSUB_PATH, &transact_topic, &payload)
        .await
        .wrap_err("publish public broadcaster transact request")?;
    tracing::info!(
        pubsub_path = PUBSUB_PATH,
        transact_topic = %transact_topic,
        elapsed_ms = publish_started.elapsed().as_millis(),
        "published public broadcaster transact request"
    );
    update_transaction_generation_stage(
        progress_tx.as_ref(),
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

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

    Ok(PublicBroadcasterSubmissionResult {
        broadcaster,
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

#[must_use]
pub fn utxo_outputs_from_utxos(mut utxos: Vec<WalletUtxo>) -> (Vec<UtxoOutput>, Vec<TokenTotal>) {
    utxos.sort_by(|a, b| match a.utxo.tree.cmp(&b.utxo.tree) {
        std::cmp::Ordering::Equal => a.utxo.position.cmp(&b.utxo.position),
        other => other,
    });

    let active_poi_list_keys = default_active_poi_list_keys();
    let mut totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let mut poi_verified_totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let utxo_outputs = utxos
        .into_iter()
        .map(|wallet_utxo| {
            let utxo = wallet_utxo.utxo;
            let token_addr = token_address_from_utxo(&utxo);
            let poi_spendable =
                wallet_utxo.spent.is_none() && utxo.poi.is_valid_for_lists(&active_poi_list_keys);
            if wallet_utxo.spent.is_none() {
                *totals_map.entry(token_addr).or_default() += utxo.note.value;
            }
            if poi_spendable {
                *poi_verified_totals_map.entry(token_addr).or_default() += utxo.note.value;
            }
            let source = &utxo.source;
            let spent = wallet_utxo.spent.as_ref();
            let poi_statuses = poi_statuses_for_output(&utxo, &active_poi_list_keys);

            UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token: token_addr.to_checksum(None),
                value: utxo.note.value.to_string(),
                commitment_kind: commitment_kind_label(utxo.poi.commitment_kind).to_string(),
                commitment: fixed_bytes_hex(&utxo.poi.commitment),
                npk: fixed_bytes_hex(&utxo.poi.npk),
                blinded_commitment: fixed_bytes_hex(&utxo.poi.blinded_commitment),
                poi_statuses,
                poi_spendable,
                source_tx_hash: source_tx_hash(source),
                source_block_number: source.block_number,
                source_block_timestamp: source.block_timestamp,
                is_spent: wallet_utxo.spent.is_some(),
                spent_tx_hash: spent.map(source_tx_hash),
                spent_block_number: spent.map(|source| source.block_number),
            }
        })
        .collect();

    let totals = totals_map
        .into_iter()
        .map(|(addr, total)| TokenTotal {
            token: addr.to_checksum(None),
            total: total.to_string(),
            poi_verified_total: poi_verified_totals_map
                .remove(&addr)
                .unwrap_or_default()
                .to_string(),
        })
        .collect();

    (utxo_outputs, totals)
}

async fn snapshot_from_handle(chain_id: u64, handle: &WalletHandle) -> ListUtxosOutput {
    let utxos = handle.utxos.read().await.clone();
    let (utxo_outputs, totals) = utxo_outputs_from_utxos(utxos);
    let unspent_count = utxo_outputs.iter().filter(|utxo| !utxo.is_spent).count();
    let spent_count = utxo_outputs.len().saturating_sub(unspent_count);

    ListUtxosOutput {
        chain_id,
        cache_key: handle.cache_key.clone(),
        utxo_count: utxo_outputs.len(),
        unspent_count,
        spent_count,
        utxos: utxo_outputs,
        totals,
    }
}

fn source_tx_hash(source: &UtxoSource) -> String {
    format!("0x{}", hex::encode(source.tx_hash))
}

fn fixed_bytes_hex(value: &FixedBytes<32>) -> String {
    format!("0x{}", hex::encode(value))
}

const fn commitment_kind_label(kind: UtxoCommitmentKind) -> &'static str {
    match kind {
        UtxoCommitmentKind::Shield => "Shield",
        UtxoCommitmentKind::Transact => "Transact",
    }
}

const fn poi_status_label(status: PoiStatus) -> &'static str {
    match status {
        PoiStatus::Valid => "Valid",
        PoiStatus::ShieldBlocked => "ShieldBlocked",
        PoiStatus::ProofSubmitted => "ProofSubmitted",
        PoiStatus::Missing => "Missing",
        PoiStatus::Unknown => "Unknown",
    }
}

fn poi_statuses_for_output(
    utxo: &Utxo,
    active_poi_list_keys: &[FixedBytes<32>],
) -> BTreeMap<String, String> {
    let mut statuses = utxo.poi.statuses.clone();
    for list_key in active_poi_list_keys {
        statuses.entry(*list_key).or_insert(PoiStatus::Unknown);
    }
    statuses
        .into_iter()
        .map(|(list_key, status)| (hex::encode(list_key), poi_status_label(status).to_string()))
        .collect()
}

fn token_address_from_utxo(utxo: &Utxo) -> Address {
    let token_bytes = utxo.note.token_hash.to_be_bytes::<32>();
    Address::from_slice(&token_bytes[12..32])
}

struct SyncedWallet {
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    chain_defaults: ChainConfigDefaults,
    rpc_url: Url,
    wallet: WalletKeys,
    handle: WalletHandle,
}

struct SyncedViewWallet {
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    handle: WalletHandle,
}

async fn setup_synced_wallet(
    mnemonic: &str,
    chain_id: u64,
    db_path: PathBuf,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    unsupported_chain_message: UnsupportedChainMessage,
) -> Result<SyncedWallet> {
    let store = WalletSessionStore::open(db_path)?;

    setup_synced_wallet_with_store(
        mnemonic,
        chain_id,
        init_block_number,
        sync_to_block,
        use_indexed_wallet_catch_up,
        rpc_url_override,
        http,
        unsupported_chain_message,
        None,
        store.db,
        store.sync_manager,
    )
    .await
}

async fn setup_synced_wallet_with_store(
    mnemonic: &str,
    chain_id: u64,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    unsupported_chain_message: UnsupportedChainMessage,
    progress_tx: Option<SyncProgressSender>,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
) -> Result<SyncedWallet> {
    let chain_defaults = chain_defaults_for_chain(chain_id, unsupported_chain_message)?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());
    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
    };

    let chain_cfg = chain_config(&chain_defaults, rpc_url.clone(), http, progress_tx.clone());
    sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let wallet = WalletKeys::from_mnemonic(mnemonic, 0).wrap_err("derive wallet keys")?;
    let scan_keys = wallet.viewing;
    let wallet_id = scan_keys
        .derive_address(None)
        .wrap_err("derive wallet id")?;
    let cache_key = wallet_cache_key(wallet_id.as_ref(), chain_id, chain_key.contract);
    let start_block = init_block_number.unwrap_or(chain_defaults.deployment_block);
    tracing::info!(
        chain_id,
        start_block,
        sync_to_block,
        use_indexed_wallet_catch_up,
        "starting mnemonic wallet sync"
    );
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key,
        start_block: Some(start_block),
        sync_to_block,
        scan_keys,
        progress_tx,
        cache_store: None,
        use_indexed_wallet_catch_up,
    };

    let mut handle = sync_manager
        .add_wallet(wallet_cfg)
        .await
        .wrap_err("register wallet sync worker")?;
    handle.wait_until_ready().await;

    Ok(SyncedWallet {
        db,
        sync_manager,
        chain_key,
        chain_defaults,
        rpc_url,
        wallet,
        handle,
    })
}

async fn setup_synced_view_wallet_with_store(
    view_session: Arc<vault::DesktopViewSession>,
    chain_id: u64,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rewind_wallet_cache: bool,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    unsupported_chain_message: UnsupportedChainMessage,
    progress_tx: Option<SyncProgressSender>,
    wait_until_ready: bool,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
) -> Result<SyncedViewWallet> {
    let chain_defaults = chain_defaults_for_chain(chain_id, unsupported_chain_message)?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());
    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
    };

    let chain_cfg = chain_config(&chain_defaults, rpc_url, http, progress_tx.clone());
    sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let start_block = init_block_number.unwrap_or(chain_defaults.deployment_block);
    tracing::info!(
        chain_id,
        start_block,
        sync_to_block,
        use_indexed_wallet_catch_up,
        "starting desktop view wallet sync"
    );
    let vault_store = vault::DesktopVaultStore::from_db(Arc::clone(&db));
    let mut wallet_chain_metadata = vault_store
        .wallet_chain_metadata_for_session(
            view_session.as_ref(),
            0,
            chain_id,
            &chain_key.contract.to_checksum(None),
            start_block,
        )
        .wrap_err("load encrypted wallet chain metadata")?;
    if rewind_wallet_cache {
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
    let cache_key = wallet_chain_metadata.wallet_chain_uuid.clone();
    let cache_store = Arc::new(
        vault::DesktopEncryptedWalletCacheStore::new(
            Arc::clone(&db),
            Arc::clone(&view_session),
            wallet_chain_metadata,
        )
        .wrap_err("create encrypted wallet cache")?,
    );
    let scan_keys = view_session.scan_keys();
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key,
        start_block: Some(start_block),
        sync_to_block,
        scan_keys,
        progress_tx,
        cache_store: Some(cache_store),
        use_indexed_wallet_catch_up,
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
        handle,
    })
}

#[derive(Clone, Copy)]
enum UnsupportedChainMessage {
    Generic,
    WalletCliV1,
}

fn chain_defaults_for_chain(
    chain_id: u64,
    unsupported_chain_message: UnsupportedChainMessage,
) -> Result<ChainConfigDefaults> {
    ChainConfigDefaults::for_chain(chain_id).ok_or_else(|| match unsupported_chain_message {
        UnsupportedChainMessage::Generic => eyre!("unsupported chain id {chain_id}"),
        UnsupportedChainMessage::WalletCliV1 => {
            eyre!("unsupported chain id {chain_id} for wallet-cli v1")
        }
    })
}

fn chain_config(
    defaults: &ChainConfigDefaults,
    rpc_url: Url,
    http: &HttpContext,
    progress_tx: Option<SyncProgressSender>,
) -> ChainConfig {
    let query_rpc_pool = Arc::new(QueryRpcPool::with_http_client(
        vec![rpc_url],
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ));

    ChainConfig {
        chain_id: defaults.chain_id,
        contract: defaults.contract,
        rpcs: query_rpc_pool,
        archive_rpc_url: None,
        archive_until_block: defaults.archive_until_block,
        deployment_block: defaults.deployment_block,
        v2_start_block: defaults.v2_start_block,
        legacy_shield_block: defaults.legacy_shield_block,
        block_range: DEFAULT_BLOCK_RANGE,
        indexed_wallet_block_range: defaults.indexed_wallet_block_range,
        poll_interval: DEFAULT_POLL_INTERVAL,
        finality_depth: defaults.finality_depth,
        quick_sync_endpoint: defaults.quick_sync_endpoint.clone(),
        anchor_interval: defaults.anchor_interval,
        anchor_retention: defaults.anchor_retention,
        http_client: Some(http.client.clone()),
        progress_tx,
    }
}

fn artifact_source(http: &HttpContext) -> ArtifactSource {
    match http.proxy_url.as_ref() {
        Some(url) => ArtifactSource::default().with_proxy(url.clone()),
        None => ArtifactSource::default(),
    }
}

fn parse_private_key(private_key: &str) -> Result<[u8; 32]> {
    let pk_hex = private_key.strip_prefix("0x").unwrap_or(private_key);
    hex::decode(pk_hex)
        .wrap_err("invalid private key hex")?
        .try_into()
        .map_err(|_| eyre!("private key must be 32 bytes"))
}

async fn buffered_gas_price(provider: &(impl Provider + Clone)) -> Result<u128> {
    let gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")?;
    Ok(gas_price * GAS_PRICE_BUFFER_NUMERATOR / GAS_PRICE_BUFFER_DENOMINATOR)
}

async fn sign_send_wait(
    provider: &(impl Provider + Clone),
    wallet: &EthereumWallet,
    tx_req: TransactionRequest,
    label: &str,
) -> Result<TxReceiptOutput> {
    let gas = provider
        .estimate_gas(tx_req.clone())
        .await
        .wrap_err_with(|| format!("{label}: estimate gas"))?
        + GAS_LIMIT_BUFFER;
    let tx_req = tx_req.with_gas_limit(gas);

    tracing::info!(
        from = %tx_req.from.unwrap_or_default(),
        to = ?tx_req.to,
        gas,
        label,
        "signing and sending",
    );

    let signed_tx = tx_req
        .build(wallet)
        .await
        .wrap_err_with(|| format!("{label}: sign"))?
        .encoded_2718();

    let tx_hash = provider
        .send_raw_transaction(&signed_tx)
        .await
        .wrap_err_with(|| format!("{label}: send"))?
        .tx_hash()
        .to_owned();

    tracing::info!(%tx_hash, label, "sent, waiting for confirmation...");

    let receipt = loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(r) = provider
            .get_transaction_receipt(tx_hash)
            .await
            .wrap_err_with(|| format!("{label}: fetch receipt"))?
        {
            break r;
        }
    };

    let status = receipt.status();
    let block_number = receipt.block_number.unwrap_or(0);
    let gas_used = receipt.gas_used;

    if status {
        tracing::info!(%tx_hash, block_number, gas_used, label, "confirmed");
    } else {
        tracing::warn!(%tx_hash, block_number, gas_used, label, "reverted");
    }

    Ok(TxReceiptOutput {
        tx_hash: format!("0x{}", hex::encode(tx_hash)),
        status,
        block_number,
        gas_used,
    })
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
    use broadcaster_core::crypto::railgun::{
        Address as RailgunAddress, AddressData, ViewingKeyData,
    };
    use broadcaster_core::notes::Note;
    use broadcaster_core::transact::{
        PreTxPoi, SnarkJsProof, build_transact_request_payload, encrypt_transact_request_with_seed,
        railgun_txid_leaf_hash, try_decrypt_transact_request,
    };
    use broadcaster_core::transact_response::build_transact_response_txhash;
    use broadcaster_monitor::FeeRow;
    use local_db::{DbConfig, DbStore, PendingOutputPoiRole};
    use poi::poi::default_active_poi_list_keys;
    use railgun_wallet::tx::{
        PrivateInputs, PublicInputs, TransactionPlanChunk, UnshieldSelectionInfo,
    };
    use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletKeys, WalletUtxo};
    use serde_json::json;

    use super::{
        ApproximateTransactionShape, EvmMessageSigner, EvmTransactionSigner, ListUtxosOutput,
        PublicBroadcasterCandidate, PublicBroadcasterFeeMode, PublicBroadcasterResultKind,
        PublicBroadcasterSelection, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS, SoftwareEvmSigner,
        TokenTotal, UtxoOutput, approximate_public_broadcaster_cost,
        approximate_public_broadcaster_gas, broadcaster_fee_amount, broadcaster_fee_covers,
        buffered_public_broadcaster_fee, decode_public_broadcaster_response,
        eligible_public_broadcasters, is_wrapped_native_token, max_send_amount_from_outputs,
        max_unshield_amount_from_outputs, parse_railgun_recipient, parse_required_poi_list_keys,
        parse_send_amount, parse_unshield_amount, public_broadcaster_amount_split,
        public_broadcaster_max_entered_amount, public_broadcaster_transact_params,
        select_public_broadcaster, send_approximate_shape, sort_specific_public_broadcasters,
        transact_topic, unshield_approximate_shape, utxo_outputs_from_utxos,
        wrapped_native_token_for_chain,
    };

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn address(byte: u8) -> Address {
        Address::from_slice(&[byte; 20])
    }

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-ops-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
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
        let viewing = broadcaster_core::crypto::railgun::ViewingKeyData::from_spending_public_key(
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
                fee: U256::from(10_u8),
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
                super::u256_to_fixed(railgun_txid_leaf_hash(
                    chunk.railgun_txid(),
                    u64::from(chunk.tree_number),
                ))
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

        let selected =
            super::poi_verified_unspent_utxos_from_records(&[valid, unknown, blocked, spent]);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].note.value, U256::from(5_u8));
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
            super::u256_to_fixed(recipient_note.commitment())
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
            super::u256_to_fixed(change_note.commitment())
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
        let unshield_note = Note::new_unshield(address(0xaa), token, U256::from(5_u8));
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
            super::u256_to_fixed(change_note.commitment())
        );
        assert_ne!(
            records[0].output_commitment,
            super::u256_to_fixed(unshield_note.commitment())
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
        )
        .expect("persist public broadcaster send output contexts");

        assert_eq!(count, 3);
        let records = store
            .list_pending_output_poi_contexts(1)
            .expect("list pending output POI contexts");
        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|record| record.output_role
            == PendingOutputPoiRole::BroadcasterFee
            && record.output_commitment == super::u256_to_fixed(fee_note.commitment())));

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
        let unshield_note = Note::new_unshield(address(0xbb), token, U256::from(6_u8));
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
        assert!(
            records.iter().all(|record| record.output_commitment
                != super::u256_to_fixed(unshield_note.commitment()))
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
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
            U256::from(35_u8)
        );
        assert_eq!(
            max_send_amount_from_outputs(&outputs, token),
            U256::from(35_u8)
        );
    }

    #[test]
    fn max_amount_from_outputs_excludes_non_poi_verified_utxos() {
        let token = address(0x11);
        let mut valid = utxo(token, 5, 0, 1);
        let mut unknown = utxo(token, 100, 0, 2);
        unknown.utxo.poi.statuses.clear();
        let (outputs, _) = utxo_outputs_from_utxos(vec![valid.clone(), unknown]);

        assert_eq!(
            max_send_amount_from_outputs(&outputs, token),
            U256::from(5_u8)
        );
        assert_eq!(
            max_unshield_amount_from_outputs(&outputs, token),
            U256::from(5_u8)
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

        let signer = SoftwareEvmSigner::from_private_key_hex(
            "0x0101010101010101010101010101010101010101010101010101010101010101",
        )
        .expect("software EVM signer");

        exercise_boundaries(&signer);
        assert!(SoftwareEvmSigner::from_private_key_hex("0x1234").is_err());
    }

    #[test]
    fn parse_unshield_amount_scales_known_token_decimals() {
        assert_eq!(
            parse_unshield_amount("1.23", Some(6)).expect("parsed amount"),
            U256::from(1_230_000_u64)
        );
        assert_eq!(
            parse_unshield_amount(".5", Some(18)).expect("parsed amount"),
            U256::from(5_u8) * U256::from(10_u8).pow(U256::from(17_u8))
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
            U256::from(123_u8)
        );
        assert!(parse_unshield_amount("1.23", None).is_err());
    }

    #[test]
    fn parse_send_amount_reuses_token_aware_amount_parsing() {
        assert_eq!(
            parse_send_amount("1.23", Some(6)).expect("parsed amount"),
            U256::from(1_230_000_u64)
        );
        assert_eq!(
            parse_send_amount("123", None).expect("parsed raw amount"),
            U256::from(123_u8)
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
    fn broadcaster_fee_amount_uses_same_token_fee_rate() {
        let fee = broadcaster_fee_amount(
            U256::from(2_000_000_000_000_000_000_u128),
            150_000,
            20_000_000_000,
        );

        assert_eq!(fee, U256::from(6_000_000_000_000_000_u128));
    }

    #[test]
    fn railgun_protocol_fee_uses_hardcoded_unshield_bps() {
        let amount = U256::from(1_000_000_u64);

        assert_eq!(
            super::railgun_protocol_fee_amount(amount, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS),
            U256::from(2_500_u64)
        );
        assert_eq!(super::railgun_protocol_fee_amount(amount, 0), U256::ZERO);
    }

    #[test]
    fn public_broadcaster_fee_stabilization_accepts_covering_fee() {
        let required = U256::from(1_000_u64);

        assert!(broadcaster_fee_covers(required, required));
        assert!(broadcaster_fee_covers(
            required + U256::from(1_u8),
            required
        ));
        assert!(!broadcaster_fee_covers(
            required - U256::from(1_u8),
            required
        ));
    }

    #[test]
    fn public_broadcaster_fee_stabilization_buffers_retries() {
        assert_eq!(
            buffered_public_broadcaster_fee(U256::from(10_000_u64)),
            U256::from(10_100_u64)
        );
        assert_eq!(
            buffered_public_broadcaster_fee(U256::from(1_u8)),
            U256::from(2_u8)
        );
    }

    #[test]
    fn public_broadcaster_fee_mode_deducts_or_adds_fee() {
        let entered = U256::from(100_u8);
        let fee = U256::from(7_u8);

        let deducted = public_broadcaster_amount_split(
            entered,
            fee,
            PublicBroadcasterFeeMode::DeductFromAmount,
        )
        .expect("deduct split");
        assert_eq!(deducted.receiver_amount, U256::from(93_u8));
        assert_eq!(deducted.total_private_spend, entered);

        let added =
            public_broadcaster_amount_split(entered, fee, PublicBroadcasterFeeMode::AddToAmount)
                .expect("add split");
        assert_eq!(added.receiver_amount, entered);
        assert_eq!(added.total_private_spend, U256::from(107_u8));
    }

    #[test]
    fn public_broadcaster_fee_mode_rejects_deducting_full_amount() {
        assert!(
            public_broadcaster_amount_split(
                U256::from(7_u8),
                U256::from(7_u8),
                PublicBroadcasterFeeMode::DeductFromAmount,
            )
            .is_err()
        );
    }

    #[test]
    fn public_broadcaster_max_entered_amount_depends_on_fee_mode() {
        let max_receiver_amount = U256::from(100_u8);
        let fee = U256::from(7_u8);

        assert_eq!(
            public_broadcaster_max_entered_amount(
                max_receiver_amount,
                fee,
                PublicBroadcasterFeeMode::DeductFromAmount,
            ),
            U256::from(107_u8)
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
        let entered = U256::from(1_000_000_000_u64);
        let selected_total = U256::from(2_000_000_000_u64);

        let deducted = approximate_public_broadcaster_cost(
            broadcaster.clone(),
            entered,
            PublicBroadcasterFeeMode::DeductFromAmount,
            0,
            100,
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
            entered,
            PublicBroadcasterFeeMode::AddToAmount,
            0,
            100,
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
        let entered = U256::from(1_000_000_u64);
        let selected_total = U256::from(2_000_000_u64);

        let estimate = approximate_public_broadcaster_cost(
            broadcaster,
            entered,
            PublicBroadcasterFeeMode::AddToAmount,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
            100,
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

        let expected_fee = estimate.receiver_amount * U256::from(25_u8) / U256::from(10_000_u64);
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
    fn approximate_shapes_include_broadcaster_fee_output_and_change() {
        let send_selection = selection_info(U256::from(15_u8), 2, 1, 3, 0, U256::from(13_u8));
        let send = send_approximate_shape(&send_selection, U256::from(13_u8));
        assert_eq!(send.input_count, 2);
        assert_eq!(send.transaction_count, 1);
        assert_eq!(send.private_output_count, 3);
        assert_eq!(send.public_output_count, 0);

        let unshield_selection = selection_info(U256::from(12_u8), 1, 1, 1, 1, U256::from(10_u8));
        let unshield = unshield_approximate_shape(&unshield_selection, U256::from(10_u8), true);
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

        let encrypted =
            encrypt_transact_request_with_seed(candidate.viewing_public_key, &params, [8u8; 32])
                .expect("encrypt request");
        let payload = build_transact_request_payload(&encrypted).expect("serialize envelope");
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
            Some(U256::from(20_000_000_000_u128))
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
        let required_keys = parse_required_poi_list_keys(&candidate).expect("required list keys");
        let params = public_broadcaster_transact_params(
            &candidate,
            address(0x33),
            Bytes::from(vec![1, 2, 3, 4]),
            20_000_000_000,
            sample_poi_map(&required_keys, &[txid_leaf]),
        );

        let encrypted =
            encrypt_transact_request_with_seed(candidate.viewing_public_key, &params, [8u8; 32])
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
        let required_keys = parse_required_poi_list_keys(&candidate).expect("required list keys");
        let params = public_broadcaster_transact_params(
            &candidate,
            address(0x33),
            Bytes::from(vec![1, 2, 3, 4]),
            20_000_000_000,
            sample_poi_map(&required_keys, &leaves),
        );

        let encrypted =
            encrypt_transact_request_with_seed(candidate.viewing_public_key, &params, [8u8; 32])
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

        let error =
            parse_required_poi_list_keys(&candidate).expect_err("invalid POI list key should fail");

        assert!(error.to_string().contains("invalid required POI list key"));
    }

    #[test]
    fn public_broadcaster_response_decodes_tx_hash() {
        let shared_key = [7u8; 32];
        let tx_hash = TxHash::from([3u8; 32]);
        let response =
            build_transact_response_txhash(None, &shared_key, tx_hash).expect("response payload");

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
    fn wrapped_native_detection_matches_supported_chains() {
        let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");
        assert!(is_wrapped_native_token(1, weth));
        assert!(!is_wrapped_native_token(1, address(0x11)));
        assert!(wrapped_native_token_for_chain(999_999).is_none());
    }
}
