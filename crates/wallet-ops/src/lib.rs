use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::eips::Encodable2718;
use alloy::hex;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder as _};
use alloy::primitives::{Address, U256, address};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use broadcaster_core::contracts::shield::{
    build_approve_calldata, build_shield_calldata, derive_shield_private_key,
};
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use eyre::{Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::tx::{
    SendRequest as RailgunSendRequest, UnshieldMode, UnshieldRequest as RailgunUnshieldRequest,
    send_selection_info, unshield_selection_info,
};
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{ProverService, TransactionBuilder, Utxo, UtxoSource, WalletKeys, WalletUtxo};
use reqwest::Url;
use serde::Serialize;
use sync_service::{
    ChainConfig, ChainConfigDefaults, ChainKey, SyncManager, SyncProgressSender, WalletConfig,
    WalletHandle,
};
pub use sync_service::{SyncProgressStage, SyncProgressUpdate};
use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

pub mod vault;

const DEFAULT_QUERY_RPC_COOLDOWN: Duration = Duration::from_secs(5);
const DEFAULT_BLOCK_RANGE: u64 = 500;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);
const GAS_LIMIT_BUFFER: u64 = 100_000;
const GAS_PRICE_BUFFER_NUMERATOR: u128 = 105;
const GAS_PRICE_BUFFER_DENOMINATOR: u128 = 100;

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
    pub input_count: usize,
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
    pub input_count: usize,
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
    _db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    _handle: WalletHandle,
}

impl WalletSession {
    pub async fn stop(&self) -> Result<()> {
        self.sync_manager
            .remove_wallet(&self.chain_key, &self.cache_key)
            .await
            .wrap_err("remove wallet sync worker")
    }

    pub async fn unspent_utxos(&self) -> Vec<Utxo> {
        self._handle
            .utxos
            .read()
            .await
            .iter()
            .filter(|entry| !entry.is_spent())
            .map(|entry| entry.utxo.clone())
            .collect()
    }
}

pub fn parse_unshield_amount(input: &str, decimals: Option<u8>) -> Result<U256> {
    let input = input.trim();
    if input.is_empty() {
        return Err(eyre!("amount is required"));
    }

    match decimals {
        Some(decimals) => parse_scaled_amount(input, decimals),
        None => {
            if !input.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(eyre!("unknown token amounts must be raw integer units"));
            }
            U256::from_str_radix(input, 10).wrap_err("invalid raw amount")
        }
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

#[must_use]
pub fn wrapped_native_token_for_chain(chain_id: u64) -> Option<Address> {
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
        _db: db,
        sync_manager,
        chain_key,
        _handle: handle,
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

    let utxos = synced
        .handle
        .utxos
        .read()
        .await
        .iter()
        .filter(|entry| !entry.is_spent())
        .map(|entry| entry.utxo.clone())
        .collect::<Vec<_>>();
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
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session._db));
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
    };
    let selection_info = unshield_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select unshield notes")?;

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

    Ok(PreparedUnshieldCall {
        chain_id: request.chain_id,
        token: request.token,
        amount: request.amount,
        recipient: request.recipient,
        unwrap: request.unwrap,
        max_spendable: selection_info.max_spendable,
        input_count: plan.inputs.len(),
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
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session._db));
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
    };
    let selection_info = send_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select send notes")?;

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

    Ok(PreparedSendCall {
        chain_id: request.chain_id,
        token: request.token,
        amount: request.amount,
        recipient,
        max_spendable: selection_info.max_spendable,
        input_count: plan.inputs.len(),
        to: plan.call.to,
        data: format!("0x{}", hex::encode(&plan.call.data)),
    })
}

#[must_use]
pub fn utxo_outputs_from_utxos(mut utxos: Vec<WalletUtxo>) -> (Vec<UtxoOutput>, Vec<TokenTotal>) {
    utxos.sort_by(|a, b| match a.utxo.tree.cmp(&b.utxo.tree) {
        std::cmp::Ordering::Equal => a.utxo.position.cmp(&b.utxo.position),
        other => other,
    });

    let mut totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let utxo_outputs = utxos
        .into_iter()
        .map(|wallet_utxo| {
            let utxo = wallet_utxo.utxo;
            let token_addr = token_address_from_utxo(&utxo);
            if wallet_utxo.spent.is_none() {
                *totals_map.entry(token_addr).or_default() += utxo.note.value;
            }
            let source = &utxo.source;
            let spent = wallet_utxo.spent.as_ref();

            UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token: token_addr.to_checksum(None),
                value: utxo.note.value.to_string(),
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
    use alloy::primitives::{Address, FixedBytes, U256};
    use broadcaster_core::notes::Note;
    use railgun_wallet::{Utxo, UtxoSource, WalletKeys, WalletUtxo};
    use serde_json::json;

    use super::{
        EvmMessageSigner, EvmTransactionSigner, ListUtxosOutput, SoftwareEvmSigner, TokenTotal,
        UtxoOutput, is_wrapped_native_token, parse_railgun_recipient, parse_send_amount,
        parse_unshield_amount, utxo_outputs_from_utxos, wrapped_native_token_for_chain,
    };

    fn address(byte: u8) -> Address {
        Address::from_slice(&[byte; 20])
    }

    fn source(byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number: u64::from(byte),
            block_timestamp: 1_700_000_000 + u64::from(byte),
        }
    }

    fn utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
        WalletUtxo::new(Utxo {
            note: Note::new_unshield(Address::ZERO, token, U256::from(value)),
            tree,
            position,
            source: source(position as u8 + 1),
        })
    }

    fn spent_utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
        let mut wallet_utxo = utxo(token, value, tree, position);
        wallet_utxo.spent = Some(source(9));
        wallet_utxo
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
                },
                TokenTotal {
                    token: token_b.to_checksum(None),
                    total: "7".to_string(),
                },
            ]
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
    fn wrapped_native_detection_matches_supported_chains() {
        let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");
        assert!(is_wrapped_native_token(1, weth));
        assert!(!is_wrapped_native_token(1, address(0x11)));
        assert!(wrapped_native_token_for_chain(999_999).is_none());
    }
}
