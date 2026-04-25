use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::eips::Encodable2718;
use alloy::hex;
use alloy::network::{EthereumWallet, TransactionBuilder as _};
use alloy::primitives::{Address, U256};
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
use railgun_wallet::tx::{UnshieldMode, UnshieldRequest as RailgunUnshieldRequest};
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{ProverService, TransactionBuilder, Utxo, WalletKeys};
use reqwest::Url;
use serde::Serialize;
use sync_service::{
    ChainConfig, ChainConfigDefaults, ChainKey, SyncManager, WalletConfig, WalletHandle,
};
use tokio::sync::watch;

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
}

pub struct WalletSessionRequest {
    pub mnemonic: String,
    pub chain_id: u64,
    pub db_path: PathBuf,
    pub init_block_number: Option<u64>,
}

impl From<ListUtxosRequest> for WalletSessionRequest {
    fn from(value: ListUtxosRequest) -> Self {
        Self {
            mnemonic: value.mnemonic,
            chain_id: value.chain_id,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UtxoOutput {
    pub tree: u32,
    pub position: u64,
    pub token: String,
    pub value: String,
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
    pub utxos: Vec<UtxoOutput>,
    pub totals: Vec<TokenTotal>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnshieldOutput {
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
    _sync_manager: Arc<SyncManager>,
    _chain_key: ChainKey,
    _handle: WalletHandle,
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
    let chain_id = request.chain_id;
    let synced = setup_synced_wallet(
        &request.mnemonic,
        chain_id,
        request.db_path,
        request.init_block_number,
        rpc_url_override,
        http,
        UnsupportedChainMessage::WalletCliV1,
    )
    .await?;

    let initial_snapshot = Arc::new(snapshot_from_handle(chain_id, &synced.handle).await);
    let (snapshots_tx, snapshots_rx) = watch::channel(initial_snapshot);
    let handle = synced.handle.clone();
    let mut rev_rx = handle.rev_rx.clone();
    tokio::spawn(async move {
        loop {
            if rev_rx.changed().await.is_err() {
                break;
            }
            let snapshot = Arc::new(snapshot_from_handle(chain_id, &handle).await);
            if snapshots_tx.send(snapshot).is_err() {
                break;
            }
        }
    });

    Ok(WalletSession {
        chain_id,
        cache_key: synced.handle.cache_key.clone(),
        ready_rx: synced.handle.ready_rx.clone(),
        snapshots_rx,
        _db: synced.db,
        _sync_manager: synced.sync_manager,
        _chain_key: synced.chain_key,
        _handle: synced.handle,
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

    let pk_bytes = parse_private_key(&request.private_key)?;
    let shield_private_key =
        derive_shield_private_key(&pk_bytes).wrap_err("derive shield private key")?;

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

    let signer = PrivateKeySigner::from(
        SigningKey::from_bytes((&pk_bytes).into()).wrap_err("invalid signing key")?,
    );
    let from_address = signer.address();
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), rpc_url)
        .erased();

    let gas_price = buffered_gas_price(&provider).await?;
    let mut nonce = provider
        .get_transaction_count(from_address)
        .await
        .wrap_err("fetch nonce")?;
    let wallet = EthereumWallet::from(signer);

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

    let synced = setup_synced_wallet(
        &request.mnemonic,
        request.chain_id,
        request.db_path,
        request.init_block_number,
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

    let utxos = synced.handle.unspents.read().await.clone();
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

    let pk_bytes = parse_private_key(private_key)?;
    let signer = PrivateKeySigner::from(
        SigningKey::from_bytes((&pk_bytes).into()).wrap_err("invalid signing key")?,
    );
    let from_address = signer.address();
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

    let receipt =
        sign_send_wait(&provider, &EthereumWallet::from(signer), tx_req, "unshield").await?;

    Ok(UnshieldResult::Sent(UnshieldSendOutput {
        tx_hash: receipt.tx_hash,
        status: receipt.status,
        block_number: receipt.block_number,
        gas_used: receipt.gas_used,
    }))
}

#[must_use]
pub fn utxo_outputs_from_utxos(mut utxos: Vec<Utxo>) -> (Vec<UtxoOutput>, Vec<TokenTotal>) {
    utxos.sort_by(|a, b| match a.tree.cmp(&b.tree) {
        std::cmp::Ordering::Equal => a.position.cmp(&b.position),
        other => other,
    });

    let mut totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let utxo_outputs = utxos
        .into_iter()
        .map(|utxo| {
            let token_addr = token_address_from_utxo(&utxo);
            *totals_map.entry(token_addr).or_default() += utxo.note.value;

            UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token: token_addr.to_checksum(None),
                value: utxo.note.value.to_string(),
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
    let utxos = handle.unspents.read().await.clone();
    let (utxo_outputs, totals) = utxo_outputs_from_utxos(utxos);

    ListUtxosOutput {
        chain_id,
        cache_key: handle.cache_key.clone(),
        utxo_count: utxo_outputs.len(),
        utxos: utxo_outputs,
        totals,
    }
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

async fn setup_synced_wallet(
    mnemonic: &str,
    chain_id: u64,
    db_path: PathBuf,
    init_block_number: Option<u64>,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    unsupported_chain_message: UnsupportedChainMessage,
) -> Result<SyncedWallet> {
    let chain_defaults = chain_defaults_for_chain(chain_id, unsupported_chain_message)?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());
    let db = Arc::new(DbStore::open(DbConfig { root_dir: db_path }).wrap_err("open local db")?);
    let sync_manager = Arc::new(SyncManager::new(Arc::clone(&db)));
    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
    };

    let chain_cfg = chain_config(&chain_defaults, rpc_url.clone(), http);
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
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key,
        start_block: Some(start_block),
        scan_keys,
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

fn chain_config(defaults: &ChainConfigDefaults, rpc_url: Url, http: &HttpContext) -> ChainConfig {
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
        poll_interval: DEFAULT_POLL_INTERVAL,
        finality_depth: defaults.finality_depth,
        quick_sync_endpoint: defaults.quick_sync_endpoint.clone(),
        anchor_interval: defaults.anchor_interval,
        anchor_retention: defaults.anchor_retention,
        http_client: Some(http.client.clone()),
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
    use alloy::primitives::{Address, U256};
    use broadcaster_core::notes::Note;
    use railgun_wallet::Utxo;
    use serde_json::json;

    use super::{ListUtxosOutput, TokenTotal, UtxoOutput, utxo_outputs_from_utxos};

    fn address(byte: u8) -> Address {
        Address::from_slice(&[byte; 20])
    }

    fn utxo(token: Address, value: u64, tree: u32, position: u64) -> Utxo {
        Utxo {
            note: Note::new_unshield(Address::ZERO, token, U256::from(value)),
            tree,
            position,
        }
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
    fn list_utxos_output_serializes_existing_field_names() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            utxos: vec![UtxoOutput {
                tree: 2,
                position: 3,
                token: "0x0000000000000000000000000000000000000001".to_string(),
                value: "4".to_string(),
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
                "utxos": [{
                    "tree": 2,
                    "position": 3,
                    "token": "0x0000000000000000000000000000000000000001",
                    "value": "4",
                }],
                "totals": [{
                    "token": "0x0000000000000000000000000000000000000001",
                    "total": "4",
                }],
            })
        );
    }
}
