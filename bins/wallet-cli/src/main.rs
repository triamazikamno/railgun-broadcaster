use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp::Ordering, path::PathBuf};

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
use railgun_wallet::tx::{UnshieldMode, UnshieldRequest};
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{ProverService, TransactionBuilder, WalletKeys};
use reqwest::Url;
use serde::Serialize;
use structopt::StructOpt;
use sync_service::{ChainConfig, ChainConfigDefaults, ChainKey, SyncManager, WalletConfig};
use tracing::metadata::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

const DEFAULT_DB_PATH: &str = "db";
const DEFAULT_QUERY_RPC_COOLDOWN: Duration = Duration::from_secs(5);
const DEFAULT_BLOCK_RANGE: u64 = 500;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, StructOpt)]
#[structopt(name = "wallet-cli")]
struct Options {
    /// Override the default RPC URL for the chain
    #[structopt(long, global = true)]
    rpc_url: Option<Url>,
    /// Route all HTTP traffic through a proxy (e.g. socks5h://127.0.0.1:9050 for Tor)
    #[structopt(long, global = true)]
    proxy: Option<Url>,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    ListUtxos(ListUtxosOptions),
    Unshield(UnshieldOptions),
    Shield(ShieldOptions),
}

#[derive(Debug, StructOpt)]
struct ListUtxosOptions {
    #[structopt(long)]
    mnemonic: String,
    #[structopt(long)]
    chain_id: u64,
    #[structopt(long, default_value = DEFAULT_DB_PATH)]
    db_path: PathBuf,
    #[structopt(long)]
    init_block_number: Option<u64>,
}

#[derive(Debug, StructOpt)]
struct UnshieldOptions {
    #[structopt(long)]
    mnemonic: String,
    #[structopt(long)]
    chain_id: u64,
    #[structopt(long)]
    token: Address,
    #[structopt(long)]
    amount: String,
    #[structopt(long)]
    recipient: Address,
    #[structopt(long, default_value = DEFAULT_DB_PATH)]
    db_path: PathBuf,
    #[structopt(long)]
    init_block_number: Option<u64>,
    /// Use UnwrapBase mode (WETH -> ETH via RelayAdapter)
    #[structopt(long)]
    unwrap: bool,
    /// EVM private key (hex). When provided, signs and sends the tx on-chain
    /// instead of printing calldata.
    #[structopt(long)]
    private_key: Option<String>,
}

#[derive(Debug, StructOpt)]
struct ShieldOptions {
    #[structopt(long)]
    chain_id: u64,
    #[structopt(long)]
    token: Address,
    #[structopt(long)]
    amount: String,
    /// Recipient 0zk address (Bech32m)
    #[structopt(long)]
    recipient: String,
    /// Sender's EVM private key (hex). Used to derive shieldPrivateKey.
    /// When --send is also provided, this key signs and submits transactions.
    #[structopt(long)]
    private_key: String,
    /// Wrap ETH to WETH before shielding. --token must be the WETH address.
    #[structopt(long)]
    wrap: bool,
    /// Sign and send transactions on-chain using the provided private key.
    #[structopt(long)]
    send: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();
    let (console_non_blocking, _console_guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(true)
                .with_writer(console_non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();
    let rpc_url_override = options.rpc_url;
    let http_client = build_http_client(options.proxy.as_ref())?;
    match options.command {
        Command::ListUtxos(opts) => run_list_utxos(opts, rpc_url_override, &http_client).await,
        Command::Unshield(opts) => run_unshield(opts, rpc_url_override, &http_client).await,
        Command::Shield(opts) => run_shield(opts, rpc_url_override, &http_client).await,
    }
}

/// Shared HTTP context built once from the `--proxy` flag and passed into
/// every subcommand that issues network requests.
struct HttpContext {
    /// Async HTTP client (with optional proxy) for reqwest / alloy usage.
    client: reqwest::Client,
    /// Proxy URL, kept around for components that build their own client
    /// (e.g. the blocking artifact downloader).
    proxy_url: Option<Url>,
}

fn build_http_client(proxy: Option<&Url>) -> Result<HttpContext> {
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

async fn run_list_utxos(
    opts: ListUtxosOptions,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<()> {
    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {0} for wallet-cli v1", opts.chain_id))?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: opts.db_path,
        })
        .wrap_err("open local db")?,
    );
    let sync_manager = Arc::new(SyncManager::new(db));

    let query_rpc_pool = Arc::new(QueryRpcPool::with_http_client(
        vec![rpc_url],
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ));

    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
    };
    let chain_cfg = ChainConfig {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
        rpcs: query_rpc_pool,
        archive_rpc_url: None,
        archive_until_block: chain_defaults.archive_until_block,
        deployment_block: chain_defaults.deployment_block,
        v2_start_block: chain_defaults.v2_start_block,
        legacy_shield_block: chain_defaults.legacy_shield_block,
        block_range: DEFAULT_BLOCK_RANGE,
        poll_interval: DEFAULT_POLL_INTERVAL,
        finality_depth: chain_defaults.finality_depth,
        quick_sync_endpoint: chain_defaults.quick_sync_endpoint.clone(),
        anchor_interval: chain_defaults.anchor_interval,
        anchor_retention: chain_defaults.anchor_retention,
        http_client: Some(http.client.clone()),
    };
    sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let wallet = WalletKeys::from_mnemonic(&opts.mnemonic, 0).wrap_err("derive wallet keys")?;
    let scan_keys = wallet.viewing;
    let wallet_id = scan_keys
        .derive_address(None)
        .wrap_err("derive wallet id")?;
    let cache_key = wallet_cache_key(wallet_id.as_ref(), opts.chain_id, chain_key.contract);

    let start_block = opts
        .init_block_number
        .unwrap_or(chain_defaults.deployment_block);
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key: cache_key.clone(),
        start_block: Some(start_block),
        scan_keys,
    };

    let mut handle = sync_manager
        .add_wallet(wallet_cfg)
        .await
        .wrap_err("register wallet sync worker")?;
    handle.wait_until_ready().await;

    let mut utxos = handle.unspents.read().await.clone();
    utxos.sort_by(|a, b| match a.tree.cmp(&b.tree) {
        Ordering::Equal => a.position.cmp(&b.position),
        other => other,
    });

    // Accumulate per-token totals while building the UTXO list.
    let mut totals_map: BTreeMap<Address, U256> = BTreeMap::new();

    let utxo_outputs: Vec<UtxoOutput> = utxos
        .into_iter()
        .map(|utxo| {
            let token_bytes = utxo.note.token_hash.to_be_bytes::<32>();
            let token_addr = Address::from_slice(&token_bytes[12..32]);

            *totals_map.entry(token_addr).or_default() += utxo.note.value;

            UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token: token_addr.to_checksum(None),
                value: utxo.note.value.to_string(),
            }
        })
        .collect();

    let totals: Vec<TokenTotal> = totals_map
        .into_iter()
        .map(|(addr, total)| TokenTotal {
            token: addr.to_checksum(None),
            total: total.to_string(),
        })
        .collect();

    let output = ListUtxosOutput {
        chain_id: opts.chain_id,
        cache_key,
        utxo_count: utxo_outputs.len(),
        utxos: utxo_outputs,
        totals,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).wrap_err("serialize output")?
    );

    Ok(())
}

#[derive(Debug, Serialize)]
struct UtxoOutput {
    tree: u32,
    position: u64,
    token: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct TokenTotal {
    token: String,
    total: String,
}

#[derive(Debug, Serialize)]
struct ListUtxosOutput {
    chain_id: u64,
    cache_key: String,
    utxo_count: usize,
    utxos: Vec<UtxoOutput>,
    totals: Vec<TokenTotal>,
}

#[derive(Debug, Serialize)]
struct UnshieldOutput {
    to: Address,
    data: String,
}

#[derive(Debug, Serialize)]
struct UnshieldSendOutput {
    tx_hash: String,
    status: bool,
    block_number: u64,
    gas_used: u64,
}

#[derive(Debug, Serialize)]
struct TxOutput {
    to: Address,
    data: String,
    /// ETH value to send with the transaction (in wei, decimal string).
    /// Only present for transactions that transfer native ETH (e.g. WETH deposit).
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct ShieldOutput {
    /// Present only when --wrap is used: calls WETH.deposit() with ETH value.
    #[serde(skip_serializing_if = "Option::is_none")]
    wrap: Option<TxOutput>,
    approve: TxOutput,
    shield: TxOutput,
}

#[derive(Debug, Serialize)]
struct TxReceiptOutput {
    tx_hash: String,
    status: bool,
    block_number: u64,
    gas_used: u64,
}

#[derive(Debug, Serialize)]
struct ShieldSendOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    wrap: Option<TxReceiptOutput>,
    approve: TxReceiptOutput,
    shield: TxReceiptOutput,
}

/// WETH `deposit()` function selector — no arguments, ETH value is the deposit
/// amount.
const WETH_DEPOSIT_SELECTOR: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];

/// Sign, send, and wait for a transaction receipt. Returns a structured receipt
/// summary or an error.
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
        + 100_000;
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

    tracing::info!(%tx_hash, label, "sent, waiting for confirmation…");

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

async fn run_shield(
    opts: ShieldOptions,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<()> {
    let amount = U256::from_str_radix(&opts.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", opts.amount))?;

    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {}", opts.chain_id))?;

    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());

    // Parse recipient 0zk address
    let railgun_addr = RailgunAddress::from(opts.recipient.as_str());
    let addr_data =
        AddressData::try_from(&railgun_addr).wrap_err("invalid recipient 0zk address")?;

    // Parse sender private key
    let pk_hex = opts
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&opts.private_key);
    let pk_bytes: [u8; 32] = hex::decode(pk_hex)
        .wrap_err("invalid private key hex")?
        .try_into()
        .map_err(|_| eyre!("private key must be 32 bytes"))?;

    // Derive shield private key
    let shield_private_key =
        derive_shield_private_key(&pk_bytes).wrap_err("derive shield private key")?;

    // Build approve calldata
    let approve_data = build_approve_calldata(chain_defaults.contract, amount);

    // Build shield calldata
    let shield_data = build_shield_calldata(
        addr_data.master_public_key,
        &addr_data.viewing_public_key,
        opts.token,
        amount,
        &shield_private_key,
    )
    .wrap_err("build shield calldata")?;

    // ── Send mode ────────────────────────────────────────────────────────
    if opts.send {
        let signer = PrivateKeySigner::from(
            SigningKey::from_bytes((&pk_bytes).into()).wrap_err("invalid signing key")?,
        );
        let from_address = signer.address();

        let provider = ProviderBuilder::new()
            .connect_reqwest(http.client.clone(), rpc_url)
            .erased();

        // Fetch base gas price once (+5% buffer, matches codebase convention)
        let gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")? * 105 / 100;
        let mut nonce = provider
            .get_transaction_count(from_address)
            .await
            .wrap_err("fetch nonce")?;

        let wallet = EthereumWallet::from(signer);

        // 1. (optional) Wrap ETH → WETH
        let wrap_receipt = if opts.wrap {
            let tx_req = TransactionRequest::default()
                .with_chain_id(opts.chain_id)
                .with_from(from_address)
                .with_to(opts.token)
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

        // 2. Approve WETH/token for Railgun contract
        let approve_tx = TransactionRequest::default()
            .with_chain_id(opts.chain_id)
            .with_from(from_address)
            .with_to(opts.token)
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

        // 3. Shield
        let shield_tx = TransactionRequest::default()
            .with_chain_id(opts.chain_id)
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

        let output = ShieldSendOutput {
            wrap: wrap_receipt,
            approve: approve_receipt,
            shield: shield_receipt,
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).wrap_err("serialize output")?
        );
    } else {
        // ── Calldata-only mode ───────────────────────────────────────────
        let wrap_output = if opts.wrap {
            Some(TxOutput {
                to: opts.token,
                data: format!("0x{}", hex::encode(WETH_DEPOSIT_SELECTOR)),
                value: Some(amount.to_string()),
            })
        } else {
            None
        };

        let output = ShieldOutput {
            wrap: wrap_output,
            approve: TxOutput {
                to: opts.token,
                data: format!("0x{}", hex::encode(&approve_data)),
                value: None,
            },
            shield: TxOutput {
                to: chain_defaults.contract,
                data: format!("0x{}", hex::encode(&shield_data)),
                value: None,
            },
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).wrap_err("serialize output")?
        );
    }

    Ok(())
}

async fn run_unshield(
    opts: UnshieldOptions,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
) -> Result<()> {
    let amount = U256::from_str_radix(&opts.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", opts.amount))?;

    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {}", opts.chain_id))?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: opts.db_path,
        })
        .wrap_err("open local db")?,
    );
    let sync_manager = Arc::new(SyncManager::new(db.clone()));

    let query_rpc_pool = Arc::new(QueryRpcPool::with_http_client(
        vec![rpc_url.clone()],
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ));

    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
    };
    let chain_cfg = ChainConfig {
        chain_id: chain_defaults.chain_id,
        contract: chain_defaults.contract,
        rpcs: query_rpc_pool,
        archive_rpc_url: None,
        archive_until_block: chain_defaults.archive_until_block,
        deployment_block: chain_defaults.deployment_block,
        v2_start_block: chain_defaults.v2_start_block,
        legacy_shield_block: chain_defaults.legacy_shield_block,
        block_range: DEFAULT_BLOCK_RANGE,
        poll_interval: DEFAULT_POLL_INTERVAL,
        finality_depth: chain_defaults.finality_depth,
        quick_sync_endpoint: chain_defaults.quick_sync_endpoint.clone(),
        anchor_interval: chain_defaults.anchor_interval,
        anchor_retention: chain_defaults.anchor_retention,
        http_client: Some(http.client.clone()),
    };
    sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let wallet = WalletKeys::from_mnemonic(&opts.mnemonic, 0).wrap_err("derive wallet keys")?;
    let scan_keys = wallet.viewing;
    let wallet_id = scan_keys
        .derive_address(None)
        .wrap_err("derive wallet id")?;
    let cache_key = wallet_cache_key(wallet_id.as_ref(), opts.chain_id, chain_key.contract);

    let start_block = opts
        .init_block_number
        .unwrap_or(chain_defaults.deployment_block);
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

    let artifact_source = match http.proxy_url.as_ref() {
        Some(url) => ArtifactSource::default().with_proxy(url.clone()),
        None => ArtifactSource::default(),
    };
    let prover = ProverService::new_with_db(artifact_source, db);

    let chain_handle = sync_manager
        .chain_handle(&chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", opts.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let utxos = handle.unspents.read().await.clone();

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: opts.chain_id,
        railgun_contract: chain_defaults.contract,
        relay_adapt_contract: chain_defaults.relay_adapt_contract,
    };

    let mode = if opts.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };

    let request = UnshieldRequest {
        token_address: opts.token,
        amount,
        recipient: opts.recipient,
        mode,
        verify_proof: true,
        spend_up_to: false,
    };

    let plan = tx_builder
        .build_unshield_plan(&wallet, &forest, &utxos, request, &prover)
        .await
        .wrap_err("build unshield plan")?;

    // If a private key was provided, sign and send the transaction on-chain.
    // Otherwise, just print the calldata for external submission.
    if let Some(ref pk_hex) = opts.private_key {
        let pk_hex = pk_hex.strip_prefix("0x").unwrap_or(pk_hex);
        let pk_bytes: [u8; 32] = hex::decode(pk_hex)
            .wrap_err("invalid private key hex")?
            .try_into()
            .map_err(|_| eyre!("private key must be 32 bytes"))?;
        let signer = PrivateKeySigner::from(
            SigningKey::from_bytes((&pk_bytes).into()).wrap_err("invalid signing key")?,
        );
        let from_address = signer.address();

        let provider = ProviderBuilder::new()
            .connect_reqwest(http.client.clone(), rpc_url)
            .erased();

        // Gas price: current price + 5% buffer (matches codebase convention)
        let gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")? * 105 / 100;

        let nonce = provider
            .get_transaction_count(from_address)
            .await
            .wrap_err("fetch nonce")?;

        let tx_req = TransactionRequest::default()
            .with_chain_id(opts.chain_id)
            .with_from(from_address)
            .with_to(plan.call.to)
            .with_input(plan.call.data.clone())
            .with_gas_price(gas_price)
            .with_nonce(nonce);

        let gas = provider
            .estimate_gas(tx_req.clone())
            .await
            .wrap_err("estimate gas")?
            + 100_000;
        let tx_req = tx_req.with_gas_limit(gas);

        let cost = U256::from(gas) * U256::from(gas_price);
        tracing::info!(
            from = %from_address,
            to = %plan.call.to,
            gas,
            gas_price,
            cost = %cost,
            nonce,
            "signing and sending unshield transaction",
        );

        let signed_tx = tx_req
            .build(&EthereumWallet::from(signer))
            .await
            .wrap_err("sign transaction")?
            .encoded_2718();

        let tx_hash = provider
            .send_raw_transaction(&signed_tx)
            .await
            .wrap_err("send raw transaction")?
            .tx_hash()
            .to_owned();

        tracing::info!(%tx_hash, "transaction sent, waiting for confirmation…");

        // Poll for receipt
        let receipt = loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if let Some(receipt) = provider
                .get_transaction_receipt(tx_hash)
                .await
                .wrap_err("fetch transaction receipt")?
            {
                break receipt;
            }
        };

        let status = receipt.status();
        let block_number = receipt.block_number.unwrap_or(0);
        let gas_used = receipt.gas_used;

        if status {
            tracing::info!(%tx_hash, block_number, gas_used, "transaction confirmed");
        } else {
            tracing::warn!(%tx_hash, block_number, gas_used, "transaction reverted");
        }

        let output = UnshieldSendOutput {
            tx_hash: format!("0x{}", hex::encode(tx_hash)),
            status,
            block_number,
            gas_used,
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).wrap_err("serialize output")?
        );
    } else {
        let output = UnshieldOutput {
            to: plan.call.to,
            data: format!("0x{}", hex::encode(&plan.call.data)),
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).wrap_err("serialize output")?
        );
    }

    Ok(())
}
