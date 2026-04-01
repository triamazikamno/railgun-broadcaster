use std::sync::Arc;
use std::time::Duration;
use std::{cmp::Ordering, path::PathBuf};

use alloy::hex;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::SolEvent;
use broadcaster_core::contracts::railgun::Shield;
use broadcaster_core::contracts::shield::{
    build_approve_calldata, build_shield_calldata, derive_shield_private_key,
};
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use eyre::{Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore};
use poi::poi::PoiRpcClient;
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
const DEFAULT_POI_RPC: &str = "https://ppoi.fdi.network";
const DEFAULT_POI_LIST: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

#[derive(Debug, StructOpt)]
#[structopt(name = "wallet-cli")]
struct Options {
    /// Override the default RPC URL for the chain
    #[structopt(long, global = true)]
    rpc_url: Option<Url>,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    ListUtxos(ListUtxosOptions),
    Unshield(UnshieldOptions),
    Shield(ShieldOptions),
    SubmitShieldPoi(SubmitShieldPoiOptions),
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
    #[structopt(long)]
    private_key: String,
}

#[derive(Debug, StructOpt)]
struct SubmitShieldPoiOptions {
    #[structopt(long)]
    chain_id: u64,
    /// Confirmed shield transaction hash
    #[structopt(long)]
    tx_hash: String,
    /// POI aggregator RPC endpoint
    #[structopt(long)]
    poi_rpc: Option<String>,
    /// Required POI list keys (repeatable)
    #[structopt(long)]
    poi_list: Vec<String>,
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
    match options.command {
        Command::ListUtxos(opts) => run_list_utxos(opts, rpc_url_override).await,
        Command::Unshield(opts) => run_unshield(opts, rpc_url_override).await,
        Command::Shield(opts) => run_shield(opts).await,
        Command::SubmitShieldPoi(opts) => run_submit_shield_poi(opts, rpc_url_override).await,
    }
}

async fn run_list_utxos(opts: ListUtxosOptions, rpc_url_override: Option<Url>) -> Result<()> {
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

    let query_rpc_pool = Arc::new(QueryRpcPool::new(vec![rpc_url], DEFAULT_QUERY_RPC_COOLDOWN));

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

    let output = ListUtxosOutput {
        chain_id: opts.chain_id,
        cache_key,
        utxo_count: utxos.len(),
        utxos: utxos
            .into_iter()
            .map(|utxo| UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token_hash: u256_hex(utxo.note.token_hash),
                value: u256_hex(utxo.note.value),
            })
            .collect(),
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
    token_hash: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ListUtxosOutput {
    chain_id: u64,
    cache_key: String,
    utxo_count: usize,
    utxos: Vec<UtxoOutput>,
}

fn u256_hex(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

#[derive(Debug, Serialize)]
struct UnshieldOutput {
    to: Address,
    data: String,
}

#[derive(Debug, Serialize)]
struct TxOutput {
    to: Address,
    data: String,
}

#[derive(Debug, Serialize)]
struct ShieldOutput {
    approve: TxOutput,
    shield: TxOutput,
}

async fn run_shield(opts: ShieldOptions) -> Result<()> {
    let amount = U256::from_str_radix(&opts.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", opts.amount))?;

    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {}", opts.chain_id))?;

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

    let output = ShieldOutput {
        approve: TxOutput {
            to: opts.token,
            data: format!("0x{}", hex::encode(&approve_data)),
        },
        shield: TxOutput {
            to: chain_defaults.contract,
            data: format!("0x{}", hex::encode(&shield_data)),
        },
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).wrap_err("serialize output")?
    );

    Ok(())
}

async fn run_submit_shield_poi(
    opts: SubmitShieldPoiOptions,
    rpc_url_override: Option<Url>,
) -> Result<()> {
    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {}", opts.chain_id))?;
    let rpc_url = rpc_url_override.unwrap_or_else(|| chain_defaults.rpc_url.clone());

    let poi_rpc_url: Url = opts
        .poi_rpc
        .as_deref()
        .unwrap_or(DEFAULT_POI_RPC)
        .parse()
        .wrap_err("invalid POI RPC URL")?;

    let poi_list_keys: Vec<String> = if opts.poi_list.is_empty() {
        vec![DEFAULT_POI_LIST.to_string()]
    } else {
        opts.poi_list
    };

    // Parse tx hash
    let tx_hash_hex = opts.tx_hash.strip_prefix("0x").unwrap_or(&opts.tx_hash);
    let tx_hash_bytes: [u8; 32] = hex::decode(tx_hash_hex)
        .wrap_err("invalid tx hash hex")?
        .try_into()
        .map_err(|_| eyre!("tx hash must be 32 bytes"))?;
    let tx_hash = FixedBytes::from(tx_hash_bytes);

    // Fetch transaction receipt
    let provider = ProviderBuilder::new().connect_http(rpc_url).erased();
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .wrap_err("fetch transaction receipt")?
        .ok_or_else(|| eyre!("transaction {} not found", opts.tx_hash))?;

    // Parse Shield events from receipt logs
    let shield_events: Vec<Shield> = receipt
        .inner
        .logs()
        .iter()
        .filter_map(|log| Shield::decode_log(log.as_ref()).ok())
        .map(|decoded| decoded.data)
        .collect();

    if shield_events.is_empty() {
        return Err(eyre!(
            "no Shield events found in transaction {}",
            opts.tx_hash
        ));
    }

    // Submit each commitment to POI aggregator
    let poi_client = PoiRpcClient::new(poi_rpc_url);

    for event in &shield_events {
        for (i, preimage) in event.commitments.iter().enumerate() {
            let commitment_hash = preimage.hash();
            let commitment_hash_hex =
                format!("0x{}", hex::encode(commitment_hash.to_be_bytes::<32>()));
            let npk_hex = format!("0x{}", hex::encode(preimage.npk));

            tracing::info!(
                commitment = %commitment_hash_hex,
                "submitting shield commitment to POI aggregator"
            );

            poi_client
                .submit_single_commitment_proof(
                    opts.chain_id,
                    &commitment_hash_hex,
                    &npk_hex,
                    &format!("0x{}", hex::encode(tx_hash)),
                    i,
                    &poi_list_keys,
                )
                .await
                .wrap_err("submit shield POI")?;
        }
    }

    tracing::info!("shield POI submission complete");
    Ok(())
}

async fn run_unshield(opts: UnshieldOptions, rpc_url_override: Option<Url>) -> Result<()> {
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

    let query_rpc_pool = Arc::new(QueryRpcPool::new(vec![rpc_url], DEFAULT_QUERY_RPC_COOLDOWN));

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

    let prover = ProverService::new_with_db(ArtifactSource::default(), db);

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

    let output = UnshieldOutput {
        to: plan.call.to,
        data: format!("0x{}", hex::encode(&plan.call.data)),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).wrap_err("serialize output")?
    );

    Ok(())
}
