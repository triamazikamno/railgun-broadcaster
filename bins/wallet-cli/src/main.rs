use std::sync::Arc;
use std::time::Duration;
use std::{cmp::Ordering, path::PathBuf};

use alloy::hex;
use alloy::primitives::{Address, U256};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use eyre::{Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::tx::{UnshieldMode, UnshieldRequest};
use railgun_wallet::wallet_cache::wallet_cache_key;
use railgun_wallet::{ProverService, TransactionBuilder, WalletKeys};
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
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    ListUtxos(ListUtxosOptions),
    Unshield(UnshieldOptions),
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
    match options.command {
        Command::ListUtxos(opts) => run_list_utxos(opts).await,
        Command::Unshield(opts) => run_unshield(opts).await,
    }
}

async fn run_list_utxos(opts: ListUtxosOptions) -> Result<()> {
    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {0} for wallet-cli v1", opts.chain_id))?;

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: opts.db_path,
        })
        .wrap_err("open local db")?,
    );
    let sync_manager = Arc::new(SyncManager::new(db));

    let query_rpc_pool = Arc::new(QueryRpcPool::new(
        vec![chain_defaults.rpc_url.clone()],
        DEFAULT_QUERY_RPC_COOLDOWN,
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

async fn run_unshield(opts: UnshieldOptions) -> Result<()> {
    let amount = U256::from_str_radix(&opts.amount, 10)
        .map_err(|e| eyre!("invalid amount '{}': {e}", opts.amount))?;

    let chain_defaults = ChainConfigDefaults::for_chain(opts.chain_id)
        .ok_or_else(|| eyre!("unsupported chain id {}", opts.chain_id))?;

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: opts.db_path,
        })
        .wrap_err("open local db")?,
    );
    let sync_manager = Arc::new(SyncManager::new(db.clone()));

    let query_rpc_pool = Arc::new(QueryRpcPool::new(
        vec![chain_defaults.rpc_url.clone()],
        DEFAULT_QUERY_RPC_COOLDOWN,
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
