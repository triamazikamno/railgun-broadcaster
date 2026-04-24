use std::path::PathBuf;

use alloy::primitives::Address;
use eyre::{Result, WrapErr};
use reqwest::Url;
use serde::Serialize;
use structopt::StructOpt;
use tracing::metadata::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use wallet_ops::{
    ListUtxosRequest, ShieldRequest, ShieldResult, UnshieldRequest, UnshieldResult,
    build_http_client, list_utxos, shield, unshield,
};

const DEFAULT_DB_PATH: &str = "db";

#[derive(StructOpt)]
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

#[derive(StructOpt)]
enum Command {
    ListUtxos(ListUtxosOptions),
    Unshield(UnshieldOptions),
    Shield(ShieldOptions),
}

#[derive(StructOpt)]
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

#[derive(StructOpt)]
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

#[derive(StructOpt)]
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
        Command::ListUtxos(opts) => {
            let output = list_utxos(opts.into(), rpc_url_override, &http_client).await?;
            print_json(&output)
        }
        Command::Unshield(opts) => {
            let output = unshield(opts.into(), rpc_url_override, &http_client).await?;
            match output {
                UnshieldResult::Calldata(output) => print_json(&output),
                UnshieldResult::Sent(output) => print_json(&output),
            }
        }
        Command::Shield(opts) => {
            let output = shield(opts.into(), rpc_url_override, &http_client).await?;
            match output {
                ShieldResult::Calldata(output) => print_json(&output),
                ShieldResult::Sent(output) => print_json(&output),
            }
        }
    }
}

fn print_json(output: &impl Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(output).wrap_err("serialize output")?
    );
    Ok(())
}

impl From<ListUtxosOptions> for ListUtxosRequest {
    fn from(value: ListUtxosOptions) -> Self {
        Self {
            mnemonic: value.mnemonic,
            chain_id: value.chain_id,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
        }
    }
}

impl From<UnshieldOptions> for UnshieldRequest {
    fn from(value: UnshieldOptions) -> Self {
        Self {
            mnemonic: value.mnemonic,
            chain_id: value.chain_id,
            token: value.token,
            amount: value.amount,
            recipient: value.recipient,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
            unwrap: value.unwrap,
            private_key: value.private_key,
        }
    }
}

impl From<ShieldOptions> for ShieldRequest {
    fn from(value: ShieldOptions) -> Self {
        Self {
            chain_id: value.chain_id,
            token: value.token,
            amount: value.amount,
            recipient: value.recipient,
            private_key: value.private_key,
            wrap: value.wrap,
            send: value.send,
        }
    }
}
