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
    WalletNetworkConfig, WalletNetworkMode, build_wallet_network_context, list_utxos, shield,
    unshield,
};

const DEFAULT_DB_PATH: &str = "db";
const SHIELD_NETWORK_DATA_DIR: &str = "railgun-wallet-cli";

#[derive(StructOpt)]
#[structopt(name = "wallet-cli")]
struct Options {
    /// Override the default RPC URL for the chain
    #[structopt(long, global = true)]
    rpc_url: Option<Url>,
    /// Route all HTTP traffic through a proxy (e.g. socks5h://127.0.0.1:9050 for Tor)
    #[structopt(long, global = true)]
    proxy: Option<Url>,
    /// Wallet network mode: tor (default), proxy, or direct.
    #[structopt(long, global = true, possible_values = &["tor", "proxy", "direct"])]
    network_mode: Option<WalletNetworkMode>,
    #[structopt(subcommand)]
    command: Command,
}

impl Options {
    fn network_data_path(&self) -> PathBuf {
        match &self.command {
            Command::ListUtxos(opts) => opts.db_path.clone(),
            Command::Unshield(opts) => opts.db_path.clone(),
            Command::Shield(_) => std::env::temp_dir().join(SHIELD_NETWORK_DATA_DIR),
        }
    }
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

    let network_data_path = options.network_data_path();
    let rpc_url_override = options.rpc_url;
    let http_client = build_wallet_network_context(WalletNetworkConfig {
        network_mode: options.network_mode,
        proxy: options.proxy.as_ref(),
        data_dir: &network_data_path,
    })
    .await?;
    tracing::info!(
        network_mode = %http_client.network_mode(),
        network_status = http_client.network_status_label(),
        network_detail = %http_client.network_status_detail(),
        "wallet-cli network context ready"
    );
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
            sync_to_block: None,
            use_indexed_wallet_catch_up: true,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn shield_options() -> ShieldOptions {
        ShieldOptions {
            chain_id: 1,
            token: Address::ZERO,
            amount: "1".to_string(),
            recipient: "0zk-test".to_string(),
            private_key: "0x00".to_string(),
            wrap: false,
            send: false,
        }
    }

    #[test]
    fn shield_network_data_path_uses_temp_dir_not_cwd_db() {
        let options = Options {
            rpc_url: None,
            proxy: None,
            network_mode: None,
            command: Command::Shield(shield_options()),
        };

        assert_eq!(
            options.network_data_path(),
            std::env::temp_dir().join(SHIELD_NETWORK_DATA_DIR)
        );
        assert_ne!(options.network_data_path(), PathBuf::from(DEFAULT_DB_PATH));
    }

    #[test]
    fn wallet_sync_commands_use_configured_db_for_network_data() {
        let db_path = PathBuf::from("custom-db");
        let options = Options {
            rpc_url: None,
            proxy: None,
            network_mode: None,
            command: Command::ListUtxos(ListUtxosOptions {
                mnemonic: "test".to_string(),
                chain_id: 1,
                db_path: db_path.clone(),
                init_block_number: None,
            }),
        };

        assert_eq!(options.network_data_path(), db_path);
    }
}
