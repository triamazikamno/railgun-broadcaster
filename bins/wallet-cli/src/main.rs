use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use alloy::hex;
use alloy::primitives::Address;
use alloy::primitives::FixedBytes;
use eyre::{Result, WrapErr, eyre};
use reqwest::Url;
use serde::Serialize;
use structopt::StructOpt;
use tracing::metadata::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use wallet_ops::{
    ListUtxosRequest, PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiReadSource,
    ShieldRequest, ShieldResult, UnshieldRequest, UnshieldResult, WalletNetworkConfig,
    WalletNetworkMode, build_wallet_network_context, list_utxos, shield, unshield,
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
    /// POI read source: poi-proxy (default) or indexed-artifacts.
    #[structopt(long, global = true, possible_values = &[
        PoiReadSourceArg::POI_PROXY,
        PoiReadSourceArg::INDEXED_ARTIFACTS,
    ])]
    poi_read_source: Option<PoiReadSourceArg>,
    /// Trusted indexed artifact publisher public key as 32-byte hex.
    #[structopt(long, global = true)]
    poi_artifact_publisher_pubkey: Option<String>,
    /// Direct URL for the signed indexed artifact manifest.
    #[structopt(long, global = true)]
    poi_artifact_manifest_url: Option<Url>,
    /// IPFS CID for the signed indexed artifact manifest.
    #[structopt(long, global = true)]
    poi_artifact_manifest_cid: Option<String>,
    /// IPNS name for the signed indexed artifact manifest.
    #[structopt(long, global = true)]
    poi_artifact_ipns_name: Option<String>,
    /// IPFS gateway base URL for indexed artifacts; repeat for fallback gateways.
    #[structopt(long, global = true)]
    poi_artifact_gateway: Vec<Url>,
    /// Maximum accepted manifest age on first indexed-artifact run, in seconds.
    #[structopt(long, global = true)]
    poi_artifact_max_manifest_age_secs: Option<u64>,
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

    fn poi_read_source(&self) -> Result<PoiReadSource> {
        match self.poi_read_source {
            Some(PoiReadSourceArg::IndexedArtifacts) => self.indexed_artifact_read_source(),
            Some(PoiReadSourceArg::PoiProxy) | None => Ok(PoiReadSource::PoiProxy),
        }
    }

    fn indexed_artifact_read_source(&self) -> Result<PoiReadSource> {
        let trusted_publisher_pubkey = self
            .poi_artifact_publisher_pubkey
            .as_deref()
            .ok_or_else(|| {
                eyre!(
                    "--poi-read-source indexed-artifacts requires --poi-artifact-publisher-pubkey"
                )
            })
            .and_then(parse_fixed_hex_32)?;
        let manifest_source = self.poi_artifact_manifest_source()?;
        if self.poi_artifact_gateway.is_empty() {
            return Err(eyre!(
                "--poi-read-source indexed-artifacts requires at least one --poi-artifact-gateway"
            ));
        }
        Ok(PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
            trusted_publisher_pubkey,
            manifest_source,
            gateway_urls: self.poi_artifact_gateway.clone(),
            max_manifest_age: self
                .poi_artifact_max_manifest_age_secs
                .map(Duration::from_secs),
        }))
    }

    fn poi_artifact_manifest_source(&self) -> Result<PoiArtifactManifestSource> {
        let mut source = None;
        if let Some(url) = self.poi_artifact_manifest_url.as_ref() {
            source = Some(PoiArtifactManifestSource::Url(url.clone()));
        }
        if let Some(cid) = self.poi_artifact_manifest_cid.as_ref() {
            if source.is_some() {
                return Err(eyre!("configure only one POI artifact manifest source"));
            }
            source = Some(PoiArtifactManifestSource::Cid(cid.clone()));
        }
        if let Some(name) = self.poi_artifact_ipns_name.as_ref() {
            if source.is_some() {
                return Err(eyre!("configure only one POI artifact manifest source"));
            }
            source = Some(PoiArtifactManifestSource::IpnsName(name.clone()));
        }
        source.ok_or_else(|| {
            eyre!(
                "--poi-read-source indexed-artifacts requires --poi-artifact-manifest-url, --poi-artifact-manifest-cid, or --poi-artifact-ipns-name"
            )
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PoiReadSourceArg {
    IndexedArtifacts,
    PoiProxy,
}

impl PoiReadSourceArg {
    const INDEXED_ARTIFACTS: &'static str = "indexed-artifacts";
    const POI_PROXY: &'static str = "poi-proxy";
}

impl FromStr for PoiReadSourceArg {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            Self::INDEXED_ARTIFACTS => Ok(Self::IndexedArtifacts),
            Self::POI_PROXY => Ok(Self::PoiProxy),
            other => Err(format!(
                "unsupported POI read source {other:?}; expected indexed-artifacts or poi-proxy"
            )),
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
    let poi_read_source = options.poi_read_source()?;
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
            let mut request: ListUtxosRequest = opts.into();
            request.poi_read_source = poi_read_source.clone();
            let output = list_utxos(request, rpc_url_override, &http_client).await?;
            print_json(&output)
        }
        Command::Unshield(opts) => {
            let mut request: UnshieldRequest = opts.into();
            request.poi_read_source = poi_read_source;
            let output = unshield(request, rpc_url_override, &http_client).await?;
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

fn parse_fixed_hex_32(value: &str) -> Result<FixedBytes<32>> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .wrap_err("decode 32-byte hex value")?;
    let len = bytes.len();
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| eyre!("expected 32-byte hex value, got {len} bytes"))?;
    Ok(FixedBytes::from(bytes))
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
            poi_read_source: PoiReadSource::PoiProxy,
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
            poi_read_source: PoiReadSource::PoiProxy,
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
            poi_read_source: None,
            poi_artifact_publisher_pubkey: None,
            poi_artifact_manifest_url: None,
            poi_artifact_manifest_cid: None,
            poi_artifact_ipns_name: None,
            poi_artifact_gateway: Vec::new(),
            poi_artifact_max_manifest_age_secs: None,
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
            poi_read_source: None,
            poi_artifact_publisher_pubkey: None,
            poi_artifact_manifest_url: None,
            poi_artifact_manifest_cid: None,
            poi_artifact_ipns_name: None,
            poi_artifact_gateway: Vec::new(),
            poi_artifact_max_manifest_age_secs: None,
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
