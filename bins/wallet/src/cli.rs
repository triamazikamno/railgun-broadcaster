use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use alloy::hex;
use alloy::primitives::FixedBytes;
use directories::BaseDirs;
use eyre::{Result, WrapErr, eyre};
use reqwest::Url;
use structopt::StructOpt;
use wallet_ops::{
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiReadSource, WalletNetworkMode,
};

const DEFAULT_DB_PATH: &str = "db";
const APP_DATA_DIR: &str = "RailOxide";

#[derive(Clone, StructOpt)]
#[structopt(name = "wallet", about = "Railgun wallet desktop GUI.")]
pub(crate) struct Options {
    #[structopt(long, parse(from_os_str))]
    pub(crate) db_path: Option<PathBuf>,

    /// Route wallet operation HTTP traffic through a proxy.
    #[structopt(long)]
    pub(crate) proxy: Option<Url>,

    /// Wallet network mode: tor (default), proxy, or direct.
    #[structopt(long, possible_values = &["tor", "proxy", "direct"])]
    pub(crate) network_mode: Option<WalletNetworkMode>,

    /// Download and prebuild wallet prover caches, then exit without opening the UI.
    #[structopt(long)]
    pub(crate) build_cache: bool,

    /// POI read source: poi-proxy (default) or indexed-artifacts.
    #[structopt(long, possible_values = &[
        PoiReadSourceArg::POI_PROXY,
        PoiReadSourceArg::INDEXED_ARTIFACTS,
    ])]
    poi_read_source: Option<PoiReadSourceArg>,

    /// Trusted indexed artifact publisher public key as 32-byte hex.
    #[structopt(long)]
    poi_artifact_publisher_pubkey: Option<String>,

    /// Direct URL for the signed indexed artifact manifest.
    #[structopt(long)]
    poi_artifact_manifest_url: Option<Url>,

    /// IPFS CID for the signed indexed artifact manifest.
    #[structopt(long)]
    poi_artifact_manifest_cid: Option<String>,

    /// IPNS name for the signed indexed artifact manifest.
    #[structopt(long)]
    poi_artifact_ipns_name: Option<String>,

    /// IPFS gateway base URL for indexed artifacts; repeat for fallback gateways.
    #[structopt(long)]
    poi_artifact_gateway: Vec<Url>,

    /// Maximum accepted manifest age on first indexed-artifact run, in seconds.
    #[structopt(long)]
    poi_artifact_max_manifest_age_secs: Option<u64>,
}

pub(crate) fn default_db_path() -> PathBuf {
    BaseDirs::new().map_or_else(
        || PathBuf::from(DEFAULT_DB_PATH),
        |dirs| dirs.data_local_dir().join(APP_DATA_DIR),
    )
}

impl Options {
    pub(crate) fn from_args() -> Self {
        <Self as StructOpt>::from_args()
    }

    pub(crate) fn poi_read_source(&self) -> Result<PoiReadSource> {
        match self.poi_read_source {
            Some(PoiReadSourceArg::IndexedArtifacts) => self.indexed_artifact_read_source(),
            Some(PoiReadSourceArg::PoiProxy) => {
                if self.has_artifact_source_config() {
                    tracing::warn!(
                        "POI artifact source flags are ignored with --poi-read-source poi-proxy"
                    );
                }
                Ok(PoiReadSource::PoiProxy)
            }
            None if self.has_artifact_source_config() => self.indexed_artifact_read_source(),
            None => Ok(PoiReadSource::PoiProxy),
        }
    }

    const fn has_artifact_source_config(&self) -> bool {
        self.poi_artifact_publisher_pubkey.is_some()
            || self.poi_artifact_manifest_url.is_some()
            || self.poi_artifact_manifest_cid.is_some()
            || self.poi_artifact_ipns_name.is_some()
            || !self.poi_artifact_gateway.is_empty()
            || self.poi_artifact_max_manifest_age_secs.is_some()
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
        let mut source = self
            .poi_artifact_manifest_url
            .as_ref()
            .map(|url| PoiArtifactManifestSource::Url(url.clone()));
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

fn parse_fixed_hex_32(value: &str) -> Result<FixedBytes<32>> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .wrap_err("decode 32-byte hex value")?;
    let len = bytes.len();
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| eyre!("expected 32-byte hex value, got {len} bytes"))?;
    Ok(FixedBytes::from(bytes))
}
