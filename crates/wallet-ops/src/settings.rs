use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use alloy::hex;
use alloy::primitives::{Address, U256};
use local_db::DbStore;
use railgun_ui::TokenAnchorSource;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BroadcasterFeePolicy, GAS_LIMIT_BUFFER, GAS_PRICE_BUFFER_DENOMINATOR,
    GAS_PRICE_BUFFER_NUMERATOR, PUBLIC_BROADCASTER_REPUBLISH_INTERVAL, PoiArtifactManifestSource,
    PoiArtifactSourceConfig, PoiReadSource, WalletNetworkMode,
    public_balance_refresh_interval_secs,
};
use sync_service::ChainConfigDefaults;

pub const WALLET_SETTINGS_KEY: &str = "wallet-settings";
pub const WALLET_SETTINGS_VERSION: u32 = 1;
pub const OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY: &str =
    "0x24b50dff3cd78a1f5f73b8c484eb4645207fdf00202f2e0f7baf17a11f6b24c9";
pub const OFFICIAL_POI_ARTIFACT_IPNS_NAME: &str =
    "k51qzi5uqu5dh3iwtu0o3o5d014fmgwaslfkody932y6owxn19o0cmhwbsjzyh";
pub const OFFICIAL_POI_ARTIFACT_GATEWAYS: &[&str] = &[
    "https://dweb.link",
    "https://ipfs.filebase.io",
    "https://ipfs.io",
];
pub const DEFAULT_WAKU_CLUSTER_ID: u32 = 5;
pub const DEFAULT_WAKU_SHARD_ID: u32 = 1;
pub const DEFAULT_WAKU_MAX_PEERS: usize = 10;
pub const DEFAULT_WAKU_PEER_CONNECTION_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_PUBLIC_BROADCASTER_RESPONSE_TIMEOUT_SECS: u64 = 120;

const MAX_FINALITY_DEPTH: u64 = 1_000_000;
const MAX_BLOCK_RANGE: u64 = 5_000_000;
const MAX_INTERVAL_SECS: u64 = 86_400;
const SUPPORTED_PROXY_SCHEMES: &[&str] = &["http", "https", "socks5", "socks5h"];

#[derive(Debug, Error)]
pub enum WalletSettingsError {
    #[error(transparent)]
    Db(#[from] local_db::DbError),
    #[error("encode wallet settings: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode wallet settings: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("unsupported wallet settings version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("wallet settings validation failed: {0}")]
    Validation(#[from] WalletSettingsValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSettingsValidationError {
    pub messages: Vec<String>,
}

impl WalletSettingsValidationError {
    #[must_use]
    pub const fn new(messages: Vec<String>) -> Self {
        Self { messages }
    }
}

impl fmt::Display for WalletSettingsValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.messages.join("; "))
    }
}

impl std::error::Error for WalletSettingsValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WalletSettings {
    pub version: u32,
    pub network: NetworkSettings,
    pub chains: ChainSettings,
    pub poi: PoiSettings,
    pub broadcaster: PublicBroadcasterSettings,
    pub tokens: TokenSettings,
    pub gas: GasSettings,
    pub runtime: RuntimeSettings,
    pub waku: WakuSettings,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            version: WALLET_SETTINGS_VERSION,
            network: NetworkSettings::default(),
            chains: ChainSettings::default(),
            poi: PoiSettings::default(),
            broadcaster: PublicBroadcasterSettings::default(),
            tokens: TokenSettings::default(),
            gas: GasSettings::default(),
            runtime: RuntimeSettings::default(),
            waku: WakuSettings::default(),
        }
    }
}

impl WalletSettings {
    pub fn validate(&self) -> Result<(), WalletSettingsValidationError> {
        let mut errors = Vec::new();
        self.network.validate(&mut errors);
        self.chains.validate(&mut errors);
        self.poi.validate(&mut errors);
        self.broadcaster.validate(&mut errors);
        self.tokens.validate(&mut errors);
        self.gas.validate(&mut errors);
        self.runtime.validate(&mut errors);
        self.waku.validate(&mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(WalletSettingsValidationError::new(errors))
        }
    }

    #[must_use]
    pub fn reset_to_defaults() -> Self {
        Self::default()
    }

    pub fn reset_network(&mut self) {
        self.network = NetworkSettings::default();
    }

    pub fn reset_chains(&mut self) {
        self.chains = ChainSettings::default();
    }

    pub fn reset_poi(&mut self) {
        self.poi = PoiSettings::default();
    }

    pub fn reset_broadcaster(&mut self) {
        self.broadcaster = PublicBroadcasterSettings::default();
    }

    pub fn reset_tokens(&mut self) {
        self.tokens = TokenSettings::default();
    }

    pub fn reset_gas(&mut self) {
        self.gas = GasSettings::default();
    }

    pub fn reset_runtime(&mut self) {
        self.runtime = RuntimeSettings::default();
    }

    pub fn reset_waku(&mut self) {
        self.waku = WakuSettings::default();
    }

    #[must_use]
    pub fn wallet_network_mode(&self) -> WalletNetworkMode {
        self.network.mode.into()
    }

    pub fn poi_read_source(&self) -> Result<PoiReadSource, WalletSettingsValidationError> {
        let mut errors = Vec::new();
        self.poi.validate(&mut errors);
        if !errors.is_empty() {
            return Err(WalletSettingsValidationError::new(errors));
        }
        Ok(match self.poi.read_source {
            PoiReadSourceSetting::PoiProxy => PoiReadSource::PoiProxy,
            PoiReadSourceSetting::IndexedArtifacts => {
                PoiReadSource::IndexedArtifacts(self.poi.artifact.source_config())
            }
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkModeSetting {
    #[default]
    Tor,
    Proxy,
    Direct,
}

impl From<NetworkModeSetting> for WalletNetworkMode {
    fn from(value: NetworkModeSetting) -> Self {
        match value {
            NetworkModeSetting::Tor => Self::Tor,
            NetworkModeSetting::Proxy => Self::Proxy,
            NetworkModeSetting::Direct => Self::Direct,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkSettings {
    pub mode: NetworkModeSetting,
    pub proxy_url: Option<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            mode: NetworkModeSetting::Tor,
            proxy_url: None,
        }
    }
}

impl NetworkSettings {
    fn validate(&self, errors: &mut Vec<String>) {
        match (self.mode, self.proxy_url.as_deref()) {
            (NetworkModeSetting::Proxy, Some(proxy)) => {
                validate_url_scheme("network.proxy_url", proxy, SUPPORTED_PROXY_SCHEMES, errors);
            }
            (NetworkModeSetting::Proxy, None) => {
                errors.push("network.proxy_url is required when network.mode is proxy".to_string());
            }
            (NetworkModeSetting::Tor | NetworkModeSetting::Direct, Some(_)) => {
                errors.push(
                    "network.proxy_url may only be configured when network.mode is proxy"
                        .to_string(),
                );
            }
            (NetworkModeSetting::Tor | NetworkModeSetting::Direct, None) => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainSettings {
    pub per_chain: BTreeMap<u64, ChainSettingsOverride>,
}

impl Default for ChainSettings {
    fn default() -> Self {
        let per_chain = railgun_ui::DEFAULT_CHAINS
            .iter()
            .copied()
            .map(|chain_id| (chain_id, ChainSettingsOverride::default()))
            .collect();
        Self { per_chain }
    }
}

impl ChainSettings {
    #[must_use]
    pub fn enabled_chain_ids(&self) -> Vec<u64> {
        railgun_ui::DEFAULT_CHAINS
            .iter()
            .copied()
            .filter(|chain_id| {
                self.per_chain
                    .get(chain_id)
                    .is_none_or(|settings| settings.enabled)
            })
            .collect()
    }

    fn validate(&self, errors: &mut Vec<String>) {
        for (chain_id, settings) in &self.per_chain {
            if !supported_chain_id(*chain_id) {
                errors.push(format!(
                    "chains.per_chain.{chain_id} is not supported; custom chain IDs are out of scope for v1"
                ));
                continue;
            }
            settings.validate(*chain_id, errors);
        }
        if self.enabled_chain_ids().is_empty() {
            errors.push("chains must leave at least one supported chain enabled".to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainSettingsOverride {
    pub enabled: bool,
    pub rpc_endpoints: Vec<String>,
    pub quick_sync: QuickSyncSettings,
    pub contracts: ChainContractSettings,
    pub deployment: ChainDeploymentSettings,
    pub finality_depth: Option<u64>,
    pub block_range: Option<u64>,
    pub poll_interval_secs: Option<u64>,
    pub indexed_wallet_block_range: Option<u64>,
    pub gas: ChainGasSettings,
}

impl Default for ChainSettingsOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            rpc_endpoints: Vec::new(),
            quick_sync: QuickSyncSettings::default(),
            contracts: ChainContractSettings::default(),
            deployment: ChainDeploymentSettings::default(),
            finality_depth: None,
            block_range: None,
            poll_interval_secs: None,
            indexed_wallet_block_range: None,
            gas: ChainGasSettings::default(),
        }
    }
}

impl ChainSettingsOverride {
    fn validate(&self, chain_id: u64, errors: &mut Vec<String>) {
        for (index, rpc) in self.rpc_endpoints.iter().enumerate() {
            validate_url_scheme(
                &format!("chains.per_chain.{chain_id}.rpc_endpoints[{index}]"),
                rpc,
                &["http", "https"],
                errors,
            );
        }
        self.quick_sync.validate(chain_id, errors);
        self.contracts.validate(chain_id, errors);
        self.deployment.validate(
            chain_id,
            self.contracts
                .railgun_contract_differs_from_default(chain_id),
            errors,
        );
        validate_optional_range(
            &format!("chains.per_chain.{chain_id}.finality_depth"),
            self.finality_depth,
            1,
            MAX_FINALITY_DEPTH,
            errors,
        );
        validate_optional_range(
            &format!("chains.per_chain.{chain_id}.block_range"),
            self.block_range,
            1,
            MAX_BLOCK_RANGE,
            errors,
        );
        validate_optional_range(
            &format!("chains.per_chain.{chain_id}.poll_interval_secs"),
            self.poll_interval_secs,
            1,
            MAX_INTERVAL_SECS,
            errors,
        );
        validate_optional_range(
            &format!("chains.per_chain.{chain_id}.indexed_wallet_block_range"),
            self.indexed_wallet_block_range,
            1,
            MAX_BLOCK_RANGE,
            errors,
        );
        self.gas
            .validate(&format!("chains.per_chain.{chain_id}.gas"), errors);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct QuickSyncSettings {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub indexed_wallet_block_range: Option<u64>,
}

impl Default for QuickSyncSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: None,
            indexed_wallet_block_range: None,
        }
    }
}

impl QuickSyncSettings {
    fn validate(&self, chain_id: u64, errors: &mut Vec<String>) {
        if let Some(endpoint) = self.endpoint.as_deref() {
            validate_url_scheme(
                &format!("chains.per_chain.{chain_id}.quick_sync.endpoint"),
                endpoint,
                &["http", "https"],
                errors,
            );
        }
        validate_optional_range(
            &format!("chains.per_chain.{chain_id}.quick_sync.indexed_wallet_block_range"),
            self.indexed_wallet_block_range,
            1,
            MAX_BLOCK_RANGE,
            errors,
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainContractSettings {
    pub railgun_contract: Option<String>,
    pub relay_adapt_contract: Option<String>,
    pub relay_adapt_7702_contract: Option<String>,
    pub wrapped_native_token: Option<String>,
    pub multicall_contract: Option<String>,
}

impl ChainContractSettings {
    #[must_use]
    pub fn railgun_contract_differs_from_default(&self, chain_id: u64) -> bool {
        let Some(contract) = self
            .railgun_contract
            .as_deref()
            .map(str::trim)
            .filter(|contract| !contract.is_empty())
        else {
            return false;
        };
        let Ok(contract) = Address::from_str(contract) else {
            return false;
        };
        let Some(defaults) = ChainConfigDefaults::for_chain(chain_id) else {
            return false;
        };
        contract != defaults.contract
    }

    fn validate(&self, chain_id: u64, errors: &mut Vec<String>) {
        validate_optional_address(
            &format!("chains.per_chain.{chain_id}.contracts.railgun_contract"),
            self.railgun_contract.as_deref(),
            errors,
        );
        validate_optional_address(
            &format!("chains.per_chain.{chain_id}.contracts.relay_adapt_contract"),
            self.relay_adapt_contract.as_deref(),
            errors,
        );
        validate_optional_address(
            &format!("chains.per_chain.{chain_id}.contracts.relay_adapt_7702_contract"),
            self.relay_adapt_7702_contract.as_deref(),
            errors,
        );
        validate_optional_address(
            &format!("chains.per_chain.{chain_id}.contracts.wrapped_native_token"),
            self.wrapped_native_token.as_deref(),
            errors,
        );
        validate_optional_address(
            &format!("chains.per_chain.{chain_id}.contracts.multicall_contract"),
            self.multicall_contract.as_deref(),
            errors,
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainDeploymentSettings {
    pub deployment_block: Option<u64>,
    pub v2_start_block: Option<u64>,
    pub legacy_shield_block: Option<u64>,
    pub archive_until_block: Option<u64>,
    pub archive_rpc_url: Option<String>,
}

impl ChainDeploymentSettings {
    #[must_use]
    pub const fn has_any_override(&self) -> bool {
        self.deployment_block.is_some()
            || self.v2_start_block.is_some()
            || self.legacy_shield_block.is_some()
            || self.archive_until_block.is_some()
            || self.archive_rpc_url.is_some()
    }

    fn validate(&self, chain_id: u64, required: bool, errors: &mut Vec<String>) {
        if required {
            validate_required_u64(
                &format!("chains.per_chain.{chain_id}.deployment.deployment_block"),
                self.deployment_block,
                errors,
            );
            validate_required_u64(
                &format!("chains.per_chain.{chain_id}.deployment.v2_start_block"),
                self.v2_start_block,
                errors,
            );
            validate_required_u64(
                &format!("chains.per_chain.{chain_id}.deployment.legacy_shield_block"),
                self.legacy_shield_block,
                errors,
            );
            validate_required_u64(
                &format!("chains.per_chain.{chain_id}.deployment.archive_until_block"),
                self.archive_until_block,
                errors,
            );
        }
        if let Some(archive_rpc_url) = self.archive_rpc_url.as_deref() {
            validate_url_scheme(
                &format!("chains.per_chain.{chain_id}.deployment.archive_rpc_url"),
                archive_rpc_url,
                &["http", "https"],
                errors,
            );
        }
    }
}

#[must_use]
pub fn should_show_chain_deployment_metadata_settings(
    chain_id: u64,
    settings: &ChainSettingsOverride,
) -> bool {
    settings
        .contracts
        .railgun_contract_differs_from_default(chain_id)
        || settings.deployment.has_any_override()
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PoiReadSourceSetting {
    #[default]
    IndexedArtifacts,
    PoiProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PoiSettings {
    pub read_source: PoiReadSourceSetting,
    pub artifact: PoiArtifactSettings,
    pub proxy: PoiProxySettings,
}

impl Default for PoiSettings {
    fn default() -> Self {
        Self {
            read_source: PoiReadSourceSetting::IndexedArtifacts,
            artifact: PoiArtifactSettings::official_preset(),
            proxy: PoiProxySettings::default(),
        }
    }
}

impl PoiSettings {
    pub fn reset_artifact_to_official_preset(&mut self) {
        self.artifact = PoiArtifactSettings::official_preset();
    }

    fn validate(&self, errors: &mut Vec<String>) {
        match self.read_source {
            PoiReadSourceSetting::IndexedArtifacts => self.artifact.validate_required(errors),
            PoiReadSourceSetting::PoiProxy => {}
        }
        self.proxy.validate(errors);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PoiArtifactSettings {
    pub publisher_pubkey: String,
    pub manifest_source: PoiArtifactManifestSourceSetting,
    pub gateway_urls: Vec<String>,
    pub max_manifest_age_secs: Option<u64>,
}

impl Default for PoiArtifactSettings {
    fn default() -> Self {
        Self::official_preset()
    }
}

impl PoiArtifactSettings {
    #[must_use]
    pub fn official_preset() -> Self {
        Self {
            publisher_pubkey: OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY.to_string(),
            manifest_source: PoiArtifactManifestSourceSetting::IpnsName(
                OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string(),
            ),
            gateway_urls: OFFICIAL_POI_ARTIFACT_GATEWAYS
                .iter()
                .map(ToString::to_string)
                .collect(),
            max_manifest_age_secs: None,
        }
    }

    fn source_config(&self) -> PoiArtifactSourceConfig {
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: parse_fixed_hex_32(&self.publisher_pubkey)
                .expect("validated POI publisher public key"),
            manifest_source: self.manifest_source.to_runtime(),
            gateway_urls: self
                .gateway_urls
                .iter()
                .map(|gateway| Url::parse(gateway).expect("validated POI gateway URL"))
                .collect(),
            max_manifest_age: self
                .max_manifest_age_secs
                .map(std::time::Duration::from_secs),
        }
    }

    fn validate_required(&self, errors: &mut Vec<String>) {
        if self.publisher_pubkey.trim().is_empty() {
            errors.push("poi.artifact.publisher_pubkey is required".to_string());
        } else if parse_fixed_hex_32(&self.publisher_pubkey).is_err() {
            errors.push("poi.artifact.publisher_pubkey must be a 32-byte hex value".to_string());
        }
        self.manifest_source
            .validate("poi.artifact.manifest_source", errors);
        if self.gateway_urls.is_empty() {
            errors.push("poi.artifact.gateway_urls must contain at least one gateway".to_string());
        }
        for (index, gateway) in self.gateway_urls.iter().enumerate() {
            validate_url_scheme(
                &format!("poi.artifact.gateway_urls[{index}]"),
                gateway,
                &["http", "https"],
                errors,
            );
        }
        validate_optional_range(
            "poi.artifact.max_manifest_age_secs",
            self.max_manifest_age_secs,
            1,
            MAX_INTERVAL_SECS * 365,
            errors,
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum PoiArtifactManifestSourceSetting {
    Url(String),
    Cid(String),
    IpnsName(String),
}

impl Default for PoiArtifactManifestSourceSetting {
    fn default() -> Self {
        Self::IpnsName(OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string())
    }
}

impl PoiArtifactManifestSourceSetting {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        match self {
            Self::Url(url) => validate_url_scheme(field, url, &["http", "https"], errors),
            Self::Cid(cid) | Self::IpnsName(cid) => {
                if cid.trim().is_empty() {
                    errors.push(format!("{field} must not be empty"));
                }
            }
        }
    }

    fn to_runtime(&self) -> PoiArtifactManifestSource {
        match self {
            Self::Url(url) => PoiArtifactManifestSource::Url(
                Url::parse(url).expect("validated POI artifact manifest URL"),
            ),
            Self::Cid(cid) => PoiArtifactManifestSource::Cid(cid.clone()),
            Self::IpnsName(name) => PoiArtifactManifestSource::IpnsName(name.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PoiProxySettings {
    pub rpc_url: String,
}

impl Default for PoiProxySettings {
    fn default() -> Self {
        Self {
            rpc_url: poi::poi::DEFAULT_WALLET_POI_RPC_URL.to_string(),
        }
    }
}

impl PoiProxySettings {
    fn validate(&self, errors: &mut Vec<String>) {
        validate_url_scheme(
            "poi.proxy.rpc_url",
            &self.rpc_url,
            &["http", "https"],
            errors,
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PublicBroadcasterSettings {
    pub min_anchor_bps: u64,
    pub max_anchor_bps: u64,
    pub allow_suspicious_broadcasters_by_default: bool,
    pub response_timeout_secs: u64,
    pub republish_interval_secs: u64,
}

impl Default for PublicBroadcasterSettings {
    fn default() -> Self {
        let policy = BroadcasterFeePolicy::default();
        Self {
            min_anchor_bps: policy.min_anchor_bps,
            max_anchor_bps: policy.max_anchor_bps,
            allow_suspicious_broadcasters_by_default: policy.allow_suspicious_broadcasters,
            response_timeout_secs: DEFAULT_PUBLIC_BROADCASTER_RESPONSE_TIMEOUT_SECS,
            republish_interval_secs: PUBLIC_BROADCASTER_REPUBLISH_INTERVAL.as_secs(),
        }
    }
}

impl PublicBroadcasterSettings {
    #[must_use]
    pub const fn fee_policy(&self) -> BroadcasterFeePolicy {
        BroadcasterFeePolicy {
            min_anchor_bps: self.min_anchor_bps,
            max_anchor_bps: self.max_anchor_bps,
            allow_suspicious_broadcasters: self.allow_suspicious_broadcasters_by_default,
        }
    }

    fn validate(&self, errors: &mut Vec<String>) {
        if self.min_anchor_bps > self.max_anchor_bps {
            errors.push(
                "broadcaster.min_anchor_bps must be less than or equal to max_anchor_bps"
                    .to_string(),
            );
        }
        validate_range(
            "broadcaster.response_timeout_secs",
            self.response_timeout_secs,
            1,
            MAX_INTERVAL_SECS,
            errors,
        );
        validate_range(
            "broadcaster.republish_interval_secs",
            self.republish_interval_secs,
            1,
            MAX_INTERVAL_SECS,
            errors,
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TokenSettings {
    pub built_in_overrides: Vec<BuiltInTokenOverride>,
    pub built_in_tombstones: Vec<TokenKey>,
    pub custom_tokens: Vec<CustomTokenSettings>,
    pub price_anchors: Vec<TokenPriceAnchorOverride>,
}

impl TokenSettings {
    fn validate(&self, errors: &mut Vec<String>) {
        for (index, override_settings) in self.built_in_overrides.iter().enumerate() {
            override_settings.validate(&format!("tokens.built_in_overrides[{index}]"), errors);
        }
        for (index, key) in self.built_in_tombstones.iter().enumerate() {
            key.validate(&format!("tokens.built_in_tombstones[{index}]"), errors);
        }
        for (index, token) in self.custom_tokens.iter().enumerate() {
            token.validate(&format!("tokens.custom_tokens[{index}]"), errors);
        }
        for (index, anchor) in self.price_anchors.iter().enumerate() {
            anchor.validate(&format!("tokens.price_anchors[{index}]"), errors);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(default, deny_unknown_fields)]
pub struct TokenKey {
    pub chain_id: u64,
    pub token_address: String,
}

impl Default for TokenKey {
    fn default() -> Self {
        Self {
            chain_id: railgun_ui::DEFAULT_CHAINS[0],
            token_address: Address::ZERO.to_string(),
        }
    }
}

impl TokenKey {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        if !supported_chain_id(self.chain_id) {
            errors.push(format!("{field}.chain_id is not supported"));
        }
        validate_address(
            &format!("{field}.token_address"),
            &self.token_address,
            errors,
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BuiltInTokenOverride {
    pub key: TokenKey,
    pub symbol: Option<String>,
    pub decimals: Option<u8>,
    pub icon_path: Option<String>,
    pub price_anchor: Option<PriceAnchorSettings>,
}

impl BuiltInTokenOverride {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        self.key.validate(&format!("{field}.key"), errors);
        validate_optional_non_empty(&format!("{field}.symbol"), self.symbol.as_deref(), errors);
        if let Some(anchor) = &self.price_anchor {
            anchor.validate(&format!("{field}.price_anchor"), errors);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CustomTokenSettings {
    pub chain_id: u64,
    pub token_address: String,
    pub symbol: String,
    pub decimals: u8,
    pub icon_path: Option<String>,
    pub price_anchor: Option<PriceAnchorSettings>,
}

impl Default for CustomTokenSettings {
    fn default() -> Self {
        Self {
            chain_id: railgun_ui::DEFAULT_CHAINS[0],
            token_address: Address::ZERO.to_string(),
            symbol: String::new(),
            decimals: 18,
            icon_path: None,
            price_anchor: None,
        }
    }
}

impl CustomTokenSettings {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        if !supported_chain_id(self.chain_id) {
            errors.push(format!("{field}.chain_id is not supported"));
        }
        validate_address(
            &format!("{field}.token_address"),
            &self.token_address,
            errors,
        );
        if self.symbol.trim().is_empty() {
            errors.push(format!("{field}.symbol must not be empty"));
        }
        if let Some(anchor) = &self.price_anchor {
            anchor.validate(&format!("{field}.price_anchor"), errors);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TokenPriceAnchorOverride {
    pub key: TokenKey,
    pub price_anchor: PriceAnchorSettings,
}

impl TokenPriceAnchorOverride {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        self.key.validate(&format!("{field}.key"), errors);
        self.price_anchor
            .validate(&format!("{field}.price_anchor"), errors);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PriceAnchorSettings {
    Fixed {
        rate: String,
    },
    Oracle {
        chain_id: u64,
        oracle_address: String,
        token_decimals: u8,
        oracle_decimals: u8,
        is_inversed: bool,
    },
    Product {
        components: Vec<Self>,
        scale_decimals: u8,
    },
}

impl Default for PriceAnchorSettings {
    fn default() -> Self {
        Self::Fixed {
            rate: "1000000000000000000".to_string(),
        }
    }
}

impl PriceAnchorSettings {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        match self {
            Self::Fixed { rate } => {
                if U256::from_str_radix(rate, 10).is_err() {
                    errors.push(format!("{field}.rate must be a decimal integer"));
                }
            }
            Self::Oracle {
                chain_id,
                oracle_address,
                token_decimals,
                oracle_decimals,
                is_inversed: _,
            } => {
                if !supported_chain_id(*chain_id) {
                    errors.push(format!("{field}.chain_id is not supported"));
                }
                validate_address(&format!("{field}.oracle_address"), oracle_address, errors);
                if *token_decimals > 36 {
                    errors.push(format!("{field}.token_decimals must be at most 36"));
                }
                if *oracle_decimals > 36 {
                    errors.push(format!("{field}.oracle_decimals must be at most 36"));
                }
            }
            Self::Product {
                components,
                scale_decimals,
            } => {
                if components.is_empty() {
                    errors.push(format!("{field}.components must not be empty"));
                }
                if *scale_decimals > 36 {
                    errors.push(format!("{field}.scale_decimals must be at most 36"));
                }
                for (index, component) in components.iter().enumerate() {
                    component.validate(&format!("{field}.components[{index}]"), errors);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct GasSettings {
    pub gas_limit_buffer: u64,
    pub gas_price_buffer_numerator: u64,
    pub gas_price_buffer_denominator: u64,
}

impl Default for GasSettings {
    fn default() -> Self {
        Self {
            gas_limit_buffer: GAS_LIMIT_BUFFER,
            gas_price_buffer_numerator: GAS_PRICE_BUFFER_NUMERATOR as u64,
            gas_price_buffer_denominator: GAS_PRICE_BUFFER_DENOMINATOR as u64,
        }
    }
}

impl GasSettings {
    fn validate(&self, errors: &mut Vec<String>) {
        if self.gas_price_buffer_denominator == 0 {
            errors.push("gas.gas_price_buffer_denominator must be greater than 0".to_string());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainGasSettings {
    pub gas_limit_buffer: Option<u64>,
    pub gas_price_buffer_numerator: Option<u64>,
    pub gas_price_buffer_denominator: Option<u64>,
}

impl ChainGasSettings {
    fn validate(&self, field: &str, errors: &mut Vec<String>) {
        if self.gas_price_buffer_denominator == Some(0) {
            errors.push(format!(
                "{field}.gas_price_buffer_denominator must be greater than 0"
            ));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeSettings {
    pub public_balance_refresh_interval_secs: u64,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            public_balance_refresh_interval_secs: public_balance_refresh_interval_secs(),
        }
    }
}

impl RuntimeSettings {
    fn validate(&self, errors: &mut Vec<String>) {
        validate_range(
            "runtime.public_balance_refresh_interval_secs",
            self.public_balance_refresh_interval_secs,
            1,
            MAX_INTERVAL_SECS,
            errors,
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WakuSettings {
    pub cluster_id: u32,
    pub shard_id: u32,
    pub doh_endpoint: Option<String>,
    pub doh_fallback_endpoints: Option<Vec<String>>,
    pub max_peers: usize,
    pub peer_connection_timeout_secs: u64,
    pub nwaku_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveChainConfig {
    pub chain_id: u64,
    pub enabled: bool,
    pub rpc_endpoints: Vec<String>,
    pub archive_rpc_url: Option<String>,
    pub quick_sync_enabled: bool,
    pub quick_sync_endpoint: Option<String>,
    pub indexed_wallet_block_range: u64,
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    pub archive_until_block: u64,
    pub railgun_contract: String,
    pub relay_adapt_contract: String,
    pub relay_adapt_7702_contract: String,
    pub wrapped_native_token: Option<String>,
    pub multicall_contract: String,
    pub finality_depth: u64,
    pub block_range: Option<u64>,
    pub poll_interval_secs: Option<u64>,
    pub gas: EffectiveChainGasSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveChainGasSettings {
    pub gas_limit_buffer: u64,
    pub gas_price_buffer_numerator: u64,
    pub gas_price_buffer_denominator: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTokenRegistry {
    pub tokens: BTreeMap<(u64, String), EffectiveTokenInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTokenInfo {
    pub chain_id: u64,
    pub token_address: String,
    pub symbol: String,
    pub decimals: u8,
    pub icon_path: Option<String>,
    pub price_anchor: Option<PriceAnchorSettings>,
    pub built_in: bool,
}

impl EffectiveTokenRegistry {
    #[must_use]
    pub fn get(&self, chain_id: u64, token: &Address) -> Option<&EffectiveTokenInfo> {
        self.tokens
            .get(&(chain_id, normalize_address_string(&token.to_string())))
    }
}

impl Default for WakuSettings {
    fn default() -> Self {
        Self {
            cluster_id: DEFAULT_WAKU_CLUSTER_ID,
            shard_id: DEFAULT_WAKU_SHARD_ID,
            doh_endpoint: None,
            doh_fallback_endpoints: None,
            max_peers: DEFAULT_WAKU_MAX_PEERS,
            peer_connection_timeout_secs: DEFAULT_WAKU_PEER_CONNECTION_TIMEOUT_SECS,
            nwaku_url: None,
        }
    }
}

impl WakuSettings {
    fn validate(&self, errors: &mut Vec<String>) {
        if let Some(doh_endpoint) = self.doh_endpoint.as_deref() {
            validate_url_scheme(
                "waku.doh_endpoint",
                doh_endpoint,
                &["http", "https"],
                errors,
            );
        }
        if let Some(endpoints) = self.doh_fallback_endpoints.as_deref() {
            for (index, endpoint) in endpoints.iter().enumerate() {
                validate_url_scheme(
                    &format!("waku.doh_fallback_endpoints[{index}]"),
                    endpoint,
                    &["http", "https"],
                    errors,
                );
            }
        }
        if self.max_peers == 0 {
            errors.push("waku.max_peers must be greater than 0".to_string());
        }
        validate_range(
            "waku.peer_connection_timeout_secs",
            self.peer_connection_timeout_secs,
            1,
            MAX_INTERVAL_SECS,
            errors,
        );
        if let Some(nwaku_url) = self.nwaku_url.as_deref() {
            validate_url_scheme("waku.nwaku_url", nwaku_url, &["http", "https"], errors);
        }
    }
}

pub fn load_wallet_settings(store: &DbStore) -> Result<WalletSettings, WalletSettingsError> {
    let Some(payload) = store.get_app_settings_record(WALLET_SETTINGS_KEY)? else {
        return Ok(WalletSettings::default());
    };
    decode_wallet_settings(&payload)
}

pub fn save_wallet_settings(
    store: &DbStore,
    settings: &WalletSettings,
) -> Result<(), WalletSettingsError> {
    let mut settings = settings.clone();
    settings.version = WALLET_SETTINGS_VERSION;
    settings.validate()?;
    let payload = encode_wallet_settings(&settings)?;
    store.put_app_settings_record(WALLET_SETTINGS_KEY, &payload)?;
    Ok(())
}

pub fn delete_wallet_settings(store: &DbStore) -> Result<(), WalletSettingsError> {
    store.delete_app_settings_record(WALLET_SETTINGS_KEY)?;
    Ok(())
}

pub fn encode_wallet_settings(settings: &WalletSettings) -> Result<Vec<u8>, WalletSettingsError> {
    let mut settings = settings.clone();
    settings.version = WALLET_SETTINGS_VERSION;
    Ok(rmp_serde::to_vec_named(&settings)?)
}

pub fn decode_wallet_settings(data: &[u8]) -> Result<WalletSettings, WalletSettingsError> {
    let settings: WalletSettings = rmp_serde::from_slice(data)?;
    if settings.version != WALLET_SETTINGS_VERSION {
        return Err(WalletSettingsError::UnsupportedVersion {
            version: settings.version,
        });
    }
    Ok(settings)
}

pub fn build_effective_chain_configs(
    settings: &WalletSettings,
) -> Result<BTreeMap<u64, EffectiveChainConfig>, WalletSettingsValidationError> {
    settings.validate()?;
    let mut configs = BTreeMap::new();
    for chain_id in railgun_ui::DEFAULT_CHAINS {
        let Some(defaults) = ChainConfigDefaults::for_chain(*chain_id) else {
            return Err(WalletSettingsValidationError::new(vec![format!(
                "chains.per_chain.{chain_id} is not supported"
            )]));
        };
        let override_settings = settings.chains.per_chain.get(chain_id);
        let enabled = override_settings.is_none_or(|settings| settings.enabled);
        let rpc_endpoints = override_settings
            .filter(|settings| !settings.rpc_endpoints.is_empty())
            .map_or_else(
                || defaults.rpc_urls.iter().map(ToString::to_string).collect(),
                |settings| settings.rpc_endpoints.clone(),
            );
        let quick_sync_default = QuickSyncSettings::default();
        let quick_sync =
            override_settings.map_or(&quick_sync_default, |settings| &settings.quick_sync);
        let contracts_default = ChainContractSettings::default();
        let contracts =
            override_settings.map_or(&contracts_default, |settings| &settings.contracts);
        let deployment_default = ChainDeploymentSettings::default();
        let deployment =
            override_settings.map_or(&deployment_default, |settings| &settings.deployment);
        let gas_default = ChainGasSettings::default();
        let gas = override_settings.map_or(&gas_default, |settings| &settings.gas);
        configs.insert(
            *chain_id,
            EffectiveChainConfig {
                chain_id: *chain_id,
                enabled,
                rpc_endpoints,
                archive_rpc_url: deployment.archive_rpc_url.clone(),
                quick_sync_enabled: quick_sync.enabled,
                quick_sync_endpoint: quick_sync.endpoint.clone().or_else(|| {
                    defaults
                        .quick_sync_endpoint
                        .as_ref()
                        .map(ToString::to_string)
                }),
                indexed_wallet_block_range: quick_sync
                    .indexed_wallet_block_range
                    .or_else(|| {
                        override_settings.and_then(|settings| settings.indexed_wallet_block_range)
                    })
                    .unwrap_or(defaults.indexed_wallet_block_range),
                deployment_block: deployment
                    .deployment_block
                    .unwrap_or(defaults.deployment_block),
                v2_start_block: deployment.v2_start_block.unwrap_or(defaults.v2_start_block),
                legacy_shield_block: deployment
                    .legacy_shield_block
                    .unwrap_or(defaults.legacy_shield_block),
                archive_until_block: deployment
                    .archive_until_block
                    .unwrap_or(defaults.archive_until_block),
                railgun_contract: contracts
                    .railgun_contract
                    .clone()
                    .unwrap_or_else(|| defaults.contract.to_string()),
                relay_adapt_contract: contracts
                    .relay_adapt_contract
                    .clone()
                    .unwrap_or_else(|| defaults.relay_adapt_contract.to_string()),
                relay_adapt_7702_contract: contracts
                    .relay_adapt_7702_contract
                    .clone()
                    .unwrap_or_else(|| defaults.relay_adapt_7702_contract.to_string()),
                wrapped_native_token: contracts.wrapped_native_token.clone().or_else(|| {
                    crate::amounts::wrapped_native_token_for_chain(*chain_id)
                        .map(|token| token.to_string())
                }),
                multicall_contract: contracts
                    .multicall_contract
                    .clone()
                    .unwrap_or_else(|| defaults.multicall_contract.to_string()),
                finality_depth: override_settings
                    .and_then(|settings| settings.finality_depth)
                    .unwrap_or(defaults.finality_depth),
                block_range: override_settings.and_then(|settings| settings.block_range),
                poll_interval_secs: override_settings
                    .and_then(|settings| settings.poll_interval_secs),
                gas: EffectiveChainGasSettings {
                    gas_limit_buffer: gas
                        .gas_limit_buffer
                        .unwrap_or(settings.gas.gas_limit_buffer),
                    gas_price_buffer_numerator: gas
                        .gas_price_buffer_numerator
                        .unwrap_or(settings.gas.gas_price_buffer_numerator),
                    gas_price_buffer_denominator: gas
                        .gas_price_buffer_denominator
                        .unwrap_or(settings.gas.gas_price_buffer_denominator),
                },
            },
        );
    }
    Ok(configs)
}

#[must_use]
pub fn default_chain_rpc_endpoints(chain_id: u64) -> Option<Vec<String>> {
    ChainConfigDefaults::for_chain(chain_id)
        .map(|defaults| defaults.rpc_urls.iter().map(ToString::to_string).collect())
}

#[must_use]
pub fn default_chain_quick_sync_endpoint(chain_id: u64) -> Option<String> {
    ChainConfigDefaults::for_chain(chain_id)
        .and_then(|defaults| defaults.quick_sync_endpoint)
        .map(|endpoint| endpoint.to_string())
}

#[must_use]
pub fn default_chain_contract_settings(chain_id: u64) -> Option<ChainContractSettings> {
    let defaults = ChainConfigDefaults::for_chain(chain_id)?;
    Some(ChainContractSettings {
        railgun_contract: Some(defaults.contract.to_string()),
        relay_adapt_contract: Some(defaults.relay_adapt_contract.to_string()),
        relay_adapt_7702_contract: Some(defaults.relay_adapt_7702_contract.to_string()),
        wrapped_native_token: crate::amounts::wrapped_native_token_for_chain(chain_id)
            .map(|token| token.to_string()),
        multicall_contract: Some(defaults.multicall_contract.to_string()),
    })
}

#[must_use]
pub fn default_token_price_anchor(chain_id: u64, token: &Address) -> Option<PriceAnchorSettings> {
    railgun_ui::lookup_token(chain_id, token)
        .and_then(|token| price_anchor_from_static_sources(chain_id, token.anchor_sources))
}

#[must_use]
pub fn default_token_price_anchor_overrides() -> Vec<TokenPriceAnchorOverride> {
    railgun_ui::token_anchor_entries()
        .filter_map(|entry| {
            let price_anchor =
                price_anchor_from_static_sources(entry.chain_id, entry.anchor_sources)?;
            Some(TokenPriceAnchorOverride {
                key: TokenKey {
                    chain_id: entry.chain_id,
                    token_address: entry.token.to_string(),
                },
                price_anchor,
            })
        })
        .collect()
}

pub fn build_effective_token_registry(
    settings: &WalletSettings,
) -> Result<EffectiveTokenRegistry, WalletSettingsValidationError> {
    settings.validate()?;
    let mut tokens = BTreeMap::new();
    for chain_id in railgun_ui::DEFAULT_CHAINS {
        for token in railgun_ui::known_tokens_for_chain(*chain_id) {
            tokens.insert(
                (
                    *chain_id,
                    normalize_address_string(&token.token.to_string()),
                ),
                EffectiveTokenInfo {
                    chain_id: *chain_id,
                    token_address: token.token.to_string(),
                    symbol: token.symbol.to_string(),
                    decimals: token.decimals,
                    icon_path: None,
                    price_anchor: price_anchor_from_static_sources(*chain_id, token.anchor_sources),
                    built_in: true,
                },
            );
        }
    }

    for tombstone in &settings.tokens.built_in_tombstones {
        tokens.remove(&token_key_tuple(tombstone));
    }

    for override_settings in &settings.tokens.built_in_overrides {
        if let Some(token) = tokens.get_mut(&token_key_tuple(&override_settings.key)) {
            if let Some(symbol) = override_settings.symbol.as_ref() {
                token.symbol.clone_from(symbol);
            }
            if let Some(decimals) = override_settings.decimals {
                token.decimals = decimals;
            }
            if let Some(icon_path) = override_settings.icon_path.as_ref() {
                token.icon_path = Some(icon_path.clone());
            }
            if let Some(anchor) = override_settings.price_anchor.as_ref() {
                token.price_anchor = Some(anchor.clone());
            }
        }
    }

    for custom in &settings.tokens.custom_tokens {
        tokens.insert(
            (
                custom.chain_id,
                normalize_address_string(&custom.token_address),
            ),
            EffectiveTokenInfo {
                chain_id: custom.chain_id,
                token_address: custom.token_address.clone(),
                symbol: custom.symbol.clone(),
                decimals: custom.decimals,
                icon_path: custom.icon_path.clone(),
                price_anchor: custom.price_anchor.clone(),
                built_in: false,
            },
        );
    }

    for anchor in &settings.tokens.price_anchors {
        if let Some(token) = tokens.get_mut(&token_key_tuple(&anchor.key)) {
            token.price_anchor = Some(anchor.price_anchor.clone());
        }
    }

    Ok(EffectiveTokenRegistry { tokens })
}

fn supported_chain_id(chain_id: u64) -> bool {
    railgun_ui::DEFAULT_CHAINS.contains(&chain_id)
}

fn token_key_tuple(key: &TokenKey) -> (u64, String) {
    (key.chain_id, normalize_address_string(&key.token_address))
}

fn normalize_address_string(address: &str) -> String {
    Address::from_str(address).map_or_else(
        |_| address.to_ascii_lowercase(),
        |address| address.to_string().to_ascii_lowercase(),
    )
}

fn price_anchor_from_static_sources(
    chain_id: u64,
    sources: &[TokenAnchorSource],
) -> Option<PriceAnchorSettings> {
    let [source] = sources else {
        return None;
    };
    price_anchor_from_static_source(chain_id, source)
}

fn price_anchor_from_static_source(
    chain_id: u64,
    source: &TokenAnchorSource,
) -> Option<PriceAnchorSettings> {
    match source {
        TokenAnchorSource::Fixed {
            token_fee_per_unit_gas,
        } => Some(PriceAnchorSettings::Fixed {
            rate: token_fee_per_unit_gas.to_string(),
        }),
        TokenAnchorSource::ChainlinkOracle {
            addr,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => Some(PriceAnchorSettings::Oracle {
            chain_id,
            oracle_address: addr.to_string(),
            token_decimals: *token_decimals,
            oracle_decimals: *oracle_decimals,
            is_inversed: *is_inversed,
        }),
        TokenAnchorSource::Product {
            sources,
            scale_decimals,
        } => Some(PriceAnchorSettings::Product {
            components: sources
                .iter()
                .map(|source| price_anchor_from_static_source(chain_id, source))
                .collect::<Option<Vec<_>>>()?,
            scale_decimals: *scale_decimals,
        }),
    }
}

fn validate_address(field: &str, value: &str, errors: &mut Vec<String>) {
    if Address::from_str(value).is_err() {
        errors.push(format!("{field} must be an EVM address"));
    }
}

fn validate_optional_address(field: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if let Some(value) = value {
        validate_address(field, value, errors);
    }
}

fn validate_optional_non_empty(field: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if value.is_some_and(|value| value.trim().is_empty()) {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_url_scheme(field: &str, value: &str, schemes: &[&str], errors: &mut Vec<String>) {
    match Url::parse(value) {
        Ok(url) if schemes.contains(&url.scheme()) => {}
        Ok(url) => errors.push(format!(
            "{field} must use one of these URL schemes: {}; got {}",
            schemes.join(", "),
            url.scheme()
        )),
        Err(error) => errors.push(format!("{field} is not a valid URL: {error}")),
    }
}

fn validate_optional_range(
    field: &str,
    value: Option<u64>,
    min: u64,
    max: u64,
    errors: &mut Vec<String>,
) {
    if let Some(value) = value {
        validate_range(field, value, min, max, errors);
    }
}

fn validate_required_u64(field: &str, value: Option<u64>, errors: &mut Vec<String>) {
    if value.is_none() {
        errors.push(format!(
            "{field} is required when railgun_contract is custom"
        ));
    }
}

fn validate_range(field: &str, value: u64, min: u64, max: u64, errors: &mut Vec<String>) {
    if value < min || value > max {
        errors.push(format!("{field} must be between {min} and {max}"));
    }
}

fn parse_fixed_hex_32(value: &str) -> Result<alloy::primitives::FixedBytes<32>, hex::FromHexError> {
    hex::decode_to_array(value.strip_prefix("0x").unwrap_or(value)).map(Into::into)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use local_db::{DbConfig, DbStore};

    use super::{
        OFFICIAL_POI_ARTIFACT_GATEWAYS, OFFICIAL_POI_ARTIFACT_IPNS_NAME,
        OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY, PoiArtifactManifestSourceSetting,
        PoiReadSourceSetting, WALLET_SETTINGS_KEY, WALLET_SETTINGS_VERSION, WalletSettings,
        WalletSettingsError, build_effective_chain_configs, build_effective_token_registry,
        decode_wallet_settings, encode_wallet_settings, load_wallet_settings, save_wallet_settings,
        should_show_chain_deployment_metadata_settings,
    };
    use sync_service::ChainConfigDefaults;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-settings-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

    #[test]
    fn missing_settings_synthesizes_official_indexed_artifact_defaults() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");

        let settings = load_wallet_settings(&store).expect("load settings");
        assert_eq!(settings.version, WALLET_SETTINGS_VERSION);
        assert_eq!(
            settings.poi.read_source,
            PoiReadSourceSetting::IndexedArtifacts
        );
        assert_eq!(
            settings.poi.artifact.publisher_pubkey,
            OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY
        );
        assert_eq!(
            settings.poi.artifact.manifest_source,
            PoiArtifactManifestSourceSetting::IpnsName(OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string())
        );
        assert_eq!(
            settings.poi.artifact.gateway_urls,
            OFFICIAL_POI_ARTIFACT_GATEWAYS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert!(
            store
                .get_app_settings_record(WALLET_SETTINGS_KEY)
                .expect("load raw settings")
                .is_none()
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn settings_roundtrip_through_local_db() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let mut settings = WalletSettings::default();
        settings.network.mode = super::NetworkModeSetting::Direct;
        settings.poi.read_source = PoiReadSourceSetting::PoiProxy;

        save_wallet_settings(&store, &settings).expect("save settings");
        let loaded = load_wallet_settings(&store).expect("load settings");
        assert_eq!(loaded, settings);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn unsupported_future_settings_version_is_rejected() {
        let settings = WalletSettings {
            version: WALLET_SETTINGS_VERSION + 1,
            ..WalletSettings::default()
        };
        let data = rmp_serde::to_vec_named(&settings).expect("encode future settings");

        let err = decode_wallet_settings(&data).expect_err("future version rejected");
        assert!(matches!(
            err,
            WalletSettingsError::UnsupportedVersion { version }
                if version == WALLET_SETTINGS_VERSION + 1
        ));
    }

    #[test]
    fn validation_rejects_ambiguous_proxy_and_disabled_chains() {
        let mut settings = WalletSettings::default();
        settings.network.proxy_url = Some("http://127.0.0.1:9050".to_string());
        for chain in settings.chains.per_chain.values_mut() {
            chain.enabled = false;
        }

        let err = settings.validate().expect_err("settings invalid");
        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("proxy_url"))
        );
        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("at least one supported chain"))
        );
    }

    #[test]
    fn reset_helpers_restore_defaults() {
        let mut settings = WalletSettings::default();
        settings.network.mode = super::NetworkModeSetting::Direct;
        settings.poi.artifact.gateway_urls.clear();

        settings.reset_network();
        settings.reset_poi();

        assert_eq!(settings.network, super::NetworkSettings::default());
        assert_eq!(settings.poi, super::PoiSettings::default());
    }

    #[test]
    fn effective_chain_configs_use_supported_presets_without_overrides() {
        let settings = WalletSettings::default();
        let configs = build_effective_chain_configs(&settings).expect("build effective configs");
        let ethereum = configs.get(&1).expect("ethereum config");
        let defaults = ChainConfigDefaults::for_chain(1).expect("ethereum defaults");

        assert!(ethereum.enabled);
        assert_eq!(
            ethereum.rpc_endpoints,
            defaults
                .rpc_urls
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert!(ethereum.rpc_endpoints.len() > 1);
        assert_eq!(ethereum.finality_depth, defaults.finality_depth);
        assert_eq!(ethereum.deployment_block, defaults.deployment_block);
        assert_eq!(ethereum.v2_start_block, defaults.v2_start_block);
        assert_eq!(ethereum.legacy_shield_block, defaults.legacy_shield_block);
        assert_eq!(ethereum.archive_until_block, defaults.archive_until_block);
        assert_eq!(ethereum.archive_rpc_url, None);
        assert_eq!(
            ethereum.quick_sync_endpoint,
            defaults.quick_sync_endpoint.map(|url| url.to_string())
        );
        assert_eq!(
            ethereum.multicall_contract,
            defaults.multicall_contract.to_string()
        );
    }

    #[test]
    fn effective_chain_configs_apply_supported_overrides_in_order() {
        let mut settings = WalletSettings::default();
        let ethereum = settings
            .chains
            .per_chain
            .get_mut(&1)
            .expect("ethereum settings");
        ethereum.rpc_endpoints = vec![
            "https://rpc-a.example".to_string(),
            "https://rpc-b.example".to_string(),
        ];
        ethereum.quick_sync.endpoint = Some("https://quick.example/graphql".to_string());
        ethereum.finality_depth = Some(64);
        ethereum.contracts.multicall_contract =
            Some("0x0000000000000000000000000000000000000001".to_string());
        ethereum.deployment.deployment_block = Some(11);
        ethereum.deployment.v2_start_block = Some(22);
        ethereum.deployment.legacy_shield_block = Some(33);
        ethereum.deployment.archive_until_block = Some(44);
        ethereum.deployment.archive_rpc_url = Some("https://archive.example".to_string());
        ethereum.gas.gas_limit_buffer = Some(250_000);

        let configs = build_effective_chain_configs(&settings).expect("build effective configs");
        let ethereum = configs.get(&1).expect("ethereum config");

        assert_eq!(
            ethereum.rpc_endpoints,
            vec!["https://rpc-a.example", "https://rpc-b.example"]
        );
        assert_eq!(
            ethereum.quick_sync_endpoint.as_deref(),
            Some("https://quick.example/graphql")
        );
        assert_eq!(ethereum.finality_depth, 64);
        assert_eq!(ethereum.deployment_block, 11);
        assert_eq!(ethereum.v2_start_block, 22);
        assert_eq!(ethereum.legacy_shield_block, 33);
        assert_eq!(ethereum.archive_until_block, 44);
        assert_eq!(
            ethereum.archive_rpc_url.as_deref(),
            Some("https://archive.example")
        );
        assert_eq!(
            ethereum.multicall_contract,
            "0x0000000000000000000000000000000000000001"
        );
        assert_eq!(ethereum.gas.gas_limit_buffer, 250_000);
    }

    #[test]
    fn custom_railgun_contract_requires_deployment_metadata() {
        let mut settings = WalletSettings::default();
        settings
            .chains
            .per_chain
            .get_mut(&1)
            .expect("ethereum settings")
            .contracts
            .railgun_contract = Some("0x0000000000000000000000000000000000000001".to_string());

        let err = settings
            .validate()
            .expect_err("deployment metadata required");
        assert!(
            err.messages.iter().any(|message| {
                message.contains("chains.per_chain.1.deployment.deployment_block")
            })
        );
        assert!(should_show_chain_deployment_metadata_settings(
            1,
            settings
                .chains
                .per_chain
                .get(&1)
                .expect("ethereum settings")
        ));

        let ethereum = settings
            .chains
            .per_chain
            .get_mut(&1)
            .expect("ethereum settings");
        ethereum.deployment.deployment_block = Some(11);
        ethereum.deployment.v2_start_block = Some(22);
        ethereum.deployment.legacy_shield_block = Some(33);
        ethereum.deployment.archive_until_block = Some(0);

        settings.validate().expect("metadata supplied");
    }

    #[test]
    fn effective_chain_configs_apply_quick_sync_bounds_and_disabled_state() {
        let mut settings = WalletSettings::default();
        let ethereum = settings
            .chains
            .per_chain
            .get_mut(&1)
            .expect("ethereum settings");
        ethereum.quick_sync.enabled = false;
        ethereum.quick_sync.indexed_wallet_block_range = Some(25_000);
        ethereum.block_range = Some(2_000);
        ethereum.poll_interval_secs = Some(30);

        let configs = build_effective_chain_configs(&settings).expect("build effective configs");
        let ethereum = configs.get(&1).expect("ethereum config");

        assert!(!ethereum.quick_sync_enabled);
        assert_eq!(ethereum.indexed_wallet_block_range, 25_000);
        assert_eq!(ethereum.block_range, Some(2_000));
        assert_eq!(ethereum.poll_interval_secs, Some(30));
    }

    #[test]
    fn chain_reset_restores_supported_chain_defaults() {
        let mut settings = WalletSettings::default();
        settings
            .chains
            .per_chain
            .get_mut(&1)
            .expect("ethereum settings")
            .enabled = false;

        settings.reset_chains();

        assert_eq!(settings.chains, super::ChainSettings::default());
        assert!(settings.chains.enabled_chain_ids().contains(&1));
    }

    #[test]
    fn effective_chain_configs_reject_unsupported_chain_ids() {
        let mut settings = WalletSettings::default();
        settings
            .chains
            .per_chain
            .insert(999, super::ChainSettingsOverride::default());

        let err = build_effective_chain_configs(&settings).expect_err("unsupported chain rejected");
        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("custom chain IDs are out of scope"))
        );
    }

    #[test]
    fn effective_token_registry_applies_overrides_tombstones_and_custom_tokens() {
        let mut settings = WalletSettings::default();
        let weth = super::TokenKey {
            chain_id: 1,
            token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
        };
        settings
            .tokens
            .built_in_overrides
            .push(super::BuiltInTokenOverride {
                key: weth,
                symbol: Some("WETHx".to_string()),
                decimals: Some(18),
                icon_path: None,
                price_anchor: Some(super::PriceAnchorSettings::Fixed {
                    rate: "2000000000000000000".to_string(),
                }),
            });
        settings.tokens.built_in_tombstones.push(super::TokenKey {
            chain_id: 1,
            token_address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
        });
        settings
            .tokens
            .custom_tokens
            .push(super::CustomTokenSettings {
                chain_id: 1,
                token_address: "0x0000000000000000000000000000000000000002".to_string(),
                symbol: "CSTM".to_string(),
                decimals: 9,
                icon_path: None,
                price_anchor: None,
            });

        let registry = build_effective_token_registry(&settings).expect("build token registry");
        let weth = registry
            .tokens
            .get(&(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string()))
            .expect("weth token");
        assert_eq!(weth.symbol, "WETHx");
        assert!(weth.price_anchor.is_some());
        assert!(
            !registry
                .tokens
                .contains_key(&(1, "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string()))
        );
        let custom = registry
            .tokens
            .get(&(1, "0x0000000000000000000000000000000000000002".to_string()))
            .expect("custom token");
        assert!(!custom.built_in);
        assert_eq!(custom.decimals, 9);
    }

    #[test]
    fn effective_token_registry_includes_static_price_anchor_defaults() {
        let settings = WalletSettings::default();

        let registry = build_effective_token_registry(&settings).expect("build token registry");

        let weth = registry
            .tokens
            .get(&(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string()))
            .expect("weth token");
        assert_eq!(
            weth.price_anchor,
            Some(super::PriceAnchorSettings::Fixed {
                rate: "1000000000000000000".to_string(),
            })
        );

        let usdt = registry
            .tokens
            .get(&(1, "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string()))
            .expect("usdt token");
        assert!(matches!(
            usdt.price_anchor,
            Some(super::PriceAnchorSettings::Oracle {
                chain_id: 1,
                token_decimals: 6,
                oracle_decimals: 8,
                is_inversed: false,
                ..
            })
        ));
    }

    #[test]
    fn broadcaster_settings_build_fee_policy_and_validate_thresholds() {
        let mut settings = WalletSettings::default();
        settings.broadcaster.min_anchor_bps = 9_000;
        settings.broadcaster.max_anchor_bps = 11_000;
        settings
            .broadcaster
            .allow_suspicious_broadcasters_by_default = true;
        settings.broadcaster.response_timeout_secs = 45;

        settings.validate().expect("broadcaster settings valid");
        let policy = settings.broadcaster.fee_policy();
        assert_eq!(policy.min_anchor_bps, 9_000);
        assert_eq!(policy.max_anchor_bps, 11_000);
        assert!(policy.allow_suspicious_broadcasters);

        settings.broadcaster.min_anchor_bps = 12_000;
        let err = settings
            .validate()
            .expect_err("invalid thresholds rejected");
        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("min_anchor_bps"))
        );
    }

    #[test]
    fn price_anchor_validation_covers_oracle_and_product_metadata() {
        let mut settings = WalletSettings::default();
        settings
            .tokens
            .price_anchors
            .push(super::TokenPriceAnchorOverride {
                key: super::TokenKey {
                    chain_id: 1,
                    token_address: "0x0000000000000000000000000000000000000002".to_string(),
                },
                price_anchor: super::PriceAnchorSettings::Product {
                    scale_decimals: 18,
                    components: vec![super::PriceAnchorSettings::Oracle {
                        chain_id: 1,
                        oracle_address: "0x0000000000000000000000000000000000000003".to_string(),
                        token_decimals: 18,
                        oracle_decimals: 8,
                        is_inversed: false,
                    }],
                },
            });

        settings.validate().expect("anchor metadata valid");

        let super::PriceAnchorSettings::Product { components, .. } = &mut settings
            .tokens
            .price_anchors
            .first_mut()
            .expect("price anchor")
            .price_anchor
        else {
            panic!("expected product anchor");
        };
        let super::PriceAnchorSettings::Oracle {
            oracle_decimals, ..
        } = &mut components[0]
        else {
            panic!("expected oracle anchor");
        };
        *oracle_decimals = 37;

        let err = settings
            .validate()
            .expect_err("bad oracle decimals rejected");
        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("oracle_decimals"))
        );
    }

    #[test]
    fn default_poi_read_source_converts_to_official_indexed_artifacts() {
        let settings = WalletSettings::default();
        let super::PoiReadSource::IndexedArtifacts(source) =
            settings.poi_read_source().expect("POI source")
        else {
            panic!("default POI source should be indexed artifacts");
        };

        assert_eq!(
            alloy::hex::encode(source.trusted_publisher_pubkey.as_slice()),
            OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY.trim_start_matches("0x")
        );
        assert_eq!(
            source.manifest_source,
            super::PoiArtifactManifestSource::IpnsName(OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string())
        );
        assert_eq!(
            source.gateway_urls.len(),
            OFFICIAL_POI_ARTIFACT_GATEWAYS.len()
        );
    }

    #[test]
    fn waku_settings_defaults_match_startup_defaults() {
        let settings = WalletSettings::default();
        assert_eq!(settings.waku.cluster_id, super::DEFAULT_WAKU_CLUSTER_ID);
        assert_eq!(settings.waku.shard_id, super::DEFAULT_WAKU_SHARD_ID);
        assert!(settings.waku.doh_endpoint.is_none());
        assert!(settings.waku.doh_fallback_endpoints.is_none());
        assert_eq!(settings.waku.max_peers, super::DEFAULT_WAKU_MAX_PEERS);
        assert_eq!(
            settings.waku.peer_connection_timeout_secs,
            super::DEFAULT_WAKU_PEER_CONNECTION_TIMEOUT_SECS
        );
    }

    #[test]
    fn waku_doh_fallback_endpoints_validate_url_schemes() {
        let mut settings = WalletSettings::default();
        settings.waku.doh_fallback_endpoints =
            Some(vec!["ftp://bad.example/dns-query".to_string()]);

        let err = settings
            .validate()
            .expect_err("bad DoH fallback scheme rejected");

        assert!(
            err.messages
                .iter()
                .any(|message| message.contains("waku.doh_fallback_endpoints[0]"))
        );
    }

    #[test]
    fn encoded_settings_decode_without_db() {
        let settings = WalletSettings::default();
        let data = encode_wallet_settings(&settings).expect("encode settings");
        let decoded = decode_wallet_settings(&data).expect("decode settings");
        assert_eq!(decoded, settings);
    }
}
