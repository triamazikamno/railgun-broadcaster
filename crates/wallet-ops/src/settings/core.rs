use super::{
    ChainSettings, Deserialize, Error, GasSettings, NetworkSettings, PoiReadSource,
    PoiReadSourceSetting, PoiSettings, PublicBroadcasterSettings, RuntimeSettings, Serialize,
    TokenSettings, WakuSettings, WalletNetworkMode, fmt,
};

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
pub const DEFAULT_WAKU_DIRECT_PEER_ID: &str =
    "16Uiu2HAkwhijhoc4UxAJD4fmYgSX91FzSDqehAaxJogYFcyo736a";
pub const DEFAULT_WAKU_DIRECT_PEER_ADDR: &str = "/dns4/baaamooobaaa.mooo.com/tcp/8000/wss";

pub(super) const MAX_FINALITY_DEPTH: u64 = 1_000_000;
pub(super) const MAX_BLOCK_RANGE: u64 = 5_000_000;
pub(super) const MAX_INTERVAL_SECS: u64 = 86_400;
pub(super) const SUPPORTED_PROXY_SCHEMES: &[&str] = &["http", "https", "socks5", "socks5h"];

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
