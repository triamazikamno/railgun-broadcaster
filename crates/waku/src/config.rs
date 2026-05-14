use std::sync::Arc;
use std::time::Duration;

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use crate::discovery::DiscoveryConfig;

pub type WakuTorClient = TorClient<PreferredRuntime>;
pub type WakuTorClientProvider = Arc<dyn Fn() -> Option<WakuTorClient> + Send + Sync>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WakuTransportProfile {
    #[default]
    Direct,
    Tor,
}

impl WakuTransportProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Tor => "tor",
        }
    }
}

#[derive(Clone)]
pub struct WakuNetworkConfig {
    pub transport_profile: WakuTransportProfile,
    pub http_client: Option<reqwest::Client>,
    pub tor_client: Option<WakuTorClientProvider>,
}

impl WakuNetworkConfig {
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            transport_profile: WakuTransportProfile::Direct,
            http_client: None,
            tor_client: None,
        }
    }

    #[must_use]
    pub fn tor_with_client_provider(
        tor_client: WakuTorClientProvider,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            transport_profile: WakuTransportProfile::Tor,
            http_client: Some(http_client),
            tor_client: Some(tor_client),
        }
    }
}

impl Default for WakuNetworkConfig {
    fn default() -> Self {
        Self::direct()
    }
}

impl std::fmt::Debug for WakuNetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakuNetworkConfig")
            .field("transport_profile", &self.transport_profile)
            .field("http_client", &self.http_client.is_some())
            .field("tor_client", &self.tor_client.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub connection_cap: usize,
    pub dial_concurrency: usize,
    pub peer_exchange_peers_per_query: u64,
    pub request_timeout: Duration,
    pub idle_timeout_secs: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            connection_cap: 12,
            dial_concurrency: 16,
            peer_exchange_peers_per_query: 60,
            request_timeout: Duration::from_secs(10),
            idle_timeout_secs: 120,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WakuConfig {
    pub discovery: DiscoveryConfig,
    pub node: NodeConfig,
    pub network: WakuNetworkConfig,
    pub cluster_id: u32,
    pub shard_id: u32,
    pub peer_exchange_cooldown: Duration,
}

impl Default for WakuConfig {
    fn default() -> Self {
        Self {
            discovery: DiscoveryConfig::default(),
            node: NodeConfig::default(),
            network: WakuNetworkConfig::default(),
            cluster_id: 1,
            shard_id: 1,
            peer_exchange_cooldown: Duration::from_secs(60),
        }
    }
}
