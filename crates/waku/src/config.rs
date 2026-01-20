use crate::discovery::DiscoveryConfig;
use std::time::Duration;

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
            connection_cap: 20,
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
    pub cluster_id: u32,
    pub peer_exchange_cooldown: Duration,
}

impl Default for WakuConfig {
    fn default() -> Self {
        Self {
            discovery: DiscoveryConfig::default(),
            node: NodeConfig::default(),
            cluster_id: 1,
            peer_exchange_cooldown: Duration::from_secs(60),
        }
    }
}
