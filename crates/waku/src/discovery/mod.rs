pub(crate) mod enr;
mod enr_tree;
mod error;
mod txt;

pub use error::{DiscoveryError, DnsResolveError, EnrDecodeError, EnrTreeError};

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::Duration;

pub const SANDBOX_ENR_TREE: &str =
    "enrtree://AIRVQ5DDA4FFWLRBCHJWUWOO6X6S4ZTZ5B667LQ6AJU6PEYDLRD5O@sandbox.waku.nodes.status.im";
pub const TEST_ENR_TREE: &str =
    "enrtree://AOGYWMBYOUIMOENHXCHILPKY3ZRFEULMFI4DOM442QSZ73TT2A7VI@test.waku.nodes.status.im";
pub const RAILGUN_TREE: &str =
    "enrtree://APMYHUVNQWHJNPI5L2KQ765EMCKUAMRWPUH3U2QIKPK6XEV3OW442@discovery.rootedinprivacy.com";
pub const DEFAULT_CLEARNET_DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
pub const DEFAULT_TOR_DOH_ENDPOINT: &str =
    "https://dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion/dns-query";

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

#[derive(Clone)]
pub struct DiscoveryConfig {
    pub enr_trees: Vec<String>,
    pub max_txt_queries_per_tree: usize,
    pub max_enrs_per_tree: usize,
    pub doh_endpoint: String,
    pub http_client: Option<reqwest::Client>,
    pub allow_system_dns: bool,
    pub dns_discovery_interval: Duration,
    pub peer_exchange_interval: Duration,
    pub peer_exchange_rounds: usize,
    pub peer_exchange_bootstrap_interval: Duration,
    pub peer_exchange_bootstrap_peers: usize,
}

impl std::fmt::Debug for DiscoveryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryConfig")
            .field("enr_trees", &self.enr_trees)
            .field("max_txt_queries_per_tree", &self.max_txt_queries_per_tree)
            .field("max_enrs_per_tree", &self.max_enrs_per_tree)
            .field("doh_endpoint", &self.doh_endpoint)
            .field("http_client", &self.http_client.is_some())
            .field("allow_system_dns", &self.allow_system_dns)
            .field("dns_discovery_interval", &self.dns_discovery_interval)
            .field("peer_exchange_interval", &self.peer_exchange_interval)
            .field("peer_exchange_rounds", &self.peer_exchange_rounds)
            .field(
                "peer_exchange_bootstrap_interval",
                &self.peer_exchange_bootstrap_interval,
            )
            .field(
                "peer_exchange_bootstrap_peers",
                &self.peer_exchange_bootstrap_peers,
            )
            .finish()
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enr_trees: vec![RAILGUN_TREE.to_string()],
            max_txt_queries_per_tree: 400,
            max_enrs_per_tree: 200,
            doh_endpoint: DEFAULT_CLEARNET_DOH_ENDPOINT.to_string(),
            http_client: None,
            allow_system_dns: true,
            dns_discovery_interval: Duration::from_secs(1800),
            peer_exchange_interval: Duration::from_secs(60),
            peer_exchange_rounds: 3,
            peer_exchange_bootstrap_interval: Duration::from_secs(10),
            peer_exchange_bootstrap_peers: 3,
        }
    }
}

impl DiscoveryConfig {
    /// Discover peers from DNS ENR trees.
    pub(crate) async fn discover_all(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        let resolver = txt::TxtResolver::new(
            self.doh_endpoint.clone(),
            self.http_client.clone(),
            self.allow_system_dns,
        )?;
        let mut peers = HashMap::<PeerId, Vec<Multiaddr>>::new();

        for tree in &self.enr_trees {
            for peer in enr_tree::discover_from_tree(
                &resolver,
                tree,
                self.max_txt_queries_per_tree,
                self.max_enrs_per_tree,
            )
            .await?
            {
                peers.entry(peer.peer_id).or_default().extend(peer.addrs);
            }
        }

        Ok(peers
            .into_iter()
            .map(|(peer_id, mut addrs)| {
                addrs.sort();
                addrs.dedup();
                DiscoveredPeer { peer_id, addrs }
            })
            .collect())
    }
}
