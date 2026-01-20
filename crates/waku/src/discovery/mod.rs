pub(crate) mod enr;
mod enr_tree;
pub mod error;
mod txt;

pub use error::{DiscoveryError, DnsResolveError, EnrDecodeError, EnrTreeError};

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::Duration;

pub const SANDBOX_ENR_TREE: &str =
    "enrtree://AIRVQ5DDA4FFWLRBCHJWUWOO6X6S4ZTZ5B667LQ6AJU6PEYDLRD5O@sandbox.waku.nodes.status.im";
pub const TEST_ENR_TREE: &str =
    "enrtree://AOGYWMBYOUIMOENHXCHILPKY3ZRFEULMFI4DOM442QSZ73TT2A7VI@test.waku.nodes.status.im";

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub enr_trees: Vec<String>,
    pub max_txt_queries_per_tree: usize,
    pub max_enrs_per_tree: usize,
    pub doh_endpoint: String,
    pub dns_discovery_interval: Duration,
    pub peer_exchange_interval: Duration,
    pub peer_exchange_rounds: usize,
    pub peer_exchange_bootstrap_interval: Duration,
    pub peer_exchange_bootstrap_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enr_trees: vec![SANDBOX_ENR_TREE.to_string(), TEST_ENR_TREE.to_string()],
            max_txt_queries_per_tree: 400,
            max_enrs_per_tree: 200,
            doh_endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
            dns_discovery_interval: Duration::from_secs(1800),
            peer_exchange_interval: Duration::from_secs(60),
            peer_exchange_rounds: 3,
            peer_exchange_bootstrap_interval: Duration::from_secs(10),
            peer_exchange_bootstrap_peers: 3,
        }
    }
}

/// Discover peers from DNS ENR trees.
pub(crate) async fn discover_all(
    config: &DiscoveryConfig,
) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
    let resolver = txt::TxtResolver::new(config.doh_endpoint.clone())?;
    let mut peers = HashMap::<PeerId, Vec<Multiaddr>>::new();

    for tree in &config.enr_trees {
        for peer in enr_tree::discover_from_tree(
            &resolver,
            tree,
            config.max_txt_queries_per_tree,
            config.max_enrs_per_tree,
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
