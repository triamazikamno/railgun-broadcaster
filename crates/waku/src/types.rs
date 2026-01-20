use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Identifier for a single in-flight operation.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OpId(u64);

impl OpId {
    #[must_use]
    pub fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

pub fn parse_peer_id(peer_id: &str) -> Result<libp2p::PeerId, libp2p::identity::ParseError> {
    libp2p::PeerId::from_str(peer_id)
}

pub fn parse_multiaddr(addr: &str) -> Result<libp2p::Multiaddr, libp2p::multiaddr::Error> {
    libp2p::Multiaddr::from_str(addr)
}
