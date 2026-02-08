use crate::discovery::DiscoveryError;
use libp2p::noise;

/// Top-level error type for the Waku node public API.
#[derive(Debug, thiserror::Error)]
pub enum WakuError {
    #[error("transport initialization failed: {0}")]
    TransportInit(#[from] TransportInitError),
    #[error("discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("operation cancelled")]
    Cancelled,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("no peers available")]
    NoPeersAvailable,
    #[error("channel full")]
    ChannelFull,
    #[error("subscription not found")]
    SubscriptionNotFound,
    #[error("filter subscribe failed: status_code={status_code}, desc={status_desc:?}")]
    FilterSubscribeFailed {
        status_code: u32,
        status_desc: Option<String>,
    },
    #[error("filter request failed")]
    FilterRequestFailed,
}

/// Errors that can occur during transport initialization.
#[derive(Debug, thiserror::Error)]
pub enum TransportInitError {
    #[error("failed to build noise config: {0}")]
    Noise(#[from] noise::Error),
    #[error("failed to wrap transport with DNS: {0}")]
    Dns(#[from] std::io::Error),
}
