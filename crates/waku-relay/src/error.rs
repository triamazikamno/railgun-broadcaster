use thiserror::Error;
use waku::error::WakuError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("spawn waku node failed: {0}")]
    SpawnNode(#[source] WakuError),

    #[error("subscribe on waku fleet failed: {0}")]
    FleetSubscribe(#[source] WakuError),

    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("nwaku returned error status: {body}")]
    NwakuStatus { body: String },
    #[error("failed to parse PeerId")]
    ParsePeerId,
    #[error("failed to parse multiaddr")]
    ParseMultiaddr,
}
