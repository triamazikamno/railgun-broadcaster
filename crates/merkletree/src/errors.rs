use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("graphql request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("graphql response missing data field")]
    MissingData,
    #[error("unexpected response format: {0}")]
    UnexpectedFormat(String),
}
