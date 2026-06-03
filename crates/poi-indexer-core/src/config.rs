use alloy_primitives::FixedBytes;
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

pub const SUPPORTED_CHAIN_IDS: &[u64] = &[1, 56, 137, 42161];

const POSTGRES_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const POSTGRES_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
const POSTGRES_BACKGROUND_CONNECTION_HEADROOM: usize = 4;
const UPSTREAM_MAX_PAGE_SIZE: usize = 500;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub upstream_url: String,
    pub list_keys: Vec<FixedBytes<32>>,
    pub chain_ids: Vec<u64>,
    pub postgres_connection_string: String,
    pub ipfs_endpoint: String,
    pub publisher_signing_key_path: PathBuf,
    pub ipns_bootstrap_peers: Vec<String>,
    pub ipns_record_lifetime: humantime_serde::Serde<Duration>,
    pub ipns_record_ttl: humantime_serde::Serde<Duration>,
    pub ipns_republish_interval: humantime_serde::Serde<Duration>,
    pub ipns_publish_timeout: humantime_serde::Serde<Duration>,
    pub page_size_max: usize,
    pub retry_budget: usize,
    pub polite_interval: humantime_serde::Serde<Duration>,
    pub blocked_shield_resync_interval: humantime_serde::Serde<Duration>,
    pub delta_publish_interval: humantime_serde::Serde<Duration>,
    pub base_rebuild_interval: humantime_serde::Serde<Duration>,
    pub retention_interval: humantime_serde::Serde<Duration>,
    pub per_pair_concurrency_limit: usize,
}

impl Config {
    /// Validates config values that can be checked before opening external resources.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.list_keys.is_empty() {
            return Err(ConfigValidationError::EmptyListKeys);
        }
        if self.chain_ids.is_empty() {
            return Err(ConfigValidationError::EmptyChainIds);
        }
        for chain_id in &self.chain_ids {
            if !SUPPORTED_CHAIN_IDS.contains(chain_id) {
                return Err(ConfigValidationError::UnknownChainId(*chain_id));
            }
        }

        if self.blocked_shield_resync_interval.is_zero() {
            return Err(ConfigValidationError::ZeroBlockedShieldResyncInterval);
        }
        if self.ipns_bootstrap_peers.is_empty() {
            return Err(ConfigValidationError::EmptyIpnsBootstrapPeers);
        }
        if self.ipns_record_lifetime.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRecordLifetime);
        }
        if self.ipns_record_ttl.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRecordTtl);
        }
        if self.ipns_republish_interval.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsRepublishInterval);
        }
        if self.ipns_publish_timeout.is_zero() {
            return Err(ConfigValidationError::ZeroIpnsPublishTimeout);
        }
        if self.retry_budget == 0 {
            return Err(ConfigValidationError::ZeroRetryBudget);
        }
        if self.page_size_max == 0 {
            return Err(ConfigValidationError::ZeroPageSizeMax);
        }
        if self.page_size_max > UPSTREAM_MAX_PAGE_SIZE {
            return Err(ConfigValidationError::PageSizeMaxTooLarge {
                configured: self.page_size_max,
                maximum: UPSTREAM_MAX_PAGE_SIZE,
            });
        }
        if self.polite_interval.is_zero() {
            return Err(ConfigValidationError::ZeroPoliteInterval);
        }
        if self.delta_publish_interval.is_zero() {
            return Err(ConfigValidationError::ZeroDeltaPublishInterval);
        }
        if self.base_rebuild_interval.is_zero() {
            return Err(ConfigValidationError::ZeroBaseRebuildInterval);
        }
        if self.retention_interval.is_zero() {
            return Err(ConfigValidationError::ZeroRetentionInterval);
        }
        if self.per_pair_concurrency_limit == 0 {
            return Err(ConfigValidationError::ZeroPerPairConcurrencyLimit);
        }
        let _pool_size = self.postgres_max_connections()?;

        Ok(())
    }

    /// Computes the pool size needed for the configured pair concurrency plus background loops.
    pub fn postgres_max_connections(&self) -> Result<u32, ConfigValidationError> {
        let workers = self
            .per_pair_concurrency_limit
            .checked_mul(2)
            .and_then(|workers| workers.checked_add(POSTGRES_BACKGROUND_CONNECTION_HEADROOM))
            .ok_or(ConfigValidationError::PostgresPoolSizeOverflow)?;
        u32::try_from(workers).map_err(|_| ConfigValidationError::PostgresPoolSizeOverflow)
    }

    /// Validates config values and establishes the first Postgres connection.
    pub async fn connect_postgres(&self) -> Result<PgPool, ConfigValidationError> {
        self.validate()?;
        let max_connections = self.postgres_max_connections()?;

        let pool = tokio::time::timeout(
            POSTGRES_CONNECT_TIMEOUT,
            PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(POSTGRES_ACQUIRE_TIMEOUT)
                .connect(&self.postgres_connection_string),
        )
        .await
        .map_err(|_| ConfigValidationError::PostgresConnectTimeout(POSTGRES_CONNECT_TIMEOUT))??;

        Ok(pool)
    }
}

#[derive(Debug, Error)]
pub enum ConfigValidationError {
    #[error("list_keys must contain at least one POI list key")]
    EmptyListKeys,
    #[error("chain_ids must contain at least one supported chain id")]
    EmptyChainIds,
    #[error("unsupported chain id {0}; supported chain ids are 1, 56, 137, 42161")]
    UnknownChainId(u64),
    #[error("postgres connection attempt timed out after {0:?}")]
    PostgresConnectTimeout(Duration),
    #[error("computed postgres pool size overflowed")]
    PostgresPoolSizeOverflow,
    #[error("blocked_shield_resync_interval must be greater than zero")]
    ZeroBlockedShieldResyncInterval,
    #[error("ipns_bootstrap_peers must contain at least one public DHT bootstrap peer")]
    EmptyIpnsBootstrapPeers,
    #[error("ipns_record_lifetime must be greater than zero")]
    ZeroIpnsRecordLifetime,
    #[error("ipns_record_ttl must be greater than zero")]
    ZeroIpnsRecordTtl,
    #[error("ipns_republish_interval must be greater than zero")]
    ZeroIpnsRepublishInterval,
    #[error("ipns_publish_timeout must be greater than zero")]
    ZeroIpnsPublishTimeout,
    #[error("retry_budget must be greater than zero")]
    ZeroRetryBudget,
    #[error("page_size_max must be greater than zero")]
    ZeroPageSizeMax,
    #[error("page_size_max {configured} exceeds upstream maximum {maximum}")]
    PageSizeMaxTooLarge { configured: usize, maximum: usize },
    #[error("polite_interval must be greater than zero")]
    ZeroPoliteInterval,
    #[error("delta_publish_interval must be greater than zero")]
    ZeroDeltaPublishInterval,
    #[error("base_rebuild_interval must be greater than zero")]
    ZeroBaseRebuildInterval,
    #[error("retention_interval must be greater than zero")]
    ZeroRetentionInterval,
    #[error("per_pair_concurrency_limit must be greater than zero")]
    ZeroPerPairConcurrencyLimit,
    #[error("postgres connection failed")]
    Postgres(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            upstream_url: "https://ppoi.example.invalid".to_string(),
            list_keys: vec![FixedBytes::from([1_u8; 32])],
            chain_ids: vec![1],
            postgres_connection_string: "not a postgres connection string".to_string(),
            ipfs_endpoint: "https://s3.filebase.com".to_string(),
            publisher_signing_key_path: PathBuf::from("publisher.key"),
            ipns_bootstrap_peers: vec!["/dnsaddr/bootstrap.libp2p.io".to_string()],
            ipns_record_lifetime: Duration::from_secs(1).into(),
            ipns_record_ttl: Duration::from_secs(1).into(),
            ipns_republish_interval: Duration::from_secs(1).into(),
            ipns_publish_timeout: Duration::from_secs(1).into(),
            page_size_max: 500,
            retry_budget: 1,
            polite_interval: Duration::from_secs(1).into(),
            blocked_shield_resync_interval: Duration::from_secs(1).into(),
            delta_publish_interval: Duration::from_secs(1).into(),
            base_rebuild_interval: Duration::from_secs(1).into(),
            retention_interval: Duration::from_secs(1).into(),
            per_pair_concurrency_limit: 1,
        }
    }

    #[tokio::test]
    async fn zero_retry_budget_is_rejected_before_postgres_connect() {
        let mut config = valid_config();
        config.retry_budget = 0;

        let error = config
            .connect_postgres()
            .await
            .expect_err("zero retry budget should fail validation");

        assert!(matches!(error, ConfigValidationError::ZeroRetryBudget));
    }

    #[test]
    fn zero_concurrency_is_rejected_at_startup_validation() {
        let mut config = valid_config();
        config.per_pair_concurrency_limit = 0;

        let error = config.validate().expect_err("zero concurrency should fail");

        match error {
            ConfigValidationError::ZeroPerPairConcurrencyLimit => {}
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[test]
    fn pool_size_scales_with_pair_concurrency_and_background_headroom() {
        let mut config = valid_config();
        config.per_pair_concurrency_limit = 4;

        assert_eq!(config.postgres_max_connections().expect("pool size"), 12);
    }

    #[test]
    fn page_size_above_upstream_limit_is_rejected() {
        let mut config = valid_config();
        config.page_size_max = 501;

        let error = config.validate().expect_err("oversized page should fail");

        match error {
            ConfigValidationError::PageSizeMaxTooLarge { .. } => {}
            other => panic!("unexpected validation error: {other:?}"),
        }
    }
}
