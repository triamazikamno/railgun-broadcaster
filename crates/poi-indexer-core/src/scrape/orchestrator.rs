use crate::config::Config;
use crate::scrape::page_size::PageSizeAdapter;
use crate::scrape::retry::RetryPolicy;
use crate::scrape::worker::{ScrapeError, ScrapeWorker};
use crate::status::SharedStatus;
use crate::store::Store;
use alloy_primitives::FixedBytes;
use poi::poi::PoiRpcClient;
use reqwest::Url;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::warn;

const DEFAULT_MIN_PAGE_SIZE: usize = 25;
const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);
const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
pub struct Orchestrator {
    upstream_url: Url,
    upstream_url_string: String,
    list_keys: Vec<FixedBytes<32>>,
    chain_ids: Vec<u64>,
    page_size_max: usize,
    retry_budget: usize,
    polite_interval: Duration,
    blocked_shield_resync_interval: Duration,
    per_pair_concurrency_limit: usize,
    store: Store,
    status: Option<SharedStatus>,
}

impl Orchestrator {
    pub fn from_config(config: &Config, store: Store) -> Result<Self, OrchestratorError> {
        let upstream_url = config.upstream_url.parse::<Url>().map_err(|source| {
            OrchestratorError::InvalidUpstreamUrl {
                url: config.upstream_url.clone(),
                reason: source.to_string(),
            }
        })?;

        Ok(Self {
            upstream_url,
            upstream_url_string: config.upstream_url.clone(),
            list_keys: config.list_keys.clone(),
            chain_ids: config.chain_ids.clone(),
            page_size_max: config.page_size_max,
            retry_budget: config.retry_budget,
            polite_interval: *config.polite_interval,
            blocked_shield_resync_interval: *config.blocked_shield_resync_interval,
            per_pair_concurrency_limit: config.per_pair_concurrency_limit,
            store,
            status: None,
        })
    }

    #[must_use]
    pub fn with_status(mut self, status: SharedStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub async fn run_until_caught_up(&self) -> Result<(), OrchestratorError> {
        let pairs = self.pairs();
        for chunk in pairs.chunks(self.per_pair_concurrency_limit) {
            let mut workers = JoinSet::new();
            for &(list_key, chain_id) in chunk {
                let mut worker = self.worker_for_pair(list_key, chain_id);
                workers.spawn(async move { worker.run_until_caught_up().await });
            }

            while let Some(result) = workers.join_next().await {
                result??;
            }
        }
        Ok(())
    }

    pub async fn run_until_caught_up_or_shutdown(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), OrchestratorError> {
        let pairs = self.pairs();
        for chunk in pairs.chunks(self.per_pair_concurrency_limit) {
            if shutdown_requested(&shutdown) {
                return Ok(());
            }

            let mut workers = JoinSet::new();
            for &(list_key, chain_id) in chunk {
                let mut worker = self.worker_for_pair(list_key, chain_id);
                let mut worker_shutdown = shutdown.clone();
                workers.spawn(async move {
                    worker
                        .run_until_caught_up_or_shutdown(&mut worker_shutdown)
                        .await
                });
            }

            while let Some(result) = workers.join_next().await {
                let _outcome = result??;
            }
        }
        Ok(())
    }

    pub async fn run_blocked_shield_resync_loop(&self) -> Result<(), OrchestratorError> {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        self.run_blocked_shield_resync_loop_or_shutdown(shutdown_rx)
            .await
    }

    pub async fn run_blocked_shield_resync_loop_or_shutdown(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), OrchestratorError> {
        let mut interval = tokio::time::interval(self.blocked_shield_resync_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                result = shutdown.changed() => {
                    if result.is_err() || shutdown_requested(&shutdown) {
                        return Ok(());
                    }
                }
            }

            if shutdown_requested(&shutdown) {
                return Ok(());
            }

            if let Err(error) = self
                .resync_blocked_shields_once_or_shutdown(shutdown.clone())
                .await
            {
                warn!(error = %error, "blocked-shield resync cycle failed; will retry on next interval");
            }
        }
    }

    pub async fn resync_blocked_shields_once(&self) -> Result<(), OrchestratorError> {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        self.resync_blocked_shields_once_or_shutdown(shutdown_rx)
            .await
    }

    pub async fn resync_blocked_shields_once_or_shutdown(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), OrchestratorError> {
        let pairs = self.pairs();
        for chunk in pairs.chunks(self.per_pair_concurrency_limit) {
            if shutdown_requested(&shutdown) {
                return Ok(());
            }

            let mut workers = JoinSet::new();
            for &(list_key, chain_id) in chunk {
                let mut worker = self.worker_for_pair(list_key, chain_id);
                let mut worker_shutdown = shutdown.clone();
                workers.spawn(async move {
                    worker
                        .sync_blocked_shields_until_caught_up_or_shutdown(&mut worker_shutdown)
                        .await
                });
            }

            while let Some(result) = workers.join_next().await {
                let _outcome = result??;
            }
        }
        Ok(())
    }

    pub async fn record_manifest_publication(
        &self,
        manifest_cid: impl Into<String>,
        ipfs_reachable: bool,
    ) {
        if let Some(status) = &self.status {
            let mut status = status.write().await;
            status.record_manifest_publication(manifest_cid);
            status.set_ipfs_reachable(ipfs_reachable);
        }
    }

    fn worker_for_pair(&self, list_key: FixedBytes<32>, chain_id: u64) -> ScrapeWorker {
        let worker = ScrapeWorker::new(
            list_key,
            chain_id,
            self.upstream_url_string.clone(),
            PoiRpcClient::new(self.upstream_url.clone()),
            PageSizeAdapter::new(
                self.page_size_max,
                self.page_size_max,
                DEFAULT_MIN_PAGE_SIZE,
            ),
            RetryPolicy::new(
                self.retry_budget,
                DEFAULT_RETRY_BASE_DELAY,
                DEFAULT_RETRY_MAX_DELAY,
            ),
            self.store.clone(),
            self.polite_interval,
        );
        if let Some(status) = &self.status {
            worker.with_status(status.clone())
        } else {
            worker
        }
    }

    fn pairs(&self) -> Vec<(FixedBytes<32>, u64)> {
        self.list_keys
            .iter()
            .flat_map(|list_key| self.chain_ids.iter().map(|chain_id| (*list_key, *chain_id)))
            .collect()
    }
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("invalid upstream URL {url}: {reason}")]
    InvalidUpstreamUrl { url: String, reason: String },
    #[error("scrape worker failed")]
    Scrape(#[from] ScrapeError),
    #[error("scrape worker task failed")]
    Join(#[from] tokio::task::JoinError),
}
