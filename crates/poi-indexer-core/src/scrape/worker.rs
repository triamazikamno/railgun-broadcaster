use crate::scrape::page_size::PageSizeAdapter;
use crate::scrape::retry::RetryPolicy;
use crate::status::SharedStatus;
use crate::store::{Store, StoreError};
use crate::verify::{VerifyError, verify_blocked_shield, verify_poi_event};
use alloy_primitives::FixedBytes;
use poi::error::PoiRpcError;
use poi::poi::{PoiRpcClient, PoiSyncedListEvent, SignedBlockedShield};
use reqwest::StatusCode;
use std::error::Error;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tracing::info;

const EVM_CHAIN_TYPE: u8 = 0;
const POSEIDON_TXID_VERSION: &str = "V2_PoseidonMerkle";

pub struct ScrapeWorker {
    list_key: FixedBytes<32>,
    chain_id: u64,
    upstream_url: String,
    rpc_client: PoiRpcClient,
    page_size: PageSizeAdapter,
    retry_policy: RetryPolicy,
    store: Store,
    polite_interval: Duration,
    status: Option<SharedStatus>,
}

impl ScrapeWorker {
    #[must_use]
    pub const fn new(
        list_key: FixedBytes<32>,
        chain_id: u64,
        upstream_url: String,
        rpc_client: PoiRpcClient,
        page_size: PageSizeAdapter,
        retry_policy: RetryPolicy,
        store: Store,
        polite_interval: Duration,
    ) -> Self {
        Self {
            list_key,
            chain_id,
            upstream_url,
            rpc_client,
            page_size,
            retry_policy,
            store,
            polite_interval,
            status: None,
        }
    }

    #[must_use]
    pub fn with_status(mut self, status: SharedStatus) -> Self {
        self.status = Some(status);
        self
    }

    #[must_use]
    pub const fn list_key(&self) -> FixedBytes<32> {
        self.list_key
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub const fn page_size(&self) -> &PageSizeAdapter {
        &self.page_size
    }

    pub async fn sync_next_page(&self) -> Result<SyncPageOutcome, ScrapeError> {
        let start_index = self.next_start_index().await?;
        let end_index = end_index(start_index, self.page_size.current_size())?;
        let events = self
            .rpc_client
            .poi_events(
                POSEIDON_TXID_VERSION,
                EVM_CHAIN_TYPE,
                self.chain_id,
                &self.list_key,
                start_index,
                end_index,
            )
            .await?;

        if events.is_empty() {
            return Ok(SyncPageOutcome::CaughtUp);
        }

        self.verify_page(start_index, &events)?;

        let Some(last_event) = events.last() else {
            return Ok(SyncPageOutcome::CaughtUp);
        };
        let last_event_index = last_event.signed_poi_event.index;
        let last_tip_merkleroot = last_event.validated_merkleroot.as_str();
        let signed_events = events
            .iter()
            .map(|event| event.signed_poi_event.clone())
            .collect::<Vec<_>>();

        let mut tx = self.store.begin().await?;
        Store::insert_events(&mut tx, &self.list_key, self.chain_id, &signed_events).await?;
        Store::advance_chain_tip(
            &mut tx,
            &self.list_key,
            self.chain_id,
            &self.upstream_url,
            last_event_index,
            Some(last_tip_merkleroot),
        )
        .await?;
        tx.commit().await.map_err(StoreError::Sqlx)?;

        Ok(SyncPageOutcome::Ingested {
            count: signed_events.len(),
            last_event_index,
        })
    }

    pub async fn run_until_caught_up(&mut self) -> Result<(), ScrapeError> {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let _outcome = self
            .run_until_caught_up_or_shutdown(&mut shutdown_rx)
            .await?;
        Ok(())
    }

    pub async fn run_until_caught_up_or_shutdown(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<RunUntilOutcome, ScrapeError> {
        if self.retry_policy.budget() == 0 {
            return Err(ScrapeError::NoRetryAttemptsConfigured);
        }

        loop {
            if shutdown_requested(shutdown) {
                return Ok(RunUntilOutcome::Shutdown);
            }

            match self.sync_next_page_with_retry(shutdown).await? {
                None => return Ok(RunUntilOutcome::Shutdown),
                Some(SyncPageOutcome::CaughtUp) => return Ok(RunUntilOutcome::CaughtUp),
                Some(SyncPageOutcome::Ingested {
                    count,
                    last_event_index,
                }) => {
                    let previous_size = self.page_size.current_size();
                    self.page_size.on_success();
                    let current_size = self.page_size.current_size();
                    if current_size != previous_size {
                        info!(
                            list_key = %self.list_key,
                            chain_id = self.chain_id,
                            previous_page_size = previous_size,
                            current_page_size = current_size,
                            "POI page size increased after successful pages"
                        );
                    }
                    info!(
                        list_key = %self.list_key,
                        chain_id = self.chain_id,
                        count,
                        last_event_index,
                        page_size = previous_size,
                        next_page_size = current_size,
                        "ingested POI event page"
                    );
                    self.record_page_success(last_event_index).await;
                    if sleep_or_shutdown(self.polite_interval, shutdown).await {
                        return Ok(RunUntilOutcome::Shutdown);
                    }
                }
            }
        }
    }

    pub async fn sync_blocked_shields_until_caught_up(&mut self) -> Result<(), ScrapeError> {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let _outcome = self
            .sync_blocked_shields_until_caught_up_or_shutdown(&mut shutdown_rx)
            .await?;
        Ok(())
    }

    pub async fn sync_blocked_shields_until_caught_up_or_shutdown(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<RunUntilOutcome, ScrapeError> {
        if self.retry_policy.budget() == 0 {
            return Err(ScrapeError::NoRetryAttemptsConfigured);
        }

        let Some(first_records) = self.collect_blocked_shields_or_shutdown(shutdown).await? else {
            return Ok(RunUntilOutcome::Shutdown);
        };
        let Some(second_records) = self.collect_blocked_shields_or_shutdown(shutdown).await? else {
            return Ok(RunUntilOutcome::Shutdown);
        };

        if !blocked_shield_sets_match(&first_records, &second_records) {
            return Err(ScrapeError::BlockedShieldSetChanged {
                first_count: first_records.len(),
                second_count: second_records.len(),
            });
        }

        let mut tx = self.store.begin().await?;
        Store::replace_blocked_shields(&mut tx, &self.list_key, self.chain_id, &second_records)
            .await?;
        tx.commit().await.map_err(StoreError::Sqlx)?;
        Ok(RunUntilOutcome::CaughtUp)
    }

    async fn collect_blocked_shields_or_shutdown(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Option<Vec<SignedBlockedShield>>, ScrapeError> {
        let mut start_index = 0;
        let mut all_records = Vec::new();
        loop {
            if shutdown_requested(shutdown) {
                return Ok(None);
            }

            match self
                .sync_blocked_shields_page_with_retry(start_index, shutdown)
                .await?
            {
                None => return Ok(None),
                Some(BlockedShieldPageOutcome::CaughtUp) => return Ok(Some(all_records)),
                Some(BlockedShieldPageOutcome::Ingested { records }) => {
                    let count = records.len();
                    start_index = start_index
                        .checked_add(count as u64)
                        .ok_or(ScrapeError::BlockedShieldIndexOverflow { start_index })?;
                    all_records.extend(records);
                    let previous_size = self.page_size.current_size();
                    self.page_size.on_success();
                    let current_size = self.page_size.current_size();
                    if current_size != previous_size {
                        info!(
                            list_key = %self.list_key,
                            chain_id = self.chain_id,
                            previous_page_size = previous_size,
                            current_page_size = current_size,
                            "blocked-shield page size increased after successful pages"
                        );
                    }
                    info!(
                        list_key = %self.list_key,
                        chain_id = self.chain_id,
                        count,
                        page_size = previous_size,
                        next_page_size = current_size,
                        "ingested blocked-shield page"
                    );
                    if sleep_or_shutdown(self.polite_interval, shutdown).await {
                        return Ok(None);
                    }
                }
            }
        }
    }

    async fn sync_next_page_with_retry(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Option<SyncPageOutcome>, ScrapeError> {
        loop {
            if shutdown_requested(shutdown) {
                return Ok(None);
            }

            let mut attempts = 0;
            loop {
                attempts += 1;
                match self.sync_next_page().await {
                    Ok(outcome) => return Ok(Some(outcome)),
                    Err(error) if error.is_retryable() && attempts < self.retry_policy.budget() => {
                        let backoff = self.retry_policy.backoff_delay(attempts - 1);
                        self.record_page_failure(
                            attempts,
                            Some(backoff),
                            format_error_chain(&error),
                        )
                        .await;
                        if sleep_or_shutdown(backoff, shutdown).await {
                            return Ok(None);
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        let previous_size = self.page_size.current_size();
                        self.page_size.on_failure();
                        let current_size = self.page_size.current_size();
                        self.record_page_failure(attempts, None, format_error_chain(&error))
                            .await;
                        if current_size != previous_size {
                            info!(
                                list_key = %self.list_key,
                                chain_id = self.chain_id,
                                previous_page_size = previous_size,
                                current_page_size = current_size,
                                attempts,
                                "POI page size shrank after retry budget exhaustion"
                            );
                        }
                        if current_size == previous_size {
                            return Err(ScrapeError::RetryBudgetExhausted {
                                attempts,
                                page_size: previous_size,
                                source: Box::new(error),
                            });
                        }
                        break;
                    }
                    Err(error) => {
                        self.record_page_failure(attempts, None, format_error_chain(&error))
                            .await;
                        return Err(error);
                    }
                }
            }
        }
    }

    async fn sync_blocked_shields_page_with_retry(
        &mut self,
        start_index: u64,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Option<BlockedShieldPageOutcome>, ScrapeError> {
        loop {
            if shutdown_requested(shutdown) {
                return Ok(None);
            }

            let mut attempts = 0;
            loop {
                attempts += 1;
                match self.sync_blocked_shields_page(start_index).await {
                    Ok(outcome) => return Ok(Some(outcome)),
                    Err(error) if error.is_retryable() && attempts < self.retry_policy.budget() => {
                        let backoff = self.retry_policy.backoff_delay(attempts - 1);
                        self.record_page_failure(
                            attempts,
                            Some(backoff),
                            format_error_chain(&error),
                        )
                        .await;
                        if sleep_or_shutdown(backoff, shutdown).await {
                            return Ok(None);
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        let previous_size = self.page_size.current_size();
                        self.page_size.on_failure();
                        let current_size = self.page_size.current_size();
                        self.record_page_failure(attempts, None, format_error_chain(&error))
                            .await;
                        if current_size != previous_size {
                            info!(
                                list_key = %self.list_key,
                                chain_id = self.chain_id,
                                previous_page_size = previous_size,
                                current_page_size = current_size,
                                attempts,
                                "blocked-shield page size shrank after retry budget exhaustion"
                            );
                        }
                        if current_size == previous_size {
                            return Err(ScrapeError::RetryBudgetExhausted {
                                attempts,
                                page_size: previous_size,
                                source: Box::new(error),
                            });
                        }
                        break;
                    }
                    Err(error) => {
                        self.record_page_failure(attempts, None, format_error_chain(&error))
                            .await;
                        return Err(error);
                    }
                }
            }
        }
    }

    async fn sync_blocked_shields_page(
        &self,
        start_index: u64,
    ) -> Result<BlockedShieldPageOutcome, ScrapeError> {
        let end_index = end_index(start_index, self.page_size.current_size())?;
        let records = self
            .rpc_client
            .blocked_shields(
                POSEIDON_TXID_VERSION,
                EVM_CHAIN_TYPE,
                self.chain_id,
                &self.list_key,
                start_index,
                end_index,
            )
            .await?;

        if records.is_empty() {
            return Ok(BlockedShieldPageOutcome::CaughtUp);
        }

        self.verify_blocked_shields(&records)?;

        Ok(BlockedShieldPageOutcome::Ingested { records })
    }

    async fn next_start_index(&self) -> Result<u64, ScrapeError> {
        let Some(last_event_index) = self
            .store
            .last_event_index(&self.list_key, self.chain_id, &self.upstream_url)
            .await?
        else {
            return Ok(0);
        };

        last_event_index
            .checked_add(1)
            .ok_or(ScrapeError::IndexOverflow { last_event_index })
    }

    fn verify_page(
        &self,
        start_index: u64,
        events: &[PoiSyncedListEvent],
    ) -> Result<(), ScrapeError> {
        let list_key = self.list_key_bytes();
        for (offset, event) in events.iter().enumerate() {
            let expected_index =
                start_index
                    .checked_add(offset as u64)
                    .ok_or(ScrapeError::IndexOverflow {
                        last_event_index: start_index,
                    })?;
            let actual_index = event.signed_poi_event.index;
            if actual_index != expected_index {
                return Err(ScrapeError::UnexpectedEventIndex {
                    expected_index,
                    actual_index,
                });
            }
            verify_poi_event(&event.signed_poi_event, &list_key)?;
        }
        Ok(())
    }

    fn verify_blocked_shields(&self, records: &[SignedBlockedShield]) -> Result<(), ScrapeError> {
        let list_key = self.list_key_bytes();
        for record in records {
            verify_blocked_shield(record, &list_key)?;
        }
        Ok(())
    }

    const fn list_key_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.list_key.as_slice());
        bytes
    }

    async fn record_page_success(&self, last_event_index: u64) {
        if let Some(status) = &self.status {
            status.write().await.record_page_success(
                &self.list_key,
                self.chain_id,
                last_event_index,
                self.page_size.current_size(),
            );
        }
    }

    async fn record_page_failure(
        &self,
        attempts: usize,
        next_backoff: Option<Duration>,
        error: String,
    ) {
        info!(
            list_key = %self.list_key,
            chain_id = self.chain_id,
            page_size = self.page_size.current_size(),
            attempts,
            next_backoff_seconds = next_backoff.map(|duration| duration.as_secs()),
            error = %error,
            "POI page request failed"
        );
        if let Some(status) = &self.status {
            status.write().await.record_page_failure(
                &self.list_key,
                self.chain_id,
                self.page_size.current_size(),
                attempts,
                next_backoff,
                error,
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunUntilOutcome {
    CaughtUp,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPageOutcome {
    CaughtUp,
    Ingested { count: usize, last_event_index: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockedShieldPageOutcome {
    CaughtUp,
    Ingested { records: Vec<SignedBlockedShield> },
}

#[derive(Debug, Error)]
pub enum ScrapeError {
    #[error("POI RPC request failed")]
    PoiRpc(#[from] PoiRpcError),
    #[error("event signature verification failed")]
    Verify(#[from] VerifyError),
    #[error("store operation failed")]
    Store(#[from] StoreError),
    #[error("page returned event index {actual_index}, expected {expected_index}")]
    UnexpectedEventIndex {
        expected_index: u64,
        actual_index: u64,
    },
    #[error("event index overflow after {last_event_index}")]
    IndexOverflow { last_event_index: u64 },
    #[error("blocked-shield pagination index overflow after {start_index}")]
    BlockedShieldIndexOverflow { start_index: u64 },
    #[error(
        "blocked-shield set changed during paginated sync: first_count={first_count} second_count={second_count}"
    )]
    BlockedShieldSetChanged {
        first_count: usize,
        second_count: usize,
    },
    #[error("retry policy budget must be greater than zero")]
    NoRetryAttemptsConfigured,
    #[error("retry budget exhausted after {attempts} attempts at page size {page_size}")]
    RetryBudgetExhausted {
        attempts: usize,
        page_size: usize,
        #[source]
        source: Box<Self>,
    },
}

impl ScrapeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::PoiRpc(PoiRpcError::Post(_)) => true,
            Self::PoiRpc(PoiRpcError::HttpStatus { status, .. }) => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            _ => false,
        }
    }
}

fn end_index(start_index: u64, page_size: usize) -> Result<u64, ScrapeError> {
    start_index
        .checked_add(page_size as u64)
        .and_then(|end_index| end_index.checked_sub(1))
        .ok_or(ScrapeError::IndexOverflow {
            last_event_index: start_index,
        })
}

fn format_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut formatted = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        formatted.push_str(": ");
        formatted.push_str(&error.to_string());
        source = error.source();
    }
    formatted
}

fn blocked_shield_sets_match(left: &[SignedBlockedShield], right: &[SignedBlockedShield]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    sort_blocked_shields(&mut left);
    sort_blocked_shields(&mut right);
    left == right
}

fn sort_blocked_shields(records: &mut [SignedBlockedShield]) {
    records.sort_by(|left, right| {
        left.blinded_commitment
            .cmp(&right.blinded_commitment)
            .then_with(|| left.commitment_hash.cmp(&right.commitment_hash))
            .then_with(|| left.signature.cmp(&right.signature))
            .then_with(|| left.block_reason.cmp(&right.block_reason))
    });
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if duration.is_zero() {
        return shutdown_requested(shutdown);
    }

    tokio::select! {
        () = tokio::time::sleep(duration) => shutdown_requested(shutdown),
        result = shutdown.changed() => result.is_err() || shutdown_requested(shutdown),
    }
}
