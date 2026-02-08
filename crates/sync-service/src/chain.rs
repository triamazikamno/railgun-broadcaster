use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, LogBatch, SharedLogBatch, WalletConfig,
};
use crate::wallet::{WalletHandle, spawn_wallet_worker};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::sol_types::SolEvent;
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{Filter, Log};
use alloy_transport::TransportError;
use async_trait::async_trait;
use broadcaster_core::provider::build_provider;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::DbStore;
use merkletree::persist::{
    PersistError, SNAPSHOT_VERSION, load_forest_snapshot, write_forest_snapshot,
};
use merkletree::quick::{DEFAULT_PAGE_SIZE, QuickSyncConfig, run_quick_sync};
use merkletree::slow::types::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, Shield, ShieldLegacyPreMar23,
    Transact,
};
use merkletree::tree::MerkleForest;
use merkletree::wallet::{WalletScanError, apply_commitment_updates_from_logs};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("provider build error: {0}")]
    ProviderBuild(TransportError),
    #[error("rpc error: {0}")]
    Rpc(#[from] TransportError),
    #[error("archive rpc url required for blocks <= {0}")]
    ArchiveRpcRequired(u64),
    #[error("snapshot error: {0}")]
    Snapshot(#[from] PersistError),
    #[error("wallet scan error: {0}")]
    WalletScan(#[from] WalletScanError),
    #[error("db error: {0}")]
    Db(#[from] local_db::DbError),
    #[error("no healthy rpc available")]
    NoHealthyRpc,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("wallet reset failed")]
    WalletResetFailed(#[from] mpsc::error::SendError<BackfillEvent>),
    #[error("backfill request failed")]
    BackfillRequestFailed(#[from] mpsc::error::SendError<BackfillRequest>),
}

impl ChainError {
    pub(crate) fn is_rpc_throttled(&self) -> bool {
        match self {
            Self::Rpc(TransportError::ErrorResp(resp)) => resp.message.contains("limit exceeded"),
            Self::Rpc(TransportError::Transport(resp)) => resp
                .as_http_error()
                .is_some_and(|err| err.status == 429 || err.body.contains("limit exceeded")),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct ChainHandle {
    pub forest: Arc<RwLock<MerkleForest>>,
    pub head_rx: watch::Receiver<u64>,
    pub safe_head_rx: watch::Receiver<u64>,
    pub forest_last_rx: watch::Receiver<u64>,
    pub live_log_rx: broadcast::Receiver<SharedLogBatch>,
}

struct WalletRegistration {
    handle: WalletHandle,
    cancel: CancellationToken,
    backfill_sender: mpsc::Sender<BackfillEvent>,
    start_block: u64,
}

pub struct ChainService {
    chain: ChainConfig,
    db: Arc<DbStore>,
    forest: Arc<RwLock<MerkleForest>>,
    head_tx: watch::Sender<u64>,
    safe_head_tx: watch::Sender<u64>,
    forest_last_tx: watch::Sender<u64>,
    live_log_tx: broadcast::Sender<SharedLogBatch>,
    backfill_tx: mpsc::Sender<BackfillRequest>,
    wallets: RwLock<HashMap<String, WalletRegistration>>,
    cancel: CancellationToken,
    anchor_last: AtomicU64,
}

impl ChainService {
    pub async fn start(db: Arc<DbStore>, chain: ChainConfig) -> Result<Arc<Self>, ChainError> {
        if chain.archive_until_block > 0
            && chain.archive_rpc_url.is_none()
            && chain.deployment_block <= chain.archive_until_block
            && chain.quick_sync_endpoint.is_none()
        {
            return Err(ChainError::ArchiveRpcRequired(chain.archive_until_block));
        }
        let archive_provider = match chain.archive_rpc_url.as_ref() {
            Some(url) => Some(
                build_provider(url)
                    .await
                    .map_err(ChainError::ProviderBuild)?,
            ),
            None => None,
        };

        let (forest, last_processed, snapshot_path, last_anchor) =
            db.load_or_initialize_forest(&chain).await?;

        let (head_tx, _head_rx) = watch::channel(0);
        let (safe_head_tx, safe_head_rx) = watch::channel(0);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let rpcs = chain.rpcs.clone();
        let service = Arc::new(Self {
            chain,
            db,
            forest,
            head_tx,
            safe_head_tx,
            forest_last_tx,
            live_log_tx,
            backfill_tx,
            wallets: RwLock::new(HashMap::new()),
            cancel: cancel.clone(),
            anchor_last: AtomicU64::new(last_anchor),
        });
        let rpc = rpcs
            .random_provider()
            .ok_or_else(|| ChainError::NoHealthyRpc)?;
        if let Ok(head) = rpc.provider.get_block_number().await {
            let safe_head = head
                .saturating_sub(service.chain.finality_depth)
                .max(service.chain.deployment_block);
            if let Err(err) = service.head_tx.send(head) {
                debug!(?err, head, "failed to send head update");
            }
            if let Err(err) = service.safe_head_tx.send(safe_head) {
                debug!(?err, safe_head, "failed to send safe head update");
            }
        }

        spawn_head_poller(service.clone(), rpcs.clone());
        spawn_live_log_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            forest_last_rx,
            safe_head_rx.clone(),
            snapshot_path,
            cancel.clone(),
        );
        spawn_backfill_loop(
            service.clone(),
            backfill_rx,
            rpcs,
            archive_provider,
            safe_head_rx,
            cancel,
        );

        Ok(service)
    }

    #[must_use]
    pub fn handle(&self) -> ChainHandle {
        ChainHandle {
            forest: self.forest.clone(),
            head_rx: self.head_tx.subscribe(),
            safe_head_rx: self.safe_head_tx.subscribe(),
            forest_last_rx: self.forest_last_tx.subscribe(),
            live_log_rx: self.live_log_tx.subscribe(),
        }
    }

    pub async fn wallet_handle(&self, cache_key: &str) -> Option<WalletHandle> {
        self.wallets
            .read()
            .await
            .get(cache_key)
            .map(|registration| registration.handle.clone())
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), ChainError> {
        let (backfill_sender, start_block) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key).ok_or(ChainError::WalletNotFound)?;
            (
                registration.backfill_sender.clone(),
                registration.start_block,
            )
        };

        let reset_from = from_block.unwrap_or(start_block);
        let safe_head = *self.safe_head_tx.borrow();
        backfill_sender
            .send(BackfillEvent::Reset {
                from_block: reset_from,
            })
            .await?;

        self.backfill_tx
            .send(BackfillRequest::Add {
                cache_key: cache_key.to_string(),
                from_block: reset_from,
                to_block: safe_head,
                sender: backfill_sender,
            })
            .await?;

        info!(cache_key = %cache_key, from_block = reset_from, "wallet reset requested");
        Ok(())
    }

    pub async fn register_wallet(&self, cfg: WalletConfig) -> WalletHandle {
        let cache_key = cfg.cache_key.clone();
        if let Some(existing) = self.wallets.read().await.get(&cache_key) {
            return existing.handle.clone();
        }

        let mut cfg = cfg;
        let start_block = cfg.start_block.unwrap_or(self.chain.deployment_block);
        cfg.start_block = Some(start_block);

        let cancel = self.cancel.child_token();
        let live_rx = self.live_log_tx.subscribe();
        let (backfill_sender, backfill_rx) = mpsc::channel(128);
        let handle = spawn_wallet_worker(
            self.db.clone(),
            cfg.clone(),
            live_rx,
            backfill_rx,
            cancel.clone(),
        );
        let mut last_scanned = start_block.saturating_sub(1);
        if let Ok(Some(meta)) = self.db.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }

        let safe_head = *self.safe_head_tx.borrow();
        let from_block = last_scanned.saturating_add(1).max(start_block);
        if from_block <= safe_head {
            if self
                .backfill_tx
                .send(BackfillRequest::Add {
                    cache_key: cfg.cache_key.clone(),
                    from_block,
                    to_block: safe_head,
                    sender: backfill_sender.clone(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cfg.cache_key, "failed to enqueue backfill request");
            }
        } else if let Err(err) = backfill_sender
            .send(BackfillEvent::Done {
                last_block: safe_head,
            })
            .await
        {
            debug!(?err, cache_key = %cfg.cache_key, "failed to send backfill done");
        }

        self.wallets.write().await.insert(
            cache_key,
            WalletRegistration {
                handle: handle.clone(),
                cancel,
                backfill_sender,
                start_block,
            },
        );

        handle
    }

    pub async fn unregister_wallet(&self, cache_key: &str) {
        if let Some((_key, registration)) = self.wallets.write().await.remove_entry(cache_key) {
            registration.cancel.cancel();
            if self
                .backfill_tx
                .send(BackfillRequest::Remove {
                    cache_key: cache_key.to_string(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cache_key, "failed to remove backfill cursor");
            }
        }
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

#[async_trait]
pub trait MerkleForestDbExt {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError>;
    fn anchor_dir(&self) -> PathBuf;
    fn find_latest_anchor(&self, chain: &ChainConfig)
    -> Result<Option<(PathBuf, u64)>, ChainError>;
}

#[async_trait]
impl MerkleForestDbExt for DbStore {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError> {
        let mut forest = MerkleForest::new();
        let mut last_processed = chain.deployment_block.saturating_sub(1);
        let file_name = format!("forest-{}-{}.msgpack", chain.chain_id, chain.contract);
        self.ensure_blob_dir("merkle_forest")?;
        let relative = DbStore::relative_blob_path("merkle_forest", &file_name);
        let mut snapshot_path = self.resolve_path(&relative);
        let mut last_anchor = 0;

        if let Ok(Some(meta)) =
            self.get_merkle_forest_meta(chain.chain_id, &chain.contract.to_string())
        {
            let path = self.resolve_path(&meta.relative_path);
            match load_forest_snapshot(&path, chain.chain_id, chain.contract) {
                Ok(Some(snapshot)) => {
                    forest = snapshot.forest;
                    last_processed = snapshot.last_processed_block;
                    snapshot_path = path;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?err, path = %path.display(), "failed to load merkle forest snapshot");
                }
            }
        }

        if last_processed < chain.deployment_block
            && let Some(endpoint) = chain.quick_sync_endpoint.clone()
        {
            let config = QuickSyncConfig {
                endpoint,
                start_block: chain.deployment_block,
                end_block: None,
                page_size: DEFAULT_PAGE_SIZE,
            };
            match run_quick_sync(config).await {
                Ok(result) => {
                    forest = result.forest;
                    last_processed = result.progress.latest_commitment_block;
                    forest.compute_roots();
                }
                Err(err) => {
                    warn!(?err, "quick sync failed");
                }
            }
        }

        if let Ok(Some((anchor_path, anchor_block))) = self.find_latest_anchor(chain) {
            last_anchor = anchor_block;
            if last_processed < anchor_block {
                match load_forest_snapshot(&anchor_path, chain.chain_id, chain.contract) {
                    Ok(Some(snapshot)) => {
                        forest = snapshot.forest;
                        last_processed = snapshot.last_processed_block;
                        snapshot_path = anchor_path;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    }
                }
            }
        }

        Ok((
            Arc::new(RwLock::new(forest)),
            last_processed,
            snapshot_path,
            last_anchor,
        ))
    }

    fn anchor_dir(&self) -> PathBuf {
        self.blob_dir().join("merkle_forest").join("anchors")
    }

    fn find_latest_anchor(
        &self,
        chain: &ChainConfig,
    ) -> Result<Option<(PathBuf, u64)>, ChainError> {
        let dir = self.anchor_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut latest: Option<(PathBuf, u64)> = None;
        for entry in std::fs::read_dir(&dir).map_err(PersistError::Io)? {
            let entry = entry.map_err(PersistError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(chain.chain_id, chain.contract, name) {
                let path = entry.path();
                match &latest {
                    Some((_, latest_block)) if *latest_block >= block => {}
                    _ => latest = Some((path, block)),
                }
            }
        }
        Ok(latest)
    }
}

fn spawn_head_poller(service: Arc<ChainService>, rpcs: Arc<QueryRpcPool>) {
    let cancel = service.cancel.clone();
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(service.chain.poll_interval) => {
                        let Some(rpc) = rpcs.random_provider() else {
                            warn!("no healthy rpc providers available");
                            continue;
                        };
                        match rpc.provider.get_block_number().await {
                            Ok(head) => {
                                let safe_head = head.saturating_sub(service.chain.finality_depth)
                                    .max(service.chain.deployment_block);
                                if let Err(err) = service.head_tx.send(head) {
                                    debug!(?err, head, "failed to send head update");
                                }
                                if let Err(err) = service.safe_head_tx.send(safe_head) {
                                    debug!(?err, safe_head, "failed to send safe head update");
                                }
                            }
                            Err(err) => {
                                warn!(?err, "failed to fetch latest block");
                                rpcs.mark_bad_provider(&rpc);
                            }
                        }
                    }
                }
            }
        }
        .instrument(tracing::info_span!("sync_head", chain_id)),
    );
}

fn spawn_live_log_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut forest_last_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    cancel: CancellationToken,
) {
    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = safe_head_rx.changed() => {},
                    _ = forest_last_rx.changed() => {},
                }

                let safe_head = *safe_head_rx.borrow();
                if safe_head == 0 && service.chain.deployment_block > 0 {
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                }
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                };
                if let Err(err) = service
                    .check_forest_reorg(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        &snapshot_path,
                        safe_head,
                        last_processed,
                    )
                    .await
                {
                    debug!(?err, rpc = rpc.url.as_str(), "reorg check failed");
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    continue;
                }

                let from_block = last_processed.saturating_add(1);
                let to_block = min(from_block + service.chain.block_range - 1, safe_head);
                match service
                    .chain
                    .fetch_logs_for_range(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        from_block,
                        to_block,
                    )
                    .await
                {
                    Ok(mut logs) => {
                        sort_logs(&mut logs);
                        let to_block_hash = service
                            .chain
                            .fetch_block_hash(&rpc.provider, archive_provider.as_ref(), to_block)
                            .await
                            .unwrap_or_else(|err| {
                                warn!(?err, to_block, "failed to fetch block hash");
                                None
                            });
                        let batch = Arc::new(LogBatch {
                            from_block,
                            to_block,
                            logs,
                            to_block_hash,
                        });

                        let batch_hash = batch.to_block_hash;
                        if let Err(err) = service.apply_forest_updates(&batch).await {
                            warn!(?err, "failed to apply forest updates");
                        } else {
                            if let Err(err) = service.live_log_tx.send(batch) {
                                debug!(?err, to_block, "failed to broadcast live log batch");
                            }
                            if let Err(err) = service.forest_last_tx.send(to_block) {
                                debug!(?err, to_block, "failed to send forest progress update");
                            }
                            if let Err(err) = service
                                .persist_forest_snapshot(&snapshot_path, to_block, batch_hash)
                                .await
                            {
                                warn!(?err, "failed to persist forest snapshot");
                            }
                        }
                    }
                    Err(err) => {
                        if err.is_rpc_throttled() {
                            warn!(
                                rpc = rpc.url.as_str(),
                                "rpc is throttled, will retry with another..."
                            );
                        } else {
                            warn!(
                                ?err,
                                rpc = rpc.url.as_str(),
                                "failed to fetch logs, retrying..."
                            );
                        }
                        rpcs.mark_bad_provider(&rpc);
                    }
                }
            }
        }
        .instrument(tracing::info_span!("sync_live")),
    );
}

fn spawn_backfill_loop(
    service: Arc<ChainService>,
    mut backfill_rx: mpsc::Receiver<BackfillRequest>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut cursors: HashMap<String, WalletBackfill> = HashMap::new();
        loop {
            if cursors.is_empty() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    Some(request) = backfill_rx.recv() => {
                        match request {
                            BackfillRequest::Add { cache_key, from_block, to_block: _, sender } => {
                                cursors.insert(cache_key, WalletBackfill { from_block, sender });
                            }
                            BackfillRequest::Reset { cache_key, from_block } => {
                                if let Some(cursor) = cursors.get_mut(&cache_key) {
                                    cursor.from_block = from_block;
                                }
                            }
                            BackfillRequest::Remove { cache_key } => {
                                cursors.remove(&cache_key);
                            }
                        }
                    }
                    _ = safe_head_rx.changed() => {},
                }
            }
            if cursors.is_empty() {
                tokio::time::sleep(service.chain.poll_interval).await;
                continue;
            }

            let safe_head = *safe_head_rx.borrow();
            let min_from = cursors.values().map(|cursor| cursor.from_block).min();
            info!(block=?min_from, "scanning wallet events");
            let Some(from_block) = min_from else {
                continue;
            };
            if from_block > safe_head {
                let done_keys: Vec<String> = cursors.keys().cloned().collect();
                for key in done_keys {
                    if let Some(cursor) = cursors.remove(&key)
                        && let Err(err) = cursor
                            .sender
                            .send(BackfillEvent::Done {
                                last_block: safe_head,
                            })
                            .await
                    {
                        debug!(
                            ?err,
                            cache_key = %key,
                            "failed to send backfill done"
                        );
                    }
                }
                continue;
            }
            let Some(rpc) = rpcs.random_provider() else {
                warn!("no healthy rpc providers available");
                tokio::time::sleep(service.chain.poll_interval).await;
                continue;
            };
            let to_block = min(from_block + service.chain.block_range - 1, safe_head);
            match service.chain.fetch_logs_for_range(
                &rpc.provider,
                archive_provider.as_ref(),
                from_block,
                to_block,
            )
            .await
            {
                Ok(mut logs) => {
                    info!(from_block, to_block, num_logs=logs.len(), "fetched backfill logs");
                    sort_logs(&mut logs);
                    let to_block_hash = service.chain.fetch_block_hash(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        to_block,
                    )
                    .await
                    .unwrap_or_else(|err| {
                        warn!(?err, to_block, "failed to fetch backfill block hash");
                        None
                    });
                    let batch = Arc::new(LogBatch {
                        from_block,
                        to_block,
                        logs,
                        to_block_hash,
                    });

                    let keys: Vec<String> = cursors.keys().cloned().collect();
                    for key in keys {
                        if let Some(cursor) = cursors.get_mut(&key)
                            && cursor.from_block <= to_block
                        {
                            if let Err(err) =
                                cursor.sender.send(BackfillEvent::Logs(batch.clone())).await
                            {
                                debug!(
                                    ?err,
                                    cache_key = %key,
                                    "failed to send backfill logs"
                                );
                            }
                            cursor.from_block = to_block.saturating_add(1);
                            if cursor.from_block > safe_head {
                                if let Err(err) = cursor
                                    .sender
                                    .send(BackfillEvent::Done {
                                        last_block: safe_head,
                                    })
                                    .await
                                {
                                    debug!(
                                        ?err,
                                        cache_key = %key,
                                        "failed to send backfill done"
                                    );
                                }
                                cursors.remove(&key);
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        rpc = rpc.url.as_str(),
                        "failed to fetch backfill logs"
                    );
                    rpcs.mark_bad_provider(&rpc);
                }
            }
        }
    }.instrument(tracing::info_span!("sync_backfill")));
}

struct WalletBackfill {
    from_block: u64,
    sender: mpsc::Sender<BackfillEvent>,
}

impl ChainService {
    async fn apply_forest_updates(&self, batch: &SharedLogBatch) -> Result<(), ChainError> {
        let mut forest = self.forest.write().await;
        apply_commitment_updates_from_logs(&mut forest, &batch.logs)?;
        forest.compute_roots();
        Ok(())
    }
    async fn reset_forest_state(
        &self,
        snapshot_path: &Path,
        last_processed: u64,
    ) -> Result<(), ChainError> {
        let mut forest = self.forest.write().await;
        let mut reset_block = self.chain.deployment_block.saturating_sub(1);

        if let Ok(Some((anchor_path, anchor_block))) = self.db.find_latest_anchor(&self.chain) {
            match load_forest_snapshot(&anchor_path, self.chain.chain_id, self.chain.contract) {
                Ok(Some(snapshot)) => {
                    *forest = snapshot.forest;
                    reset_block = snapshot.last_processed_block;
                    write_forest_snapshot(
                        snapshot_path,
                        self.chain.chain_id,
                        self.chain.contract,
                        reset_block,
                        &forest,
                    )?;
                    self.anchor_last.store(anchor_block, Ordering::Relaxed);
                    info!(
                        from = last_processed,
                        to = reset_block,
                        anchor = %anchor_path.display(),
                        "forest reset to anchor"
                    );
                }
                Ok(None) => {
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
                Err(err) => {
                    warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
            }
        } else {
            *forest = MerkleForest::new();
            self.anchor_last.store(0, Ordering::Relaxed);
        }

        write_forest_snapshot(
            snapshot_path,
            self.chain.chain_id,
            self.chain.contract,
            reset_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
            snapshot_path,
            reset_block,
            SNAPSHOT_VERSION,
            [0u8; 32],
        )?;
        if let Err(err) = self.forest_last_tx.send(reset_block) {
            debug!(?err, reset_block, "failed to send forest reset update");
        }
        info!(
            from = last_processed,
            to = reset_block,
            "forest state reset"
        );
        Ok(())
    }

    async fn reset_wallets(&self, safe_head: u64) {
        let wallets = self.wallets.read().await;
        for (cache_key, registration) in wallets.iter() {
            if let Err(err) = registration
                .backfill_sender
                .send(BackfillEvent::Reset {
                    from_block: registration.start_block,
                })
                .await
            {
                debug!(
                    ?err,
                    cache_key = %cache_key,
                    "failed to send wallet reset"
                );
            }
            if self
                .backfill_tx
                .send(BackfillRequest::Add {
                    cache_key: cache_key.clone(),
                    from_block: registration.start_block,
                    to_block: safe_head,
                    sender: registration.backfill_sender.clone(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cache_key, "failed to enqueue wallet backfill");
            }
        }
    }

    async fn check_forest_reorg(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        snapshot_path: &Path,
        safe_head: u64,
        last_processed: u64,
    ) -> Result<(), ChainError> {
        if last_processed < self.chain.deployment_block {
            return Ok(());
        }
        let meta = self
            .db
            .get_merkle_forest_meta(self.chain.chain_id, &self.chain.contract.to_string())?;
        let Some(meta) = meta else {
            return Ok(());
        };
        if meta.hash == [0u8; 32] {
            return Ok(());
        }
        let current_hash = self
            .chain
            .fetch_block_hash(provider, archive_provider, last_processed)
            .await?;
        if let Some(current_hash) = current_hash
            && current_hash != meta.hash
        {
            warn!(
                last_processed,
                "detected reorg, resetting forest and wallet caches"
            );
            self.reset_forest_state(snapshot_path, last_processed)
                .await?;
            self.reset_wallets(safe_head).await;
        }
        Ok(())
    }

    async fn persist_forest_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        block_hash: Option<[u8; 32]>,
    ) -> Result<(), ChainError> {
        let forest = self.forest.read().await;
        write_forest_snapshot(
            snapshot_path,
            self.chain.chain_id,
            self.chain.contract,
            last_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
            snapshot_path,
            last_block,
            SNAPSHOT_VERSION,
            block_hash.unwrap_or([0u8; 32]),
        )?;

        self.maybe_write_anchor_snapshot(snapshot_path, last_block, &forest)?;

        Ok(())
    }

    fn maybe_write_anchor_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        forest: &MerkleForest,
    ) -> Result<(), PersistError> {
        let interval = self.chain.anchor_interval;
        if interval == 0 {
            return Ok(());
        }
        let last_anchor = self.anchor_last.load(Ordering::Relaxed);
        if last_block < last_anchor.saturating_add(interval) {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        std::fs::create_dir_all(&anchor_dir)?;
        let file_name = anchor_file_name(self.chain.chain_id, self.chain.contract, last_block);
        let relative = DbStore::relative_blob_path("merkle_forest/anchors", &file_name);
        let path = self.db.resolve_path(&relative);
        write_forest_snapshot(
            &path,
            self.chain.chain_id,
            self.chain.contract,
            last_block,
            forest,
        )?;
        self.anchor_last.store(last_block, Ordering::Relaxed);
        if path.as_path() != snapshot_path {
            debug!(path = %path.display(), block = last_block, "wrote anchor snapshot");
        }
        if let Err(err) = self.prune_anchor_snapshots(snapshot_path) {
            warn!(?err, "failed to prune anchor snapshots");
        }
        Ok(())
    }

    fn prune_anchor_snapshots(&self, snapshot_path: &Path) -> Result<(), PersistError> {
        let retention = self.chain.anchor_retention;
        if retention == 0 {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        if !anchor_dir.exists() {
            return Ok(());
        }
        let mut anchors = Vec::with_capacity(retention + 8);
        for entry in std::fs::read_dir(&anchor_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(self.chain.chain_id, self.chain.contract, name)
            {
                anchors.push((entry.path(), block));
            }
        }
        if anchors.len() <= retention {
            return Ok(());
        }
        anchors.sort_by_key(|(_, block)| *block);
        let mut keep = HashSet::new();
        for (path, _) in anchors.iter().rev().take(retention) {
            keep.insert(path.clone());
        }
        if snapshot_path.starts_with(&anchor_dir) {
            keep.insert(snapshot_path.to_path_buf());
        }
        for (path, block) in anchors {
            if keep.contains(&path) {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    debug!(path = %path.display(), block, "pruned anchor snapshot");
                }
                Err(err) => {
                    warn!(?err, path = %path.display(), block, "failed to prune anchor snapshot");
                }
            }
        }
        Ok(())
    }
}

impl ChainConfig {
    async fn fetch_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let provider = if self.archive_until_block > 0 && block_number <= self.archive_until_block {
            archive_provider.ok_or(ChainError::ArchiveRpcRequired(self.archive_until_block))?
        } else {
            provider
        };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.hash.0))
    }

    async fn fetch_logs_for_range(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, ChainError> {
        let mut logs = Vec::new();
        let archive_until_block = self.archive_until_block;

        if archive_until_block > 0 && from_block <= archive_until_block {
            let archive_end = to_block.min(archive_until_block);
            let archive_provider =
                archive_provider.ok_or(ChainError::ArchiveRpcRequired(archive_until_block))?;
            let archive_logs = fetch_logs_for_range_with_provider(
                archive_provider,
                self.contract,
                from_block,
                archive_end,
                self.v2_start_block,
                self.legacy_shield_block,
            )
            .await?;
            logs.extend(archive_logs);
        }

        if to_block > archive_until_block {
            let standard_start = if archive_until_block > 0 {
                from_block.max(archive_until_block + 1)
            } else {
                from_block
            };
            let standard_logs = fetch_logs_for_range_with_provider(
                provider,
                self.contract,
                standard_start,
                to_block,
                self.v2_start_block,
                self.legacy_shield_block,
            )
            .await?;
            logs.extend(standard_logs);
        }

        Ok(logs)
    }
}

async fn fetch_logs_for_range_with_provider(
    provider: &DynProvider,
    contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Result<Vec<Log>, ChainError> {
    let mut logs = Vec::new();

    if from_block <= v2_start_block {
        let legacy_end = to_block.min(v2_start_block);
        let legacy_filter = Filter::new()
            .select(from_block..=legacy_end)
            .address(contract)
            .event_signature(vec![
                CommitmentBatch::SIGNATURE_HASH,
                GeneratedCommitmentBatch::SIGNATURE_HASH,
            ]);
        let legacy_logs = provider.get_logs(&legacy_filter).await?;
        logs.extend(legacy_logs);
    }

    if to_block >= v2_start_block {
        let v2_start = from_block.max(v2_start_block);
        let transact_filter = Filter::new()
            .select(v2_start..=to_block)
            .address(contract)
            .event_signature(Transact::SIGNATURE_HASH);
        let transact_logs = provider.get_logs(&transact_filter).await?;
        logs.extend(transact_logs);

        if v2_start <= legacy_shield_block {
            let legacy_shield_end = to_block.min(legacy_shield_block);
            let legacy_shield_filter = Filter::new()
                .select(v2_start..=legacy_shield_end)
                .address(contract)
                .event_signature(ShieldLegacyPreMar23::SIGNATURE_HASH);
            let legacy_shield_logs = provider.get_logs(&legacy_shield_filter).await?;
            logs.extend(legacy_shield_logs);
        }

        if to_block > legacy_shield_block {
            let modern_start = v2_start.max(legacy_shield_block.saturating_add(1));
            let modern_shield_filter = Filter::new()
                .select(modern_start..=to_block)
                .address(contract)
                .event_signature(Shield::SIGNATURE_HASH);
            let modern_shield_logs = provider.get_logs(&modern_shield_filter).await?;
            logs.extend(modern_shield_logs);
        }
    }

    let nullifier_filter = Filter::new()
        .select(from_block..=to_block)
        .address(contract)
        .event_signature(vec![Nullifiers::SIGNATURE_HASH, Nullified::SIGNATURE_HASH]);
    let nullifier_logs = provider.get_logs(&nullifier_filter).await?;
    logs.extend(nullifier_logs);

    Ok(logs)
}

fn sort_logs(logs: &mut [Log]) {
    logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
}

fn anchor_file_name(chain_id: u64, contract: Address, block: u64) -> String {
    format!("forest-{chain_id}-{contract}-anchor-{block}.msgpack")
}

fn parse_anchor_block(chain_id: u64, contract: Address, name: &str) -> Option<u64> {
    let prefix = format!("forest-{chain_id}-{contract}-anchor-");
    let suffix = ".msgpack";
    if !name.starts_with(&prefix) || !name.ends_with(suffix) {
        return None;
    }
    let start = prefix.len();
    let end = name.len().saturating_sub(suffix.len());
    name.get(start..end)?.parse::<u64>().ok()
}
