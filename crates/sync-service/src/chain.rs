use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, LogBatch, SharedLogBatch, SyncProgressSender,
    SyncProgressStage, SyncProgressUpdate, WalletConfig,
};
use crate::wallet::{WalletHandle, apply_wallet_delta_to_vec, spawn_wallet_worker};
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
use merkletree::errors::SyncError;
use merkletree::persist::{
    PersistError, SNAPSHOT_VERSION, load_forest_snapshot, write_forest_snapshot,
};
use merkletree::quick::{
    DEFAULT_PAGE_SIZE, IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment,
    IndexedNullifier, IndexedShieldCommitment, IndexedTransactCommitment, QuickSyncClient,
    QuickSyncConfig, run_quick_sync_into_with_progress,
};
use merkletree::slow::types::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, Shield, ShieldLegacyPreMar23,
    Transact,
};
use merkletree::tree::MerkleForest;
use merkletree::wallet::{
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput,
    WalletScanError, apply_commitment_updates_from_logs, parse_indexed_wallet_delta,
};
use railgun_wallet::UtxoSource;
use railgun_wallet::wallet_cache::WalletCacheDbExt;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexedWalletPageKind {
    Legacy,
    Modern,
}

impl IndexedWalletPageKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
        }
    }
}

fn send_sync_progress(progress_tx: Option<&SyncProgressSender>, update: SyncProgressUpdate) {
    if let Some(progress_tx) = progress_tx
        && let Err(err) = progress_tx.send(Some(update))
    {
        debug!(?err, "failed to send sync progress update");
    }
}

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

        let rpcs = chain.rpcs.clone();
        let rpc = rpcs
            .random_provider()
            .ok_or_else(|| ChainError::NoHealthyRpc)?;
        let (initial_head, initial_safe_head) = fetch_initial_head(&chain, &rpc.provider).await;

        let (forest, last_processed, snapshot_path, last_anchor) = db
            .load_or_initialize_forest(
                &chain,
                initial_safe_head,
                Some(&rpc.provider),
                archive_provider.as_ref(),
            )
            .await?;

        let (head_tx, _head_rx) = watch::channel(initial_head);
        let (safe_head_tx, safe_head_rx) = watch::channel(initial_safe_head);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
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

        let mut last_scanned = start_block.saturating_sub(1);
        if let Ok(Some(meta)) = self.db.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }

        let safe_head = *self.safe_head_tx.borrow();
        last_scanned = self
            .indexed_wallet_catch_up(&cfg, start_block, last_scanned, safe_head)
            .await;

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
        let from_block = wallet_backfill_from_block(last_scanned, start_block);

        // When safe_head has not been set yet (still 0) we cannot tell
        // whether the wallet is caught up, so we always enqueue a backfill
        // request and let the backfill loop wait for safe_head to become
        // available.  This avoids prematurely marking the wallet as ready
        // with stale cached data.
        let needs_backfill = safe_head == 0 || from_block <= safe_head;

        if needs_backfill {
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
                warn!(cache_key = %cfg.cache_key, "backfill loop unavailable, sending done as fallback");
                let _ = backfill_sender
                    .send(BackfillEvent::Done {
                        last_block: safe_head,
                    })
                    .await;
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

    async fn indexed_wallet_catch_up(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        safe_head: u64,
    ) -> u64 {
        if safe_head == 0 {
            debug!(cache_key = %cfg.cache_key, "safe head unavailable; skipping indexed wallet catch-up");
            return last_scanned;
        }
        let Some(endpoint) = self.chain.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cfg.cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return last_scanned;
        };
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return last_scanned;
            }
        };
        let target = probe.height.min(safe_head);
        let mut from_block = last_scanned.saturating_add(1).max(start_block);
        let progress_start = from_block;
        let progress_tx = cfg
            .progress_tx
            .clone()
            .or_else(|| self.chain.progress_tx.clone());
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            safe_head,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet catch-up target"
        );
        if from_block > target {
            return last_scanned;
        }
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                progress_start,
                target,
            ),
        );

        let mut wallet_utxos = match self.db.load_wallet_utxos(&cfg.cache_key) {
            Ok(wallet_utxos) => wallet_utxos,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "failed to load wallet cache for indexed catch-up; using RPC backfill"
                );
                return last_scanned;
            }
        };
        let mut checkpoint = last_scanned;
        while from_block <= target {
            let page_kind = indexed_wallet_page_kind(from_block, self.chain.v2_start_block);
            let to_block = indexed_wallet_to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let page =
                match fetch_indexed_wallet_page(&client, page_kind, from_block, to_block).await {
                    Ok(page) => page,
                    Err(err) => {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet catch-up page failed; using RPC backfill"
                        );
                        return checkpoint;
                    }
                };
            let delta = parse_indexed_wallet_delta(
                &page.transact_commitments,
                &page.shield_commitments,
                &page.legacy_encrypted_commitments,
                &page.legacy_generated_commitments,
                &page.nullifiers,
                &cfg.scan_keys,
            );
            apply_wallet_delta_to_vec(cfg, &mut wallet_utxos, delta);
            if let Err(err) = self.db.store_wallet_utxos(
                &cfg.cache_key,
                &wallet_utxos,
                Some(page.checkpoint_block),
                None,
            ) {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    fallback_from = checkpoint,
                    "failed to persist indexed wallet checkpoint; using RPC backfill"
                );
                return checkpoint;
            }
            checkpoint = page.checkpoint_block;
            info!(
                cache_key = %cfg.cache_key,
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                transact_rows = page.transact_rows,
                shield_rows = page.shield_rows,
                legacy_encrypted_rows = page.legacy_encrypted_rows,
                legacy_generated_rows = page.legacy_generated_rows,
                nullifier_rows = page.nullifier_rows,
                "indexed wallet catch-up page complete"
            );
            from_block = checkpoint.saturating_add(1);
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    checkpoint,
                    target,
                ),
            );
        }
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                target,
                target,
            ),
        );
        checkpoint
    }
}

async fn fetch_initial_head(chain: &ChainConfig, provider: &DynProvider) -> (u64, u64) {
    for attempt in 0..3u32 {
        match provider.get_block_number().await {
            Ok(head) => {
                let safe_head = head
                    .saturating_sub(chain.finality_depth)
                    .max(chain.deployment_block);
                return (head, safe_head);
            }
            Err(err) => {
                warn!(
                    ?err,
                    attempt, "failed to fetch initial block number, retrying..."
                );
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
                }
            }
        }
    }
    (0, 0)
}

struct IndexedWalletPage {
    transact_commitments: Vec<IndexedTransactCommitmentInput>,
    shield_commitments: Vec<IndexedShieldCommitmentInput>,
    legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitmentInput>,
    legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitmentInput>,
    nullifiers: Vec<IndexedNullifierInput>,
    checkpoint_block: u64,
    transact_rows: usize,
    shield_rows: usize,
    legacy_encrypted_rows: usize,
    legacy_generated_rows: usize,
    nullifier_rows: usize,
}

async fn fetch_indexed_wallet_page(
    client: &QuickSyncClient,
    page_kind: IndexedWalletPageKind,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    match page_kind {
        IndexedWalletPageKind::Legacy => {
            fetch_indexed_legacy_wallet_page(client, from_block, to_block).await
        }
        IndexedWalletPageKind::Modern => {
            fetch_indexed_modern_wallet_page(client, from_block, to_block).await
        }
    }
}

async fn fetch_indexed_modern_wallet_page(
    client: &QuickSyncClient,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    let page = client
        .fetch_indexed_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
        .await?;
    let transact = page.transact_commitments;
    let shields = page.shield_commitments;
    let nullifiers = page.nullifiers;
    let page_size = DEFAULT_PAGE_SIZE.get();
    let transact_checkpoint = complete_stream_checkpoint(
        transact.len(),
        page_size,
        to_block,
        transact.iter().map(|item| item.block_number.to()),
    );
    let shield_checkpoint = complete_stream_checkpoint(
        shields.len(),
        page_size,
        to_block,
        shields.iter().map(|item| item.block_number.to()),
    );
    let nullifier_checkpoint = complete_stream_checkpoint(
        nullifiers.len(),
        page_size,
        to_block,
        nullifiers.iter().map(|item| item.block_number.to()),
    );
    let checkpoint_block = transact_checkpoint
        .min(shield_checkpoint)
        .min(nullifier_checkpoint);
    if checkpoint_block < from_block {
        return Err(SyncError::UnexpectedFormat(format!(
            "indexed wallet page is incomplete at block {from_block}; reduce page range or increase page size"
        )));
    }

    let transact_rows = transact.len();
    let shield_rows = shields.len();
    let nullifier_rows = nullifiers.len();
    let transact_commitments = transact
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_transact_input)
        .collect();
    let shield_commitments = shields
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_shield_input)
        .collect();
    let nullifiers = nullifiers
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_nullifier_input)
        .collect();

    Ok(IndexedWalletPage {
        transact_commitments,
        shield_commitments,
        legacy_encrypted_commitments: Vec::new(),
        legacy_generated_commitments: Vec::new(),
        nullifiers,
        checkpoint_block,
        transact_rows,
        shield_rows,
        legacy_encrypted_rows: 0,
        legacy_generated_rows: 0,
        nullifier_rows,
    })
}

async fn fetch_indexed_legacy_wallet_page(
    client: &QuickSyncClient,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    let page = client
        .fetch_indexed_legacy_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
        .await?;
    let legacy_encrypted = page.legacy_encrypted_commitments;
    let legacy_generated = page.legacy_generated_commitments;
    let nullifiers = page.nullifiers;
    let page_size = DEFAULT_PAGE_SIZE.get();
    let encrypted_checkpoint = complete_stream_checkpoint(
        legacy_encrypted.len(),
        page_size,
        to_block,
        legacy_encrypted.iter().map(|item| item.block_number.to()),
    );
    let generated_checkpoint = complete_stream_checkpoint(
        legacy_generated.len(),
        page_size,
        to_block,
        legacy_generated.iter().map(|item| item.block_number.to()),
    );
    let nullifier_checkpoint = complete_stream_checkpoint(
        nullifiers.len(),
        page_size,
        to_block,
        nullifiers.iter().map(|item| item.block_number.to()),
    );
    let checkpoint_block = encrypted_checkpoint
        .min(generated_checkpoint)
        .min(nullifier_checkpoint);
    if checkpoint_block < from_block {
        return Err(SyncError::UnexpectedFormat(format!(
            "indexed legacy wallet page is incomplete at block {from_block}; reduce page range or increase page size"
        )));
    }

    let legacy_encrypted_rows = legacy_encrypted.len();
    let legacy_generated_rows = legacy_generated.len();
    let nullifier_rows = nullifiers.len();
    let legacy_encrypted_commitments = legacy_encrypted
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_legacy_encrypted_input)
        .collect();
    let legacy_generated_commitments = legacy_generated
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_legacy_generated_input)
        .collect();
    let nullifiers = nullifiers
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_nullifier_input)
        .collect();

    Ok(IndexedWalletPage {
        transact_commitments: Vec::new(),
        shield_commitments: Vec::new(),
        legacy_encrypted_commitments,
        legacy_generated_commitments,
        nullifiers,
        checkpoint_block,
        transact_rows: 0,
        shield_rows: 0,
        legacy_encrypted_rows,
        legacy_generated_rows,
        nullifier_rows,
    })
}

fn complete_stream_checkpoint<I>(
    row_count: usize,
    page_size: usize,
    target_block: u64,
    block_numbers: I,
) -> u64
where
    I: Iterator<Item = u64>,
{
    if row_count < page_size {
        return target_block;
    }
    block_numbers
        .max()
        .unwrap_or(target_block)
        .saturating_sub(1)
}

fn indexed_source(tx_hash: alloy::primitives::FixedBytes<32>, block_number: u64) -> UtxoSource {
    UtxoSource {
        tx_hash,
        block_number,
    }
}

fn indexed_transact_input(item: IndexedTransactCommitment) -> IndexedTransactCommitmentInput {
    IndexedTransactCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        hash: item.hash,
        ciphertext: item.ciphertext.ciphertext,
        blinded_sender_viewing_key: item.ciphertext.blinded_sender_viewing_key,
        memo: item.ciphertext.memo,
        source: indexed_source(item.transaction_hash, item.block_number.to()),
    }
}

fn indexed_shield_input(item: IndexedShieldCommitment) -> IndexedShieldCommitmentInput {
    IndexedShieldCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        preimage: item.preimage(),
        shield_ciphertext: item.shield_ciphertext(),
        source: indexed_source(item.transaction_hash, item.block_number.to()),
    }
}

fn indexed_nullifier_input(item: IndexedNullifier) -> IndexedNullifierInput {
    IndexedNullifierInput {
        tree_number: item.tree_number.to(),
        nullifier: item.nullifier,
        source: indexed_source(item.transaction_hash, item.block_number.to()),
    }
}

fn indexed_legacy_encrypted_input(
    item: IndexedLegacyEncryptedCommitment,
) -> IndexedLegacyEncryptedCommitmentInput {
    IndexedLegacyEncryptedCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        hash: item.hash,
        ciphertext: item.ciphertext.ciphertext,
        ephemeral_keys: item.ciphertext.ephemeral_keys,
        memo: item.ciphertext.memo,
        source: indexed_source(item.transaction_hash, item.block_number.to()),
    }
}

fn indexed_legacy_generated_input(
    item: IndexedLegacyGeneratedCommitment,
) -> IndexedLegacyGeneratedCommitmentInput {
    IndexedLegacyGeneratedCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        preimage: item.preimage.into(),
        encrypted_random: item.encrypted_random,
        source: indexed_source(item.transaction_hash, item.block_number.to()),
    }
}

fn indexed_wallet_page_kind(from_block: u64, v2_start_block: u64) -> IndexedWalletPageKind {
    if v2_start_block > 0 && from_block < v2_start_block {
        IndexedWalletPageKind::Legacy
    } else {
        IndexedWalletPageKind::Modern
    }
}

fn indexed_wallet_to_block(
    from_block: u64,
    target: u64,
    v2_start_block: u64,
    indexed_wallet_block_range: u64,
) -> u64 {
    let range_end = min(
        from_block.saturating_add(indexed_wallet_block_range.saturating_sub(1)),
        target,
    );
    if v2_start_block > 0 && from_block < v2_start_block {
        range_end.min(v2_start_block.saturating_sub(1))
    } else {
        range_end
    }
}

fn wallet_backfill_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

#[async_trait]
pub trait MerkleForestDbExt {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
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
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
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

        if let Some(endpoint) = chain.quick_sync_endpoint.clone() {
            let client = match chain.http_client.clone() {
                Some(http_client) => {
                    QuickSyncClient::with_http_client(endpoint.clone(), http_client)
                }
                None => QuickSyncClient::new(endpoint.clone()),
            };
            match client.fetch_squid_height().await {
                Ok(indexed_height) => {
                    let target = indexed_height.min(safe_head);
                    info!(
                        chain_id = chain.chain_id,
                        indexed_height,
                        safe_head,
                        current_block = last_processed,
                        target,
                        "indexed forest catch-up target"
                    );
                    if target > last_processed {
                        let start_block =
                            last_processed.saturating_add(1).max(chain.deployment_block);
                        if start_block <= target {
                            let mut candidate = forest.clone();
                            let config = QuickSyncConfig {
                                endpoint,
                                start_block,
                                end_block: Some(target),
                                page_size: DEFAULT_PAGE_SIZE,
                                http_client: chain.http_client.clone(),
                            };
                            let progress_tx = chain.progress_tx.clone();
                            send_sync_progress(
                                progress_tx.as_ref(),
                                SyncProgressUpdate::new(
                                    SyncProgressStage::SynchronizingCommitments,
                                    start_block,
                                    start_block,
                                    target,
                                ),
                            );
                            match run_quick_sync_into_with_progress(
                                &mut candidate,
                                config,
                                |progress| {
                                    send_sync_progress(
                                        progress_tx.as_ref(),
                                        SyncProgressUpdate::new(
                                            SyncProgressStage::SynchronizingCommitments,
                                            progress.start_block,
                                            progress.latest_block,
                                            target,
                                        ),
                                    );
                                },
                            )
                            .await
                            {
                                Ok(progress) => {
                                    let block_hash = match provider {
                                        Some(provider) => chain
                                            .fetch_block_hash(provider, archive_provider, target)
                                            .await
                                            .unwrap_or_else(|err| {
                                                warn!(
                                                    ?err,
                                                    target,
                                                    "failed to fetch indexed forest target block hash"
                                                );
                                                None
                                            }),
                                        None => None,
                                    };
                                    match persist_indexed_forest_snapshot(
                                        self,
                                        chain,
                                        &snapshot_path,
                                        target,
                                        block_hash,
                                        &candidate,
                                    ) {
                                        Ok(()) => {
                                            forest = candidate;
                                            last_processed = target;
                                            send_sync_progress(
                                                progress_tx.as_ref(),
                                                SyncProgressUpdate::new(
                                                    SyncProgressStage::SynchronizingCommitments,
                                                    start_block,
                                                    target,
                                                    target,
                                                ),
                                            );
                                            info!(
                                                chain_id = chain.chain_id,
                                                from_block = start_block,
                                                target,
                                                commitments = progress.commitments,
                                                "indexed forest catch-up complete"
                                            );
                                        }
                                        Err(err) => {
                                            warn!(
                                                ?err,
                                                fallback_from = last_processed,
                                                "indexed forest catch-up persistence failed; falling back to RPC"
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        ?err,
                                        fallback_from = last_processed,
                                        "indexed forest catch-up failed; falling back to RPC"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        "indexed forest status query failed; falling back to RPC"
                    );
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

fn persist_indexed_forest_snapshot(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    last_block: u64,
    block_hash: Option<[u8; 32]>,
    forest: &MerkleForest,
) -> Result<(), ChainError> {
    write_forest_snapshot(
        snapshot_path,
        chain.chain_id,
        chain.contract,
        last_block,
        forest,
    )?;
    db.update_merkle_forest_meta(
        chain.chain_id,
        &chain.contract.to_string(),
        snapshot_path,
        last_block,
        SNAPSHOT_VERSION,
        block_hash.unwrap_or([0u8; 32]),
    )?;
    Ok(())
}

fn spawn_head_poller(service: Arc<ChainService>, rpcs: Arc<QueryRpcPool>) {
    let cancel = service.cancel.clone();
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                // Poll first, then sleep.  This ensures the very first poll
                // happens immediately instead of after a full poll_interval
                // delay, which is critical for fast safe_head availability.
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => { continue; }
                    }
                };
                match rpc.provider.get_block_number().await {
                    Ok(head) => {
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
                    Err(err) => {
                        warn!(?err, "failed to fetch latest block");
                        rpcs.mark_bad_provider(&rpc);
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(service.chain.poll_interval) => {}
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
                // Re-enter the loop immediately so that pending requests in
                // backfill_rx are picked up without an unnecessary poll_interval
                // delay.
                continue;
            }

            let safe_head = *safe_head_rx.borrow();
            let min_from = cursors.values().map(|cursor| cursor.from_block).min();
            info!(block=?min_from, "scanning wallet events");
            let Some(from_block) = min_from else {
                continue;
            };
            if from_block > safe_head {
                if safe_head == 0 {
                    // safe_head not yet available — the head poller hasn't
                    // successfully fetched a block number yet.  Wait for it
                    // instead of prematurely marking wallets as done.
                    debug!("safe_head is 0, waiting for head poller before backfill");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = safe_head_rx.changed() => { continue; }
                    }
                }
                // safe_head > 0 and all cursors are past it — genuinely caught up.
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

#[cfg(test)]
mod tests {
    use super::{
        IndexedWalletPageKind, complete_stream_checkpoint, indexed_wallet_page_kind,
        indexed_wallet_to_block, wallet_backfill_from_block,
    };

    #[test]
    fn complete_stream_checkpoint_uses_target_for_non_full_pages() {
        let checkpoint = complete_stream_checkpoint(2, 10, 100, [20_u64, 40].into_iter());

        assert_eq!(checkpoint, 100);
    }

    #[test]
    fn complete_stream_checkpoint_stops_before_partial_final_block() {
        let checkpoint = complete_stream_checkpoint(3, 3, 100, [20_u64, 25, 25].into_iter());

        assert_eq!(checkpoint, 24);
    }

    #[test]
    fn wallet_backfill_starts_after_indexed_checkpoint() {
        assert_eq!(wallet_backfill_from_block(99, 10), 100);
        assert_eq!(wallet_backfill_from_block(0, 10), 10);
    }

    #[test]
    fn indexed_wallet_page_kind_is_legacy_only_before_v2_start() {
        assert_eq!(
            indexed_wallet_page_kind(99, 100),
            IndexedWalletPageKind::Legacy
        );
        assert_eq!(
            indexed_wallet_page_kind(100, 100),
            IndexedWalletPageKind::Modern
        );
        assert_eq!(
            indexed_wallet_page_kind(99, 0),
            IndexedWalletPageKind::Modern
        );
    }

    #[test]
    fn indexed_wallet_to_block_splits_at_v2_start() {
        assert_eq!(indexed_wallet_to_block(50, 200_000, 100, 300_000), 99);
        assert_eq!(indexed_wallet_to_block(100, 200_000, 100, 300_000), 200_000);
        assert_eq!(indexed_wallet_to_block(50, 60, 100, 300_000), 60);
    }

    #[test]
    fn indexed_wallet_to_block_uses_configured_range() {
        assert_eq!(
            indexed_wallet_to_block(100, 10_000_000, 0, 1_000_000),
            1_000_099
        );
        assert_eq!(
            indexed_wallet_to_block(100, 10_000_000, 0, 5_000_000),
            5_000_099
        );
    }
}
