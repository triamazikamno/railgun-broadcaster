use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::DbStore;
use merkletree::wallet::{WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{Utxo, UtxoSource, WalletUtxo};

use crate::types::{BackfillEvent, SharedLogBatch, WalletCacheStore, WalletConfig};

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
    rev_tx: watch::Sender<u64>,
}

async fn apply_wallet_logs(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    batch: &SharedLogBatch,
    last_scanned: u64,
) -> Result<(u64, bool), WalletScanError> {
    let filtered_logs: Vec<_> = batch
        .logs
        .iter()
        .filter(|log| log.block_number.unwrap_or_default() > last_scanned)
        .cloned()
        .collect();

    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
    } = if filtered_logs.is_empty() {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
        }
    } else {
        parse_wallet_delta_from_logs(&filtered_logs, &batch.block_timestamps, &cfg.scan_keys)?
    };

    let changed = apply_wallet_delta(
        cfg,
        wallet_utxos,
        WalletLogDelta {
            utxos: new_utxos,
            nullifiers,
        },
    )
    .await;

    Ok((batch.to_block, changed))
}

pub(crate) async fn apply_wallet_delta(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    delta: WalletLogDelta,
) -> bool {
    let mut locked = wallet_utxos.write().await;
    apply_wallet_delta_to_vec(cfg, &mut locked, delta)
}

pub(crate) fn apply_wallet_delta_to_vec(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> bool {
    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();
    let mut changed = false;
    if !nullifier_sources.is_empty() {
        for wallet_utxo in wallet_utxos.iter_mut().filter(|entry| !entry.is_spent()) {
            if let Some(source) = spent_source_for_utxo(
                &wallet_utxo.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            ) {
                wallet_utxo.spent = Some(source);
                changed = true;
            }
        }
    }

    let mut existing: HashSet<_> = wallet_utxos
        .iter()
        .map(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position))
        .collect();
    for utxo in new_utxos {
        if existing.insert((utxo.tree, utxo.position)) {
            let spent =
                spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
            wallet_utxos.push(WalletUtxo { utxo, spent });
            changed = true;
        }
    }

    let before_dedupe = wallet_utxos.len();
    dedupe_wallet_utxos(wallet_utxos);
    changed || wallet_utxos.len() != before_dedupe
}

fn spent_source_for_utxo(
    utxo: &Utxo,
    nullifying_key: alloy::primitives::U256,
    nullifier_sources: &HashMap<(u32, alloy::primitives::U256), UtxoSource>,
) -> Option<UtxoSource> {
    nullifier_sources
        .get(&(utxo.tree, utxo.nullifier(nullifying_key)))
        .cloned()
}

impl WalletHandle {
    pub async fn wait_until_ready(&mut self) {
        while !*self.ready_rx.borrow() {
            if self.ready_rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub(crate) fn notify_changed(&self) {
        notify_wallet_rev(self);
    }
}

fn notify_wallet_rev(handle: &WalletHandle) {
    let rev = handle.rev_rx.borrow().wrapping_add(1);
    if let Err(err) = handle.rev_tx.send(rev) {
        debug!(?err, cache_key = %handle.cache_key, "failed to send wallet revision");
    }
}

#[derive(Default)]
struct WalletPersistState {
    needs_full_persist: bool,
    pending_cache_reset: Option<u64>,
}

struct WalletProgressPersist<'a> {
    cache_key: &'a str,
    snapshot: &'a [WalletUtxo],
    last_scanned: u64,
    last_scanned_block_hash: Option<[u8; 32]>,
    changed: bool,
}

fn persist_wallet_progress(
    cache_store: &dyn WalletCacheStore,
    request: WalletProgressPersist<'_>,
    state: &mut WalletPersistState,
) -> Result<bool, WalletCacheError> {
    if let Some(reset_last_scanned) = state.pending_cache_reset {
        cache_store.reset_wallet_cache(request.cache_key, reset_last_scanned)?;
        state.pending_cache_reset = None;
        state.needs_full_persist = true;
    }

    let full_persist = request.changed || state.needs_full_persist;
    if full_persist {
        return match cache_store.store_wallet_utxos(
            request.cache_key,
            request.snapshot,
            Some(request.last_scanned),
            request.last_scanned_block_hash,
        ) {
            Ok(()) => {
                state.needs_full_persist = false;
                Ok(true)
            }
            Err(err) => {
                state.needs_full_persist = true;
                Err(err)
            }
        };
    }

    cache_store.update_wallet_meta(
        request.cache_key,
        request.last_scanned,
        request.last_scanned_block_hash,
    )?;
    Ok(false)
}

pub(crate) fn spawn_wallet_worker(
    db: Arc<DbStore>,
    cfg: WalletConfig,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> WalletHandle {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let cache_store = wallet_cache_store(&db, &cfg);
    let (ready_tx, ready_rx) = watch::channel(false);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        utxos: utxos.clone(),
        ready_rx,
        rev_rx,
        rev_tx,
    };

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    tokio::spawn(async move {
        let mut last_scanned = initial_last_scanned;
        let snapshot = utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %cfg.cache_key,
            total = snapshot.len(),
            unspent,
            spent,
            last_scanned,
            "loaded wallet cache"
        );
        drop(snapshot);

        let mut backfill_complete_block: Option<u64> = None;
        let mut persist_state = WalletPersistState::default();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::Logs(batch) => {
                            if batch.to_block <= last_scanned {
                                continue;
                            }
                            debug!(
                                cache_key = %cfg.cache_key,
                                from_block = batch.from_block,
                                to_block = batch.to_block,
                                last_scanned,
                                logs = batch.logs.len(),
                                "applying wallet backfill logs"
                            );
                            match apply_wallet_logs(&cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, changed)) => {
                                    last_scanned = updated_last_scanned;
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let persisted_full_snapshot = match persist_wallet_progress(
                                        cache_store.as_ref(),
                                        WalletProgressPersist {
                                            cache_key: &cfg.cache_key,
                                            snapshot: &snapshot,
                                            last_scanned,
                                            last_scanned_block_hash: batch.to_block_hash,
                                            changed,
                                        },
                                        &mut persist_state,
                                    ) {
                                        Ok(persisted_full_snapshot) => persisted_full_snapshot,
                                        Err(err) => {
                                            warn!(?err, cache_key = %cfg.cache_key, "failed to persist wallet cache");
                                            false
                                        }
                                    };
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet backfill batch complete"
                                    );
                                    if changed {
                                        worker_handle.notify_changed();
                                    }
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to apply backfill logs");
                                }
                            }
                        }
                        BackfillEvent::Done { last_block } => {
                            let should_persist = last_scanned < last_block
                                || persist_state.needs_full_persist
                                || persist_state.pending_cache_reset.is_some();
                            if last_scanned < last_block {
                                last_scanned = last_block;
                            }
                            let snapshot = utxos.read().await;
                            if should_persist
                                && let Err(err) = persist_wallet_progress(
                                    cache_store.as_ref(),
                                    WalletProgressPersist {
                                        cache_key: &cfg.cache_key,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: None,
                                        changed: false,
                                    },
                                    &mut persist_state,
                                )
                            {
                                warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                            }
                            let (unspent, spent) = wallet_utxo_counts(&snapshot);
                            backfill_complete_block = Some(last_block);
                            if let Err(err) = ready_tx.send(true) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send ready state");
                            }
                            info!(
                                cache_key = %cfg.cache_key,
                                last_scanned,
                                total = snapshot.len(),
                                unspent,
                                spent,
                                "wallet backfill complete"
                            );
                        }
                        BackfillEvent::Reset { from_block } => {
                            let mut locked = utxos.write().await;
                            locked.clear();
                            last_scanned = from_block.saturating_sub(1);
                            match cache_store.reset_wallet_cache(&cfg.cache_key, last_scanned) {
                                Ok(()) => {
                                    persist_state.needs_full_persist = false;
                                    persist_state.pending_cache_reset = None;
                                }
                                Err(err) => {
                                    persist_state.needs_full_persist = true;
                                    persist_state.pending_cache_reset = Some(last_scanned);
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to reset wallet cache");
                                }
                            }
                            worker_handle.notify_changed();
                            backfill_complete_block = None;
                            if let Err(err) = ready_tx.send(false) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send ready state");
                            }
                            info!(cache_key = %cfg.cache_key, "wallet cache reset");
                        }
                    }
                }
                result = live_rx.recv() => {
                    match result {
                        Ok(batch) => {
                            if cfg.sync_to_block.is_some() {
                                continue;
                            }
                            if backfill_complete_block.is_none()
                                || batch.to_block <= last_scanned
                            {
                                continue;
                            }
                            match apply_wallet_logs(&cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, changed)) => {
                                    last_scanned = updated_last_scanned;
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let persisted_full_snapshot = match persist_wallet_progress(
                                        cache_store.as_ref(),
                                        WalletProgressPersist {
                                            cache_key: &cfg.cache_key,
                                            snapshot: &snapshot,
                                            last_scanned,
                                            last_scanned_block_hash: batch.to_block_hash,
                                            changed,
                                        },
                                        &mut persist_state,
                                    ) {
                                        Ok(persisted_full_snapshot) => persisted_full_snapshot,
                                        Err(err) => {
                                            warn!(?err, cache_key = %cfg.cache_key, "failed to persist wallet cache");
                                            false
                                        }
                                    };
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet live batch complete"
                                    );
                                    if changed {
                                        worker_handle.notify_changed();
                                    }
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to apply live logs");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!(cache_key = %cfg.cache_key, "wallet live log receiver lagged");
                        }
                    }
                }
            }
        }
    }.instrument(tracing::info_span!("wallet", chain_id)));

    handle
}

pub(crate) fn wallet_cache_store(
    db: &Arc<DbStore>,
    cfg: &WalletConfig,
) -> Arc<dyn WalletCacheStore> {
    cfg.cache_store
        .clone()
        .unwrap_or_else(|| Arc::clone(db) as Arc<dyn WalletCacheStore>)
}

fn dedupe_wallet_utxos(utxos: &mut Vec<WalletUtxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|wallet_utxo| seen.insert((wallet_utxo.utxo.tree, wallet_utxo.utxo.position)));
}

fn wallet_utxo_counts(utxos: &[WalletUtxo]) -> (usize, usize) {
    let spent = utxos.iter().filter(|utxo| utxo.is_spent()).count();
    (utxos.len().saturating_sub(spent), spent)
}

#[cfg(test)]
mod tests {
    use super::{
        WalletHandle, WalletPersistState, WalletProgressPersist, apply_wallet_delta_to_vec,
        notify_wallet_rev, persist_wallet_progress, spent_source_for_utxo,
    };
    use crate::types::{ChainKey, WalletCacheStore, WalletConfig};
    use alloy::primitives::{Address, FixedBytes, U256};
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use local_db::WalletMeta;
    use merkletree::wallet::{SpentNullifier, WalletLogDelta};
    use railgun_wallet::wallet_cache::WalletCacheError;
    use railgun_wallet::{Utxo, UtxoSource, WalletUtxo};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{RwLock, watch};

    fn source(byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number: u64::from(byte),
            block_timestamp: 1_700_000_000 + u64::from(byte),
        }
    }

    fn wallet_config(nullifying_key: U256) -> WalletConfig {
        WalletConfig {
            chain: ChainKey {
                chain_id: 1,
                contract: Address::ZERO,
            },
            cache_key: "test".to_string(),
            start_block: Some(0),
            sync_to_block: None,
            scan_keys: ViewingKeyData {
                viewing_private_key: [0u8; 32],
                viewing_public_key: [0u8; 32],
                nullifying_key,
                master_public_key: U256::ZERO,
            },
            progress_tx: None,
            cache_store: None,
            use_indexed_wallet_catch_up: true,
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct RecordingCacheState {
        store_calls: usize,
        meta_calls: usize,
        reset_calls: usize,
        fail_next_store: bool,
        fail_next_reset: bool,
    }

    #[derive(Default)]
    struct RecordingCacheStore {
        state: Mutex<RecordingCacheState>,
    }

    impl RecordingCacheStore {
        fn fail_next_store(&self) {
            self.state.lock().expect("cache state").fail_next_store = true;
        }

        fn fail_next_reset(&self) {
            self.state.lock().expect("cache state").fail_next_reset = true;
        }

        fn state(&self) -> RecordingCacheState {
            *self.state.lock().expect("cache state")
        }
    }

    impl WalletCacheStore for RecordingCacheStore {
        fn store_wallet_utxos(
            &self,
            _wallet_id: &str,
            _utxos: &[WalletUtxo],
            _last_scanned_block: Option<u64>,
            _last_scanned_block_hash: Option<[u8; 32]>,
        ) -> Result<(), WalletCacheError> {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
            Ok(())
        }

        fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
            Ok(Vec::new())
        }

        fn get_wallet_meta(
            &self,
            _wallet_id: &str,
        ) -> Result<Option<WalletMeta>, WalletCacheError> {
            Ok(None)
        }

        fn update_wallet_meta(
            &self,
            _wallet_id: &str,
            _last_scanned_block: u64,
            _last_scanned_block_hash: Option<[u8; 32]>,
        ) -> Result<(), WalletCacheError> {
            self.state.lock().expect("cache state").meta_calls += 1;
            Ok(())
        }

        fn reset_wallet_cache(
            &self,
            _wallet_id: &str,
            _last_scanned_block: u64,
        ) -> Result<(), WalletCacheError> {
            let mut state = self.state.lock().expect("cache state");
            state.reset_calls += 1;
            if state.fail_next_reset {
                state.fail_next_reset = false;
                return Err(WalletCacheError::Crypto);
            }
            Ok(())
        }
    }

    #[test]
    fn failed_full_persist_forces_next_no_change_batch_to_store_snapshot() {
        let cache_store = RecordingCacheStore::default();
        cache_store.fail_next_store();
        let snapshot = Vec::new();
        let mut persist_state = WalletPersistState::default();

        assert!(
            persist_wallet_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: true,
                },
                &mut persist_state,
            )
            .is_err()
        );
        assert!(persist_state.needs_full_persist);
        assert_eq!(cache_store.state().store_calls, 1);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_wallet_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 11,
                last_scanned_block_hash: None,
                changed: false,
            },
            &mut persist_state,
        )
        .expect("retry full persist");
        assert!(persisted_full_snapshot);
        assert!(!persist_state.needs_full_persist);
        assert_eq!(cache_store.state().store_calls, 2);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_wallet_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 12,
                last_scanned_block_hash: None,
                changed: false,
            },
            &mut persist_state,
        )
        .expect("metadata-only persist");
        assert!(!persisted_full_snapshot);
        assert_eq!(cache_store.state().store_calls, 2);
        assert_eq!(cache_store.state().meta_calls, 1);
    }

    #[test]
    fn pending_cache_reset_blocks_metadata_only_until_reset_succeeds() {
        let cache_store = RecordingCacheStore::default();
        cache_store.fail_next_reset();
        let snapshot = Vec::new();
        let mut persist_state = WalletPersistState {
            needs_full_persist: true,
            pending_cache_reset: Some(9),
        };

        assert!(
            persist_wallet_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: false,
                },
                &mut persist_state,
            )
            .is_err()
        );
        assert_eq!(persist_state.pending_cache_reset, Some(9));
        assert_eq!(cache_store.state().reset_calls, 1);
        assert_eq!(cache_store.state().store_calls, 0);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_wallet_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 10,
                last_scanned_block_hash: None,
                changed: false,
            },
            &mut persist_state,
        )
        .expect("reset then full persist");
        assert!(persisted_full_snapshot);
        assert_eq!(persist_state.pending_cache_reset, None);
        assert!(!persist_state.needs_full_persist);
        assert_eq!(cache_store.state().reset_calls, 2);
        assert_eq!(cache_store.state().store_calls, 1);
        assert_eq!(cache_store.state().meta_calls, 0);
    }

    #[test]
    fn notify_wallet_rev_increments_revision() {
        let (ready_tx, ready_rx) = watch::channel(false);
        drop(ready_tx);
        let (rev_tx, rev_rx) = watch::channel(0_u64);
        let handle = WalletHandle {
            cache_key: "cache-key".to_string(),
            utxos: Arc::new(RwLock::new(Vec::new())),
            ready_rx,
            rev_rx,
            rev_tx,
        };

        notify_wallet_rev(&handle);
        assert_eq!(*handle.rev_rx.borrow(), 1);

        notify_wallet_rev(&handle);
        assert_eq!(*handle.rev_rx.borrow(), 2);
    }

    #[test]
    fn spent_nullifiers_are_scoped_by_tree() {
        let nullifying_key = U256::from(42_u8);
        let utxo_tree_one = Utxo {
            note: Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            tree: 1,
            position: 7,
            source: source(1),
        };
        let utxo_tree_two = Utxo {
            note: utxo_tree_one.note.clone(),
            tree: 2,
            position: 7,
            source: source(2),
        };
        let shared_nullifier = utxo_tree_one.nullifier(nullifying_key);
        let spent_source = source(9);
        let nullifier_sources = HashMap::from([((2, shared_nullifier), spent_source.clone())]);

        assert_eq!(
            spent_source_for_utxo(&utxo_tree_one, nullifying_key, &nullifier_sources,),
            None,
        );
        assert_eq!(
            spent_source_for_utxo(&utxo_tree_two, nullifying_key, &nullifier_sources),
            Some(spent_source),
        );
    }

    #[test]
    fn indexed_delta_marks_matching_utxo_spent() {
        let nullifying_key = U256::from(42_u8);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo {
            note: Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            tree: 2,
            position: 7,
            source: source(1),
        };
        let spent_source = source(9);
        let nullifier = utxo.nullifier(nullifying_key);
        let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
        let delta = WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: 2,
                nullifier,
                source: spent_source.clone(),
            }],
        };

        let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

        assert!(changed);
        assert_eq!(wallet_utxos[0].spent, Some(spent_source));
    }

    #[test]
    fn indexed_delta_preserves_unmatched_utxo() {
        let nullifying_key = U256::from(42_u8);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo {
            note: Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            tree: 2,
            position: 7,
            source: source(1),
        };
        let nullifier = utxo.nullifier(nullifying_key);
        let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
        let delta = WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: 3,
                nullifier,
                source: source(9),
            }],
        };

        let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

        assert!(!changed);
        assert!(wallet_utxos[0].spent.is_none());
    }
}
