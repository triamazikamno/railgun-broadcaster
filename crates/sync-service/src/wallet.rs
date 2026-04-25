use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::DbStore;
use merkletree::wallet::{WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs};
use railgun_wallet::Utxo;
use railgun_wallet::wallet_cache::WalletCacheDbExt;

use crate::types::{BackfillEvent, SharedLogBatch, WalletConfig};

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub unspents: Arc<RwLock<Vec<Utxo>>>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
}

async fn apply_wallet_logs(
    cfg: &WalletConfig,
    unspents: &Arc<RwLock<Vec<Utxo>>>,
    batch: &SharedLogBatch,
    last_scanned: u64,
) -> Result<u64, WalletScanError> {
    let filtered_logs: Vec<_> = batch
        .logs
        .iter()
        .filter(|log| log.block_number.unwrap_or_default() > last_scanned)
        .cloned()
        .collect();

    let WalletLogDelta {
        mut utxos,
        nullifiers,
    } = if filtered_logs.is_empty() {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
        }
    } else {
        parse_wallet_delta_from_logs(&filtered_logs, &cfg.scan_keys)?
    };

    let mut locked = unspents.write().await;
    if !nullifiers.is_empty() {
        let nullifier_set: HashSet<_> = nullifiers.into_iter().collect();
        locked.retain(|utxo| {
            !utxo_spent_by_nullifier(utxo, cfg.scan_keys.nullifying_key, &nullifier_set)
        });
        utxos.retain(|utxo| {
            !utxo_spent_by_nullifier(utxo, cfg.scan_keys.nullifying_key, &nullifier_set)
        });
    }
    locked.append(&mut utxos);
    dedupe_utxos(&mut locked);

    Ok(batch.to_block)
}

fn utxo_spent_by_nullifier(
    utxo: &Utxo,
    nullifying_key: alloy::primitives::U256,
    nullifier_set: &HashSet<(u32, alloy::primitives::U256)>,
) -> bool {
    nullifier_set.contains(&(utxo.tree, utxo.nullifier(nullifying_key)))
}

impl WalletHandle {
    pub async fn wait_until_ready(&mut self) {
        while !*self.ready_rx.borrow() {
            if self.ready_rx.changed().await.is_err() {
                break;
            }
        }
    }
}

fn notify_wallet_rev(rev_tx: &watch::Sender<u64>, rev: &mut u64, cache_key: &str) {
    *rev = rev.wrapping_add(1);
    if let Err(err) = rev_tx.send(*rev) {
        debug!(?err, cache_key, "failed to send wallet revision");
    }
}

pub(crate) fn spawn_wallet_worker(
    db: Arc<DbStore>,
    cfg: WalletConfig,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
) -> WalletHandle {
    let unspents = Arc::new(RwLock::new(Vec::new()));
    let (ready_tx, ready_rx) = watch::channel(false);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        unspents: unspents.clone(),
        ready_rx,
        rev_rx,
    };

    let chain_id = cfg.chain.chain_id;
    tokio::spawn(async move {
        let mut rev = 0_u64;
        let start_block = cfg.start_block.unwrap_or(0);
        let mut last_scanned = start_block.saturating_sub(1);

        match db.load_unspent_utxos(&cfg.cache_key) {
            Ok(cached) => {
                let mut locked = unspents.write().await;
                *locked = cached;
                notify_wallet_rev(&rev_tx, &mut rev, &cfg.cache_key);
            }
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to load wallet cache");
            }
        }

        if let Ok(Some(meta)) = db.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }
        if last_scanned < start_block {
            last_scanned = start_block.saturating_sub(1);
        }

        let mut backfill_complete_block: Option<u64> = None;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::Logs(batch) => {
                            if batch.to_block <= last_scanned {
                                continue;
                            }
                            match apply_wallet_logs(&cfg, &unspents, &batch, last_scanned).await {
                                Ok(updated_last_scanned) => {
                                    last_scanned = updated_last_scanned;
                                    if let Err(err) = db.store_unspent_utxos(
                                        &cfg.cache_key,
                                        &unspents.read().await,
                                        Some(last_scanned),
                                        batch.to_block_hash,
                                    ) {
                                        warn!(?err, cache_key = %cfg.cache_key, "failed to persist wallet cache");
                                    }
                                    notify_wallet_rev(&rev_tx, &mut rev, &cfg.cache_key);
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to apply backfill logs");
                                }
                            }
                        }
                        BackfillEvent::Done { last_block } => {
                            if last_scanned < last_block {
                                last_scanned = last_block;
                                if let Err(err) = db.store_unspent_utxos(
                                    &cfg.cache_key,
                                    &unspents.read().await,
                                    Some(last_scanned),
                                    None,
                                ) {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                                }
                            }
                            backfill_complete_block = Some(last_block);
                            if let Err(err) = ready_tx.send(true) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send ready state");
                            }
                            debug!(cache_key = %cfg.cache_key, "wallet backfill complete");
                        }
                        BackfillEvent::Reset { from_block } => {
                            let mut locked = unspents.write().await;
                            locked.clear();
                            last_scanned = from_block.saturating_sub(1);
                            if let Err(err) = db.store_unspent_utxos(
                                &cfg.cache_key,
                                &locked,
                                Some(last_scanned),
                                None,
                            ) {
                                warn!(?err, cache_key = %cfg.cache_key, "failed to reset wallet cache");
                            }
                            notify_wallet_rev(&rev_tx, &mut rev, &cfg.cache_key);
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
                            if backfill_complete_block.is_none()
                                || batch.to_block <= last_scanned
                            {
                                continue;
                            }
                            match apply_wallet_logs(&cfg, &unspents, &batch, last_scanned).await {
                                Ok(updated_last_scanned) => {
                                    last_scanned = updated_last_scanned;
                                    if let Err(err) = db.store_unspent_utxos(
                                        &cfg.cache_key,
                                        &unspents.read().await,
                                        Some(last_scanned),
                                        batch.to_block_hash,
                                    ) {
                                        warn!(?err, cache_key = %cfg.cache_key, "failed to persist wallet cache");
                                    }
                                    notify_wallet_rev(&rev_tx, &mut rev, &cfg.cache_key);
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

fn dedupe_utxos(utxos: &mut Vec<Utxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|utxo| seen.insert((utxo.tree, utxo.position)));
}

#[cfg(test)]
mod tests {
    use super::{notify_wallet_rev, utxo_spent_by_nullifier};
    use alloy::primitives::U256;
    use broadcaster_core::notes::Note;
    use railgun_wallet::Utxo;
    use std::collections::HashSet;
    use tokio::sync::watch;

    #[test]
    fn notify_wallet_rev_increments_revision() {
        let (tx, rx) = watch::channel(0_u64);
        let mut rev = 0_u64;

        notify_wallet_rev(&tx, &mut rev, "cache-key");
        assert_eq!(*rx.borrow(), 1);

        notify_wallet_rev(&tx, &mut rev, "cache-key");
        assert_eq!(*rx.borrow(), 2);
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
        };
        let utxo_tree_two = Utxo {
            note: utxo_tree_one.note.clone(),
            tree: 2,
            position: 7,
        };
        let shared_nullifier = utxo_tree_one.nullifier(nullifying_key);
        let nullifier_set = HashSet::from([(2, shared_nullifier)]);

        assert!(!utxo_spent_by_nullifier(
            &utxo_tree_one,
            nullifying_key,
            &nullifier_set,
        ));
        assert!(utxo_spent_by_nullifier(
            &utxo_tree_two,
            nullifying_key,
            &nullifier_set,
        ));
    }
}
