use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::DbStore;
use merkletree::wallet::{WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs};
use railgun_wallet::wallet_cache::WalletCacheDbExt;
use railgun_wallet::{Utxo, UtxoSource, WalletUtxo};

use crate::types::{BackfillEvent, SharedLogBatch, WalletConfig};

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
}

async fn apply_wallet_logs(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
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
        utxos: new_utxos,
        nullifiers,
    } = if filtered_logs.is_empty() {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
        }
    } else {
        parse_wallet_delta_from_logs(&filtered_logs, &cfg.scan_keys)?
    };

    apply_wallet_delta(
        cfg,
        wallet_utxos,
        WalletLogDelta {
            utxos: new_utxos,
            nullifiers,
        },
    )
    .await;

    Ok(batch.to_block)
}

pub(crate) async fn apply_wallet_delta(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    delta: WalletLogDelta,
) {
    let mut locked = wallet_utxos.write().await;
    apply_wallet_delta_to_vec(cfg, &mut locked, delta);
}

pub(crate) fn apply_wallet_delta_to_vec(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) {
    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();
    if !nullifier_sources.is_empty() {
        for wallet_utxo in wallet_utxos.iter_mut().filter(|entry| !entry.is_spent()) {
            if let Some(source) = spent_source_for_utxo(
                &wallet_utxo.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            ) {
                wallet_utxo.spent = Some(source);
            }
        }
    }
    wallet_utxos.extend(new_utxos.into_iter().map(|utxo| {
        let spent = spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
        WalletUtxo { utxo, spent }
    }));
    dedupe_wallet_utxos(wallet_utxos);
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
    let utxos = Arc::new(RwLock::new(Vec::new()));
    let (ready_tx, ready_rx) = watch::channel(false);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        utxos: utxos.clone(),
        ready_rx,
        rev_rx,
    };

    let chain_id = cfg.chain.chain_id;
    tokio::spawn(async move {
        let mut rev = 0_u64;
        let start_block = cfg.start_block.unwrap_or(0);
        let mut last_scanned = start_block.saturating_sub(1);

        match db.load_wallet_utxos(&cfg.cache_key) {
            Ok(cached) => {
                let mut locked = utxos.write().await;
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
                            match apply_wallet_logs(&cfg, &utxos, &batch, last_scanned).await {
                                Ok(updated_last_scanned) => {
                                    last_scanned = updated_last_scanned;
                                    if let Err(err) = db.store_wallet_utxos(
                                        &cfg.cache_key,
                                        &utxos.read().await,
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
                                if let Err(err) = db.store_wallet_utxos(
                                    &cfg.cache_key,
                                    &utxos.read().await,
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
                            let mut locked = utxos.write().await;
                            locked.clear();
                            last_scanned = from_block.saturating_sub(1);
                            if let Err(err) = db.store_wallet_utxos(
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
                            match apply_wallet_logs(&cfg, &utxos, &batch, last_scanned).await {
                                Ok(updated_last_scanned) => {
                                    last_scanned = updated_last_scanned;
                                    if let Err(err) = db.store_wallet_utxos(
                                        &cfg.cache_key,
                                        &utxos.read().await,
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

fn dedupe_wallet_utxos(utxos: &mut Vec<WalletUtxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|wallet_utxo| seen.insert((wallet_utxo.utxo.tree, wallet_utxo.utxo.position)));
}

#[cfg(test)]
mod tests {
    use super::{apply_wallet_delta_to_vec, notify_wallet_rev, spent_source_for_utxo};
    use crate::types::{ChainKey, WalletConfig};
    use alloy::primitives::{Address, FixedBytes, U256};
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use merkletree::wallet::{SpentNullifier, WalletLogDelta};
    use railgun_wallet::{Utxo, UtxoSource, WalletUtxo};
    use std::collections::HashMap;
    use tokio::sync::watch;

    fn source(byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number: u64::from(byte),
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
            scan_keys: ViewingKeyData {
                viewing_private_key: [0u8; 32],
                viewing_public_key: [0u8; 32],
                nullifying_key,
                master_public_key: U256::ZERO,
            },
            progress_tx: None,
        }
    }

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

        apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

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

        apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

        assert!(wallet_utxos[0].spent.is_none());
    }
}
