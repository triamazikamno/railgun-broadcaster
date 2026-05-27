pub const WALLET_POI_STATUS_BATCH_SIZE: usize = 1000;
pub const WALLET_POI_RECOVERABLE_REFRESH_AFTER: Duration = Duration::from_secs(60);
pub(super) const WALLET_POI_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
pub(super) const WALLET_POI_LIVE_TAIL_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const WALLET_METADATA_LIVE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const WALLET_METADATA_LIVE_FLUSH_BLOCKS: u64 = 25;
pub(super) const LOCAL_PENDING_SPENT_TTL: Duration = Duration::from_secs(10 * 60);
pub(super) const OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER: Duration = Duration::from_secs(10 * 60);
pub(super) const OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER: Duration =
    Duration::from_secs(24 * 60 * 60);
pub(super) const OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER: Duration =
    Duration::from_secs(24 * 60 * 60);
pub(super) const PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
pub(super) const OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES: u64 = 128;
pub(super) const OUTPUT_POI_RECOVERY_TXID_GRAPH_PAGE_SIZE: usize = 10_000;
pub(super) const OUTPUT_POI_RECOVERY_VERIFY_PROOF: bool = true;
pub(super) const OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER: Duration = Duration::from_secs(5);
pub(super) const EVM_CHAIN_TYPE: u8 = 0;

#[derive(Debug, Clone, Copy)]
pub(super) enum WalletPoiRefreshSelection {
    Required,
    RequiredOrRecoverable,
    RecoverableStale { now: u64 },
    Recoverable,
}

impl WalletPoiRefreshSelection {
    pub(super) const fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RequiredOrRecoverable => "required_or_recoverable",
            Self::RecoverableStale { .. } => "recoverable_stale",
            Self::Recoverable => "recoverable",
        }
    }

    pub(super) fn matches_wallet_utxo(
        self,
        wallet_utxo: &WalletUtxo,
        active_list_keys: &[FixedBytes<32>],
    ) -> bool {
        match self {
            Self::Required => {
                wallet_utxo.utxo.poi.refreshed_at.is_none()
                    || active_list_keys
                        .iter()
                        .any(|list_key| !wallet_utxo.utxo.poi.statuses.contains_key(list_key))
            }
            Self::RequiredOrRecoverable => {
                Self::Required.matches_wallet_utxo(wallet_utxo, active_list_keys)
                    || wallet_utxo
                        .utxo
                        .poi
                        .has_recoverable_status_for_lists(active_list_keys)
            }
            Self::Recoverable => wallet_utxo
                .utxo
                .poi
                .has_recoverable_status_for_lists(active_list_keys),
            Self::RecoverableStale { now } => {
                wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
                    && wallet_utxo
                        .utxo
                        .poi
                        .refreshed_at
                        .is_none_or(|refreshed_at| {
                            now.saturating_sub(refreshed_at)
                                >= WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs()
                        })
            }
        }
    }
}

use super::*;

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub pending_overlay: Arc<RwLock<WalletPendingOverlay>>,
    pub(super) last_scanned: Arc<AtomicU64>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    pub(super) poi_read_source: PoiReadSource,
    pub(super) local_poi_caches: Option<WalletLocalPoiCaches>,
    pub(super) poi_refresh_tx: mpsc::Sender<WalletPoiRefreshRequest>,
    pub(super) rev_tx: watch::Sender<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct WalletPendingOverlay {
    pub new_utxos: Vec<WalletUtxo>,
    pub pending_spent: Vec<WalletPendingSpent>,
    pub local_pending_spent: Vec<WalletPendingSpent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPendingSpent {
    pub tree: u32,
    pub position: u64,
    pub tx_hash: Option<FixedBytes<32>>,
    pub block_number: Option<u64>,
    pub block_timestamp: Option<u64>,
}

impl WalletPendingSpent {
    #[must_use]
    pub const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }

    pub(super) fn from_source(utxo: &Utxo, source: UtxoSource) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash: Some(source.tx_hash),
            block_number: Some(source.block_number),
            block_timestamp: Some(source.block_timestamp),
        }
    }

    pub(super) fn submitted(utxo: &Utxo, tx_hash: Option<FixedBytes<32>>, now: u64) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash,
            block_number: None,
            block_timestamp: Some(now),
        }
    }
}

impl WalletHandle {
    #[must_use]
    pub fn last_scanned(&self) -> u64 {
        self.last_scanned.load(Ordering::Relaxed)
    }

    pub(super) fn set_last_scanned(&self, block: u64) {
        self.last_scanned.store(block, Ordering::Relaxed);
    }

    pub async fn pending_overlay(&self) -> WalletPendingOverlay {
        self.pending_overlay.read().await.clone()
    }

    pub async fn clear_local_pending_spent(&self) -> bool {
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let changed = !overlay.local_pending_spent.is_empty();
            overlay.local_pending_spent.clear();
            changed
        };
        self.notify_if_changed(changed);
        changed
    }

    pub async fn mark_pending_spent_utxos(&self, utxos: &[Utxo], tx_hash: Option<FixedBytes<32>>) {
        if utxos.is_empty() {
            return;
        }
        let now = now_epoch_secs();
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let chain_pending: HashSet<_> = overlay
                .pending_spent
                .iter()
                .map(WalletPendingSpent::key)
                .collect();
            let mut existing: HashSet<_> = overlay
                .local_pending_spent
                .iter()
                .map(WalletPendingSpent::key)
                .collect();
            let before = overlay.local_pending_spent.len();
            let mut updated_existing = false;
            for utxo in utxos {
                let key = (utxo.tree, utxo.position);
                if chain_pending.contains(&key) {
                    continue;
                }
                if existing.insert(key) {
                    overlay
                        .local_pending_spent
                        .push(WalletPendingSpent::submitted(utxo, tx_hash, now));
                } else if let Some(spent) = overlay
                    .local_pending_spent
                    .iter_mut()
                    .find(|spent| spent.key() == key)
                    && spent.tx_hash != tx_hash
                {
                    spent.tx_hash = tx_hash;
                    spent.block_timestamp = Some(now);
                    updated_existing = true;
                }
            }
            overlay
                .local_pending_spent
                .sort_by_key(WalletPendingSpent::key);
            overlay.local_pending_spent.len() != before || updated_existing
        };
        self.notify_if_changed(changed);
    }

    pub(crate) async fn set_chain_pending_overlay(&self, next: WalletPendingOverlay) {
        let now = now_epoch_secs();
        let confirmed_spent: HashSet<_> = {
            let utxos = self.utxos.read().await;
            utxos
                .iter()
                .filter(|utxo| utxo.is_spent())
                .map(|utxo| (utxo.utxo.tree, utxo.utxo.position))
                .collect()
        };
        let chain_pending_spent: HashSet<_> = next
            .pending_spent
            .iter()
            .map(WalletPendingSpent::key)
            .collect();
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let chain_changed = !chain_pending_overlay_matches(&overlay, &next);
            let before_local = overlay.local_pending_spent.len();
            overlay.local_pending_spent.retain(|spent| {
                let key = spent.key();
                if confirmed_spent.contains(&key) || chain_pending_spent.contains(&key) {
                    return false;
                }
                let submitted_at = spent.block_timestamp.unwrap_or(now);
                now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
            });
            let local_changed = overlay.local_pending_spent.len() != before_local;
            overlay.new_utxos = next.new_utxos;
            overlay.pending_spent = next.pending_spent;
            chain_changed || local_changed
        };
        self.notify_if_changed(changed);
    }

    pub async fn refresh_poi_statuses(&self) -> bool {
        self.poi_refresh_tx
            .send(WalletPoiRefreshRequest {
                force_output_poi_recovery: true,
            })
            .await
            .is_ok()
    }

    #[must_use]
    pub const fn poi_read_source(&self) -> &PoiReadSource {
        &self.poi_read_source
    }

    #[must_use]
    pub fn local_poi_caches(&self) -> Option<WalletLocalPoiCaches> {
        self.local_poi_caches.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WalletPoiRefreshRequest {
    pub(super) force_output_poi_recovery: bool,
}
