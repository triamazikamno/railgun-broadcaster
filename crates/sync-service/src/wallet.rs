use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{FixedBytes, U256};
use async_trait::async_trait;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::{DbStore, PendingOutputPoiContextRecord, PendingOutputPoiObservation};
use merkletree::wallet::{
    CommitmentObservation, WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs,
};
use poi::error::PoiError;
use poi::poi::{
    BlindedCommitmentData, BlindedCommitmentType, DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient,
    SingleCommitmentProofContext, default_active_poi_list_keys,
};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
use url::Url;

use crate::types::{BackfillEvent, SharedLogBatch, WalletCacheStore, WalletConfig};

pub const WALLET_POI_STATUS_BATCH_SIZE: usize = 1000;
const EVM_CHAIN_TYPE: u8 = 0;

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
    rev_tx: watch::Sender<u64>,
}

#[async_trait]
pub(crate) trait PoiStatusReader: Send + Sync {
    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError>;
}

#[async_trait]
impl PoiStatusReader for PoiRpcClient {
    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        PoiRpcClient::pois_per_list(
            self,
            txid_version,
            chain_type,
            chain_id,
            list_keys,
            blinded_commitment_datas,
        )
        .await
    }
}

#[async_trait]
pub(crate) trait PendingOutputPoiSubmitter: Send + Sync {
    async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError>;
}

#[async_trait]
impl PendingOutputPoiSubmitter for PoiRpcClient {
    async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        PoiRpcClient::submit_single_commitment_proofs(
            self,
            txid_version,
            chain_type,
            chain_id,
            context,
            utxo_tree_out,
            utxo_position_out,
        )
        .await?;
        Ok(())
    }
}

async fn apply_wallet_logs(
    db: &DbStore,
    poi_submitter: Option<&dyn PendingOutputPoiSubmitter>,
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
        commitment_observations,
    } = if filtered_logs.is_empty() {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
        }
    } else {
        parse_wallet_delta_from_logs(&filtered_logs, &batch.block_timestamps, &cfg.scan_keys)?
    };

    process_pending_output_poi_observations(
        db,
        cfg.chain.chain_id,
        &commitment_observations,
        poi_submitter,
    )
    .await;

    let changed = apply_wallet_delta(
        cfg,
        wallet_utxos,
        WalletLogDelta {
            utxos: new_utxos,
            nullifiers,
            commitment_observations,
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
        ..
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

pub(crate) async fn process_pending_output_poi_observations(
    db: &DbStore,
    chain_id: u64,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
) {
    for observation in observations {
        if let Err(err) = record_pending_output_poi_observation(db, chain_id, observation) {
            warn!(
                ?err,
                chain_id,
                commitment = %hex_fixed(&u256_to_fixed(observation.commitment)),
                "failed to record pending output POI observation"
            );
        }
    }

    let Some(submitter) = submitter else {
        return;
    };
    if let Err(err) = submit_observed_pending_output_pois(db, chain_id, submitter).await {
        warn!(
            ?err,
            chain_id, "failed to submit observed pending output POI contexts"
        );
    }
}

fn record_pending_output_poi_observation(
    db: &DbStore,
    chain_id: u64,
    observation: &CommitmentObservation,
) -> Result<(), local_db::DbError> {
    let output_commitment = u256_to_fixed(observation.commitment);
    let Some(mut record) = db.get_pending_output_poi_context(chain_id, &output_commitment)? else {
        return Ok(());
    };
    let observed = PendingOutputPoiObservation {
        output_tree: u64::from(observation.tree),
        output_position: observation.position,
        tx_hash: observation.source.tx_hash,
        block_number: observation.source.block_number,
        block_timestamp: observation.source.block_timestamp,
    };
    if record.observation.as_ref() != Some(&observed) {
        record.observation = Some(observed);
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(())
}

async fn submit_observed_pending_output_pois(
    db: &DbStore,
    chain_id: u64,
    submitter: &dyn PendingOutputPoiSubmitter,
) -> Result<(), local_db::DbError> {
    let records = db.list_pending_output_poi_contexts(chain_id)?;
    for mut record in records {
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        if record.terminal_error.is_some() {
            continue;
        }
        let missing_list_keys = missing_pending_output_poi_list_keys(&record);
        if missing_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = retain_pending_output_poi_lists(&record, &missing_list_keys);
        if pre_transaction_pois.len() != missing_list_keys.len() {
            record.terminal_error =
                Some("missing pre-transaction POI for pending output".to_string());
            db.put_pending_output_poi_context(&record)?;
            continue;
        }
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        };
        match submitter
            .submit_single_commitment_proofs(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                &context,
                observation.output_tree,
                observation.output_position,
            )
            .await
        {
            Ok(()) => {
                for list_key in missing_list_keys {
                    if !record.submitted_poi_list_keys.contains(&list_key) {
                        record.submitted_poi_list_keys.push(list_key);
                    }
                }
                db.put_pending_output_poi_context(&record)?;
            }
            Err(err) => {
                warn!(
                    ?err,
                    chain_id,
                    commitment = %hex_fixed(&record.output_commitment),
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(())
}

fn missing_pending_output_poi_list_keys(
    record: &PendingOutputPoiContextRecord,
) -> Vec<FixedBytes<32>> {
    let list_keys: Vec<_> = if record.required_poi_list_keys.is_empty() {
        record
            .pre_transaction_pois_per_txid_leaf_per_list
            .keys()
            .copied()
            .collect()
    } else {
        record.required_poi_list_keys.clone()
    };
    list_keys
        .into_iter()
        .filter(|list_key| !record.submitted_poi_list_keys.contains(list_key))
        .collect()
}

fn retain_pending_output_poi_lists(
    record: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, broadcaster_core::transact::PreTxPoi>> {
    list_keys
        .iter()
        .filter_map(|list_key| {
            record
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
                .cloned()
                .map(|per_leaf| (*list_key, per_leaf))
        })
        .collect()
}

fn u256_to_fixed(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

fn hex_fixed(value: &FixedBytes<32>) -> String {
    alloy::hex::encode(value)
}

pub(crate) async fn refresh_wallet_poi_statuses(
    client: &dyn PoiStatusReader,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    wallet_utxos: &mut [WalletUtxo],
) -> bool {
    if active_list_keys.is_empty() {
        return false;
    }

    let unspent: Vec<_> = wallet_utxos
        .iter()
        .enumerate()
        .filter(|(_, wallet_utxo)| !wallet_utxo.is_spent())
        .map(|(index, wallet_utxo)| {
            (
                index,
                BlindedCommitmentData::new(
                    wallet_utxo.utxo.poi.blinded_commitment,
                    blinded_commitment_type(wallet_utxo.utxo.poi.commitment_kind),
                ),
            )
        })
        .collect();

    let mut changed = false;
    for chunk in unspent.chunks(WALLET_POI_STATUS_BATCH_SIZE) {
        let request_data: Vec<_> = chunk.iter().map(|(_, data)| *data).collect();
        match client
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                chain_id,
                active_list_keys,
                &request_data,
            )
            .await
        {
            Ok(statuses_by_blinded_commitment) => {
                let refreshed_at = now_epoch_secs();
                for (index, data) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    if apply_poi_statuses(
                        wallet_utxo,
                        active_list_keys,
                        statuses_by_blinded_commitment.get(&data.blinded_commitment),
                        refreshed_at,
                    ) {
                        changed = true;
                    }
                }
            }
            Err(error) => {
                warn!(
                    ?error,
                    chain_id,
                    commitments = chunk.len(),
                    "wallet POI status chunk failed; leaving statuses unknown"
                );
                for (index, _) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    if apply_unknown_poi_statuses(wallet_utxo, active_list_keys) {
                        changed = true;
                    }
                }
            }
        }
    }
    changed
}

pub(crate) fn wallet_poi_status_refresh_needed(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    !active_list_keys.is_empty()
        && wallet_utxos.iter().any(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && (wallet_utxo.utxo.poi.refreshed_at.is_none()
                    || active_list_keys
                        .iter()
                        .any(|list_key| !wallet_utxo.utxo.poi.statuses.contains_key(list_key)))
        })
}

fn apply_poi_statuses(
    wallet_utxo: &mut WalletUtxo,
    active_list_keys: &[FixedBytes<32>],
    statuses: Option<&BTreeMap<FixedBytes<32>, PoiStatus>>,
    refreshed_at: u64,
) -> bool {
    let mut changed = false;
    for list_key in active_list_keys {
        let status = statuses
            .and_then(|per_list| per_list.get(list_key))
            .copied()
            .unwrap_or(PoiStatus::Missing);
        if wallet_utxo.utxo.poi.statuses.insert(*list_key, status) != Some(status) {
            changed = true;
        }
    }
    if wallet_utxo.utxo.poi.refreshed_at != Some(refreshed_at) {
        wallet_utxo.utxo.poi.refreshed_at = Some(refreshed_at);
        changed = true;
    }
    changed
}

fn apply_unknown_poi_statuses(
    wallet_utxo: &mut WalletUtxo,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    let mut changed = false;
    for list_key in active_list_keys {
        if wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(*list_key, PoiStatus::Unknown)
            != Some(PoiStatus::Unknown)
        {
            changed = true;
        }
    }
    changed
}

fn blinded_commitment_type(kind: UtxoCommitmentKind) -> BlindedCommitmentType {
    match kind {
        UtxoCommitmentKind::Shield => BlindedCommitmentType::Shield,
        UtxoCommitmentKind::Transact => BlindedCommitmentType::Transact,
    }
}

pub(crate) fn wallet_poi_status_client() -> Option<PoiRpcClient> {
    let url = Url::parse(DEFAULT_WALLET_POI_RPC_URL).ok()?;
    Some(PoiRpcClient::new(url))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
        let poi_status_client = wallet_poi_status_client();
        let active_poi_list_keys = default_active_poi_list_keys();

        if let Some(client) = poi_status_client.as_ref() {
            let mut locked = utxos.write().await;
            if wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys)
                && refresh_wallet_poi_statuses(
                    client,
                    cfg.chain.chain_id,
                    &active_poi_list_keys,
                    &mut locked,
                )
                .await
            {
                let (unspent, spent) = wallet_utxo_counts(&locked);
                let persisted_full_snapshot = match persist_wallet_progress(
                    cache_store.as_ref(),
                    WalletProgressPersist {
                        cache_key: &cfg.cache_key,
                        snapshot: &locked,
                        last_scanned,
                        last_scanned_block_hash: None,
                        changed: true,
                    },
                    &mut persist_state,
                ) {
                    Ok(persisted_full_snapshot) => persisted_full_snapshot,
                    Err(err) => {
                        warn!(?err, cache_key = %cfg.cache_key, "failed to persist wallet POI status refresh");
                        false
                    }
                };
                info!(
                    cache_key = %cfg.cache_key,
                    total = locked.len(),
                    unspent,
                    spent,
                    persisted_full_snapshot,
                    "wallet POI status refresh complete"
                );
                worker_handle.notify_changed();
            }
        }

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
                            let poi_submitter = poi_status_client
                                .as_ref()
                                .map(|client| client as &dyn PendingOutputPoiSubmitter);
                            match apply_wallet_logs(db.as_ref(), poi_submitter, &cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, mut changed)) => {
                                    last_scanned = updated_last_scanned;
                                    if changed
                                        && let Some(client) = poi_status_client.as_ref()
                                    {
                                        let mut locked = utxos.write().await;
                                        changed |= refresh_wallet_poi_statuses(
                                            client,
                                            cfg.chain.chain_id,
                                            &active_poi_list_keys,
                                            &mut locked,
                                        ).await;
                                    }
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
                            let poi_submitter = poi_status_client
                                .as_ref()
                                .map(|client| client as &dyn PendingOutputPoiSubmitter);
                            match apply_wallet_logs(db.as_ref(), poi_submitter, &cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, mut changed)) => {
                                    last_scanned = updated_last_scanned;
                                    if changed
                                        && let Some(client) = poi_status_client.as_ref()
                                    {
                                        let mut locked = utxos.write().await;
                                        changed |= refresh_wallet_poi_statuses(
                                            client,
                                            cfg.chain.chain_id,
                                            &active_poi_list_keys,
                                            &mut locked,
                                        ).await;
                                    }
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
        DEFAULT_TXID_VERSION, PendingOutputPoiSubmitter, PoiStatusReader,
        WALLET_POI_STATUS_BATCH_SIZE, WalletHandle, WalletPersistState, WalletProgressPersist,
        apply_wallet_delta_to_vec, notify_wallet_rev, persist_wallet_progress,
        process_pending_output_poi_observations, refresh_wallet_poi_statuses,
        spent_source_for_utxo, wallet_poi_status_refresh_needed,
    };
    use crate::types::{ChainKey, WalletCacheStore, WalletConfig};
    use alloy::primitives::{Address, Bytes, FixedBytes, U256};
    use async_trait::async_trait;
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use broadcaster_core::transact::{PreTxPoi, SnarkJsProof};
    use local_db::{
        DbConfig, DbStore, PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletMeta,
    };
    use merkletree::wallet::{CommitmentObservation, SpentNullifier, WalletLogDelta};
    use poi::error::PoiError;
    use poi::poi::{BlindedCommitmentData, SingleCommitmentProofContext};
    use railgun_wallet::wallet_cache::WalletCacheError;
    use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::{RwLock, watch};

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-sync-service-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

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

    fn test_wallet_utxo(position: u64) -> WalletUtxo {
        WalletUtxo::new(Utxo::new(
            Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            2,
            position,
            source((position % 200) as u8 + 1),
            UtxoCommitmentKind::Transact,
        ))
    }

    #[derive(Default)]
    struct RecordingPoiStatusClient {
        calls: Mutex<Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)>>,
        fail_calls: Mutex<HashSet<usize>>,
    }

    impl RecordingPoiStatusClient {
        fn fail_call(&self, call_index: usize) {
            self.fail_calls
                .lock()
                .expect("fail calls")
                .insert(call_index);
        }

        fn calls(&self) -> Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)> {
            self.calls.lock().expect("poi calls").clone()
        }
    }

    #[async_trait]
    impl PoiStatusReader for RecordingPoiStatusClient {
        async fn pois_per_list(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            list_keys: &[FixedBytes<32>],
            blinded_commitment_datas: &[BlindedCommitmentData],
        ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError>
        {
            let call_index = {
                let mut calls = self.calls.lock().expect("poi calls");
                let call_index = calls.len();
                calls.push((list_keys.to_vec(), blinded_commitment_datas.to_vec()));
                call_index
            };
            if self
                .fail_calls
                .lock()
                .expect("fail calls")
                .contains(&call_index)
            {
                return Err(PoiError::MerkleRootsRejected);
            }
            Ok(blinded_commitment_datas
                .iter()
                .map(|data| {
                    (
                        data.blinded_commitment,
                        list_keys
                            .iter()
                            .copied()
                            .map(|list_key| (list_key, PoiStatus::Valid))
                            .collect(),
                    )
                })
                .collect())
        }
    }

    #[derive(Default)]
    struct RecordingPendingOutputPoiSubmitter {
        calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
        fail_next: Mutex<bool>,
    }

    impl RecordingPendingOutputPoiSubmitter {
        fn fail_next(&self) {
            *self.fail_next.lock().expect("fail next") = true;
        }

        fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
            self.calls.lock().expect("submission calls").clone()
        }
    }

    #[async_trait]
    impl PendingOutputPoiSubmitter for RecordingPendingOutputPoiSubmitter {
        async fn submit_single_commitment_proofs(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            context: &SingleCommitmentProofContext,
            utxo_tree_out: u64,
            utxo_position_out: u64,
        ) -> Result<(), PoiError> {
            self.calls.lock().expect("submission calls").push((
                context.commitment,
                utxo_tree_out,
                utxo_position_out,
            ));
            let mut fail_next = self.fail_next.lock().expect("fail next");
            if *fail_next {
                *fail_next = false;
                return Err(PoiError::MerkleRootsRejected);
            }
            Ok(())
        }
    }

    fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
        PreTxPoi {
            snark_proof: SnarkJsProof {
                pi_a: [U256::from(byte), U256::from(byte + 1)],
                pi_b: [
                    [U256::from(byte + 2), U256::from(byte + 3)],
                    [U256::from(byte + 4), U256::from(byte + 5)],
                ],
                pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
            },
            txid_merkleroot: FixedBytes::from([byte; 32]),
            poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
            blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
            railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
        }
    }

    fn pending_output_record(
        chain_id: u64,
        output_commitment: FixedBytes<32>,
        list_key: FixedBytes<32>,
    ) -> PendingOutputPoiContextRecord {
        let txid_leaf = FixedBytes::from([0x55; 32]);
        PendingOutputPoiContextRecord {
            chain_id,
            wallet_id: "wallet-1".to_string(),
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            output_commitment,
            output_npk: FixedBytes::from([0x66; 32]),
            utxo_tree_in: 9,
            railgun_txid: U256::from(7_u8),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
                list_key,
                BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))]),
            )]),
            required_poi_list_keys: vec![list_key],
            output_role: PendingOutputPoiRole::Recipient,
            created_at: 123,
            source_operation_id: None,
            observation: None,
            submitted_poi_list_keys: Vec::new(),
            terminal_error: None,
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

    #[tokio::test]
    async fn poi_status_refresh_chunks_unspent_utxos() {
        let client = RecordingPoiStatusClient::default();
        let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
        let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
            .map(|position| test_wallet_utxo(position as u64))
            .collect::<Vec<_>>();

        let changed = refresh_wallet_poi_statuses(&client, 1, &list_keys, &mut wallet_utxos).await;

        assert!(changed);
        let calls = client.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, list_keys);
        assert_eq!(calls[0].1.len(), WALLET_POI_STATUS_BATCH_SIZE);
        assert_eq!(calls[1].0, list_keys);
        assert_eq!(calls[1].1.len(), 1);
        assert!(wallet_utxos.iter().all(|wallet_utxo| {
            wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys)
                && wallet_utxo.utxo.poi.refreshed_at.is_some()
        }));
    }

    #[tokio::test]
    async fn poi_status_refresh_needed_after_indexed_delta_discovers_utxo() {
        let client = RecordingPoiStatusClient::default();
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let cfg = wallet_config(U256::ZERO);
        let mut wallet_utxos = Vec::new();
        let delta = WalletLogDelta {
            utxos: vec![test_wallet_utxo(1).utxo],
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
        };

        assert!(apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta));
        assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));

        let changed =
            refresh_wallet_poi_statuses(&client, cfg.chain.chain_id, &list_keys, &mut wallet_utxos)
                .await;

        assert!(changed);
        assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
        assert_eq!(client.calls().len(), 1);
        assert_eq!(
            wallet_utxos[0].utxo.poi.statuses.get(&list_key),
            Some(&PoiStatus::Valid)
        );
        assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
    }

    #[tokio::test]
    async fn poi_status_refresh_keeps_failed_chunks_unknown() {
        let client = RecordingPoiStatusClient::default();
        client.fail_call(0);
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
            .map(|position| test_wallet_utxo(position as u64))
            .collect::<Vec<_>>();

        let changed = refresh_wallet_poi_statuses(&client, 1, &list_keys, &mut wallet_utxos).await;

        assert!(changed);
        assert_eq!(client.calls().len(), 2);
        assert_eq!(
            wallet_utxos[0].utxo.poi.statuses.get(&list_key),
            Some(&PoiStatus::Unknown)
        );
        assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, None);
        assert_eq!(
            wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
                .utxo
                .poi
                .statuses
                .get(&list_key),
            Some(&PoiStatus::Valid)
        );
        assert!(
            wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
                .utxo
                .poi
                .refreshed_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn pending_output_poi_matches_undecryptable_observation_and_marks_submitted() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x77; 32]);
        let list_key = FixedBytes::from([0x44; 32]);
        store
            .put_pending_output_poi_context(&pending_output_record(
                chain_id,
                output_commitment,
                list_key,
            ))
            .expect("store pending context");
        let submitter = RecordingPendingOutputPoiSubmitter::default();
        let observation = CommitmentObservation {
            tree: 12,
            position: 34,
            commitment: U256::from_be_bytes(output_commitment.0),
            source: source(8),
        };

        process_pending_output_poi_observations(&store, chain_id, &[observation], Some(&submitter))
            .await;

        let loaded = store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending context")
            .expect("pending context present");
        let observed = loaded.observation.expect("observation recorded");
        assert_eq!(observed.output_tree, 12);
        assert_eq!(observed.output_position, 34);
        assert_eq!(observed.tx_hash, source(8).tx_hash);
        assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
        assert_eq!(submitter.calls(), vec![(output_commitment, 12, 34)]);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn pending_output_poi_matches_wallet_owned_observation_and_keeps_utxo() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let utxo = test_wallet_utxo(36).utxo;
        let output_commitment = FixedBytes::from(utxo.note.commitment().to_be_bytes::<32>());
        let list_key = FixedBytes::from([0x46; 32]);
        store
            .put_pending_output_poi_context(&pending_output_record(
                chain_id,
                output_commitment,
                list_key,
            ))
            .expect("store pending context");
        let submitter = RecordingPendingOutputPoiSubmitter::default();
        let observation = CommitmentObservation {
            tree: utxo.tree,
            position: utxo.position,
            commitment: utxo.note.commitment(),
            source: source(10),
        };
        let delta = WalletLogDelta {
            utxos: vec![utxo],
            nullifiers: Vec::new(),
            commitment_observations: vec![observation],
        };

        process_pending_output_poi_observations(
            &store,
            chain_id,
            &delta.commitment_observations,
            Some(&submitter),
        )
        .await;
        let mut wallet_utxos = Vec::new();
        let changed =
            apply_wallet_delta_to_vec(&wallet_config(U256::ZERO), &mut wallet_utxos, delta);

        assert!(changed);
        assert_eq!(wallet_utxos.len(), 1);
        assert_eq!(wallet_utxos[0].utxo.position, 36);
        let loaded = store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending context")
            .expect("pending context present");
        assert!(loaded.observation.is_some());
        assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
        assert_eq!(submitter.calls(), vec![(output_commitment, 2, 36)]);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn pending_output_poi_submission_failure_remains_retryable() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x78; 32]);
        let list_key = FixedBytes::from([0x45; 32]);
        store
            .put_pending_output_poi_context(&pending_output_record(
                chain_id,
                output_commitment,
                list_key,
            ))
            .expect("store pending context");
        let submitter = RecordingPendingOutputPoiSubmitter::default();
        submitter.fail_next();
        let observation = CommitmentObservation {
            tree: 13,
            position: 35,
            commitment: U256::from_be_bytes(output_commitment.0),
            source: source(9),
        };

        process_pending_output_poi_observations(&store, chain_id, &[observation], Some(&submitter))
            .await;
        let failed = store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending context")
            .expect("pending context present");
        assert!(failed.observation.is_some());
        assert!(failed.submitted_poi_list_keys.is_empty());
        assert!(failed.terminal_error.is_none());

        process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;

        let retried = store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load retried pending context")
            .expect("pending context present");
        assert_eq!(retried.submitted_poi_list_keys, vec![list_key]);
        assert_eq!(submitter.calls().len(), 2);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
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
        let utxo_tree_one = Utxo::new(
            Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            1,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        );
        let utxo_tree_two = Utxo::new(
            utxo_tree_one.note.clone(),
            2,
            7,
            source(2),
            UtxoCommitmentKind::Transact,
        );
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
        let utxo = Utxo::new(
            Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            2,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        );
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
            commitment_observations: Vec::new(),
        };

        let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

        assert!(changed);
        assert_eq!(wallet_utxos[0].spent, Some(spent_source));
    }

    #[test]
    fn indexed_delta_preserves_unmatched_utxo() {
        let nullifying_key = U256::from(42_u8);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo::new(
            Note {
                token_hash: U256::from(1_u8),
                value: U256::from(10_u8),
                random: [0u8; 16],
                npk: U256::from(2_u8),
            },
            2,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        );
        let nullifier = utxo.nullifier(nullifying_key);
        let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
        let delta = WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: 3,
                nullifier,
                source: source(9),
            }],
            commitment_observations: Vec::new(),
        };

        let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

        assert!(!changed);
        assert!(wallet_utxos[0].spent.is_none());
    }
}
