use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Bytes, FixedBytes, U64, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{Transaction, relayCall, transactCall};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use merkletree::quick::{GraphPostError, post_graphql_data};
use merkletree::tree::{MerkleForest, MerkleTree};
use railgun_wallet::prover::ProverError;
use railgun_wallet::tx::{
    InputWitness, PostTransactionPoiData, PostTransactionPoiGenerationRequest,
    PreTransactionPoiError, PreTransactionPoiMap, PrivateInputs, PublicInputs,
    TransactionPlanChunk, generate_post_transaction_pois,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::{
    DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
};
use poi::error::PoiError;
use poi::poi::{
    BlindedCommitmentData, BlindedCommitmentType, DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient,
    SingleCommitmentProofContext, ValidatedRailgunTxidStatus, default_active_poi_list_keys,
};
use railgun_wallet::scan::{
    CommitmentObservation, WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs,
};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{
    PoiStatus, RailgunSpendSigner, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource,
    WalletUtxo,
};
use url::Url;

use crate::types::{BackfillEvent, SharedLogBatch, WalletCacheStore, WalletConfig};

pub const WALLET_POI_STATUS_BATCH_SIZE: usize = 1000;
pub const WALLET_POI_RECOVERABLE_REFRESH_AFTER: Duration = Duration::from_secs(60);
const WALLET_POI_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const WALLET_METADATA_LIVE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);
const WALLET_METADATA_LIVE_FLUSH_BLOCKS: u64 = 25;
const OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER: Duration = Duration::from_secs(10 * 60);
const OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES: u64 = 128;
const OUTPUT_POI_RECOVERY_TXID_GRAPH_PAGE_SIZE: usize = 10_000;
const OUTPUT_POI_RECOVERY_VERIFY_PROOF: bool = true;
const EVM_CHAIN_TYPE: u8 = 0;

#[derive(Debug, Clone, Copy)]
enum WalletPoiRefreshSelection {
    Required,
    RequiredOrRecoverable,
    RecoverableStale { now: u64 },
    Recoverable,
}

impl WalletPoiRefreshSelection {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RequiredOrRecoverable => "required_or_recoverable",
            Self::RecoverableStale { .. } => "recoverable_stale",
            Self::Recoverable => "recoverable",
        }
    }

    fn matches_wallet_utxo(
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

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub ready_rx: watch::Receiver<bool>,
    pub rev_rx: watch::Receiver<u64>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    poi_refresh_tx: mpsc::Sender<WalletPoiRefreshRequest>,
    rev_tx: watch::Sender<u64>,
}

impl WalletHandle {
    pub async fn refresh_poi_statuses(&self) -> bool {
        self.poi_refresh_tx
            .send(WalletPoiRefreshRequest {
                force_output_poi_recovery: true,
            })
            .await
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
struct WalletPoiRefreshRequest {
    force_output_poi_recovery: bool,
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

    async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &broadcaster_core::transact::PreTxPoi,
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

    async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &broadcaster_core::transact::PreTxPoi,
    ) -> Result<(), PoiError> {
        PoiRpcClient::submit_transact_proof(
            self,
            txid_version,
            chain_type,
            chain_id,
            list_key,
            txid_merkleroot_index,
            poi,
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
    let started = Instant::now();
    let filter_started = Instant::now();
    let filtered_logs: Vec<_> = batch
        .logs
        .iter()
        .filter(|log| log.block_number.unwrap_or_default() > last_scanned)
        .cloned()
        .collect();
    let filter_elapsed_ms = filter_started.elapsed().as_millis();

    let parse_started = Instant::now();
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
    let parse_elapsed_ms = parse_started.elapsed().as_millis();
    let delta_utxos = new_utxos.len();
    let delta_nullifiers = nullifiers.len();
    let commitment_observation_count = commitment_observations.len();

    let poi_submitter = if commitment_observation_count > 0 {
        poi_submitter
    } else {
        None
    };
    let poi_observation_started = Instant::now();
    process_pending_output_poi_observations(
        db,
        cfg.chain.chain_id,
        &commitment_observations,
        poi_submitter,
    )
    .await;
    let poi_observation_elapsed_ms = poi_observation_started.elapsed().as_millis();

    let apply_started = Instant::now();
    let outcome = apply_wallet_delta_with_outcome(
        cfg,
        wallet_utxos,
        WalletLogDelta {
            utxos: new_utxos,
            nullifiers,
            commitment_observations,
        },
    )
    .await;
    let apply_elapsed_ms = apply_started.elapsed().as_millis();
    discard_pending_output_poi_contexts_for_spent_outputs(
        db,
        cfg.chain.chain_id,
        &outcome.spent_output_commitments,
    );
    let changed = outcome.changed;

    debug!(
        cache_key = %cfg.cache_key,
        chain_id = cfg.chain.chain_id,
        from_block = batch.from_block,
        to_block = batch.to_block,
        logs = batch.logs.len(),
        filtered_logs = filtered_logs.len(),
        delta_utxos,
        delta_nullifiers,
        commitment_observations = commitment_observation_count,
        poi_submission_enabled = poi_submitter.is_some(),
        changed,
        filter_elapsed_ms,
        parse_elapsed_ms,
        poi_observation_elapsed_ms,
        apply_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "applied wallet log delta"
    );

    Ok((batch.to_block, changed))
}

async fn apply_wallet_delta_with_outcome(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    delta: WalletLogDelta,
) -> WalletDeltaApplyOutcome {
    let started = Instant::now();
    let lock_wait_started = Instant::now();
    let mut locked = wallet_utxos.write().await;
    let lock_wait_elapsed_ms = lock_wait_started.elapsed().as_millis();
    let rows_before = locked.len();
    let outcome = apply_wallet_delta_to_vec_with_outcome(cfg, &mut locked, delta);
    debug!(
        cache_key = %cfg.cache_key,
        rows_before,
        rows_after = locked.len(),
        changed = outcome.changed,
        spent_outputs = outcome.spent_output_commitments.len(),
        lock_wait_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "applied wallet delta to cache"
    );
    outcome
}

pub(crate) fn apply_wallet_delta_to_vec(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> bool {
    apply_wallet_delta_to_vec_with_outcome(cfg, wallet_utxos, delta).changed
}

fn apply_wallet_delta_to_vec_with_outcome(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> WalletDeltaApplyOutcome {
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
    let mut spent_output_commitments = Vec::new();
    if !nullifier_sources.is_empty() {
        for wallet_utxo in wallet_utxos.iter_mut().filter(|entry| !entry.is_spent()) {
            if let Some(source) = spent_source_for_utxo(
                &wallet_utxo.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            ) {
                wallet_utxo.spent = Some(source);
                spent_output_commitments.push(wallet_utxo.utxo.poi.commitment);
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
            if spent.is_some() {
                spent_output_commitments.push(utxo.poi.commitment);
            }
            wallet_utxos.push(WalletUtxo { utxo, spent });
            changed = true;
        }
    }

    let before_dedupe = wallet_utxos.len();
    dedupe_wallet_utxos(wallet_utxos);
    WalletDeltaApplyOutcome {
        changed: changed || wallet_utxos.len() != before_dedupe,
        spent_output_commitments,
    }
}

#[derive(Debug, Default)]
struct WalletDeltaApplyOutcome {
    changed: bool,
    spent_output_commitments: Vec<FixedBytes<32>>,
}

fn discard_pending_output_poi_contexts_for_spent_outputs(
    db: &DbStore,
    chain_id: u64,
    spent_output_commitments: &[FixedBytes<32>],
) {
    for output_commitment in spent_output_commitments {
        if let Err(err) = db.delete_pending_output_poi_context(chain_id, output_commitment) {
            warn!(
                ?err,
                chain_id,
                commitment = %hex::encode(output_commitment),
                "failed to delete pending output POI context for spent output"
            );
        }
    }
}

fn spent_source_for_utxo(
    utxo: &Utxo,
    nullifying_key: U256,
    nullifier_sources: &HashMap<(u32, U256), UtxoSource>,
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
    process_pending_output_poi_observations_inner(db, chain_id, observations, submitter, false)
        .await;
}

async fn process_pending_output_poi_observations_inner(
    db: &DbStore,
    chain_id: u64,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
    force_submission_retry: bool,
) {
    let started = Instant::now();
    let record_started = Instant::now();
    for observation in observations {
        if let Err(err) = record_pending_output_poi_observation(db, chain_id, observation) {
            warn!(
                ?err,
                chain_id,
                commitment = %hex::encode(FixedBytes::from(observation.commitment.to_be_bytes::<32>())),
                "failed to record pending output POI observation"
            );
        }
    }
    let record_elapsed_ms = record_started.elapsed().as_millis();

    let Some(submitter) = submitter else {
        if observations.is_empty() {
            return;
        }
        debug!(
            chain_id,
            observations = observations.len(),
            submitted = false,
            record_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
        return;
    };
    let submit_started = Instant::now();
    let submitted_contexts =
        match submit_observed_pending_output_pois(db, chain_id, submitter, force_submission_retry)
            .await
        {
            Ok(submitted_contexts) => submitted_contexts,
            Err(err) => {
                warn!(
                    ?err,
                    chain_id, "failed to submit observed pending output POI contexts"
                );
                0
            }
        };
    if submitted_contexts > 0 || !observations.is_empty() {
        debug!(
            chain_id,
            observations = observations.len(),
            submitted = true,
            submitted_contexts,
            record_elapsed_ms,
            submit_elapsed_ms = submit_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
    }
}

fn record_pending_output_poi_observation(
    db: &DbStore,
    chain_id: u64,
    observation: &CommitmentObservation,
) -> Result<(), local_db::DbError> {
    let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
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
    if record.observe(observed) {
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(())
}

async fn submit_observed_pending_output_pois(
    db: &DbStore,
    chain_id: u64,
    submitter: &dyn PendingOutputPoiSubmitter,
    force_submission_retry: bool,
) -> Result<usize, local_db::DbError> {
    let records = db.list_pending_output_poi_contexts(chain_id)?;
    let mut submitted_contexts = 0;
    let now = now_epoch_secs();
    for mut record in records {
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        if record.terminal_error.is_some() {
            continue;
        }
        let recovery =
            db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?;
        let mut missing_list_keys = record.missing_list_keys();
        if missing_list_keys.is_empty()
            && recovery
                .as_ref()
                .is_some_and(|record| record.submission_retry_allowed(now, force_submission_retry))
        {
            missing_list_keys = record.list_keys();
        }
        if missing_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&missing_list_keys);
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
        let Some(submit_identity) = pending_output_poi_submit_identity(&record, &observation)
        else {
            warn!(
                chain_id,
                commitment = %hex::encode(record.output_commitment),
                output_tree = observation.output_tree,
                output_position = observation.output_position,
                "pending output POI context has invalid output tree"
            );
            continue;
        };
        let submitted_list_keys = missing_list_keys.clone();
        debug!(
            chain_id,
            wallet_id = %record.wallet_id,
            commitment = %hex::encode(record.output_commitment),
            npk = %hex::encode(record.output_npk),
            output_tree = observation.output_tree,
            output_position = observation.output_position,
            derived_blinded_commitment = %hex::encode(submit_identity.derived_blinded_commitment),
            railgun_txid = %hex::encode(FixedBytes::from(record.railgun_txid.to_be_bytes::<32>())),
            txid_leaf_hash = %hex::encode(submit_identity.txid_leaf_hash),
            utxo_tree_in = record.utxo_tree_in,
            source_tx_hash = %hex::encode(observation.tx_hash),
            list_keys = ?submitted_list_keys,
            pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
            "submitting pending output POI context"
        );
        match submit_pending_output_poi_context(
            submitter,
            chain_id,
            &record,
            &context,
            &observation,
            &submitted_list_keys,
        )
        .await
        {
            Ok(()) => {
                for list_key in &submitted_list_keys {
                    if !record.submitted_poi_list_keys.contains(list_key) {
                        record.submitted_poi_list_keys.push(*list_key);
                    }
                }
                db.put_pending_output_poi_context(&record)?;
                if let Some(mut recovery) = recovery.clone() {
                    recovery.apply_action(
                        OutputPoiRecoveryAction::Submitted {
                            retry_after: OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                        },
                        now,
                    );
                    db.put_output_poi_recovery(&recovery)?;
                }
                submitted_contexts += 1;
            }
            Err(err) => {
                if let Some(mut recovery) = recovery.clone() {
                    recovery.apply_action(
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    );
                    db.put_output_poi_recovery(&recovery)?;
                }
                warn!(
                    ?err,
                    chain_id,
                    commitment = %hex::encode(record.output_commitment),
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(submitted_contexts)
}

async fn submit_pending_output_poi_context(
    submitter: &dyn PendingOutputPoiSubmitter,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<(), PoiError> {
    if let Some(txid_merkleroot_index) = record.txid_merkleroot_index {
        for list_key in submitted_list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                submitter
                    .submit_transact_proof(
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await?;
            }
        }
        Ok(())
    } else {
        submitter
            .submit_single_commitment_proofs(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                context,
                observation.output_tree,
                observation.output_position,
            )
            .await
    }
}

struct PendingOutputPoiSubmitIdentity {
    derived_blinded_commitment: FixedBytes<32>,
    txid_leaf_hash: FixedBytes<32>,
}

fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    let txid_leaf_hash = record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
        txid_leaf_hash,
    })
}

#[derive(Clone, Copy)]
struct RecoverySpendPublicKey {
    spending_public_key: [U256; 2],
}

impl RailgunSpendSigner for RecoverySpendPublicKey {
    fn spending_public_key(&self) -> [U256; 2] {
        self.spending_public_key
    }

    fn sign_spend_message(&self, _msg: U256) -> [U256; 3] {
        [U256::ZERO; 3]
    }
}

struct OutputPoiRecoveryRequest<'a> {
    db: &'a DbStore,
    cfg: &'a WalletConfig,
    rpcs: &'a QueryRpcPool,
    http_client: Option<&'a reqwest::Client>,
    forest: &'a MerkleForest,
    poi_client: &'a PoiRpcClient,
    submitter: &'a dyn PendingOutputPoiSubmitter,
    active_list_keys: &'a [FixedBytes<32>],
    wallet_utxos: &'a [WalletUtxo],
    force_retry: bool,
}

#[derive(Debug)]
struct RecoveryChunk {
    chunk: TransactionPlanChunk,
    output: Utxo,
    output_start_global: u128,
}

#[derive(Debug, Clone)]
struct RecoveryFailure {
    status: OutputPoiRecoveryStatus,
    message: String,
    retry_after: Option<Duration>,
}

impl RecoveryFailure {
    fn permanent(status: OutputPoiRecoveryStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    fn retryable(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    message: String,
}

#[derive(Deserialize)]
struct JsonRpcTransaction {
    input: Option<String>,
    data: Option<String>,
}

async fn recover_missing_output_pois(request: OutputPoiRecoveryRequest<'_>) -> usize {
    let Some(spending_public_key) = request.cfg.spending_public_key else {
        return 0;
    };
    let Some(prover) = request.cfg.poi_recovery_prover.as_ref() else {
        return 0;
    };
    if request.active_list_keys.is_empty() {
        return 0;
    }

    let started = Instant::now();
    let now = now_epoch_secs();
    let mut fetched_inputs: HashMap<FixedBytes<32>, Result<Bytes, RecoveryFailure>> =
        HashMap::new();
    let mut recovered = 0usize;
    let candidates = output_poi_recovery_candidates(request.wallet_utxos, request.active_list_keys);

    for candidate in candidates {
        let output_commitment = candidate.utxo.poi.commitment;
        let source_tx_hash = candidate.utxo.source.tx_hash;
        let existing_pending_context = request
            .db
            .get_pending_output_poi_context(request.cfg.chain.chain_id, &output_commitment)
            .ok()
            .flatten();
        if let Some(existing_pending_context) = existing_pending_context.as_ref() {
            if !request.force_retry {
                continue;
            }
            log_forced_output_poi_recovery_regeneration(
                request.cfg,
                candidate,
                existing_pending_context,
            );
        }

        match request.db.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) {
            Ok(Some(record)) if !record.retry_allowed(now, request.force_retry) => {
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "failed to load output POI recovery cache"
                );
                continue;
            }
        }

        let tx_input = if let Some(cached) = fetched_inputs.get(&source_tx_hash) {
            cached.clone()
        } else if let Ok(Some(record)) = request.db.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) && let Some(tx_input) = record.tx_input
        {
            Ok(Bytes::from(tx_input))
        } else {
            let fetched = fetch_transaction_input(
                request.rpcs,
                request.http_client,
                request.cfg.chain.chain_id,
                source_tx_hash,
            )
            .await;
            fetched_inputs.insert(source_tx_hash, fetched.clone());
            if let Ok(tx_input) = &fetched {
                put_output_poi_recovery_tx_input(request.db, request.cfg, candidate, tx_input, now);
            }
            fetched
        };

        let tx_input = match tx_input {
            Ok(tx_input) => tx_input,
            Err(failure) => {
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    failure,
                    now,
                );
                continue;
            }
        };

        let decoded = match decode_railgun_transactions(&tx_input) {
            Ok(decoded) => decoded,
            Err(failure) => {
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    failure,
                    now,
                );
                continue;
            }
        };

        let recovery_chunk = match build_output_poi_recovery_chunk(
            candidate,
            request.wallet_utxos,
            &decoded,
            request.forest,
            request.active_list_keys,
            spending_public_key,
            &request.cfg.scan_keys,
        ) {
            Ok(recovery_chunk) => recovery_chunk,
            Err(failure) => {
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    failure,
                    now,
                );
                continue;
            }
        };

        let txid_data = match recovered_output_txid_data(
            request.cfg,
            request.poi_client,
            request.http_client,
            source_tx_hash,
            output_commitment,
            &recovery_chunk,
        )
        .await
        {
            Ok(txid_data) => txid_data,
            Err(failure) => {
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    failure,
                    now,
                );
                continue;
            }
        };

        match generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
            chunk: &recovery_chunk.chunk,
            txid_data: &txid_data.poi_data,
            chain_type: EVM_CHAIN_TYPE,
            chain_id: request.cfg.chain.chain_id,
            txid_version: Some(DEFAULT_TXID_VERSION),
            required_poi_list_keys: request.active_list_keys,
            poi_client: request.poi_client,
            prover,
            verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
        })
        .await
        {
            Ok(pre_transaction_pois) => {
                let record = pending_output_poi_context_from_recovery(
                    request.cfg,
                    candidate,
                    &recovery_chunk,
                    txid_data.poi_data.txid_merkleroot_index,
                    pre_transaction_pois,
                    request.active_list_keys,
                    now,
                );
                if let Err(err) = request.db.put_pending_output_poi_context(&record) {
                    warn!(
                        ?err,
                        cache_key = %request.cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist recovered output POI context"
                    );
                    continue;
                }
                put_output_poi_recovery_record(
                    request.db,
                    request.cfg,
                    candidate,
                    now,
                    OutputPoiRecoveryAction::Detected {
                        status: OutputPoiRecoveryStatus::Recoverable,
                        retry_after: None,
                        last_error: None,
                        increment_attempts: false,
                    },
                );
                debug!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    txid_merkleroot_index = txid_data.poi_data.txid_merkleroot_index,
                    target_txid_index = txid_data.target_txid_index,
                    inputs = recovery_chunk.chunk.inputs.len(),
                    outputs = recovery_chunk.chunk.outputs.len(),
                    input_tree = recovery_chunk.chunk.tree_number,
                    "reconstructed output POI context"
                );
                recovered += 1;
            }
            Err(err) => {
                let retry_after = output_poi_recovery_proof_retry_after(&err);
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::ProofGenerationFailed,
                        err.to_string(),
                        retry_after,
                    ),
                    now,
                );
            }
        }
    }

    if recovered > 0 {
        match submit_observed_pending_output_pois(
            request.db,
            request.cfg.chain.chain_id,
            request.submitter,
            false,
        )
        .await
        {
            Ok(submitted_contexts) => {
                debug!(
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    submitted_contexts,
                    elapsed_ms = started.elapsed().as_millis(),
                    "recovered missing output POI contexts"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    "failed to submit recovered output POI contexts"
                );
            }
        }
    }

    recovered
}

#[derive(Debug)]
struct RecoveredOutputTxidData {
    target_txid_index: u64,
    poi_data: PostTransactionPoiData,
}

async fn recovered_output_txid_data(
    cfg: &WalletConfig,
    poi_client: &PoiRpcClient,
    http_client: Option<&reqwest::Client>,
    source_tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
    recovery_chunk: &RecoveryChunk,
) -> Result<RecoveredOutputTxidData, RecoveryFailure> {
    let Some(endpoint) = cfg.quick_sync_endpoint.as_ref() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no quick-sync endpoint configured for TXID proof recovery",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let target = fetch_recovery_graph_transaction_by_commitment(
        &client,
        endpoint,
        source_tx_hash,
        output_commitment,
    )
    .await?;
    target.validate_against_recovery_chunk(recovery_chunk)?;

    let target_txid_index = fetch_recovery_graph_txid_index(&client, endpoint, &target.id).await?;
    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let target_index = target_txid_index % TREE_LEAF_COUNT;

    let latest_validated = poi_client
        .latest_validated_railgun_txid(DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, cfg.chain.chain_id)
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("fetch latest validated TXID failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let root_txid_index = txid_root_index_for_target(target_txid_index, latest_validated)?;
    let root_tree = root_txid_index / TREE_LEAF_COUNT;
    if root_tree != target_tree {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "latest validated TXID tree is before recovered transaction tree",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let root_index = root_txid_index % TREE_LEAF_COUNT;
    let leaf_count = root_index.saturating_add(1);
    let transactions =
        fetch_recovery_graph_txid_tree_segment(&client, endpoint, target_tree, leaf_count).await?;
    if transactions.len() != leaf_count as usize {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!(
                "TXID graph returned {} leaves for tree {target_tree}, expected {leaf_count}",
                transactions.len()
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    let mut txid_tree = MerkleTree::default();
    for (position, transaction) in transactions.iter().enumerate() {
        txid_tree
            .insert(position as u64, transaction.txid_leaf_hash())
            .map_err(|err| {
                RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::MissingMerkleProof,
                    format!("build TXID Merkle tree failed: {err}"),
                    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                )
            })?;
    }
    let proof = txid_tree.prove_with_leaf_count(target_index, leaf_count);
    let expected_leaf = target.txid_leaf_hash();
    if proof.leaf != expected_leaf {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "reconstructed TXID proof leaf does not match target transaction",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let txid_merkleroot = FixedBytes::from(proof.root.to_be_bytes::<32>());
    let valid_root = poi_client
        .validate_txid_merkleroot(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            target_tree,
            root_index,
            &txid_merkleroot,
        )
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("validate recovered TXID merkleroot failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    if !valid_root {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node rejected recovered TXID merkleroot",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    Ok(RecoveredOutputTxidData {
        target_txid_index,
        poi_data: PostTransactionPoiData {
            txid_leaf_hash: FixedBytes::from(proof.leaf.to_be_bytes::<32>()),
            txid_merkleroot,
            txid_merkleroot_index: root_txid_index,
            txid_merkle_proof_indices: U256::from(target_index),
            txid_merkle_proof_path_elements: proof.path_elements.to_vec(),
            utxo_batch_global_start_position_out: U256::from(recovery_chunk.output_start_global),
        },
    })
}

fn txid_root_index_for_target(
    target_txid_index: u64,
    latest_validated: ValidatedRailgunTxidStatus,
) -> Result<u64, RecoveryFailure> {
    let Some(latest_validated_index) = latest_validated.validated_txid_index else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node did not return a latest validated TXID index",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    if latest_validated_index < target_txid_index {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "latest validated TXID index is before recovered transaction",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let latest_tree = latest_validated_index / TREE_LEAF_COUNT;
    if latest_tree == target_tree {
        Ok(latest_validated_index)
    } else {
        Ok((target_tree + 1) * TREE_LEAF_COUNT - 1)
    }
}

async fn fetch_recovery_graph_transaction_by_commitment(
    client: &reqwest::Client,
    endpoint: &Url,
    tx_hash: FixedBytes<32>,
    commitment: FixedBytes<32>,
) -> Result<RecoveryGraphRailgunTransaction, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxByCommitment($txHash: Bytes!, $commitment: Bytes!) {
  transactions(
    where: { transactionHash_eq: $txHash, commitments_containsAll: [$commitment] }
    orderBy: id_ASC
    limit: 2
  ) {
    id
    nullifiers
    commitments
    boundParamsHash
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
"#;
    let data: RecoveryGraphTransactionsData = post_recovery_graphql(
        client,
        endpoint,
        QUERY,
        json!({
            "txHash": hex::encode_prefixed(tx_hash),
            "commitment": hex::encode_prefixed(commitment),
        }),
    )
    .await?;
    let mut transactions = data.transactions;
    match transactions.len() {
        1 => Ok(transactions.remove(0)),
        0 => Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "indexed TXID transaction not found for recovered output",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )),
        _ => Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "multiple indexed TXID transactions matched recovered output",
        )),
    }
}

async fn fetch_recovery_graph_txid_index(
    client: &reqwest::Client,
    endpoint: &Url,
    graph_id: &str,
) -> Result<u64, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxidIndex($id: String!) {
  transactionsConnection(orderBy: [id_ASC], where: { id_lte: $id }) {
    totalCount
  }
}
"#;
    let data: RecoveryGraphTxidIndexData =
        post_recovery_graphql(client, endpoint, QUERY, json!({ "id": graph_id })).await?;
    data.transactions_connection
        .total_count
        .checked_sub(1)
        .ok_or_else(|| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "indexed TXID transaction count is zero",
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })
}

async fn fetch_recovery_graph_txid_tree_segment(
    client: &reqwest::Client,
    endpoint: &Url,
    tree: u64,
    leaf_count: u64,
) -> Result<Vec<RecoveryGraphRailgunTransaction>, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxidTreeSegment($offset: Int!, $limit: Int!) {
  transactions(orderBy: id_ASC, offset: $offset, limit: $limit) {
    id
    nullifiers
    commitments
    boundParamsHash
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
"#;
    let start = tree.saturating_mul(TREE_LEAF_COUNT);
    let mut transactions = Vec::with_capacity(leaf_count as usize);
    while transactions.len() < leaf_count as usize {
        let remaining = leaf_count as usize - transactions.len();
        let limit = remaining.min(OUTPUT_POI_RECOVERY_TXID_GRAPH_PAGE_SIZE);
        let offset = start.saturating_add(transactions.len() as u64);
        let data: RecoveryGraphTransactionsData = post_recovery_graphql(
            client,
            endpoint,
            QUERY,
            json!({
                "offset": offset,
                "limit": limit,
            }),
        )
        .await?;
        if data.transactions.is_empty() {
            break;
        }
        transactions.extend(data.transactions);
    }
    Ok(transactions)
}

async fn post_recovery_graphql<T>(
    client: &reqwest::Client,
    endpoint: &Url,
    query: &'static str,
    variables: serde_json::Value,
) -> Result<T, RecoveryFailure>
where
    T: for<'de> Deserialize<'de>,
{
    post_graphql_data(client, endpoint, query, &variables)
        .await
        .map_err(recovery_graph_failure)
}

fn recovery_graph_failure(error: GraphPostError) -> RecoveryFailure {
    let message = match error {
        GraphPostError::Request(error) => format!("TXID graph request failed: {error}"),
        GraphPostError::ReadBody(error) => format!("read TXID graph response failed: {error}"),
        GraphPostError::HttpStatus { status, body } => {
            format!("TXID graph request returned {status}: {body}")
        }
        GraphPostError::Json(error) => format!("decode TXID graph response failed: {error}"),
        GraphPostError::Graphql(message) => format!("TXID graph returned errors: {message}"),
        GraphPostError::MissingData => "TXID graph response missing data".to_string(),
    };
    RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::TxFetchFailed,
        message,
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    )
}

#[derive(Debug, Deserialize)]
struct RecoveryGraphTransactionsData {
    transactions: Vec<RecoveryGraphRailgunTransaction>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGraphTxidIndexData {
    #[serde(rename = "transactionsConnection")]
    transactions_connection: RecoveryGraphConnection,
}

#[derive(Debug, Deserialize)]
struct RecoveryGraphConnection {
    #[serde(rename = "totalCount")]
    total_count: u64,
}

#[derive(Debug, Deserialize)]
struct RecoveryGraphRailgunTransaction {
    id: String,
    nullifiers: Vec<U256>,
    commitments: Vec<U256>,
    #[serde(rename = "boundParamsHash")]
    bound_params_hash: U256,
    #[serde(rename = "utxoTreeIn")]
    utxo_tree_in: U64,
    #[serde(rename = "utxoTreeOut")]
    utxo_tree_out: U64,
    #[serde(rename = "utxoBatchStartPositionOut")]
    utxo_batch_start_position_out: U64,
}

impl RecoveryGraphRailgunTransaction {
    fn railgun_txid(&self) -> U256 {
        compute_railgun_txid_parts(&self.nullifiers, &self.commitments, self.bound_params_hash)
    }

    fn txid_leaf_hash(&self) -> U256 {
        railgun_txid_leaf_hash_with_output_start(
            self.railgun_txid(),
            self.utxo_tree_in.to(),
            U256::from(self.output_start_global()),
        )
    }

    fn output_start_global(&self) -> u128 {
        let output_tree = self.utxo_tree_out.to::<u128>();
        let output_position = self.utxo_batch_start_position_out.to::<u128>();
        output_tree * u128::from(TREE_LEAF_COUNT) + output_position
    }

    fn validate_against_recovery_chunk(
        &self,
        recovery_chunk: &RecoveryChunk,
    ) -> Result<(), RecoveryFailure> {
        if self.railgun_txid() != recovery_chunk.chunk.railgun_txid() {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "indexed TXID transaction does not match recovered calldata transaction",
            ));
        }
        if self.output_start_global() != recovery_chunk.output_start_global {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "indexed TXID output position does not match recovered wallet output",
            ));
        }
        Ok(())
    }
}

fn output_poi_recovery_proof_retry_after(err: &PreTransactionPoiError) -> Duration {
    match err {
        PreTransactionPoiError::Prover(
            ProverError::WorkerPanic(_) | ProverError::WorkerDropped | ProverError::QueueClosed,
        ) => OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        _ => OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    }
}

fn output_poi_recovery_candidates<'a>(
    wallet_utxos: &'a [WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> Vec<&'a WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
        })
        .collect()
}

async fn fetch_transaction_input(
    rpcs: &QueryRpcPool,
    http_client: Option<&reqwest::Client>,
    chain_id: u64,
    tx_hash: FixedBytes<32>,
) -> Result<Bytes, RecoveryFailure> {
    let Some(provider) = rpcs.random_provider() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no healthy RPC available",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let tx_hash_hex = hex::encode_prefixed(tx_hash);
    let response = client
        .post(provider.url.clone())
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash_hex],
        }))
        .send()
        .await
        .map_err(|err| {
            rpcs.mark_bad_provider(&provider);
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("fetch transaction RPC failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("fetch transaction RPC returned HTTP {status}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let response: JsonRpcResponse<JsonRpcTransaction> = response.json().await.map_err(|err| {
        rpcs.mark_bad_provider(&provider);
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("decode transaction RPC response failed: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    if let Some(error) = response.error {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!(
                "fetch transaction RPC error on chain {chain_id}: {}",
                error.message
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let Some(tx) = response.result else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "transaction not found",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let input = tx.input.or(tx.data).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction has no input",
        )
    })?;
    let input = input.strip_prefix("0x").unwrap_or(&input);
    let bytes = hex::decode(input).map_err(|err| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            format!("transaction input is not hex: {err}"),
        )
    })?;
    Ok(Bytes::from(bytes))
}

fn decode_railgun_transactions(calldata: &[u8]) -> Result<Vec<Transaction>, RecoveryFailure> {
    if calldata.len() < 4 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction input too short",
        ));
    }
    if let Ok(call) = transactCall::abi_decode(calldata) {
        return Ok(call._transactions);
    }
    if let Ok(call) = relayCall::abi_decode(calldata) {
        if !call._actionData.calls.is_empty() {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "relay transaction with action data is not treated as consolidation recovery",
            ));
        }
        return Ok(call._transactions);
    }
    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::UnsupportedShape,
        "transaction is not a Railgun transact or relay call",
    ))
}

fn build_output_poi_recovery_chunk(
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    transactions: &[Transaction],
    forest: &MerkleForest,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<RecoveryChunk, RecoveryFailure> {
    if transactions.len() != 1 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "batched transactions are not treated as consolidation recovery",
        ));
    }
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    for transaction in transactions {
        let Some(output_index) = transaction
            .commitments
            .iter()
            .position(|commitment| U256::from_be_bytes(commitment.0) == output_commitment)
        else {
            continue;
        };
        if transaction.boundParams.unshield != 0 {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "matched output belongs to an unshield transaction",
            ));
        }

        let output_start_global = output_start_global_position(&candidate.utxo, output_index)?;
        let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
        let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
        let input_tree = u32::from(transaction.boundParams.treeNumber);
        let max_leaf_count = if input_tree == output_start_tree {
            output_start_position
        } else if input_tree < output_start_tree {
            TREE_LEAF_COUNT
        } else {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "transaction input tree is after output tree",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        };

        let outputs = wallet_outputs_for_transaction(candidate, wallet_utxos, transaction)?;
        let inputs =
            wallet_inputs_for_transaction(candidate, wallet_utxos, transaction, scan_keys)?;
        if inputs.iter().any(|wallet_utxo| {
            active_list_keys.iter().any(|list_key| {
                wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
            })
        }) {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::InputPoiNotValid,
                "one or more transaction inputs are shield-blocked",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }

        let merkle_root = U256::from_be_bytes(transaction.merkleRoot.0);
        let first_input = inputs.first().ok_or_else(|| {
            RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletInputs,
                "transaction has no wallet-owned inputs",
            )
        })?;
        let leaf_count = recovery_leaf_count_for_merkle_root(
            forest,
            input_tree,
            first_input,
            max_leaf_count,
            merkle_root,
        )?;
        let mut input_witnesses = Vec::with_capacity(inputs.len());
        for input in inputs {
            let Some(proof) =
                forest.prove_with_leaf_count(input.utxo.tree, input.utxo.position, leaf_count)
            else {
                return Err(RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::MissingMerkleProof,
                    "input tree missing from local Merkle forest",
                    OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                ));
            };
            if proof.root != merkle_root || proof.leaf != input.utxo.note.commitment() {
                return Err(RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::MissingMerkleProof,
                    "reconstructed Merkle proof does not match transaction root",
                    OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                ));
            }
            input_witnesses.push(InputWitness {
                utxo: input.utxo.clone(),
                merkle_proof: proof,
            });
        }

        let output_notes = outputs
            .iter()
            .map(|wallet_utxo| wallet_utxo.utxo.note.clone())
            .collect::<Vec<_>>();
        let public_inputs = PublicInputs::from_transaction(merkle_root, transaction, &output_notes);
        let signer = RecoverySpendPublicKey {
            spending_public_key,
        };
        let private_inputs = PrivateInputs::from_inputs(
            input_witnesses[0].utxo.token_address(),
            &input_witnesses,
            &output_notes,
            scan_keys,
            &signer,
        );
        return Ok(RecoveryChunk {
            chunk: TransactionPlanChunk {
                tree_number: input_tree,
                merkle_root,
                inputs: input_witnesses,
                outputs: output_notes,
                has_unshield: false,
                public_inputs,
                private_inputs,
                signature: [U256::ZERO; 3],
            },
            output: candidate.utxo.clone(),
            output_start_global,
        });
    }

    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::NotSelfOriginated,
        "source transaction does not contain the wallet output commitment",
    ))
}

fn output_start_global_position(utxo: &Utxo, output_index: usize) -> Result<u128, RecoveryFailure> {
    let global = u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position);
    global.checked_sub(output_index as u128).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "output index is before observed output position",
        )
    })
}

fn recovery_leaf_count_for_merkle_root(
    forest: &MerkleForest,
    input_tree: u32,
    first_input: &WalletUtxo,
    max_leaf_count: u64,
    merkle_root: U256,
) -> Result<u64, RecoveryFailure> {
    let min_leaf_count = first_input.utxo.position.saturating_add(1);
    if max_leaf_count < min_leaf_count {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "transaction root predates the first wallet input leaf",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let lower_bound = max_leaf_count
        .saturating_sub(OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES)
        .max(min_leaf_count);
    for leaf_count in (lower_bound..=max_leaf_count).rev() {
        let Some(proof) =
            forest.prove_with_leaf_count(input_tree, first_input.utxo.position, leaf_count)
        else {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "input tree missing from local Merkle forest",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        };
        if proof.leaf == first_input.utxo.note.commitment() && proof.root == merkle_root {
            return Ok(leaf_count);
        }
    }
    Err(RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::MissingMerkleProof,
        "reconstructed Merkle proof does not match transaction root within recovery search window",
        OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    ))
}

fn wallet_outputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_utxos: &'a [WalletUtxo],
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let mut outputs = Vec::with_capacity(transaction.commitments.len());
    for commitment in &transaction.commitments {
        let commitment = FixedBytes::from(commitment.0);
        let Some(output) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo.utxo.poi.commitment == commitment
        }) else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletOutputs,
                "not all private transaction outputs are wallet-owned",
            ));
        };
        outputs.push(output);
    }
    if outputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "transaction has no private outputs",
        ));
    }
    Ok(outputs)
}

fn wallet_inputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_utxos: &'a [WalletUtxo],
    transaction: &Transaction,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let input_tree = u32::from(transaction.boundParams.treeNumber);
    let mut inputs = Vec::with_capacity(transaction.nullifiers.len());
    for nullifier in &transaction.nullifiers {
        let nullifier = U256::from_be_bytes(nullifier.0);
        let Some(input) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.tree == input_tree
                && wallet_utxo.utxo.nullifier(scan_keys.nullifying_key) == nullifier
                && wallet_utxo
                    .spent
                    .as_ref()
                    .is_some_and(|spent| spent.tx_hash == candidate.utxo.source.tx_hash)
        }) else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

fn pending_output_poi_context_from_recovery(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    now: u64,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: recovery_chunk.output.poi.commitment,
        output_npk: recovery_chunk.output.poi.npk,
        utxo_tree_in: u64::from(recovery_chunk.chunk.tree_number),
        railgun_txid: recovery_chunk.chunk.railgun_txid(),
        txid_merkleroot_index: Some(txid_merkleroot_index),
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        required_poi_list_keys: active_list_keys.to_vec(),
        output_role: PendingOutputPoiRole::Change,
        created_at: now,
        source_operation_id: Some(format!(
            "recovered-output-poi:{}",
            hex::encode(candidate.utxo.source.tx_hash)
        )),
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(candidate.utxo.tree),
            output_position: candidate.utxo.position,
            tx_hash: candidate.utxo.source.tx_hash,
            block_number: candidate.utxo.source.block_number,
            block_timestamp: candidate.utxo.source.block_timestamp,
        }),
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn log_forced_output_poi_recovery_regeneration(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    existing_pending_context: &PendingOutputPoiContextRecord,
) {
    let stored_derived_blinded_commitment = existing_pending_context
        .observation
        .as_ref()
        .and_then(|observation| {
            pending_output_poi_submit_identity(existing_pending_context, observation)
                .map(|identity| identity.derived_blinded_commitment)
        })
        .map_or_else(|| "none".to_string(), hex::encode);
    let stored_source_tx_hash = existing_pending_context.observation.as_ref().map_or_else(
        || "none".to_string(),
        |observation| hex::encode(observation.tx_hash),
    );
    debug!(
        cache_key = %cfg.cache_key,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
        stored_derived_blinded_commitment = %stored_derived_blinded_commitment,
        stored_source_tx_hash = %stored_source_tx_hash,
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        "force-regenerating recovered output POI context"
    );
}

fn new_output_poi_recovery_record(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        output_commitment: candidate.utxo.poi.commitment,
        source_tx_hash: candidate.utxo.source.tx_hash,
        tx_input: None,
        status,
        created_at: now,
        updated_at: now,
        last_detection_at: None,
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 0,
        last_error: None,
    }
}

fn record_output_poi_recovery_failure(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    failure: RecoveryFailure,
    now: u64,
) {
    let status = failure.status;
    let message = failure.message;
    put_output_poi_recovery_record(
        db,
        cfg,
        candidate,
        now,
        OutputPoiRecoveryAction::Detected {
            status,
            retry_after: failure.retry_after,
            last_error: Some(message.clone()),
            increment_attempts: true,
        },
    );
    debug!(
        cache_key = %cfg.cache_key,
        status = ?status,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        error = %message,
        "output POI recovery skipped"
    );
}

fn put_output_poi_recovery_tx_input(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    tx_input: &Bytes,
    now: u64,
) {
    let existing = db
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.utxo.poi.commitment,
        )
        .ok()
        .flatten();
    let mut record = existing.unwrap_or_else(|| {
        new_output_poi_recovery_record(cfg, candidate, OutputPoiRecoveryStatus::Recoverable, now)
    });
    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: tx_input.to_vec(),
        },
        now,
    );
    if let Err(err) = db.put_output_poi_recovery(&record) {
        warn!(
            ?err,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "failed to persist output POI recovery transaction input"
        );
    }
}

fn put_output_poi_recovery_record(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    now: u64,
    action: OutputPoiRecoveryAction,
) {
    let existing = db
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.utxo.poi.commitment,
        )
        .ok()
        .flatten();
    let default_status = match &action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } => OutputPoiRecoveryStatus::Recoverable,
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut record = existing
        .unwrap_or_else(|| new_output_poi_recovery_record(cfg, candidate, default_status, now));
    record.apply_action(action, now);
    if let Err(err) = db.put_output_poi_recovery(&record) {
        warn!(
            ?err,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "failed to persist output POI recovery state"
        );
    }
}

fn mark_valid_output_poi_recoveries(
    db: &DbStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) {
    if active_list_keys.is_empty() {
        return;
    }
    let now = now_epoch_secs();
    for wallet_utxo in wallet_utxos.iter().filter(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.poi.is_valid_for_lists(active_list_keys)
            && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
    }) {
        let Ok(Some(mut record)) = db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        ) else {
            continue;
        };
        if record.status == OutputPoiRecoveryStatus::Valid {
            continue;
        }
        record.apply_action(OutputPoiRecoveryAction::Valid, now);
        if let Err(err) = db.put_output_poi_recovery(&record) {
            warn!(?err, cache_key = %cfg.cache_key, "failed to mark output POI recovery valid");
        }
    }
}

async fn refresh_wallet_poi_statuses_selected(
    client: &dyn PoiStatusReader,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    wallet_utxos: &mut [WalletUtxo],
    selection: WalletPoiRefreshSelection,
) -> bool {
    if active_list_keys.is_empty() {
        return false;
    }

    let started = Instant::now();
    let selection_label = selection.as_str();
    let unspent: Vec<_> = wallet_utxos
        .iter()
        .enumerate()
        .filter(|(_, wallet_utxo)| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
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

    debug!(
        chain_id,
        selection = selection_label,
        list_keys = active_list_keys.len(),
        commitments = unspent.len(),
        batch_size = WALLET_POI_STATUS_BATCH_SIZE,
        "wallet POI status refresh started"
    );
    let mut status_changes = 0usize;
    for (chunk_index, chunk) in unspent.chunks(WALLET_POI_STATUS_BATCH_SIZE).enumerate() {
        let request_data: Vec<_> = chunk.iter().map(|(_, data)| *data).collect();
        let chunk_started = Instant::now();
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
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                let refreshed_at = now_epoch_secs();
                for (index, data) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo.utxo.poi.apply_status_refresh(
                        active_list_keys,
                        statuses_by_blinded_commitment.get(&data.blinded_commitment),
                        refreshed_at,
                    );
                }
                debug!(
                    chain_id,
                    selection = selection_label,
                    chunk_index,
                    commitments = chunk.len(),
                    returned_commitments = statuses_by_blinded_commitment.len(),
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk complete"
                );
            }
            Err(error) => {
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                warn!(
                    ?error,
                    chain_id,
                    commitments = chunk.len(),
                    chunk_index,
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk failed; leaving statuses unknown"
                );
                for (index, _) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo
                        .utxo
                        .poi
                        .mark_statuses_unknown_for_lists(active_list_keys);
                }
            }
        }
    }
    let changed = status_changes > 0;
    debug!(
        chain_id,
        selection = selection_label,
        commitments = unspent.len(),
        status_changes,
        changed,
        elapsed_ms = started.elapsed().as_millis(),
        "wallet POI status refresh complete"
    );
    changed
}

pub(crate) fn wallet_poi_status_refresh_needed(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    wallet_poi_status_refresh_needed_for_selection(
        wallet_utxos,
        active_list_keys,
        WalletPoiRefreshSelection::Required,
    )
}

fn wallet_poi_status_refresh_needed_for_selection(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    selection: WalletPoiRefreshSelection,
) -> bool {
    !active_list_keys.is_empty()
        && wallet_utxos.iter().any(|wallet_utxo| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
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

pub(crate) struct WalletWorkerServices {
    pub db: Arc<DbStore>,
    pub rpcs: Arc<QueryRpcPool>,
    pub http_client: Option<reqwest::Client>,
    pub forest: Arc<RwLock<MerkleForest>>,
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
        let rev = self.rev_rx.borrow().wrapping_add(1);
        if let Err(err) = self.rev_tx.send(rev) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet revision");
        }
    }

    fn notify_if_changed(&self, changed: bool) {
        if changed {
            self.notify_changed();
        }
    }
}

#[derive(Default)]
struct WalletPersistState {
    needs_full_persist: bool,
    pending_cache_reset: Option<u64>,
}

impl WalletPersistState {
    fn persist_progress(
        &mut self,
        cache_store: &dyn WalletCacheStore,
        request: WalletProgressPersist<'_>,
    ) -> Result<bool, WalletCacheError> {
        if let Some(reset_last_scanned) = self.pending_cache_reset {
            let reset_started = Instant::now();
            cache_store.reset_wallet_cache(request.cache_key, reset_last_scanned)?;
            self.pending_cache_reset = None;
            self.needs_full_persist = true;
            debug!(
                cache_key = %request.cache_key,
                reset_last_scanned,
                elapsed_ms = reset_started.elapsed().as_millis(),
                "reset wallet cache before persisting progress"
            );
        }

        let full_persist = request.changed || self.needs_full_persist;
        if full_persist {
            let persist_started = Instant::now();
            return match cache_store.store_wallet_utxos(
                request.cache_key,
                request.snapshot,
                Some(request.last_scanned),
                request.last_scanned_block_hash,
            ) {
                Ok(()) => {
                    self.needs_full_persist = false;
                    debug!(
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "persisted wallet full snapshot"
                    );
                    Ok(true)
                }
                Err(err) => {
                    self.needs_full_persist = true;
                    debug!(
                        ?err,
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "failed to persist wallet full snapshot"
                    );
                    Err(err)
                }
            };
        }

        let meta_started = Instant::now();
        cache_store.update_wallet_meta(
            request.cache_key,
            request.last_scanned,
            request.last_scanned_block_hash,
        )?;
        debug!(
            cache_key = %request.cache_key,
            last_scanned = request.last_scanned,
            elapsed_ms = meta_started.elapsed().as_millis(),
            "persisted wallet metadata progress"
        );
        Ok(false)
    }
}

struct WalletLiveMetadataFlush {
    last_persisted_block: u64,
    last_persisted_at: Instant,
}

impl WalletLiveMetadataFlush {
    fn new(last_persisted_block: u64, now: Instant) -> Self {
        Self {
            last_persisted_block,
            last_persisted_at: now,
        }
    }

    fn should_flush(&self, last_scanned: u64, now: Instant) -> bool {
        last_scanned.saturating_sub(self.last_persisted_block) >= WALLET_METADATA_LIVE_FLUSH_BLOCKS
            || now.duration_since(self.last_persisted_at) >= WALLET_METADATA_LIVE_FLUSH_INTERVAL
    }

    fn mark_persisted(&mut self, last_persisted_block: u64, now: Instant) {
        self.last_persisted_block = last_persisted_block;
        self.last_persisted_at = now;
    }
}

struct WalletProgressPersist<'a> {
    cache_key: &'a str,
    snapshot: &'a [WalletUtxo],
    last_scanned: u64,
    last_scanned_block_hash: Option<[u8; 32]>,
    changed: bool,
}

#[derive(Default)]
struct WalletProgressPersistOutcome {
    persisted_full_snapshot: bool,
    persisted_progress: bool,
}

struct WalletSnapshotPersist<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    snapshot: &'a [WalletUtxo],
    last_scanned: u64,
    last_scanned_block_hash: Option<[u8; 32]>,
    changed: bool,
    persist_state: &'a mut WalletPersistState,
    live_metadata_flush: Option<&'a mut WalletLiveMetadataFlush>,
    error_message: &'static str,
}

struct WalletPoiStatusRefreshPersist<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    active_list_keys: &'a [FixedBytes<32>],
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    last_scanned: u64,
    persist_state: &'a mut WalletPersistState,
}

fn persist_wallet_snapshot(request: WalletSnapshotPersist<'_>) -> WalletProgressPersistOutcome {
    let WalletSnapshotPersist {
        cache_store,
        cfg,
        snapshot,
        last_scanned,
        last_scanned_block_hash,
        changed,
        persist_state,
        live_metadata_flush,
        error_message,
    } = request;

    match persist_state.persist_progress(
        cache_store,
        WalletProgressPersist {
            cache_key: &cfg.cache_key,
            snapshot,
            last_scanned,
            last_scanned_block_hash,
            changed,
        },
    ) {
        Ok(persisted_full_snapshot) => {
            if let Some(live_metadata_flush) = live_metadata_flush {
                live_metadata_flush.mark_persisted(last_scanned, Instant::now());
            }
            WalletProgressPersistOutcome {
                persisted_full_snapshot,
                persisted_progress: true,
            }
        }
        Err(err) => {
            warn!(?err, cache_key = %cfg.cache_key, "{error_message}");
            WalletProgressPersistOutcome::default()
        }
    }
}

async fn refresh_wallet_poi_statuses_and_persist(
    client: &dyn PoiStatusReader,
    persist: WalletPoiStatusRefreshPersist<'_>,
    selection: WalletPoiRefreshSelection,
) -> bool {
    let started = Instant::now();
    let selection_label = selection.as_str();
    let lock_wait_started = Instant::now();
    let mut locked = persist.utxos.write().await;
    let lock_wait_elapsed_ms = lock_wait_started.elapsed().as_millis();
    let changed = refresh_wallet_poi_statuses_selected(
        client,
        persist.cfg.chain.chain_id,
        persist.active_list_keys,
        &mut locked,
        selection,
    )
    .await;
    if !changed {
        debug!(
            cache_key = %persist.cfg.cache_key,
            selection = selection_label,
            changed,
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "wallet POI status refresh persistence skipped"
        );
        return false;
    }

    let persist_started = Instant::now();
    if let Err(err) = persist.persist_state.persist_progress(
        persist.cache_store,
        WalletProgressPersist {
            cache_key: &persist.cfg.cache_key,
            snapshot: &locked,
            last_scanned: persist.last_scanned,
            last_scanned_block_hash: None,
            changed: true,
        },
    ) {
        warn!(?err, cache_key = %persist.cfg.cache_key, "failed to persist wallet POI status refresh");
    }
    debug!(
        cache_key = %persist.cfg.cache_key,
        selection = selection_label,
        changed,
        rows = locked.len(),
        lock_wait_elapsed_ms,
        persist_elapsed_ms = persist_started.elapsed().as_millis(),
        elapsed_ms = started.elapsed().as_millis(),
        "wallet POI status refresh persisted"
    );
    true
}

struct OutputPoiRecoveryRun<'a> {
    db: &'a DbStore,
    cfg: &'a WalletConfig,
    rpcs: &'a QueryRpcPool,
    http_client: Option<&'a reqwest::Client>,
    forest: &'a Arc<RwLock<MerkleForest>>,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    client: &'a PoiRpcClient,
    active_list_keys: &'a [FixedBytes<32>],
    force_retry: bool,
}

async fn recover_missing_output_pois_from_wallet(run: OutputPoiRecoveryRun<'_>) -> usize {
    if run.cfg.spending_public_key.is_none() || run.cfg.poi_recovery_prover.is_none() {
        return 0;
    }
    let snapshot = run.utxos.read().await.clone();
    mark_valid_output_poi_recoveries(run.db, run.cfg, &snapshot, run.active_list_keys);
    if output_poi_recovery_candidates(&snapshot, run.active_list_keys).is_empty() {
        return 0;
    }
    let forest = run.forest.read().await.clone();
    recover_missing_output_pois(OutputPoiRecoveryRequest {
        db: run.db,
        cfg: run.cfg,
        rpcs: run.rpcs,
        http_client: run.http_client,
        forest: &forest,
        poi_client: run.client,
        submitter: run.client,
        active_list_keys: run.active_list_keys,
        wallet_utxos: &snapshot,
        force_retry: run.force_retry,
    })
    .await
}

fn set_poi_refreshing(sender: &watch::Sender<bool>, value: bool, cache_key: &str) {
    if let Err(err) = sender.send(value) {
        debug!(?err, cache_key, "failed to send wallet POI refresh state");
    }
}

pub(crate) fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> WalletHandle {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let WalletWorkerServices {
        db,
        rpcs,
        http_client,
        forest,
    } = services;
    let cache_store = wallet_cache_store(&db, &cfg);
    let (ready_tx, ready_rx) = watch::channel(false);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        utxos: utxos.clone(),
        ready_rx,
        rev_rx,
        poi_refreshing_rx,
        poi_refresh_tx,
        rev_tx,
    };

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    tokio::spawn(async move {
        let worker_started = Instant::now();
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
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(last_scanned, worker_started);
        let poi_status_client = wallet_poi_status_client();
        let active_poi_list_keys = default_active_poi_list_keys();

        if poi_status_client.is_some() {
            let locked = utxos.read().await;
            debug!(
                cache_key = %cfg.cache_key,
                poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys),
                "startup wallet POI status refresh deferred until wallet ready"
            );
        }

        let mut readiness_started = worker_started;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if backfill_complete_block.is_none() {
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh skipped until backfill complete"
                        );
                        continue;
                    }
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    let changed = refresh_wallet_poi_statuses_and_persist(
                        client,
                        WalletPoiStatusRefreshPersist {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            active_list_keys: &active_poi_list_keys,
                            utxos: &utxos,
                            last_scanned,
                            persist_state: &mut persist_state,
                        },
                        WalletPoiRefreshSelection::Recoverable,
                    ).await;
                    let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        db: db.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: refresh_request.force_output_poi_recovery,
                    }).await;
                    let force_submission_retry = refresh_request.force_output_poi_recovery && recovered == 0;
                    process_pending_output_poi_observations_inner(
                        db.as_ref(),
                        cfg.chain.chain_id,
                        &[],
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        force_submission_retry,
                    ).await;
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                    worker_handle.notify_if_changed(changed);
                }
                _ = tokio::time::sleep(WALLET_POI_REFRESH_INTERVAL), if poi_status_client.is_some() && backfill_complete_block.is_some() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    let now = now_epoch_secs();
                    let selection = WalletPoiRefreshSelection::RecoverableStale { now };
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            selection,
                        )
                    };
                    if !refresh_needed {
                        let snapshot = utxos.read().await.clone();
                        mark_valid_output_poi_recoveries(db.as_ref(), &cfg, &snapshot, &active_poi_list_keys);
                        process_pending_output_poi_observations_inner(
                            db.as_ref(),
                            cfg.chain.chain_id,
                            &[],
                            Some(client as &dyn PendingOutputPoiSubmitter),
                            false,
                        ).await;
                        continue;
                    }
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    let changed = refresh_wallet_poi_statuses_and_persist(
                        client,
                        WalletPoiStatusRefreshPersist {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            active_list_keys: &active_poi_list_keys,
                            utxos: &utxos,
                            last_scanned,
                            persist_state: &mut persist_state,
                        },
                        selection,
                    ).await;
                    recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        db: db.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: false,
                    }).await;
                    process_pending_output_poi_observations_inner(
                        db.as_ref(),
                        cfg.chain.chain_id,
                        &[],
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        false,
                    ).await;
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                    worker_handle.notify_if_changed(changed);
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::IndexedDelta { from_block, to_block, delta } => {
                            if to_block <= last_scanned {
                                continue;
                            }
                            let delta = *delta;
                            let delta_utxos = delta.utxos.len();
                            let delta_nullifiers = delta.nullifiers.len();
                            let commitment_observations = delta.commitment_observations.len();
                            debug!(
                                cache_key = %cfg.cache_key,
                                from_block,
                                to_block,
                                last_scanned,
                                delta_utxos,
                                delta_nullifiers,
                                commitment_observations,
                                "applying indexed wallet delta"
                            );
                            let poi_observation_started = Instant::now();
                            process_pending_output_poi_observations(
                                db.as_ref(),
                                cfg.chain.chain_id,
                                &delta.commitment_observations,
                                None,
                            )
                            .await;
                            let apply_started = Instant::now();
                            let outcome = apply_wallet_delta_with_outcome(&cfg, &utxos, delta).await;
                            discard_pending_output_poi_contexts_for_spent_outputs(
                                db.as_ref(),
                                cfg.chain.chain_id,
                                &outcome.spent_output_commitments,
                            );
                            let changed = outcome.changed;
                            last_scanned = to_block;
                            let snapshot = utxos.read().await;
                            let (unspent, spent) = wallet_utxo_counts(&snapshot);
                            let persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                snapshot: &snapshot,
                                last_scanned,
                                last_scanned_block_hash: None,
                                changed,
                                persist_state: &mut persist_state,
                                live_metadata_flush: Some(&mut live_metadata_flush),
                                error_message: "failed to persist indexed wallet cache",
                            });
                            debug!(
                                cache_key = %cfg.cache_key,
                                last_scanned,
                                total = snapshot.len(),
                                unspent,
                                spent,
                                changed,
                                poi_status_deferred = poi_status_client.is_some(),
                                persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                needs_full_persist = persist_state.needs_full_persist,
                                poi_observation_elapsed_ms = poi_observation_started.elapsed().as_millis(),
                                elapsed_ms = apply_started.elapsed().as_millis(),
                                "indexed wallet delta complete"
                            );
                            worker_handle.notify_if_changed(changed);
                        }
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
                            match apply_wallet_logs(db.as_ref(), None, &cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, changed)) => {
                                    last_scanned = updated_last_scanned;
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                        cache_store: cache_store.as_ref(),
                                        cfg: &cfg,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: batch.to_block_hash,
                                        changed,
                                        persist_state: &mut persist_state,
                                        live_metadata_flush: Some(&mut live_metadata_flush),
                                        error_message: "failed to persist wallet cache",
                                    });
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        poi_status_deferred = poi_status_client.is_some(),
                                        persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet backfill batch complete"
                                    );
                                    worker_handle.notify_if_changed(changed);
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
                                && let Err(err) = persist_state.persist_progress(
                                    cache_store.as_ref(),
                                    WalletProgressPersist {
                                        cache_key: &cfg.cache_key,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: None,
                                        changed: false,
                                    },
                                )
                            {
                                warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                            }
                            if should_persist {
                                live_metadata_flush.mark_persisted(last_scanned, Instant::now());
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
                                ready_elapsed_ms = readiness_started.elapsed().as_millis(),
                                worker_elapsed_ms = worker_started.elapsed().as_millis(),
                                "wallet backfill complete"
                            );
                            drop(snapshot);
                            tokio::task::yield_now().await;

                            if let Some(client) = poi_status_client.as_ref() {
                                let post_ready_poi_started = Instant::now();
                                process_pending_output_poi_observations(
                                    db.as_ref(),
                                    cfg.chain.chain_id,
                                    &[],
                                    Some(client as &dyn PendingOutputPoiSubmitter),
                                ).await;

                                let refresh_needed = {
                                    let locked = utxos.read().await;
                                    wallet_poi_status_refresh_needed_for_selection(
                                        &locked,
                                        &active_poi_list_keys,
                                        WalletPoiRefreshSelection::RequiredOrRecoverable,
                                    )
                                };
                                if refresh_needed {
                                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                                    let changed = refresh_wallet_poi_statuses_and_persist(
                                        client,
                                        WalletPoiStatusRefreshPersist {
                                            cache_store: cache_store.as_ref(),
                                            cfg: &cfg,
                                            active_list_keys: &active_poi_list_keys,
                                            utxos: &utxos,
                                            last_scanned,
                                            persist_state: &mut persist_state,
                                        },
                                        WalletPoiRefreshSelection::RequiredOrRecoverable,
                                    ).await;
                                    recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                        db: db.as_ref(),
                                        cfg: &cfg,
                                        rpcs: rpcs.as_ref(),
                                        http_client: http_client.as_ref(),
                                        forest: &forest,
                                        utxos: &utxos,
                                        client,
                                        active_list_keys: &active_poi_list_keys,
                                        force_retry: false,
                                    }).await;
                                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                                    worker_handle.notify_if_changed(changed);
                                    info!(
                                        cache_key = %cfg.cache_key,
                                        changed,
                                        elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                        "post-ready wallet POI status refresh complete"
                                    );
                                } else {
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                        "post-ready wallet POI status refresh not needed"
                                    );
                                }
                            }
                        }
                        BackfillEvent::Reset { from_block } => {
                            readiness_started = Instant::now();
                            let mut locked = utxos.write().await;
                            locked.clear();
                            last_scanned = from_block.saturating_sub(1);
                            match cache_store.reset_wallet_cache(&cfg.cache_key, last_scanned) {
                                Ok(()) => {
                                    persist_state.needs_full_persist = false;
                                    persist_state.pending_cache_reset = None;
                                    live_metadata_flush.mark_persisted(last_scanned, Instant::now());
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
                            if batch.logs.is_empty() {
                                last_scanned = batch.to_block;
                                let should_persist = persist_state.needs_full_persist
                                    || persist_state.pending_cache_reset.is_some()
                                    || live_metadata_flush
                                        .should_flush(last_scanned, Instant::now());
                                let mut persist_outcome = WalletProgressPersistOutcome::default();
                                if should_persist {
                                    let snapshot = utxos.read().await;
                                    persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                        cache_store: cache_store.as_ref(),
                                        cfg: &cfg,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: batch.to_block_hash,
                                        changed: false,
                                        persist_state: &mut persist_state,
                                        live_metadata_flush: Some(&mut live_metadata_flush),
                                        error_message: "failed to persist empty wallet live batch progress",
                                    });
                                }
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    last_scanned,
                                    metadata_persisted = persist_outcome.persisted_progress,
                                    persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                    needs_full_persist = persist_state.needs_full_persist,
                                    "wallet empty live batch complete"
                                );
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
                                        changed |= refresh_wallet_poi_statuses_selected(
                                            client,
                                            cfg.chain.chain_id,
                                            &active_poi_list_keys,
                                            &mut locked,
                                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                                        ).await;
                                    }
                                    if changed
                                        && let Some(client) = poi_status_client.as_ref()
                                    {
                                        recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                            db: db.as_ref(),
                                            cfg: &cfg,
                                            rpcs: rpcs.as_ref(),
                                            http_client: http_client.as_ref(),
                                            forest: &forest,
                                            utxos: &utxos,
                                            client,
                                            active_list_keys: &active_poi_list_keys,
                                            force_retry: false,
                                        }).await;
                                    }
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let should_persist = changed
                                        || persist_state.needs_full_persist
                                        || persist_state.pending_cache_reset.is_some()
                                        || live_metadata_flush
                                            .should_flush(last_scanned, Instant::now());
                                    let mut persist_outcome = WalletProgressPersistOutcome::default();
                                    if should_persist {
                                        persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                            cache_store: cache_store.as_ref(),
                                            cfg: &cfg,
                                            snapshot: &snapshot,
                                            last_scanned,
                                            last_scanned_block_hash: batch.to_block_hash,
                                            changed,
                                            persist_state: &mut persist_state,
                                            live_metadata_flush: Some(&mut live_metadata_flush),
                                            error_message: "failed to persist wallet cache",
                                        });
                                    }
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        metadata_persisted = persist_outcome.persisted_progress,
                                        persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet live batch complete"
                                    );
                                    worker_handle.notify_if_changed(changed);
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
        DEFAULT_TXID_VERSION, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, PendingOutputPoiSubmitter, PoiStatusReader,
        RecoveryGraphRailgunTransaction, WALLET_METADATA_LIVE_FLUSH_BLOCKS,
        WALLET_METADATA_LIVE_FLUSH_INTERVAL, WALLET_POI_RECOVERABLE_REFRESH_AFTER,
        WALLET_POI_STATUS_BATCH_SIZE, WalletHandle, WalletLiveMetadataFlush, WalletPersistState,
        WalletPoiRefreshRequest, WalletPoiRefreshSelection, WalletProgressPersist,
        apply_wallet_delta_to_vec, apply_wallet_delta_to_vec_with_outcome,
        discard_pending_output_poi_contexts_for_spent_outputs, output_poi_recovery_candidates,
        output_poi_recovery_proof_retry_after, output_start_global_position,
        pending_output_poi_submit_identity, process_pending_output_poi_observations,
        process_pending_output_poi_observations_inner, recovery_leaf_count_for_merkle_root,
        refresh_wallet_poi_statuses_selected, spent_source_for_utxo,
        wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
    };
    use crate::types::{ChainKey, WalletCacheStore, WalletConfig};
    use alloy::primitives::{Address, Bytes, FixedBytes, U64, U256};
    use alloy::uint;
    use async_trait::async_trait;
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use broadcaster_core::transact::{PreTxPoi, SnarkJsProof, railgun_txid_leaf_hash};
    use broadcaster_core::tree::TREE_LEAF_COUNT;
    use local_db::{
        DbConfig, DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord,
        OutputPoiRecoveryStatus, PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletMeta,
    };
    use merkletree::tree::{MerkleForest, MerkleTreeUpdate};
    use poi::error::PoiError;
    use poi::poi::{BlindedCommitmentData, SingleCommitmentProofContext};
    use railgun_wallet::scan::{CommitmentObservation, SpentNullifier, WalletLogDelta};
    use railgun_wallet::wallet_cache::WalletCacheError;
    use railgun_wallet::{
        PoiStatus, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource, WalletUtxo,
    };
    use railgun_wallet::{prover::ProverError, tx::PreTransactionPoiError};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::{RwLock, mpsc, watch};

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
            quick_sync_endpoint: None,
            scan_keys: ViewingKeyData {
                viewing_private_key: [0u8; 32],
                viewing_public_key: [0u8; 32],
                nullifying_key,
                master_public_key: U256::ZERO,
            },
            spending_public_key: None,
            progress_tx: None,
            cache_store: None,
            poi_recovery_prover: None,
            use_indexed_wallet_catch_up: true,
        }
    }

    fn test_wallet_utxo(position: u64) -> WalletUtxo {
        test_wallet_utxo_with_kind(position, UtxoCommitmentKind::Transact)
    }

    fn test_wallet_utxo_with_kind(position: u64, kind: UtxoCommitmentKind) -> WalletUtxo {
        WalletUtxo::new(Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
            },
            2,
            position,
            source((position % 200) as u8 + 1),
            kind,
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

        async fn submit_transact_proof(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            _list_key: &FixedBytes<32>,
            txid_merkleroot_index: u64,
            poi: &PreTxPoi,
        ) -> Result<(), PoiError> {
            self.calls.lock().expect("submission calls").push((
                poi.blinded_commitments_out
                    .first()
                    .copied()
                    .unwrap_or_default(),
                txid_merkleroot_index,
                0,
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
            railgun_txid: uint!(7_U256),
            txid_merkleroot_index: None,
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

    fn output_poi_recovery_record(
        chain_id: u64,
        wallet_id: &str,
        output_commitment: FixedBytes<32>,
        status: OutputPoiRecoveryStatus,
        next_retry_at: Option<u64>,
    ) -> OutputPoiRecoveryRecord {
        OutputPoiRecoveryRecord {
            chain_id,
            wallet_id: wallet_id.to_string(),
            output_commitment,
            source_tx_hash: FixedBytes::from([0x99; 32]),
            tx_input: None,
            status,
            created_at: 1,
            updated_at: 1,
            last_detection_at: Some(1),
            last_submission_at: None,
            next_retry_at,
            attempt_count: 0,
            last_error: None,
        }
    }

    #[test]
    fn output_poi_recovery_action_caches_tx_input_without_resetting_state() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            Some(20),
        );
        record.attempt_count = 3;
        record.last_error = Some("previous".to_string());

        record.apply_action(
            OutputPoiRecoveryAction::CacheTxInput {
                tx_input: vec![0xde, 0xad],
            },
            10,
        );

        assert_eq!(record.tx_input, Some(vec![0xde, 0xad]));
        assert_eq!(
            record.status,
            OutputPoiRecoveryStatus::ProofGenerationFailed
        );
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_detection_at, Some(10));
        assert_eq!(record.next_retry_at, Some(20));
        assert_eq!(record.attempt_count, 3);
        assert_eq!(record.last_error.as_deref(), Some("previous"));
    }

    #[test]
    fn output_poi_recovery_action_records_detected_failure() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );

        record.apply_action(
            OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::DecodeFailed,
                retry_after: Some(Duration::from_secs(30)),
                last_error: Some("decode failed".to_string()),
                increment_attempts: true,
            },
            10,
        );

        assert_eq!(record.status, OutputPoiRecoveryStatus::DecodeFailed);
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_detection_at, Some(10));
        assert_eq!(record.next_retry_at, Some(40));
        assert_eq!(record.attempt_count, 1);
        assert_eq!(record.last_error.as_deref(), Some("decode failed"));
    }

    #[test]
    fn output_poi_recovery_action_records_recovered_context() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            Some(20),
        );
        record.attempt_count = 2;
        record.last_error = Some("old".to_string());

        record.apply_action(
            OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            10,
        );

        assert_eq!(record.status, OutputPoiRecoveryStatus::Recoverable);
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_detection_at, Some(10));
        assert_eq!(record.next_retry_at, None);
        assert_eq!(record.attempt_count, 2);
        assert_eq!(record.last_error, None);
    }

    #[test]
    fn output_poi_recovery_action_records_submit_success() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );
        record.last_error = Some("old".to_string());

        record.apply_action(
            OutputPoiRecoveryAction::Submitted {
                retry_after: Duration::from_secs(60),
            },
            10,
        );

        assert_eq!(record.status, OutputPoiRecoveryStatus::Submitted);
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_submission_at, Some(10));
        assert_eq!(record.next_retry_at, Some(70));
        assert_eq!(record.attempt_count, 1);
        assert_eq!(record.last_error, None);
    }

    #[test]
    fn output_poi_recovery_action_records_submit_failure() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );

        record.apply_action(
            OutputPoiRecoveryAction::SubmitFailed {
                error: "submit failed".to_string(),
                retry_after: Duration::from_secs(60),
            },
            10,
        );

        assert_eq!(record.status, OutputPoiRecoveryStatus::SubmitFailed);
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_submission_at, None);
        assert_eq!(record.next_retry_at, Some(70));
        assert_eq!(record.attempt_count, 1);
        assert_eq!(record.last_error.as_deref(), Some("submit failed"));
    }

    #[test]
    fn output_poi_recovery_action_marks_valid_without_touching_history() {
        let mut record = output_poi_recovery_record(
            1,
            "wallet",
            FixedBytes::from([0x44; 32]),
            OutputPoiRecoveryStatus::Submitted,
            Some(20),
        );
        record.last_detection_at = Some(4);
        record.last_submission_at = Some(5);
        record.attempt_count = 2;
        record.last_error = Some("old".to_string());

        record.apply_action(OutputPoiRecoveryAction::Valid, 10);

        assert_eq!(record.status, OutputPoiRecoveryStatus::Valid);
        assert_eq!(record.updated_at, 10);
        assert_eq!(record.last_detection_at, Some(4));
        assert_eq!(record.last_submission_at, Some(5));
        assert_eq!(record.next_retry_at, None);
        assert_eq!(record.attempt_count, 2);
        assert_eq!(record.last_error, None);
    }

    #[test]
    fn pending_output_submit_identity_derives_status_query_blinded_commitment() {
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x77; 32]);
        let list_key = FixedBytes::from([0x11; 32]);
        let record = pending_output_record(chain_id, output_commitment, list_key);
        let observation = local_db::PendingOutputPoiObservation {
            output_tree: 3,
            output_position: 42,
            tx_hash: source(11).tx_hash,
            block_number: 11,
            block_timestamp: 1_700_000_011,
        };

        let identity =
            pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

        assert_eq!(
            identity.derived_blinded_commitment,
            UtxoPoiMetadata::blinded_commitment_for(
                record.output_commitment,
                record.output_npk,
                observation.output_tree as u32,
                observation.output_position,
            )
        );
    }

    #[test]
    fn pending_output_submit_identity_uses_included_txid_leaf_for_recovery() {
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x77; 32]);
        let list_key = FixedBytes::from([0x11; 32]);
        let included_txid_leaf = FixedBytes::from([0x99; 32]);
        let mut record = pending_output_record(chain_id, output_commitment, list_key);
        let dummy_txid_leaf = FixedBytes::from(
            railgun_txid_leaf_hash(record.railgun_txid, record.utxo_tree_in).to_be_bytes::<32>(),
        );
        record.txid_merkleroot_index = Some(105_572);
        record.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
            list_key,
            BTreeMap::from([(included_txid_leaf, sample_pre_tx_poi(0x10))]),
        )]);
        let observation = local_db::PendingOutputPoiObservation {
            output_tree: 3,
            output_position: 42,
            tx_hash: source(11).tx_hash,
            block_number: 11,
            block_timestamp: 1_700_000_011,
        };

        let identity =
            pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

        assert_eq!(identity.txid_leaf_hash, included_txid_leaf);
        assert_ne!(identity.txid_leaf_hash, dummy_txid_leaf);
    }

    #[test]
    fn output_start_global_position_handles_nonzero_output_index_across_tree_boundary() {
        let utxo = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
            },
            3,
            1,
            source(17),
            UtxoCommitmentKind::Transact,
        );

        let start_global = output_start_global_position(&utxo, 2).expect("start global");

        assert_eq!(start_global / u128::from(TREE_LEAF_COUNT), 2);
        assert_eq!(start_global % u128::from(TREE_LEAF_COUNT), 65_535);
        assert_eq!(
            start_global,
            u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position) - 2
        );
    }

    #[test]
    fn recovered_graph_output_start_matches_local_output_start_global() {
        let utxo = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
            },
            3,
            1,
            source(18),
            UtxoCommitmentKind::Transact,
        );
        let local_start = output_start_global_position(&utxo, 2).expect("local start");
        let graph_transaction = RecoveryGraphRailgunTransaction {
            id: "tx-1".to_string(),
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            bound_params_hash: U256::ZERO,
            utxo_tree_in: U64::from(2_u8),
            utxo_tree_out: U64::from(2_u8),
            utxo_batch_start_position_out: U64::from(65_535_u64),
        };

        let graph_start = graph_transaction.output_start_global();

        assert_eq!(graph_start, local_start);
    }

    #[test]
    fn recovery_graph_transaction_deserializes_typed_scalars() {
        let transaction: RecoveryGraphRailgunTransaction =
            serde_json::from_value(serde_json::json!({
                "id": "tx-1",
                "nullifiers": ["0x0a"],
                "commitments": ["0x0b"],
                "boundParamsHash": "0x0c",
                "utxoTreeIn": "2",
                "utxoTreeOut": "0x3",
                "utxoBatchStartPositionOut": "65535",
            }))
            .expect("deserialize graph transaction");

        assert_eq!(transaction.nullifiers, vec![uint!(10_U256)]);
        assert_eq!(transaction.commitments, vec![uint!(11_U256)]);
        assert_eq!(transaction.bound_params_hash, uint!(12_U256));
        assert_eq!(transaction.utxo_tree_in, U64::from(2_u8));
        assert_eq!(transaction.utxo_tree_out, U64::from(3_u8));
        assert_eq!(
            transaction.utxo_batch_start_position_out,
            U64::from(65_535_u64)
        );
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
    fn live_metadata_flush_waits_for_interval_or_block_threshold() {
        let now = Instant::now();
        let flush = WalletLiveMetadataFlush::new(100, now);

        assert!(!flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1, now));
        assert!(flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS, now));
        assert!(flush.should_flush(101, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
    }

    #[test]
    fn live_metadata_flush_mark_persisted_resets_thresholds() {
        let now = Instant::now();
        let mut flush = WalletLiveMetadataFlush::new(100, now);

        flush.mark_persisted(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL);

        assert!(!flush.should_flush(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
        assert!(!flush.should_flush(
            125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1,
            now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
        ));
        assert!(flush.should_flush(
            125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS,
            now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
        ));
    }

    #[test]
    fn recovery_leaf_count_search_finds_root_before_later_commitments() {
        let first_input = test_wallet_utxo(0);
        let mut forest_before_later = MerkleForest::new();
        forest_before_later
            .insert_leaf(MerkleTreeUpdate {
                tree_number: first_input.utxo.tree,
                tree_position: first_input.utxo.position,
                hash: first_input.utxo.note.commitment(),
            })
            .expect("insert input leaf");
        let expected_root = forest_before_later
            .prove_with_leaf_count(first_input.utxo.tree, first_input.utxo.position, 1)
            .expect("historical proof")
            .root;

        let mut forest_after_later = forest_before_later;
        forest_after_later
            .insert_leaf(MerkleTreeUpdate {
                tree_number: first_input.utxo.tree,
                tree_position: 1,
                hash: uint!(12_U256),
            })
            .expect("insert later leaf");
        forest_after_later
            .insert_leaf(MerkleTreeUpdate {
                tree_number: first_input.utxo.tree,
                tree_position: 2,
                hash: uint!(13_U256),
            })
            .expect("insert second later leaf");

        let leaf_count = recovery_leaf_count_for_merkle_root(
            &forest_after_later,
            first_input.utxo.tree,
            &first_input,
            3,
            expected_root,
        )
        .expect("find historical leaf count");

        assert_eq!(leaf_count, 1);
    }

    #[test]
    fn output_poi_recovery_proof_panic_uses_long_backoff() {
        let panic_err =
            PreTransactionPoiError::Prover(ProverError::WorkerPanic("boom".to_string()));
        assert_eq!(
            output_poi_recovery_proof_retry_after(&panic_err),
            OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER
        );

        let transient_err = PreTransactionPoiError::InputCountMismatch {
            expected: 1,
            got: 0,
        };
        assert_eq!(
            output_poi_recovery_proof_retry_after(&transient_err),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER
        );
    }

    #[tokio::test]
    async fn poi_status_refresh_chunks_unspent_utxos() {
        let client = RecordingPoiStatusClient::default();
        let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
        let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
            .map(|position| test_wallet_utxo(position as u64))
            .collect::<Vec<_>>();

        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            1,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
        .await;

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

        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            cfg.chain.chain_id,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
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

    #[test]
    fn stale_missing_poi_status_is_refresh_needed_after_ttl() {
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut wallet_utxo = test_wallet_utxo(1);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        wallet_utxo.utxo.poi.refreshed_at = Some(100);
        let wallet_utxos = vec![wallet_utxo];

        assert!(!wallet_poi_status_refresh_needed_for_selection(
            &wallet_utxos,
            &list_keys,
            WalletPoiRefreshSelection::RecoverableStale {
                now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs() - 1,
            },
        ));
        assert!(wallet_poi_status_refresh_needed_for_selection(
            &wallet_utxos,
            &list_keys,
            WalletPoiRefreshSelection::RecoverableStale {
                now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
            },
        ));
    }

    #[test]
    fn stale_transact_missing_without_pending_context_is_timer_retryable() {
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Transact);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        wallet_utxo.utxo.poi.refreshed_at = Some(100);
        let wallet_utxos = vec![wallet_utxo];

        assert!(wallet_poi_status_refresh_needed_for_selection(
            &wallet_utxos,
            &list_keys,
            WalletPoiRefreshSelection::RecoverableStale {
                now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
            },
        ));
    }

    #[test]
    fn stale_shield_missing_remains_timer_retryable_without_pending_context() {
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        wallet_utxo.utxo.poi.refreshed_at = Some(100);
        let wallet_utxos = vec![wallet_utxo];

        assert!(wallet_poi_status_refresh_needed_for_selection(
            &wallet_utxos,
            &list_keys,
            WalletPoiRefreshSelection::RecoverableStale {
                now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
            },
        ));
    }

    #[tokio::test]
    async fn forced_recoverable_poi_refresh_batches_missing_utxos() {
        let client = RecordingPoiStatusClient::default();
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut valid = test_wallet_utxo(0);
        valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
        valid.utxo.poi.refreshed_at = Some(100);
        let mut missing_one = test_wallet_utxo(1);
        missing_one
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        missing_one.utxo.poi.refreshed_at = Some(100);
        let mut missing_two = test_wallet_utxo(2);
        missing_two
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        missing_two.utxo.poi.refreshed_at = Some(100);
        let mut wallet_utxos = vec![valid, missing_one, missing_two];

        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            1,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::Recoverable,
        )
        .await;

        assert!(changed);
        let calls = client.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.len(), 2);
        assert!(
            wallet_utxos
                .iter()
                .all(|wallet_utxo| wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys))
        );
    }

    #[tokio::test]
    async fn required_or_recoverable_poi_refresh_skips_currently_valid_utxos() {
        let client = RecordingPoiStatusClient::default();
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut valid = test_wallet_utxo(0);
        valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
        valid.utxo.poi.refreshed_at = Some(100);
        let mut valid_without_refresh_time = test_wallet_utxo(1);
        valid_without_refresh_time
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Valid);
        let mut missing = test_wallet_utxo(2);
        missing
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        missing.utxo.poi.refreshed_at = Some(100);
        let mut wallet_utxos = vec![valid, valid_without_refresh_time, missing];

        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            1,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
        .await;

        assert!(changed);
        let calls = client.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.len(), 2);
        assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, Some(100));
        assert!(wallet_utxos[1].utxo.poi.refreshed_at.is_some());
        assert_eq!(
            wallet_utxos[2].utxo.poi.statuses.get(&list_key),
            Some(&PoiStatus::Valid)
        );
    }

    #[tokio::test]
    async fn poi_status_refresh_timestamp_only_update_is_changed() {
        let client = RecordingPoiStatusClient::default();
        let list_key = FixedBytes::from([0x11; 32]);
        let list_keys = vec![list_key];
        let mut valid_without_refresh_time = test_wallet_utxo(1);
        valid_without_refresh_time
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Valid);
        let mut wallet_utxos = vec![valid_without_refresh_time];

        assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            1,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
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

        let changed = refresh_wallet_poi_statuses_selected(
            &client,
            1,
            &list_keys,
            &mut wallet_utxos,
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
        .await;

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
    async fn recovered_pending_output_poi_uses_transact_proof_submission() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x79; 32]);
        let list_key = FixedBytes::from([0x47; 32]);
        let mut record = pending_output_record(chain_id, output_commitment, list_key);
        record.txid_merkleroot_index = Some(105_572);
        let expected_blinded_commitment = record
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&list_key)
            .expect("list")
            .values()
            .next()
            .expect("poi")
            .blinded_commitments_out[0];
        store
            .put_pending_output_poi_context(&record)
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
        assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
        assert_eq!(
            submitter.calls(),
            vec![(expected_blinded_commitment, 105_572, 0)]
        );

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

    #[tokio::test]
    async fn recovered_output_poi_context_resubmits_after_retry_time() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x79; 32]);
        let list_key = FixedBytes::from([0x47; 32]);
        let mut pending = pending_output_record(chain_id, output_commitment, list_key);
        pending.observation = Some(local_db::PendingOutputPoiObservation {
            output_tree: 14,
            output_position: 36,
            tx_hash: source(11).tx_hash,
            block_number: 11,
            block_timestamp: 1_700_000_011,
        });
        pending.submitted_poi_list_keys = vec![list_key];
        store
            .put_pending_output_poi_context(&pending)
            .expect("store pending context");
        store
            .put_output_poi_recovery(&output_poi_recovery_record(
                chain_id,
                &pending.wallet_id,
                output_commitment,
                OutputPoiRecoveryStatus::Submitted,
                Some(0),
            ))
            .expect("store recovery state");
        let submitter = RecordingPendingOutputPoiSubmitter::default();

        process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;

        let loaded = store
            .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
            .expect("load recovery state")
            .expect("recovery state present");
        assert_eq!(loaded.status, OutputPoiRecoveryStatus::Submitted);
        assert!(loaded.last_submission_at.is_some());
        assert!(loaded.next_retry_at.is_some_and(|next| next > 0));
        assert_eq!(submitter.calls(), vec![(output_commitment, 14, 36)]);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn recovered_output_poi_context_resubmits_when_forced_before_retry_time() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x7a; 32]);
        let list_key = FixedBytes::from([0x48; 32]);
        let mut pending = pending_output_record(chain_id, output_commitment, list_key);
        pending.observation = Some(local_db::PendingOutputPoiObservation {
            output_tree: 15,
            output_position: 37,
            tx_hash: source(12).tx_hash,
            block_number: 12,
            block_timestamp: 1_700_000_012,
        });
        pending.submitted_poi_list_keys = vec![list_key];
        store
            .put_pending_output_poi_context(&pending)
            .expect("store pending context");
        store
            .put_output_poi_recovery(&output_poi_recovery_record(
                chain_id,
                &pending.wallet_id,
                output_commitment,
                OutputPoiRecoveryStatus::Submitted,
                Some(u64::MAX),
            ))
            .expect("store recovery state");
        let submitter = RecordingPendingOutputPoiSubmitter::default();

        process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;
        assert!(submitter.calls().is_empty());

        process_pending_output_poi_observations_inner(
            &store,
            chain_id,
            &[],
            Some(&submitter),
            true,
        )
        .await;

        assert_eq!(submitter.calls(), vec![(output_commitment, 15, 37)]);

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn output_poi_recovery_retry_skips_permanent_statuses() {
        let due = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x80; 32]),
            OutputPoiRecoveryStatus::Submitted,
            Some(10),
        );
        assert!(due.retry_allowed(11, false));

        let not_self = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x81; 32]),
            OutputPoiRecoveryStatus::NotSelfOriginated,
            Some(0),
        );
        assert!(!not_self.retry_allowed(11, false));

        let missing_inputs = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x82; 32]),
            OutputPoiRecoveryStatus::MissingWalletInputs,
            None,
        );
        assert!(!missing_inputs.retry_allowed(11, false));

        let valid = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x83; 32]),
            OutputPoiRecoveryStatus::Valid,
            Some(0),
        );
        assert!(!valid.retry_allowed(11, false));
    }

    #[test]
    fn forced_output_poi_recovery_retry_ignores_future_retry_for_retryable_status() {
        let future = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x83; 32]),
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            Some(999_999),
        );
        assert!(!future.retry_allowed(11, false));
        assert!(future.retry_allowed(11, true));

        let not_self = output_poi_recovery_record(
            1,
            "wallet-1",
            FixedBytes::from([0x84; 32]),
            OutputPoiRecoveryStatus::NotSelfOriginated,
            Some(0),
        );
        assert!(!not_self.retry_allowed(11, true));
    }

    #[test]
    fn failed_full_persist_forces_next_no_change_batch_to_store_snapshot() {
        let cache_store = RecordingCacheStore::default();
        cache_store.fail_next_store();
        let snapshot = Vec::new();
        let mut persist_state = WalletPersistState::default();

        assert!(
            persist_state
                .persist_progress(
                    &cache_store,
                    WalletProgressPersist {
                        cache_key: "wallet",
                        snapshot: &snapshot,
                        last_scanned: 10,
                        last_scanned_block_hash: None,
                        changed: true,
                    },
                )
                .is_err()
        );
        assert!(persist_state.needs_full_persist);
        assert_eq!(cache_store.state().store_calls, 1);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_state
            .persist_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 11,
                    last_scanned_block_hash: None,
                    changed: false,
                },
            )
            .expect("retry full persist");
        assert!(persisted_full_snapshot);
        assert!(!persist_state.needs_full_persist);
        assert_eq!(cache_store.state().store_calls, 2);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_state
            .persist_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 12,
                    last_scanned_block_hash: None,
                    changed: false,
                },
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
            persist_state
                .persist_progress(
                    &cache_store,
                    WalletProgressPersist {
                        cache_key: "wallet",
                        snapshot: &snapshot,
                        last_scanned: 10,
                        last_scanned_block_hash: None,
                        changed: false,
                    },
                )
                .is_err()
        );
        assert_eq!(persist_state.pending_cache_reset, Some(9));
        assert_eq!(cache_store.state().reset_calls, 1);
        assert_eq!(cache_store.state().store_calls, 0);
        assert_eq!(cache_store.state().meta_calls, 0);

        let persisted_full_snapshot = persist_state
            .persist_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: false,
                },
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
    fn notify_changed_increments_revision() {
        let (ready_tx, ready_rx) = watch::channel(false);
        drop(ready_tx);
        let (rev_tx, rev_rx) = watch::channel(0_u64);
        let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
        let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
        let handle = WalletHandle {
            cache_key: "cache-key".to_string(),
            utxos: Arc::new(RwLock::new(Vec::new())),
            ready_rx,
            rev_rx,
            poi_refreshing_rx,
            poi_refresh_tx,
            rev_tx,
        };

        handle.notify_changed();
        assert_eq!(*handle.rev_rx.borrow(), 1);

        handle.notify_changed();
        assert_eq!(*handle.rev_rx.borrow(), 2);
    }

    #[tokio::test]
    async fn wallet_handle_manual_poi_refresh_sends_forced_recovery_request() {
        let (ready_tx, ready_rx) = watch::channel(false);
        drop(ready_tx);
        let (rev_tx, rev_rx) = watch::channel(0_u64);
        let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel::<WalletPoiRefreshRequest>(1);
        let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
        let handle = WalletHandle {
            cache_key: "cache-key".to_string(),
            utxos: Arc::new(RwLock::new(Vec::new())),
            ready_rx,
            rev_rx,
            poi_refreshing_rx,
            poi_refresh_tx,
            rev_tx,
        };

        assert!(handle.refresh_poi_statuses().await);

        let request = poi_refresh_rx.recv().await.expect("refresh request");
        assert!(request.force_output_poi_recovery);
    }

    #[test]
    fn spent_nullifiers_are_scoped_by_tree() {
        let nullifying_key = uint!(42_U256);
        let utxo_tree_one = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
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
        let nullifying_key = uint!(42_U256);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
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
    fn indexed_delta_reports_spent_output_commitment() {
        let nullifying_key = uint!(42_U256);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
            },
            2,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        );
        let output_commitment = utxo.poi.commitment;
        let nullifier = utxo.nullifier(nullifying_key);
        let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
        let delta = WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: 2,
                nullifier,
                source: source(9),
            }],
            commitment_observations: Vec::new(),
        };

        let outcome = apply_wallet_delta_to_vec_with_outcome(&cfg, &mut wallet_utxos, delta);

        assert!(outcome.changed);
        assert_eq!(outcome.spent_output_commitments, vec![output_commitment]);
    }

    #[test]
    fn spent_output_discards_pending_output_poi_context() {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let chain_id = 1;
        let output_commitment = FixedBytes::from([0x91; 32]);
        store
            .put_pending_output_poi_context(&pending_output_record(
                chain_id,
                output_commitment,
                FixedBytes::from([0x92; 32]),
            ))
            .expect("store pending context");

        discard_pending_output_poi_contexts_for_spent_outputs(
            &store,
            chain_id,
            &[output_commitment],
        );

        assert!(
            store
                .get_pending_output_poi_context(chain_id, &output_commitment)
                .expect("load pending context")
                .is_none()
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn output_poi_recovery_candidates_skip_spent_utxos() {
        let list_key = FixedBytes::from([0x93; 32]);
        let mut spent = test_wallet_utxo(7);
        spent.utxo.poi.statuses.insert(list_key, PoiStatus::Missing);
        spent.spent = Some(source(9));
        let mut unspent = test_wallet_utxo(8);
        unspent
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        let wallet_utxos = vec![spent, unspent];

        let candidates = output_poi_recovery_candidates(&wallet_utxos, &[list_key]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].utxo.position, 8);
    }

    #[test]
    fn indexed_delta_preserves_unmatched_utxo() {
        let nullifying_key = uint!(42_U256);
        let cfg = wallet_config(nullifying_key);
        let utxo = Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                value: uint!(10_U256),
                random: [0u8; 16],
                npk: uint!(2_U256),
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
