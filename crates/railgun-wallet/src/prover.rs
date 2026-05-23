use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use alloy::primitives::U256;
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomReduction, WitnessCalculator};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, prepare_verifying_key};
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use wasmer::Store;

use crate::artifacts::{ArtifactError, ArtifactSource, poi_variant_name, variant_name};
use crate::tx::{PoiProofInputs, PrivateInputs, PublicInputs};
use crate::wasm_module_cache::{load_or_compile_wasm_module, wasm_module_cache_exists};
use crate::zkey_cache::{load_or_parse_zkey, zkey_cache_exists};
use broadcaster_core::contracts::railgun::{G1Point, G2Point, SnarkProof};
use broadcaster_core::crypto::ark_utils::prime_field_to_u256;
use broadcaster_core::transact::{MERKLE_ZERO_VALUE, SnarkJsProof};
use broadcaster_core::tree::TREE_DEPTH;
use local_db::{DbConfig, DbStore};

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("zkey parse failed: {0}")]
    Zkey(String),
    #[error("wasm module failed: {0}")]
    WasmModule(String),
    #[error("witness generation failed: {0}")]
    Witness(#[from] color_eyre::Report),
    #[error("proof generation failed: {0}")]
    Prove(#[from] SynthesisError),
    #[error("proof verification failed")]
    InvalidProof,
    #[error("proof verification error: {0}")]
    Verify(String),
    #[error("proof queue closed")]
    QueueClosed,
    #[error("proof worker dropped")]
    WorkerDropped,
    #[error("proof worker panicked: {0}")]
    WorkerPanic(String),
    #[error("prover cache build failed for all {total_variants} variants")]
    CacheBuildFailed { total_variants: usize },
}

#[derive(Debug, Clone)]
struct CircuitWitnessInputs {
    values: BTreeMap<String, Vec<BigInt>>,
}

#[derive(Debug, Clone)]
pub struct RailgunWitnessInputs {
    inner: CircuitWitnessInputs,
}

#[derive(Debug, Clone)]
struct PoiWitnessInputs {
    inner: CircuitWitnessInputs,
}

impl CircuitWitnessInputs {
    fn new(values: BTreeMap<String, Vec<BigInt>>) -> Self {
        Self { values }
    }

    fn to_hex_map(&self) -> BTreeMap<String, Vec<String>> {
        self.values
            .iter()
            .map(|(k, v)| {
                let values = v.iter().map(|value| format!("{value:#x}")).collect();
                (k.clone(), values)
            })
            .collect()
    }
}

impl RailgunWitnessInputs {
    #[must_use]
    pub fn new(
        public_inputs: &PublicInputs,
        private_inputs: &PrivateInputs,
        signature: &[U256; 3],
    ) -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            "merkleRoot".to_string(),
            vec![public_inputs.merkle_root.into()],
        );
        values.insert(
            "boundParamsHash".to_string(),
            vec![public_inputs.bound_params_hash.into()],
        );
        values.insert(
            "nullifiers".to_string(),
            public_inputs.nullifiers.iter().map(BigInt::from).collect(),
        );
        values.insert(
            "commitmentsOut".to_string(),
            public_inputs
                .commitments_out
                .iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "token".to_string(),
            vec![private_inputs.token_address.into()],
        );
        values.insert(
            "publicKey".to_string(),
            private_inputs.public_key.iter().map(BigInt::from).collect(),
        );
        values.insert(
            "signature".to_string(),
            signature.iter().copied().map(BigInt::from).collect(),
        );
        values.insert(
            "randomIn".to_string(),
            private_inputs.random_in.iter().map(BigInt::from).collect(),
        );
        values.insert(
            "valueIn".to_string(),
            private_inputs.value_in.iter().map(BigInt::from).collect(),
        );
        values.insert(
            "pathElements".to_string(),
            private_inputs
                .path_elements
                .iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "leavesIndices".to_string(),
            private_inputs
                .leaves_indices
                .iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "nullifyingKey".to_string(),
            vec![private_inputs.nullifying_key.into()],
        );
        values.insert(
            "npkOut".to_string(),
            private_inputs.npk_out.iter().map(BigInt::from).collect(),
        );
        values.insert(
            "valueOut".to_string(),
            private_inputs.value_out.iter().map(BigInt::from).collect(),
        );

        Self {
            inner: CircuitWitnessInputs::new(values),
        }
    }

    #[must_use]
    pub fn to_hex_map(&self) -> BTreeMap<String, Vec<String>> {
        self.inner.to_hex_map()
    }
}

impl From<RailgunWitnessInputs> for BTreeMap<String, Vec<BigInt>> {
    fn from(inputs: RailgunWitnessInputs) -> Self {
        inputs.inner.into()
    }
}

impl PoiWitnessInputs {
    #[must_use]
    pub fn new(inputs: &PoiProofInputs, max_inputs: usize, max_outputs: usize) -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            "anyRailgunTxidMerklerootAfterTransaction".to_string(),
            vec![inputs.any_railgun_txid_merkleroot_after_transaction.into()],
        );
        values.insert(
            "boundParamsHash".to_string(),
            vec![inputs.bound_params_hash.into()],
        );
        values.insert(
            "nullifiers".to_string(),
            pad_u256(inputs.nullifiers.clone(), max_inputs, MERKLE_ZERO_VALUE)
                .into_iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "commitmentsOut".to_string(),
            pad_u256(
                inputs.commitments_out.clone(),
                max_outputs,
                MERKLE_ZERO_VALUE,
            )
            .into_iter()
            .map(BigInt::from)
            .collect(),
        );
        values.insert(
            "spendingPublicKey".to_string(),
            inputs
                .spending_public_key
                .iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "nullifyingKey".to_string(),
            vec![inputs.nullifying_key.into()],
        );
        values.insert("token".to_string(), vec![inputs.token.into()]);
        values.insert(
            "randomsIn".to_string(),
            pad_u256(inputs.randoms_in.clone(), max_inputs, MERKLE_ZERO_VALUE)
                .into_iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "valuesIn".to_string(),
            pad_u256(inputs.values_in.clone(), max_inputs, U256::ZERO)
                .into_iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "utxoPositionsIn".to_string(),
            pad_u256(
                inputs.utxo_positions_in.clone(),
                max_inputs,
                MERKLE_ZERO_VALUE,
            )
            .into_iter()
            .map(BigInt::from)
            .collect(),
        );
        values.insert("utxoTreeIn".to_string(), vec![inputs.utxo_tree_in.into()]);
        values.insert(
            "npksOut".to_string(),
            pad_u256(inputs.npks_out.clone(), max_outputs, MERKLE_ZERO_VALUE)
                .into_iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "valuesOut".to_string(),
            pad_u256(inputs.values_out.clone(), max_outputs, U256::ZERO)
                .into_iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "utxoBatchGlobalStartPositionOut".to_string(),
            vec![inputs.utxo_batch_global_start_position_out.into()],
        );
        values.insert(
            "railgunTxidIfHasUnshield".to_string(),
            vec![inputs.railgun_txid_if_has_unshield.into()],
        );
        values.insert(
            "railgunTxidMerkleProofIndices".to_string(),
            vec![inputs.railgun_txid_merkle_proof_indices.into()],
        );
        values.insert(
            "railgunTxidMerkleProofPathElements".to_string(),
            inputs
                .railgun_txid_merkle_proof_path_elements
                .iter()
                .map(BigInt::from)
                .collect(),
        );
        values.insert(
            "poiMerkleroots".to_string(),
            pad_u256(
                inputs.poi_merkleroots.clone(),
                max_inputs,
                MERKLE_ZERO_VALUE,
            )
            .into_iter()
            .map(BigInt::from)
            .collect(),
        );
        values.insert(
            "poiInMerkleProofIndices".to_string(),
            pad_u256(
                inputs.poi_in_merkle_proof_indices.clone(),
                max_inputs,
                U256::ZERO,
            )
            .into_iter()
            .map(BigInt::from)
            .collect(),
        );
        values.insert(
            "poiInMerkleProofPathElements".to_string(),
            pad_u256_rows(
                inputs.poi_in_merkle_proof_path_elements.clone(),
                max_inputs,
                TREE_DEPTH,
                MERKLE_ZERO_VALUE,
            )
            .into_iter()
            .flatten()
            .map(BigInt::from)
            .collect(),
        );

        Self {
            inner: CircuitWitnessInputs::new(values),
        }
    }
}

impl From<PoiWitnessInputs> for BTreeMap<String, Vec<BigInt>> {
    fn from(inputs: PoiWitnessInputs) -> Self {
        inputs.inner.into()
    }
}

impl From<CircuitWitnessInputs> for BTreeMap<String, Vec<BigInt>> {
    fn from(inputs: CircuitWitnessInputs) -> Self {
        inputs.values
    }
}

fn pad_u256(mut values: Vec<U256>, target: usize, fill: U256) -> Vec<U256> {
    values.resize(target, fill);
    values.truncate(target);
    values
}

fn pad_u256_rows(
    mut values: Vec<Vec<U256>>,
    target_rows: usize,
    row_len: usize,
    fill: U256,
) -> Vec<Vec<U256>> {
    for row in &mut values {
        row.resize(row_len, fill);
        row.truncate(row_len);
    }
    values.resize_with(target_rows, || vec![fill; row_len]);
    values.truncate(target_rows);
    values
}

const DEFAULT_PROVER_QUEUE: usize = 4;
const DEFAULT_PROVER_WORKERS: usize = 2;

enum ProverJob {
    Railgun {
        enqueued_at: Instant,
        public_inputs: PublicInputs,
        private_inputs: PrivateInputs,
        signature: [U256; 3],
        verify_proof: bool,
        response: oneshot::Sender<Result<SnarkProof, ProverError>>,
    },
    Poi {
        enqueued_at: Instant,
        inputs: PoiProofInputs,
        verify_proof: bool,
        response: oneshot::Sender<Result<PoiProofResult, ProverError>>,
    },
}

#[derive(Debug, Clone)]
pub struct PoiProofResult {
    pub snark_proof: SnarkJsProof,
    pub public_signals: Vec<U256>,
}

#[derive(Debug, Clone)]
pub struct ProverService {
    senders: Arc<Vec<mpsc::Sender<ProverJob>>>,
    next_worker: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProverCacheBuildReport {
    pub railgun_variants: usize,
    pub poi_variants: usize,
    pub total_variants: usize,
    pub succeeded_variants: usize,
    pub failed_variants: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProverCacheBuildStage {
    Preparing,
    BuildingVariant,
    VariantReady,
}

impl ProverCacheBuildStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preparing => "Preparing prover cache",
            Self::BuildingVariant => "Building prover cache",
            Self::VariantReady => "Prover cache variant ready",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProverCacheBuildProgress {
    pub stage: ProverCacheBuildStage,
    pub railgun_variants: usize,
    pub poi_variants: usize,
    pub total_variants: usize,
    pub completed_variants: usize,
    pub succeeded_variants: usize,
    pub failed_variants: usize,
    pub current_variant: Option<String>,
    pub current_variant_is_poi: Option<bool>,
}

impl ProverCacheBuildProgress {
    #[must_use]
    pub const fn preparing() -> Self {
        Self {
            stage: ProverCacheBuildStage::Preparing,
            railgun_variants: 0,
            poi_variants: 0,
            total_variants: 0,
            completed_variants: 0,
            succeeded_variants: 0,
            failed_variants: 0,
            current_variant: None,
            current_variant_is_poi: None,
        }
    }

    #[must_use]
    pub fn percent(&self) -> u8 {
        if self.total_variants == 0 {
            return 0;
        }
        let percent = self.completed_variants.saturating_mul(100) / self.total_variants;
        u8::try_from(percent.min(100)).unwrap_or(100)
    }
}

struct ProverCacheVariant {
    variant: String,
    poi_shape: Option<(usize, usize)>,
}

struct ProverBlockingContext<'a> {
    db_store: Option<&'a DbStore>,
    cache_lock: &'a Mutex<()>,
    queue_wait_elapsed_ms: u128,
}

impl ProverService {
    #[must_use]
    pub fn new(source: ArtifactSource) -> Self {
        Self::with_capacity_db(source, DEFAULT_PROVER_QUEUE, open_db(DbConfig::default()))
    }

    #[must_use]
    pub fn new_with_db_dir(source: ArtifactSource, db_dir: PathBuf) -> Self {
        Self::with_capacity_db(
            source,
            DEFAULT_PROVER_QUEUE,
            open_db(DbConfig { root_dir: db_dir }),
        )
    }

    #[must_use]
    pub fn new_with_db(source: ArtifactSource, db: Arc<DbStore>) -> Self {
        Self::with_capacity_db(source, DEFAULT_PROVER_QUEUE, Some(db))
    }

    #[must_use]
    pub fn with_capacity(source: ArtifactSource, queue_size: usize) -> Self {
        Self::with_capacity_db(source, queue_size, open_db(DbConfig::default()))
    }

    #[must_use]
    pub fn with_capacity_db(
        source: ArtifactSource,
        queue_size: usize,
        db_store: Option<Arc<DbStore>>,
    ) -> Self {
        let worker_count = default_prover_worker_count();
        let cache_lock = Arc::new(Mutex::new(()));
        let mut senders = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let (sender, receiver): (mpsc::Sender<ProverJob>, mpsc::Receiver<ProverJob>) =
                mpsc::channel(queue_size);
            spawn_prover_worker(
                worker_index,
                source.clone(),
                db_store.clone(),
                receiver,
                Arc::clone(&cache_lock),
            );
            senders.push(sender);
        }
        Self {
            senders: Arc::new(senders),
            next_worker: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn prove_unshield(
        &self,
        public_inputs: &PublicInputs,
        private_inputs: &PrivateInputs,
        signature: &[U256; 3],
        verify_proof: bool,
    ) -> Result<SnarkProof, ProverError> {
        let (response, receiver) = oneshot::channel();
        let job = ProverJob::Railgun {
            enqueued_at: Instant::now(),
            public_inputs: public_inputs.clone(),
            private_inputs: private_inputs.clone(),
            signature: *signature,
            verify_proof,
            response,
        };
        self.send_job(job).await?;
        receiver.await.map_err(|_| ProverError::WorkerDropped)?
    }

    pub async fn prove_poi(
        &self,
        inputs: &PoiProofInputs,
        verify_proof: bool,
    ) -> Result<SnarkJsProof, ProverError> {
        self.prove_poi_with_public_signals(inputs, verify_proof)
            .await
            .map(|result| result.snark_proof)
    }

    pub async fn prove_poi_with_public_signals(
        &self,
        inputs: &PoiProofInputs,
        verify_proof: bool,
    ) -> Result<PoiProofResult, ProverError> {
        let (response, receiver) = oneshot::channel();
        let job = ProverJob::Poi {
            enqueued_at: Instant::now(),
            inputs: inputs.clone(),
            verify_proof,
            response,
        };
        self.send_job(job).await?;
        receiver.await.map_err(|_| ProverError::WorkerDropped)?
    }

    async fn send_job(&self, job: ProverJob) -> Result<(), ProverError> {
        let worker_index = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        self.senders[worker_index]
            .send(job)
            .await
            .map_err(|_| ProverError::QueueClosed)
    }
}

fn default_prover_worker_count() -> usize {
    thread::available_parallelism().map_or(1, |count| count.get().clamp(1, DEFAULT_PROVER_WORKERS))
}

fn spawn_prover_worker(
    worker_index: usize,
    source: ArtifactSource,
    db_store: Option<Arc<DbStore>>,
    mut receiver: mpsc::Receiver<ProverJob>,
    cache_lock: Arc<Mutex<()>>,
) {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("prover runtime");
        // TODO: cache artifacts in memory to avoid repeated disk reads.
        while let Some(job) = receiver.blocking_recv() {
            let _guard = runtime.enter();
            match job {
                ProverJob::Railgun {
                    enqueued_at,
                    public_inputs,
                    private_inputs,
                    signature,
                    verify_proof,
                    response,
                } => {
                    let queue_wait_elapsed_ms = enqueued_at.elapsed().as_millis();
                    debug!(
                        worker_index,
                        queue_wait_elapsed_ms,
                        nullifiers = public_inputs.nullifiers.len(),
                        commitments_out = public_inputs.commitments_out.len(),
                        "started railgun prover job"
                    );
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        prove_unshield_blocking(
                            &source,
                            &public_inputs,
                            &private_inputs,
                            &signature,
                            verify_proof,
                            ProverBlockingContext {
                                db_store: db_store.as_deref(),
                                cache_lock: &cache_lock,
                                queue_wait_elapsed_ms,
                            },
                        )
                    }))
                    .unwrap_or_else(|payload| {
                        let message = panic_payload_to_string(payload.as_ref());
                        warn!(
                            worker_index,
                            panic = %message,
                            nullifiers = public_inputs.nullifiers.len(),
                            commitments_out = public_inputs.commitments_out.len(),
                            "railgun prover worker caught panic"
                        );
                        Err(ProverError::WorkerPanic(message))
                    });
                    if response.send(result).is_err() {
                        debug!(worker_index, "failed to send prover response");
                    }
                }
                ProverJob::Poi {
                    enqueued_at,
                    inputs,
                    verify_proof,
                    response,
                } => {
                    let queue_wait_elapsed_ms = enqueued_at.elapsed().as_millis();
                    let (max_inputs, max_outputs) = poi_circuit_size(&inputs);
                    debug!(
                        worker_index,
                        queue_wait_elapsed_ms,
                        max_inputs,
                        max_outputs,
                        nullifiers = inputs.nullifiers.len(),
                        commitments_out = inputs.commitments_out.len(),
                        "started POI prover job"
                    );
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        prove_poi_blocking(
                            &source,
                            &inputs,
                            verify_proof,
                            ProverBlockingContext {
                                db_store: db_store.as_deref(),
                                cache_lock: &cache_lock,
                                queue_wait_elapsed_ms,
                            },
                        )
                    }))
                    .unwrap_or_else(|payload| {
                        let message = panic_payload_to_string(payload.as_ref());
                        warn!(
                            worker_index,
                            panic = %message,
                            max_inputs,
                            max_outputs,
                            nullifiers = inputs.nullifiers.len(),
                            commitments_out = inputs.commitments_out.len(),
                            "POI prover worker caught panic"
                        );
                        Err(ProverError::WorkerPanic(message))
                    });
                    if response.send(result).is_err() {
                        debug!(worker_index, "failed to send POI prover response");
                    }
                }
            }
        }
    });
}

fn lock_cache(cache_lock: &Mutex<()>) -> Result<std::sync::MutexGuard<'_, ()>, ProverError> {
    cache_lock
        .lock()
        .map_err(|_| ProverError::WorkerPanic("prover cache lock poisoned".to_string()))
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    "unknown panic payload".to_string()
}

fn open_db(config: DbConfig) -> Option<Arc<DbStore>> {
    match DbStore::open(config) {
        Ok(store) => Some(Arc::new(store)),
        Err(err) => {
            warn!(?err, "failed to open local db");
            None
        }
    }
}

pub fn build_prover_cache(
    source: &ArtifactSource,
    db_store: Option<&DbStore>,
) -> Result<ProverCacheBuildReport, ProverError> {
    build_prover_cache_with_progress(source, db_store, |_| {})
}

pub fn build_prover_cache_with_progress(
    source: &ArtifactSource,
    db_store: Option<&DbStore>,
    mut on_progress: impl FnMut(ProverCacheBuildProgress),
) -> Result<ProverCacheBuildReport, ProverError> {
    let started = Instant::now();
    let mut variants = source
        .list_variants()?
        .into_iter()
        .map(|variant| ProverCacheVariant {
            variant,
            poi_shape: None,
        })
        .collect::<Vec<_>>();
    let railgun_variants = variants.len();
    variants.extend([
        ProverCacheVariant {
            variant: poi_variant_name(3, 3),
            poi_shape: Some((3, 3)),
        },
        ProverCacheVariant {
            variant: poi_variant_name(13, 13),
            poi_shape: Some((13, 13)),
        },
    ]);
    let poi_variants = variants.len() - railgun_variants;
    let total_variants = variants.len();
    let mut progress = ProverCacheBuildProgress {
        stage: ProverCacheBuildStage::Preparing,
        railgun_variants,
        poi_variants,
        total_variants,
        completed_variants: 0,
        succeeded_variants: 0,
        failed_variants: 0,
        current_variant: None,
        current_variant_is_poi: None,
    };
    on_progress(progress.clone());

    info!(
        railgun_variants,
        poi_variants,
        total_variants,
        artifact_dir = %source.out_dir.display(),
        "building prover cache"
    );
    let mut succeeded_variants = 0_usize;
    let mut failed_variants = 0_usize;
    for variant in &variants {
        progress.stage = ProverCacheBuildStage::BuildingVariant;
        progress.current_variant = Some(variant.variant.clone());
        progress.current_variant_is_poi = Some(variant.poi_shape.is_some());
        on_progress(progress.clone());
        match build_prover_variant_cache(source, db_store, variant) {
            Ok(()) => {
                succeeded_variants += 1;
                progress.succeeded_variants = succeeded_variants;
            }
            Err(error) => {
                failed_variants += 1;
                progress.failed_variants = failed_variants;
                warn!(
                    %error,
                    variant = %variant.variant,
                    is_poi = variant.poi_shape.is_some(),
                    failed_variants,
                    total_variants,
                    "prover cache variant failed; continuing"
                );
            }
        }
        progress.stage = ProverCacheBuildStage::VariantReady;
        progress.completed_variants += 1;
        on_progress(progress.clone());
    }
    if succeeded_variants == 0 && failed_variants > 0 {
        return Err(ProverError::CacheBuildFailed { total_variants });
    }

    let report = ProverCacheBuildReport {
        railgun_variants,
        poi_variants,
        total_variants,
        succeeded_variants,
        failed_variants,
        elapsed_ms: started.elapsed().as_millis(),
    };
    info!(
        railgun_variants = report.railgun_variants,
        poi_variants = report.poi_variants,
        total_variants = report.total_variants,
        succeeded_variants = report.succeeded_variants,
        failed_variants = report.failed_variants,
        elapsed_ms = report.elapsed_ms,
        "prover cache build complete"
    );
    Ok(report)
}

fn build_prover_variant_cache(
    source: &ArtifactSource,
    db_store: Option<&DbStore>,
    variant: &ProverCacheVariant,
) -> Result<(), ProverError> {
    let started = Instant::now();
    let paths = source.download_variant(&variant.variant, false)?;
    let wasm_read_started = Instant::now();
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;
    let wasm_read_elapsed_ms = wasm_read_started.elapsed().as_millis();

    let zkey_started = Instant::now();
    let expected_hash = source.expected_zkey_hash(&variant.variant)?;
    let mut expected_hash_bytes = [0u8; 32];
    expected_hash_bytes.copy_from_slice(expected_hash.as_slice());
    let zkey_cache_hit = match db_store {
        Some(db) => zkey_cache_exists(db, &variant.variant, expected_hash_bytes)
            .map_err(|err| ProverError::Zkey(err.to_string()))?,
        None => false,
    };
    if !zkey_cache_hit {
        drop(
            load_or_parse_zkey(db_store, &variant.variant, expected_hash_bytes, &paths.zkey)
                .map_err(|err| ProverError::Zkey(err.to_string()))?,
        );
    }
    let zkey_elapsed_ms = zkey_started.elapsed().as_millis();

    let module_started = Instant::now();
    let store = variant
        .poi_shape
        .map_or_else(Store::default, |(max_inputs, max_outputs)| {
            poi_witness_store(max_inputs, max_outputs)
        });
    let compiler = variant
        .poi_shape
        .map_or("default", |(max_inputs, max_outputs)| {
            poi_witness_compiler_name(max_inputs, max_outputs)
        });
    let module_cache_hit = match db_store {
        Some(db) => wasm_module_cache_exists(db, &variant.variant, compiler, &wasm)
            .map_err(|err| ProverError::WasmModule(err.to_string()))?,
        None => false,
    };
    if !module_cache_hit {
        drop(
            load_or_compile_wasm_module(db_store, &store, &variant.variant, compiler, &wasm)
                .map_err(|err| ProverError::WasmModule(err.to_string()))?,
        );
    }
    let module_elapsed_ms = module_started.elapsed().as_millis();
    info!(
        variant = %variant.variant,
        is_poi = variant.poi_shape.is_some(),
        compiler,
        wasm_read_elapsed_ms,
        zkey_elapsed_ms,
        zkey_cache_hit,
        module_elapsed_ms,
        module_cache_hit,
        elapsed_ms = started.elapsed().as_millis(),
        "prover cache variant ready"
    );
    Ok(())
}

fn prove_unshield_blocking(
    source: &ArtifactSource,
    public_inputs: &PublicInputs,
    private_inputs: &PrivateInputs,
    signature: &[U256; 3],
    verify_proof: bool,
    context: ProverBlockingContext<'_>,
) -> Result<SnarkProof, ProverError> {
    let total_started = Instant::now();
    debug!(
        nullifiers = public_inputs.nullifiers.len(),
        commitments_out = public_inputs.commitments_out.len(),
        ?source,
        "ensuring artifacts"
    );
    let ensure_started = Instant::now();
    {
        let _cache_guard = lock_cache(context.cache_lock)?;
        source.ensure_artifacts(
            public_inputs.nullifiers.len(),
            public_inputs.commitments_out.len(),
        )?;
    }
    let ensure_elapsed_ms = ensure_started.elapsed().as_millis();
    debug!("loading artifacts");
    let variant = variant_name(
        public_inputs.nullifiers.len(),
        public_inputs.commitments_out.len(),
    );
    let paths = source.artifact_paths(&variant);
    let wasm_read_started = Instant::now();
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;
    let wasm_read_elapsed_ms = wasm_read_started.elapsed().as_millis();
    let zkey_started = Instant::now();
    let expected_hash = source.expected_zkey_hash(&variant)?;
    let mut expected_hash_bytes = [0u8; 32];
    expected_hash_bytes.copy_from_slice(expected_hash.as_slice());
    let (proving_key, matrices) = {
        let _cache_guard = lock_cache(context.cache_lock)?;
        load_or_parse_zkey(context.db_store, &variant, expected_hash_bytes, &paths.zkey)
            .map_err(|e| ProverError::Zkey(e.to_string()))?
    };
    let zkey_elapsed_ms = zkey_started.elapsed().as_millis();
    let num_instance_variables = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let proof_matrices = [matrices.a, matrices.b, matrices.c];

    let module_started = Instant::now();
    let mut store = Store::default();
    let cached_module = {
        let _cache_guard = lock_cache(context.cache_lock)?;
        load_or_compile_wasm_module(context.db_store, &store, &variant, "default", &wasm)
            .map_err(|err| ProverError::WasmModule(err.to_string()))?
    };
    let module_cache_hit = cached_module.cache_hit;
    let module = cached_module.module;
    let mut calculator = WitnessCalculator::from_module(&mut store, module)?;
    let module_elapsed_ms = module_started.elapsed().as_millis();

    let witness_input_started = Instant::now();
    let witness_inputs = RailgunWitnessInputs::new(public_inputs, private_inputs, signature);
    let witness_inputs: BTreeMap<_, _> = witness_inputs.into();
    let witness_input_elapsed_ms = witness_input_started.elapsed().as_millis();
    let witness_started = Instant::now();
    let witness =
        calculator.calculate_witness_element::<Fr, _>(&mut store, witness_inputs, false)?;
    let witness_elapsed_ms = witness_started.elapsed().as_millis();

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let prove_started = Instant::now();
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        r,
        s,
        &proof_matrices,
        num_instance_variables,
        num_constraints,
        &witness,
    )?;
    let prove_elapsed_ms = prove_started.elapsed().as_millis();

    let verify_elapsed_ms = if verify_proof {
        let verify_started = Instant::now();
        let public_inputs = public_inputs_from_witness(&witness, num_instance_variables);
        let pvk = prepare_verifying_key(&proving_key.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs)
                .map_err(|err: SynthesisError| ProverError::Verify(err.to_string()))?;
        if !verified {
            return Err(ProverError::InvalidProof);
        }
        verify_started.elapsed().as_millis()
    } else {
        0
    };

    debug!(
        variant = %variant,
        nullifiers = public_inputs.nullifiers.len(),
        commitments_out = public_inputs.commitments_out.len(),
        verify_proof,
        queue_wait_elapsed_ms = context.queue_wait_elapsed_ms,
        ensure_elapsed_ms,
        wasm_read_elapsed_ms,
        zkey_elapsed_ms,
        module_elapsed_ms,
        module_cache_hit,
        witness_input_elapsed_ms,
        witness_elapsed_ms,
        prove_elapsed_ms,
        verify_elapsed_ms,
        elapsed_ms = total_started.elapsed().as_millis(),
        "generated railgun proof"
    );

    Ok(ark_proof_to_sol(proof))
}

fn prove_poi_blocking(
    source: &ArtifactSource,
    inputs: &PoiProofInputs,
    verify_proof: bool,
    context: ProverBlockingContext<'_>,
) -> Result<PoiProofResult, ProverError> {
    let total_started = Instant::now();
    let (max_inputs, max_outputs) = poi_circuit_size(inputs);
    debug!(
        max_inputs,
        max_outputs,
        nullifiers = inputs.nullifiers.len(),
        commitments_out = inputs.commitments_out.len(),
        wasm_compiler = poi_witness_compiler_name(max_inputs, max_outputs),
        ?source,
        "ensuring POI artifacts"
    );
    let ensure_started = Instant::now();
    {
        let _cache_guard = lock_cache(context.cache_lock)?;
        source.ensure_poi_artifacts(max_inputs, max_outputs)?;
    }
    let ensure_elapsed_ms = ensure_started.elapsed().as_millis();
    debug!("loading POI artifacts");
    let variant = poi_variant_name(max_inputs, max_outputs);
    let paths = source.artifact_paths(&variant);
    let wasm_read_started = Instant::now();
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;
    let wasm_read_elapsed_ms = wasm_read_started.elapsed().as_millis();
    let zkey_started = Instant::now();
    let expected_hash = source.expected_zkey_hash(&variant)?;
    let mut expected_hash_bytes = [0u8; 32];
    expected_hash_bytes.copy_from_slice(expected_hash.as_slice());
    let (proving_key, matrices) = {
        let _cache_guard = lock_cache(context.cache_lock)?;
        load_or_parse_zkey(context.db_store, &variant, expected_hash_bytes, &paths.zkey)
            .map_err(|e| ProverError::Zkey(e.to_string()))?
    };
    let zkey_elapsed_ms = zkey_started.elapsed().as_millis();
    let num_instance_variables = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let proof_matrices = [matrices.a, matrices.b, matrices.c];

    let module_started = Instant::now();
    let mut store = poi_witness_store(max_inputs, max_outputs);
    let compiler = poi_witness_compiler_name(max_inputs, max_outputs);
    let cached_module = {
        let _cache_guard = lock_cache(context.cache_lock)?;
        load_or_compile_wasm_module(context.db_store, &store, &variant, compiler, &wasm)
            .map_err(|err| ProverError::WasmModule(err.to_string()))?
    };
    let module_cache_hit = cached_module.cache_hit;
    let module = cached_module.module;
    let mut calculator = WitnessCalculator::from_module(&mut store, module)?;
    let module_elapsed_ms = module_started.elapsed().as_millis();

    let witness_input_started = Instant::now();
    let witness_inputs = PoiWitnessInputs::new(inputs, max_inputs, max_outputs);
    let witness_inputs: BTreeMap<_, _> = witness_inputs.into();
    let witness_input_elapsed_ms = witness_input_started.elapsed().as_millis();
    let witness_started = Instant::now();
    let witness =
        calculator.calculate_witness_element::<Fr, _>(&mut store, witness_inputs, false)?;
    let witness_elapsed_ms = witness_started.elapsed().as_millis();

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let prove_started = Instant::now();
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        r,
        s,
        &proof_matrices,
        num_instance_variables,
        num_constraints,
        &witness,
    )?;
    let prove_elapsed_ms = prove_started.elapsed().as_millis();

    let public_inputs = public_inputs_from_witness(&witness, num_instance_variables);
    let verify_elapsed_ms = if verify_proof {
        let verify_started = Instant::now();
        let pvk = prepare_verifying_key(&proving_key.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs)
                .map_err(|err: SynthesisError| ProverError::Verify(err.to_string()))?;
        if !verified {
            return Err(ProverError::InvalidProof);
        }
        verify_started.elapsed().as_millis()
    } else {
        0
    };

    debug!(
        variant = %variant,
        max_inputs,
        max_outputs,
        nullifiers = inputs.nullifiers.len(),
        commitments_out = inputs.commitments_out.len(),
        verify_proof,
        queue_wait_elapsed_ms = context.queue_wait_elapsed_ms,
        ensure_elapsed_ms,
        wasm_read_elapsed_ms,
        zkey_elapsed_ms,
        module_elapsed_ms,
        module_cache_hit,
        witness_input_elapsed_ms,
        witness_elapsed_ms,
        prove_elapsed_ms,
        verify_elapsed_ms,
        elapsed_ms = total_started.elapsed().as_millis(),
        "generated POI proof"
    );

    Ok(PoiProofResult {
        snark_proof: ark_proof_to_snarkjs(proof),
        public_signals: public_inputs.into_iter().map(prime_field_to_u256).collect(),
    })
}

fn poi_circuit_size(inputs: &PoiProofInputs) -> (usize, usize) {
    if inputs.nullifiers.len() <= 3 && inputs.commitments_out.len() <= 3 {
        (3, 3)
    } else {
        (13, 13)
    }
}

fn poi_witness_store(max_inputs: usize, max_outputs: usize) -> Store {
    if use_singlepass_poi_witness(max_inputs, max_outputs) {
        return Store::new(wasmer::sys::EngineBuilder::new(
            wasmer_compiler_singlepass::Singlepass::default(),
        ));
    }
    Store::default()
}

const fn poi_witness_compiler_name(max_inputs: usize, max_outputs: usize) -> &'static str {
    if use_singlepass_poi_witness(max_inputs, max_outputs) {
        "singlepass"
    } else {
        "default"
    }
}

const fn use_singlepass_poi_witness(max_inputs: usize, max_outputs: usize) -> bool {
    max_inputs == 13 && max_outputs == 13
}

fn ark_proof_to_sol(proof: Proof<Bn254>) -> SnarkProof {
    let a = G1Point {
        x: prime_field_to_u256(proof.a.x),
        y: prime_field_to_u256(proof.a.y),
    };
    let c = G1Point {
        x: prime_field_to_u256(proof.c.x),
        y: prime_field_to_u256(proof.c.y),
    };

    let b_x_c0 = prime_field_to_u256(proof.b.x.c0);
    let b_x_c1 = prime_field_to_u256(proof.b.x.c1);
    let b_y_c0 = prime_field_to_u256(proof.b.y.c0);
    let b_y_c1 = prime_field_to_u256(proof.b.y.c1);
    let b = G2Point {
        x: [b_x_c1, b_x_c0],
        y: [b_y_c1, b_y_c0],
    };

    SnarkProof { a, b, c }
}

fn ark_proof_to_snarkjs(proof: Proof<Bn254>) -> SnarkJsProof {
    SnarkJsProof {
        pi_a: [
            prime_field_to_u256(proof.a.x),
            prime_field_to_u256(proof.a.y),
        ],
        pi_b: [
            [
                prime_field_to_u256(proof.b.x.c0),
                prime_field_to_u256(proof.b.x.c1),
            ],
            [
                prime_field_to_u256(proof.b.y.c0),
                prime_field_to_u256(proof.b.y.c1),
            ],
        ],
        pi_c: [
            prime_field_to_u256(proof.c.x),
            prime_field_to_u256(proof.c.y),
        ],
    }
}

fn public_inputs_from_witness(witness: &[Fr], count: usize) -> Vec<Fr> {
    if count <= 1 {
        return Vec::new();
    }
    witness[1..count].to_vec()
}

#[cfg(test)]
mod tests {
    use super::{
        MERKLE_ZERO_VALUE, PoiProofInputs, PoiWitnessInputs, ark_proof_to_snarkjs,
        poi_witness_compiler_name,
    };
    use alloy::primitives::U256;
    use alloy::uint;
    use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
    use ark_groth16::Proof;

    fn sample_poi_inputs() -> PoiProofInputs {
        PoiProofInputs {
            any_railgun_txid_merkleroot_after_transaction: uint!(1_U256),
            bound_params_hash: uint!(2_U256),
            nullifiers: vec![uint!(3_U256)],
            commitments_out: vec![uint!(4_U256)],
            spending_public_key: [uint!(5_U256), uint!(6_U256)],
            nullifying_key: uint!(7_U256),
            token: uint!(8_U256),
            randoms_in: vec![uint!(9_U256)],
            values_in: vec![uint!(10_U256)],
            utxo_positions_in: vec![uint!(11_U256)],
            utxo_tree_in: uint!(12_U256),
            npks_out: vec![uint!(13_U256)],
            values_out: vec![uint!(14_U256)],
            utxo_batch_global_start_position_out: uint!(15_U256),
            railgun_txid_if_has_unshield: U256::ZERO,
            railgun_txid_merkle_proof_indices: U256::ZERO,
            railgun_txid_merkle_proof_path_elements: vec![U256::ZERO; 16],
            poi_merkleroots: vec![uint!(16_U256)],
            poi_in_merkle_proof_indices: vec![uint!(17_U256)],
            poi_in_merkle_proof_path_elements: vec![vec![uint!(18_U256); 16]],
        }
    }

    #[test]
    fn poi_witness_inputs_pad_public_and_private_signals() {
        let witness = PoiWitnessInputs::new(&sample_poi_inputs(), 3, 3);
        let hex = witness.inner.to_hex_map();

        assert_eq!(hex["nullifiers"].len(), 3);
        assert_eq!(hex["commitmentsOut"].len(), 3);
        assert_eq!(hex["valuesIn"], vec!["0xa", "0x0", "0x0"]);
        assert_eq!(hex["valuesOut"], vec!["0xe", "0x0", "0x0"]);
        assert_eq!(hex["spendingPublicKey"], vec!["0x5", "0x6"]);
        assert_eq!(hex["poiInMerkleProofPathElements"].len(), 3 * 16);
        assert_eq!(hex["nullifiers"][1], format!("0x{MERKLE_ZERO_VALUE:x}"));
        assert_eq!(hex["poiMerkleroots"][1], format!("0x{MERKLE_ZERO_VALUE:x}"));
    }

    #[test]
    fn poi_witness_uses_singlepass_for_large_recovery_circuit() {
        assert_eq!(poi_witness_compiler_name(13, 13), "singlepass");
        assert_eq!(poi_witness_compiler_name(3, 3), "default");
    }

    #[test]
    fn ark_proof_to_snarkjs_keeps_snarkjs_pi_b_order() {
        let proof = Proof::<Bn254> {
            a: G1Affine::new_unchecked(fq(5), fq(6)),
            b: G2Affine::new_unchecked(Fq2::new(fq(1), fq(2)), Fq2::new(fq(3), fq(4))),
            c: G1Affine::new_unchecked(fq(7), fq(8)),
        };

        let snarkjs = ark_proof_to_snarkjs(proof);

        assert_eq!(
            snarkjs.pi_b,
            [
                [uint!(1_U256), uint!(2_U256)],
                [uint!(3_U256), uint!(4_U256)]
            ]
        );
    }

    fn fq(value: u64) -> Fq {
        Fq::from(value)
    }
}
