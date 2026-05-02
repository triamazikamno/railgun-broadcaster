use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

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
use tracing::{debug, warn};
use wasmer::{Module, Store};

use crate::artifacts::{
    ArtifactError, ArtifactSource, artifact_paths, ensure_artifacts_with_source,
    ensure_poi_artifacts_with_source, expected_zkey_hash, poi_variant_name, variant_name,
};
use crate::tx::{PoiProofInputs, PrivateInputs, PublicInputs};
use crate::zkey_cache::load_or_parse_zkey;
use broadcaster_core::contracts::railgun::{G1Point, G2Point, SnarkProof};
use broadcaster_core::crypto::ark_utils::prime_field_to_u256;
use broadcaster_core::transact::{MERKLE_ZERO_VALUE, SnarkJsProof};
use local_db::{DbConfig, DbStore};

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("zkey parse failed: {0}")]
    Zkey(String),
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
                merkletree::tree::TREE_DEPTH,
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

enum ProverJob {
    Railgun {
        public_inputs: PublicInputs,
        private_inputs: PrivateInputs,
        signature: [U256; 3],
        verify_proof: bool,
        response: oneshot::Sender<Result<SnarkProof, ProverError>>,
    },
    Poi {
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
    sender: mpsc::Sender<ProverJob>,
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
        let (sender, mut receiver): (mpsc::Sender<ProverJob>, mpsc::Receiver<ProverJob>) =
            mpsc::channel(queue_size);
        let db_store = db_store.clone();
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
                        public_inputs,
                        private_inputs,
                        signature,
                        verify_proof,
                        response,
                    } => {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            prove_unshield_blocking(
                                &source,
                                &public_inputs,
                                &private_inputs,
                                &signature,
                                verify_proof,
                                db_store.as_deref(),
                            )
                        }))
                        .unwrap_or_else(|payload| {
                            let message = panic_payload_to_string(payload.as_ref());
                            warn!(
                                panic = %message,
                                nullifiers = public_inputs.nullifiers.len(),
                                commitments_out = public_inputs.commitments_out.len(),
                                "railgun prover worker caught panic"
                            );
                            Err(ProverError::WorkerPanic(message))
                        });
                        if response.send(result).is_err() {
                            debug!("failed to send prover response");
                        }
                    }
                    ProverJob::Poi {
                        inputs,
                        verify_proof,
                        response,
                    } => {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            prove_poi_blocking(&source, &inputs, verify_proof, db_store.as_deref())
                        }))
                        .unwrap_or_else(|payload| {
                            let message = panic_payload_to_string(payload.as_ref());
                            let (max_inputs, max_outputs) = poi_circuit_size(&inputs);
                            warn!(
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
                            debug!("failed to send POI prover response");
                        }
                    }
                }
            }
        });
        Self { sender }
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
            public_inputs: public_inputs.clone(),
            private_inputs: private_inputs.clone(),
            signature: *signature,
            verify_proof,
            response,
        };
        self.sender
            .send(job)
            .await
            .map_err(|_| ProverError::QueueClosed)?;
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
            inputs: inputs.clone(),
            verify_proof,
            response,
        };
        self.sender
            .send(job)
            .await
            .map_err(|_| ProverError::QueueClosed)?;
        receiver.await.map_err(|_| ProverError::WorkerDropped)?
    }
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

fn prove_unshield_blocking(
    source: &ArtifactSource,
    public_inputs: &PublicInputs,
    private_inputs: &PrivateInputs,
    signature: &[U256; 3],
    verify_proof: bool,
    db_store: Option<&DbStore>,
) -> Result<SnarkProof, ProverError> {
    debug!(
        nullifiers = public_inputs.nullifiers.len(),
        commitments_out = public_inputs.commitments_out.len(),
        ?source,
        "ensuring artifacts"
    );
    ensure_artifacts_with_source(
        public_inputs.nullifiers.len(),
        public_inputs.commitments_out.len(),
        source,
    )?;
    debug!("loading artifacts");
    let variant = variant_name(
        public_inputs.nullifiers.len(),
        public_inputs.commitments_out.len(),
    );
    let paths = artifact_paths(&variant, source);
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;
    let expected_hash = expected_zkey_hash(&variant, source)?;
    let mut expected_hash_bytes = [0u8; 32];
    expected_hash_bytes.copy_from_slice(expected_hash.as_slice());
    let (proving_key, matrices) =
        load_or_parse_zkey(db_store, &variant, expected_hash_bytes, &paths.zkey)
            .map_err(|e| ProverError::Zkey(e.to_string()))?;
    let num_instance_variables = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let proof_matrices = [matrices.a, matrices.b, matrices.c];

    let mut store = Store::default();
    let module = Module::new(&store, wasm).map_err(color_eyre::Report::from)?;
    let mut calculator = WitnessCalculator::from_module(&mut store, module)?;

    let witness_inputs = RailgunWitnessInputs::new(public_inputs, private_inputs, signature);
    let witness_inputs: BTreeMap<_, _> = witness_inputs.into();
    let witness =
        calculator.calculate_witness_element::<Fr, _>(&mut store, witness_inputs, false)?;

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        r,
        s,
        &proof_matrices,
        num_instance_variables,
        num_constraints,
        &witness,
    )?;

    if verify_proof {
        let public_inputs = public_inputs_from_witness(&witness, num_instance_variables);
        let pvk = prepare_verifying_key(&proving_key.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs)
                .map_err(|err: SynthesisError| ProverError::Verify(err.to_string()))?;
        if !verified {
            return Err(ProverError::InvalidProof);
        }
    }

    Ok(ark_proof_to_sol(proof))
}

fn prove_poi_blocking(
    source: &ArtifactSource,
    inputs: &PoiProofInputs,
    verify_proof: bool,
    db_store: Option<&DbStore>,
) -> Result<PoiProofResult, ProverError> {
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
    ensure_poi_artifacts_with_source(max_inputs, max_outputs, source)?;
    debug!("loading POI artifacts");
    let variant = poi_variant_name(max_inputs, max_outputs);
    let paths = artifact_paths(&variant, source);
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;
    let expected_hash = expected_zkey_hash(&variant, source)?;
    let mut expected_hash_bytes = [0u8; 32];
    expected_hash_bytes.copy_from_slice(expected_hash.as_slice());
    let (proving_key, matrices) =
        load_or_parse_zkey(db_store, &variant, expected_hash_bytes, &paths.zkey)
            .map_err(|e| ProverError::Zkey(e.to_string()))?;
    let num_instance_variables = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let proof_matrices = [matrices.a, matrices.b, matrices.c];

    let mut store = poi_witness_store(max_inputs, max_outputs);
    let module = Module::new(&store, wasm).map_err(color_eyre::Report::from)?;
    let mut calculator = WitnessCalculator::from_module(&mut store, module)?;

    let witness_inputs = PoiWitnessInputs::new(inputs, max_inputs, max_outputs);
    let witness_inputs: BTreeMap<_, _> = witness_inputs.into();
    let witness =
        calculator.calculate_witness_element::<Fr, _>(&mut store, witness_inputs, false)?;

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        r,
        s,
        &proof_matrices,
        num_instance_variables,
        num_constraints,
        &witness,
    )?;

    let public_inputs = public_inputs_from_witness(&witness, num_instance_variables);
    if verify_proof {
        let pvk = prepare_verifying_key(&proving_key.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs)
                .map_err(|err: SynthesisError| ProverError::Verify(err.to_string()))?;
        if !verified {
            return Err(ProverError::InvalidProof);
        }
    }

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
