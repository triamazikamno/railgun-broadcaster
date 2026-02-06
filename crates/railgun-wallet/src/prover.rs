use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use alloy::primitives::U256;
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomReduction, WitnessCalculator};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, prepare_verifying_key};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::thread_rng;
use num_bigint::{BigInt, Sign};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;
use wasmer::{Module, Store};

use crate::artifacts::{
    ArtifactError, ArtifactSource, artifact_paths, ensure_artifacts_with_source,
    expected_zkey_hash, variant_name,
};
use crate::tx::{PrivateInputs, PublicInputs};
use crate::zkey_cache::load_or_parse_zkey;
use broadcaster_core::contracts::railgun::{G1Point, G2Point, SnarkProof};
use broadcaster_core::crypto::ark_utils::prime_field_to_u256;
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
}

#[derive(Debug, Clone)]
pub struct WitnessInputs {
    values: BTreeMap<String, Vec<BigInt>>,
}

impl WitnessInputs {
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

        Self { values }
    }

    #[must_use]
    pub fn to_hex_map(&self) -> BTreeMap<String, Vec<String>> {
        self.values
            .iter()
            .map(|(k, v)| {
                let values = v.iter().map(bigint_to_hex).collect();
                (k.clone(), values)
            })
            .collect()
    }

    #[must_use]
    pub fn into_inputs(self) -> BTreeMap<String, Vec<BigInt>> {
        self.values
    }

    #[must_use]
    pub fn as_inputs(&self) -> &BTreeMap<String, Vec<BigInt>> {
        &self.values
    }
}

const DEFAULT_PROVER_QUEUE: usize = 4;

struct ProverJob {
    public_inputs: PublicInputs,
    private_inputs: PrivateInputs,
    signature: [U256; 3],
    verify_proof: bool,
    response: oneshot::Sender<Result<SnarkProof, ProverError>>,
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
                let result = prove_unshield_blocking(
                    &source,
                    &job.public_inputs,
                    &job.private_inputs,
                    &job.signature,
                    job.verify_proof,
                    db_store.as_deref(),
                );
                if job.response.send(result).is_err() {
                    debug!("failed to send prover response");
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
        let job = ProverJob {
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
}

fn open_db(config: DbConfig) -> Option<Arc<DbStore>> {
    match DbStore::open(config) {
        Ok(store) => Some(Arc::new(store)),
        Err(err) => {
            tracing::warn!(?err, "failed to open local db");
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

    let mut store = Store::default();
    let module = Module::new(&store, wasm).map_err(color_eyre::Report::from)?;
    let mut calculator = WitnessCalculator::from_module(&mut store, module)?;

    let witness_inputs = WitnessInputs::new(public_inputs, private_inputs, signature);
    let witness = calculator.calculate_witness_element::<Fr, _>(
        &mut store,
        witness_inputs.into_inputs(),
        false,
    )?;

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        r,
        s,
        &matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &witness,
    )?;

    if verify_proof {
        let public_inputs = public_inputs_from_witness(&witness, matrices.num_instance_variables);
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

fn public_inputs_from_witness(witness: &[Fr], count: usize) -> Vec<Fr> {
    if count <= 1 {
        return Vec::new();
    }
    witness[1..count].to_vec()
}

fn bigint_to_hex(value: &BigInt) -> String {
    if value.sign() == Sign::NoSign {
        return "0x0".to_string();
    }
    format!("0x{}", value.to_str_radix(16))
}
