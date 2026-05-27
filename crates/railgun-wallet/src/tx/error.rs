use super::*;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("no matching utxos for amount. max immediately spendable: {0}")]
    InsufficientBalance(U256),
    #[error("no matching fee-token utxos for broadcaster fee. max immediately spendable: {0}")]
    InsufficientFeeTokenBalance(U256),
    #[error("utxos exceed circuit input limit")]
    TooManyInputs,
    #[error("inputs span multiple trees")]
    MixedTrees,
    #[error("inputs contain unexpected token")]
    TokenMismatch,
    #[error("signature message too large: {inputs} inputs + {outputs} outputs (max 16)")]
    SignatureInputLimit { inputs: usize, outputs: usize },
    #[error("missing merkle root")]
    MissingRoot,
    #[error("missing action data for unwrap")]
    MissingActionData,
    #[error("missing merkle proof for tree {tree} position {position}")]
    MissingProof { tree: u32, position: u64 },
    #[error("min gas price exceeds uint72: {0}")]
    MinGasPriceTooLarge(u128),
    #[error("encrypt note failed: {0}")]
    Encrypt(#[from] crate::notes::NoteError),
    #[error("prove failed: {0}")]
    Prover(#[from] ProverError),
}

#[derive(Debug, Error)]
pub enum PreTransactionPoiError {
    #[error("POI proof input count mismatch: expected {expected}, got {got}")]
    InputCountMismatch { expected: usize, got: usize },
    #[error("POI output count mismatch: expected at least {expected}, got {got}")]
    OutputCountMismatch { expected: usize, got: usize },
    #[error("missing private output before unshield marker")]
    MissingPrivateOutputBeforeUnshield,
    #[error("POI merkle proof count mismatch: expected {expected}, got {got}")]
    MerkleProofCountMismatch { expected: usize, got: usize },
    #[error("POI merkle proof leaf mismatch at index {index}: expected {expected}, got {actual}")]
    MerkleProofLeafMismatch {
        index: usize,
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error(
        "POI merkle proof path length mismatch at index {index}: expected {expected}, got {got}"
    )]
    MerkleProofPathLengthMismatch {
        index: usize,
        expected: usize,
        got: usize,
    },
    #[error("TXID merkle proof path length mismatch: expected {expected}, got {got}")]
    TxidMerkleProofPathLengthMismatch { expected: usize, got: usize },
    #[error("TXID leaf hash mismatch: expected {expected}, got {actual}")]
    TxidLeafHashMismatch {
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("POI public signal count mismatch: expected {expected}, got {got}")]
    PublicSignalCountMismatch { expected: usize, got: usize },
    #[error("POI public signal mismatch for {field}: expected {expected}, got {actual}")]
    PublicSignalMismatch {
        field: &'static str,
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("invalid hex field {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("POI RPC failed: {0}")]
    PoiRpc(#[from] PoiRpcError),
    #[error("POI merkle proof source failed: {0}")]
    ProofSource(String),
    #[error("POI prove failed: {0}")]
    Prover(#[from] ProverError),
}
