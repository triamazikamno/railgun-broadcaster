use alloy::primitives::FixedBytes;
use thiserror::Error;
use broadcaster_core::crypto::snark_proof::SnarkProofError;

#[derive(Debug, Error)]
pub enum PoiError {
    #[error("POI validation failed for listKey={list_key}: {source}")]
    ValidateList {
        list_key: FixedBytes<32>,
        #[source]
        source: Box<Self>,
    },
    #[error("missing required listKey in POI map")]
    MissingListKey,
    #[error("missing POI proof for txidLeafHash={leaf_hex}")]
    MissingProof { leaf_hex: FixedBytes<32> },
    #[error("txidMerkleroot mismatch. expected(dummy)={expected}, got={actual}")]
    TxidMerklerootMismatch {
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("RPC request failed: {source}")]
    RpcRequest {
        #[from]
        source: PoiRpcError,
    },
    #[error("POI node rejected merkle roots")]
    MerkleRootsRejected,
    #[error("invalid SNARK proof")]
    InvalidSnarkProof,
    #[error("SNARK verification failed: {source}")]
    SnarkVerify {
        #[from]
        source: SnarkProofError,
    },
}

#[derive(Debug, Error)]
pub enum PoiRpcError {
    #[error("POI RPC POST failed: {0}")]
    Post(#[from] reqwest::Error),
    #[error("POI RPC HTTP {status}: {body}")]
    HttpStatus {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("POI RPC JSON decode failed: {0}")]
    JsonDecode(#[source] reqwest::Error),
    #[error("POI RPC response decode failed: {0}")]
    ResponseDecode(#[source] reqwest::Error),
    #[error("txid merkleroot not found")]
    TxidMerklerootNotFound,
}
