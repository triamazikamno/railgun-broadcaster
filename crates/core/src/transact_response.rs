use serde::Serialize;
use thiserror::Error;

use alloy::primitives::{Bytes, TxHash};

use crate::crypto::aes_gcm::{AesGcmError, encrypt_in_place_16b_iv};

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("serialize payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("getrandom failed")]
    GetRandom,
    #[error("invalid aes key")]
    InvalidKey,
    #[error("encrypt failed")]
    Encrypt,
}

fn encrypt_json_with_shared_key<T: Serialize>(
    shared_key: &[u8; 32],
    payload: &T,
) -> Result<([u8; 32], Vec<u8>), ResponseError> {
    let mut pt = serde_json::to_vec(payload)?;
    let iv_tag = encrypt_in_place_16b_iv(shared_key, &mut pt).map_err(|err| match err {
        AesGcmError::InvalidKey => ResponseError::InvalidKey,
        AesGcmError::RandomFailed => ResponseError::GetRandom,
        AesGcmError::EncryptFailed | AesGcmError::DecryptFailed => ResponseError::Encrypt,
    })?;
    Ok((iv_tag, pt))
}

fn build_transact_response_message(
    id: Option<u64>,
    shared_key: &[u8; 32],
    payload: &serde_json::Value,
) -> Result<Vec<u8>, ResponseError> {
    #[derive(Debug, Serialize)]
    struct JsonRpcEncryptedResult {
        pub jsonrpc: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub id: Option<u64>,
        pub result: [Bytes; 2],
    }

    let (iv_tag, ct) = encrypt_json_with_shared_key(shared_key, payload)?;

    let msg = JsonRpcEncryptedResult {
        jsonrpc: "2.0",
        id,
        result: [Bytes::copy_from_slice(&iv_tag), Bytes::from(ct)],
    };

    Ok(serde_json::to_vec(&msg)?)
}

pub fn build_transact_response_txhash(
    id: Option<u64>,
    shared_key: &[u8; 32],
    tx_hash: TxHash,
) -> Result<Vec<u8>, ResponseError> {
    let payload = serde_json::json!({ "txHash": tx_hash.to_string() });
    build_transact_response_message(id, shared_key, &payload)
}

#[allow(dead_code)]
pub fn build_transact_response_error(
    id: Option<u64>,
    shared_key: &[u8; 32],
    error: &str,
) -> Result<Vec<u8>, ResponseError> {
    let payload = serde_json::json!({ "error": error });
    build_transact_response_message(id, shared_key, &payload)
}
