use serde::{Deserialize, Serialize};
use thiserror::Error;

use alloy::primitives::{Bytes, TxHash};

use crate::crypto::aes_gcm::{AesGcmError, decrypt_in_place_16b_iv, encrypt_in_place_16b_iv};

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("json payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("getrandom failed")]
    GetRandom,
    #[error("invalid aes key")]
    InvalidKey,
    #[error("encrypt failed")]
    Encrypt,
    #[error("invalid iv/tag length: {len}")]
    InvalidIvTag { len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedTransactResponse {
    TxHash(String),
    Error(String),
}

#[derive(Debug, Deserialize)]
struct JsonRpcEncryptedResult {
    pub result: [Bytes; 2],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactResponsePayload {
    tx_hash: Option<String>,
    error: Option<String>,
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

pub fn try_decrypt_transact_response_message(
    shared_key: &[u8; 32],
    message: &[u8],
) -> Result<Option<DecryptedTransactResponse>, ResponseError> {
    let encrypted: JsonRpcEncryptedResult = serde_json::from_slice(message)?;
    let iv_tag = &encrypted.result[0];
    if iv_tag.len() != 32 {
        return Err(ResponseError::InvalidIvTag { len: iv_tag.len() });
    }
    let mut iv = [0u8; 16];
    let mut tag = [0u8; 16];
    iv.copy_from_slice(&iv_tag[..16]);
    tag.copy_from_slice(&iv_tag[16..]);
    let mut ciphertext = encrypted.result[1].to_vec();
    match decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut ciphertext) {
        Ok(()) => {}
        Err(AesGcmError::DecryptFailed) => return Ok(None),
        Err(AesGcmError::InvalidKey) => return Err(ResponseError::InvalidKey),
        Err(AesGcmError::RandomFailed) => return Err(ResponseError::GetRandom),
        Err(AesGcmError::EncryptFailed) => return Err(ResponseError::Encrypt),
    }
    let payload: TransactResponsePayload = serde_json::from_slice(&ciphertext)?;
    if let Some(tx_hash) = payload.tx_hash {
        return Ok(Some(DecryptedTransactResponse::TxHash(tx_hash)));
    }
    if let Some(error) = payload.error {
        return Ok(Some(DecryptedTransactResponse::Error(error)));
    }
    Ok(None)
}
