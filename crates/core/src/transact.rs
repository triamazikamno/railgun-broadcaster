use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use ruint::uint;

use crate::contracts::railgun::{ActionData, Transaction, relayCall, transactCall};
use crate::crypto::aes_gcm::{AesGcmError, decrypt_in_place_16b_iv, split_iv_tag};
use crate::crypto::poseidon::poseidon;
use crate::crypto::shared_key::shared_symmetric_key;

#[derive(Debug, Error)]
pub enum TransactError {
    #[error("invalid ed25519 pubkey")]
    InvalidEd25519Pubkey,
    #[error("shared key error")]
    SharedKey,
    #[error(transparent)]
    AesGcm(#[from] AesGcmError),
    #[error("ivtag must be 32 bytes, got {len}")]
    InvalidIvTag { len: usize },
    #[error("calldata too short: {len}")]
    CalldataTooShort { len: usize },
    #[error("unknown function call: {selector}")]
    UnknownFunctionCall { selector: String },
    #[error("no transactions")]
    MissingTransactions,
    #[error("no commitment ciphertext")]
    MissingCommitmentCiphertext,
    #[error("plaintext too short: {len}")]
    PlaintextTooShort { len: usize },
    #[error("token hash invalid")]
    InvalidTokenHash,
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("abi decode error: {0}")]
    AbiDecode(#[from] alloy::sol_types::Error),
}

/// X25519 clamp
const fn clamp25519(mut b: [u8; 32]) -> [u8; 32] {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    b
}

/// Convert Ed25519 seed -> X25519 scalar bytes
fn ed_seed_to_x25519_scalar(seed32: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed32);
    clamp25519(hash[..32].try_into().expect("sha512 output is 512 bits"))
}

/// Ed25519 pubkey (compressed Edwards Y) -> Montgomery u
fn ed25519_pub_to_montgomery_u(ed_pub: &[u8; 32]) -> Result<[u8; 32], TransactError> {
    let comp = CompressedEdwardsY(*ed_pub);
    let point = comp
        .decompress()
        .ok_or(TransactError::InvalidEd25519Pubkey)?;
    Ok(point.to_montgomery().to_bytes())
}

fn shared_key_32(
    viewing_priv_seed: &[u8; 32],
    client_ed_pub: &[u8; 32],
) -> Result<[u8; 32], TransactError> {
    let scalar = ed_seed_to_x25519_scalar(viewing_priv_seed);
    let mont_u = ed25519_pub_to_montgomery_u(client_ed_pub)?;
    let secret = StaticSecret::from(scalar);
    let peer = X25519PublicKey::from(mont_u);
    Ok(secret.diffie_hellman(&peer).to_bytes())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcasterRawParamsTransact {
    pub chain_type: u64,
    #[serde(rename = "chainID")]
    pub chain_id: u64,

    pub min_gas_price: U256,

    #[serde(rename = "feesID")]
    pub fees_id: Option<String>,
    pub to: Address,
    pub data: Bytes,
    pub broadcaster_viewing_key: FixedBytes<32>,

    // pub use_relay_adapt: bool,

    // pub min_version: Option<String>,
    // pub max_version: Option<String>,
    pub txid_version: Option<String>,

    #[serde(default)]
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    // pub dev_log: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreTxPoi {
    pub snark_proof: SnarkJsProof,
    pub txid_merkleroot: FixedBytes<32>,
    pub poi_merkleroots: Vec<FixedBytes<32>>,
    pub blinded_commitments_out: Vec<FixedBytes<32>>,
    pub railgun_txid_if_has_unshield: Bytes,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnarkJsProof {
    pub pi_a: [U256; 2],
    pub pi_b: [[U256; 2]; 2],
    pub pi_c: [U256; 2],
}

#[derive(Debug)]
pub struct DecryptedTransact {
    pub shared_key: [u8; 32],
    pub params: BroadcasterRawParamsTransact,
}

pub fn try_decrypt_transact_request(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<DecryptedTransact>, TransactError> {
    let shared = shared_key_32(viewing_priv_seed, &pubkey).map_err(|_| TransactError::SharedKey)?;

    if let Some(params) = decrypt::<BroadcasterRawParamsTransact>(
        &shared,
        &encrypted_data[0],
        encrypted_data[1].to_vec(),
    )? {
        tracing::debug!(
            pubkey = hex::encode(pubkey),
            ?encrypted_data,
            "decrypting transact request"
        );
        Ok(Some(DecryptedTransact {
            shared_key: shared,
            params,
        }))
    } else {
        Ok(None)
    }
}

fn decrypt<T: serde::de::DeserializeOwned>(
    shared_key: &[u8; 32],
    ivtag: &[u8],
    ct: Vec<u8>,
) -> Result<Option<T>, TransactError> {
    let mut ct = ct;
    if ivtag.len() != 32 {
        return Err(TransactError::InvalidIvTag { len: ivtag.len() });
    }
    let iv = ivtag[..16]
        .try_into()
        .map_err(|_| TransactError::InvalidIvTag { len: ivtag.len() })?;
    let tag = ivtag[16..]
        .try_into()
        .map_err(|_| TransactError::InvalidIvTag { len: ivtag.len() })?;

    match decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut ct) {
        Ok(()) => {}
        Err(AesGcmError::DecryptFailed) => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(ct=%String::from_utf8_lossy(&ct), "deserializing plaintext");
    let params: T = serde_json::from_slice(&ct)?;

    Ok(Some(params))
}

pub const MERKLE_ZERO_VALUE: U256 =
    uint!(2051258411002736885948763699317990061539314419500486054347250703186609807356_U256);

#[must_use]
pub fn pad_with_merkle_zero(mut v: Vec<U256>, target: usize) -> Vec<U256> {
    while v.len() < target {
        v.push(MERKLE_ZERO_VALUE);
    }
    v.truncate(target);
    v
}

fn compute_railgun_txid_v2(tx0: &Transaction) -> U256 {
    let nullifiers: Vec<U256> = tx0
        .nullifiers
        .iter()
        .map(|b| U256::from_be_bytes(b.0))
        .collect();

    let commitments: Vec<U256> = tx0
        .commitments
        .iter()
        .map(|b| U256::from_be_bytes(b.0))
        .collect();

    let nullifiers_hash = poseidon(pad_with_merkle_zero(nullifiers, 13));
    let commitments_hash = poseidon(pad_with_merkle_zero(commitments, 13));

    poseidon(vec![
        nullifiers_hash,
        commitments_hash,
        tx0.boundParams.hash(),
    ])
}

#[derive(Debug)]
pub struct ParsedTransactCalldata {
    pub fee_token: Address,
    pub fee_amount: U256,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub tx_nullifiers_len: usize,
    pub tx_commitments_out_len: usize,
    pub action_data: Option<ActionData>,
}

pub fn parse_transact_calldata(
    calldata: &[u8],
    viewing_privkey: &[u8; 32],
) -> Result<ParsedTransactCalldata, TransactError> {
    if calldata.len() < 4 {
        return Err(TransactError::CalldataTooShort {
            len: calldata.len(),
        });
    }
    let (transactions, action_data) = if let Ok(call) = transactCall::abi_decode(calldata) {
        (call._transactions, None)
    } else if let Ok(call) = relayCall::abi_decode(calldata) {
        (call._transactions, Some(call._actionData))
    } else {
        return Err(TransactError::UnknownFunctionCall {
            selector: hex::encode(&calldata[..4]),
        });
    };

    let tx0 = transactions
        .first()
        .ok_or(TransactError::MissingTransactions)?;

    let railgun_txid = compute_railgun_txid_v2(tx0);
    let utxo_tree_in = tx0.boundParams.treeNumber.into();

    let cc0 = tx0
        .boundParams
        .commitmentCiphertext
        .first()
        .ok_or(TransactError::MissingCommitmentCiphertext)?;

    let (iv, tag) = split_iv_tag(cc0.ciphertext[0].0);

    let mut ct = Vec::with_capacity(32 * 3 + cc0.memo.len());
    ct.extend_from_slice(&cc0.ciphertext[1].0);
    ct.extend_from_slice(&cc0.ciphertext[2].0);
    ct.extend_from_slice(&cc0.ciphertext[3].0);
    ct.extend_from_slice(&cc0.memo);

    let blinded_sender = cc0.blindedSenderViewingKey.0;
    let key = shared_symmetric_key(viewing_privkey, &blinded_sender)
        .map_err(|_| TransactError::InvalidEd25519Pubkey)?;

    decrypt_in_place_16b_iv(&key, &iv, &tag, &mut ct)?;

    if ct.len() < 96 {
        return Err(TransactError::PlaintextTooShort { len: ct.len() });
    }

    let token_hash = &ct[32..64];
    if token_hash[..12] != [0u8; 12] {
        return Err(TransactError::InvalidTokenHash);
    }
    let fee_token = Address::from_slice(&token_hash[12..32]);
    let fee_amount = U256::from_be_slice(&ct[64 + 16..96]);

    Ok(ParsedTransactCalldata {
        fee_token,
        fee_amount,
        railgun_txid,
        utxo_tree_in,
        tx_nullifiers_len: tx0.nullifiers.len(),
        tx_commitments_out_len: tx0.commitments.len(),
        action_data,
    })
}
