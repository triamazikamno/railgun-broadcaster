use aes_gcm::aead::AeadInPlace;
use aes_gcm::{AesGcm, KeyInit, Nonce, Tag};
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use alloy::primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use curve25519_dalek::scalar::Scalar;
use openssl::symm::{Cipher, Crypter, Mode};
use ruint::uint;

use crate::crypto::poseidon::poseidon;

type Aes256Gcm16 = AesGcm<aes::Aes256, typenum::U16>;

#[derive(Debug, Error)]
pub enum TransactError {
    #[error("invalid ed25519 pubkey")]
    InvalidEd25519Pubkey,
    #[error("shared key error")]
    SharedKey,
    #[error("aes key error")]
    AesKey,
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
    #[error("openssl error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
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
    let iv = &ivtag[..16];
    let tag = &ivtag[16..];

    let cipher = Aes256Gcm16::new_from_slice(shared_key).map_err(|_| TransactError::AesKey)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);
    #[allow(deprecated)]
    let tag = Tag::from_slice(tag);

    if cipher
        .decrypt_in_place_detached(nonce, b"", &mut ct, tag)
        .is_err()
    {
        return Ok(None);
    }

    tracing::debug!(ct=%String::from_utf8_lossy(&ct), "deserializing plaintext");
    let params: T = serde_json::from_slice(&ct)?;

    Ok(Some(params))
}

sol! {
    struct G1Point { uint256 x; uint256 y; }
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct SnarkProof { G1Point a; G2Point b; G1Point c; }

    struct CommitmentCiphertext {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertext[] commitmentCiphertext;
    }

    struct TokenData {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    struct CommitmentPreimage {
        bytes32 npk;
        TokenData token;
        uint120 value;
    }

    struct Transaction {
        SnarkProof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParams boundParams;
        CommitmentPreimage unshieldPreimage;
    }

    function transact(Transaction[] _transactions) payable;

    #[derive(Debug)]
    struct Call {
        address to;
        bytes data;
        uint256 value;
    }

    #[derive(Debug)]
    struct ActionData {
        bytes31 random;
        bool requireSuccess;
        uint256 minGasLimit;
        Call[] calls;
    }
    function relay(Transaction[] calldata _transactions, ActionData calldata _actionData) payable;
}

const SNARK_PRIME: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub const MERKLE_ZERO_VALUE: U256 =
    uint!(2051258411002736885948763699317990061539314419500486054347250703186609807356_U256);

fn pad_to_13_with_merkle_zero(mut v: Vec<U256>) -> Vec<U256> {
    while v.len() < 13 {
        v.push(MERKLE_ZERO_VALUE);
    }
    v.truncate(13);
    v
}

fn hash_bound_params_v2(bound_params: &BoundParams) -> U256 {
    let encoded = bound_params.abi_encode();
    let h = keccak256(encoded);
    let x = U256::from_be_bytes(*h);
    x % SNARK_PRIME
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

    let nullifiers_hash = poseidon(pad_to_13_with_merkle_zero(nullifiers));
    let commitments_hash = poseidon(pad_to_13_with_merkle_zero(commitments));

    let bound_params_hash = hash_bound_params_v2(&tx0.boundParams);

    poseidon(vec![nullifiers_hash, commitments_hash, bound_params_hash])
}

fn private_scalar_from_viewing_privkey(vpriv: &[u8; 32]) -> Scalar {
    let h = Sha512::digest(vpriv);
    let mut head = [0u8; 32];
    head.copy_from_slice(&h[..32]);

    head[0] &= 248;
    head[31] &= 127;
    head[31] |= 64;

    Scalar::from_bytes_mod_order(head)
}

fn shared_symmetric_key(
    vpriv: &[u8; 32],
    blinded_sender_viewing_key: &[u8; 32],
) -> Result<[u8; 32], TransactError> {
    let scalar = private_scalar_from_viewing_privkey(vpriv);

    let point = CompressedEdwardsY(*blinded_sender_viewing_key)
        .decompress()
        .ok_or(TransactError::InvalidEd25519Pubkey)?;

    let shared_point = (point * scalar).compress().to_bytes();

    let digest = Sha256::digest(shared_point);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn aes_256_gcm_decrypt_16b_iv(
    key: &[u8; 32],
    iv16: &[u8; 16],
    tag16: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TransactError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv16))?;

    crypter.set_tag(tag16)?;

    let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
    let n1 = crypter.update(ciphertext, &mut out)?;
    let n2 = crypter.finalize(&mut out[n1..])?;
    out.truncate(n1 + n2);
    Ok(out)
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

    let iv_tag_bytes = cc0.ciphertext[0].0;
    let mut iv = [0u8; 16];
    let mut tag = [0u8; 16];
    iv.copy_from_slice(&iv_tag_bytes[..16]);
    tag.copy_from_slice(&iv_tag_bytes[16..]);

    let mut ct = Vec::with_capacity(32 * 3 + cc0.memo.len());
    ct.extend_from_slice(&cc0.ciphertext[1].0);
    ct.extend_from_slice(&cc0.ciphertext[2].0);
    ct.extend_from_slice(&cc0.ciphertext[3].0);
    ct.extend_from_slice(&cc0.memo);

    let blinded_sender = cc0.blindedSenderViewingKey.0;
    let key = shared_symmetric_key(viewing_privkey, &blinded_sender)?;

    let pt = aes_256_gcm_decrypt_16b_iv(&key, &iv, &tag, &ct)?;

    if pt.len() < 96 {
        return Err(TransactError::PlaintextTooShort { len: pt.len() });
    }

    let token_hash = &pt[32..64];
    if token_hash[..12] != [0u8; 12] {
        return Err(TransactError::InvalidTokenHash);
    }
    let fee_token = Address::from_slice(&token_hash[12..32]);
    let fee_amount = U256::from_be_slice(&pt[64 + 16..96]);

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
