use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use ruint::uint;

use crate::contracts::railgun::{ActionData, Transaction, relayCall, transactCall};
use crate::crypto::aes_gcm::{AesGcmError, decrypt_in_place_16b_iv, split_iv_tag};
use crate::crypto::poseidon::poseidon;
use crate::crypto::shared_key::{ed25519_private_scalar_bytes, shared_symmetric_key};
use crate::notes::note_public_key;

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
    #[error("no commitment")]
    MissingCommitment,
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
    #[error("missing pre-transaction POI for required list key")]
    MissingPreTransactionPoiForAssurance,
    #[error("unsupported txid version: {txid_version}")]
    UnsupportedTxidVersion { txid_version: String },
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
    let scalar = ed25519_private_scalar_bytes(viewing_priv_seed);
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

    pub min_gas_price: Option<U256>,

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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

pub const DEFAULT_TXID_VERSION: &str = "V2_PoseidonMerkle";

#[must_use]
pub fn pad_with_merkle_zero(mut v: Vec<U256>, target: usize) -> Vec<U256> {
    while v.len() < target {
        v.push(MERKLE_ZERO_VALUE);
    }
    v.truncate(target);
    v
}

fn compute_railgun_txid_poseidon(tx0: &Transaction) -> U256 {
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

#[must_use]
pub fn txid_version_or_default(txid_version: Option<&str>) -> &str {
    txid_version.unwrap_or(DEFAULT_TXID_VERSION)
}

pub fn supported_txid_version(txid_version: Option<&str>) -> Result<&str, TransactError> {
    let txid_version = txid_version_or_default(txid_version);
    if txid_version == DEFAULT_TXID_VERSION {
        Ok(txid_version)
    } else {
        Err(TransactError::UnsupportedTxidVersion {
            txid_version: txid_version.to_string(),
        })
    }
}

pub fn compute_railgun_txid(
    tx0: &Transaction,
    txid_version: Option<&str>,
) -> Result<U256, TransactError> {
    let _txid_version = supported_txid_version(txid_version)?;
    Ok(compute_railgun_txid_poseidon(tx0))
}

#[must_use]
pub fn railgun_txid_leaf_hash(railgun_txid: U256, utxo_tree_in: u64) -> U256 {
    const GLOBAL_TREE_POSITION_TREE: u64 = 199_999;
    const GLOBAL_TREE_POSITION_POS: u64 = 199_999;
    const TREE_MAX_ITEMS: u64 = 65_536;

    let gpos = U256::from(GLOBAL_TREE_POSITION_TREE) * U256::from(TREE_MAX_ITEMS)
        + U256::from(GLOBAL_TREE_POSITION_POS);
    poseidon(vec![railgun_txid, U256::from(utxo_tree_in), gpos])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeNoteAssuranceContext {
    pub chain_type: u8,
    pub txid_version: String,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub fee_commitment: FixedBytes<32>,
    pub fee_note_npk: FixedBytes<32>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
}

#[derive(Debug)]
pub struct ParsedTransactCalldata {
    pub fee_token: Address,
    pub fee_amount: U256,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub fee_commitment: FixedBytes<32>,
    pub fee_note_npk: FixedBytes<32>,
    pub tx_nullifiers_len: usize,
    pub tx_commitments_out_len: usize,
    pub action_data: Option<ActionData>,
    pub fee_note_assurance: Option<FeeNoteAssuranceContext>,
}

pub fn attach_fee_note_assurance_context(
    parsed_transact: &mut ParsedTransactCalldata,
    params: &BroadcasterRawParamsTransact,
    required_poi_list_keys: &[FixedBytes<32>],
) -> Result<(), TransactError> {
    if required_poi_list_keys.is_empty() {
        parsed_transact.fee_note_assurance = None;
        return Ok(());
    }

    let txid_version = supported_txid_version(params.txid_version.as_deref())?;

    let leaf = railgun_txid_leaf_hash(parsed_transact.railgun_txid, parsed_transact.utxo_tree_in);
    let leaf_hex: FixedBytes<32> = leaf.into();

    if !required_poi_list_keys.iter().all(|list_key| {
        params
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(list_key)
            .is_some_and(|per_list| per_list.contains_key(&leaf_hex))
    }) {
        return Err(TransactError::MissingPreTransactionPoiForAssurance);
    }

    parsed_transact.fee_note_assurance = Some(FeeNoteAssuranceContext {
        chain_type: params.chain_type as u8,
        txid_version: txid_version.to_string(),
        railgun_txid: parsed_transact.railgun_txid,
        utxo_tree_in: parsed_transact.utxo_tree_in,
        fee_commitment: parsed_transact.fee_commitment,
        fee_note_npk: parsed_transact.fee_note_npk,
        pre_transaction_pois_per_txid_leaf_per_list: params
            .pre_transaction_pois_per_txid_leaf_per_list
            .clone(),
        required_poi_list_keys: required_poi_list_keys.to_vec(),
    });

    Ok(())
}

pub fn parse_transact_calldata(
    calldata: &[u8],
    viewing_privkey: &[u8; 32],
    receiver_master_public_key: U256,
    txid_version: Option<&str>,
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

    let railgun_txid = compute_railgun_txid(tx0, txid_version)?;
    let utxo_tree_in = tx0.boundParams.treeNumber.into();
    let fee_commitment = tx0
        .commitments
        .first()
        .copied()
        .ok_or(TransactError::MissingCommitment)?;

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

    let mut token_hash = [0u8; 32];
    token_hash.copy_from_slice(&ct[32..64]);
    let mut random = [0u8; 16];
    random.copy_from_slice(&ct[64..80]);
    let mut value_bytes = [0u8; 16];
    value_bytes.copy_from_slice(&ct[80..96]);

    if token_hash[..12] != [0u8; 12] {
        return Err(TransactError::InvalidTokenHash);
    }
    let fee_token = Address::from_slice(&token_hash[12..32]);
    let fee_amount = U256::from_be_slice(&value_bytes);
    let fee_note_npk: FixedBytes<32> = note_public_key(receiver_master_public_key, random).into();

    Ok(ParsedTransactCalldata {
        fee_token,
        fee_amount,
        railgun_txid,
        utxo_tree_in,
        fee_commitment,
        fee_note_npk,
        tx_nullifiers_len: tx0.nullifiers.len(),
        tx_commitments_out_len: tx0.commitments.len(),
        action_data,
        fee_note_assurance: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, PreTxPoi, SnarkJsProof, TransactError,
        attach_fee_note_assurance_context, compute_railgun_txid, parse_transact_calldata,
        railgun_txid_leaf_hash,
    };
    use crate::contracts::railgun::{
        BoundParams, CommitmentCiphertext, CommitmentPreimage, SnarkProof, TokenData, Transaction,
        transactCall,
    };
    use crate::crypto::aes_gcm::encrypt_in_place_16b_iv;
    use crate::crypto::railgun::{ViewingKeyData, derive_viewing_public_key};
    use crate::crypto::shared_key::shared_symmetric_key;
    use crate::notes::{Note, note_public_key};
    use alloy::primitives::{Address, Bytes, FixedBytes, U256};
    use alloy::sol_types::SolCall;
    use std::collections::BTreeMap;

    fn sample_viewing_key_data() -> ViewingKeyData {
        ViewingKeyData::from_spending_public_key([7u8; 32], [U256::from(3_u8), U256::from(9_u8)])
    }

    fn sample_ciphertext(
        viewing_key_data: &ViewingKeyData,
        token: Address,
        value: U256,
        random: [u8; 16],
        encoded_mpk: U256,
    ) -> CommitmentCiphertext {
        let sender_viewing_private_key = [11u8; 32];
        let blinded_sender = derive_viewing_public_key(&sender_viewing_private_key);
        let shared_key =
            shared_symmetric_key(&viewing_key_data.viewing_private_key, &blinded_sender)
                .expect("shared key");

        let mut plaintext = Vec::with_capacity(96);
        plaintext.extend_from_slice(&encoded_mpk.to_be_bytes::<32>());
        plaintext.extend_from_slice(&U256::from_be_slice(token.as_slice()).to_be_bytes::<32>());
        plaintext.extend_from_slice(&random);
        let value_bytes = value.to_be_bytes::<32>();
        plaintext.extend_from_slice(&value_bytes[16..]);
        let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext).expect("encrypt note");

        let mut ciphertext_words = [[0u8; 32]; 4];
        ciphertext_words[0].copy_from_slice(&iv_tag);
        ciphertext_words[1].copy_from_slice(&plaintext[..32]);
        ciphertext_words[2].copy_from_slice(&plaintext[32..64]);
        ciphertext_words[3].copy_from_slice(&plaintext[64..96]);

        CommitmentCiphertext {
            ciphertext: ciphertext_words.map(FixedBytes::from),
            blindedSenderViewingKey: FixedBytes::from(blinded_sender),
            blindedReceiverViewingKey: FixedBytes::ZERO,
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        }
    }

    fn sample_transaction_and_params_with_encoded_mpk(
        txid_version: Option<&str>,
        encoded_mpk: U256,
    ) -> (
        Vec<u8>,
        Transaction,
        BroadcasterRawParamsTransact,
        FixedBytes<32>,
        FixedBytes<32>,
    ) {
        let viewing_key_data = sample_viewing_key_data();
        let fee_token = Address::from([0x22; 20]);
        let fee_value = U256::from(42_u8);
        let random = [0x55; 16];
        let npk = note_public_key(viewing_key_data.master_public_key, random);
        let fee_commitment = Note {
            token_hash: U256::from_be_slice(fee_token.as_slice()),
            value: fee_value,
            random,
            npk,
        }
        .commitment();
        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::ZERO,
            nullifiers: vec![FixedBytes::from([1u8; 32])],
            commitments: vec![fee_commitment.into()],
            boundParams: BoundParams::new_transact(
                9,
                0,
                1,
                vec![sample_ciphertext(
                    &viewing_key_data,
                    fee_token,
                    fee_value,
                    random,
                    encoded_mpk,
                )],
                Address::ZERO,
                FixedBytes::ZERO,
            ),
            unshieldPreimage: CommitmentPreimage {
                npk: FixedBytes::ZERO,
                token: TokenData {
                    tokenType: 0,
                    tokenAddress: Address::ZERO,
                    tokenSubID: U256::ZERO,
                },
                value: alloy::primitives::Uint::<120, 2>::ZERO,
            },
        };

        let railgun_txid = compute_railgun_txid(&transaction, txid_version).expect("txid");
        let leaf: FixedBytes<32> = railgun_txid_leaf_hash(railgun_txid, 9).into();
        let required_list_key = FixedBytes::from([0x88; 32]);
        let pre_tx_poi = PreTxPoi {
            snark_proof: SnarkJsProof {
                pi_a: [U256::ZERO, U256::ZERO],
                pi_b: [[U256::ZERO, U256::ZERO], [U256::ZERO, U256::ZERO]],
                pi_c: [U256::ZERO, U256::ZERO],
            },
            txid_merkleroot: FixedBytes::ZERO,
            poi_merkleroots: vec![FixedBytes::ZERO],
            blinded_commitments_out: vec![FixedBytes::from([0x77; 32])],
            railgun_txid_if_has_unshield: Bytes::new(),
        };

        let mut per_leaf = BTreeMap::new();
        per_leaf.insert(leaf, pre_tx_poi);
        let mut per_list = BTreeMap::new();
        per_list.insert(required_list_key, per_leaf);

        let params = BroadcasterRawParamsTransact {
            chain_type: 0,
            chain_id: 1,
            min_gas_price: None,
            fees_id: None,
            to: Address::ZERO,
            data: transactCall {
                _transactions: vec![transaction.clone()],
            }
            .abi_encode()
            .into(),
            broadcaster_viewing_key: FixedBytes::ZERO,
            txid_version: txid_version.map(str::to_string),
            pre_transaction_pois_per_txid_leaf_per_list: per_list,
        };

        (
            transactCall {
                _transactions: vec![transaction.clone()],
            }
            .abi_encode(),
            transaction,
            params,
            fee_commitment.into(),
            FixedBytes::from([0x77; 32]),
        )
    }

    fn sample_transaction_and_params(
        txid_version: Option<&str>,
    ) -> (
        Vec<u8>,
        Transaction,
        BroadcasterRawParamsTransact,
        FixedBytes<32>,
        FixedBytes<32>,
    ) {
        let viewing_key_data = sample_viewing_key_data();
        sample_transaction_and_params_with_encoded_mpk(
            txid_version,
            viewing_key_data.master_public_key,
        )
    }

    #[test]
    fn parse_transact_extracts_fee_note_context_fields() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, _, fee_commitment, _) = sample_transaction_and_params(None);
        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(parsed.utxo_tree_in, 9);
        assert_eq!(parsed.fee_commitment, fee_commitment);
        assert!(parsed.fee_note_assurance.is_none());
    }

    #[test]
    fn parse_transact_uses_receiver_master_public_key_for_visible_sender_note() {
        let viewing_key_data = sample_viewing_key_data();
        let sender_master_public_key = U256::from(0x1234_u64);
        let encoded_mpk = viewing_key_data.master_public_key ^ sender_master_public_key;
        let (calldata, _, _, fee_commitment, _) =
            sample_transaction_and_params_with_encoded_mpk(None, encoded_mpk);

        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(parsed.fee_commitment, fee_commitment);
        let expected_npk: FixedBytes<32> =
            note_public_key(viewing_key_data.master_public_key, [0x55; 16]).into();
        assert_eq!(parsed.fee_note_npk, expected_npk);
    }

    #[test]
    fn parse_transact_rejects_unsupported_txid_version() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, _, _, _) = sample_transaction_and_params(None);

        let error = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            Some("V3_PoseidonMerkle"),
        )
        .expect_err("unsupported txid version should fail");

        assert!(matches!(
            error,
            TransactError::UnsupportedTxidVersion { txid_version }
            if txid_version == "V3_PoseidonMerkle"
        ));
    }

    #[test]
    fn attach_fee_note_assurance_context_rejects_unsupported_txid_version() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, mut params, _, _) = sample_transaction_and_params(None);
        params.txid_version = Some("V3_PoseidonMerkle".to_string());
        let mut parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        let error = attach_fee_note_assurance_context(
            &mut parsed,
            &params,
            &[FixedBytes::from([0x88; 32])],
        )
        .expect_err("unsupported txid version should fail");

        assert!(matches!(
            error,
            TransactError::UnsupportedTxidVersion { txid_version }
            if txid_version == "V3_PoseidonMerkle"
        ));
    }

    #[test]
    fn default_txid_version_is_v2_poseidon_merkle() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, transaction, _, _, _) = sample_transaction_and_params(None);
        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(
            parsed.railgun_txid,
            compute_railgun_txid(&transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
        );
    }
}
