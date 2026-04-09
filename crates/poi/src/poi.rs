use crate::error::{PoiError, PoiRpcError};
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, FeeNoteAssuranceContext, ParsedTransactCalldata,
    railgun_txid_leaf_hash, txid_version_or_default,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

pub struct Poi {
    rpc_client: PoiRpcClient,
    snark_prover: Arc<Prover>,
    required_poi_list: Vec<FixedBytes<32>>,
}

impl Poi {
    pub const fn new(
        rpc_client: PoiRpcClient,
        snark_prover: Arc<Prover>,
        required_poi_list: Vec<FixedBytes<32>>,
    ) -> Self {
        Self {
            rpc_client,
            snark_prover,
            required_poi_list,
        }
    }

    pub async fn validate_all(
        &self,
        parsed_calldata: &ParsedTransactCalldata,
        params: &BroadcasterRawParamsTransact,
    ) -> Result<(), PoiError> {
        for list_key in &self.required_poi_list {
            self.validate(parsed_calldata, params, list_key)
                .await
                .map_err(|source| PoiError::ValidateList {
                    list_key: *list_key,
                    source: Box::new(source),
                })?;
        }
        Ok(())
    }

    async fn validate(
        &self,
        parsed_calldata: &ParsedTransactCalldata,
        params: &BroadcasterRawParamsTransact,
        required_list_key: &FixedBytes<32>,
    ) -> Result<(), PoiError> {
        let leaf =
            railgun_txid_leaf_hash(parsed_calldata.railgun_txid, parsed_calldata.utxo_tree_in);
        let leaf_hex: FixedBytes<32> = leaf.into();

        let per_list = params
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(required_list_key)
            .ok_or(PoiError::MissingListKey)?;

        let poi = per_list
            .get(&leaf_hex)
            .ok_or(PoiError::MissingProof { leaf_hex })?;

        let expected_root = FixedBytes::from(dummy_txid_root(leaf).to_be_bytes::<32>());
        if expected_root != poi.txid_merkleroot {
            return Err(PoiError::TxidMerklerootMismatch {
                expected: expected_root,
                actual: poi.txid_merkleroot,
            });
        }
        let txid_version = txid_version_or_default(params.txid_version.as_deref());
        let ok = self
            .rpc_client
            .validate_poi_merkleroots(
                txid_version,
                params.chain_type as u8,
                params.chain_id,
                required_list_key,
                &poi.poi_merkleroots
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .await?;

        if !ok {
            return Err(PoiError::MerkleRootsRejected);
        }

        let snark_ok = self.snark_prover.verify(
            parsed_calldata.tx_nullifiers_len,
            parsed_calldata.tx_commitments_out_len,
            poi,
        )?;

        if !snark_ok {
            return Err(PoiError::InvalidSnarkProof);
        }

        Ok(())
    }

    pub async fn submit_fee_note_single_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        context: &FeeNoteAssuranceContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        debug!(
            method = POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            chain_type,
            chain_id,
            txid_version = %context.txid_version,
            fee_commitment = %encode_fixed_bytes(&context.fee_commitment),
            fee_note_npk = %encode_fixed_bytes(&context.fee_note_npk),
            railgun_txid = %encode_u256(context.railgun_txid),
            utxo_tree_in = context.utxo_tree_in,
            utxo_tree_out,
            utxo_position_out,
            required_poi_list_keys = ?context
                .required_poi_list_keys
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            poi_list_keys = ?context
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "submit fee-note single-commitment poi"
        );
        self.rpc_client
            .submit_single_commitment_proofs(
                &context.txid_version,
                chain_type,
                chain_id,
                context,
                utxo_tree_out,
                utxo_position_out,
            )
            .await?;
        Ok(())
    }

    pub async fn fee_note_statuses_for_blinded_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        required_poi_list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<BTreeMap<FixedBytes<32>, PoiStatus>, PoiError> {
        debug!(
            method = POI_POIS_PER_LIST_METHOD,
            chain_type,
            chain_id,
            txid_version,
            fee_blinded_commitment = %encode_fixed_bytes(blinded_commitment),
            required_poi_list_keys = ?required_poi_list_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "query fee-note poi statuses for candidate commitment"
        );
        self.rpc_client
            .pois_per_list(
                txid_version,
                chain_type,
                chain_id,
                required_poi_list_keys,
                blinded_commitment,
            )
            .await
    }
}

const POI_VALIDATE_MERKLEROOTS_METHOD: &str = "ppoi_validate_poi_merkleroots";
const POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD: &str = "ppoi_submit_single_commitment_proofs";
const POI_POIS_PER_LIST_METHOD: &str = "ppoi_pois_per_list";

#[derive(Debug, Serialize)]
struct JsonRpcReq<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResp<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainParams {
    chain_type: String,
    #[serde(rename = "chainID")]
    chain_id: String,
    txid_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidatePOIMerklerootsParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    poi_merkleroots: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitSingleCommitmentProofsParams {
    #[serde(flatten)]
    chain: ChainParams,
    single_commitment_proofs_data: SingleCommitmentProofsData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SingleCommitmentProofsData {
    commitment: String,
    npk: String,
    utxo_tree_in: u64,
    utxo_tree_out: u64,
    utxo_position_out: u64,
    railgun_txid: String,
    pois: BTreeMap<String, BTreeMap<String, SubmitPreTxPoi>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitPreTxPoi {
    snark_proof: SubmitSnarkJsProof,
    txid_merkleroot: String,
    poi_merkleroots: Vec<String>,
    blinded_commitments_out: Vec<String>,
    railgun_txid_if_has_unshield: String,
}

#[derive(Debug, Serialize)]
struct SubmitSnarkJsProof {
    pi_a: [String; 2],
    pi_b: [[String; 2]; 2],
    pi_c: [String; 2],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPoisPerListParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_keys: Vec<String>,
    blinded_commitment_datas: Vec<BlindedCommitmentData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlindedCommitmentData {
    blinded_commitment: String,
    #[serde(rename = "type")]
    commitment_type: &'static str,
}

pub type PoisPerListMap = BTreeMap<String, BTreeMap<String, PoiStatus>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoiStatus {
    Valid,
    ShieldBlocked,
    ProofSubmitted,
    Missing,
}

pub struct PoiRpcClient {
    base_url: Url,
    http: reqwest::Client,
    next_id: std::sync::atomic::AtomicU64,
}

impl PoiRpcClient {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            http: reqwest::Client::new(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Creates a client that routes all traffic through the given
    /// pre-configured [`reqwest::Client`] (e.g. one with a SOCKS proxy).
    #[must_use]
    pub const fn with_http_client(base_url: Url, http: reqwest::Client) -> Self {
        Self {
            base_url,
            http,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn chain_params(txid_version: &str, chain_type: u8, chain_id: u64) -> ChainParams {
        ChainParams {
            chain_type: chain_type.to_string(),
            chain_id: chain_id.to_string(),
            txid_version: txid_version.to_string(),
        }
    }

    async fn send_request<P, R>(&self, method: &'static str, params: P) -> Result<R, PoiRpcError>
    where
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let req = JsonRpcReq {
            jsonrpc: "2.0",
            id: self.next_id(),
            method,
            params,
        };

        let resp = self
            .http
            .post(self.base_url.clone())
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(PoiRpcError::HttpStatus { status, body });
        }

        let body = resp.text().await?;
        decode_json_rpc_response(&body)
    }

    async fn send_request_allow_missing_result<P>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<(), PoiRpcError>
    where
        P: Serialize,
    {
        let req = JsonRpcReq {
            jsonrpc: "2.0",
            id: self.next_id(),
            method,
            params,
        };

        let resp = self
            .http
            .post(self.base_url.clone())
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(PoiRpcError::HttpStatus { status, body });
        }

        let body = resp.text().await?;
        decode_json_rpc_ack_response(&body)
    }

    fn submit_single_commitment_pois(
        context: &FeeNoteAssuranceContext,
    ) -> BTreeMap<String, BTreeMap<String, SubmitPreTxPoi>> {
        context
            .pre_transaction_pois_per_txid_leaf_per_list
            .iter()
            .map(|(list_key, per_leaf)| {
                (
                    hex::encode(list_key),
                    per_leaf
                        .iter()
                        .map(|(leaf, poi)| {
                            (
                                hex::encode(leaf),
                                SubmitPreTxPoi {
                                    snark_proof: SubmitSnarkJsProof {
                                        pi_a: poi.snark_proof.pi_a.map(|value| value.to_string()),
                                        pi_b: poi
                                            .snark_proof
                                            .pi_b
                                            .map(|row| row.map(|value| value.to_string())),
                                        pi_c: poi.snark_proof.pi_c.map(|value| value.to_string()),
                                    },
                                    txid_merkleroot: hex::encode(poi.txid_merkleroot),
                                    poi_merkleroots: poi
                                        .poi_merkleroots
                                        .iter()
                                        .map(hex::encode)
                                        .collect(),
                                    blinded_commitments_out: poi
                                        .blinded_commitments_out
                                        .iter()
                                        .map(encode_fixed_bytes)
                                        .collect(),
                                    railgun_txid_if_has_unshield: encode_bytes(
                                        &poi.railgun_txid_if_has_unshield,
                                    ),
                                },
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn validate_poi_merkleroots_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[String],
    ) -> ValidatePOIMerklerootsParams {
        ValidatePOIMerklerootsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            poi_merkleroots: poi_merkleroots.to_vec(),
        }
    }

    fn submit_single_commitment_proofs_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &FeeNoteAssuranceContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> SubmitSingleCommitmentProofsParams {
        SubmitSingleCommitmentProofsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            single_commitment_proofs_data: SingleCommitmentProofsData {
                commitment: encode_fixed_bytes(&context.fee_commitment),
                npk: encode_fixed_bytes(&context.fee_note_npk),
                utxo_tree_in: context.utxo_tree_in,
                utxo_tree_out,
                utxo_position_out,
                railgun_txid: encode_u256_bare(context.railgun_txid),
                pois: Self::submit_single_commitment_pois(context),
            },
        }
    }

    fn pois_per_list_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> GetPoisPerListParams {
        GetPoisPerListParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_keys: list_keys.iter().map(hex::encode).collect(),
            blinded_commitment_datas: vec![BlindedCommitmentData {
                blinded_commitment: encode_fixed_bytes(blinded_commitment),
                commitment_type: "Transact",
            }],
        }
    }

    async fn validate_poi_merkleroots(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[String],
    ) -> Result<bool, PoiRpcError> {
        self.send_request(
            POI_VALIDATE_MERKLEROOTS_METHOD,
            Self::validate_poi_merkleroots_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                poi_merkleroots,
            ),
        )
        .await
    }

    async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &FeeNoteAssuranceContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiRpcError> {
        self.send_request_allow_missing_result(
            POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            Self::submit_single_commitment_proofs_params(
                txid_version,
                chain_type,
                chain_id,
                context,
                utxo_tree_out,
                utxo_position_out,
            ),
        )
        .await
    }

    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<BTreeMap<FixedBytes<32>, PoiStatus>, PoiError> {
        let blinded_commitment_hex = encode_fixed_bytes(blinded_commitment);
        let response: PoisPerListMap = self
            .send_request(
                POI_POIS_PER_LIST_METHOD,
                Self::pois_per_list_params(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_keys,
                    blinded_commitment,
                ),
            )
            .await?;

        let per_list = response
            .get(&blinded_commitment_hex)
            .cloned()
            .unwrap_or_default();

        Ok(list_keys
            .iter()
            .copied()
            .map(|list_key| {
                let status = per_list
                    .get(&hex::encode(list_key))
                    .copied()
                    .unwrap_or(PoiStatus::Missing);
                (list_key, status)
            })
            .collect())
    }
}

fn decode_json_rpc_response<R>(body: &str) -> Result<R, PoiRpcError>
where
    R: for<'de> Deserialize<'de>,
{
    let parsed: JsonRpcResp<R> = serde_json::from_str(body).map_err(PoiRpcError::JsonDecode)?;
    if let Some(error) = parsed.error {
        return Err(PoiRpcError::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    parsed.result.ok_or(PoiRpcError::MissingResult)
}

fn decode_json_rpc_ack_response(body: &str) -> Result<(), PoiRpcError> {
    let parsed: JsonRpcResp<serde_json::Value> =
        serde_json::from_str(body).map_err(PoiRpcError::JsonDecode)?;
    if let Some(error) = parsed.error {
        return Err(PoiRpcError::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    Ok(())
}

const TREE_DEPTH: usize = 16;

fn dummy_txid_root(leaf: U256) -> U256 {
    let mut acc = leaf;
    for _ in 0..TREE_DEPTH {
        acc = poseidon(vec![acc, U256::ZERO]);
    }
    acc
}

fn encode_fixed_bytes(value: &FixedBytes<32>) -> String {
    format!("0x{}", hex::encode(value))
}

fn encode_u256(value: U256) -> String {
    format!("0x{value:064x}")
}

fn encode_u256_bare(value: U256) -> String {
    format!("{value:064x}")
}

fn encode_bytes(value: &alloy::primitives::Bytes) -> String {
    if value.is_empty() {
        "0x00".to_string()
    } else {
        format!("0x{}", hex::encode(value))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PoiRpcClient, PoiStatus, decode_json_rpc_ack_response, decode_json_rpc_response,
        encode_fixed_bytes, encode_u256_bare, railgun_txid_leaf_hash,
    };
    use crate::error::PoiRpcError;
    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
    use serde_json::to_value;
    use std::collections::BTreeMap;

    fn sample_context() -> FeeNoteAssuranceContext {
        let list_key = FixedBytes::from([0x11; 32]);
        let leaf = FixedBytes::from([0x22; 32]);
        let poi = PreTxPoi {
            snark_proof: SnarkJsProof {
                pi_a: [U256::ZERO, U256::ZERO],
                pi_b: [[U256::ZERO, U256::ZERO], [U256::ZERO, U256::ZERO]],
                pi_c: [U256::ZERO, U256::ZERO],
            },
            txid_merkleroot: FixedBytes::from([0x33; 32]),
            poi_merkleroots: vec![FixedBytes::from([0x44; 32])],
            blinded_commitments_out: vec![FixedBytes::from([0x55; 32])],
            railgun_txid_if_has_unshield: alloy::primitives::Bytes::new(),
        };
        let mut per_leaf = BTreeMap::new();
        per_leaf.insert(leaf, poi);
        let mut per_list = BTreeMap::new();
        per_list.insert(list_key, per_leaf);

        FeeNoteAssuranceContext {
            chain_type: 0,
            txid_version: "V3_PoseidonMerkle".to_string(),
            railgun_txid: U256::from(9_u8),
            utxo_tree_in: 7,
            fee_commitment: FixedBytes::from([0x66; 32]),
            fee_note_npk: FixedBytes::from([0x77; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: per_list,
            required_poi_list_keys: vec![list_key],
        }
    }

    #[test]
    fn validate_request_uses_non_default_txid_version() {
        let params = PoiRpcClient::validate_poi_merkleroots_params(
            "V3_PoseidonMerkle",
            0,
            1,
            &FixedBytes::from([0x99; 32]),
            &["abcd".to_string()],
        );
        let json = to_value(params).expect("serialize validate params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(json["chainType"], "0");
        assert_eq!(json["chainID"], "1");
    }

    #[test]
    fn single_commitment_submit_request_serializes_context() {
        let context = sample_context();
        let params = PoiRpcClient::submit_single_commitment_proofs_params(
            &context.txid_version,
            0,
            1,
            &context,
            10,
            12,
        );
        let json = to_value(params).expect("serialize submit params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(
            json["singleCommitmentProofsData"]["commitment"],
            encode_fixed_bytes(&context.fee_commitment)
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["npk"],
            encode_fixed_bytes(&context.fee_note_npk)
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["railgunTxid"],
            encode_u256_bare(context.railgun_txid)
        );
        assert_eq!(json["singleCommitmentProofsData"]["utxoTreeOut"], 10);
        assert_eq!(json["singleCommitmentProofsData"]["utxoPositionOut"], 12);
        assert!(
            json["singleCommitmentProofsData"]["pois"]
                .get(hex::encode(context.required_poi_list_keys[0]))
                .is_some()
        );
        assert!(
            json["singleCommitmentProofsData"]["pois"]
                .get(format!(
                    "0x{}",
                    hex::encode(context.required_poi_list_keys[0])
                ))
                .is_none()
        );
    }

    #[test]
    fn single_commitment_submit_request_uses_bare_hex_poi_keys() {
        let context = sample_context();
        let params = PoiRpcClient::submit_single_commitment_proofs_params(
            &context.txid_version,
            0,
            1,
            &context,
            10,
            12,
        );
        let json = to_value(params).expect("serialize submit params");
        let list_key = hex::encode(context.required_poi_list_keys[0]);
        let leaf_key = hex::encode(
            context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(&context.required_poi_list_keys[0])
                .expect("list")
                .keys()
                .next()
                .expect("leaf"),
        );

        assert!(
            json["singleCommitmentProofsData"]["pois"][&list_key]
                .get(&leaf_key)
                .is_some()
        );
        assert!(
            json["singleCommitmentProofsData"]["pois"][&list_key]
                .get(format!("0x{leaf_key}"))
                .is_none()
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["txidMerkleroot"],
            hex::encode(FixedBytes::from([0x33; 32]))
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["poiMerkleroots"][0],
            hex::encode(FixedBytes::from([0x44; 32]))
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["blindedCommitmentsOut"]
                [0],
            encode_fixed_bytes(&FixedBytes::from([0x55; 32]))
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["railgunTxidIfHasUnshield"],
            "0x00"
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["snarkProof"]["pi_a"]
                [0],
            "0"
        );
    }

    #[test]
    fn pois_per_list_query_serializes_blinded_commitment_request() {
        let context = sample_context();
        let blinded_commitment = FixedBytes::from([0x88; 32]);
        let params = PoiRpcClient::pois_per_list_params(
            &context.txid_version,
            0,
            1,
            &context.required_poi_list_keys,
            &blinded_commitment,
        );
        let json = to_value(params).expect("serialize pois per list params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(
            json["listKeys"][0],
            hex::encode(context.required_poi_list_keys[0])
        );
        assert_eq!(json["blindedCommitmentDatas"][0]["type"], "Transact");
        assert_eq!(
            json["blindedCommitmentDatas"][0]["blindedCommitment"],
            encode_fixed_bytes(&blinded_commitment)
        );
    }

    #[test]
    fn missing_list_status_defaults_to_missing() {
        let blinded_commitment = FixedBytes::from([0x88; 32]);
        let response = BTreeMap::from([(
            encode_fixed_bytes(&blinded_commitment),
            BTreeMap::from([("deadbeef".to_string(), PoiStatus::Valid)]),
        )]);
        let list_key = FixedBytes::from([0x11; 32]);
        let per_list = response
            .get(&encode_fixed_bytes(&blinded_commitment))
            .cloned()
            .unwrap_or_default();

        let status = per_list
            .get(&hex::encode(list_key))
            .copied()
            .unwrap_or(PoiStatus::Missing);
        assert_eq!(status, PoiStatus::Missing);
    }

    #[test]
    fn txid_leaf_hash_matches_existing_poseidon_path() {
        let leaf = railgun_txid_leaf_hash(U256::from(1_u8), 2);
        assert_ne!(leaf, U256::ZERO);
    }

    #[test]
    fn decode_json_rpc_success_response() {
        let result: bool = decode_json_rpc_response(r#"{"result":true}"#).expect("decode result");
        assert!(result);
    }

    #[test]
    fn decode_json_rpc_error_response() {
        let error = decode_json_rpc_response::<bool>(
            r#"{"error":{"code":-32000,"message":"invalid proof","data":{"detail":"bad npk"}}}"#,
        )
        .expect_err("json-rpc error");

        match error {
            PoiRpcError::JsonRpc {
                code,
                message,
                data,
            } => {
                assert_eq!(code, -32000);
                assert_eq!(message, "invalid proof");
                assert_eq!(data.expect("data")["detail"], "bad npk");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decode_json_rpc_missing_result_is_decode_error() {
        let error = decode_json_rpc_response::<bool>(r"{}").expect_err("missing result error");

        assert!(matches!(error, PoiRpcError::MissingResult));
    }

    #[test]
    fn decode_json_rpc_ack_response_without_result_is_success() {
        decode_json_rpc_ack_response(r#"{"jsonrpc":"2.0","id":2}"#)
            .expect("ack response should succeed");
    }

    #[test]
    fn decode_json_rpc_ack_response_with_error_fails() {
        let error = decode_json_rpc_ack_response(
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"bad request"}}"#,
        )
        .expect_err("ack error");

        assert!(matches!(error, PoiRpcError::JsonRpc { .. }));
    }
}
