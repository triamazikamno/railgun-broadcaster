use crate::error::{PoiError, PoiRpcError};
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{BroadcasterRawParamsTransact, ParsedTransactCalldata};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
        let txid_version = params
            .txid_version
            .as_ref()
            .map_or("V2_PoseidonMerkle", |v| v.as_str());
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
}

const POI_VALIDATE_MERKLEROOTS_METHOD: &str = "ppoi_validate_poi_merkleroots";

#[derive(Debug, Serialize)]
struct JsonRpcReq<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResp<T> {
    result: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidatePOIMerklerootsParams {
    chain_type: String,
    #[serde(rename = "chainID")]
    chain_id: String,
    txid_version: String,
    list_key: String,
    poi_merkleroots: Vec<String>,
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

    async fn validate_poi_merkleroots(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[String],
    ) -> Result<bool, PoiRpcError> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let req = JsonRpcReq {
            jsonrpc: "2.0",
            id,
            method: POI_VALIDATE_MERKLEROOTS_METHOD,
            params: ValidatePOIMerklerootsParams {
                chain_type: chain_type.to_string(),
                chain_id: chain_id.to_string(),
                txid_version: txid_version.to_string(),
                list_key: hex::encode(list_key),
                poi_merkleroots: poi_merkleroots.to_vec(),
            },
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

        let parsed: JsonRpcResp<bool> = resp.json().await.map_err(PoiRpcError::JsonDecode)?;

        Ok(parsed.result)
    }
}
const TREE_DEPTH: usize = 16;
const GLOBAL_TREE_POSITION_TREE: u64 = 199_999;
const GLOBAL_TREE_POSITION_POS: u64 = 199_999;
const TREE_MAX_ITEMS: u64 = 65_536;

fn global_tree_position_pre_tx_poi() -> U256 {
    U256::from(GLOBAL_TREE_POSITION_TREE) * U256::from(TREE_MAX_ITEMS)
        + U256::from(GLOBAL_TREE_POSITION_POS)
}

fn railgun_txid_leaf_hash(railgun_txid: U256, utxo_tree_in: u64) -> U256 {
    let gpos = global_tree_position_pre_tx_poi();
    let utxo = U256::from(utxo_tree_in);
    poseidon(vec![railgun_txid, utxo, gpos])
}

fn dummy_txid_root(leaf: U256) -> U256 {
    let mut acc = leaf;
    for _ in 0..TREE_DEPTH {
        acc = poseidon(vec![acc, U256::ZERO]);
    }
    acc
}
