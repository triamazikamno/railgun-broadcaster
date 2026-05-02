use crate::error::{PoiError, PoiRpcError};
use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, FeeNoteAssuranceContext, ParsedTransactCalldata,
    ParsedTransactTransaction, PreTxPoi, SnarkJsProof, dummy_txid_root, railgun_txid_leaf_hash,
    txid_version_or_default,
};
pub use broadcaster_core::utxo::PoiStatus;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

pub const DEFAULT_WALLET_POI_RPC_URL: &str = "https://ppoi.fdi.network";
pub const DEFAULT_ACTIVE_POI_LIST_KEY_HEX: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

const DEFAULT_ACTIVE_POI_LIST_KEY_BYTES: [u8; 32] = [
    0xef, 0xc6, 0xdd, 0xb5, 0x9c, 0x09, 0x8a, 0x13, 0xfb, 0x2b, 0x61, 0x8f, 0xda, 0xe9, 0x4c, 0x1c,
    0x3a, 0x80, 0x7a, 0xbc, 0x8f, 0xb1, 0x83, 0x7c, 0x93, 0x62, 0x0c, 0x91, 0x43, 0xee, 0x9e, 0x88,
];

#[must_use]
pub fn default_active_poi_list_key() -> FixedBytes<32> {
    FixedBytes::from(DEFAULT_ACTIVE_POI_LIST_KEY_BYTES)
}

#[must_use]
pub fn default_active_poi_list_keys() -> Vec<FixedBytes<32>> {
    vec![default_active_poi_list_key()]
}

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
            for transaction in &parsed_calldata.transactions {
                self.validate_transaction(transaction, params, list_key)
                    .await
                    .map_err(|source| PoiError::ValidateList {
                        list_key: *list_key,
                        source: Box::new(source),
                    })?;
            }
        }
        Ok(())
    }

    async fn validate_transaction(
        &self,
        transaction: &ParsedTransactTransaction,
        params: &BroadcasterRawParamsTransact,
        required_list_key: &FixedBytes<32>,
    ) -> Result<(), PoiError> {
        let leaf = railgun_txid_leaf_hash(transaction.railgun_txid, transaction.utxo_tree_in);
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
            transaction.tx_nullifiers_len,
            transaction.tx_commitments_out_len,
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
            fee_commitment = %hex::encode_prefixed(context.fee_commitment),
            fee_note_npk = %hex::encode_prefixed(context.fee_note_npk),
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
        let single_commitment_context =
            SingleCommitmentProofContext::from_fee_note_assurance(context);
        self.rpc_client
            .submit_single_commitment_proofs(
                &context.txid_version,
                chain_type,
                chain_id,
                &single_commitment_context,
                utxo_tree_out,
                utxo_position_out,
            )
            .await?;
        Ok(())
    }

    pub async fn submit_single_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        debug!(
            method = POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            chain_type,
            chain_id,
            txid_version = %context.txid_version,
            commitment = %hex::encode_prefixed(context.commitment),
            npk = %hex::encode_prefixed(context.npk),
            railgun_txid = %encode_u256(context.railgun_txid),
            utxo_tree_in = context.utxo_tree_in,
            utxo_tree_out,
            utxo_position_out,
            poi_list_keys = ?context
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "submit single-commitment poi"
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
            fee_blinded_commitment = %hex::encode_prefixed(blinded_commitment),
            required_poi_list_keys = ?required_poi_list_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "query fee-note poi statuses for candidate commitment"
        );
        let statuses = self
            .rpc_client
            .pois_per_list(
                txid_version,
                chain_type,
                chain_id,
                required_poi_list_keys,
                &[BlindedCommitmentData::transact(*blinded_commitment)],
            )
            .await?;

        Ok(statuses
            .get(blinded_commitment)
            .cloned()
            .unwrap_or_else(|| {
                required_poi_list_keys
                    .iter()
                    .copied()
                    .map(|list_key| (list_key, PoiStatus::Missing))
                    .collect()
            }))
    }
}

const POI_VALIDATE_MERKLEROOTS_METHOD: &str = "ppoi_validate_poi_merkleroots";
const POI_VALIDATE_TXID_MERKLEROOT_METHOD: &str = "ppoi_validate_txid_merkleroot";
const POI_VALIDATED_TXID_METHOD: &str = "ppoi_validated_txid";
const POI_SUBMIT_TRANSACT_PROOF_METHOD: &str = "ppoi_submit_transact_proof";
const POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD: &str = "ppoi_submit_single_commitment_proofs";
const POI_POIS_PER_LIST_METHOD: &str = "ppoi_pois_per_list";
const POI_MERKLE_PROOFS_METHOD: &str = "ppoi_merkle_proofs";

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
struct SubmitTransactProofParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    transact_proof_data: SubmitTransactProofData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitTransactProofData {
    #[serde(flatten)]
    proof: SubmitPoiProofData,
    txid_merkleroot_index: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetLatestValidatedRailgunTxidParams {
    #[serde(flatten)]
    chain: ChainParams,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedRailgunTxidStatus {
    pub validated_txid_index: Option<u64>,
    pub validated_merkleroot: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateTxidMerklerootParams {
    #[serde(flatten)]
    chain: ChainParams,
    tree: u64,
    index: u64,
    merkleroot: String,
}

#[derive(Debug, Clone)]
pub struct SingleCommitmentProofContext {
    pub txid_version: String,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub commitment: FixedBytes<32>,
    pub npk: FixedBytes<32>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
}

impl SingleCommitmentProofContext {
    #[must_use]
    pub fn from_fee_note_assurance(context: &FeeNoteAssuranceContext) -> Self {
        Self {
            txid_version: context.txid_version.clone(),
            railgun_txid: context.railgun_txid,
            utxo_tree_in: context.utxo_tree_in,
            commitment: context.fee_commitment,
            npk: context.fee_note_npk,
            pre_transaction_pois_per_txid_leaf_per_list: context
                .pre_transaction_pois_per_txid_leaf_per_list
                .clone(),
        }
    }
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
    pois: BTreeMap<String, BTreeMap<String, SubmitPoiProofData>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitPoiProofData {
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

impl From<&PreTxPoi> for SubmitPoiProofData {
    fn from(poi: &PreTxPoi) -> Self {
        Self {
            snark_proof: SubmitSnarkJsProof::from(&poi.snark_proof),
            txid_merkleroot: hex::encode(poi.txid_merkleroot),
            poi_merkleroots: poi.poi_merkleroots.iter().map(hex::encode).collect(),
            blinded_commitments_out: poi
                .blinded_commitments_out
                .iter()
                .map(hex::encode_prefixed)
                .collect(),
            railgun_txid_if_has_unshield: if poi.railgun_txid_if_has_unshield.is_empty() {
                "0x00".to_string()
            } else {
                hex::encode_prefixed(&poi.railgun_txid_if_has_unshield)
            },
        }
    }
}

impl From<&SnarkJsProof> for SubmitSnarkJsProof {
    fn from(proof: &SnarkJsProof) -> Self {
        Self {
            pi_a: proof.pi_a.map(|value| value.to_string()),
            pi_b: proof.pi_b.map(|row| row.map(|value| value.to_string())),
            pi_c: proof.pi_c.map(|value| value.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPoisPerListParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_keys: Vec<String>,
    blinded_commitment_datas: Vec<BlindedCommitmentDataParam>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlindedCommitmentDataParam {
    blinded_commitment: String,
    #[serde(rename = "type")]
    commitment_type: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetMerkleProofsParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    blinded_commitments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiMerkleProof {
    pub leaf: String,
    pub elements: Vec<String>,
    pub indices: String,
    pub root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlindedCommitmentType {
    Shield,
    Transact,
    Unshield,
}

impl BlindedCommitmentType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Shield => "Shield",
            Self::Transact => "Transact",
            Self::Unshield => "Unshield",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedCommitmentData {
    pub blinded_commitment: FixedBytes<32>,
    pub commitment_type: BlindedCommitmentType,
}

impl BlindedCommitmentData {
    #[must_use]
    pub const fn new(
        blinded_commitment: FixedBytes<32>,
        commitment_type: BlindedCommitmentType,
    ) -> Self {
        Self {
            blinded_commitment,
            commitment_type,
        }
    }

    #[must_use]
    pub const fn shield(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Shield)
    }

    #[must_use]
    pub const fn transact(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Transact)
    }

    #[must_use]
    pub const fn unshield(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Unshield)
    }
}

pub type PoisPerListMap = BTreeMap<String, BTreeMap<String, PoiStatus>>;
pub type PoisPerListStatusMap = BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>;

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
        decode_json_rpc_ack_response(method, &body)
    }

    fn submit_single_commitment_pois(
        context: &SingleCommitmentProofContext,
    ) -> BTreeMap<String, BTreeMap<String, SubmitPoiProofData>> {
        context
            .pre_transaction_pois_per_txid_leaf_per_list
            .iter()
            .map(|(list_key, per_leaf)| {
                (
                    hex::encode(list_key),
                    per_leaf
                        .iter()
                        .map(|(leaf, poi)| (hex::encode(leaf), poi.into()))
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

    fn validate_txid_merkleroot_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        tree: u64,
        index: u64,
        merkleroot: &FixedBytes<32>,
    ) -> ValidateTxidMerklerootParams {
        ValidateTxidMerklerootParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            tree,
            index,
            merkleroot: hex::encode(merkleroot),
        }
    }

    fn latest_validated_txid_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
    ) -> GetLatestValidatedRailgunTxidParams {
        GetLatestValidatedRailgunTxidParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
        }
    }

    fn submit_single_commitment_proofs_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> SubmitSingleCommitmentProofsParams {
        SubmitSingleCommitmentProofsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            single_commitment_proofs_data: SingleCommitmentProofsData {
                commitment: hex::encode_prefixed(context.commitment),
                npk: hex::encode_prefixed(context.npk),
                utxo_tree_in: context.utxo_tree_in,
                utxo_tree_out,
                utxo_position_out,
                railgun_txid: encode_u256_bare(context.railgun_txid),
                pois: Self::submit_single_commitment_pois(context),
            },
        }
    }

    fn submit_transact_proof_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> SubmitTransactProofParams {
        SubmitTransactProofParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            transact_proof_data: SubmitTransactProofData {
                proof: poi.into(),
                txid_merkleroot_index,
            },
        }
    }

    fn pois_per_list_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> GetPoisPerListParams {
        GetPoisPerListParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_keys: list_keys.iter().map(hex::encode).collect(),
            blinded_commitment_datas: blinded_commitment_datas
                .iter()
                .map(|data| BlindedCommitmentDataParam {
                    blinded_commitment: hex::encode_prefixed(data.blinded_commitment),
                    commitment_type: data.commitment_type.as_str(),
                })
                .collect(),
        }
    }

    fn poi_merkle_proofs_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> GetMerkleProofsParams {
        GetMerkleProofsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            blinded_commitments: blinded_commitments
                .iter()
                .map(hex::encode_prefixed)
                .collect(),
        }
    }

    pub async fn validate_poi_merkleroots(
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

    pub async fn validate_txid_merkleroot(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        tree: u64,
        index: u64,
        merkleroot: &FixedBytes<32>,
    ) -> Result<bool, PoiRpcError> {
        self.send_request(
            POI_VALIDATE_TXID_MERKLEROOT_METHOD,
            Self::validate_txid_merkleroot_params(
                txid_version,
                chain_type,
                chain_id,
                tree,
                index,
                merkleroot,
            ),
        )
        .await
    }

    pub async fn latest_validated_railgun_txid(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
    ) -> Result<ValidatedRailgunTxidStatus, PoiRpcError> {
        self.send_request(
            POI_VALIDATED_TXID_METHOD,
            Self::latest_validated_txid_params(txid_version, chain_type, chain_id),
        )
        .await
    }

    pub async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
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

    pub async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiRpcError> {
        self.send_request_allow_missing_result(
            POI_SUBMIT_TRANSACT_PROOF_METHOD,
            Self::submit_transact_proof_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                txid_merkleroot_index,
                poi,
            ),
        )
        .await
    }

    pub async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<PoisPerListStatusMap, PoiError> {
        let response: PoisPerListMap = self
            .send_request(
                POI_POIS_PER_LIST_METHOD,
                Self::pois_per_list_params(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_keys,
                    blinded_commitment_datas,
                ),
            )
            .await?;

        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                let blinded_commitment_hex = hex::encode_prefixed(data.blinded_commitment);
                let per_list = response
                    .get(&blinded_commitment_hex)
                    .cloned()
                    .unwrap_or_default();
                let statuses = list_keys
                    .iter()
                    .copied()
                    .map(|list_key| {
                        let status = per_list
                            .get(&hex::encode(list_key))
                            .copied()
                            .unwrap_or(PoiStatus::Missing);
                        (list_key, status)
                    })
                    .collect();
                (data.blinded_commitment, statuses)
            })
            .collect())
    }

    pub async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PoiRpcError> {
        self.send_request(
            POI_MERKLE_PROOFS_METHOD,
            Self::poi_merkle_proofs_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                blinded_commitments,
            ),
        )
        .await
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

fn decode_json_rpc_ack_response(method: &'static str, body: &str) -> Result<(), PoiRpcError> {
    let parsed: JsonRpcResp<serde_json::Value> =
        serde_json::from_str(body).map_err(PoiRpcError::JsonDecode)?;
    if let Some(error) = parsed.error {
        return Err(PoiRpcError::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    if let Some(result) = parsed.result
        && !result.is_null()
    {
        debug!(method, result = %result, "POI RPC ack response contained result");
    }
    Ok(())
}

fn encode_u256(value: U256) -> String {
    format!("0x{value:064x}")
}

fn encode_u256_bare(value: U256) -> String {
    format!("{value:064x}")
}

#[cfg(test)]
mod tests {
    use super::{
        BlindedCommitmentData, DEFAULT_ACTIVE_POI_LIST_KEY_HEX, DEFAULT_WALLET_POI_RPC_URL,
        PoiMerkleProof, PoiRpcClient, PoiStatus, SingleCommitmentProofContext,
        ValidatedRailgunTxidStatus, decode_json_rpc_ack_response, decode_json_rpc_response,
        default_active_poi_list_key, encode_u256_bare, railgun_txid_leaf_hash,
    };
    use crate::error::PoiRpcError;
    use alloy::{
        hex,
        primitives::{FixedBytes, U256},
        uint,
    };
    use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
    use serde_json::to_value;
    use std::collections::BTreeMap;

    fn sample_context() -> FeeNoteAssuranceContext {
        let list_key = FixedBytes::from([0x11; 32]);
        let leaf = FixedBytes::from([0x22; 32]);
        let poi = PreTxPoi {
            snark_proof: SnarkJsProof::zero(),
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
            railgun_txid: uint!(9_U256),
            utxo_tree_in: 7,
            fee_commitment: FixedBytes::from([0x66; 32]),
            fee_note_npk: FixedBytes::from([0x77; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: per_list,
            required_poi_list_keys: vec![list_key],
        }
    }

    #[test]
    fn wallet_poi_defaults_are_available() {
        assert_eq!(DEFAULT_WALLET_POI_RPC_URL, "https://ppoi.fdi.network");
        assert_eq!(
            hex::encode(default_active_poi_list_key()),
            DEFAULT_ACTIVE_POI_LIST_KEY_HEX
        );
    }

    #[test]
    fn poi_status_supports_local_unknown() {
        let json = serde_json::to_string(&PoiStatus::Unknown).expect("serialize unknown status");
        assert_eq!(json, r#""Unknown""#);
        let status: PoiStatus = serde_json::from_str(&json).expect("deserialize unknown status");
        assert_eq!(status, PoiStatus::Unknown);
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
        let single_commitment_context =
            SingleCommitmentProofContext::from_fee_note_assurance(&context);
        let params = PoiRpcClient::submit_single_commitment_proofs_params(
            &context.txid_version,
            0,
            1,
            &single_commitment_context,
            10,
            12,
        );
        let json = to_value(params).expect("serialize submit params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(
            json["singleCommitmentProofsData"]["commitment"],
            hex::encode_prefixed(context.fee_commitment)
        );
        assert_eq!(
            json["singleCommitmentProofsData"]["npk"],
            hex::encode_prefixed(context.fee_note_npk)
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
                .get(hex::encode_prefixed(context.required_poi_list_keys[0]))
                .is_none()
        );
    }

    #[test]
    fn transact_proof_submit_request_serializes_railway_shape() {
        let context = sample_context();
        let list_key = context.required_poi_list_keys[0];
        let poi = context
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&list_key)
            .expect("list")
            .values()
            .next()
            .expect("poi");
        let params = PoiRpcClient::submit_transact_proof_params(
            &context.txid_version,
            0,
            1,
            &list_key,
            105_572,
            poi,
        );
        let json = to_value(params).expect("serialize transact proof params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(json["listKey"], hex::encode(list_key));
        assert!(json.get("singleCommitmentProofsData").is_none());
        assert_eq!(
            json["transactProofData"]["txidMerkleroot"],
            hex::encode(poi.txid_merkleroot)
        );
        assert_eq!(json["transactProofData"]["txidMerklerootIndex"], 105_572);
        assert_eq!(
            json["transactProofData"]["poiMerkleroots"][0],
            hex::encode(poi.poi_merkleroots[0])
        );
        assert_eq!(
            json["transactProofData"]["blindedCommitmentsOut"][0],
            hex::encode_prefixed(poi.blinded_commitments_out[0])
        );
        assert_eq!(
            json["transactProofData"]["railgunTxidIfHasUnshield"],
            "0x00"
        );
    }

    #[test]
    fn validated_txid_response_deserializes() {
        let status: ValidatedRailgunTxidStatus = decode_json_rpc_response(
            r#"{"result":{"validatedTxidIndex":105578,"validatedMerkleroot":"2946581b750a59be1865ea5499ed515957865df1dcecf5db07ea5c7fcf473396"}}"#,
        )
        .expect("decode validated txid");

        assert_eq!(status.validated_txid_index, Some(105_578));
        assert_eq!(
            status.validated_merkleroot.as_deref(),
            Some("2946581b750a59be1865ea5499ed515957865df1dcecf5db07ea5c7fcf473396")
        );
    }

    #[test]
    fn single_commitment_submit_request_uses_bare_hex_poi_keys() {
        let context = sample_context();
        let single_commitment_context =
            SingleCommitmentProofContext::from_fee_note_assurance(&context);
        let params = PoiRpcClient::submit_single_commitment_proofs_params(
            &context.txid_version,
            0,
            1,
            &single_commitment_context,
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
            hex::encode_prefixed(FixedBytes::from([0x55; 32]))
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
        let shield_blinded_commitment = FixedBytes::from([0x99; 32]);
        let params = PoiRpcClient::pois_per_list_params(
            &context.txid_version,
            0,
            1,
            &context.required_poi_list_keys,
            &[
                BlindedCommitmentData::transact(blinded_commitment),
                BlindedCommitmentData::shield(shield_blinded_commitment),
            ],
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
            hex::encode_prefixed(blinded_commitment)
        );
        assert_eq!(json["blindedCommitmentDatas"][1]["type"], "Shield");
        assert_eq!(
            json["blindedCommitmentDatas"][1]["blindedCommitment"],
            hex::encode_prefixed(shield_blinded_commitment)
        );
    }

    #[test]
    fn poi_merkle_proofs_query_serializes_blinded_commitments() {
        let context = sample_context();
        let list_key = context.required_poi_list_keys[0];
        let blinded_commitments = [FixedBytes::from([0x88; 32]), FixedBytes::from([0x99; 32])];
        let params = PoiRpcClient::poi_merkle_proofs_params(
            &context.txid_version,
            0,
            1,
            &list_key,
            &blinded_commitments,
        );
        let json = to_value(params).expect("serialize merkle proof params");

        assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
        assert_eq!(json["listKey"], hex::encode(list_key));
        assert_eq!(
            json["blindedCommitments"][0],
            hex::encode_prefixed(blinded_commitments[0])
        );
        assert_eq!(
            json["blindedCommitments"][1],
            hex::encode_prefixed(blinded_commitments[1])
        );
    }

    #[test]
    fn poi_merkle_proofs_response_decodes() {
        let proofs: Vec<PoiMerkleProof> = decode_json_rpc_response(
            r#"{"result":[{"leaf":"0x11","elements":["0x22"],"indices":"0x00","root":"0x33"}]}"#,
        )
        .expect("decode merkle proofs");

        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].leaf, "0x11");
        assert_eq!(proofs[0].elements, vec!["0x22".to_string()]);
        assert_eq!(proofs[0].indices, "0x00");
        assert_eq!(proofs[0].root, "0x33");
    }

    #[test]
    fn missing_list_status_defaults_to_missing() {
        let blinded_commitment = FixedBytes::from([0x88; 32]);
        let response = BTreeMap::from([(
            hex::encode_prefixed(blinded_commitment),
            BTreeMap::from([("deadbeef".to_string(), PoiStatus::Valid)]),
        )]);
        let list_key = FixedBytes::from([0x11; 32]);
        let per_list = response
            .get(&hex::encode_prefixed(blinded_commitment))
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
        let leaf = railgun_txid_leaf_hash(uint!(1_U256), 2);
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
        decode_json_rpc_ack_response("test_method", r#"{"jsonrpc":"2.0","id":2}"#)
            .expect("ack response should succeed");
    }

    #[test]
    fn decode_json_rpc_ack_response_with_error_fails() {
        let error = decode_json_rpc_ack_response(
            "test_method",
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"bad request"}}"#,
        )
        .expect_err("ack error");

        assert!(matches!(error, PoiRpcError::JsonRpc { .. }));
    }
}
