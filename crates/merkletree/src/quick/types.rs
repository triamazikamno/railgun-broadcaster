use alloy::primitives::{FixedBytes, U256};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Commitment {
    pub id: FixedBytes<64>,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    #[serde(rename = "batchStartTreePosition")]
    pub batch_start_tree_position: U256,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    pub hash: U256,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Nullifier {
    pub id: FixedBytes<64>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Unshield {
    pub id: FixedBytes<36>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "eventLogIndex")]
    pub event_log_index: U256,
}
