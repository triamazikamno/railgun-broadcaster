use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::Instant;

use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use alloy::sol_types::SolCall;
use alloy::uint;
use async_trait::async_trait;
use rand::Rng;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use thiserror::Error;

use ::poi::error::PoiRpcError;
use ::poi::poi::{PoiMerkleProof, PoiRpcClient};
use broadcaster_core::contracts::railgun::{
    ActionData, BoundParams, CommitmentPreimage, SnarkProof, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, MERKLE_ZERO_VALUE, PreTxPoi, SnarkJsProof, compute_railgun_txid_parts,
    dummy_txid_root, pre_transaction_output_global_position, railgun_txid_leaf_hash,
    railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::{TREE_DEPTH, TREE_LEAF_COUNT, normalize_tree_position};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleProof};

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::{Note, NoteCiphertext};
use crate::prover::{ProverError, ProverService};

mod builder;
mod error;
mod poi;
mod types;

pub use builder::*;
pub use error::*;
pub use poi::*;
pub use types::*;
