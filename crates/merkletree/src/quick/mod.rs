mod graphql;
mod types;

use tracing::info;

use types::Commitment;

use crate::sync::{SyncProgress, SyncResult};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroUsize;
use url::Url;

use crate::tree::{MerkleForest, MerkleTreeUpdate, TREE_LEAF_COUNT, normalize_tree_position};

pub use graphql::{DEFAULT_PAGE_SIZE, QuickSyncClient};

#[derive(Debug, Clone)]
pub struct QuickSyncConfig {
    pub endpoint: Url,
    pub start_block: u64,
    pub end_block: Option<u64>,
    pub page_size: NonZeroUsize,
}

impl Default for QuickSyncConfig {
    fn default() -> Self {
        Self {
            endpoint: Url::parse(
                "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql",
            )
            .expect("valid quick sync endpoint"),
            start_block: 0,
            end_block: None,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

#[derive(Debug)]
pub struct QuickSyncResult {
    pub forest: MerkleForest,
    pub progress: SyncProgress,
}

pub async fn run_quick_sync(config: QuickSyncConfig) -> SyncResult<QuickSyncResult> {
    let QuickSyncConfig {
        endpoint,
        start_block,
        end_block,
        page_size,
    } = config;
    let page_size_value = page_size.get();
    let client = QuickSyncClient::new(endpoint);
    let mut forest = MerkleForest::new();

    let mut total_commitments = 0usize;
    let mut total_nullifiers = 0usize;
    let mut total_unshields = 0usize;
    let mut latest_block = start_block;
    let mut latest_commitment_block = start_block;
    let max_commitments = 16 * TREE_LEAF_COUNT as usize;
    let mut commitment_ids = HashSet::new();
    let mut nullifier_ids = HashSet::new();
    let mut unshield_ids = HashSet::new();

    let mut commitment_cursor = start_block;
    loop {
        let commitments = client
            .fetch_list::<graphql::CommitmentsData>(
                graphql::COMMITMENTS_QUERY,
                commitment_cursor,
                page_size,
            )
            .await?;
        let commitment_count = commitments.len();
        if commitment_count == 0 {
            break;
        }

        let mut max_block_seen = commitment_cursor;
        let mut max_block_in_range = None;
        let mut batch_map: BTreeMap<(u32, u64), Vec<Commitment>> = BTreeMap::new();
        for commitment in commitments {
            let block_number: u64 = commitment.block_number.to();
            max_block_seen = max_block_seen.max(block_number);
            if let Some(end_block) = end_block
                && block_number > end_block
            {
                continue;
            }
            max_block_in_range = Some(max_block_in_range.unwrap_or(block_number).max(block_number));
            if !commitment_ids.insert(commitment.id) {
                continue;
            }
            let tree_number: u32 = commitment.tree_number.to();
            let batch_start_tree_position: u64 = commitment.batch_start_tree_position.to();
            let key = (tree_number, batch_start_tree_position);
            batch_map.entry(key).or_default().push(commitment);
        }

        for ((_tree_number, _start_position), batch) in batch_map {
            for commitment in batch {
                let tree_number: u32 = commitment.tree_number.to();
                let tree_position: u64 = commitment.tree_position.to();
                let (tree_number, tree_position) =
                    normalize_tree_position(tree_number, tree_position);
                let leaf = MerkleTreeUpdate {
                    tree_number,
                    tree_position,
                    hash: commitment.hash,
                };
                forest.insert_leaf(leaf)?;
                total_commitments += 1;
            }
        }

        if let Some(block) = max_block_in_range {
            latest_commitment_block = latest_commitment_block.max(block);
            latest_block = latest_block.max(block);
        }
        info!(
            target: "quick-sync",
            "commitments page: count={}, latest_block={}",
            total_commitments,
            latest_block
        );

        if commitment_count < page_size_value {
            break;
        }
        if let Some(end_block) = end_block
            && max_block_seen >= end_block
        {
            break;
        }
        if total_commitments >= max_commitments {
            break;
        }
        commitment_cursor = max_block_seen;
    }

    let mut nullifier_cursor = start_block;
    loop {
        let nullifiers = client
            .fetch_list::<graphql::NullifiersData>(
                graphql::NULLIFIERS_QUERY,
                nullifier_cursor,
                page_size,
            )
            .await?;
        if nullifiers.is_empty() {
            break;
        }
        let mut max_block_seen = nullifier_cursor;
        let mut max_block_in_range = None;
        for nullifier in &nullifiers {
            let block_number: u64 = nullifier.block_number.to();
            max_block_seen = max_block_seen.max(block_number);
            if let Some(end_block) = end_block
                && block_number > end_block
            {
                continue;
            }
            if !nullifier_ids.insert(nullifier.id) {
                continue;
            }
            max_block_in_range = Some(max_block_in_range.unwrap_or(block_number).max(block_number));
            total_nullifiers += 1;
        }
        if let Some(block) = max_block_in_range {
            latest_block = latest_block.max(block);
        }
        info!(
            target: "quick-sync",
            "nullifiers page: count={}, latest_block={}",
            total_nullifiers,
            latest_block
        );
        if nullifiers.len() < page_size_value {
            break;
        }
        if let Some(end_block) = end_block
            && max_block_seen >= end_block
        {
            break;
        }
        nullifier_cursor = max_block_seen + 1;
    }

    let mut unshield_cursor = start_block;
    loop {
        let unshields = client
            .fetch_list::<graphql::UnshieldsData>(
                graphql::UNSHIELDS_QUERY,
                unshield_cursor,
                page_size,
            )
            .await?;
        if unshields.is_empty() {
            break;
        }
        let mut max_block_seen = unshield_cursor;
        let mut max_block_in_range = None;
        for unshield in &unshields {
            let block_number: u64 = unshield.block_number.to();
            max_block_seen = max_block_seen.max(block_number);
            if let Some(end_block) = end_block
                && block_number > end_block
            {
                continue;
            }
            if !unshield_ids.insert(unshield.id) {
                continue;
            }
            max_block_in_range = Some(max_block_in_range.unwrap_or(block_number).max(block_number));
            total_unshields += 1;
        }
        if let Some(block) = max_block_in_range {
            latest_block = latest_block.max(block);
        }
        info!(
            target: "quick-sync",
            "unshields page: count={}, latest_block={}",
            total_unshields,
            latest_block
        );
        if unshields.len() < page_size_value {
            break;
        }
        if let Some(end_block) = end_block
            && max_block_seen >= end_block
        {
            break;
        }
        unshield_cursor = max_block_seen + 1;
    }

    forest.compute_roots();

    Ok(QuickSyncResult {
        forest,
        progress: SyncProgress {
            latest_block,
            latest_commitment_block,
            commitments: total_commitments,
            nullifiers: total_nullifiers,
            unshields: total_unshields,
        },
    })
}
