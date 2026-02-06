use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use alloy::primitives::U256;
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use rayon::iter::IntoParallelRefMutIterator;

use crate::errors::SyncError;

pub const TREE_DEPTH: usize = 16;
pub const TREE_LEAF_COUNT: u64 = 1 << TREE_DEPTH;
const PARALLEL_HASH_LAYER_MIN_LEN: usize = 1024;

static ZERO_HASHES: LazyLock<[U256; TREE_DEPTH + 1]> = LazyLock::new(compute_zero_hashes);

#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeUpdate {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
}

#[must_use]
pub const fn normalize_tree_position(tree_number: u32, tree_position: u64) -> (u32, u64) {
    let normalized_index = tree_position % TREE_LEAF_COUNT;
    let tree_increment = (tree_position / TREE_LEAF_COUNT) as u32;
    (tree_number + tree_increment, normalized_index)
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleTree {
    leaves: BTreeMap<u64, U256>,
    root: Option<U256>,
}

#[derive(Debug, Clone, Copy)]
pub struct MerkleProof {
    pub root: U256,
    pub leaf: U256,
    pub leaf_index: u64,
    pub path_elements: [U256; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
}

impl MerkleTree {
    pub fn insert(&mut self, position: u64, leaf: U256) -> Result<(), SyncError> {
        let local_position = position % TREE_LEAF_COUNT;
        self.leaves.insert(local_position, leaf);
        self.root = None;
        Ok(())
    }

    pub fn compute_root(&mut self) -> U256 {
        if let Some(root) = self.root {
            return root;
        }

        let mut layer = vec![ZERO_HASHES[0]; TREE_LEAF_COUNT as usize];
        for (index, leaf) in &self.leaves {
            let idx = *index as usize;
            if idx < layer.len() {
                layer[idx] = *leaf;
            }
        }

        while layer.len() > 1 {
            hash_layer(&mut layer);
        }

        let root = layer[0];
        self.root = Some(root);
        root
    }

    #[must_use]
    pub const fn root(&self) -> Option<U256> {
        self.root
    }

    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn prove(&self, position: u64) -> MerkleProof {
        let local_position = position % TREE_LEAF_COUNT;
        let mut layer = vec![ZERO_HASHES[0]; TREE_LEAF_COUNT as usize];
        for (index, leaf) in &self.leaves {
            let idx = *index as usize;
            if idx < layer.len() {
                layer[idx] = *leaf;
            }
        }

        let mut index = local_position as usize;
        let leaf = layer[index];
        let mut path_elements = [U256::ZERO; TREE_DEPTH];
        let mut path_indices = [0u8; TREE_DEPTH];

        for level in 0..TREE_DEPTH {
            let is_right = index % 2 == 1;
            path_indices[level] = u8::from(is_right);
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            path_elements[level] = layer
                .get(sibling_index)
                .copied()
                .unwrap_or(ZERO_HASHES[level]);

            hash_layer(&mut layer);
            index /= 2;
        }

        MerkleProof {
            root: layer[0],
            leaf,
            leaf_index: local_position,
            path_elements,
            path_indices,
        }
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleForest {
    trees: BTreeMap<u32, MerkleTree>,
}

impl MerkleForest {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trees: BTreeMap::new(),
        }
    }

    pub fn insert_leaf(&mut self, update: MerkleTreeUpdate) -> Result<(), SyncError> {
        let tree = self.trees.entry(update.tree_number).or_default();
        tree.insert(update.tree_position, update.hash)?;
        Ok(())
    }

    pub fn insert_updates<I>(&mut self, updates: I) -> Result<usize, SyncError>
    where
        I: Iterator<Item = MerkleTreeUpdate>,
    {
        let mut count = 0usize;
        for update in updates {
            self.insert_leaf(update)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn compute_roots(&mut self) {
        self.trees.par_iter_mut().for_each(|(_, tree)| {
            tree.compute_root();
        });
    }

    #[must_use]
    pub fn roots(&self) -> BTreeMap<u32, U256> {
        self.trees
            .iter()
            .map(|(id, tree)| (*id, tree.root().unwrap_or(U256::ZERO)))
            .collect()
    }

    #[must_use]
    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }

    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.trees.values().map(MerkleTree::leaf_count).sum()
    }

    #[must_use]
    pub fn leaf_at(&self, tree_number: u32, position: u64) -> Option<U256> {
        self.trees
            .get(&tree_number)
            .and_then(|tree| tree.leaves.get(&position).copied())
    }

    #[must_use]
    pub fn prove(&self, tree_number: u32, tree_position: u64) -> Option<MerkleProof> {
        let (tree_number, tree_position) = normalize_tree_position(tree_number, tree_position);
        self.trees
            .get(&tree_number)
            .map(|tree| tree.prove(tree_position))
    }
}

fn compute_zero_hashes() -> [U256; TREE_DEPTH + 1] {
    let mut zeros = [U256::ZERO; TREE_DEPTH + 1];
    zeros[0] = MERKLE_ZERO_VALUE;
    for level in 1..=TREE_DEPTH {
        zeros[level] = poseidon(vec![zeros[level - 1], zeros[level - 1]]);
    }
    zeros
}

fn hash_layer(layer: &mut Vec<U256>) {
    let parent_count = layer.len() / 2;
    if parent_count >= PARALLEL_HASH_LAYER_MIN_LEN {
        let mut parents = vec![U256::ZERO; parent_count];
        parents
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, parent)| {
                let left = layer[index * 2];
                let right = layer[index * 2 + 1];
                *parent = poseidon(vec![left, right]);
            });
        *layer = parents;
        return;
    }

    for index in 0..parent_count {
        let left = layer[index * 2];
        let right = layer[index * 2 + 1];
        layer[index] = poseidon(vec![left, right]);
    }
    layer.truncate(parent_count);
}

#[cfg(feature = "bench")]
pub fn bench_hash_layer_alloc(layer: &mut Vec<U256>) {
    hash_layer(layer);
}

#[cfg(feature = "bench")]
pub fn bench_compute_root_alloc(tree: &MerkleTree) -> U256 {
    let mut layer = vec![ZERO_HASHES[0]; TREE_LEAF_COUNT as usize];
    for (index, leaf) in &tree.leaves {
        let idx = *index as usize;
        if idx < layer.len() {
            layer[idx] = *leaf;
        }
    }

    while layer.len() > 1 {
        hash_layer(&mut layer);
    }
    layer[0]
}
