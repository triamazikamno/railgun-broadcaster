use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use alloy::primitives::U256;
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::transact::MERKLE_ZERO_VALUE;
use broadcaster_core::tree::{TREE_DEPTH, TREE_LEAF_COUNT, normalize_tree_position};
use rayon::iter::IntoParallelRefMutIterator;

use crate::errors::SyncError;

const PARALLEL_HASH_LAYER_MIN_LEN: usize = 1024;

static ZERO_HASHES: LazyLock<[U256; TREE_DEPTH + 1]> = LazyLock::new(compute_zero_hashes);

#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeUpdate {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
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

#[derive(Debug, Clone)]
pub struct DenseMerkleTree {
    layers: Vec<Vec<U256>>,
}

impl MerkleTree {
    pub fn insert(&mut self, position: u64, leaf: U256) -> Result<(), SyncError> {
        validate_tree_position(position)?;
        self.leaves.insert(position, leaf);
        self.root = None;
        Ok(())
    }

    pub fn compute_root(&mut self) -> U256 {
        if let Some(root) = self.root {
            return root;
        }

        let root = self.computed_root();
        self.root = Some(root);
        root
    }

    #[must_use]
    pub fn computed_root(&self) -> U256 {
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

        layer[0]
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
        self.prove_with_leaf_count(position, TREE_LEAF_COUNT)
    }

    #[must_use]
    pub fn prove_with_leaf_count(&self, position: u64, leaf_count: u64) -> MerkleProof {
        let local_position = position % TREE_LEAF_COUNT;
        let clamped_leaf_count = leaf_count.min(TREE_LEAF_COUNT);
        let leaf = if local_position < clamped_leaf_count {
            self.leaves
                .get(&local_position)
                .copied()
                .unwrap_or(ZERO_HASHES[0])
        } else {
            ZERO_HASHES[0]
        };
        let mut path_elements = [U256::ZERO; TREE_DEPTH];
        let mut path_indices = [0u8; TREE_DEPTH];
        let mut root = leaf;

        for level in 0..TREE_DEPTH {
            let is_right = ((local_position >> level) & 1) == 1;
            path_indices[level] = u8::from(is_right);
            let sibling_start = ((local_position >> level) ^ 1) << level;
            let sibling = self.subtree_root(sibling_start, level, clamped_leaf_count);
            path_elements[level] = sibling;
            root = if is_right {
                poseidon(vec![sibling, root])
            } else {
                poseidon(vec![root, sibling])
            };
        }

        MerkleProof {
            root,
            leaf,
            leaf_index: local_position,
            path_elements,
            path_indices,
        }
    }

    fn subtree_root(&self, start: u64, depth: usize, leaf_count: u64) -> U256 {
        if start >= leaf_count {
            return ZERO_HASHES[depth];
        }
        let width = 1_u64 << depth;
        let end = start.saturating_add(width).min(TREE_LEAF_COUNT);
        let upper = end.min(leaf_count);
        if self.leaves.range(start..upper).next().is_none() {
            return ZERO_HASHES[depth];
        }
        if depth == 0 {
            return self.leaves.get(&start).copied().unwrap_or(ZERO_HASHES[0]);
        }
        let half_width = width / 2;
        let left = self.subtree_root(start, depth - 1, leaf_count);
        let right = self.subtree_root(start + half_width, depth - 1, leaf_count);
        poseidon(vec![left, right])
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
        validate_tree_position(update.tree_position)?;
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
    pub fn computed_roots(&self) -> BTreeMap<u32, U256> {
        self.trees
            .iter()
            .map(|(id, tree)| (*id, tree.computed_root()))
            .collect()
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
    pub fn contains_tree(&self, tree_number: u32) -> bool {
        self.trees.contains_key(&tree_number)
    }

    #[must_use]
    pub fn prove(&self, tree_number: u32, tree_position: u64) -> Option<MerkleProof> {
        let (tree_number, tree_position) = normalize_tree_position(tree_number, tree_position);
        self.trees
            .get(&tree_number)
            .map(|tree| tree.prove(tree_position))
    }

    #[must_use]
    pub fn prove_with_leaf_count(
        &self,
        tree_number: u32,
        tree_position: u64,
        leaf_count: u64,
    ) -> Option<MerkleProof> {
        let (tree_number, tree_position) = normalize_tree_position(tree_number, tree_position);
        self.trees
            .get(&tree_number)
            .map(|tree| tree.prove_with_leaf_count(tree_position, leaf_count))
    }
}

impl DenseMerkleTree {
    #[must_use]
    pub fn from_forest_prefix(forest: &MerkleForest, tree_number: u32, leaf_count: u64) -> Self {
        let clamped_leaf_count = leaf_count.min(TREE_LEAF_COUNT);
        let mut leaves = vec![MERKLE_ZERO_VALUE; TREE_LEAF_COUNT as usize];
        if let Some(tree) = forest.trees.get(&tree_number) {
            for (position, leaf) in tree.leaves.range(0..clamped_leaf_count) {
                leaves[*position as usize] = *leaf;
            }
        }
        Self::from_full_leaf_layer(leaves)
    }

    #[must_use]
    pub fn from_ordered_leaves<I>(leaves: I, leaf_count: u64) -> Self
    where
        I: IntoIterator<Item = U256>,
    {
        let clamped_leaf_count = leaf_count.min(TREE_LEAF_COUNT) as usize;
        let mut layer = vec![MERKLE_ZERO_VALUE; TREE_LEAF_COUNT as usize];
        for (index, leaf) in leaves.into_iter().take(clamped_leaf_count).enumerate() {
            layer[index] = leaf;
        }
        Self::from_full_leaf_layer(layer)
    }

    #[must_use]
    pub fn from_full_leaf_layer(mut layer: Vec<U256>) -> Self {
        layer.resize(TREE_LEAF_COUNT as usize, MERKLE_ZERO_VALUE);
        if layer.len() > TREE_LEAF_COUNT as usize {
            layer.truncate(TREE_LEAF_COUNT as usize);
        }
        let mut layers = Vec::with_capacity(TREE_DEPTH + 1);
        layers.push(layer.clone());
        while layer.len() > 1 {
            hash_layer(&mut layer);
            layers.push(layer.clone());
        }
        Self { layers }
    }

    #[must_use]
    pub fn root(&self) -> U256 {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or(MERKLE_ZERO_VALUE)
    }

    pub fn remove_leaf(&mut self, position: u64) {
        let mut index = position as usize;
        if index >= self.layers[0].len() {
            return;
        }
        self.layers[0][index] = MERKLE_ZERO_VALUE;
        for level in 0..TREE_DEPTH {
            let parent_index = index / 2;
            let left = self.layers[level][parent_index * 2];
            let right = self.layers[level][parent_index * 2 + 1];
            self.layers[level + 1][parent_index] = poseidon(vec![left, right]);
            index = parent_index;
        }
    }

    #[must_use]
    pub fn prove(&self, position: u64) -> MerkleProof {
        let local_position = position % TREE_LEAF_COUNT;
        let mut path_elements = [U256::ZERO; TREE_DEPTH];
        let mut path_indices = [0_u8; TREE_DEPTH];
        let mut index = local_position as usize;
        for level in 0..TREE_DEPTH {
            let is_right = index % 2 == 1;
            path_indices[level] = u8::from(is_right);
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            path_elements[level] = self.layers[level][sibling_index];
            index /= 2;
        }
        MerkleProof {
            root: self.root(),
            leaf: self.layers[0][local_position as usize],
            leaf_index: local_position,
            path_elements,
            path_indices,
        }
    }
}

const fn validate_tree_position(tree_position: u64) -> Result<(), SyncError> {
    if tree_position >= TREE_LEAF_COUNT {
        return Err(SyncError::InvalidTreePosition {
            tree_position,
            max_position: TREE_LEAF_COUNT,
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::uint;

    #[test]
    fn prove_with_leaf_count_ignores_later_leaves() {
        let mut forest_before = MerkleForest::new();
        forest_before
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: uint!(11_U256),
            })
            .unwrap();
        forest_before.compute_roots();
        let expected = forest_before.prove(0, 0).unwrap();

        let mut forest_after = forest_before.clone();
        forest_after
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 1,
                hash: uint!(12_U256),
            })
            .unwrap();
        forest_after.compute_roots();

        let historical = forest_after.prove_with_leaf_count(0, 0, 1).unwrap();
        let current = forest_after.prove(0, 0).unwrap();

        assert_eq!(historical.root, expected.root);
        assert_eq!(historical.path_elements, expected.path_elements);
        assert_ne!(current.root, expected.root);
    }

    #[test]
    fn sparse_proof_root_matches_computed_current_root() {
        let mut forest = MerkleForest::new();
        for position in [0, 3, 11, 1024] {
            forest
                .insert_leaf(MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: position,
                    hash: U256::from(position + 1),
                })
                .unwrap();
        }
        forest.compute_roots();

        let proof = forest.prove(0, 3).unwrap();

        assert_eq!(proof.root, forest.roots()[&0]);
        assert_eq!(proof.leaf, uint!(4_U256));
    }

    #[test]
    fn tree_insert_rejects_out_of_range_position_without_wrapping() {
        let mut tree = MerkleTree::default();
        tree.insert(0, uint!(11_U256)).unwrap();

        let error = tree.insert(TREE_LEAF_COUNT, uint!(12_U256)).unwrap_err();

        assert!(matches!(
            error,
            SyncError::InvalidTreePosition {
                tree_position: TREE_LEAF_COUNT,
                max_position: TREE_LEAF_COUNT,
            }
        ));
        assert_eq!(tree.leaves.get(&0), Some(&uint!(11_U256)));
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn forest_insert_rejects_out_of_range_local_position() {
        let mut forest = MerkleForest::new();

        let error = forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 7,
                tree_position: TREE_LEAF_COUNT,
                hash: uint!(12_U256),
            })
            .unwrap_err();

        assert!(matches!(
            error,
            SyncError::InvalidTreePosition {
                tree_position: TREE_LEAF_COUNT,
                max_position: TREE_LEAF_COUNT,
            }
        ));
        assert_eq!(forest.tree_count(), 0);
    }
}
