use alloy::primitives::U256;
use alloy::uint;

pub const TREE_DEPTH: usize = 16;
pub const TREE_LEAF_COUNT: u64 = 1 << TREE_DEPTH;
pub const TREE_LEAF_COUNT_U256: U256 = uint!(65_536_U256);

#[must_use]
pub const fn normalize_tree_position(tree_number: u32, tree_position: u64) -> (u32, u64) {
    let normalized_index = tree_position % TREE_LEAF_COUNT;
    let tree_increment = (tree_position / TREE_LEAF_COUNT) as u32;
    (tree_number + tree_increment, normalized_index)
}
