use alloy::primitives::{FixedBytes, U256};

pub use broadcaster_core::contracts::railgun::{
    CommitmentBatch, CommitmentCiphertext, CommitmentPreimage, GeneratedCommitmentBatch,
    LegacyCommitmentCiphertext, LegacyCommitmentPreimage, Nullified, Nullifiers, Shield,
    ShieldCiphertext, ShieldLegacyPreMar23, TokenData, Transact, Unshield,
};

use crate::tree::MerkleTreeUpdate;

pub(crate) struct CommitmentUpdates<I> {
    tree_number: u32,
    next_index: u64,
    iter: I,
}

impl<I> CommitmentUpdates<I>
where
    I: Iterator<Item = U256>,
{
    const fn new(tree_number: u32, start_position: u64, iter: I) -> Self {
        Self {
            tree_number,
            next_index: start_position,
            iter,
        }
    }
}

impl<I> Iterator for CommitmentUpdates<I>
where
    I: Iterator<Item = U256>,
{
    type Item = MerkleTreeUpdate;

    fn next(&mut self) -> Option<Self::Item> {
        let hash = self.iter.next()?;
        let (tree_number, tree_position) =
            crate::tree::normalize_tree_position(self.tree_number, self.next_index);
        self.next_index += 1;
        Some(MerkleTreeUpdate {
            tree_number,
            tree_position,
            hash,
        })
    }
}

pub(crate) trait IntoCommitmentUpdates<'a> {
    type Iter: Iterator<Item = U256> + 'a;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter>;
}

impl<'a> IntoCommitmentUpdates<'a> for Transact {
    type Iter = std::iter::Map<std::slice::Iter<'a, FixedBytes<32>>, fn(&FixedBytes<32>) -> U256>;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter> {
        const fn to_u256(hash: &FixedBytes<32>) -> U256 {
            U256::from_be_bytes(hash.0)
        }

        CommitmentUpdates::new(
            self.treeNumber.to(),
            self.startPosition.to(),
            self.hash.iter().map(to_u256 as fn(&FixedBytes<32>) -> U256),
        )
    }
}

impl<'a> IntoCommitmentUpdates<'a> for Shield {
    type Iter =
        std::iter::Map<std::slice::Iter<'a, CommitmentPreimage>, fn(&CommitmentPreimage) -> U256>;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter> {
        CommitmentUpdates::new(
            self.treeNumber.to(),
            self.startPosition.to(),
            self.commitments
                .iter()
                .map(CommitmentPreimage::hash as fn(&CommitmentPreimage) -> U256),
        )
    }
}

impl<'a> IntoCommitmentUpdates<'a> for ShieldLegacyPreMar23 {
    type Iter =
        std::iter::Map<std::slice::Iter<'a, CommitmentPreimage>, fn(&CommitmentPreimage) -> U256>;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter> {
        CommitmentUpdates::new(
            self.treeNumber.to(),
            self.startPosition.to(),
            self.commitments
                .iter()
                .map(CommitmentPreimage::hash as fn(&CommitmentPreimage) -> U256),
        )
    }
}

impl<'a> IntoCommitmentUpdates<'a> for CommitmentBatch {
    type Iter = std::iter::Copied<std::slice::Iter<'a, U256>>;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter> {
        CommitmentUpdates::new(
            self.treeNumber.to(),
            self.startPosition.to(),
            self.hash.iter().copied(),
        )
    }
}

impl<'a> IntoCommitmentUpdates<'a> for GeneratedCommitmentBatch {
    type Iter = std::iter::Map<
        std::slice::Iter<'a, LegacyCommitmentPreimage>,
        fn(&LegacyCommitmentPreimage) -> U256,
    >;

    fn commitment_updates(&'a self) -> CommitmentUpdates<Self::Iter> {
        CommitmentUpdates::new(
            self.treeNumber.to(),
            self.startPosition.to(),
            self.commitments
                .iter()
                .map(LegacyCommitmentPreimage::hash as fn(&LegacyCommitmentPreimage) -> U256),
        )
    }
}
