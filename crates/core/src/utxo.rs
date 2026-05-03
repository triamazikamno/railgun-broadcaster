use alloy::primitives::{Address, FixedBytes, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::poseidon::poseidon;
use crate::notes::Note;
use crate::tree::TREE_LEAF_COUNT_U256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoSource {
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct Utxo {
    pub note: Note,
    pub tree: u32,
    pub position: u64,
    pub source: UtxoSource,
    pub poi: UtxoPoiMetadata,
}

impl Utxo {
    #[must_use]
    pub fn new(
        note: Note,
        tree: u32,
        position: u64,
        source: UtxoSource,
        commitment_kind: UtxoCommitmentKind,
    ) -> Self {
        let poi = UtxoPoiMetadata::from_note(commitment_kind, &note, tree, position);
        Self {
            note,
            tree,
            position,
            source,
            poi,
        }
    }

    #[must_use]
    pub fn nullifier(&self, nullifying_key: U256) -> U256 {
        poseidon(vec![nullifying_key, U256::from(self.position)])
    }

    #[must_use]
    pub fn token_address(&self) -> Address {
        let token_bytes = self.note.token_hash.to_be_bytes::<32>();
        Address::from_slice(&token_bytes[12..32])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UtxoCommitmentKind {
    Shield,
    Transact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoiStatus {
    Valid,
    ShieldBlocked,
    ProofSubmitted,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoPoiMetadata {
    pub commitment_kind: UtxoCommitmentKind,
    pub commitment: FixedBytes<32>,
    pub npk: FixedBytes<32>,
    pub blinded_commitment: FixedBytes<32>,
    pub statuses: BTreeMap<FixedBytes<32>, PoiStatus>,
    pub refreshed_at: Option<u64>,
}

impl UtxoPoiMetadata {
    #[must_use]
    pub fn from_note(
        commitment_kind: UtxoCommitmentKind,
        note: &Note,
        tree: u32,
        position: u64,
    ) -> Self {
        let commitment = FixedBytes::from(note.commitment().to_be_bytes::<32>());
        let npk = FixedBytes::from(note.npk.to_be_bytes::<32>());
        let blinded_commitment = derive_blinded_commitment(commitment, npk, tree, position);
        Self {
            commitment_kind,
            commitment,
            npk,
            blinded_commitment,
            statuses: BTreeMap::new(),
            refreshed_at: None,
        }
    }

    #[must_use]
    pub fn is_valid_for_lists(&self, list_keys: &[FixedBytes<32>]) -> bool {
        list_keys.iter().all(|list_key| {
            self.statuses
                .get(list_key)
                .is_some_and(|status| *status == PoiStatus::Valid)
        })
    }
}

#[must_use]
pub fn derive_blinded_commitment(
    commitment: FixedBytes<32>,
    npk: FixedBytes<32>,
    tree: u32,
    position: u64,
) -> FixedBytes<32> {
    let global_tree_position = U256::from(tree) * TREE_LEAF_COUNT_U256 + U256::from(position);
    poseidon(vec![commitment.into(), npk.into(), global_tree_position]).into()
}

#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub spent: Option<UtxoSource>,
}

impl WalletUtxo {
    #[must_use]
    pub const fn new(utxo: Utxo) -> Self {
        Self { utxo, spent: None }
    }

    #[must_use]
    pub const fn is_spent(&self) -> bool {
        self.spent.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::derive_blinded_commitment;
    use crate::crypto::poseidon::poseidon;
    use crate::tree::TREE_LEAF_COUNT_U256;
    use alloy::primitives::{FixedBytes, U256};

    #[test]
    fn blinded_commitment_uses_global_tree_position() {
        let commitment = FixedBytes::from([0x11; 32]);
        let npk = FixedBytes::from([0x22; 32]);
        let tree = 2;
        let position = 7;

        let expected_global_position =
            U256::from(tree) * TREE_LEAF_COUNT_U256 + U256::from(position);
        let expected: FixedBytes<32> = poseidon(vec![
            commitment.into(),
            npk.into(),
            expected_global_position,
        ])
        .into();

        assert_eq!(
            derive_blinded_commitment(commitment, npk, tree, position),
            expected
        );
        assert_ne!(
            derive_blinded_commitment(commitment, npk, tree, position),
            derive_blinded_commitment(commitment, npk, tree, position + 1)
        );
    }
}
