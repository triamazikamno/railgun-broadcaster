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

impl PoiStatus {
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        matches!(self, Self::Missing | Self::ProofSubmitted | Self::Unknown)
    }
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
        let blinded_commitment = Self::blinded_commitment_for(commitment, npk, tree, position);
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

    #[must_use]
    pub fn has_recoverable_status_for_lists(&self, list_keys: &[FixedBytes<32>]) -> bool {
        list_keys.iter().any(|list_key| {
            self.statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
        })
    }

    #[must_use]
    pub fn apply_status_refresh(
        &mut self,
        list_keys: &[FixedBytes<32>],
        statuses: Option<&BTreeMap<FixedBytes<32>, PoiStatus>>,
        refreshed_at: u64,
    ) -> usize {
        let mut status_changes = 0usize;
        let old_refreshed_at = self.refreshed_at;
        for list_key in list_keys {
            let status = statuses
                .and_then(|per_list| per_list.get(list_key))
                .copied()
                .unwrap_or(PoiStatus::Missing);
            let old_status = self.statuses.insert(*list_key, status);
            if old_status != Some(status) {
                status_changes += 1;
            }
        }
        self.refreshed_at = Some(refreshed_at);
        if old_refreshed_at != Some(refreshed_at) {
            status_changes += 1;
        }
        status_changes
    }

    #[must_use]
    pub fn mark_statuses_unknown_for_lists(&mut self, list_keys: &[FixedBytes<32>]) -> usize {
        let mut status_changes = 0usize;
        for list_key in list_keys {
            let old_status = self.statuses.insert(*list_key, PoiStatus::Unknown);
            if old_status != Some(PoiStatus::Unknown) {
                status_changes += 1;
            }
        }
        status_changes
    }

    #[must_use]
    pub fn blinded_commitment_for(
        commitment: FixedBytes<32>,
        npk: FixedBytes<32>,
        tree: u32,
        position: u64,
    ) -> FixedBytes<32> {
        let global_tree_position = U256::from(tree) * TREE_LEAF_COUNT_U256 + U256::from(position);
        poseidon(vec![commitment.into(), npk.into(), global_tree_position]).into()
    }
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
    use std::collections::BTreeMap;

    use alloy::primitives::{FixedBytes, U256};

    use crate::crypto::poseidon::poseidon;
    use crate::tree::TREE_LEAF_COUNT_U256;

    use super::{PoiStatus, UtxoCommitmentKind, UtxoPoiMetadata};

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
            UtxoPoiMetadata::blinded_commitment_for(commitment, npk, tree, position),
            expected
        );
        assert_ne!(
            UtxoPoiMetadata::blinded_commitment_for(commitment, npk, tree, position),
            UtxoPoiMetadata::blinded_commitment_for(commitment, npk, tree, position + 1)
        );
    }

    #[test]
    fn poi_status_recoverable_matches_retryable_statuses() {
        assert!(!PoiStatus::Valid.is_recoverable());
        assert!(!PoiStatus::ShieldBlocked.is_recoverable());
        assert!(PoiStatus::ProofSubmitted.is_recoverable());
        assert!(PoiStatus::Missing.is_recoverable());
        assert!(PoiStatus::Unknown.is_recoverable());
    }

    #[test]
    fn poi_metadata_has_recoverable_status_for_lists() {
        let recoverable_list = FixedBytes::from([0x11; 32]);
        let valid_list = FixedBytes::from([0x22; 32]);
        let shield_blocked_list = FixedBytes::from([0x33; 32]);
        let missing_list = FixedBytes::from([0x44; 32]);
        let metadata = UtxoPoiMetadata {
            commitment_kind: UtxoCommitmentKind::Transact,
            commitment: FixedBytes::from([0xaa; 32]),
            npk: FixedBytes::from([0xbb; 32]),
            blinded_commitment: FixedBytes::from([0xcc; 32]),
            statuses: BTreeMap::from([
                (recoverable_list, PoiStatus::Missing),
                (valid_list, PoiStatus::Valid),
                (shield_blocked_list, PoiStatus::ShieldBlocked),
            ]),
            refreshed_at: None,
        };

        assert!(metadata.has_recoverable_status_for_lists(&[recoverable_list]));
        assert!(metadata.has_recoverable_status_for_lists(&[missing_list]));
        assert!(!metadata.has_recoverable_status_for_lists(&[valid_list, shield_blocked_list]));
        assert!(!metadata.has_recoverable_status_for_lists(&[]));
    }

    #[test]
    fn poi_metadata_apply_status_refresh_updates_statuses_and_refresh_time() {
        let updated_list = FixedBytes::from([0x11; 32]);
        let unchanged_list = FixedBytes::from([0x22; 32]);
        let missing_list = FixedBytes::from([0x33; 32]);
        let mut metadata = UtxoPoiMetadata {
            commitment_kind: UtxoCommitmentKind::Transact,
            commitment: FixedBytes::from([0xaa; 32]),
            npk: FixedBytes::from([0xbb; 32]),
            blinded_commitment: FixedBytes::from([0xcc; 32]),
            statuses: BTreeMap::from([
                (updated_list, PoiStatus::Unknown),
                (unchanged_list, PoiStatus::Valid),
            ]),
            refreshed_at: Some(10),
        };
        let refreshed_statuses = BTreeMap::from([
            (updated_list, PoiStatus::Valid),
            (unchanged_list, PoiStatus::Valid),
        ]);

        let changes = metadata.apply_status_refresh(
            &[updated_list, unchanged_list, missing_list],
            Some(&refreshed_statuses),
            20,
        );

        assert_eq!(changes, 3);
        assert_eq!(
            metadata.statuses.get(&updated_list),
            Some(&PoiStatus::Valid)
        );
        assert_eq!(
            metadata.statuses.get(&unchanged_list),
            Some(&PoiStatus::Valid)
        );
        assert_eq!(
            metadata.statuses.get(&missing_list),
            Some(&PoiStatus::Missing)
        );
        assert_eq!(metadata.refreshed_at, Some(20));

        assert_eq!(
            metadata.apply_status_refresh(
                &[updated_list, unchanged_list, missing_list],
                Some(&refreshed_statuses),
                20,
            ),
            0
        );
    }

    #[test]
    fn poi_metadata_mark_statuses_unknown_for_lists_does_not_refresh() {
        let updated_list = FixedBytes::from([0x11; 32]);
        let unchanged_list = FixedBytes::from([0x22; 32]);
        let inserted_list = FixedBytes::from([0x33; 32]);
        let mut metadata = UtxoPoiMetadata {
            commitment_kind: UtxoCommitmentKind::Transact,
            commitment: FixedBytes::from([0xaa; 32]),
            npk: FixedBytes::from([0xbb; 32]),
            blinded_commitment: FixedBytes::from([0xcc; 32]),
            statuses: BTreeMap::from([
                (updated_list, PoiStatus::Valid),
                (unchanged_list, PoiStatus::Unknown),
            ]),
            refreshed_at: Some(20),
        };

        let changes = metadata.mark_statuses_unknown_for_lists(&[
            updated_list,
            unchanged_list,
            inserted_list,
        ]);

        assert_eq!(changes, 2);
        assert_eq!(
            metadata.statuses.get(&updated_list),
            Some(&PoiStatus::Unknown)
        );
        assert_eq!(
            metadata.statuses.get(&unchanged_list),
            Some(&PoiStatus::Unknown)
        );
        assert_eq!(
            metadata.statuses.get(&inserted_list),
            Some(&PoiStatus::Unknown)
        );
        assert_eq!(metadata.refreshed_at, Some(20));

        assert_eq!(
            metadata.mark_statuses_unknown_for_lists(&[
                updated_list,
                unchanged_list,
                inserted_list,
            ]),
            0
        );
    }
}
