use super::{
    FeeNoteAssuranceFallback, collect_pending_fee_note_assurance_records,
    should_remove_fee_note_assurance_fallback,
};
use crate::fee_note_assurance::FeeNoteAssuranceRecordOutcome;
use crate::fee_note_store::PendingFeeNoteAssuranceRecord;
use alloy::primitives::FixedBytes;
use alloy::uint;
use broadcaster_core::transact::FeeNoteAssuranceContext;
use std::collections::{BTreeMap, HashMap};

fn sample_record(chain_id: u64, tx_hash: [u8; 32]) -> PendingFeeNoteAssuranceRecord {
    PendingFeeNoteAssuranceRecord {
        chain_id,
        public_tx_hash: FixedBytes::from(tx_hash),
        context: FeeNoteAssuranceContext {
            chain_type: 0,
            txid_version: "V2_PoseidonMerkle".to_string(),
            railgun_txid: uint!(5_U256),
            utxo_tree_in: 9,
            fee_commitment: FixedBytes::from([1u8; 32]),
            fee_note_npk: FixedBytes::from([2u8; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            required_poi_list_keys: vec![FixedBytes::from([4u8; 32])],
        },
    }
}

#[test]
fn fallback_queue_roundtrips_records() {
    let fallback = FeeNoteAssuranceFallback::default();
    let record = sample_record(1, [0x11; 32]);

    fallback.insert(record.clone());

    let snapshot = fallback.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].public_tx_hash, record.public_tx_hash);
    assert_eq!(
        snapshot[0].context.railgun_txid,
        record.context.railgun_txid
    );

    fallback.remove(&record.public_tx_hash);
    assert!(fallback.snapshot().is_empty());
}

#[test]
fn collect_pending_fee_note_assurance_records_prefers_db_record() {
    let fallback_record = sample_record(1, [0x22; 32]);
    let mut db_record = fallback_record.clone();
    db_record.context.railgun_txid = uint!(9_U256);

    let records = collect_pending_fee_note_assurance_records(
        vec![db_record.clone()],
        vec![fallback_record, sample_record(1, [0x33; 32])],
    );
    let by_hash = records
        .into_iter()
        .map(|(record, was_fallback_only)| (record.public_tx_hash, (record, was_fallback_only)))
        .collect::<HashMap<_, _>>();

    assert_eq!(by_hash.len(), 2);
    assert_eq!(
        by_hash[&FixedBytes::from([0x22; 32])]
            .0
            .context
            .railgun_txid,
        db_record.context.railgun_txid
    );
    assert!(!by_hash[&FixedBytes::from([0x22; 32])].1);
    assert!(by_hash[&FixedBytes::from([0x33; 32])].1);
}

#[test]
fn completed_fallback_record_is_removed() {
    assert!(should_remove_fee_note_assurance_fallback(
        FeeNoteAssuranceRecordOutcome::Completed,
        true,
    ));
}

#[test]
fn terminal_fallback_record_is_removed() {
    assert!(should_remove_fee_note_assurance_fallback(
        FeeNoteAssuranceRecordOutcome::Terminal,
        true,
    ));
}

#[test]
fn pending_fallback_record_is_kept() {
    assert!(!should_remove_fee_note_assurance_fallback(
        FeeNoteAssuranceRecordOutcome::Pending,
        true,
    ));
}

#[test]
fn db_backed_record_is_never_removed_from_fallback() {
    assert!(!should_remove_fee_note_assurance_fallback(
        FeeNoteAssuranceRecordOutcome::Completed,
        false,
    ));
}
