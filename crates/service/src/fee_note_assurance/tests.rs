use super::{
    FeeNoteAssuranceSubmissionTracker, ReceiptEvaluation, ReceiptObservation,
    derive_fee_note_blinded_commitment, required_list_statuses_valid,
};
use crate::fee_note_store::FeeNoteAssuranceTerminalOutcome;
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, Log as PrimitiveLog, U256};
use alloy::sol_types::SolEvent;
use alloy::uint;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Transact};
use poi::poi::PoiStatus;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn railgun_contract() -> Address {
    Address::from([0x55; 20])
}

fn decode_fixed(hex_value: &str) -> FixedBytes<32> {
    let bytes: [u8; 32] = hex::decode(hex_value)
        .expect("decode hex")
        .try_into()
        .expect("32-byte hex value");
    FixedBytes::from(bytes)
}

fn should_submit_fee_note_assurance(
    tracker: &FeeNoteAssuranceSubmissionTracker,
    public_tx_hash: FixedBytes<32>,
    now: Instant,
    backoff: Duration,
) -> bool {
    tracker
        .next_submit_in(public_tx_hash, now, backoff)
        .is_none()
}

fn transact_log(fee_commitment: FixedBytes<32>, start_position: u64) -> Log {
    let event = Transact {
        treeNumber: uint!(7_U256),
        startPosition: U256::from(start_position),
        hash: vec![fee_commitment],
        ciphertext: vec![CommitmentCiphertext {
            ciphertext: [FixedBytes::ZERO; 4],
            blindedSenderViewingKey: FixedBytes::ZERO,
            blindedReceiverViewingKey: FixedBytes::ZERO,
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        }],
    };

    Log {
        inner: PrimitiveLog {
            address: railgun_contract(),
            data: event.encode_log_data(),
        },
        ..Log::default()
    }
}

#[test]
fn missing_receipt_stays_pending() {
    let receipt: Option<&ReceiptObservation> = None;
    assert_eq!(
        receipt.map_or(ReceiptEvaluation::Pending, |receipt| {
            receipt.evaluate(100, railgun_contract(), FixedBytes::from([1u8; 32]))
        }),
        ReceiptEvaluation::Pending
    );
}

#[test]
fn unsafe_receipt_stays_pending() {
    let receipt = ReceiptObservation {
        block_number: 101,
        status: false,
        logs: vec![],
    };

    assert_eq!(
        receipt.evaluate(100, railgun_contract(), FixedBytes::from([1u8; 32])),
        ReceiptEvaluation::Pending
    );
}

#[test]
fn safe_reverted_receipt_is_terminal() {
    let receipt = ReceiptObservation {
        block_number: 100,
        status: false,
        logs: vec![],
    };

    assert_eq!(
        receipt.evaluate(100, railgun_contract(), FixedBytes::from([1u8; 32])),
        ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::RevertedReceipt)
    );
}

#[test]
fn matching_transact_log_derives_fee_output_position() {
    let fee_commitment = FixedBytes::from([0x99; 32]);
    let receipt = ReceiptObservation {
        block_number: 100,
        status: true,
        logs: vec![transact_log(fee_commitment, 42)],
    };

    assert_eq!(
        receipt.evaluate(100, railgun_contract(), fee_commitment),
        ReceiptEvaluation::Ready(super::DerivedFeeOutputPosition {
            utxo_tree_out: 7,
            utxo_position_out: 42,
        })
    );
}

#[test]
fn mismatched_safe_receipt_is_terminal() {
    let receipt = ReceiptObservation {
        block_number: 100,
        status: true,
        logs: vec![transact_log(FixedBytes::from([0x44; 32]), 42)],
    };

    assert_eq!(
        receipt.evaluate(100, railgun_contract(), FixedBytes::from([0x99; 32])),
        ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::CommitmentMismatch)
    );
}

#[test]
fn proof_submitted_status_keeps_record_pending() {
    let list_key = FixedBytes::from([0x11; 32]);
    let statuses = BTreeMap::from([(list_key, PoiStatus::ProofSubmitted)]);

    assert!(!required_list_statuses_valid(&[list_key], &statuses));
}

#[test]
fn completion_checks_only_acceptance_time_list_keys() {
    let required_list_key = FixedBytes::from([0x11; 32]);
    let runtime_only_list_key = FixedBytes::from([0x22; 32]);
    let statuses = BTreeMap::from([
        (required_list_key, PoiStatus::Valid),
        (runtime_only_list_key, PoiStatus::Missing),
    ]);

    assert!(required_list_statuses_valid(
        &[required_list_key],
        &statuses
    ));
}

#[test]
fn derive_fee_note_blinded_commitment_matches_engine_formula() {
    let blinded_commitment = derive_fee_note_blinded_commitment(
        decode_fixed("1df757a1e41a19eda05c294fd2bc0a1f87a419f8abd5100f23d575501fea739d"),
        decode_fixed("2cb80dd82e59ed008072f45c9cb4309259c617ab8128fd777475aa21d922349d"),
        3,
        8838,
    );

    assert_eq!(
        blinded_commitment,
        decode_fixed("18b4b67957cc3ad570062898685ec0691d62e8bd2158f2dc112bcf8606e3ae06")
    );
}

#[test]
fn submission_log_is_emitted_once_per_process() {
    let tracker = FeeNoteAssuranceSubmissionTracker::default();
    let tx_hash = FixedBytes::from([0x11; 32]);

    assert!(tracker.mark_logged(tx_hash));
    assert!(!tracker.mark_logged(tx_hash));
}

#[test]
fn submission_backoff_allows_first_submit() {
    let tracker = FeeNoteAssuranceSubmissionTracker::default();

    assert!(should_submit_fee_note_assurance(
        &tracker,
        FixedBytes::from([0x11; 32]),
        Instant::now(),
        Duration::from_mins(15),
    ));
}

#[test]
fn submission_backoff_blocks_immediate_retry() {
    let tracker = FeeNoteAssuranceSubmissionTracker::default();
    let tx_hash = FixedBytes::from([0x11; 32]);
    let now = Instant::now();
    tracker.mark_attempt(tx_hash, now);

    assert!(!should_submit_fee_note_assurance(
        &tracker,
        tx_hash,
        now + Duration::from_mins(1),
        Duration::from_mins(15),
    ));
}

#[test]
fn submission_backoff_allows_retry_after_elapsed_time() {
    let tracker = FeeNoteAssuranceSubmissionTracker::default();
    let tx_hash = FixedBytes::from([0x11; 32]);
    let now = Instant::now();
    tracker.mark_attempt(tx_hash, now);

    assert!(should_submit_fee_note_assurance(
        &tracker,
        tx_hash,
        now + Duration::from_secs(901),
        Duration::from_mins(15),
    ));
}
