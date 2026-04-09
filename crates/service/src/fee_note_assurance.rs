use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::Provider;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::Transact;
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::{DbStore, FeeNoteAssuranceTerminalOutcome, PendingFeeNoteAssuranceRecord};
use poi::poi::{Poi, PoiStatus};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivedFeeOutputPosition {
    pub utxo_tree_out: u64,
    pub utxo_position_out: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReceiptObservation {
    pub block_number: u64,
    pub status: bool,
    pub logs: Vec<Log>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptEvaluation {
    Pending,
    Ready(DerivedFeeOutputPosition),
    Terminal(FeeNoteAssuranceTerminalOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeeNoteAssuranceRecordOutcome {
    Pending,
    Completed,
    Terminal,
}

pub(crate) async fn process_fee_note_assurance_record(
    db: &DbStore,
    query_rpc_pool: &QueryRpcPool,
    poi: &Poi,
    logged_submissions: &Mutex<HashSet<FixedBytes<32>>>,
    railgun_contract: Address,
    finality_depth: u64,
    record: PendingFeeNoteAssuranceRecord,
) -> FeeNoteAssuranceRecordOutcome {
    let Some(provider_handle) = query_rpc_pool.random_provider() else {
        warn!(
            chain_id = record.chain_id,
            tx_hash = %record.public_tx_hash,
            "no query rpc available for fee-note assurance"
        );
        return FeeNoteAssuranceRecordOutcome::Pending;
    };

    let head = match provider_handle.provider.get_block_number().await {
        Ok(head) => head,
        Err(error) => {
            warn!(
                %error,
                rpc = %provider_handle.url,
                chain_id = record.chain_id,
                tx_hash = %record.public_tx_hash,
                "fetch latest block failed for fee-note assurance"
            );
            query_rpc_pool.mark_bad_provider(&provider_handle);
            return FeeNoteAssuranceRecordOutcome::Pending;
        }
    };
    let safe_head = head.saturating_sub(finality_depth);

    let receipt = match provider_handle
        .provider
        .get_transaction_receipt(record.public_tx_hash)
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!(
                %error,
                rpc = %provider_handle.url,
                chain_id = record.chain_id,
                tx_hash = %record.public_tx_hash,
                "fetch transaction receipt failed for fee-note assurance"
            );
            query_rpc_pool.mark_bad_provider(&provider_handle);
            return FeeNoteAssuranceRecordOutcome::Pending;
        }
    };

    let receipt_observation = receipt.as_ref().and_then(|receipt| {
        receipt.block_number.map(|block_number| ReceiptObservation {
            block_number,
            status: receipt.status(),
            logs: receipt.logs().to_vec(),
        })
    });

    match evaluate_receipt(
        receipt_observation.as_ref(),
        safe_head,
        railgun_contract,
        record.context.fee_commitment,
    ) {
        ReceiptEvaluation::Pending => FeeNoteAssuranceRecordOutcome::Pending,
        ReceiptEvaluation::Terminal(reason) => {
            if let Err(error) = db.mark_fee_note_assurance_terminal(&record, reason) {
                error!(
                    ?error,
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    ?reason,
                    "persisting terminal fee-note assurance outcome failed"
                );
                FeeNoteAssuranceRecordOutcome::Pending
            } else {
                warn!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    ?reason,
                    "fee-note assurance reached a terminal non-retriable outcome"
                );
                FeeNoteAssuranceRecordOutcome::Terminal
            }
        }
        ReceiptEvaluation::Ready(output) => {
            let fee_blinded_commitment = derive_fee_note_blinded_commitment(
                record.context.fee_commitment,
                record.context.fee_note_npk,
                output.utxo_tree_out,
                output.utxo_position_out,
            );

            if let Ok(statuses) = poi
                .fee_note_statuses_for_blinded_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context.txid_version,
                    &record.context.required_poi_list_keys,
                    &fee_blinded_commitment,
                )
                .await
                && required_list_statuses_valid(&record.context.required_poi_list_keys, &statuses)
            {
                if let Err(error) =
                    db.delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
                {
                    error!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "deleting completed fee-note assurance record failed"
                    );
                    return FeeNoteAssuranceRecordOutcome::Pending;
                }
                info!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    "fee-note assurance already complete"
                );
                return FeeNoteAssuranceRecordOutcome::Completed;
            }

            if let Err(error) = poi
                .submit_fee_note_single_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context,
                    output.utxo_tree_out,
                    output.utxo_position_out,
                )
                .await
            {
                warn!(
                    ?error,
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    utxo_tree_out = output.utxo_tree_out,
                    utxo_position_out = output.utxo_position_out,
                    "submit single-commitment fee-note POI failed; keeping record pending"
                );
                return FeeNoteAssuranceRecordOutcome::Pending;
            }

            if mark_fee_note_submission_logged(logged_submissions, record.public_tx_hash) {
                info!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    fee_blinded_commitment = %fee_blinded_commitment,
                    utxo_tree_out = output.utxo_tree_out,
                    utxo_position_out = output.utxo_position_out,
                    "submitted fee-note single-commitment poi"
                );
            }

            let statuses = match poi
                .fee_note_statuses_for_blinded_commitment(
                    record.context.chain_type,
                    record.chain_id,
                    &record.context.txid_version,
                    &record.context.required_poi_list_keys,
                    &fee_blinded_commitment,
                )
                .await
            {
                Ok(statuses) => statuses,
                Err(error) => {
                    warn!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "query fee-note POI statuses failed after submission; keeping record pending"
                    );
                    return FeeNoteAssuranceRecordOutcome::Pending;
                }
            };

            if required_list_statuses_valid(&record.context.required_poi_list_keys, &statuses) {
                if let Err(error) =
                    db.delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
                {
                    error!(
                        ?error,
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "deleting completed fee-note assurance record failed"
                    );
                    FeeNoteAssuranceRecordOutcome::Pending
                } else {
                    info!(
                        chain_id = record.chain_id,
                        tx_hash = %record.public_tx_hash,
                        "fee-note assurance completed"
                    );
                    FeeNoteAssuranceRecordOutcome::Completed
                }
            } else {
                debug!(
                    chain_id = record.chain_id,
                    tx_hash = %record.public_tx_hash,
                    fee_blinded_commitment = %fee_blinded_commitment,
                    ?statuses,
                    "fee-note assurance still pending required POI validity"
                );
                FeeNoteAssuranceRecordOutcome::Pending
            }
        }
    }
}

fn mark_fee_note_submission_logged(
    logged_submissions: &Mutex<HashSet<FixedBytes<32>>>,
    public_tx_hash: FixedBytes<32>,
) -> bool {
    let mut logged_submissions = logged_submissions
        .lock()
        .expect("fee-note assurance submission log set poisoned");
    logged_submissions.insert(public_tx_hash)
}

pub(crate) fn evaluate_receipt(
    receipt: Option<&ReceiptObservation>,
    safe_head: u64,
    railgun_contract: Address,
    fee_commitment: FixedBytes<32>,
) -> ReceiptEvaluation {
    let Some(receipt) = receipt else {
        return ReceiptEvaluation::Pending;
    };

    if receipt.block_number > safe_head {
        return ReceiptEvaluation::Pending;
    }

    if !receipt.status {
        return ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::RevertedReceipt);
    }

    match derive_fee_output_position_from_logs(&receipt.logs, railgun_contract, fee_commitment) {
        Some(output) => ReceiptEvaluation::Ready(output),
        None => ReceiptEvaluation::Terminal(FeeNoteAssuranceTerminalOutcome::CommitmentMismatch),
    }
}

pub(crate) fn required_list_statuses_valid(
    required_poi_list_keys: &[FixedBytes<32>],
    statuses: &BTreeMap<FixedBytes<32>, PoiStatus>,
) -> bool {
    required_poi_list_keys.iter().all(|list_key| {
        statuses
            .get(list_key)
            .is_some_and(|status| *status == PoiStatus::Valid)
    })
}

fn derive_fee_note_blinded_commitment(
    fee_commitment: FixedBytes<32>,
    fee_note_npk: FixedBytes<32>,
    utxo_tree_out: u64,
    utxo_position_out: u64,
) -> FixedBytes<32> {
    const TREE_MAX_ITEMS: u64 = 65_536;

    let global_tree_position =
        U256::from(utxo_tree_out) * U256::from(TREE_MAX_ITEMS) + U256::from(utxo_position_out);

    poseidon(vec![
        fee_commitment.into(),
        fee_note_npk.into(),
        global_tree_position,
    ])
    .into()
}

fn derive_fee_output_position_from_logs(
    logs: &[Log],
    railgun_contract: Address,
    fee_commitment: FixedBytes<32>,
) -> Option<DerivedFeeOutputPosition> {
    logs.iter()
        .filter(|log| log.address() == railgun_contract)
        .filter_map(|log| log.log_decode::<Transact>().ok())
        .find_map(|log| {
            let event = log.inner.data;
            (event.hash.first().copied() == Some(fee_commitment)).then(|| {
                DerivedFeeOutputPosition {
                    utxo_tree_out: event.treeNumber.to(),
                    utxo_position_out: event.startPosition.to(),
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{
        ReceiptEvaluation, ReceiptObservation, derive_fee_note_blinded_commitment,
        evaluate_receipt, mark_fee_note_submission_logged, required_list_statuses_valid,
    };
    use alloy::hex;
    use alloy::primitives::{Address, Bytes, FixedBytes, Log as PrimitiveLog, U256};
    use alloy::sol_types::SolEvent;
    use alloy_rpc_types_eth::Log;
    use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Transact};
    use local_db::FeeNoteAssuranceTerminalOutcome;
    use poi::poi::PoiStatus;
    use std::collections::BTreeMap;
    use std::collections::HashSet;
    use std::sync::Mutex;

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

    fn transact_log(fee_commitment: FixedBytes<32>, start_position: u64) -> Log {
        let event = Transact {
            treeNumber: U256::from(7_u8),
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
        assert_eq!(
            evaluate_receipt(None, 100, railgun_contract(), FixedBytes::from([1u8; 32])),
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
            evaluate_receipt(
                Some(&receipt),
                100,
                railgun_contract(),
                FixedBytes::from([1u8; 32])
            ),
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
            evaluate_receipt(
                Some(&receipt),
                100,
                railgun_contract(),
                FixedBytes::from([1u8; 32])
            ),
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
            evaluate_receipt(Some(&receipt), 100, railgun_contract(), fee_commitment),
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
            evaluate_receipt(
                Some(&receipt),
                100,
                railgun_contract(),
                FixedBytes::from([0x99; 32])
            ),
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
        let logged_submissions = Mutex::new(HashSet::new());
        let tx_hash = FixedBytes::from([0x11; 32]);

        assert!(mark_fee_note_submission_logged(
            &logged_submissions,
            tx_hash
        ));
        assert!(!mark_fee_note_submission_logged(
            &logged_submissions,
            tx_hash
        ));
    }
}
