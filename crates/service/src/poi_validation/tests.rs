use super::{
    EVM_CHAIN_TYPE, FeeNoteStatusOutcome, LocalPoiFallbackReason, RootValidationOutcome,
    local_fee_note_status_outcome, local_root_validation_outcome, snark_validation_result,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use broadcaster_core::transact::{BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION};
use poi::error::PoiError;
use poi::poi::default_active_poi_list_key;
use std::collections::BTreeMap;

const CHAIN_ID: u64 = 1;

fn params_with_poi_map(
    pre_transaction_pois_per_txid_leaf_per_list: BTreeMap<
        FixedBytes<32>,
        BTreeMap<FixedBytes<32>, broadcaster_core::transact::PreTxPoi>,
    >,
) -> BroadcasterRawParamsTransact {
    BroadcasterRawParamsTransact {
        chain_type: u64::from(EVM_CHAIN_TYPE),
        chain_id: CHAIN_ID,
        transact_type: None,
        min_gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        authorization: None,
        fees_id: None,
        to: Address::ZERO,
        data: Bytes::new(),
        broadcaster_viewing_key: FixedBytes::ZERO,
        txid_version: None,
        pre_transaction_pois_per_txid_leaf_per_list,
        other: alloy::serde::OtherFields::default(),
    }
}

#[tokio::test]
async fn non_default_list_uses_proxy_without_local_cache() {
    let default_list_key = default_active_poi_list_key();
    let non_default_list_key = FixedBytes::from([0x22; 32]);

    assert_eq!(
        local_root_validation_outcome(
            None,
            &[default_list_key],
            EVM_CHAIN_TYPE,
            CHAIN_ID,
            DEFAULT_TXID_VERSION,
            &non_default_list_key,
            &[FixedBytes::from([0x99; 32])],
        )
        .await,
        RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::NonDefaultListKey)
    );
}

#[tokio::test]
async fn missing_poi_on_any_inner_transaction_or_list_precedes_root_requests() {
    use broadcaster_core::crypto::snark_proof::Prover;
    use broadcaster_core::transact::{
        PreTxPoi, SnarkJsProof, dummy_txid_root, parse_transact_calldata, railgun_txid_leaf_hash,
    };
    use poi::poi::{Poi, PoiRpcClient};
    use std::sync::Arc;

    // No calls: the setup shape, whose `execute` carries only the private fee.
    let (params, receiver, _) = crate::executor_tests::recovery_request(
        CHAIN_ID,
        Address::repeat_byte(0x23),
        U256::ZERO,
        Vec::new(),
    );
    let parsed = parse_transact_calldata(
        &params.data,
        &receiver.viewing_private_key,
        receiver.master_public_key,
        None,
    )
    .unwrap();
    let lists = [FixedBytes::repeat_byte(0x11), FixedBytes::repeat_byte(0x22)];
    let leaves = parsed
        .transactions
        .iter()
        .map(|tx| railgun_txid_leaf_hash(tx.railgun_txid, tx.utxo_tree_in))
        .collect::<Vec<_>>();
    let proofs = leaves
        .iter()
        .map(|leaf| {
            (
                FixedBytes::from(*leaf),
                PreTxPoi {
                    snark_proof: SnarkJsProof::zero(),
                    txid_merkleroot: dummy_txid_root(*leaf).into(),
                    poi_merkleroots: vec![FixedBytes::ZERO],
                    blinded_commitments_out: vec![FixedBytes::ZERO],
                    railgun_txid_if_has_unshield: Bytes::new(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let rpc = PoiRpcClient::new("http://127.0.0.1:1".parse::<url::Url>().unwrap());
    let prover = Arc::new(Prover::new().unwrap());
    let validator = super::BroadcasterPoiValidator::new(
        Arc::new(Poi::new(rpc.clone(), prover.clone(), lists.to_vec())),
        rpc,
        prover,
        lists.to_vec(),
        None,
    );
    for (missing_list, missing_leaf) in [
        (lists[1], None),
        (lists[0], Some(FixedBytes::from(leaves[1]))),
        (lists[1], Some(FixedBytes::from(leaves[0]))),
    ] {
        let mut map = BTreeMap::from([(lists[0], proofs.clone()), (lists[1], proofs.clone())]);
        if let Some(leaf) = missing_leaf {
            map.get_mut(&missing_list).unwrap().remove(&leaf);
        } else {
            map.remove(&missing_list);
        }
        let error = validator
            .validate_all(&parsed, &params_with_poi_map(map))
            .await
            .unwrap_err();
        let PoiError::ValidateList { list_key, source } = error else {
            panic!("expected missing proof/list rejection before RPC");
        };
        assert_eq!(list_key, missing_list);
        match missing_leaf {
            Some(expected) => assert!(
                matches!(*source, PoiError::MissingProof { leaf_hex } if leaf_hex == expected)
            ),
            None => assert!(matches!(*source, PoiError::MissingListKey)),
        }
    }
    // A complete map clears the proof-map stage for every fee transaction on every list.
    let complete = params_with_poi_map(BTreeMap::from([
        (lists[0], proofs.clone()),
        (lists[1], proofs),
    ]));
    for list_key in &lists {
        for transaction in &parsed.transactions {
            assert!(
                super::transaction_poi_for_validation(transaction, &complete, list_key).is_ok()
            );
        }
    }
}

#[test]
fn invalid_snark_result_is_rejected_without_proxy_retry() {
    assert!(matches!(
        snark_validation_result(false),
        Err(PoiError::InvalidSnarkProof)
    ));
}

#[tokio::test]
async fn fee_note_non_default_list_falls_back_to_proxy() {
    let default_list_key = default_active_poi_list_key();
    let non_default_list_key = FixedBytes::from([0x22; 32]);

    match local_fee_note_status_outcome(
        None,
        &[default_list_key],
        EVM_CHAIN_TYPE,
        CHAIN_ID,
        DEFAULT_TXID_VERSION,
        &[non_default_list_key],
        &FixedBytes::from([0x44; 32]),
    )
    .await
    {
        FeeNoteStatusOutcome::LocalValid(_) => panic!("expected proxy fallback"),
        FeeNoteStatusOutcome::ProxyFallback { reason, .. } => {
            assert_eq!(reason, LocalPoiFallbackReason::NonDefaultListKey);
        }
    }
}
