use alloy::eips::eip7702::Authorization;
use alloy::primitives::{Address, B256, Bytes, U256, Uint};
use alloy::providers::ProviderBuilder;
use alloy::serde::{OtherFields, WithOtherFields};
use alloy::signers::{SignerSync, local::PrivateKeySigner};
use alloy::sol_types::SolCall;
use alloy::transports::mock::Asserter;
use broadcaster_core::contracts::executor::execute_signing_hash;
use broadcaster_core::contracts::railgun::{
    BoundParams, Call, CommitmentPreimage, RelayAdapt7702, RelayAdapt7702ActionData, SnarkProof,
    TokenData, Transaction, executeCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    BroadcasterAuthorization, BroadcasterRawParamsTransact, BroadcasterTransactRequestType,
    parse_transact_calldata,
};
use railgun_wallet::notes::{Note, NoteCiphertext};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tx_submit::Queue;

use super::{
    EVM_GAS_LIMIT_BUFFER, PrepareEvmTransactionError, funded_submission_queue,
    prepare_evm_tx7702_transaction,
};

pub(super) fn recovery_request(
    chain_id: u64,
    delegate: Address,
    nonce: U256,
    calls: Vec<Call>,
) -> (
    BroadcasterRawParamsTransact,
    ViewingKeyData,
    PrivateKeySigner,
) {
    recovery_request_with_authorization_chain(chain_id, U256::from(chain_id), delegate, nonce, calls)
}

/// Like `recovery_request`, with the delegation authorization signed for
/// `authorization_chain_id` instead of the request chain.
fn recovery_request_with_authorization_chain(
    chain_id: u64,
    authorization_chain_id: U256,
    delegate: Address,
    nonce: U256,
    calls: Vec<Call>,
) -> (
    BroadcasterRawParamsTransact,
    ViewingKeyData,
    PrivateKeySigner,
) {
    let owner = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x12)).unwrap();
    let receiver =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(3), U256::from(9)]);
    let sender = ViewingKeyData::from_spending_public_key([8; 32], [U256::from(4), U256::from(10)]);
    let fee_token = Address::repeat_byte(0x22);
    let transactions = [1_000_000_000_000_000_u64, 1]
        .into_iter()
        .zip([1, 2])
        .map(|(amount, index)| {
            let note = Note::new_change(
                receiver.master_public_key,
                fee_token,
                U256::from(amount),
                [index; 16],
            );
            let ciphertext = NoteCiphertext::try_from_note(
                &note,
                &sender.address_data(),
                &receiver.address_data(),
                &sender.viewing_private_key,
            )
            .unwrap();
            Transaction {
                proof: SnarkProof::default(),
                merkleRoot: B256::ZERO,
                nullifiers: vec![B256::repeat_byte(index)],
                commitments: vec![note.commitment().into()],
                boundParams: BoundParams::new_transact(
                    9,
                    0,
                    chain_id,
                    vec![ciphertext.into()],
                    owner.address(),
                    B256::ZERO,
                ),
                unshieldPreimage: CommitmentPreimage {
                    npk: B256::ZERO,
                    token: TokenData {
                        tokenType: 0,
                        tokenAddress: Address::ZERO,
                        tokenSubID: U256::ZERO,
                    },
                    value: Uint::<120, 2>::ZERO,
                },
            }
        })
        .collect::<Vec<_>>();
    let action = RelayAdapt7702ActionData {
        requireSuccess: true,
        minGasLimit: U256::ZERO,
        calls,
    };
    let signature = owner
        .sign_hash_sync(&execute_signing_hash(
            &transactions,
            &action,
            nonce,
            chain_id,
            owner.address(),
        ))
        .unwrap();
    let authorization = Authorization {
        chain_id: authorization_chain_id,
        address: delegate,
        nonce: 0,
    };
    let auth_signature = owner
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    let params = BroadcasterRawParamsTransact {
        chain_type: 0,
        chain_id,
        transact_type: Some(BroadcasterTransactRequestType::Tx7702),
        min_gas_price: None,
        max_fee_per_gas: Some(U256::from(1_000_000_000)),
        max_priority_fee_per_gas: Some(U256::ONE),
        authorization: Some(BroadcasterAuthorization {
            address: delegate,
            nonce: U256::ZERO,
            chain_id: authorization_chain_id,
            signature: WithOtherFields::new(auth_signature),
            other: OtherFields::default(),
        }),
        fees_id: Some("public-fixture".into()),
        to: owner.address(),
        data: RelayAdapt7702::executeCall {
            _transactions: transactions,
            _actionData: action,
            _nonce: nonce,
            _signature: signature.as_bytes().into(),
        }
        .abi_encode()
        .into(),
        broadcaster_viewing_key: receiver.viewing_public_key.into(),
        txid_version: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
        other: OtherFields::default(),
    };
    (params, receiver, owner)
}

#[tokio::test]
async fn execute_fee_outputs_cover_estimated_cost_before_recovery_queue_admission() {
    let delegate = Address::repeat_byte(0x23);
    let (params, receiver, _) = recovery_request(
        1,
        delegate,
        U256::from(9),
        vec![Call {
            to: Address::repeat_byte(0x24),
            data: Bytes::new(),
            value: U256::from(11),
        }],
    );
    let current = RelayAdapt7702::executeCall::abi_decode(&params.data).unwrap();
    let historical = executeCall {
        _transactions: current._transactions.clone(),
        _actionData: current._actionData.clone(),
        _signature: current._signature,
    }
    .abi_encode();
    let fees = fees::Manager::new(
        &HashMap::new(),
        U256::from(10).pow(U256::from(18)),
        Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1))),
        Address::ZERO,
        Address::repeat_byte(0x22),
        Duration::from_mins(1),
    );
    for data in [params.data.as_ref(), historical.as_slice()] {
        let mut parsed = parse_transact_calldata(
            data,
            &receiver.viewing_private_key,
            receiver.master_public_key,
            None,
        )
        .unwrap();
        assert_eq!(parsed.transactions.len(), 2);
        assert_ne!(
            parsed.transactions[0].railgun_txid,
            parsed.transactions[1].railgun_txid
        );
        let refund = fees.convert_to_eth(&parsed).await;
        assert_eq!(refund, U256::from(1_000_000_000_000_000_u64));
        for (estimated_gas, max_fee, accepted) in [
            (300_000_u64, 1_000_000_000_u64, true),
            (2_000_000, 1_000_000_000, false),
            (300_000, 10_000_000_000, false),
        ] {
            let mut request: BroadcasterRawParamsTransact =
                serde_json::from_value(serde_json::to_value(&params).unwrap()).unwrap();
            request.max_fee_per_gas = Some(U256::from(max_fee));
            let asserter = Asserter::new();
            asserter.push_success(&"0x7");
            asserter.push_success(&format!("0x{estimated_gas:x}"));
            let provider = ProviderBuilder::new().connect_mocked_client(asserter);
            let prepared = prepare_evm_tx7702_transaction(
                &provider,
                1,
                Address::repeat_byte(0x42),
                &request,
                Some(delegate),
            )
            .await
            .unwrap();
            assert_eq!(
                matches!(
                    funded_submission_queue(&parsed, prepared.cost, refund),
                    Some(Queue::Mev)
                ),
                accepted
            );
        }
        // An unpriced token is not a native-token payment, regardless of its raw amount.
        parsed.fee_token = Address::repeat_byte(0xff);
        let unpriced_refund = fees.convert_to_eth(&parsed).await;
        assert!(funded_submission_queue(&parsed, U256::ONE, unpriced_refund).is_none());
    }
    // Recovery multicalls carry no private fee notes and are never admitted.
    let multicall = RelayAdapt7702::multicallCall {
        _requireSuccess: true,
        _calls: Vec::new(),
        _nonce: U256::from(9),
        _signature: Bytes::new(),
    }
    .abi_encode();
    assert!(matches!(
        parse_transact_calldata(
            &multicall,
            &receiver.viewing_private_key,
            receiver.master_public_key,
            None
        ),
        Err(broadcaster_core::transact::TransactError::UnknownFunctionCall { .. })
    ));
}

#[tokio::test]
async fn prepared_tx7702_request_carries_owner_authorization_and_estimated_cost() {
    let delegate = Address::repeat_byte(0x23);
    // SDK clients may sign the delegation for chain zero; the request chain still applies.
    for authorization_chain_id in [U256::ONE, U256::ZERO] {
        let (params, _, owner) = recovery_request_with_authorization_chain(
            1,
            authorization_chain_id,
            delegate,
            U256::from(9),
            vec![Call {
                to: Address::repeat_byte(0x24),
                data: Bytes::new(),
                value: U256::from(11),
            }],
        );
        let asserter = Asserter::new();
        asserter.push_success(&"0x7");
        asserter.push_success(&"0x493e0");
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let prepared = prepare_evm_tx7702_transaction(
            &provider,
            1,
            Address::repeat_byte(0x42),
            &params,
            Some(delegate),
        )
        .await
        .unwrap();

        assert!(asserter.read_q().is_empty());
        assert_eq!(prepared.tx_req.to, Some(owner.address().into()));
        assert_eq!(prepared.tx_req.input.input(), Some(&params.data));
        assert_eq!(prepared.tx_req.nonce, Some(7));
        assert_eq!(prepared.gas, 300_000 + EVM_GAS_LIMIT_BUFFER);
        assert_eq!(
            prepared.cost,
            U256::from(prepared.gas) * U256::from(1_000_000_000)
        );
        let signed = &prepared.tx_req.authorization_list.unwrap()[0];
        assert_eq!(signed.recover_authority().unwrap(), owner.address());
        assert_eq!(signed.inner().chain_id, authorization_chain_id);
        assert_eq!(
            signed,
            &params
                .authorization
                .unwrap()
                .signed_authorization()
                .unwrap()
        );
    }
}

#[tokio::test]
async fn incompatible_authorizations_are_rejected_before_rpc_preparation() {
    let delegate = Address::repeat_byte(0x23);
    let request = || {
        recovery_request(
            1,
            delegate,
            U256::from(9),
            vec![Call {
                to: Address::repeat_byte(0x24),
                data: Bytes::new(),
                value: U256::from(11),
            }],
        )
        .0
    };
    let mut wrong_owner = request();
    wrong_owner.to = Address::repeat_byte(0xab);
    let mut wrong_chain = request();
    wrong_chain.authorization.as_mut().unwrap().chain_id = U256::from(56);
    let mut wrong_delegate = request();
    wrong_delegate.authorization.as_mut().unwrap().address = Address::repeat_byte(0xac);
    let mut wide_nonce = request();
    wide_nonce.authorization.as_mut().unwrap().nonce = U256::MAX;

    for (params, expected) in [
        (wrong_owner, "authority"),
        (wrong_chain, "chain"),
        (wrong_delegate, "delegate"),
        (wide_nonce, "nonce"),
    ] {
        let asserter = Asserter::new();
        asserter.push_success(&"0x7");
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let error = prepare_evm_tx7702_transaction(
            &provider,
            1,
            Address::repeat_byte(0x42),
            &params,
            Some(delegate),
        )
        .await
        .unwrap_err();
        assert!(match expected {
            "authority" => matches!(
                error,
                PrepareEvmTransactionError::Tx7702AuthorizationAuthorityMismatch { .. }
            ),
            "chain" => matches!(
                error,
                PrepareEvmTransactionError::Tx7702AuthorizationChainIdMismatch { .. }
            ),
            "delegate" => matches!(
                error,
                PrepareEvmTransactionError::Tx7702AuthorizationAddressMismatch { .. }
            ),
            "nonce" => matches!(error, PrepareEvmTransactionError::Tx7702Authorization(_)),
            _ => unreachable!(),
        });
        assert_eq!(
            asserter.read_q().len(),
            1,
            "rejection must precede nonce lookup and estimation"
        );
    }
}
