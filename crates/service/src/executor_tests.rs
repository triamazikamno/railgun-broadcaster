use alloy::eips::eip7702::Authorization;
use alloy::primitives::{Address, B256, Bytes, U256, Uint};
use alloy::providers::ProviderBuilder;
use alloy::rpc::types::TransactionRequest;
use alloy::serde::{OtherFields, WithOtherFields};
use alloy::signers::{SignerSync, local::PrivateKeySigner};
use alloy::sol_types::SolCall;
use alloy::transports::mock::Asserter;
use axum::{Json, Router, extract::State, routing::post};
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tx_submit::Queue;

use super::{
    EVM_GAS_LIMIT_BUFFER, PrepareEvmTransactionError, TX7702_DELEGATION_PROBE_GAS_LIMIT,
    funded_submission_queue, prepare_evm_tx7702_transaction, prepare_evm_tx7702_with_fallback,
};

struct Tx7702RpcFixture {
    url: url::Url,
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Tx7702RpcFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Tx7702RpcState {
    estimated_gas: u64,
    required_gas: u64,
    executes_delegation: bool,
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Tx7702RpcFixture {
    async fn start(estimated_gas: u64, required_gas: u64, executes_delegation: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(tx7702_rpc_response))
            .with_state(Tx7702RpcState {
                estimated_gas,
                required_gas,
                executes_delegation,
                requests: requests.clone(),
            });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url,
            requests,
            task,
        }
    }
}

async fn tx7702_rpc_response(
    State(state): State<Tx7702RpcState>,
    Json(request): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    state.requests.lock().unwrap().push(request.clone());
    let result = match request["method"].as_str().unwrap() {
        "eth_getTransactionCount" => serde_json::json!("0x7"),
        "eth_estimateGas" => serde_json::json!(format!("0x{:x}", state.estimated_gas)),
        "eth_call" => {
            let tx: TransactionRequest =
                serde_json::from_value(request["params"][0].clone()).unwrap();
            // Model an RPC with no gas cap and the finite sender balance from the BSC failure.
            let gas = tx.gas.unwrap_or(u64::MAX);
            let balance = U256::from(302_432_038_208_973_193_u64);
            let cost = U256::from(gas) * U256::from(tx.max_fee_per_gas.unwrap());
            if cost > balance {
                return Json(serde_json::json!({
                    "jsonrpc": "2.0", "id": request["id"],
                    "error": {
                        "code": -32000,
                        "message": "insufficient funds for gas * price + value"
                    }
                }));
            }
            let getter = RelayAdapt7702::nonceCall {}.abi_encode();
            if tx.input.input().unwrap().as_ref() == getter {
                if state.executes_delegation {
                    serde_json::json!(format!("0x{:064x}", 9))
                } else {
                    serde_json::json!("0x")
                }
            } else {
                if tx.gas.unwrap() < state.required_gas {
                    return Json(serde_json::json!({
                        "jsonrpc": "2.0", "id": request["id"],
                        "error": { "code": -32000, "message": "out of gas" }
                    }));
                }
                serde_json::json!("0x")
            }
        }
        method => panic!("unexpected RPC method {method}"),
    };
    Json(serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
}

#[tokio::test]
async fn tx7702_underestimated_gas_is_rejected_before_submission() {
    let delegate = Address::repeat_byte(0x23);
    let (params, _, _) = recovery_request(137, delegate, U256::from(9), Vec::new());
    let fixture = Tx7702RpcFixture::start(69_626, 1_475_582, true).await;
    let provider = ProviderBuilder::new().connect_http(fixture.url.clone());
    let result = prepare_evm_tx7702_transaction(
        &provider,
        137,
        Address::repeat_byte(0x42),
        &params,
        Some(delegate),
    )
    .await;
    assert!(matches!(
        result,
        Err(PrepareEvmTransactionError::Tx7702Simulation(_))
    ));
    let requests = fixture.requests.lock().unwrap();
    let execution = requests.last().unwrap();
    assert_eq!(execution["method"], "eth_call");
    let tx: TransactionRequest = serde_json::from_value(execution["params"][0].clone()).unwrap();
    assert_eq!(
        tx.gas,
        Some(69_626),
        "simulate at the raw estimate before adding the buffer"
    );
}

#[tokio::test]
async fn tx7702_preparation_falls_back_from_bad_estimation_and_ignored_delegation() {
    let delegate = Address::repeat_byte(0x23);
    let (params, _, _) = recovery_request(137, delegate, U256::from(9), Vec::new());
    for executes_delegation in [true, false] {
        let failed = Tx7702RpcFixture::start(69_626, 1_475_582, executes_delegation).await;
        let working = Tx7702RpcFixture::start(1_500_000, 1_475_582, true).await;
        let pool = QueryRpcPool::new(
            vec![failed.url.clone(), working.url.clone()],
            Duration::from_secs(60),
        );
        let mut handle = pool.available_providers().remove(0);
        let prepared = prepare_evm_tx7702_with_fallback(
            &mut handle,
            &pool,
            137,
            Address::repeat_byte(0x42),
            &params,
            Some(delegate),
        )
        .await
        .unwrap();
        assert_eq!(handle.index, 1);
        assert_eq!(prepared.gas, 1_500_000 + EVM_GAS_LIMIT_BUFFER);
        assert_eq!(
            pool.available_providers().len(),
            2,
            "request failures must not cool down RPC endpoints"
        );
        let failed_requests = failed.requests.lock().unwrap();
        assert_eq!(
            failed_requests
                .iter()
                .filter(|request| request["method"] == "eth_getTransactionCount")
                .count(),
            1
        );
        if !executes_delegation {
            assert!(
                !failed_requests
                    .iter()
                    .any(|request| request["method"] == "eth_estimateGas"),
                "an empty delegated getter result must be rejected before estimation"
            );
        }
    }
}

#[tokio::test]
async fn tx7702_preparation_stops_after_each_eligible_rpc_fails_once() {
    let delegate = Address::repeat_byte(0x23);
    let (params, _, _) = recovery_request(137, delegate, U256::from(9), Vec::new());
    let fixtures = [
        Tx7702RpcFixture::start(69_626, 1_475_582, true).await,
        Tx7702RpcFixture::start(69_626, 1_475_582, false).await,
        Tx7702RpcFixture::start(69_626, 1_475_582, true).await,
    ];
    let pool = QueryRpcPool::new(
        fixtures.iter().map(|fixture| fixture.url.clone()).collect(),
        Duration::from_secs(60),
    );
    let mut handle = pool.available_providers().remove(0);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        prepare_evm_tx7702_with_fallback(
            &mut handle,
            &pool,
            137,
            Address::repeat_byte(0x42),
            &params,
            Some(delegate),
        ),
    )
    .await
    .expect("endpoint attempts must be bounded");
    assert!(matches!(
        result,
        Err(PrepareEvmTransactionError::Tx7702Simulation(_)
            | PrepareEvmTransactionError::Tx7702DelegationDecode(_))
    ));
    for fixture in &fixtures {
        assert_eq!(
            fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "eth_getTransactionCount")
                .count(),
            1
        );
    }
    assert_eq!(pool.available_providers().len(), fixtures.len());
}

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
    recovery_request_with_authorization_chain(
        chain_id,
        U256::from(chain_id),
        delegate,
        nonce,
        calls,
    )
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

/// `execute` call lists for an action-bearing request and a setup request that
/// carries only the private fee; admission must treat both the same.
fn execute_call_shapes() -> [Vec<Call>; 2] {
    [
        vec![Call {
            to: Address::repeat_byte(0x24),
            data: Bytes::new(),
            value: U256::from(11),
        }],
        Vec::new(),
    ]
}

#[tokio::test]
async fn execute_fee_outputs_cover_estimated_cost_before_recovery_queue_admission() {
    let delegate = Address::repeat_byte(0x23);
    let fees = fees::Manager::new(
        &HashMap::new(),
        U256::from(10).pow(U256::from(18)),
        Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1))),
        Address::ZERO,
        Address::repeat_byte(0x22),
        Duration::from_mins(1),
    );
    let requests =
        execute_call_shapes().map(|calls| recovery_request(1, delegate, U256::from(9), calls));
    for (params, receiver, _) in &requests {
        let current = RelayAdapt7702::executeCall::abi_decode(&params.data).unwrap();
        let historical = executeCall {
            _transactions: current._transactions.clone(),
            _actionData: current._actionData.clone(),
            _signature: current._signature,
        }
        .abi_encode();
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
                    serde_json::from_value(serde_json::to_value(params).unwrap()).unwrap();
                request.max_fee_per_gas = Some(U256::from(max_fee));
                let asserter = Asserter::new();
                asserter.push_success(&"0x7");
                asserter.push_success(&format!("0x{:064x}", 9));
                asserter.push_success(&format!("0x{estimated_gas:x}"));
                asserter.push_success(&"0x");
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
    }
    let receiver = &requests[0].1;
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
        let fixture = Tx7702RpcFixture::start(300_000, 300_000, true).await;
        let provider = ProviderBuilder::new().connect_http(fixture.url.clone());
        let prepared = prepare_evm_tx7702_transaction(
            &provider,
            1,
            Address::repeat_byte(0x42),
            &params,
            Some(delegate),
        )
        .await
        .unwrap();

        let requests = fixture.requests.lock().unwrap();
        let calls: Vec<_> = requests
            .iter()
            .filter(|request| request["method"] == "eth_call")
            .collect();
        assert_eq!(calls.len(), 2);
        let mut expected_probe = prepared.tx_req.clone();
        expected_probe.gas = Some(TX7702_DELEGATION_PROBE_GAS_LIMIT);
        expected_probe.input = RelayAdapt7702::nonceCall {}.abi_encode().into();
        let mut expected_execution = prepared.tx_req.clone();
        expected_execution.gas = Some(300_000);
        for (call, expected) in calls.iter().zip([expected_probe, expected_execution]) {
            assert_eq!(call["params"][1], "pending");
            let actual: TransactionRequest =
                serde_json::from_value(call["params"][0].clone()).unwrap();
            assert_eq!(
                actual, expected,
                "simulation must preserve authorization, calldata, sender and fee envelope"
            );
        }
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
    let fixtures = [
        Tx7702RpcFixture::start(300_000, 300_000, true).await,
        Tx7702RpcFixture::start(300_000, 300_000, true).await,
    ];
    let pool = QueryRpcPool::new(
        fixtures.iter().map(|fixture| fixture.url.clone()).collect(),
        Duration::from_secs(60),
    );

    for (params, expected) in [
        (wrong_owner, "authority"),
        (wrong_chain, "chain"),
        (wrong_delegate, "delegate"),
        (wide_nonce, "nonce"),
    ] {
        let mut handle = pool.available_providers().remove(0);
        let error = prepare_evm_tx7702_with_fallback(
            &mut handle,
            &pool,
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
            handle.index, 0,
            "invalid requests must not retry other endpoints"
        );
        for fixture in &fixtures {
            assert!(
                fixture.requests.lock().unwrap().is_empty(),
                "rejection must precede RPC preparation"
            );
        }
    }
}
