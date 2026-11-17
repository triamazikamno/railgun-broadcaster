//! EVM transaction preparation, including the EIP-7702 request checks, and
//! signed submission through the transaction broadcaster.

use alloy::eips::Encodable2718;
use alloy::eips::eip7702::SignedAuthorization;
use alloy::network::{
    EthereumWallet, NetworkTransactionBuilder, TransactionBuilder, TransactionBuilder7702,
};
use alloy::primitives::{Address, Bytes, ChainId, TxHash, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolCall;
use alloy::transports::TransportErrorKind;
use broadcaster_core::contracts::railgun::RelayAdapt7702;
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use broadcaster_core::transact::{
    BroadcasterAuthorization, BroadcasterRawParamsTransact, TransactError,
};
use rand::seq::SliceRandom;
use thiserror::Error;
use tracing::debug;
use tx_submit::{Queue, TxBroadcaster};

#[derive(Debug, Error)]
pub enum SubmitTxError {
    #[error("sign tx request: {0}")]
    Sign(#[from] alloy::network::TransactionBuilderError<alloy::network::Ethereum>),
    #[error("broadcast transaction: {0}")]
    Broadcast(#[from] tx_submit::TxSubmitError),
    #[error("no tx hash found")]
    MissingHash,
}

const GAS_PRICE_BPS_DENOMINATOR: u128 = 10_000;
pub(crate) const USER_TRANSACT_GAS_PRICE_BUFFER_BPS: u128 = 10_100;
pub(crate) const MAINTENANCE_GAS_PRICE_BUFFER_BPS: u128 = 10_500;
pub(crate) const EVM_GAS_LIMIT_BUFFER: u64 = 100_000;
// Covers intrinsic gas, one authorization and the delegated nonce getter.
pub(crate) const TX7702_DELEGATION_PROBE_GAS_LIMIT: u64 = 100_000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EvmGasPricePolicy {
    pub gas_price_buffer_bps: u128,
    pub min_gas_price: Option<u128>,
    pub max_gas_price: Option<u128>,
}

#[derive(Debug)]
pub(crate) struct PreparedEvmTransaction {
    pub tx_req: TransactionRequest,
    pub gas: u64,
    pub gas_price: u128,
    pub cost: U256,
}

#[derive(Debug, Error)]
pub(crate) enum PrepareEvmTransactionError {
    #[error("fetch gas price failed: {0}")]
    FetchGasPrice(#[source] alloy::transports::RpcError<TransportErrorKind>),
    #[error("gas price {gas_price} exceeds max {max_gas_price}")]
    MaxGasPrice {
        gas_price: u128,
        max_gas_price: u128,
    },
    #[error("fetch nonce failed: {0}")]
    FetchNonce(#[source] alloy::transports::RpcError<TransportErrorKind>),
    #[error("estimate gas failed: {0}")]
    EstimateGas(#[source] alloy::transports::RpcError<TransportErrorKind>),
    #[error("tx7702 simulation failed: {0}")]
    Tx7702Simulation(#[source] alloy::transports::RpcError<TransportErrorKind>),
    #[error("decode tx7702 delegated nonce failed: {0}")]
    Tx7702DelegationDecode(#[source] alloy::sol_types::Error),
    #[error("missing tx7702 field: {field}")]
    MissingTx7702Field { field: &'static str },
    #[error("missing relay_adapt_7702_contract")]
    MissingRelayAdapt7702Contract,
    #[error("tx7702 field {field} value {value} exceeds u128")]
    Tx7702FieldExceedsU128 { field: &'static str, value: U256 },
    #[error("invalid tx7702 authorization: {0}")]
    Tx7702Authorization(#[source] TransactError),
    #[error(
        "tx7702 authorization chain_id {authorization_chain_id} is not 0 or chain_id {chain_id}"
    )]
    Tx7702AuthorizationChainIdMismatch {
        authorization_chain_id: U256,
        chain_id: ChainId,
    },
    #[error(
        "tx7702 authorization address {actual} does not match relay_adapt_7702_contract {expected}"
    )]
    Tx7702AuthorizationAddressMismatch { actual: Address, expected: Address },
    #[error("recover tx7702 authorization authority failed: {0}")]
    Tx7702AuthorizationRecovery(#[source] alloy::eips::eip7702::Eip7702Error),
    #[error("tx7702 authorization authority {actual} does not match request to {expected}")]
    Tx7702AuthorizationAuthorityMismatch { actual: Address, expected: Address },
}

pub(crate) async fn prepare_evm_transaction(
    provider: &(impl Provider + Clone),
    chain_id: ChainId,
    from: Address,
    to: Address,
    input: Bytes,
    policy: EvmGasPricePolicy,
) -> Result<PreparedEvmTransaction, PrepareEvmTransactionError> {
    let mut gas_price = provider
        .get_gas_price()
        .await
        .map_err(PrepareEvmTransactionError::FetchGasPrice)?;
    if let Some(min_gas_price) = policy.min_gas_price {
        gas_price = gas_price.max(min_gas_price);
    }
    gas_price = gas_price * policy.gas_price_buffer_bps / GAS_PRICE_BPS_DENOMINATOR;
    if let Some(max_gas_price) = policy.max_gas_price
        && gas_price > max_gas_price
    {
        return Err(PrepareEvmTransactionError::MaxGasPrice {
            gas_price,
            max_gas_price,
        });
    }

    let nonce = provider
        .get_transaction_count(from)
        .await
        .map_err(PrepareEvmTransactionError::FetchNonce)?;
    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from)
        .with_to(to)
        .with_input(input)
        .with_gas_price(gas_price)
        .with_nonce(nonce);
    let gas = provider
        .estimate_gas(tx_req.clone())
        .await
        .map_err(PrepareEvmTransactionError::EstimateGas)?
        + EVM_GAS_LIMIT_BUFFER;
    let tx_req = tx_req.with_gas_limit(gas);
    let cost = U256::from(gas) * U256::from(gas_price);

    Ok(PreparedEvmTransaction {
        tx_req,
        gas,
        gas_price,
        cost,
    })
}

pub(crate) async fn prepare_evm_tx7702_transaction(
    provider: &(impl Provider + Clone),
    chain_id: ChainId,
    from: Address,
    params: &BroadcasterRawParamsTransact,
    relay_adapt_7702_contract: Option<Address>,
) -> Result<PreparedEvmTransaction, PrepareEvmTransactionError> {
    let relay_adapt_7702_contract = relay_adapt_7702_contract
        .ok_or(PrepareEvmTransactionError::MissingRelayAdapt7702Contract)?;
    let authorization =
        params
            .authorization
            .as_ref()
            .ok_or(PrepareEvmTransactionError::MissingTx7702Field {
                field: "authorization",
            })?;
    let max_fee_per_gas = tx7702_fee_field(params.max_fee_per_gas, "maxFeePerGas")?;
    let max_priority_fee_per_gas =
        tx7702_fee_field(params.max_priority_fee_per_gas, "maxPriorityFeePerGas")?;
    let signed_authorization = verify_tx7702_authorization(
        authorization,
        chain_id,
        relay_adapt_7702_contract,
        params.to,
    )?;

    let nonce = provider
        .get_transaction_count(from)
        .await
        .map_err(PrepareEvmTransactionError::FetchNonce)?;
    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from)
        .with_to(params.to)
        .with_input(params.data.clone())
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
        .with_nonce(nonce)
        .with_authorization_list(vec![signed_authorization]);
    // An RPC that ignores the authorization can report success without executing the delegate.
    // Bound the fee-bearing probe so it cannot inherit an unlimited RPC gas cap.
    let delegation_result = provider
        .call(
            tx_req
                .clone()
                .with_gas_limit(TX7702_DELEGATION_PROBE_GAS_LIMIT)
                .with_input(RelayAdapt7702::nonceCall {}.abi_encode()),
        )
        .pending()
        .await
        .map_err(PrepareEvmTransactionError::Tx7702Simulation)?;
    RelayAdapt7702::nonceCall::abi_decode_returns(&delegation_result)
        .map_err(PrepareEvmTransactionError::Tx7702DelegationDecode)?;
    let gas = provider
        .estimate_gas(tx_req.clone())
        .await
        .map_err(PrepareEvmTransactionError::EstimateGas)?;
    // Validate the raw estimate so the buffer cannot hide an RPC estimation failure.
    provider
        .call(tx_req.clone().with_gas_limit(gas))
        .pending()
        .await
        .map_err(PrepareEvmTransactionError::Tx7702Simulation)?;
    let gas = gas + EVM_GAS_LIMIT_BUFFER;
    let tx_req = tx_req.with_gas_limit(gas);
    let cost = U256::from(gas) * U256::from(max_fee_per_gas);

    Ok(PreparedEvmTransaction {
        tx_req,
        gas,
        gas_price: max_fee_per_gas,
        cost,
    })
}

/// A required TX7702 fee field as `u128`.
fn tx7702_fee_field(
    value: Option<U256>,
    field: &'static str,
) -> Result<u128, PrepareEvmTransactionError> {
    value
        .ok_or(PrepareEvmTransactionError::MissingTx7702Field { field })
        .and_then(|value| {
            u128::try_from(value)
                .map_err(|_| PrepareEvmTransactionError::Tx7702FieldExceedsU128 { field, value })
        })
}

/// Checks that the authorization targets this chain (or any chain) and the
/// configured `RelayAdapt7702`, and that its signer is the request's `to`.
fn verify_tx7702_authorization(
    authorization: &BroadcasterAuthorization,
    chain_id: ChainId,
    relay_adapt_7702_contract: Address,
    to: Address,
) -> Result<SignedAuthorization, PrepareEvmTransactionError> {
    let authorization_chain_id = authorization.chain_id;
    if authorization_chain_id != U256::ZERO && authorization_chain_id != U256::from(chain_id) {
        return Err(
            PrepareEvmTransactionError::Tx7702AuthorizationChainIdMismatch {
                authorization_chain_id,
                chain_id,
            },
        );
    }

    if authorization.address != relay_adapt_7702_contract {
        return Err(
            PrepareEvmTransactionError::Tx7702AuthorizationAddressMismatch {
                actual: authorization.address,
                expected: relay_adapt_7702_contract,
            },
        );
    }

    let signed_authorization = authorization
        .signed_authorization()
        .map_err(PrepareEvmTransactionError::Tx7702Authorization)?;
    let authority = signed_authorization
        .recover_authority()
        .map_err(PrepareEvmTransactionError::Tx7702AuthorizationRecovery)?;
    if authority != to {
        return Err(
            PrepareEvmTransactionError::Tx7702AuthorizationAuthorityMismatch {
                actual: authority,
                expected: to,
            },
        );
    }
    Ok(signed_authorization)
}

pub(crate) async fn prepare_evm_tx7702_with_fallback(
    provider_handle: &mut ProviderHandle,
    query_rpc_pool: &QueryRpcPool,
    chain_id: ChainId,
    from: Address,
    params: &BroadcasterRawParamsTransact,
    relay_adapt_7702_contract: Option<Address>,
) -> Result<PreparedEvmTransaction, PrepareEvmTransactionError> {
    let mut remaining = query_rpc_pool.available_providers();
    remaining.retain(|handle| handle.index != provider_handle.index);
    remaining.shuffle(&mut rand::rng());
    loop {
        let result = prepare_evm_tx7702_transaction(
            &provider_handle.provider,
            chain_id,
            from,
            params,
            relay_adapt_7702_contract,
        )
        .await;
        match result {
            Err(
                error @ (PrepareEvmTransactionError::FetchNonce(_)
                | PrepareEvmTransactionError::EstimateGas(_)
                | PrepareEvmTransactionError::Tx7702Simulation(_)
                | PrepareEvmTransactionError::Tx7702DelegationDecode(_)),
            ) => {
                let Some(next) = remaining.pop() else {
                    return Err(error);
                };
                debug!(%error, rpc_index = provider_handle.index, "retry tx7702 preparation with another query rpc");
                // Invalid or stale requests can also fail simulation; do not cool down the RPC.
                *provider_handle = next;
            }
            result => return result,
        }
    }
}

pub(crate) async fn submit_tx(
    broadcaster: &TxBroadcaster,
    signer: LocalSigner<SigningKey>,
    tx_req: TransactionRequest,
    additional_txs: Option<Vec<Vec<u8>>>,
    queue: Queue,
) -> Result<TxHash, SubmitTxError> {
    let signed_tx = tx_req
        .build(&EthereumWallet::from(signer))
        .await?
        .encoded_2718();
    let tx_hash = broadcaster
        .broadcast(signed_tx, additional_txs, queue)
        .await?;
    tx_hash.ok_or(SubmitTxError::MissingHash)
}
