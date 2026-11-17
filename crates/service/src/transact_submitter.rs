//! The task that prepares, funds and submits queued transact requests and
//! answers each requester over Waku.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, TxHash, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::LocalSigner;
use alloy::transports::TransportErrorKind;
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use broadcaster_core::transact::{
    BroadcasterTransactRequestType, DecryptedTransact, ParsedTransactCalldata,
};
use broadcaster_core::transact_response::DecryptedTransactResponse;
use fees::Manager as FeesManager;
use local_db::DbStore;
use rand::seq::IndexedRandom;
use tracing::{Instrument, error, info, info_span, warn};
use tx_submit::{Queue, TxBroadcaster};
use waku_relay::client::Client;
use waku_relay::msg::ContentTopic;

use crate::evm_tx::{
    EvmGasPricePolicy, PrepareEvmTransactionError, PreparedEvmTransaction,
    USER_TRANSACT_GAS_PRICE_BUFFER_BPS, prepare_evm_transaction, prepare_evm_tx7702_with_fallback,
    submit_tx,
};
use crate::fee_note_store::{FeeNoteAssuranceDbExt, PendingFeeNoteAssuranceRecord};
use crate::fee_note_worker::FeeNoteAssuranceFallback;
use crate::{BroadcasterService, ResponseReceiver, pretty_number};

const ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE: &str =
    "Estimate gas failed, please refresh and try again";

impl BroadcasterService {
    pub fn spawn_tx_submitter(&self) {
        let chain_id = self.chain_id;
        let submitter = TransactSubmitter {
            rx: self.rx.clone(),
            db: self.db.clone(),
            pending_fee_note_assurance_fallback: self.pending_fee_note_assurance_fallback.clone(),
            query_rpc_pool: self.query_rpc_pool.clone(),
            count_transact_requests: self.count_transact_requests.clone(),
            count_txs_landed: self.count_txs_landed.clone(),
            fees_manager: self.fees_manager.clone(),
            chain_id,
            evm_wallets: self.evm_wallets.clone(),
            broadcaster: self.broadcaster.clone(),
            client: self.client.clone(),
            relay_adapt_7702_contract: self.relay_adapt_7702_contract,
            transact_response_topic: ContentTopic::transact_response_topic(chain_id),
        };

        tokio::spawn(submitter.run().instrument(info_span!("tx", chain_id)));
    }
}

/// One chain's submission task. It holds the request receiver but not the
/// sender, so it ends once the service is dropped.
struct TransactSubmitter {
    rx: ResponseReceiver,
    db: Arc<DbStore>,
    pending_fee_note_assurance_fallback: Arc<FeeNoteAssuranceFallback>,
    query_rpc_pool: Arc<QueryRpcPool>,
    count_transact_requests: Arc<AtomicU32>,
    count_txs_landed: Arc<AtomicU32>,
    fees_manager: Arc<FeesManager>,
    chain_id: u64,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    broadcaster: Arc<TxBroadcaster>,
    client: Arc<Client>,
    relay_adapt_7702_contract: Option<Address>,
    transact_response_topic: String,
}

impl TransactSubmitter {
    async fn run(self) {
        while let Ok((decrypted_payload, calldata)) = self
            .rx
            .recv()
            .await
            .inspect_err(|error| warn!(%error, "failed to receive transact request"))
        {
            self.handle(&decrypted_payload, &calldata).await;
        }
    }

    async fn handle(
        &self,
        decrypted_payload: &DecryptedTransact,
        calldata: &ParsedTransactCalldata,
    ) {
        let chain_id = self.chain_id;
        if chain_id != decrypted_payload.params.chain_id {
            warn!(
                request_chain_id = decrypted_payload.params.chain_id,
                expected_chain_id = chain_id,
                "wrong chain_id"
            );
            return;
        }
        if decrypted_payload
            .params
            .fees_id
            .as_ref()
            .is_none_or(|fees_id| !self.fees_manager.is_fees_id_valid(fees_id))
        {
            warn!(
                ?decrypted_payload.params.fees_id,
                "cached fees id not found"
            );
        }

        self.count_transact_requests.fetch_add(1, Ordering::Relaxed);

        let Some((_wallet, signer)) = self.evm_wallets.choose(&mut rand::rng()) else {
            warn!("no wallets available");
            return;
        };

        let Some(mut provider_handle) = self.query_rpc_pool.random_provider() else {
            warn!("no query rpc available");
            return;
        };

        let prepared_tx = match self
            .prepare(decrypted_payload, signer.address(), &mut provider_handle)
            .await
        {
            Ok(prepared_tx) => prepared_tx,
            Err(error) => {
                self.report_prepare_error(&error, &provider_handle, &decrypted_payload.shared_key)
                    .await;
                return;
            }
        };
        self.submit(&decrypted_payload.shared_key, calldata, signer, prepared_tx)
            .await;
    }

    /// Prepares the request's transaction. A TX7702 request can move
    /// `provider_handle` to another query RPC.
    async fn prepare(
        &self,
        decrypted_payload: &DecryptedTransact,
        from: Address,
        provider_handle: &mut ProviderHandle,
    ) -> Result<PreparedEvmTransaction, PrepareEvmTransactionError> {
        let rpc = provider_handle.provider.clone();
        let transact_type = decrypted_payload
            .params
            .transact_type
            .unwrap_or(BroadcasterTransactRequestType::Common);
        match transact_type {
            BroadcasterTransactRequestType::Common => {
                let min_gas_price = decrypted_payload
                    .params
                    .min_gas_price
                    .unwrap_or_default()
                    .to();
                prepare_evm_transaction(
                    &rpc,
                    self.chain_id,
                    from,
                    decrypted_payload.params.to,
                    decrypted_payload.params.data.clone(),
                    EvmGasPricePolicy {
                        gas_price_buffer_bps: USER_TRANSACT_GAS_PRICE_BUFFER_BPS,
                        min_gas_price: Some(min_gas_price),
                        max_gas_price: None,
                    },
                )
                .await
            }
            BroadcasterTransactRequestType::Tx7702 => {
                prepare_evm_tx7702_with_fallback(
                    provider_handle,
                    &self.query_rpc_pool,
                    self.chain_id,
                    from,
                    &decrypted_payload.params,
                    self.relay_adapt_7702_contract,
                )
                .await
            }
        }
    }

    async fn report_prepare_error(
        &self,
        error: &PrepareEvmTransactionError,
        provider_handle: &ProviderHandle,
        shared_key: &[u8; 32],
    ) {
        match error {
            PrepareEvmTransactionError::FetchGasPrice(_) => {
                warn!(%error, rpc = %provider_handle.url, "fetch gas price failed");
                self.query_rpc_pool.mark_bad_provider(provider_handle);
            }
            PrepareEvmTransactionError::FetchNonce(_) => {
                warn!(%error, rpc = %provider_handle.url, "fetch nonce failed");
                self.query_rpc_pool.mark_bad_provider(provider_handle);
            }
            PrepareEvmTransactionError::EstimateGas(source) => {
                let error_message = transact_estimate_gas_error_message(source);
                warn!(%error, rpc = %provider_handle.url, "estimate gas failed");
                self.publish_error_response(shared_key, &error_message)
                    .await;
            }
            PrepareEvmTransactionError::Tx7702Simulation(_)
            | PrepareEvmTransactionError::Tx7702DelegationDecode(_) => {
                warn!(%error, rpc_index = provider_handle.index, "tx7702 simulation failed");
                self.publish_error_response(shared_key, ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE)
                    .await;
            }
            PrepareEvmTransactionError::MaxGasPrice { .. } => {
                warn!(%error, rpc = %provider_handle.url, "gas price rejected");
            }
            PrepareEvmTransactionError::MissingRelayAdapt7702Contract => {
                warn!(%error, rpc = %provider_handle.url, "tx7702 unsupported on this chain");
                self.publish_error_response(
                    shared_key,
                    "Broadcaster is not configured for TX7702 on this chain",
                )
                .await;
            }
            PrepareEvmTransactionError::MissingTx7702Field { .. }
            | PrepareEvmTransactionError::Tx7702FieldExceedsU128 { .. }
            | PrepareEvmTransactionError::Tx7702Authorization(_)
            | PrepareEvmTransactionError::Tx7702AuthorizationChainIdMismatch { .. }
            | PrepareEvmTransactionError::Tx7702AuthorizationAddressMismatch { .. }
            | PrepareEvmTransactionError::Tx7702AuthorizationRecovery(_)
            | PrepareEvmTransactionError::Tx7702AuthorizationAuthorityMismatch { .. } => {
                warn!(%error, rpc = %provider_handle.url, "invalid tx7702 request");
                self.publish_error_response(
                    shared_key,
                    "Invalid TX7702 request, please refresh and try again",
                )
                .await;
            }
        }
    }

    /// Submits a prepared transaction whose fee covers its gas, records its
    /// fee-note assurance and sends the requester the transaction hash.
    async fn submit(
        &self,
        shared_key: &[u8; 32],
        calldata: &ParsedTransactCalldata,
        signer: &LocalSigner<SigningKey>,
        prepared_tx: PreparedEvmTransaction,
    ) {
        let PreparedEvmTransaction {
            tx_req,
            gas,
            gas_price,
            cost,
        } = prepared_tx;
        let refund = self.fees_manager.convert_to_eth(calldata).await;

        info!(
            gas,
            %gas_price,
            cost = pretty_number(&cost, 18),
            refund = pretty_number(&refund, 18),
            "estimated gas"
        );

        let Some(queue) = funded_submission_queue(calldata, cost, refund) else {
            warn!("gas cost is too high, ignoring the transact request...");
            self.publish_error_response(
                shared_key,
                "Gas cost is too high, please refresh and try again",
            )
            .await;
            return;
        };

        let Ok(tx_hash) = submit_tx(&self.broadcaster, signer.clone(), tx_req, None, queue)
            .await
            .inspect_err(|error| error!(%error, "submit tx failed"))
        else {
            return;
        };
        info!(?tx_hash, "submitted tx");
        self.count_txs_landed.fetch_add(1, Ordering::Relaxed);
        self.record_fee_note_assurance(calldata, tx_hash);
        self.publish_tx_hash(shared_key, tx_hash).await;
    }

    /// Persists the submitted transaction's fee-note assurance record, or keeps
    /// it in the in-memory fallback when the database write fails.
    fn record_fee_note_assurance(&self, calldata: &ParsedTransactCalldata, tx_hash: TxHash) {
        let Some(context) = calldata.fee_note_assurance.as_ref() else {
            return;
        };
        let chain_id = self.chain_id;
        let record = PendingFeeNoteAssuranceRecord {
            chain_id,
            public_tx_hash: tx_hash,
            context: context.clone(),
        };
        if let Err(error) = self.db.put_pending_fee_note_assurance(&record) {
            error!(
                ?error,
                chain_id,
                tx_hash = %tx_hash,
                "persist fee-note assurance record failed"
            );
            self.pending_fee_note_assurance_fallback.insert(record);
        }
    }

    async fn publish_tx_hash(&self, shared_key: &[u8; 32], tx_hash: TxHash) {
        if let Ok(transact_response) =
            DecryptedTransactResponse::encrypted_tx_hash_message(None, shared_key, tx_hash)
                .inspect_err(|error| error!(%error, "build transact response failed"))
            && let Err(error) = self
                .client
                .publish(&self.transact_response_topic, &transact_response)
                .await
        {
            error!(%error, "publish transact response failed");
        }
    }

    async fn publish_error_response(&self, shared_key: &[u8; 32], message: &str) {
        publish_transact_error_response(
            &self.client,
            &self.transact_response_topic,
            shared_key,
            message,
        )
        .await;
    }
}

pub(crate) fn funded_submission_queue(
    calldata: &ParsedTransactCalldata,
    cost: U256,
    refund: U256,
) -> Option<Queue> {
    if refund < cost {
        return None;
    }
    Some(if calldata.action_data.is_some() {
        Queue::Mev
    } else {
        Queue::Mempool
    })
}

fn build_transact_error_response(
    shared_key: &[u8; 32],
    message: &str,
) -> Result<Vec<u8>, broadcaster_core::transact_response::ResponseError> {
    DecryptedTransactResponse::encrypted_error_message(None, shared_key, message)
}

fn transact_estimate_gas_error_message(
    error: &alloy::transports::RpcError<TransportErrorKind>,
) -> String {
    let Some(payload) = error.as_error_resp() else {
        return ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE.to_owned();
    };
    if payload.message.is_empty() {
        ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE.to_owned()
    } else {
        format!("Estimate gas failed: {}", payload.message)
    }
}

async fn publish_transact_error_response(
    client: &Client,
    transact_response_topic: &str,
    shared_key: &[u8; 32],
    message: &str,
) {
    let transact_response = match build_transact_error_response(shared_key, message) {
        Ok(transact_response) => transact_response,
        Err(error) => {
            error!(%error, "build error transact response failed");
            return;
        }
    };

    if let Err(error) = client
        .publish(transact_response_topic, &transact_response)
        .await
    {
        error!(%error, "publish error transact response failed");
    }
}

#[cfg(test)]
mod tests;
