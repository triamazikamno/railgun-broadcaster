use crate::{pretty_number, submit_tx};
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, ChainId, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::LocalSigner;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use config::AutoRefillSettings;
use railgun_wallet::tx::{TransactionBuilder as RailgunTxBuilder, UnshieldMode, UnshieldRequest};
use railgun_wallet::{ProverService, WalletKeys};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sync_service::{ChainHandle, WalletHandle};
use tracing::{info, warn};
use tx_submit::{Queue, TxBroadcaster};

pub(crate) struct AutoRefillConfig {
    pub chain_id: ChainId,
    pub railgun_contract: Address,
    pub relay_adapt_contract: Address,
    pub wrapped_native_token: Address,
    pub wallet: WalletKeys,
    pub wallet_handle: WalletHandle,
    pub chain_handle: ChainHandle,
    pub auto_refill: AutoRefillSettings,
}

pub(crate) struct AutoRefillService {
    tx_builder: RailgunTxBuilder,
    wallet: WalletKeys,
    wallet_handle: WalletHandle,
    chain_handle: ChainHandle,
    interval: Duration,
    min_amount: U256,
    target_amount: U256,
    max_gas_price: Option<U256>,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    wrapped_native_token: Address,
    query_rpc_pool: Arc<QueryRpcPool>,
    broadcaster: Arc<TxBroadcaster>,
    prover: Arc<ProverService>,
}

impl AutoRefillService {
    pub(crate) fn new(
        cfg: AutoRefillConfig,
        evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
        query_rpc_pool: Arc<QueryRpcPool>,
        broadcaster: Arc<TxBroadcaster>,
        prover: Arc<ProverService>,
    ) -> Self {
        Self {
            tx_builder: RailgunTxBuilder {
                chain_type: 0,
                chain_id: cfg.chain_id,
                railgun_contract: cfg.railgun_contract,
                relay_adapt_contract: cfg.relay_adapt_contract,
            },
            wallet: cfg.wallet,
            wallet_handle: cfg.wallet_handle,
            chain_handle: cfg.chain_handle,
            interval: cfg.auto_refill.interval.into_inner(),
            min_amount: cfg.auto_refill.min_amount,
            target_amount: cfg.auto_refill.target_amount,
            max_gas_price: cfg.auto_refill.max_gas_price,
            evm_wallets,
            wrapped_native_token: cfg.wrapped_native_token,
            query_rpc_pool,
            broadcaster,
            prover,
        }
    }

    pub(crate) async fn run(&self) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.check_and_refill().await;
        }
    }

    async fn check_and_refill(&self) {
        if self.evm_wallets.is_empty() {
            return;
        }
        let Some(provider_handle) = self.query_rpc_pool.random_provider() else {
            warn!("no query rpc available for auto-refill");
            return;
        };

        for (_wallet, signer) in &self.evm_wallets {
            let wallet_address = signer.address();
            let rpc = provider_handle.provider.clone();
            let balance = match rpc.get_balance(wallet_address).await {
                Ok(balance) => balance,
                Err(error) => {
                    warn!(
                        %error,
                        wallet = %wallet_address,
                        rpc = %provider_handle.url,
                        "fetch balance failed",
                    );
                    self.query_rpc_pool.mark_bad_provider(&provider_handle);
                    continue;
                }
            };

            if balance >= self.min_amount {
                continue;
            }
            if balance >= self.target_amount {
                continue;
            }
            let refill_amount = self.target_amount - balance;
            if refill_amount.is_zero() {
                continue;
            }

            let gas_price = match rpc.get_gas_price().await {
                Ok(gas_price) => gas_price * 105 / 100,
                Err(error) => {
                    warn!(
                        %error,
                        wallet = %wallet_address,
                        rpc = %provider_handle.url,
                        "fetch gas price failed",
                    );
                    self.query_rpc_pool.mark_bad_provider(&provider_handle);
                    continue;
                }
            };
            if let Some(max_gas_price) = self.max_gas_price {
                let max_gas_price = max_gas_price.to::<u128>();
                if gas_price > max_gas_price {
                    info!(
                        wallet = %wallet_address,
                        gas_price,
                        max_gas_price,
                        "auto-refill skipped due to gas price",
                    );
                    continue;
                }
            }

            let utxos = self.wallet_handle.unspents.read().await.clone();
            if utxos.is_empty() {
                warn!(wallet = %wallet_address, "no unspent utxos available for auto-refill");
                continue;
            }

            let token_hash = U256::from_be_slice(self.wrapped_native_token.as_slice());
            let mut totals_by_tree: HashMap<u32, U256> = HashMap::new();
            let mut matching = 0usize;
            for utxo in &utxos {
                if utxo.note.token_hash != token_hash {
                    continue;
                }
                matching += 1;
                totals_by_tree
                    .entry(utxo.tree)
                    .and_modify(|total| *total += utxo.note.value)
                    .or_insert(utxo.note.value);
            }
            if matching == 0 {
                warn!(
                    wallet = %wallet_address,
                    token = %self.wrapped_native_token,
                    "no matching utxos for wrapped token",
                );
                continue;
            }
            if let Some((tree, total)) = totals_by_tree
                .iter()
                .max_by_key(|(_, total)| *total)
                .map(|(tree, total)| (*tree, *total))
            {
                info!(
                    wallet = %wallet_address,
                    matching,
                    tree,
                    total = %pretty_number(&total, 18),
                    requested = %pretty_number(&refill_amount, 18),
                    "auto-refill utxo summary",
                );
            }

            let mut forest = self.chain_handle.forest.read().await.clone();
            forest.compute_roots();

            let request = UnshieldRequest {
                token_address: self.wrapped_native_token,
                amount: refill_amount,
                recipient: wallet_address,
                mode: UnshieldMode::UnwrapBase,
                verify_proof: true,
                spend_up_to: true,
            };

            let plan = match self
                .tx_builder
                .build_unshield_plan(&self.wallet, &forest, &utxos, request, &self.prover)
                .await
            {
                Ok(plan) => plan,
                Err(error) => {
                    warn!(
                        %error,
                        wallet = %wallet_address,
                        amount = %pretty_number(&refill_amount, 18),
                        "build unshield plan failed",
                    );
                    continue;
                }
            };

            if plan.unshield_note.value < refill_amount {
                info!(
                    wallet = %wallet_address,
                    requested = %pretty_number(&refill_amount, 18),
                    actual = %pretty_number(&plan.unshield_note.value, 18),
                    inputs = plan.inputs.len(),
                    "auto-refill used spend-up-to",
                );
            }

            let tx_req = TransactionRequest::default()
                .with_chain_id(self.tx_builder.chain_id)
                .with_from(wallet_address)
                .with_to(plan.call.to)
                .with_input(plan.call.data.clone())
                .with_gas_price(gas_price)
                .with_nonce(match rpc.get_transaction_count(wallet_address).await {
                    Ok(nonce) => nonce,
                    Err(error) => {
                        warn!(
                            %error,
                            wallet = %wallet_address,
                            rpc = %provider_handle.url,
                            "fetch nonce failed",
                        );
                        self.query_rpc_pool.mark_bad_provider(&provider_handle);
                        continue;
                    }
                });

            let Ok(gas) = rpc.estimate_gas(tx_req.clone()).await.inspect_err(|error| {
                warn!(
                    %error,
                    wallet = %wallet_address,
                    rpc = %provider_handle.url,
                    "estimate gas failed",
                );
            }) else {
                continue;
            };

            let gas = gas + 100_000;
            let tx_req = tx_req.with_gas_limit(gas);
            let cost = U256::from(gas) * U256::from(gas_price);

            info!(
                wallet = %wallet_address,
                balance = %pretty_number(&balance, 18),
                target = %pretty_number(&self.target_amount, 18),
                amount = %pretty_number(&refill_amount, 18),
                gas,
                gas_price,
                cost = %pretty_number(&cost, 18),
                ?tx_req,
                "auto-refill unshield",
            );

            match submit_tx(
                &self.broadcaster,
                signer.clone(),
                tx_req,
                None,
                Queue::Mempool,
            )
            .await
            {
                Ok(tx_hash) => {
                    info!(wallet = %wallet_address, ?tx_hash, "auto-refill submitted");
                }
                Err(error) => {
                    warn!(wallet = %wallet_address, %error, "auto-refill submit failed");
                }
            }
        }
    }
}
