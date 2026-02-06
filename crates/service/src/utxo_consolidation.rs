use crate::submit_tx;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, ChainId, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::LocalSigner;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use config::UtxoConsolidationSettings;
use railgun_wallet::tx::TransactionBuilder as RailgunTxBuilder;
use railgun_wallet::{ProverService, WalletKeys};
use rand::seq::IndexedRandom;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sync_service::{ChainHandle, WalletHandle};
use tracing::{debug, info, warn};
use tx_submit::{Queue, TxBroadcaster};

pub(crate) struct UtxoConsolidationConfig {
    pub chain_id: ChainId,
    pub railgun_contract: Address,
    pub relay_adapt_contract: Address,
    pub wallet: WalletKeys,
    pub wallet_handle: WalletHandle,
    pub chain_handle: ChainHandle,
    pub settings: UtxoConsolidationSettings,
}

pub(crate) struct UtxoConsolidationService {
    tx_builder: RailgunTxBuilder,
    wallet: WalletKeys,
    wallet_handle: WalletHandle,
    chain_handle: ChainHandle,
    interval: Duration,
    min_utxos: usize,
    max_gas_price: Option<U256>,
    tokens: Vec<Address>,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    query_rpc_pool: Arc<QueryRpcPool>,
    broadcaster: Arc<TxBroadcaster>,
    prover: Arc<ProverService>,
}

impl UtxoConsolidationService {
    pub(crate) fn new(
        cfg: UtxoConsolidationConfig,
        evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
        query_rpc_pool: Arc<QueryRpcPool>,
        broadcaster: Arc<TxBroadcaster>,
        prover: Arc<ProverService>,
    ) -> Self {
        let settings = cfg.settings;
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
            interval: settings.interval.into_inner(),
            min_utxos: settings.min_utxos,
            max_gas_price: settings.max_gas_price,
            tokens: settings.tokens,
            evm_wallets,
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
            self.check_and_consolidate().await;
        }
    }

    async fn check_and_consolidate(&self) {
        if self.evm_wallets.is_empty() {
            warn!("no evm wallets available for utxo consolidation");
            return;
        }
        if self.tokens.is_empty() {
            warn!("no tokens configured for utxo consolidation");
            return;
        }
        if self.min_utxos == 0 {
            warn!(
                min_utxos = self.min_utxos,
                "utxo consolidation disabled due to min_utxos"
            );
            return;
        }
        let max_inputs = 13;

        let Some(provider_handle) = self.query_rpc_pool.random_provider() else {
            warn!("no query rpc available for utxo consolidation");
            return;
        };
        let rpc = provider_handle.provider.clone();

        let gas_price = match rpc.get_gas_price().await {
            Ok(gas_price) => gas_price * 105 / 100,
            Err(error) => {
                warn!(
                    %error,
                    rpc = %provider_handle.url,
                    "fetch gas price failed",
                );
                self.query_rpc_pool.mark_bad_provider(&provider_handle);
                return;
            }
        };
        if let Some(max_gas_price) = self.max_gas_price {
            let max_gas_price = max_gas_price.to::<u128>();
            if gas_price > max_gas_price {
                debug!(
                    gas_price,
                    max_gas_price, "utxo consolidation skipped due to gas price"
                );
                return;
            }
        }

        let utxos = self.wallet_handle.unspents.read().await.clone();
        if utxos.is_empty() {
            warn!("no unspent utxos available for utxo consolidation");
            return;
        }

        let Some((_wallet, signer)) = self.evm_wallets.choose(&mut rand::rng()) else {
            warn!("no wallets available for utxo consolidation");
            return;
        };
        let signer = signer.clone();

        let mut forest = self.chain_handle.forest.read().await.clone();
        forest.compute_roots();

        for token in &self.tokens {
            let token_hash = U256::from_be_slice(token.as_slice());
            let mut by_tree: HashMap<u32, Vec<_>> = HashMap::new();
            for utxo in &utxos {
                if utxo.note.token_hash != token_hash {
                    continue;
                }
                by_tree.entry(utxo.tree).or_default().push(utxo.clone());
            }

            let mut best: Option<(u32, Vec<_>, U256)> = None;
            for (tree, candidates) in by_tree {
                let total = candidates
                    .iter()
                    .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value);
                let replace = match best.as_ref() {
                    None => true,
                    Some((_, best_candidates, best_total)) => {
                        candidates.len() > best_candidates.len()
                            || (candidates.len() == best_candidates.len() && total > *best_total)
                    }
                };
                if replace {
                    best = Some((tree, candidates, total));
                }
            }

            let Some((tree, mut candidates, candidate_total)) = best else {
                continue;
            };
            let candidate_count = candidates.len();
            if candidate_count < self.min_utxos {
                debug!(
                    token = %token,
                    tree,
                    candidate_count,
                    min_utxos = self.min_utxos,
                    %candidate_total,
                    total_utxos=utxos.len(),
                    "utxo consolidation skipped due to min_utxos"
                );
                continue;
            }

            candidates.sort_by(|a, b| a.note.value.cmp(&b.note.value));
            if candidates.len() > max_inputs {
                candidates.truncate(max_inputs);
            }

            let total = candidates
                .iter()
                .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value);
            let plan = match self
                .tx_builder
                .build_transact_plan(&self.wallet, &forest, &candidates, *token, &self.prover)
                .await
            {
                Ok(plan) => plan,
                Err(error) => {
                    warn!(
                        %error,
                        token = %token,
                        tree,
                        inputs = candidates.len(),
                        "build transact plan failed",
                    );
                    continue;
                }
            };

            let tx_req = TransactionRequest::default()
                .with_chain_id(self.tx_builder.chain_id)
                .with_from(signer.address())
                .with_to(plan.call.to)
                .with_input(plan.call.data.clone())
                .with_gas_price(gas_price)
                .with_nonce(match rpc.get_transaction_count(signer.address()).await {
                    Ok(nonce) => nonce,
                    Err(error) => {
                        warn!(
                            %error,
                            rpc = %provider_handle.url,
                            "fetch nonce failed",
                        );
                        self.query_rpc_pool.mark_bad_provider(&provider_handle);
                        return;
                    }
                });

            let Ok(gas) = rpc.estimate_gas(tx_req.clone()).await.inspect_err(|error| {
                warn!(
                    %error,
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
                token = %token,
                tree,
                inputs = candidates.len(),
                total = %total,
                gas,
                gas_price,
                cost = %cost,
                total_utxos=utxos.len(),
                "utxo consolidation transact",
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
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    info!(token = %token, ?tx_hash, "utxo consolidation submitted");
                }
                Err(error) => {
                    warn!(token = %token, %error, "utxo consolidation submit failed");
                }
            }
        }
    }
}
