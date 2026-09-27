use alloy::primitives::{Address, U256};
use alloy::providers::{CallItem, Provider};
use alloy::sol;
use alloy::sol_types::SolCall;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::ParsedTransactCalldata;
use config::FeeRate;
use rand::RngExt;
use rand::distr::Alphanumeric;
use rand::seq::SliceRandom;
use ruint::uint;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

pub use public_broadcaster_protocol::{Body, Payload, PayloadError};

sol! {
    #[sol(rpc)]
    interface AggregatorInterface {
        function latestAnswer() external view returns (int256);
    }
}

#[derive(Debug, Error)]
pub enum FeesError {
    #[error("provider error")]
    Provider(#[from] alloy::transports::TransportError),
    #[error("multicall error")]
    Multicall(#[from] alloy::providers::MulticallError),
    #[error("invalid price: {value}")]
    InvalidPrice { value: String },
    #[error("no query rpc available")]
    NoQueryRpc,
}

struct OracleInstance {
    token_addr: Address,
    token_decimals: u8,
    is_inversed: bool,
    addr: Address,
}

pub struct Manager {
    prices: RwLock<HashMap<Address, U256>>,
    cache: moka::future::Cache<String, HashMap<Address, U256>>,
    oracle_instances: Vec<OracleInstance>,
    fee_bonus: U256,
    rpcs: Arc<QueryRpcPool>,
    multicall_addr: Address,
    trusted_fees: Arc<tokio::sync::Mutex<HashMap<String, HashMap<Address, U256>>>>,
}

impl Manager {
    pub fn new(
        config: &HashMap<Address, FeeRate>,
        fee_bonus: U256,
        rpcs: Arc<QueryRpcPool>,
        multicall_addr: Address,
        wrapped_native_token: Address,
        fee_id_cache_ttl: Duration,
    ) -> Self {
        let mut oracle_instances = Vec::with_capacity(config.len());
        let mut prices = HashMap::with_capacity(config.len());
        for (token_addr, config) in config.clone() {
            match config {
                FeeRate::Oracle {
                    addr,
                    token_decimals,
                    is_inversed,
                } => {
                    oracle_instances.push(OracleInstance {
                        token_addr,
                        token_decimals,
                        is_inversed,
                        addr,
                    });
                }
                FeeRate::Fixed(val) => {
                    prices.insert(
                        token_addr,
                        val * fee_bonus / uint!(1000000000000000000_U256),
                    );
                }
            }
        }
        prices.entry(wrapped_native_token).or_insert(fee_bonus);
        Self {
            prices: RwLock::new(prices),
            cache: moka::future::Cache::builder()
                .time_to_live(fee_id_cache_ttl)
                .build(),
            oracle_instances,
            fee_bonus,
            multicall_addr,
            rpcs,
            trusted_fees: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub async fn create_fees(&self) -> (String, HashMap<Address, U256>) {
        let mut fees = self.prices.read().await.clone();
        let trusted_fees = self.get_avg_trusted_signer_fees().await;
        for (address, fee) in &mut fees {
            let Some(trusted_fee) = trusted_fees.get(address) else {
                continue;
            };
            let (max_fee, min_fee) = (
                trusted_fee * uint!(129_U256) / uint!(100_U256),
                trusted_fee * uint!(91_U256) / uint!(100_U256),
            );
            if !max_fee.is_zero() && *fee > max_fee {
                *fee = max_fee;
            }
            if *fee < min_fee {
                *fee = min_fee;
            }
        }
        let fees_id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(|c| char::from(c).to_ascii_lowercase())
            .collect();
        self.cache.insert(fees_id.clone(), fees.clone()).await;
        (fees_id, fees)
    }

    #[must_use]
    pub fn is_fees_id_valid(&self, fees_id: &str) -> bool {
        self.cache.contains_key(fees_id)
    }

    pub async fn update_prices(&self) -> Result<(), FeesError> {
        // Snapshot the available providers so each is tried at most once,
        // including when the configured cooldown is zero.
        let mut rpcs = self.rpcs.available_providers();
        rpcs.shuffle(&mut rand::rng());
        let mut last_error = FeesError::NoQueryRpc;
        for rpc in rpcs {
            let mut multicall = rpc
                .provider
                .multicall()
                .dynamic::<AggregatorInterface::latestAnswerCall>()
                .address(self.multicall_addr);
            for oracle in &self.oracle_instances {
                multicall = multicall.add_call_dynamic(CallItem::new(
                    oracle.addr,
                    AggregatorInterface::latestAnswerCall {}.abi_encode().into(),
                ));
            }
            match multicall.try_aggregate(false).await {
                Ok(results) => {
                    for (oracle, res) in self.oracle_instances.iter().zip(results) {
                        match res {
                            Ok(val) => {
                                let price =
                                    U256::try_from(val).map_err(|_| FeesError::InvalidPrice {
                                        value: val.to_string(),
                                    })?;
                                let val = if oracle.is_inversed {
                                    uint!(10_U256).pow(U256::from(oracle.token_decimals))
                                        * self.fee_bonus
                                        / price
                                } else {
                                    price
                                        * uint!(10_U256).pow(U256::from(10 + oracle.token_decimals))
                                        * self.fee_bonus
                                        / uint!(1000000000000000000000000000000000000_U256)
                                };
                                tracing::debug!(?oracle.token_addr, %val, "updating price");
                                self.prices.write().await.insert(oracle.token_addr, val);
                            }
                            Err(error) => {
                                tracing::warn!(
                                    "failed to get price for {}: {error}",
                                    oracle.token_addr
                                );
                            }
                        }
                    }
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(%rpc.url, %error, "failed to get prices");
                    self.rpcs.mark_bad_provider(&rpc);
                    last_error = FeesError::Multicall(error);
                }
            }
        }
        Err(last_error)
    }
    pub async fn handle_trusted_signer_fees(
        &self,
        railgun_address: String,
        fees: HashMap<Address, U256>,
    ) {
        self.trusted_fees.lock().await.insert(railgun_address, fees);
    }
    async fn get_avg_trusted_signer_fees(&self) -> HashMap<Address, U256> {
        let mut total_fees: HashMap<Address, U256> = HashMap::new();
        let mut count: HashMap<Address, usize> = HashMap::new();
        for fees in self.trusted_fees.lock().await.values() {
            for (address, fee) in fees {
                *total_fees.entry(*address).or_insert(U256::ZERO) += fee;
                *count.entry(*address).or_insert(0) += 1;
            }
        }
        total_fees
            .iter()
            .map(|(address, total)| (*address, total / U256::from(count[address])))
            .collect()
    }
    pub async fn convert_to_eth(&self, calldata: &ParsedTransactCalldata) -> U256 {
        tracing::info!(token=?calldata.fee_token, amount=%calldata.fee_amount, "converting value to gas token");
        self.prices
            .read()
            .await
            .get(&calldata.fee_token)
            .filter(|price| !price.is_zero())
            .map_or(U256::ZERO, |price| {
                calldata.fee_amount * self.fee_bonus / price
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Bytes;
    use alloy::sol_types::SolValue;
    use axum::{Json, Router, extract::Path, routing::post};
    use serde_json::{Value, json};
    use std::sync::Mutex;

    async fn price_rpc_pool(
        second_response: Value,
    ) -> (
        Arc<QueryRpcPool>,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = requests.clone();
        let app = Router::new().route(
            "/{provider}",
            post(
                move |Path(provider): Path<String>, Json(request): Json<Value>| {
                    let requests = captured_requests.clone();
                    let second_response = second_response.clone();
                    async move {
                        assert_eq!(request["method"], "eth_call");
                        let mut requests = requests.lock().unwrap();
                        requests.push(provider);
                        let mut response = if requests.len() == 1 {
                            price_rpc_error()
                        } else {
                            second_response
                        };
                        response["jsonrpc"] = json!("2.0");
                        response["id"] = request["id"].clone();
                        Json(response)
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let pool = Arc::new(QueryRpcPool::new(
            ["a", "b"]
                .map(|name| format!("http://{addr}/{name}").parse().unwrap())
                .to_vec(),
            Duration::from_mins(1),
        ));
        (pool, requests, server)
    }

    fn price_rpc_error() -> Value {
        json!({"error": {"code": -32602, "message": "request is too complex/large, try lesser input"}})
    }

    fn oracle_manager(pool: Arc<QueryRpcPool>) -> Manager {
        Manager::new(
            &HashMap::from([(
                Address::repeat_byte(1),
                FeeRate::Oracle {
                    addr: Address::repeat_byte(2),
                    token_decimals: 18,
                    is_inversed: false,
                },
            )]),
            uint!(1000000000000000000_U256),
            pool,
            Address::repeat_byte(3),
            Address::ZERO,
            Duration::from_mins(1),
        )
    }

    #[tokio::test]
    async fn price_refresh_falls_back_after_rpc_rejection() {
        let result = vec![(true, Bytes::from(U256::from(200_000_000).abi_encode()))].abi_encode();
        let (pool, requests, server) = price_rpc_pool(json!({"result": Bytes::from(result)})).await;
        let manager = oracle_manager(pool.clone());

        let refresh = manager.update_prices().await;
        server.abort();
        refresh.expect("price refresh should use the other RPC");

        let (_, fees) = manager.create_fees().await;
        assert_eq!(
            fees[&Address::repeat_byte(1)],
            uint!(2000000000000000000_U256)
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0], requests[1]);
        assert_eq!(pool.available_providers().len(), 1);
    }

    #[tokio::test]
    async fn price_refresh_returns_error_when_all_rpcs_fail() {
        let (pool, requests, server) = price_rpc_pool(price_rpc_error()).await;
        let manager = oracle_manager(pool.clone());

        let refresh = manager.update_prices().await;
        server.abort();
        assert!(matches!(refresh, Err(FeesError::Multicall(_))));

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0], requests[1]);
        assert!(pool.available_providers().is_empty());
    }

    #[tokio::test]
    async fn fee_id_cache_uses_configured_ttl() {
        let manager = Manager::new(
            &HashMap::new(),
            uint!(1_U256),
            Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1))),
            Address::ZERO,
            Address::ZERO,
            Duration::from_millis(10),
        );

        let (fees_id, _) = manager.create_fees().await;
        assert!(manager.is_fees_id_valid(&fees_id));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!manager.is_fees_id_valid(&fees_id));
    }
}
