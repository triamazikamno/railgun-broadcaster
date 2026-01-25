use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::sol;
use broadcaster_core::crypto::railgun;
use broadcaster_core::serde_helpers;
use broadcaster_core::transact::ParsedTransactCalldata;
use config::FeeRate;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use rand::distr::Alphanumeric;
use ruint::uint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("serialize payload")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid signature length: {len}")]
    InvalidSignatureLen { len: usize },
    #[error("invalid viewing key: {message}")]
    PublicKey { message: String },
    #[error("signature error")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("invalid signature bytes")]
    SignatureBytes(#[from] std::array::TryFromSliceError),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    #[serde(with = "serde_helpers::hex_string")]
    pub data: Vec<u8>,
    #[serde(with = "serde_helpers::hex_string")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    // #[serde(with = "serde_helpers::decimal_map")]
    pub fees: HashMap<Address, U256>,
    pub fee_expiration: u64,
    #[serde(rename = "feesID")]
    pub fees_id: String,
    pub railgun_address: railgun::Address,
    pub available_wallets: u32,
    pub version: String,
    #[serde(with = "serde_helpers::checksum_address")]
    pub relay_adapt: Address,
    #[serde(rename = "requiredPOIListKeys")]
    pub required_poi_list_keys: Vec<String>,
    pub reliability: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

impl Body {
    pub fn into_signed_payload(
        self,
        viewing_priv_seed_32: [u8; 32],
    ) -> Result<Payload, PayloadError> {
        let data = serde_json::to_string(&self)?.into_bytes();
        let sk = SigningKey::from_bytes(&viewing_priv_seed_32);
        let signature = sk.sign(&data);
        Ok(Payload {
            data,
            signature: signature.to_bytes().into(),
        })
    }
}

impl Payload {
    pub fn decode_and_verify(&self) -> Result<(Body, bool), PayloadError> {
        if self.signature.len() != 64 {
            return Err(PayloadError::InvalidSignatureLen {
                len: self.signature.len(),
            });
        }
        let decoded_data: Body = serde_json::from_slice(self.data.as_ref())?;
        let viewing_pk =
            railgun::PublicKey::try_from(&decoded_data.railgun_address).map_err(|error| {
                PayloadError::PublicKey {
                    message: error.to_string(),
                }
            })?;

        let vk = VerifyingKey::from_bytes(&viewing_pk)?;
        let sig = Signature::from_bytes(self.signature.as_slice().try_into()?);

        Ok((decoded_data, vk.verify(self.data.as_ref(), &sig).is_ok()))
    }
}

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
}

struct OracleInstance<P: Provider> {
    token_addr: Address,
    token_decimals: u8,
    is_inversed: bool,
    instance: AggregatorInterface::AggregatorInterfaceInstance<P>,
}

pub struct Manager<P: Provider> {
    prices: RwLock<HashMap<Address, U256>>,
    cache: moka::future::Cache<String, HashMap<Address, U256>>,
    oracle_instances: Vec<OracleInstance<P>>,
    fee_bonus: U256,
    rpc: P,
    multicall_addr: Address,
}

impl<P: Provider + Clone> Manager<P> {
    pub fn new(
        config: &HashMap<Address, FeeRate>,
        fee_bonus: U256,
        rpc: P,
        multicall_addr: Address,
    ) -> Self {
        let mut oracle_instances = Vec::new();
        let mut prices = HashMap::new();
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
                        instance: AggregatorInterface::AggregatorInterfaceInstance::new(
                            addr,
                            rpc.clone(),
                        ),
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
        Self {
            prices: RwLock::new(prices),
            cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(180))
                .build(),
            oracle_instances,
            fee_bonus,
            multicall_addr,
            rpc,
        }
    }

    pub async fn create_fees(&self) -> (String, HashMap<Address, U256>) {
        let fees = self.prices.read().await.clone();
        let fees_id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(|c| char::from(c).to_ascii_lowercase())
            .collect();
        self.cache.insert(fees_id.clone(), fees.clone()).await;
        (fees_id, fees)
    }

    pub fn is_fees_id_valid(&self, fees_id: &str) -> bool {
        self.cache.contains_key(fees_id)
    }

    pub async fn update_prices(&self) -> Result<(), FeesError> {
        let mut multicall = self.rpc.multicall().dynamic().address(self.multicall_addr);
        for oracle in &self.oracle_instances {
            multicall = multicall.add_dynamic(oracle.instance.latestAnswer());
        }
        let results = multicall.try_aggregate(false).await?;
        for (oracle, res) in self.oracle_instances.iter().zip(results) {
            match res {
                Ok(val) => {
                    let price = U256::try_from(val).map_err(|_| FeesError::InvalidPrice {
                        value: val.to_string(),
                    })?;
                    let val = if oracle.is_inversed {
                        uint!(10_U256).pow(U256::from(oracle.token_decimals)) * self.fee_bonus
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
                    tracing::warn!("failed to get price for {}: {error}", oracle.token_addr);
                }
            }
        }
        Ok(())
    }

    pub async fn convert_to_eth(&self, calldata: &ParsedTransactCalldata) -> U256 {
        tracing::info!(token=?calldata.fee_token, amount=%calldata.fee_amount, "converting value to gas token");
        self.prices
            .read()
            .await
            .get(&calldata.fee_token)
            .filter(|price| !price.is_zero())
            .map_or(calldata.fee_amount, |price| {
                calldata.fee_amount * self.fee_bonus / price
            })
    }
}
