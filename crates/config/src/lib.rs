use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, U256};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

mod serde_helpers;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chains: Vec<Chain>,
    pub query_rpc_cooldown: humantime_serde::Serde<Duration>,
    pub trusted_signers: HashSet<String>,
    pub required_poi_list: Vec<FixedBytes<32>>,
    pub poi_rpc: Option<Url>,
    pub waku: Waku,
    pub admin: Option<AdminConfig>,
    pub artifacts_metadata_dir: Option<PathBuf>,
    pub artifacts_cache_dir: Option<PathBuf>,
    pub db_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waku {
    pub nwaku_url: Option<String>,
    pub shard_id: Option<u32>,
    #[serde(default)]
    pub direct_peers: Vec<AdditionalWakuPeer>,
    pub dns_enr_trees: Option<Vec<String>>,
    pub doh_endpoint: Option<String>,
    pub cluster_id: Option<u32>,
    pub max_peers: Option<usize>,
    pub peer_connection_timeout: Option<humantime_serde::Serde<Duration>>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub listen_addr: String,
    pub token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdditionalWakuPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub key: Key,
    pub chain_id: ChainId,
    pub fee_bonus: FeeBonusBps,
    pub fees_ttl: humantime_serde::Serde<Duration>,
    pub fees_refresh_interval: humantime_serde::Serde<Duration>,
    pub fees: HashMap<Address, FeeRate>,
    pub query_rpcs: Vec<Url>,
    pub wrapped_native_token: Address,
    pub submit_rpcs: Vec<Rpc>,
    pub multicall_contract: Option<Address>,
    pub relay_adapt_contract: Address,
    pub relay_adapt_7702_contract: Option<Address>,
    pub evm_wallets: Vec<Bytes>,
    pub identifier: Option<String>,
    pub sync: Option<SyncChainConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBonusBps(u32);

impl FeeBonusBps {
    #[must_use]
    pub const fn bps(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FeeBonusBps {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FeeBonusBpsVisitor)
    }
}

struct FeeBonusBpsVisitor;

impl Visitor<'_> for FeeBonusBpsVisitor {
    type Value = FeeBonusBps;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-negative fee bonus percent")
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < 0 {
            return Err(E::custom("fee_bonus must be non-negative"));
        }
        let value = u64::try_from(value).map_err(|_| E::custom("fee_bonus out of range"))?;
        self.visit_u64(value)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bps = value
            .checked_mul(100)
            .and_then(|bps| u32::try_from(bps).ok())
            .ok_or_else(|| E::custom("fee_bonus out of range"))?;
        Ok(FeeBonusBps(bps))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("fee_bonus must be finite"));
        }
        if value < 0.0 {
            return Err(E::custom("fee_bonus must be non-negative"));
        }
        let scaled = value * 100.0;
        if scaled > f64::from(u32::MAX) {
            return Err(E::custom("fee_bonus out of range"));
        }

        let nearest_bps = scaled.round();
        let bps = if (scaled - nearest_bps).abs() <= f64::EPSILON * scaled.abs().max(1.0) * 4.0 {
            nearest_bps
        } else {
            scaled.trunc()
        };
        #[allow(clippy::cast_sign_loss)]
        Ok(FeeBonusBps(bps as u32))
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Key {
    ViewingPrivkey(Bytes),
    Mnemonic(Box<MnemonicSettings>),
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MnemonicSettings {
    pub seed_phrase: String,
    pub init_block_number: u64,
    #[serde(default)]
    pub num_derived_evm_wallets: usize,
    pub auto_refill: Option<AutoRefillSettings>,
    pub utxo_consolidation: Option<UtxoConsolidationSettings>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AutoRefillSettings {
    #[serde(
        default,
        deserialize_with = "serde_helpers::ether_value::deserialize_opt"
    )]
    pub max_gas_price: Option<U256>,
    pub interval: humantime_serde::Serde<Duration>,
    #[serde(deserialize_with = "serde_helpers::ether_value::deserialize")]
    pub target_amount: U256,
    #[serde(deserialize_with = "serde_helpers::ether_value::deserialize")]
    pub min_amount: U256,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UtxoConsolidationSettings {
    #[serde(
        default,
        deserialize_with = "serde_helpers::ether_value::deserialize_opt"
    )]
    pub max_gas_price: Option<U256>,
    pub interval: humantime_serde::Serde<Duration>,
    pub min_utxos: usize,
    pub tokens: Vec<Address>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SyncChainConfig {
    pub railgun_contract: Option<Address>,
    pub rpc_url: Option<Url>,
    pub archive_rpc_url: Option<Url>,
    pub archive_until_block: Option<u64>,
    pub deployment_block: Option<u64>,
    pub v2_start_block: Option<u64>,
    pub legacy_shield_block: Option<u64>,
    pub finality_depth: Option<u64>,
    pub quick_sync_endpoint: Option<Url>,
    #[serde(default)]
    pub disable_quick_sync: bool,
    pub anchor_interval: Option<u64>,
    pub anchor_retention: Option<usize>,
    pub poll_interval: Option<humantime_serde::Serde<Duration>>,
    pub block_range: Option<u64>,
    pub indexed_wallet_block_range: Option<u64>,
}

#[derive(Deserialize, Clone)]
pub enum FeeRate {
    Oracle {
        addr: Address,
        token_decimals: u8,
        #[serde(default)]
        is_inversed: bool,
    },
    Fixed(#[serde(deserialize_with = "serde_helpers::ether_value::deserialize")] U256),
}

#[derive(Deserialize, Clone)]
pub enum Rpc {
    Flashbots { url: Url, num_blocks: u64 },
    Normal(Url),
    Private { url: Url, has_mev: bool },
    BloxrouteBackrunme { url: Url, api_key: String },
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::FeeBonusBps;

    #[derive(Debug, Deserialize)]
    struct FeeBonusFixture {
        fee_bonus: FeeBonusBps,
    }

    fn parse_fee_bonus(value: &serde_json::Value) -> FeeBonusBps {
        serde_json::from_value::<FeeBonusFixture>(serde_json::json!({ "fee_bonus": value }))
            .expect("fee bonus should parse")
            .fee_bonus
    }

    #[test]
    fn fee_bonus_whole_percent_deserializes_to_basis_points() {
        assert_eq!(parse_fee_bonus(&serde_json::json!(5)).bps(), 500);
    }

    #[test]
    fn fee_bonus_two_decimal_percent_deserializes_to_basis_points() {
        assert_eq!(parse_fee_bonus(&serde_json::json!(2.34)).bps(), 234);
    }

    #[test]
    fn fee_bonus_two_decimal_underflow_does_not_round_down() {
        assert_eq!(parse_fee_bonus(&serde_json::json!(0.29)).bps(), 29);
    }

    #[test]
    fn fee_bonus_extra_decimal_precision_is_truncated() {
        assert_eq!(parse_fee_bonus(&serde_json::json!(2.349)).bps(), 234);
    }

    #[test]
    fn fee_bonus_rejects_negative_percent() {
        let error = serde_json::from_value::<FeeBonusFixture>(serde_json::json!({
            "fee_bonus": -1,
        }))
        .unwrap_err();

        assert!(error.to_string().contains("non-negative"));
    }
}
