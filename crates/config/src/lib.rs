use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, U256};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

mod serde_helpers;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chains: Vec<Chain>,
    pub query_rpc_cooldown: humantime_serde::Serde<Duration>,
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
    pub fee_bonus: f32,
    pub fees_ttl: humantime_serde::Serde<Duration>,
    pub fees_refresh_interval: humantime_serde::Serde<Duration>,
    pub fees: HashMap<Address, FeeRate>,
    pub query_rpcs: Vec<Url>,
    pub wrapped_native_token: Address,
    pub submit_rpcs: Vec<Rpc>,
    pub multicall_contract: Option<Address>,
    pub relay_adapt_contract: Address,
    pub evm_wallets: Vec<Bytes>,
    pub identifier: Option<String>,
    pub sync: Option<SyncChainConfig>,
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
