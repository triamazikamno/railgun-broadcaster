use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, U256};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub nwaku_url: Option<String>,
    pub chains: Vec<Chain>,
    pub required_poi_list: Vec<FixedBytes<32>>,
    pub poi_rpc: Option<Url>,
    pub additional_waku_peers: Vec<AdditionalWakuPeer>,
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
    pub viewing_privkey: Bytes,
    pub chain_id: ChainId,
    pub fee_bonus: f32,
    pub fees_ttl: humantime_serde::Serde<Duration>,
    pub fees_refresh_interval: humantime_serde::Serde<Duration>,
    pub fees: HashMap<Address, FeeRate>,
    pub query_rpc: Url,
    pub submit_rpcs: Vec<Rpc>,
    pub multicall_contract: Option<Address>,
    pub relay_adapt_contract: Address,
    pub evm_wallets: Vec<Bytes>,
    pub identifier: Option<String>,
}

#[derive(Deserialize, Clone)]
pub enum FeeRate {
    Oracle {
        addr: Address,
        token_decimals: u8,
        #[serde(default)]
        is_inversed: bool,
    },
    Fixed(U256),
}

#[derive(Deserialize, Clone)]
pub enum Rpc {
    Flashbots { url: Url, num_blocks: u64 },
    Normal(Url),
    Private { url: Url, has_mev: bool },
    BloxrouteBackrunme { url: Url, api_key: String },
}
