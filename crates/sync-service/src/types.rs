use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy_rpc_types_eth::Log;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use merkletree::wallet::WalletScanKeys;
use tokio::sync::mpsc;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainKey {
    pub chain_id: u64,
    pub contract: Address,
}

#[derive(Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub contract: Address,
    pub rpcs: Arc<QueryRpcPool>,
    pub archive_rpc_url: Option<Url>,
    pub archive_until_block: u64,
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    pub block_range: u64,
    pub poll_interval: Duration,
    pub finality_depth: u64,
    pub quick_sync_endpoint: Option<Url>,
    pub anchor_interval: u64,
    pub anchor_retention: usize,
}

#[derive(Debug, Clone)]
pub struct ChainConfigDefaults {
    pub chain_id: u64,
    pub contract: Address,
    pub rpc_url: Url,
    pub quick_sync_endpoint: Option<Url>,
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    pub archive_until_block: u64,
    pub finality_depth: u64,
    pub anchor_interval: u64,
    pub anchor_retention: usize,
}

impl ChainConfigDefaults {
    pub fn for_chain(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self {
                chain_id,
                contract: Address::from_str("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")
                    .expect("valid railgun contract"),
                rpc_url: Url::parse("https://eth.llamarpc.com").expect("valid ethereum rpc url"),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql")
                        .expect("valid ethereum quick sync endpoint"),
                ),
                deployment_block: 14_737_691,
                v2_start_block: 16_076_750,
                legacy_shield_block: 16_790_263,
                archive_until_block: 15_537_393,
                finality_depth: 12,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            56 => Some(Self {
                chain_id,
                contract: Address::from_str("0x590162bf4b50f6576a459b75309ee21d92178a10")
                    .expect("valid railgun contract"),
                rpc_url: Url::parse("https://bsc.publicnode.com").expect("valid bsc rpc url"),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql")
                        .expect("valid bsc quick sync endpoint"),
                ),
                deployment_block: 17_633_701,
                v2_start_block: 23_478_204,
                legacy_shield_block: 26_313_947,
                archive_until_block: 0,
                finality_depth: 15,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            137 => Some(Self {
                chain_id,
                contract: Address::from_str("0x19b620929f97b7b990801496c3b361ca5def8c71")
                    .expect("valid railgun contract"),
                rpc_url: Url::parse("https://rpc-mainnet.matic.quiknode.pro")
                    .expect("valid polygon rpc url"),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql")
                        .expect("valid polygon quick sync endpoint"),
                ),
                deployment_block: 28_083_766,
                v2_start_block: 36_219_104,
                legacy_shield_block: 40_143_539,
                archive_until_block: 0,
                finality_depth: 256,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            42161 => Some(Self {
                chain_id,
                contract: Address::from_str("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9")
                    .expect("valid railgun contract"),
                rpc_url: Url::parse("https://rpc.ankr.com/arbitrum")
                    .expect("valid arbitrum rpc url"),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql")
                        .expect("valid arbitrum quick sync endpoint"),
                ),
                deployment_block: 56_109_834,
                v2_start_block: 0,
                legacy_shield_block: 68_196_853,
                archive_until_block: 0,
                finality_depth: 64,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalletConfig {
    pub chain: ChainKey,
    pub cache_key: String,
    pub start_block: Option<u64>,
    pub scan_keys: WalletScanKeys,
}

#[derive(Debug, Clone)]
pub struct LogBatch {
    pub from_block: u64,
    pub to_block: u64,
    pub logs: Vec<Log>,
    pub to_block_hash: Option<[u8; 32]>,
}

pub type SharedLogBatch = Arc<LogBatch>;

#[derive(Debug, Clone)]
pub enum BackfillEvent {
    Logs(SharedLogBatch),
    Done { last_block: u64 },
    Reset { from_block: u64 },
}

#[derive(Debug)]
pub enum BackfillRequest {
    Add {
        cache_key: String,
        from_block: u64,
        to_block: u64,
        sender: mpsc::Sender<BackfillEvent>,
    },
    Reset {
        cache_key: String,
        from_block: u64,
    },
    Remove {
        cache_key: String,
    },
}
