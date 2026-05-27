use crate::txid_cache::{TxidPublicCacheKey, sync_txid_public_cache_to_graph_tip};
use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, LogBatch, SharedLogBatch, SyncProgressSender,
    SyncProgressStage, SyncProgressUpdate, WalletConfig,
};
use crate::wallet::{
    WalletHandle, WalletPendingOverlay, WalletWorkerServices, apply_wallet_delta_to_vec,
    pending_overlay_from_delta, process_pending_output_poi_observations, spawn_wallet_worker,
    wallet_cache_store,
};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, FixedBytes};
use alloy::sol_types::SolEvent;
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{Filter, Log};
use alloy_transport::TransportError;
use async_trait::async_trait;
use broadcaster_core::provider::build_provider;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::DbStore;
use merkletree::errors::SyncError;
use merkletree::persist::{MerkleForestSnapshot, PersistError, SNAPSHOT_VERSION};
use merkletree::quick::{
    DEFAULT_PAGE_SIZE, IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment,
    IndexedNullifier, IndexedShieldCommitment, IndexedTransactCommitment, QuickSyncClient,
    QuickSyncConfig, run_quick_sync_into_with_progress,
};
use merkletree::slow::CommitmentUpdateError;
use merkletree::slow::types::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, Shield, ShieldLegacyPreMar23,
    Transact,
};
use merkletree::tree::MerkleForest;
use railgun_wallet::UtxoSource;
use railgun_wallet::scan::{
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput,
    WalletLogDelta, WalletScanError, parse_indexed_wallet_delta, parse_wallet_delta_from_logs,
};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

mod backfill;
mod forest_db;
mod indexed_wallet;
mod logs;
mod service;
mod types;
mod workers;

use backfill::*;
use forest_db::*;
use indexed_wallet::*;
use logs::*;
use types::*;
use workers::*;

pub use types::{ChainError, ChainHandle, ChainService};

#[cfg(test)]
mod tests;
