use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Bytes, FixedBytes, U64, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{Transaction, relayCall, transactCall};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::{TREE_LEAF_COUNT, normalize_tree_position};
use merkletree::quick::{GraphPostError, post_graphql_data};
use merkletree::tree::{DenseMerkleTree, MerkleForest};
use railgun_wallet::prover::ProverError;
use railgun_wallet::tx::{
    InputWitness, PoiMerkleProofSource, PostTransactionPoiData,
    PostTransactionPoiGenerationRequest, PreTransactionPoiError, PreTransactionPoiMap,
    PrivateInputs, PublicInputs, TransactionPlanChunk, generate_post_transaction_pois,
};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::{
    DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
};
use poi::artifacts::{SnapshotEvent, verify_poi_event};
use poi::cache::{POI_EVENTS_PAGE_SIZE, PoiCache, PoiCacheError, PoiCacheIdentity};
use poi::error::{PoiError, PoiRpcError};
use poi::poi::{
    BlindedCommitmentData, BlindedCommitmentType, DEFAULT_WALLET_POI_RPC_URL, PoiMerkleProof,
    PoiRpcClient, PoiSyncedListEvent, SingleCommitmentProofContext, ValidatedRailgunTxidStatus,
    default_active_poi_list_keys,
};
use railgun_wallet::scan::{
    CommitmentObservation, WalletLogDelta, WalletScanError, parse_wallet_delta_from_logs,
};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{
    PoiStatus, RailgunSpendSigner, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource,
    WalletUtxo,
};
use url::Url;

use crate::poi_artifacts::{PersistedPoiArtifactCache, PoiArtifactIngestor, load_persisted_cache};
use crate::txid_cache::{
    TxidPublicCacheError, TxidPublicCacheKey, TxidPublicCacheTransaction,
    TxidPublicCachedTransaction, TxidPublicLatestValidated, sync_txid_public_cache,
    sync_txid_public_cache_until_recovered_output, txid_public_cached_latest_validated,
    txid_public_proof_for_recovered_output, txid_public_proof_for_recovered_output_at_index,
    txid_public_transaction_for_recovered_output,
};
use crate::types::{
    BackfillEvent, PoiReadSource, SharedLogBatch, WalletCacheStore, WalletConfig,
    WalletLocalPoiCaches,
};

mod delta;
mod handle;
mod local_poi_cache;
mod output_poi_recovery;
mod pending_output_poi;
mod persist;
mod poi_refresh;
mod poi_sources;
mod worker;

use delta::*;
use handle::*;
use local_poi_cache::*;
use output_poi_recovery::*;
use pending_output_poi::*;
use persist::*;
use poi_refresh::*;
use poi_sources::*;

pub(crate) use delta::{apply_wallet_delta_to_vec, pending_overlay_from_delta};
pub use handle::{WalletHandle, WalletPendingOverlay, WalletPendingSpent};
pub(crate) use pending_output_poi::process_pending_output_poi_observations;
pub(crate) use persist::{WalletWorkerServices, wallet_poi_status_client};
pub(crate) use poi_refresh::{LivePoiTailError, LivePoiTailOutcome, sync_live_poi_event_tail};
pub use poi_sources::LocalPoiMerkleProofSource;
pub(crate) use worker::{spawn_wallet_worker, wallet_cache_store};

#[cfg(test)]
mod tests;
