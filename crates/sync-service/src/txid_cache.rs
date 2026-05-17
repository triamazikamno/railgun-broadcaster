use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use local_db::{BlobMeta, DbError, DbStore};
use merkletree::errors::SyncError;
use merkletree::quick::{IndexedRailgunTransaction, QuickSyncClient};
use merkletree::tree::{DenseMerkleTree, MerkleProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info, warn};
use url::Url;

const TXID_CACHE_BLOB_KIND: &str = "txid_public_cache";
const TXID_CACHE_FORMAT_VERSION: u32 = 2;
const TXID_CACHE_PAGE_SIZE: NonZeroUsize =
    NonZeroUsize::new(10_000).expect("txid cache page size is non-zero");
static TXID_CACHE_SYNC_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static TXID_CACHE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub(crate) enum TxidPublicCacheError {
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("quick-sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("TXID public cache is not ready: next index {next_index}, required {required_index}")]
    CacheNotReady {
        next_index: u64,
        required_index: u64,
    },
    #[error("recovered transaction is missing from local TXID public cache")]
    MissingTarget,
    #[error("multiple cached TXID rows match recovered transaction")]
    AmbiguousTarget,
    #[error("cached TXID page is missing leaf at index {index}")]
    MissingLeaf { index: u64 },
    #[error("cached TXID proof leaf does not match target row")]
    LeafMismatch,
    #[error("cached TXID root does not match latest validated root")]
    RootMismatch,
    #[error("TXID cache metadata mismatch: {0}")]
    MetadataMismatch(String),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxidPublicCacheKey<'a> {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct TxidPublicProof {
    pub target_txid_index: u64,
    pub root_txid_index: u64,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxidPublicLatestValidated {
    pub txid_index: u64,
    pub merkleroot: Option<FixedBytes<32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct TxidPublicCachedTransaction {
    pub txid_index: u64,
    pub txid_leaf_hash: FixedBytes<32>,
    pub transaction: TxidPublicCacheTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCacheManifest {
    format_version: u32,
    chain_type: u8,
    chain_id: u64,
    txid_version: String,
    page_size: usize,
    next_txid_index: u64,
    latest_validated_txid_index: Option<u64>,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
    #[serde(default)]
    validated_cached_txid_index: Option<u64>,
    pages: Vec<TxidPublicCachePageRef>,
}

#[derive(Debug, Clone, Copy)]
struct TxidPublicCacheRefresh {
    fetched_rows: u64,
    refreshed_to: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCachePageRef {
    start_index: u64,
    row_count: u64,
    relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCachePage {
    format_version: u32,
    start_index: u64,
    rows: Vec<TxidPublicCacheRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCacheIndexShard {
    format_version: u32,
    shard: u8,
    entries: Vec<TxidPublicCacheIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCacheIndexEntry {
    transaction_hash: FixedBytes<32>,
    txid_index: u64,
    page_start_index: u64,
    row_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxidPublicCacheRow {
    txid_index: u64,
    txid_leaf_hash: FixedBytes<32>,
    transaction: TxidPublicCacheTransaction,
}

impl From<TxidPublicCacheRow> for TxidPublicCachedTransaction {
    fn from(row: TxidPublicCacheRow) -> Self {
        Self {
            txid_index: row.txid_index,
            txid_leaf_hash: row.txid_leaf_hash,
            transaction: row.transaction,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxidPublicCacheTransaction {
    pub id: String,
    pub transaction_hash: FixedBytes<32>,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub merkle_root: U256,
    pub nullifiers: Vec<U256>,
    pub commitments: Vec<U256>,
    pub bound_params_hash: U256,
    pub has_unshield: bool,
    pub utxo_tree_in: u64,
    pub utxo_tree_out: u64,
    pub utxo_batch_start_position_out: u64,
}

impl From<IndexedRailgunTransaction> for TxidPublicCacheTransaction {
    fn from(transaction: IndexedRailgunTransaction) -> Self {
        Self {
            id: transaction.id,
            transaction_hash: transaction.transaction_hash,
            block_number: transaction.block_number.to(),
            block_timestamp: transaction.block_timestamp.to(),
            merkle_root: U256::from_be_bytes(transaction.merkle_root.0),
            nullifiers: transaction.nullifiers,
            commitments: transaction.commitments,
            bound_params_hash: transaction.bound_params_hash,
            has_unshield: transaction.has_unshield,
            utxo_tree_in: transaction.utxo_tree_in.to(),
            utxo_tree_out: transaction.utxo_tree_out.to(),
            utxo_batch_start_position_out: transaction.utxo_batch_start_position_out.to(),
        }
    }
}

impl TxidPublicCacheTransaction {
    pub(crate) fn output_start_global(&self) -> u128 {
        u128::from(self.utxo_tree_out) * u128::from(TREE_LEAF_COUNT)
            + u128::from(self.utxo_batch_start_position_out)
    }

    pub(crate) fn output_index(&self, output_commitment: FixedBytes<32>) -> Option<usize> {
        let output_commitment = U256::from_be_bytes(output_commitment.0);
        self.commitments
            .iter()
            .position(|commitment| *commitment == output_commitment)
    }
}

fn txid_public_cache_page_from_rows(
    start_index: u64,
    rows: Vec<IndexedRailgunTransaction>,
) -> TxidPublicCachePage {
    TxidPublicCachePage {
        format_version: TXID_CACHE_FORMAT_VERSION,
        start_index,
        rows: rows
            .into_iter()
            .enumerate()
            .map(|(offset, transaction)| {
                let txid_index = start_index + offset as u64;
                let txid_leaf_hash =
                    FixedBytes::from(transaction.txid_leaf_hash().to_be_bytes::<32>());
                TxidPublicCacheRow {
                    txid_index,
                    txid_leaf_hash,
                    transaction: transaction.into(),
                }
            })
            .collect(),
    }
}

pub(crate) async fn sync_txid_public_cache(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<(), TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    let previous_validated_txid_index = manifest.latest_validated_txid_index;
    let previous_validated_merkleroot = manifest.latest_validated_merkleroot;
    if previous_validated_txid_index.is_some_and(|index| index > latest_validated_txid_index)
        || (previous_validated_txid_index == Some(latest_validated_txid_index)
            && previous_validated_merkleroot != latest_validated_merkleroot)
    {
        manifest.validated_cached_txid_index = None;
    }
    manifest.latest_validated_txid_index = Some(latest_validated_txid_index);
    manifest.latest_validated_merkleroot = latest_validated_merkleroot;

    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut fetched_rows = 0_u64;
    let refresh_start = manifest
        .validated_cached_txid_index
        .map_or(0, |index| index.saturating_add(1));
    let refresh_needed = refresh_start <= latest_validated_txid_index;
    if refresh_needed {
        let refresh = refresh_txid_public_cache_range(
            &mut manifest,
            db,
            &client,
            key,
            refresh_start,
            latest_validated_txid_index,
        )
        .await?;
        fetched_rows = fetched_rows.saturating_add(refresh.fetched_rows);
        if let Some(refreshed_to) = refresh.refreshed_to {
            manifest.validated_cached_txid_index = Some(refreshed_to);
        }
    }
    while !refresh_needed && manifest.next_txid_index <= latest_validated_txid_index {
        let start_index = manifest.next_txid_index;
        let rows = client
            .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
            .await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        insert_or_replace_page(&mut manifest, db, key, &page)?;
        rebuild_index_for_manifest(&manifest, db, key)?;
        manifest.validated_cached_txid_index = Some(start_index.saturating_add(row_count - 1));
        fetched_rows = fetched_rows.saturating_add(row_count);
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache page synced"
        );
        if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
            break;
        }
    }

    write_manifest(db, key, &manifest)?;
    info!(
        chain_id = key.chain_id,
        txid_version = key.txid_version,
        latest_validated_txid_index,
        next_txid_index = manifest.next_txid_index,
        fetched_rows,
        elapsed_ms = started.elapsed().as_millis(),
        "TXID public cache sync complete"
    );
    Ok(())
}

pub(crate) async fn sync_txid_public_cache_to_graph_tip(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
) -> Result<u64, TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut fetched_rows = 0_u64;
    loop {
        let start_index = manifest.next_txid_index;
        let rows = client
            .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
            .await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        append_page(&mut manifest, db, key, &page)?;
        update_index_for_page(db, key, &page)?;
        fetched_rows = fetched_rows.saturating_add(row_count);
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache background page synced"
        );
        if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
            break;
        }
    }

    write_manifest(db, key, &manifest)?;
    info!(
        chain_id = key.chain_id,
        txid_version = key.txid_version,
        next_txid_index = manifest.next_txid_index,
        fetched_rows,
        elapsed_ms = started.elapsed().as_millis(),
        "TXID public cache background sync complete"
    );
    Ok(fetched_rows)
}

pub(crate) async fn sync_txid_public_cache_until_recovered_output(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    sync_txid_public_cache_until_recovered_output_with_page_size(
        db,
        endpoint,
        http_client,
        key,
        tx_hash,
        output_commitment,
        TXID_CACHE_PAGE_SIZE,
    )
    .await
}

async fn sync_txid_public_cache_until_recovered_output_with_page_size(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
    page_size: NonZeroUsize,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    match find_public_recovery_transaction_in_manifest(
        &manifest,
        db,
        key,
        tx_hash,
        output_commitment,
    ) {
        Ok(row) => return Ok(row.into()),
        Err(TxidPublicCacheError::MissingTarget) => {}
        Err(err) => return Err(err),
    }
    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut next_index = manifest
        .validated_cached_txid_index
        .map_or(0, |index| index.saturating_add(1))
        .min(manifest.next_txid_index);
    let mut fetched_rows = 0_u64;
    loop {
        let start_index = next_index;
        let rows = client
            .fetch_public_txid_page(start_index, page_size)
            .await?;
        if rows.is_empty() {
            write_manifest(db, key, &manifest)?;
            return Err(TxidPublicCacheError::MissingTarget);
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        if start_index < manifest.next_txid_index {
            insert_or_replace_page(&mut manifest, db, key, &page)?;
            rebuild_index_for_manifest(&manifest, db, key)?;
        } else {
            append_page(&mut manifest, db, key, &page)?;
            update_index_for_page(db, key, &page)?;
        }
        next_index = start_index.saturating_add(row_count);
        fetched_rows = fetched_rows.saturating_add(row_count);
        write_manifest(db, key, &manifest)?;
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache recovery page synced"
        );

        if let Some(row) = find_target_row_in_page(&manifest, &page, tx_hash, output_commitment)? {
            info!(
                chain_id = key.chain_id,
                txid_version = key.txid_version,
                target_txid_index = row.txid_index,
                fetched_rows,
                elapsed_ms = started.elapsed().as_millis(),
                "TXID public cache recovery target synced"
            );
            return Ok(row.into());
        }
        if row_count < page_size.get() as u64 {
            return Err(TxidPublicCacheError::MissingTarget);
        }
    }
}

pub(crate) fn txid_public_cached_latest_validated(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<Option<TxidPublicLatestValidated>, TxidPublicCacheError> {
    let Some(manifest) = load_manifest(db, key)? else {
        return Ok(None);
    };
    validate_manifest(&manifest, key)?;
    Ok(manifest
        .latest_validated_txid_index
        .map(|txid_index| TxidPublicLatestValidated {
            txid_index,
            merkleroot: manifest.latest_validated_merkleroot,
        }))
}

#[cfg(test)]
pub(crate) async fn put_txid_public_latest_validated(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    latest: TxidPublicLatestValidated,
) -> Result<(), TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let mut manifest = load_or_new_manifest(db, key)?;
    manifest.latest_validated_txid_index = Some(latest.txid_index);
    manifest.latest_validated_merkleroot = latest.merkleroot;
    write_manifest(db, key, &manifest)
}

async fn refresh_txid_public_cache_range(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    client: &QuickSyncClient,
    key: TxidPublicCacheKey<'_>,
    start_index: u64,
    end_index: u64,
) -> Result<TxidPublicCacheRefresh, TxidPublicCacheError> {
    let mut fetched_rows = 0_u64;
    let mut refreshed_to = None;
    let mut next_index = start_index;
    while next_index <= end_index {
        let remaining = end_index.saturating_sub(next_index).saturating_add(1);
        let limit = NonZeroUsize::new(remaining.min(TXID_CACHE_PAGE_SIZE.get() as u64) as usize)
            .expect("validated TXID refresh limit is non-zero");
        let rows = client.fetch_public_txid_page(next_index, limit).await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(next_index, rows);
        insert_or_replace_page(manifest, db, key, &page)?;
        fetched_rows = fetched_rows.saturating_add(row_count);
        refreshed_to = Some(next_index.saturating_add(row_count - 1));
        debug!(
            chain_id = key.chain_id,
            start_index = next_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache validated page refreshed"
        );
        next_index = next_index.saturating_add(row_count);
        if row_count < limit.get() as u64 {
            break;
        }
    }
    if fetched_rows > 0 {
        rebuild_index_for_manifest(manifest, db, key)?;
    }
    Ok(TxidPublicCacheRefresh {
        fetched_rows,
        refreshed_to,
    })
}

pub(crate) fn txid_public_proof_for_recovered_output(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    expected_leaf_hash: U256,
    output_start_global: u128,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: latest_validated_txid_index,
    })?;
    validate_manifest(&manifest, key)?;
    let expected_leaf_hash = FixedBytes::from(expected_leaf_hash.to_be_bytes::<32>());
    let target = find_target_row(&manifest, db, expected_leaf_hash, output_start_global)?;
    txid_public_proof_for_target_row(
        &manifest,
        db,
        target,
        latest_validated_txid_index,
        latest_validated_merkleroot,
    )
}

pub(crate) fn txid_public_proof_for_recovered_output_at_index(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    target_txid_index: u64,
    expected_leaf_hash: U256,
    output_start_global: u128,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: latest_validated_txid_index,
    })?;
    validate_manifest(&manifest, key)?;
    validated_root_txid_index(&manifest, target_txid_index, latest_validated_txid_index)?;
    let target = row_for_txid_index(&manifest, db, target_txid_index)?.ok_or(
        TxidPublicCacheError::MissingLeaf {
            index: target_txid_index,
        },
    )?;
    let expected_leaf_hash = FixedBytes::from(expected_leaf_hash.to_be_bytes::<32>());
    if target.txid_leaf_hash != expected_leaf_hash
        || target.transaction.output_start_global() != output_start_global
    {
        return Err(TxidPublicCacheError::LeafMismatch);
    }
    txid_public_proof_for_target_row(
        &manifest,
        db,
        target,
        latest_validated_txid_index,
        latest_validated_merkleroot,
    )
}

fn txid_public_proof_for_target_row(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    target: TxidPublicCacheRow,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let root_txid_index =
        validated_root_txid_index(manifest, target.txid_index, latest_validated_txid_index)?;
    let target_tree = target.txid_index / TREE_LEAF_COUNT;
    let target_index = target.txid_index % TREE_LEAF_COUNT;
    let root_index = root_txid_index % TREE_LEAF_COUNT;
    let leaf_count = root_index.saturating_add(1);
    let leaves = read_tree_leaves(manifest, db, target_tree, leaf_count)?;
    let tree = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count);
    let proof = tree.prove(target_index);
    if proof.leaf != U256::from_be_bytes(target.txid_leaf_hash.0) {
        return Err(TxidPublicCacheError::LeafMismatch);
    }

    let computed_root = FixedBytes::from(proof.root.to_be_bytes::<32>());
    if root_txid_index == latest_validated_txid_index
        && latest_validated_merkleroot.is_some_and(|root| root != computed_root)
    {
        return Err(TxidPublicCacheError::RootMismatch);
    }

    Ok(TxidPublicProof {
        target_txid_index: target.txid_index,
        root_txid_index,
        proof,
    })
}

fn validated_root_txid_index(
    manifest: &TxidPublicCacheManifest,
    target_txid_index: u64,
    latest_validated_txid_index: u64,
) -> Result<u64, TxidPublicCacheError> {
    if latest_validated_txid_index < target_txid_index {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: manifest.next_txid_index,
            required_index: target_txid_index,
        });
    }
    let root_txid_index =
        txid_root_index_for_target(target_txid_index, latest_validated_txid_index);
    if manifest
        .validated_cached_txid_index
        .is_none_or(|index| index < root_txid_index)
    {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: manifest
                .validated_cached_txid_index
                .map_or(0, |index| index.saturating_add(1)),
            required_index: root_txid_index,
        });
    }
    Ok(root_txid_index)
}

pub(crate) fn txid_public_transaction_for_recovered_output(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: 0,
    })?;
    validate_manifest(&manifest, key)?;
    let row = find_public_recovery_transaction_in_manifest(
        &manifest,
        db,
        key,
        tx_hash,
        output_commitment,
    )?;
    Ok(row.into())
}

fn find_public_recovery_transaction_in_manifest(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    if let Some(row) = find_target_row_by_hash_index(manifest, db, key, tx_hash, output_commitment)?
    {
        return Ok(row);
    }
    rebuild_index_for_manifest(manifest, db, key)?;
    if let Some(row) = find_target_row_by_hash_index(manifest, db, key, tx_hash, output_commitment)?
    {
        return Ok(row);
    }
    find_target_row_by_scan(manifest, db, tx_hash, output_commitment)
}

fn find_target_row_by_hash_index(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let entries = index_entries_for_hash(db, key, tx_hash)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let mut found = RecoveredOutputMatch::default();
    for entry in entries {
        let Some(row) = row_for_index_entry(manifest, db, &entry)? else {
            continue;
        };
        found.remember(manifest, row, tx_hash, output_commitment)?;
    }
    Ok(found.row)
}

fn find_target_row_by_scan(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    let mut found = RecoveredOutputMatch::default();
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            found.remember(manifest, row, tx_hash, output_commitment)?;
        }
    }
    found.row.ok_or(TxidPublicCacheError::MissingTarget)
}

fn find_target_row_in_page(
    manifest: &TxidPublicCacheManifest,
    page: &TxidPublicCachePage,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let mut found = RecoveredOutputMatch::default();
    for row in page.rows.iter().cloned() {
        found.remember(manifest, row, tx_hash, output_commitment)?;
    }
    Ok(found.row)
}

#[derive(Default)]
struct RecoveredOutputMatch {
    row: Option<TxidPublicCacheRow>,
    validated: bool,
}

impl RecoveredOutputMatch {
    fn remember(
        &mut self,
        manifest: &TxidPublicCacheManifest,
        row: TxidPublicCacheRow,
        tx_hash: FixedBytes<32>,
        output_commitment: FixedBytes<32>,
    ) -> Result<(), TxidPublicCacheError> {
        if row.transaction.transaction_hash != tx_hash
            || row.transaction.output_index(output_commitment).is_none()
        {
            return Ok(());
        }
        let validated = manifest
            .validated_cached_txid_index
            .is_some_and(|index| row.txid_index <= index);
        match (&self.row, self.validated, validated) {
            (None, _, _) => {
                self.row = Some(row);
                self.validated = validated;
            }
            (Some(_), true, false) => {}
            (Some(_), false, true) => {
                self.row = Some(row);
                self.validated = true;
            }
            (Some(_), _, _) => return Err(TxidPublicCacheError::AmbiguousTarget),
        }
        Ok(())
    }
}

fn row_for_index_entry(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    entry: &TxidPublicCacheIndexEntry,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let Some(page_ref) = manifest
        .pages
        .iter()
        .find(|page_ref| page_ref.start_index == entry.page_start_index)
    else {
        return Ok(None);
    };
    let page = read_page(db, page_ref)?;
    let Some(row) = page.rows.get(entry.row_offset as usize).cloned() else {
        return Ok(None);
    };
    if row.txid_index != entry.txid_index
        || row.transaction.transaction_hash != entry.transaction_hash
    {
        return Ok(None);
    }
    Ok(Some(row))
}

fn row_for_txid_index(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    txid_index: u64,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let Some(page_ref) = manifest.pages.iter().find(|page_ref| {
        txid_index >= page_ref.start_index
            && txid_index < page_ref.start_index.saturating_add(page_ref.row_count)
    }) else {
        return Ok(None);
    };
    let page = read_page(db, page_ref)?;
    let offset = (txid_index - page_ref.start_index) as usize;
    let Some(row) = page.rows.get(offset).cloned() else {
        return Ok(None);
    };
    if row.txid_index == txid_index {
        Ok(Some(row))
    } else {
        Ok(None)
    }
}

fn txid_root_index_for_target(target_txid_index: u64, latest_validated_txid_index: u64) -> u64 {
    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let latest_tree = latest_validated_txid_index / TREE_LEAF_COUNT;
    if latest_tree == target_tree {
        latest_validated_txid_index
    } else {
        (target_tree + 1) * TREE_LEAF_COUNT - 1
    }
}

fn load_or_new_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<TxidPublicCacheManifest, TxidPublicCacheError> {
    if let Some(manifest) = load_manifest(db, key)? {
        match validate_manifest(&manifest, key) {
            Ok(()) => return Ok(manifest),
            Err(err) => {
                warn!(
                    ?err,
                    chain_id = key.chain_id,
                    txid_version = key.txid_version,
                    "resetting incompatible TXID public cache manifest"
                );
            }
        }
    }
    Ok(TxidPublicCacheManifest {
        format_version: TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        txid_version: key.txid_version.to_string(),
        page_size: TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index: 0,
        latest_validated_txid_index: None,
        latest_validated_merkleroot: None,
        validated_cached_txid_index: None,
        pages: Vec::new(),
    })
}

fn load_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<Option<TxidPublicCacheManifest>, TxidPublicCacheError> {
    let Some(meta) = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &cache_id(key))? else {
        return Ok(None);
    };
    let path = db.resolve_path(&meta.relative_path);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(rmp_serde::from_slice(&bytes)?)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn validate_manifest(
    manifest: &TxidPublicCacheManifest,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    if manifest.format_version != TXID_CACHE_FORMAT_VERSION {
        return Err(TxidPublicCacheError::MetadataMismatch(format!(
            "unsupported format version {}",
            manifest.format_version
        )));
    }
    if manifest.chain_type != key.chain_type
        || manifest.chain_id != key.chain_id
        || manifest.txid_version != key.txid_version
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "cache identity mismatch".to_string(),
        ));
    }
    Ok(())
}

fn write_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    manifest: &TxidPublicCacheManifest,
) -> Result<(), TxidPublicCacheError> {
    let name = manifest_file_name(key);
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
    let bytes = rmp_serde::to_vec_named(manifest)?;
    write_blob_file(db, &path, &bytes)?;
    let now = now_epoch_secs()?;
    let existing = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &cache_id(key))?;
    db.put_blob_meta(
        TXID_CACHE_BLOB_KIND,
        &cache_id(key),
        &BlobMeta {
            format_version: TXID_CACHE_FORMAT_VERSION,
            relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
            content_hash: Sha256::digest(&bytes).into(),
            created_at: existing.map_or(now, |meta| meta.created_at),
            updated_at: now,
            last_block: None,
        },
    )?;
    Ok(())
}

fn write_page(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<TxidPublicCachePageRef, TxidPublicCacheError> {
    let name = page_file_name(key, page.start_index);
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
    let bytes = rmp_serde::to_vec_named(page)?;
    write_blob_file(db, &path, &bytes)?;
    Ok(TxidPublicCachePageRef {
        start_index: page.start_index,
        row_count: page.rows.len() as u64,
        relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
    })
}

fn append_page(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let page_ref = write_page(db, key, page)?;
    manifest.next_txid_index = manifest
        .next_txid_index
        .max(page.start_index.saturating_add(page.rows.len() as u64));
    manifest.pages.push(page_ref);
    manifest.pages.sort_by_key(|page_ref| page_ref.start_index);
    Ok(())
}

fn insert_or_replace_page(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let page_end = page.start_index.saturating_add(page.rows.len() as u64);
    let mut pages = Vec::with_capacity(manifest.pages.len() + 1);
    for page_ref in std::mem::take(&mut manifest.pages) {
        let existing_end = page_ref.start_index.saturating_add(page_ref.row_count);
        if existing_end <= page.start_index || page_ref.start_index >= page_end {
            pages.push(page_ref);
            continue;
        }

        let existing = read_page(db, &page_ref)?;
        let before_rows: Vec<_> = existing
            .rows
            .iter()
            .take_while(|row| row.txid_index < page.start_index)
            .cloned()
            .collect();
        if let Some(page_ref) = write_preserved_page_segment(db, key, before_rows)? {
            pages.push(page_ref);
        }

        let after_rows: Vec<_> = existing
            .rows
            .into_iter()
            .filter(|row| row.txid_index >= page_end)
            .collect();
        if let Some(page_ref) = write_preserved_page_segment(db, key, after_rows)? {
            pages.push(page_ref);
        }
    }

    pages.push(write_page(db, key, page)?);
    pages.sort_by_key(|page_ref| page_ref.start_index);
    manifest.next_txid_index = manifest.next_txid_index.max(page_end);
    manifest.pages = pages;
    Ok(())
}

fn write_preserved_page_segment(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    rows: Vec<TxidPublicCacheRow>,
) -> Result<Option<TxidPublicCachePageRef>, TxidPublicCacheError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let page = TxidPublicCachePage {
        format_version: TXID_CACHE_FORMAT_VERSION,
        start_index: first.txid_index,
        rows,
    };
    write_page(db, key, &page).map(Some)
}

fn write_blob_file(db: &DbStore, path: &Path, bytes: &[u8]) -> Result<(), TxidPublicCacheError> {
    db.ensure_blob_dir(TXID_CACHE_BLOB_KIND)?;
    let nonce = TXID_CACHE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

fn read_page(
    db: &DbStore,
    page_ref: &TxidPublicCachePageRef,
) -> Result<TxidPublicCachePage, TxidPublicCacheError> {
    let bytes = fs::read(db.resolve_path(&page_ref.relative_path))?;
    let page: TxidPublicCachePage = rmp_serde::from_slice(&bytes)?;
    if page.format_version != TXID_CACHE_FORMAT_VERSION || page.start_index != page_ref.start_index
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "page metadata mismatch".to_string(),
        ));
    }
    Ok(page)
}

fn update_index_for_page(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let mut entries_by_shard: BTreeMap<u8, Vec<TxidPublicCacheIndexEntry>> = BTreeMap::new();
    for (row_offset, row) in page.rows.iter().enumerate() {
        entries_by_shard
            .entry(index_shard(row.transaction.transaction_hash))
            .or_default()
            .push(TxidPublicCacheIndexEntry {
                transaction_hash: row.transaction.transaction_hash,
                txid_index: row.txid_index,
                page_start_index: page.start_index,
                row_offset: row_offset as u64,
            });
    }
    let page_end = page.start_index.saturating_add(page.rows.len() as u64);
    for (shard, mut new_entries) in entries_by_shard {
        let mut index = load_index_shard(db, key, shard)?;
        index
            .entries
            .retain(|entry| entry.txid_index < page.start_index || entry.txid_index >= page_end);
        index.entries.append(&mut new_entries);
        index.entries.sort_by_key(|entry| entry.txid_index);
        write_index_shard(db, key, &index)?;
    }
    Ok(())
}

fn rebuild_index_for_manifest(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    clear_index_shards(db, key)?;
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        update_index_for_page(db, key, &page)?;
    }
    Ok(())
}

fn clear_index_shards(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    for shard in u8::MIN..=u8::MAX {
        let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn index_entries_for_hash(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
) -> Result<Vec<TxidPublicCacheIndexEntry>, TxidPublicCacheError> {
    let index = load_index_shard(db, key, index_shard(tx_hash))?;
    Ok(index
        .entries
        .into_iter()
        .filter(|entry| entry.transaction_hash == tx_hash)
        .collect())
}

fn load_index_shard(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    shard: u8,
) -> Result<TxidPublicCacheIndexShard, TxidPublicCacheError> {
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
    match fs::read(path) {
        Ok(bytes) => {
            let index: TxidPublicCacheIndexShard = rmp_serde::from_slice(&bytes)?;
            if index.format_version == TXID_CACHE_FORMAT_VERSION && index.shard == shard {
                Ok(index)
            } else {
                Ok(empty_index_shard(shard))
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(empty_index_shard(shard)),
        Err(err) => Err(err.into()),
    }
}

fn write_index_shard(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    index: &TxidPublicCacheIndexShard,
) -> Result<(), TxidPublicCacheError> {
    let path = db.blob_path(
        TXID_CACHE_BLOB_KIND,
        &index_shard_file_name(key, index.shard),
    );
    let bytes = rmp_serde::to_vec_named(index)?;
    write_blob_file(db, &path, &bytes)
}

const fn empty_index_shard(shard: u8) -> TxidPublicCacheIndexShard {
    TxidPublicCacheIndexShard {
        format_version: TXID_CACHE_FORMAT_VERSION,
        shard,
        entries: Vec::new(),
    }
}

const fn index_shard(tx_hash: FixedBytes<32>) -> u8 {
    tx_hash.0[0]
}

fn find_target_row(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    expected_leaf_hash: FixedBytes<32>,
    output_start_global: u128,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    let mut found = None;
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            if row.txid_leaf_hash == expected_leaf_hash
                && row.transaction.output_start_global() == output_start_global
            {
                if found.is_some() {
                    return Err(TxidPublicCacheError::AmbiguousTarget);
                }
                found = Some(row);
            }
        }
    }
    found.ok_or(TxidPublicCacheError::MissingTarget)
}

fn read_tree_leaves(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    tree: u64,
    leaf_count: u64,
) -> Result<Vec<U256>, TxidPublicCacheError> {
    let start = tree.saturating_mul(TREE_LEAF_COUNT);
    let mut leaves = vec![None; leaf_count as usize];
    for page_ref in &manifest.pages {
        let page_end = page_ref.start_index.saturating_add(page_ref.row_count);
        let range_end = start.saturating_add(leaf_count);
        if page_end <= start || page_ref.start_index >= range_end {
            continue;
        }
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            if row.txid_index >= start && row.txid_index < range_end {
                let index = (row.txid_index - start) as usize;
                leaves[index] = Some(U256::from_be_bytes(row.txid_leaf_hash.0));
            }
        }
    }
    leaves
        .into_iter()
        .enumerate()
        .map(|(index, leaf)| {
            leaf.ok_or_else(|| TxidPublicCacheError::MissingLeaf {
                index: start + index as u64,
            })
        })
        .collect()
}

fn cache_id(key: TxidPublicCacheKey<'_>) -> String {
    format!("{}|{}|{}", key.chain_type, key.chain_id, key.txid_version)
}

fn manifest_file_name(key: TxidPublicCacheKey<'_>) -> String {
    format!(
        "{}-{}-{}-manifest.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

fn page_file_name(key: TxidPublicCacheKey<'_>, start_index: u64) -> String {
    format!(
        "{}-{}-{}-{start_index:016}.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

fn index_shard_file_name(key: TxidPublicCacheKey<'_>, shard: u8) -> String {
    format!(
        "{}-{}-{}-tx-index-{shard:02x}.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_epoch_secs() -> Result<u64, std::io::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    Ok(now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{
        TxidPublicCacheKey, TxidPublicLatestValidated, index_entries_for_hash,
        put_txid_public_latest_validated, safe_file_component, sync_txid_public_cache,
        sync_txid_public_cache_to_graph_tip,
        sync_txid_public_cache_until_recovered_output_with_page_size,
        txid_public_cached_latest_validated, txid_public_proof_for_recovered_output,
        txid_public_proof_for_recovered_output_at_index,
        txid_public_transaction_for_recovered_output, txid_root_index_for_target,
    };
    use alloy::primitives::{FixedBytes, U64, U256};
    use broadcaster_core::tree::TREE_LEAF_COUNT;
    use local_db::{DbConfig, DbStore};
    use merkletree::quick::IndexedRailgunTransaction;
    use merkletree::tree::DenseMerkleTree;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::num::NonZeroUsize;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;
    use url::Url;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn txid_root_index_uses_latest_index_in_same_tree() {
        assert_eq!(txid_root_index_for_target(5, 9), 9);
    }

    #[test]
    fn txid_root_index_uses_full_tree_when_latest_is_later_tree() {
        assert_eq!(
            txid_root_index_for_target(5, TREE_LEAF_COUNT + 9),
            TREE_LEAF_COUNT - 1
        );
    }

    #[test]
    fn safe_file_component_replaces_path_separators() {
        assert_eq!(
            safe_file_component("V2/Poseidon:Merkle"),
            "V2_Poseidon_Merkle"
        );
    }

    #[tokio::test]
    async fn txid_public_cache_syncs_broad_page_and_builds_proof() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let (endpoint, requests) = spawn_graphql(
            r#"{"data":{"transactions":[{"id":"0x0001","blockNumber":"12","blockTimestamp":"1700000012","transactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111","merkleRoot":"0x2222222222222222222222222222222222222222222222222222222222222222","nullifiers":["0x01"],"commitments":["0x02"],"boundParamsHash":"0x03","hasUnshield":false,"utxoTreeIn":"0","utxoTreeOut":"0","utxoBatchStartPositionOut":"0"}]}}"#,
        );
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };

        sync_txid_public_cache(&db, &endpoint, None, key, 0, None)
            .await
            .expect("sync public txid cache");
        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        let page = super::read_page(&db, &manifest.pages[0]).expect("read page");
        let expected_leaf = U256::from_be_bytes(page.rows[0].txid_leaf_hash.0);
        let index_entries =
            index_entries_for_hash(&db, key, page.rows[0].transaction.transaction_hash)
                .expect("read tx hash index");
        assert_eq!(index_entries.len(), 1);
        assert_eq!(index_entries[0].txid_index, 0);
        let proof = txid_public_proof_for_recovered_output(
            &db,
            key,
            expected_leaf,
            page.rows[0].transaction.output_start_global(),
            0,
            None,
        )
        .expect("build cached txid proof");

        assert_eq!(proof.target_txid_index, 0);
        assert_eq!(proof.root_txid_index, 0);
        assert_eq!(proof.proof.leaf, expected_leaf);
        let cached = txid_public_transaction_for_recovered_output(
            &db,
            key,
            page.rows[0].transaction.transaction_hash,
            page.rows[0].transaction.commitments[0]
                .to_be_bytes::<32>()
                .into(),
        )
        .expect("lookup recovered output row");
        assert_eq!(cached.txid_index, 0);
        assert_eq!(
            cached.transaction.merkle_root,
            U256::from_be_bytes([0x22; 32])
        );
        assert_eq!(
            txid_public_cached_latest_validated(&db, key)
                .expect("read latest validated")
                .expect("latest validated present")
                .txid_index,
            0
        );
        put_txid_public_latest_validated(
            &db,
            key,
            TxidPublicLatestValidated {
                txid_index: 12,
                merkleroot: Some(FixedBytes::from([0x33; 32])),
            },
        )
        .await
        .expect("update latest validated");
        let latest = txid_public_cached_latest_validated(&db, key)
            .expect("read updated latest validated")
            .expect("updated latest present");
        assert_eq!(latest.txid_index, 12);
        assert_eq!(latest.merkleroot, Some(FixedBytes::from([0x33; 32])));
        let request = requests
            .recv_timeout(Duration::from_secs(5))
            .expect("request received");
        assert!(request.contains("PublicTxidPage"));
        assert!(!request.contains("transactionHash_eq"));
        assert!(!request.contains("commitments_containsAll"));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_refreshes_prefetched_rows_when_validated() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let stale = indexed_transaction(0x11, 0x02, 0x01, 0x03);
        let corrected = indexed_transaction(0x22, 0x04, 0x05, 0x06);
        let (prefetch_endpoint, _prefetch_requests) =
            spawn_graphql_response(public_txid_response(vec![stale.clone()]));

        sync_txid_public_cache_to_graph_tip(&db, &prefetch_endpoint, None, key)
            .await
            .expect("prefetch stale graph-tip row");
        let stale_cached = txid_public_transaction_for_recovered_output(
            &db,
            key,
            stale.transaction_hash,
            fixed_bytes_from_u256(stale.commitments[0]),
        )
        .expect("stale graph-tip row cached");
        assert_eq!(
            stale_cached.transaction.transaction_hash,
            stale.transaction_hash
        );

        let corrected_leaf = corrected.txid_leaf_hash();
        let corrected_root = root_for_single_leaf(corrected_leaf);
        let (validated_endpoint, _validated_requests) =
            spawn_graphql_response(public_txid_response(vec![corrected.clone()]));
        sync_txid_public_cache(&db, &validated_endpoint, None, key, 0, Some(corrected_root))
            .await
            .expect("refresh newly validated row");

        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        let refreshed_row = super::row_for_txid_index(&manifest, &db, 0)
            .expect("read refreshed row")
            .expect("refreshed row present");
        assert_eq!(
            refreshed_row.txid_leaf_hash,
            FixedBytes::from(corrected_leaf.to_be_bytes::<32>())
        );
        assert_eq!(manifest.validated_cached_txid_index, Some(0));
        assert!(
            index_entries_for_hash(&db, key, stale.transaction_hash)
                .expect("read stale tx hash index")
                .is_empty()
        );
        let corrected_cached = txid_public_transaction_for_recovered_output(
            &db,
            key,
            corrected.transaction_hash,
            fixed_bytes_from_u256(corrected.commitments[0]),
        )
        .expect("corrected row cached");
        assert_eq!(
            corrected_cached.transaction.transaction_hash,
            corrected.transaction_hash
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_lookup_prefers_validated_duplicate_over_unvalidated_stale() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let filler = indexed_transaction(0x11, 0x01, 0x02, 0x03);
        let stale_duplicate = indexed_transaction(0x44, 0x02, 0x03, 0x04);
        let canonical = indexed_transaction(0x44, 0x02, 0x05, 0x06);
        let (prefetch_endpoint, _prefetch_requests) =
            spawn_graphql_response(public_txid_response(vec![filler, stale_duplicate.clone()]));

        sync_txid_public_cache_to_graph_tip(&db, &prefetch_endpoint, None, key)
            .await
            .expect("prefetch stale duplicate row");
        let (validated_endpoint, _validated_requests) =
            spawn_graphql_response(public_txid_response(vec![canonical.clone()]));
        sync_txid_public_cache(&db, &validated_endpoint, None, key, 0, None)
            .await
            .expect("refresh canonical validated row");

        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.validated_cached_txid_index, Some(0));
        let stale_row = super::row_for_txid_index(&manifest, &db, 1)
            .expect("read stale row")
            .expect("stale row present");
        assert_eq!(
            stale_row.transaction.transaction_hash,
            canonical.transaction_hash
        );
        let index_entries = index_entries_for_hash(&db, key, canonical.transaction_hash)
            .expect("read duplicate tx hash index");
        assert_eq!(index_entries.len(), 2);

        let cached = txid_public_transaction_for_recovered_output(
            &db,
            key,
            canonical.transaction_hash,
            fixed_bytes_from_u256(canonical.commitments[0]),
        )
        .expect("validated duplicate should win over stale graph-tip duplicate");

        assert_eq!(cached.txid_index, 0);
        assert_eq!(cached.transaction.nullifiers, canonical.nullifiers);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_recovery_catchup_stops_after_target_page() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let target = indexed_transaction(0x77, 0x02, 0x03, 0x04);
        let (endpoint, requests) =
            spawn_graphql_response(public_txid_response(vec![target.clone()]));

        let cached = sync_txid_public_cache_until_recovered_output_with_page_size(
            &db,
            &endpoint,
            None,
            key,
            target.transaction_hash,
            fixed_bytes_from_u256(target.commitments[0]),
            NonZeroUsize::new(1).expect("test page size is non-zero"),
        )
        .await
        .expect("target row should be returned from first page");

        assert_eq!(cached.txid_index, 0);
        assert_eq!(cached.transaction.transaction_hash, target.transaction_hash);
        let request = requests
            .recv_timeout(Duration::from_secs(5))
            .expect("request received");
        assert!(request.contains("PublicTxidPage"));
        assert!(
            requests.recv_timeout(Duration::from_millis(100)).is_err(),
            "targeted recovery catch-up should not request pages after the target page"
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_recovery_refreshes_rewritten_rows_below_high_water_mark() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let stale = indexed_transaction(0x11, 0x01, 0x02, 0x03);
        let stale_tail = indexed_transaction(0x12, 0x04, 0x05, 0x06);
        let canonical = indexed_transaction(0x77, 0x09, 0x0a, 0x0b);
        let (prefetch_endpoint, _prefetch_requests) =
            spawn_graphql_response(public_txid_response(vec![stale.clone(), stale_tail]));
        sync_txid_public_cache_to_graph_tip(&db, &prefetch_endpoint, None, key)
            .await
            .expect("prefetch stale graph-tip rows");
        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.next_txid_index, 2);
        assert_eq!(manifest.validated_cached_txid_index, None);

        let (recovery_endpoint, requests) =
            spawn_graphql_response(public_txid_response(vec![canonical.clone()]));
        let cached = sync_txid_public_cache_until_recovered_output_with_page_size(
            &db,
            &recovery_endpoint,
            None,
            key,
            canonical.transaction_hash,
            fixed_bytes_from_u256(canonical.commitments[0]),
            NonZeroUsize::new(1).expect("test page size is non-zero"),
        )
        .await
        .expect("target row below high-water mark should be refreshed and returned");

        assert_eq!(cached.txid_index, 0);
        assert_eq!(
            cached.transaction.transaction_hash,
            canonical.transaction_hash
        );
        let request = requests
            .recv_timeout(Duration::from_secs(5))
            .expect("recovery request received");
        assert!(request.contains("\"offset\":0"));
        let manifest = super::load_manifest(&db, key)
            .expect("reload manifest")
            .expect("manifest present");
        assert_eq!(manifest.next_txid_index, 2);
        let refreshed = super::row_for_txid_index(&manifest, &db, 0)
            .expect("read refreshed row")
            .expect("refreshed row present");
        assert_eq!(
            refreshed.transaction.transaction_hash,
            canonical.transaction_hash
        );
        assert!(
            index_entries_for_hash(&db, key, stale.transaction_hash)
                .expect("read stale index")
                .is_empty()
        );
        let canonical_entries = index_entries_for_hash(&db, key, canonical.transaction_hash)
            .expect("read canonical index");
        assert_eq!(canonical_entries.len(), 1);
        assert_eq!(canonical_entries[0].txid_index, 0);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_retries_incomplete_validated_refresh_for_same_latest() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let stale = indexed_transaction(0x11, 0x02, 0x01, 0x03);
        let corrected = indexed_transaction(0x22, 0x04, 0x05, 0x06);
        let corrected_leaf = corrected.txid_leaf_hash();
        let corrected_root = root_for_single_leaf(corrected_leaf);
        let (prefetch_endpoint, _prefetch_requests) =
            spawn_graphql_response(public_txid_response(vec![stale]));

        sync_txid_public_cache_to_graph_tip(&db, &prefetch_endpoint, None, key)
            .await
            .expect("prefetch stale graph-tip row");
        let (empty_endpoint, _empty_requests) =
            spawn_graphql_response(public_txid_response(vec![]));
        sync_txid_public_cache(&db, &empty_endpoint, None, key, 0, Some(corrected_root))
            .await
            .expect("empty validated refresh records latest metadata only");
        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.latest_validated_txid_index, Some(0));
        assert_eq!(manifest.validated_cached_txid_index, None);
        let err = txid_public_proof_for_recovered_output_at_index(
            &db,
            key,
            0,
            corrected_leaf,
            corrected.output_start_global(),
            0,
            Some(corrected_root),
        )
        .expect_err("stale graph-tip row should not be trusted as validated");
        assert!(matches!(
            err,
            super::TxidPublicCacheError::CacheNotReady {
                next_index: 0,
                required_index: 0,
            }
        ));

        let (corrected_endpoint, _corrected_requests) =
            spawn_graphql_response(public_txid_response(vec![corrected.clone()]));
        sync_txid_public_cache(&db, &corrected_endpoint, None, key, 0, Some(corrected_root))
            .await
            .expect("same latest retries incomplete validated refresh");

        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.validated_cached_txid_index, Some(0));
        let refreshed_row = super::row_for_txid_index(&manifest, &db, 0)
            .expect("read refreshed row")
            .expect("refreshed row present");
        assert_eq!(
            refreshed_row.txid_leaf_hash,
            FixedBytes::from(corrected_leaf.to_be_bytes::<32>())
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_latest_validated_waits_for_graph_tip_sync_manifest_write() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let graph_row = indexed_transaction(0x33, 0x07, 0x08, 0x09);
        let (endpoint, requests, release_response) =
            spawn_delayed_graphql_response(public_txid_response(vec![graph_row]));
        let sync_db = Arc::clone(&db);
        let sync_endpoint = endpoint.clone();
        let sync_handle = tokio::spawn(async move {
            sync_txid_public_cache_to_graph_tip(&sync_db, &sync_endpoint, None, key).await
        });
        tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join request receiver")
            .expect("graph-tip request received");

        let latest_db = Arc::clone(&db);
        let latest_handle = tokio::spawn(async move {
            put_txid_public_latest_validated(
                &latest_db,
                key,
                TxidPublicLatestValidated {
                    txid_index: 12,
                    merkleroot: Some(FixedBytes::from([0x44; 32])),
                },
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!latest_handle.is_finished());

        release_response.send(()).expect("release graph response");
        sync_handle
            .await
            .expect("join graph-tip sync")
            .expect("graph-tip sync succeeds");
        latest_handle
            .await
            .expect("join latest update")
            .expect("latest update succeeds");
        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.next_txid_index, 1);
        assert_eq!(manifest.latest_validated_txid_index, Some(12));
        assert_eq!(
            manifest.latest_validated_merkleroot,
            Some(FixedBytes::from([0x44; 32]))
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_public_cache_rejects_oversized_graph_offset_without_writing_page() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let key = TxidPublicCacheKey {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V2_PoseidonMerkle",
        };
        let next_txid_index = i32::MAX as u64 + 1;
        super::write_manifest(
            &db,
            key,
            &super::TxidPublicCacheManifest {
                format_version: super::TXID_CACHE_FORMAT_VERSION,
                chain_type: key.chain_type,
                chain_id: key.chain_id,
                txid_version: key.txid_version.to_string(),
                page_size: super::TXID_CACHE_PAGE_SIZE.get(),
                next_txid_index,
                latest_validated_txid_index: None,
                latest_validated_merkleroot: None,
                validated_cached_txid_index: None,
                pages: Vec::new(),
            },
        )
        .expect("seed manifest");
        //noinspection HttpUrlsUsage
        let endpoint = Url::parse("http://127.0.0.1:1/graphql").expect("unused mock URL");

        let err = sync_txid_public_cache_to_graph_tip(&db, &endpoint, None, key)
            .await
            .expect_err("oversized graph offset should fail before fetching a page");

        assert!(matches!(
            err,
            super::TxidPublicCacheError::Sync(
                merkletree::errors::SyncError::UnexpectedFormat(message)
            ) if message.contains("exceeds GraphQL Int max")
        ));
        let manifest = super::load_manifest(&db, key)
            .expect("load manifest")
            .expect("manifest present");
        assert_eq!(manifest.next_txid_index, next_txid_index);
        assert!(manifest.pages.is_empty());

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-txid-cache-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

    fn indexed_transaction(
        tx_hash_byte: u8,
        commitment: u8,
        nullifier: u8,
        bound_params_hash: u8,
    ) -> IndexedRailgunTransaction {
        IndexedRailgunTransaction {
            id: format!("0x{tx_hash_byte:04x}"),
            block_number: U256::from(12),
            block_timestamp: U256::from(1_700_000_012_u64),
            transaction_hash: FixedBytes::from([tx_hash_byte; 32]),
            merkle_root: FixedBytes::from([0x55; 32]),
            nullifiers: vec![U256::from(nullifier)],
            commitments: vec![U256::from(commitment)],
            bound_params_hash: U256::from(bound_params_hash),
            has_unshield: false,
            utxo_tree_in: U64::from(0),
            utxo_tree_out: U64::from(0),
            utxo_batch_start_position_out: U64::from(0),
        }
    }

    fn public_txid_response(transactions: Vec<IndexedRailgunTransaction>) -> String {
        serde_json::json!({ "data": { "transactions": transactions } }).to_string()
    }

    fn fixed_bytes_from_u256(value: U256) -> FixedBytes<32> {
        FixedBytes::from(value.to_be_bytes::<32>())
    }

    fn root_for_single_leaf(leaf: U256) -> FixedBytes<32> {
        let tree = DenseMerkleTree::from_ordered_leaves(vec![leaf], 1);
        FixedBytes::from(tree.prove(0).root.to_be_bytes::<32>())
    }

    fn spawn_graphql(response_body: &'static str) -> (Url, mpsc::Receiver<String>) {
        spawn_graphql_response(response_body.to_string())
    }

    fn spawn_graphql_response(response_body: String) -> (Url, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock url");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).expect("read request");
            let request = String::from_utf8_lossy(&request[..read]).to_string();
            tx.send(request).expect("send request");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (url, rx)
    }

    fn spawn_delayed_graphql_response(
        response_body: String,
    ) -> (Url, mpsc::Receiver<String>, mpsc::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock url");
        let (request_tx, request_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).expect("read request");
            let request = String::from_utf8_lossy(&request[..read]).to_string();
            request_tx.send(request).expect("send request");
            release_rx.recv().expect("wait for response release");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (url, request_rx, release_tx)
    }
}
