use super::{
    TxidPublicCacheKey, TxidPublicLatestValidated, index_entries_for_hash,
    put_txid_public_latest_validated, safe_file_component, sync_txid_public_cache,
    sync_txid_public_cache_to_graph_tip,
    sync_txid_public_cache_until_recovered_output_with_page_size,
    txid_public_cached_latest_validated, txid_public_proof_for_recovered_output,
    txid_public_proof_for_recovered_output_at_index, txid_public_transaction_for_recovered_output,
    txid_root_index_for_target,
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
    let index_entries = index_entries_for_hash(&db, key, page.rows[0].transaction.transaction_hash)
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
    let (endpoint, requests) = spawn_graphql_response(public_txid_response(vec![target.clone()]));

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
    let canonical_entries =
        index_entries_for_hash(&db, key, canonical.transaction_hash).expect("read canonical index");
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
    let (empty_endpoint, _empty_requests) = spawn_graphql_response(public_txid_response(vec![]));
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
