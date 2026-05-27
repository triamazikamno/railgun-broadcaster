use super::{
    DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, LOCAL_PENDING_SPENT_TTL, LocalPoiMerkleProofSource,
    LocalPoiStatusReader, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
    PendingOutputPoiSubmitter, PoiStatusReader, PublicCacheTxidRecoveryRequest,
    RecoveryGraphRailgunTransaction, WALLET_METADATA_LIVE_FLUSH_BLOCKS,
    WALLET_METADATA_LIVE_FLUSH_INTERVAL, WALLET_POI_RECOVERABLE_REFRESH_AFTER,
    WALLET_POI_STATUS_BATCH_SIZE, WalletHandle, WalletLiveMetadataFlush, WalletNullifierIndex,
    WalletPendingOverlay, WalletPendingSpent, WalletPersistState, WalletPoiRefreshRequest,
    WalletPoiRefreshSelection, WalletProgressPersist, apply_wallet_delta_to_vec,
    apply_wallet_delta_to_vec_with_outcome,
    build_output_poi_recovery_chunk_from_public_transaction,
    discard_pending_output_poi_contexts_for_spent_outputs,
    force_resubmit_matching_pending_output_pois, install_persisted_local_poi_caches,
    install_tailed_poi_cache_if_current, local_poi_caches_available_for_lists, now_epoch_secs,
    output_poi_recovery_candidates, output_poi_recovery_proof_retry_after,
    output_start_global_position, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_submit_identity, pending_overlay_from_delta,
    preflight_local_output_poi_input_proofs, process_pending_output_poi_observations,
    process_pending_output_poi_observations_inner, recovered_output_txid_data_from_public_cache,
    recovery_input_merkle_tree_for_root, refresh_wallet_poi_statuses_selected,
    refresh_wallet_poi_statuses_selected_with_config, rewind_wallet_utxos,
    spawn_startup_artifact_poi_cache_warmup, spent_source_for_utxo, sync_live_poi_event_tail,
    verify_submitted_pending_output_pois, verify_submitted_pending_output_pois_with_config,
    wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
};
use crate::txid_cache::{
    TxidPublicCacheKey, TxidPublicCacheTransaction, TxidPublicCachedTransaction,
    sync_txid_public_cache,
};
use crate::types::{
    ChainKey, PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiReadSource, WalletCacheStore,
    WalletConfig,
};
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U64, U256};
use alloy::uint;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{
    BoundParams, CommitmentPreimage, SnarkProof, Transaction,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::transact::{PreTxPoi, SnarkJsProof, railgun_txid_leaf_hash};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use ed25519_dalek::{Signer, SigningKey};
use local_db::{
    DbConfig, DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiRole, PoiArtifactCacheRecord,
    PoiArtifactDescriptorRecord, WalletMeta,
};
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleTreeUpdate};
use poi::artifacts::{ArtifactDescriptor, Manifest, ManifestEntry};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::error::PoiError;
use poi::poi::{
    BlindedCommitmentData, PoiEventType, PoiRpcClient, PoiSyncedListEvent, SignedPoiEvent,
    SingleCommitmentProofContext,
};
use railgun_wallet::prover::ProverError;
use railgun_wallet::scan::{CommitmentObservation, SpentNullifier, WalletLogDelta};
use railgun_wallet::tx::{PoiMerkleProofSource, PreTransactionPoiError};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{
    PoiStatus, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource, WalletUtxo,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc, watch};
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-sync-service-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn source(byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    }
}

fn wallet_config(nullifying_key: U256) -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        cache_key: "test".to_string(),
        start_block: Some(0),
        sync_to_block: None,
        quick_sync_endpoint: None,
        scan_keys: ViewingKeyData {
            viewing_private_key: [0u8; 32],
            viewing_public_key: [0u8; 32],
            nullifying_key,
            master_public_key: U256::ZERO,
        },
        spending_public_key: None,
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: None,
        poi_read_source: PoiReadSource::PoiProxy,
        local_poi_caches: None,
        manage_local_poi_cache: true,
        use_indexed_wallet_catch_up: true,
    }
}

fn test_wallet_utxo(position: u64) -> WalletUtxo {
    test_wallet_utxo_with_kind(position, UtxoCommitmentKind::Transact)
}

fn test_wallet_handle(utxos: Vec<WalletUtxo>) -> WalletHandle {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    WalletHandle {
        cache_key: "cache-key".to_string(),
        utxos: Arc::new(RwLock::new(utxos)),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        ready_rx,
        rev_rx,
        poi_refreshing_rx,
        poi_read_source: PoiReadSource::PoiProxy,
        local_poi_caches: None,
        poi_refresh_tx,
        rev_tx,
    }
}

fn local_pending_spent_for(utxo: &WalletUtxo, submitted_at: u64) -> WalletPendingSpent {
    WalletPendingSpent {
        tree: utxo.utxo.tree,
        position: utxo.utxo.position,
        tx_hash: Some(FixedBytes::from([0x77; 32])),
        block_number: None,
        block_timestamp: Some(submitted_at),
    }
}

fn test_wallet_utxo_with_kind(position: u64, kind: UtxoCommitmentKind) -> WalletUtxo {
    WalletUtxo::new(Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        position,
        source((position % 200) as u8 + 1),
        kind,
    ))
}

fn recovery_test_transaction(
    input: &WalletUtxo,
    output: &WalletUtxo,
    nullifying_key: U256,
) -> Transaction {
    Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::ZERO,
        nullifiers: vec![FixedBytes::from(
            input.utxo.nullifier(nullifying_key).to_be_bytes::<32>(),
        )],
        commitments: vec![output.utxo.poi.commitment],
        boundParams: BoundParams::new_transact(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    }
}

#[test]
fn rewind_wallet_utxos_preserves_pre_reorg_outputs() {
    let kept_unspent = test_wallet_utxo(1);
    let mut kept_spent = test_wallet_utxo(2);
    kept_spent.spent = Some(source(4));
    let mut reopened_spend = test_wallet_utxo(3);
    reopened_spend.spent = Some(source(12));
    let dropped_output = test_wallet_utxo(20);

    let mut wallet_utxos = vec![kept_unspent, kept_spent, reopened_spend, dropped_output];
    let changed = rewind_wallet_utxos(&mut wallet_utxos, 10);

    assert!(changed);
    assert_eq!(wallet_utxos.len(), 3);
    assert!(wallet_utxos.iter().any(|utxo| utxo.utxo.position == 1));
    assert!(wallet_utxos.iter().any(|utxo| {
        utxo.utxo.position == 2
            && utxo
                .spent
                .as_ref()
                .is_some_and(|spent| spent.block_number == 4)
    }));
    assert!(
        wallet_utxos
            .iter()
            .any(|utxo| utxo.utxo.position == 3 && utxo.spent.is_none())
    );
    assert!(!wallet_utxos.iter().any(|utxo| utxo.utxo.position == 20));
}

#[derive(Default)]
struct RecordingPoiStatusClient {
    calls: Mutex<Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)>>,
    fail_calls: Mutex<HashSet<usize>>,
    default_status: Mutex<Option<PoiStatus>>,
    statuses: Mutex<HashMap<FixedBytes<32>, PoiStatus>>,
}

struct MockPoiRpc {
    url: Url,
    requests: std_mpsc::Receiver<serde_json::Value>,
}

impl RecordingPoiStatusClient {
    fn fail_call(&self, call_index: usize) {
        self.fail_calls
            .lock()
            .expect("fail calls")
            .insert(call_index);
    }

    fn set_default_status(&self, status: PoiStatus) {
        *self.default_status.lock().expect("default status") = Some(status);
    }

    fn calls(&self) -> Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)> {
        self.calls.lock().expect("poi calls").clone()
    }
}

async fn spawn_poi_rpc(result: serde_json::Value) -> MockPoiRpc {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock POI RPC");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock POI RPC URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        let (body_start, content_length) = loop {
            let read = socket.read(&mut buf).await.expect("read request");
            assert!(
                read > 0,
                "mock POI RPC connection closed before request body"
            );
            bytes.extend_from_slice(&buf[..read]);
            if let Some(lengths) = http_body_bounds(&bytes) {
                break lengths;
            }
        };
        let body = &bytes[body_start..body_start + content_length];
        let request: serde_json::Value = serde_json::from_slice(body).expect("request JSON");
        tx.send(request.clone()).expect("record request");
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result,
        })
        .to_string();
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.len()
        );
        socket
            .write_all(headers.as_bytes())
            .await
            .expect("write headers");
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write body");
    });
    MockPoiRpc { url, requests }
}

async fn spawn_http_response(body: Vec<u8>) -> (Url, std_mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock HTTP server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock HTTP URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = socket.read(&mut buf).await.expect("read request");
            assert!(read > 0, "mock HTTP connection closed before request");
            bytes.extend_from_slice(&buf[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        tx.send(String::from_utf8_lossy(&bytes).to_string())
            .expect("record request");
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        socket
            .write_all(headers.as_bytes())
            .await
            .expect("write headers");
        socket.write_all(&body).await.expect("write body");
    });
    (url, requests)
}

fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
    let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
    let content_length = headers.lines().find_map(|line| {
        line.strip_prefix("content-length:")
            .or_else(|| line.strip_prefix("Content-Length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
    })?;
    (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
}

#[async_trait]
impl PoiStatusReader for RecordingPoiStatusClient {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        let call_index = {
            let mut calls = self.calls.lock().expect("poi calls");
            let call_index = calls.len();
            calls.push((list_keys.to_vec(), blinded_commitment_datas.to_vec()));
            call_index
        };
        if self
            .fail_calls
            .lock()
            .expect("fail calls")
            .contains(&call_index)
        {
            return Err(PoiError::MerkleRootsRejected);
        }
        let default_status = self
            .default_status
            .lock()
            .expect("default status")
            .unwrap_or(PoiStatus::Valid);
        let statuses = self.statuses.lock().expect("statuses").clone();
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                let status = statuses
                    .get(&data.blinded_commitment)
                    .copied()
                    .unwrap_or(default_status);
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, status))
                        .collect(),
                )
            })
            .collect())
    }
}

#[derive(Default)]
struct RecordingPendingOutputPoiSubmitter {
    calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
    fail_next: Mutex<bool>,
}

impl RecordingPendingOutputPoiSubmitter {
    fn fail_next(&self) {
        *self.fail_next.lock().expect("fail next") = true;
    }

    fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
        self.calls.lock().expect("submission calls").clone()
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for RecordingPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.calls.lock().expect("submission calls").push((
            context.commitment,
            utxo_tree_out,
            utxo_position_out,
        ));
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            return Err(PoiError::MerkleRootsRejected);
        }
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.calls.lock().expect("submission calls").push((
            poi.blinded_commitments_out
                .first()
                .copied()
                .unwrap_or_default(),
            txid_merkleroot_index,
            0,
        ));
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            return Err(PoiError::MerkleRootsRejected);
        }
        Ok(())
    }
}

fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof {
            pi_a: [U256::from(byte), U256::from(byte + 1)],
            pi_b: [
                [U256::from(byte + 2), U256::from(byte + 3)],
                [U256::from(byte + 4), U256::from(byte + 5)],
            ],
            pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
        },
        txid_merkleroot: FixedBytes::from([byte; 32]),
        poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
        blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

fn pending_output_record(
    chain_id: u64,
    output_commitment: FixedBytes<32>,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: "wallet-1".to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment,
        output_npk: FixedBytes::from([0x66; 32]),
        utxo_tree_in: 9,
        railgun_txid: uint!(7_U256),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
            list_key,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))]),
        )]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn matching_pending_output_record(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let mut record = pending_output_record(
        cfg.chain.chain_id,
        wallet_utxo.utxo.poi.commitment,
        list_key,
    );
    record.output_npk = wallet_utxo.utxo.poi.npk;
    record.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(wallet_utxo.utxo.tree),
        output_position: wallet_utxo.utxo.position,
        tx_hash: wallet_utxo.utxo.source.tx_hash,
        block_number: wallet_utxo.utxo.source.block_number,
        block_timestamp: wallet_utxo.utxo.source.block_timestamp,
    });
    record
}

fn output_poi_recovery_record(
    chain_id: u64,
    wallet_id: &str,
    output_commitment: FixedBytes<32>,
    status: OutputPoiRecoveryStatus,
    next_retry_at: Option<u64>,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        output_commitment,
        source_tx_hash: FixedBytes::from([0x99; 32]),
        tx_input: None,
        status,
        created_at: 1,
        updated_at: 1,
        last_detection_at: Some(1),
        last_submission_at: None,
        next_retry_at,
        attempt_count: 0,
        last_error: None,
    }
}

#[test]
fn output_poi_recovery_action_caches_tx_input_without_resetting_state() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 3;
    record.last_error = Some("previous".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: vec![0xde, 0xad],
        },
        10,
    );

    assert_eq!(record.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(20));
    assert_eq!(record.attempt_count, 3);
    assert_eq!(record.last_error.as_deref(), Some("previous"));
}

#[test]
fn output_poi_recovery_action_records_detected_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::DecodeFailed,
            retry_after: Some(Duration::from_secs(30)),
            last_error: Some("decode failed".to_string()),
            increment_attempts: true,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::DecodeFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(40));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("decode failed"));
}

#[test]
fn output_poi_recovery_action_records_recovered_context() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_success() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Submitted {
            retry_after: Duration::from_secs(60),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, Some(10));
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "submit failed".to_string(),
            retry_after: Duration::from_secs(60),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::SubmitFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, None);
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("submit failed"));
}

#[test]
fn output_poi_recovery_action_marks_valid_without_touching_history() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    record.last_detection_at = Some(4);
    record.last_submission_at = Some(5);
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(OutputPoiRecoveryAction::Valid, 10);

    assert_eq!(record.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(4));
    assert_eq!(record.last_submission_at, Some(5));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn pending_output_submit_identity_derives_status_query_blinded_commitment() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let record = pending_output_record(chain_id, output_commitment, list_key);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(
        identity.derived_blinded_commitment,
        UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            observation.output_tree as u32,
            observation.output_position,
        )
    );
}

#[test]
fn pending_output_submit_identity_uses_included_txid_leaf_for_recovery() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let included_txid_leaf = FixedBytes::from([0x99; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    let dummy_txid_leaf = FixedBytes::from(
        railgun_txid_leaf_hash(record.railgun_txid, record.utxo_tree_in).to_be_bytes::<32>(),
    );
    record.txid_merkleroot_index = Some(105_572);
    record.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(included_txid_leaf, sample_pre_tx_poi(0x10))]),
    )]);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(identity.txid_leaf_hash, included_txid_leaf);
    assert_ne!(identity.txid_leaf_hash, dummy_txid_leaf);
}

#[test]
fn output_start_global_position_handles_nonzero_output_index_across_tree_boundary() {
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        3,
        1,
        source(17),
        UtxoCommitmentKind::Transact,
    );

    let start_global = output_start_global_position(&utxo, 2).expect("start global");

    assert_eq!(start_global / u128::from(TREE_LEAF_COUNT), 2);
    assert_eq!(start_global % u128::from(TREE_LEAF_COUNT), 65_535);
    assert_eq!(
        start_global,
        u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position) - 2
    );
}

#[test]
fn recovered_graph_output_start_matches_local_output_start_global() {
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        3,
        1,
        source(18),
        UtxoCommitmentKind::Transact,
    );
    let local_start = output_start_global_position(&utxo, 2).expect("local start");
    let graph_transaction = RecoveryGraphRailgunTransaction {
        id: "tx-1".to_string(),
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        bound_params_hash: U256::ZERO,
        utxo_tree_in: U64::from(2_u8),
        utxo_tree_out: U64::from(2_u8),
        utxo_batch_start_position_out: U64::from(65_535_u64),
    };

    let graph_start = graph_transaction.output_start_global();

    assert_eq!(graph_start, local_start);
}

#[test]
fn recovery_graph_transaction_deserializes_typed_scalars() {
    let transaction: RecoveryGraphRailgunTransaction = serde_json::from_value(serde_json::json!({
        "id": "tx-1",
        "nullifiers": ["0x0a"],
        "commitments": ["0x0b"],
        "boundParamsHash": "0x0c",
        "utxoTreeIn": "2",
        "utxoTreeOut": "0x3",
        "utxoBatchStartPositionOut": "65535",
    }))
    .expect("deserialize graph transaction");

    assert_eq!(transaction.nullifiers, vec![uint!(10_U256)]);
    assert_eq!(transaction.commitments, vec![uint!(11_U256)]);
    assert_eq!(transaction.bound_params_hash, uint!(12_U256));
    assert_eq!(transaction.utxo_tree_in, U64::from(2_u8));
    assert_eq!(transaction.utxo_tree_out, U64::from(3_u8));
    assert_eq!(
        transaction.utxo_batch_start_position_out,
        U64::from(65_535_u64)
    );
}

#[derive(Debug, Clone, Copy, Default)]
struct RecordingCacheState {
    store_calls: usize,
    meta_calls: usize,
    reset_calls: usize,
    fail_next_store: bool,
    fail_next_reset: bool,
}

#[derive(Default)]
struct RecordingCacheStore {
    state: Mutex<RecordingCacheState>,
}

impl RecordingCacheStore {
    fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    fn fail_next_reset(&self) {
        self.state.lock().expect("cache state").fail_next_reset = true;
    }

    fn state(&self) -> RecordingCacheState {
        *self.state.lock().expect("cache state")
    }
}

impl WalletCacheStore for RecordingCacheStore {
    fn store_wallet_utxos(
        &self,
        _wallet_id: &str,
        _utxos: &[WalletUtxo],
        _last_scanned_block: Option<u64>,
        _last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        state.store_calls += 1;
        if state.fail_next_store {
            state.fail_next_store = false;
            return Err(WalletCacheError::Crypto);
        }
        Ok(())
    }

    fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        Ok(Vec::new())
    }

    fn get_wallet_meta(&self, _wallet_id: &str) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(None)
    }

    fn update_wallet_meta(
        &self,
        _wallet_id: &str,
        _last_scanned_block: u64,
        _last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError> {
        self.state.lock().expect("cache state").meta_calls += 1;
        Ok(())
    }

    fn reset_wallet_cache(
        &self,
        _wallet_id: &str,
        _last_scanned_block: u64,
    ) -> Result<(), WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        state.reset_calls += 1;
        if state.fail_next_reset {
            state.fail_next_reset = false;
            return Err(WalletCacheError::Crypto);
        }
        Ok(())
    }
}

#[test]
fn live_metadata_flush_waits_for_interval_or_block_threshold() {
    let now = Instant::now();
    let flush = WalletLiveMetadataFlush::new(100, now);

    assert!(!flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1, now));
    assert!(flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS, now));
    assert!(flush.should_flush(101, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
}

#[test]
fn live_metadata_flush_mark_persisted_resets_thresholds() {
    let now = Instant::now();
    let mut flush = WalletLiveMetadataFlush::new(100, now);

    flush.mark_persisted(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL);

    assert!(!flush.should_flush(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
    assert!(!flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
    assert!(flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
}

#[test]
fn recovery_input_tree_search_finds_root_before_later_commitments() {
    let first_input = test_wallet_utxo(0);
    let mut forest_before_later = MerkleForest::new();
    forest_before_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: first_input.utxo.position,
            hash: first_input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let expected_root = forest_before_later
        .prove_with_leaf_count(first_input.utxo.tree, first_input.utxo.position, 1)
        .expect("historical proof")
        .root;

    let mut forest_after_later = forest_before_later;
    forest_after_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: 1,
            hash: uint!(12_U256),
        })
        .expect("insert later leaf");
    forest_after_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: 2,
            hash: uint!(13_U256),
        })
        .expect("insert second later leaf");

    let current_proof = forest_after_later
        .prove_with_leaf_count(first_input.utxo.tree, first_input.utxo.position, 3)
        .expect("current proof");
    assert_ne!(current_proof.root, expected_root);

    let input_merkle = recovery_input_merkle_tree_for_root(
        &forest_after_later,
        first_input.utxo.tree,
        &first_input,
        3,
        expected_root,
    )
    .expect("find historical root");
    let recovered_proof = input_merkle.tree.prove(first_input.utxo.position);

    assert_eq!(recovered_proof.root, expected_root);
    assert_eq!(recovered_proof.leaf, first_input.utxo.note.commitment());
}

#[test]
fn output_poi_recovery_chunk_builds_from_public_txid_cache_row_without_calldata() {
    let nullifying_key = uint!(9_U256);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let transaction = TxidPublicCacheTransaction {
        id: "0x01".to_string(),
        transaction_hash: output.utxo.source.tx_hash,
        block_number: output.utxo.source.block_number,
        block_timestamp: output.utxo.source.block_timestamp,
        merkle_root,
        nullifiers: vec![input.utxo.nullifier(nullifying_key)],
        commitments: vec![U256::from_be_bytes(output.utxo.poi.commitment.0)],
        bound_params_hash: uint!(3_U256),
        has_unshield: false,
        utxo_tree_in: u64::from(input.utxo.tree),
        utxo_tree_out: u64::from(output.utxo.tree),
        utxo_batch_start_position_out: output.utxo.position,
    };
    let cached_transaction = TxidPublicCachedTransaction {
        txid_index: 42,
        txid_leaf_hash: FixedBytes::ZERO,
        transaction,
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(
        &wallet_utxos,
        &ViewingKeyData {
            viewing_private_key: [0_u8; 32],
            viewing_public_key: [0_u8; 32],
            master_public_key: uint!(1_U256),
            nullifying_key,
        },
    );

    let chunk = build_output_poi_recovery_chunk_from_public_transaction(
        &output,
        &wallet_nullifiers,
        &cached_transaction,
        &forest,
        &[],
        [uint!(4_U256), uint!(5_U256)],
        &ViewingKeyData {
            viewing_private_key: [0_u8; 32],
            viewing_public_key: [0_u8; 32],
            master_public_key: uint!(1_U256),
            nullifying_key,
        },
    )
    .expect("build chunk from public row");

    assert_eq!(chunk.chunk.merkle_root, merkle_root);
    assert_eq!(chunk.chunk.public_inputs.bound_params_hash, uint!(3_U256));
    assert_eq!(
        chunk.chunk.public_inputs.nullifiers,
        cached_transaction.transaction.nullifiers
    );
    assert_eq!(
        chunk.output_start_global,
        cached_transaction.transaction.output_start_global()
    );
    assert_eq!(chunk.target_txid_index, Some(42));
}

#[tokio::test]
async fn public_cache_txid_recovery_rejects_poi_rejected_root_before_persisting_context() {
    let nullifying_key = uint!(9_U256);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let bound_params_hash = uint!(3_U256);
    let transaction = TxidPublicCacheTransaction {
        id: "0x01".to_string(),
        transaction_hash: output.utxo.source.tx_hash,
        block_number: output.utxo.source.block_number,
        block_timestamp: output.utxo.source.block_timestamp,
        merkle_root,
        nullifiers: vec![input.utxo.nullifier(nullifying_key)],
        commitments: vec![U256::from_be_bytes(output.utxo.poi.commitment.0)],
        bound_params_hash,
        has_unshield: false,
        utxo_tree_in: u64::from(input.utxo.tree),
        utxo_tree_out: u64::from(output.utxo.tree),
        utxo_batch_start_position_out: output.utxo.position,
    };
    let cached_transaction = TxidPublicCachedTransaction {
        txid_index: 0,
        txid_leaf_hash: FixedBytes::ZERO,
        transaction: transaction.clone(),
    };
    let wallet_utxos = vec![input, output.clone()];
    let scan_keys = ViewingKeyData {
        viewing_private_key: [0_u8; 32],
        viewing_public_key: [0_u8; 32],
        master_public_key: uint!(1_U256),
        nullifying_key,
    };
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);
    let recovery_chunk = build_output_poi_recovery_chunk_from_public_transaction(
        &output,
        &wallet_nullifiers,
        &cached_transaction,
        &forest,
        &[],
        [uint!(4_U256), uint!(5_U256)],
        &scan_keys,
    )
    .expect("build recovery chunk");

    let graph_response = serde_json::json!({
        "data": {
            "transactions": [{
                "id": transaction.id,
                "blockNumber": transaction.block_number.to_string(),
                "blockTimestamp": transaction.block_timestamp.to_string(),
                "transactionHash": hex::encode_prefixed(transaction.transaction_hash),
                "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
                "nullifiers": [hex::encode_prefixed(FixedBytes::from(transaction.nullifiers[0].to_be_bytes::<32>()))],
                "commitments": [hex::encode_prefixed(output.utxo.poi.commitment)],
                "boundParamsHash": hex::encode_prefixed(FixedBytes::from(bound_params_hash.to_be_bytes::<32>())),
                "hasUnshield": false,
                "utxoTreeIn": transaction.utxo_tree_in.to_string(),
                "utxoTreeOut": transaction.utxo_tree_out.to_string(),
                "utxoBatchStartPositionOut": transaction.utxo_batch_start_position_out.to_string(),
            }]
        }
    })
    .to_string()
    .into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(graph_response).await;
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cache_key = TxidPublicCacheKey {
        chain_type: EVM_CHAIN_TYPE,
        chain_id: 1,
        txid_version: DEFAULT_TXID_VERSION,
    };
    sync_txid_public_cache(&store, &graph_endpoint, None, cache_key, 0, None)
        .await
        .expect("seed public txid cache");
    let poi_mock = spawn_poi_rpc(serde_json::json!(false)).await;
    let poi_client = PoiRpcClient::new(poi_mock.url.clone());
    let mut cfg = wallet_config(nullifying_key);
    cfg.quick_sync_endpoint = Some(graph_endpoint);
    cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        max_manifest_age: None,
    });

    let failure = recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
        db: &store,
        cfg: &cfg,
        poi_client: &poi_client,
        http_client: None,
        source_tx_hash: output.utxo.source.tx_hash,
        output_commitment: output.utxo.poi.commitment,
        recovery_chunk: &recovery_chunk,
        started: Instant::now(),
    })
    .await
    .expect_err("POI-rejected root should fail public-cache TXID recovery");

    assert_eq!(failure.status, OutputPoiRecoveryStatus::MissingMerkleProof);
    assert!(failure.message.contains("POI node rejected"));
    let validate_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("root validation request");
    assert_eq!(validate_request["method"], "ppoi_validate_txid_merkleroot");
    assert!(
        store
            .list_pending_output_poi_contexts(cfg.chain.chain_id)
            .expect("list pending contexts")
            .is_empty()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_proof_panic_uses_long_backoff() {
    let panic_err = PreTransactionPoiError::Prover(ProverError::WorkerPanic("boom".to_string()));
    assert_eq!(
        output_poi_recovery_proof_retry_after(&panic_err),
        OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER
    );

    let transient_err = PreTransactionPoiError::InputCountMismatch {
        expected: 1,
        got: 0,
    };
    assert_eq!(
        output_poi_recovery_proof_retry_after(&transient_err),
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER
    );
}

#[tokio::test]
async fn poi_status_refresh_chunks_unspent_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, list_keys);
    assert_eq!(calls[0].1.len(), WALLET_POI_STATUS_BATCH_SIZE);
    assert_eq!(calls[1].0, list_keys);
    assert_eq!(calls[1].1.len(), 1);
    assert!(wallet_utxos.iter().all(|wallet_utxo| {
        wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys)
            && wallet_utxo.utxo.poi.refreshed_at.is_some()
    }));
}

#[tokio::test]
async fn local_poi_status_refresh_reads_cache_without_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1), test_wallet_utxo(2)];
    let valid_blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let missing_blinded_commitment = wallet_utxos[1].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[hex::encode_prefixed(valid_blinded_commitment)])
        .expect("apply local poi leaf");
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let local_reader = LocalPoiStatusReader::new(local_caches);
    let unused_remote = RecordingPoiStatusClient::default();

    let changed = refresh_wallet_poi_statuses_selected(
        &local_reader,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(unused_remote.calls().is_empty());
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.blinded_commitment,
        valid_blinded_commitment
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.blinded_commitment,
        missing_blinded_commitment
    );
}

#[tokio::test]
async fn indexed_artifacts_status_refresh_does_not_call_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("artifact URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        max_manifest_age: None,
    });
    cfg.local_poi_caches = Some(local_caches);
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp db");
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let remote_client = PoiRpcClient::new(mock.url.clone());

    let changed = refresh_wallet_poi_statuses_selected_with_config(
        &remote_client,
        &db,
        None,
        &cfg,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_startup_warms_cache_even_when_status_refresh_not_needed() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut cache = PoiCache::new(identity.clone());
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x33; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    let expected_root = *cache.current_roots().get(&0).expect("current root");
    cache.accept_current_roots();

    let base_descriptor = ArtifactDescriptor::from_bytes("bafybase", b"");
    let blocked_descriptor = ArtifactDescriptor::from_bytes("bafyblocked", b"");
    let entry = ManifestEntry {
        list_key: hex::encode_prefixed(list_key),
        chain_id: 1,
        base: base_descriptor.clone(),
        deltas: Vec::new(),
        blocked_shields: blocked_descriptor.clone(),
        current_tip_index: 0,
        current_tip_merkleroot: hex::encode_prefixed(expected_root),
    };

    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let key_path = root_dir.join("publisher.key");
    fs::write(&key_path, [0x07_u8; 32]).expect("write publisher key");
    let signing_key = poi::artifacts::manifest::load_publisher_signing_key(&key_path)
        .expect("load publisher key");
    let trusted_publisher_pubkey = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let mut manifest = Manifest::new(2, 1_700_000_000_000, 7, String::new(), vec![entry]);
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let (manifest_url, requests) = spawn_http_response(manifest_bytes).await;

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key,
        last_accepted_manifest_sequence: 6,
        base_descriptor: descriptor_record(&base_descriptor),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: descriptor_record(&blocked_descriptor),
        current_tip_index: 0,
        current_tip_root: expected_root,
        cache_payload: cache.to_bytes().expect("cache payload"),
        updated_at: 1,
    })
    .expect("seed artifact cache");

    let local_caches = Arc::new(RwLock::new(BTreeMap::new()));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
        trusted_publisher_pubkey,
        manifest_source: PoiArtifactManifestSource::Url(manifest_url.clone()),
        gateway_urls: vec![manifest_url],
        max_manifest_age: None,
    });
    cfg.local_poi_caches = Some(Arc::clone(&local_caches));

    let handle = spawn_startup_artifact_poi_cache_warmup(
        Arc::clone(&db),
        None,
        cfg,
        vec![list_key],
        BTreeMap::new(),
    )
    .expect("startup warmup spawned");
    handle.await.expect("startup warmup joined");

    let request = requests
        .recv_timeout(Duration::from_secs(1))
        .expect("manifest request");
    assert!(request.starts_with("GET / HTTP/1.1"));
    let locked = local_caches.read().await;
    let mut warmed = locked.get(&list_key).expect("warmed local cache").clone();
    assert_eq!(warmed.current_roots().get(&0), Some(&expected_root));
    let persisted = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read persisted artifact cache")
        .expect("persisted artifact cache");
    assert_eq!(persisted.last_accepted_manifest_sequence, 7);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_installs_persisted_artifact_cache_before_warmup() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut cache = PoiCache::new(identity.clone());
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x44; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    let expected_root = *cache.current_roots().get(&0).expect("current root");
    cache.accept_current_roots();

    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let base_descriptor = ArtifactDescriptor::from_bytes("bafybase", b"");
    let blocked_descriptor = ArtifactDescriptor::from_bytes("bafyblocked", b"");
    db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key,
        last_accepted_manifest_sequence: 6,
        base_descriptor: descriptor_record(&base_descriptor),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: descriptor_record(&blocked_descriptor),
        current_tip_index: 0,
        current_tip_root: expected_root,
        cache_payload: cache.to_bytes().expect("cache payload"),
        updated_at: 1,
    })
    .expect("seed artifact cache");

    let local_caches = Arc::new(RwLock::new(BTreeMap::new()));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        max_manifest_age: None,
    });
    cfg.local_poi_caches = Some(Arc::clone(&local_caches));

    assert!(!local_poi_caches_available_for_lists(&cfg, &[list_key]).await);
    let installed = install_persisted_local_poi_caches(db.as_ref(), &cfg, &[list_key]).await;

    assert_eq!(installed.len(), 1);
    assert!(installed.contains_key(&list_key));
    assert!(local_poi_caches_available_for_lists(&cfg, &[list_key]).await);
    let locked = local_caches.read().await;
    let mut installed_cache = locked.get(&list_key).expect("installed cache").clone();
    assert_eq!(
        installed_cache.current_roots().get(&0),
        Some(&expected_root)
    );
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn descriptor_record(descriptor: &ArtifactDescriptor) -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: descriptor.cid.clone(),
        sha256: descriptor.sha256.clone(),
        byte_size: descriptor.byte_size,
    }
}

#[tokio::test]
async fn poi_proxy_status_refresh_calls_remote_pois_per_list_without_local_ingestion() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mock = spawn_poi_rpc(serde_json::json!({
        hex::encode_prefixed(blinded_commitment): {
            hex::encode(list_key): "Valid",
        }
    }))
    .await;
    let remote_client = PoiRpcClient::new(mock.url.clone());
    let mut cfg = wallet_config(U256::ZERO);
    cfg.poi_read_source = PoiReadSource::PoiProxy;
    cfg.local_poi_caches = Some(Arc::new(RwLock::new(BTreeMap::new())));
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp db");

    let changed = refresh_wallet_poi_statuses_selected_with_config(
        &remote_client,
        &db,
        None,
        &cfg,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote status request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_proxy_merkle_proof_source_calls_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mock = spawn_poi_rpc(serde_json::json!([{
        "leaf": hex::encode_prefixed(blinded_commitment),
        "elements": [],
        "indices": "0x00",
        "root": "0x00",
    }]))
    .await;
    let client = PoiRpcClient::new(mock.url.clone());

    let proofs = client
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("remote proof response");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote proof request");
    assert_eq!(request["method"], "ppoi_merkle_proofs");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, hex::encode_prefixed(blinded_commitment));
}

#[tokio::test]
async fn local_poi_merkle_proof_source_reads_cache_without_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let proofs = source
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("local proof");

    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, hex::encode_prefixed(blinded_commitment));
}

#[tokio::test]
async fn local_output_poi_proof_preflight_fails_before_expensive_recovery_when_cache_missing() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache.accept_current_roots();
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let failure = preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect_err("missing local proof preflight should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(failure.message.contains("missing POI cache proof data"));
    assert_eq!(
        failure.retry_after,
        Some(OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    );
}

#[tokio::test]
async fn local_output_poi_proof_preflight_checks_transaction_inputs() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply input POI event");
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect("input proof preflight succeeds");
}

#[tokio::test]
async fn live_poi_tail_applies_public_events_and_validates_root() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let blinded_commitment = FixedBytes::from([0x33; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let mut signed_event = SignedPoiEvent {
        index: 1,
        blinded_commitment: hex::encode_prefixed(blinded_commitment),
        signature: String::new(),
        event_type: PoiEventType::Transact,
    };
    signed_event.signature = hex::encode(
        signing_key
            .sign(&poi::artifacts::verify::canonical_poi_event_message(
                &signed_event,
            ))
            .to_bytes(),
    );
    let signature: [u8; 64] = hex::decode(&signed_event.signature)
        .expect("signature hex")
        .try_into()
        .expect("signature length");
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact checkpoint event");
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: signed_event.index,
            blinded_commitment: *blinded_commitment,
            signature,
            event_type: signed_event.event_type,
        }])
        .expect("apply expected event");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let events = vec![PoiSyncedListEvent {
        signed_poi_event: signed_event,
        validated_merkleroot: hex::encode_prefixed(expected_root),
    }];
    let mock = spawn_poi_rpc(serde_json::to_value(events).expect("events JSON")).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact checkpoint event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote event request");
    assert_eq!(request["method"], "ppoi_poi_events");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    let proof = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect("proof after live root validation");
    assert_eq!(proof[0].leaf, hex::encode_prefixed(blinded_commitment));
}

#[test]
fn dense_merkle_tree_matches_forest_proof_and_removal_roots() {
    let mut forest = MerkleForest::default();
    for position in [0_u64, 1, 2, 7, 8, 9, 42] {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: position,
                hash: U256::from(position + 100),
            })
            .expect("insert leaf");
    }

    let mut dense = DenseMerkleTree::from_forest_prefix(&forest, 0, 43);
    let dense_proof = dense.prove(7);
    let sparse_proof = forest
        .prove_with_leaf_count(0, 7, 43)
        .expect("sparse proof");
    assert_eq!(dense_proof.root, sparse_proof.root);
    assert_eq!(dense_proof.leaf, sparse_proof.leaf);
    assert_eq!(dense_proof.path_elements, sparse_proof.path_elements);
    assert_eq!(dense_proof.path_indices, sparse_proof.path_indices);

    for position in (10_u64..43).rev() {
        dense.remove_leaf(position);
    }
    let dense_short_proof = dense.prove(7);
    let sparse_short_proof = forest
        .prove_with_leaf_count(0, 7, 10)
        .expect("sparse short proof");
    assert_eq!(dense_short_proof.root, sparse_short_proof.root);
    assert_eq!(
        dense_short_proof.path_elements,
        sparse_short_proof.path_elements
    );
}

#[tokio::test]
async fn tailed_cache_install_skips_when_current_cache_advanced() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let initial_commitment = FixedBytes::from([0x22; 32]);
    let stale_tail_commitment = FixedBytes::from([0x33; 32]);
    let current_tail_commitment = FixedBytes::from([0x44; 32]);

    let mut initial_cache = PoiCache::new(identity);
    initial_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *initial_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply initial event");
    initial_cache.accept_current_roots();
    let original_next_event_index = initial_cache.progress().next_event_index;

    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(
        list_key,
        initial_cache.clone(),
    )])));
    let mut stale_tail_cache = initial_cache;
    stale_tail_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *stale_tail_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply stale tail event");

    {
        let mut locked = local_caches.write().await;
        let current = locked.get_mut(&list_key).expect("current cache");
        current
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *current_tail_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("advance current cache");
        current.accept_current_roots();
    }

    let installed = install_tailed_poi_cache_if_current(
        &local_caches,
        list_key,
        stale_tail_cache,
        original_next_event_index,
    )
    .await;

    let locked = local_caches.read().await;
    let current = locked.get(&list_key).expect("current cache");
    assert!(!installed);
    assert!(current.position(&current_tail_commitment).is_some());
    assert!(current.position(&stale_tail_commitment).is_none());
}

#[tokio::test]
async fn poi_status_refresh_needed_after_indexed_delta_discovers_utxo() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let cfg = wallet_config(U256::ZERO);
    let mut wallet_utxos = Vec::new();
    let delta = WalletLogDelta {
        utxos: vec![test_wallet_utxo(1).utxo],
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
    };

    assert!(apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta));
    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[test]
fn stale_missing_poi_status_is_refresh_needed_after_ttl() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo(1);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(!wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs() - 1,
        },
    ));
    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_transact_missing_without_pending_context_is_timer_retryable() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Transact);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_shield_missing_remains_timer_retryable_without_pending_context() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[tokio::test]
async fn forced_recoverable_poi_refresh_batches_missing_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut missing_one = test_wallet_utxo(1);
    missing_one
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_one.utxo.poi.refreshed_at = Some(100);
    let mut missing_two = test_wallet_utxo(2);
    missing_two
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_two.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, missing_one, missing_two];

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::Recoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert!(
        wallet_utxos
            .iter()
            .all(|wallet_utxo| wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys))
    );
}

#[tokio::test]
async fn required_or_recoverable_poi_refresh_skips_currently_valid_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut missing = test_wallet_utxo(2);
    missing
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, valid_without_refresh_time, missing];

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, Some(100));
    assert!(wallet_utxos[1].utxo.poi.refreshed_at.is_some());
    assert_eq!(
        wallet_utxos[2].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
}

#[tokio::test]
async fn poi_status_refresh_timestamp_only_update_is_changed() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut wallet_utxos = vec![valid_without_refresh_time];

    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[tokio::test]
async fn poi_status_refresh_keeps_failed_chunks_unknown() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(client.calls().len(), 2);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Unknown)
    );
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, None);
    assert_eq!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .refreshed_at
            .is_some()
    );
}

#[tokio::test]
async fn pending_output_poi_matches_undecryptable_observation_and_marks_submitted() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x44; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(&store, chain_id, &[observation], Some(&submitter))
        .await;

    let loaded = store
        .get_pending_output_poi_context(chain_id, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    let observed = loaded.observation.expect("observation recorded");
    assert_eq!(observed.output_tree, 12);
    assert_eq!(observed.output_position, 34);
    assert_eq!(observed.tx_hash, source(8).tx_hash);
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 12, 34)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_pending_output_poi_uses_transact_proof_submission() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    record.txid_merkleroot_index = Some(105_572);
    let expected_blinded_commitment = record
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .expect("list")
        .values()
        .next()
        .expect("poi")
        .blinded_commitments_out[0];
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(&store, chain_id, &[observation], Some(&submitter))
        .await;

    let loaded = store
        .get_pending_output_poi_context(chain_id, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(
        submitter.calls(),
        vec![(expected_blinded_commitment, 105_572, 0)]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_matches_wallet_owned_observation_and_keeps_utxo() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let utxo = test_wallet_utxo(36).utxo;
    let output_commitment = FixedBytes::from(utxo.note.commitment().to_be_bytes::<32>());
    let list_key = FixedBytes::from([0x46; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: utxo.tree,
        position: utxo.position,
        commitment: utxo.note.commitment(),
        source: source(10),
    };
    let delta = WalletLogDelta {
        utxos: vec![utxo],
        nullifiers: Vec::new(),
        commitment_observations: vec![observation],
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        &delta.commitment_observations,
        Some(&submitter),
    )
    .await;
    let mut wallet_utxos = Vec::new();
    let changed = apply_wallet_delta_to_vec(&wallet_config(U256::ZERO), &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos.len(), 1);
    assert_eq!(wallet_utxos[0].utxo.position, 36);
    let loaded = store
        .get_pending_output_poi_context(chain_id, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert!(loaded.observation.is_some());
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 2, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_deletes_valid_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x90; 32]);
    let list_key = FixedBytes::from([0x91; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 12,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();

    let outcome =
        verify_submitted_pending_output_pois(&client, &store, chain_id, &[list_key]).await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending")
            .is_none()
    );
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, vec![list_key]);
    assert_eq!(calls[0].1[0].blinded_commitment, derived_blinded_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_allows_retry_after_missing_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x92; 32]);
    let list_key = FixedBytes::from([0x93; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 13,
        tx_hash: source(13).tx_hash,
        block_number: 13,
        block_timestamp: 1_700_000_013,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();
    client.set_default_status(PoiStatus::Missing);

    let outcome =
        verify_submitted_pending_output_pois(&client, &store, chain_id, &[list_key]).await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 1);
    let mut recovery = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.next_retry_at.is_some());
    recovery.next_retry_at = Some(0);
    store
        .put_output_poi_recovery(&recovery)
        .expect("force retry due");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations_inner(&store, chain_id, &[], Some(&submitter), false)
        .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 3, 13)]);
    let updated = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load updated recovery")
        .expect("recovery present");
    assert!(updated.next_retry_at.is_some_and(|next| next > 0));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_pending_verification_uses_local_cache_without_remote_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x94; 32]);
    let list_key = FixedBytes::from([0x95; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 14,
        tx_hash: source(14).tx_hash,
        block_number: 14,
        block_timestamp: 1_700_000_014,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[hex::encode_prefixed(derived_blinded_commitment)])
        .expect("apply local POI leaf");
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("artifact URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        max_manifest_age: None,
    });
    cfg.local_poi_caches = Some(local_caches);
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let remote_client = PoiRpcClient::new(mock.url.clone());

    let outcome =
        verify_submitted_pending_output_pois_with_config(&remote_client, &cfg, &store, &[list_key])
            .await;

    assert_eq!(outcome.completed, 1);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending")
            .is_none()
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_submission_failure_remains_retryable() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x78; 32]);
    let list_key = FixedBytes::from([0x45; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    submitter.fail_next();
    let observation = CommitmentObservation {
        tree: 13,
        position: 35,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(9),
    };

    process_pending_output_poi_observations(&store, chain_id, &[observation], Some(&submitter))
        .await;
    let failed = store
        .get_pending_output_poi_context(chain_id, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert!(failed.observation.is_some());
    assert!(failed.submitted_poi_list_keys.is_empty());
    assert!(failed.terminal_error.is_none());

    process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;

    let retried = store
        .get_pending_output_poi_context(chain_id, &output_commitment)
        .expect("load retried pending context")
        .expect("pending context present");
    assert_eq!(retried.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls().len(), 2);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_after_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 14,
        output_position: 36,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(0),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;

    let loaded = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery state")
        .expect("recovery state present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::Submitted);
    assert!(loaded.last_submission_at.is_some());
    assert!(loaded.next_retry_at.is_some_and(|next| next > 0));
    assert_eq!(submitter.calls(), vec![(output_commitment, 14, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_when_forced_before_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x7a; 32]);
    let list_key = FixedBytes::from([0x48; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 15,
        output_position: 37,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(u64::MAX),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(&store, chain_id, &[], Some(&submitter)).await;
    assert!(submitter.calls().is_empty());

    process_pending_output_poi_observations_inner(&store, chain_id, &[], Some(&submitter), true)
        .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 15, 37)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_poi_context_matches_wallet_output_identity() {
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x49; 32]);
    let wallet_utxo = test_wallet_utxo(38);
    let record = matching_pending_output_record(&cfg, &wallet_utxo, list_key);

    assert_ne!(record.wallet_id, cfg.cache_key);

    assert!(pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &record
    ));

    let mut wrong_position = record.clone();
    wrong_position
        .observation
        .as_mut()
        .expect("observation")
        .output_position += 1;
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_position
    ));

    let mut wrong_npk = record;
    wrong_npk.output_npk = FixedBytes::from([0x88; 32]);
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_npk
    ));
}

#[tokio::test]
async fn force_resubmits_matching_pending_output_despite_permanent_recovery_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4a; 32]);
    let mut wallet_utxo = test_wallet_utxo(39);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            wallet_utxo.utxo.poi.commitment,
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            None,
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.last_submission_at.is_some());
    assert!(recovery.next_retry_at.is_some());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmitted_recovered_pending_output_uses_pending_retry_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4c; 32]);
    let mut wallet_utxo = test_wallet_utxo(41);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.wallet_id.clone_from(&cfg.cache_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    let last_submission_at = recovery
        .last_submission_at
        .expect("last submission timestamp");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(recovery.attempt_count, 1);
    assert_eq!(
        recovery.next_retry_at,
        Some(last_submission_at + PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER.as_secs())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_ignores_nonmatching_pending_output_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4b; 32]);
    let mut wallet_utxo = test_wallet_utxo(40);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.output_npk = FixedBytes::from([0x89; 32]);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 0);
    assert!(submitter.calls().is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_retry_skips_permanent_statuses() {
    let due = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x80; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(10),
    );
    assert!(due.retry_allowed(11, false));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x81; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, false));

    let missing_inputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x82; 32]),
        OutputPoiRecoveryStatus::MissingWalletInputs,
        None,
    );
    assert!(!missing_inputs.retry_allowed(11, false));

    let valid = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::Valid,
        Some(0),
    );
    assert!(!valid.retry_allowed(11, false));
}

#[test]
fn forced_output_poi_recovery_retry_ignores_future_retry_for_retryable_status() {
    let future = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(999_999),
    );
    assert!(!future.retry_allowed(11, false));
    assert!(future.retry_allowed(11, true));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x84; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, true));
}

#[test]
fn failed_full_persist_forces_next_no_change_batch_to_store_snapshot() {
    let cache_store = RecordingCacheStore::default();
    cache_store.fail_next_store();
    let snapshot = Vec::new();
    let mut persist_state = WalletPersistState::default();

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: true,
                },
            )
            .is_err()
    );
    assert!(persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 11,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("retry full persist");
    assert!(persisted_full_snapshot);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 12,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("metadata-only persist");
    assert!(!persisted_full_snapshot);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 1);
}

#[test]
fn pending_cache_reset_blocks_metadata_only_until_reset_succeeds() {
    let cache_store = RecordingCacheStore::default();
    cache_store.fail_next_reset();
    let snapshot = Vec::new();
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(9),
    };

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: false,
                },
            )
            .is_err()
    );
    assert_eq!(persist_state.pending_cache_reset, Some(9));
    assert_eq!(cache_store.state().reset_calls, 1);
    assert_eq!(cache_store.state().store_calls, 0);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 10,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("reset then full persist");
    assert!(persisted_full_snapshot);
    assert_eq!(persist_state.pending_cache_reset, None);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().reset_calls, 2);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);
}

#[test]
fn notify_changed_increments_revision() {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let handle = WalletHandle {
        cache_key: "cache-key".to_string(),
        utxos: Arc::new(RwLock::new(Vec::new())),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        ready_rx,
        rev_rx,
        poi_refreshing_rx,
        poi_read_source: PoiReadSource::PoiProxy,
        local_poi_caches: None,
        poi_refresh_tx,
        rev_tx,
    };

    handle.notify_changed();
    assert_eq!(*handle.rev_rx.borrow(), 1);

    handle.notify_changed();
    assert_eq!(*handle.rev_rx.borrow(), 2);
}

#[tokio::test]
async fn wallet_handle_manual_poi_refresh_sends_forced_recovery_request() {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel::<WalletPoiRefreshRequest>(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let handle = WalletHandle {
        cache_key: "cache-key".to_string(),
        utxos: Arc::new(RwLock::new(Vec::new())),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        ready_rx,
        rev_rx,
        poi_refreshing_rx,
        poi_read_source: PoiReadSource::PoiProxy,
        local_poi_caches: None,
        poi_refresh_tx,
        rev_tx,
    };

    assert!(handle.refresh_poi_statuses().await);

    let request = poi_refresh_rx.recv().await.expect("refresh request");
    assert!(request.force_output_poi_recovery);
}

#[test]
fn spent_nullifiers_are_scoped_by_tree() {
    let nullifying_key = uint!(42_U256);
    let utxo_tree_one = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        1,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let utxo_tree_two = Utxo::new(
        utxo_tree_one.note.clone(),
        2,
        7,
        source(2),
        UtxoCommitmentKind::Transact,
    );
    let shared_nullifier = utxo_tree_one.nullifier(nullifying_key);
    let spent_source = source(9);
    let nullifier_sources = HashMap::from([((2, shared_nullifier), spent_source.clone())]);

    assert_eq!(
        spent_source_for_utxo(&utxo_tree_one, nullifying_key, &nullifier_sources,),
        None,
    );
    assert_eq!(
        spent_source_for_utxo(&utxo_tree_two, nullifying_key, &nullifier_sources),
        Some(spent_source),
    );
}

#[test]
fn indexed_delta_marks_matching_utxo_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let spent_source = source(9);
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos[0].spent, Some(spent_source));
}

#[test]
fn indexed_delta_reports_spent_output_commitment() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let output_commitment = utxo.poi.commitment;
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
    };

    let outcome = apply_wallet_delta_to_vec_with_outcome(&cfg, &mut wallet_utxos, delta);

    assert!(outcome.changed);
    assert_eq!(outcome.spent_output_commitments, vec![output_commitment]);
}

#[test]
fn pending_overlay_marks_matching_confirmed_utxo_pending_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let wallet_utxo = test_wallet_utxo(7);
    let nullifier = wallet_utxo.utxo.nullifier(nullifying_key);
    let spent_source = source(9);
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: wallet_utxo.utxo.tree,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
    };

    let overlay = pending_overlay_from_delta(&cfg, &[wallet_utxo], delta);

    assert!(overlay.new_utxos.is_empty());
    assert_eq!(overlay.pending_spent.len(), 1);
    assert_eq!(overlay.pending_spent[0].key(), (2, 7));
    assert_eq!(overlay.pending_spent[0].tx_hash, Some(spent_source.tx_hash));
    assert_eq!(
        overlay.pending_spent[0].block_number,
        Some(spent_source.block_number)
    );
}

#[tokio::test]
async fn local_pending_spent_expires_after_successful_overlay_refresh() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs().saturating_sub(LOCAL_PENDING_SPENT_TTL.as_secs() + 1);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert!(
        handle
            .pending_overlay()
            .await
            .local_pending_spent
            .is_empty()
    );
}

#[tokio::test]
async fn local_pending_spent_retains_recent_submissions() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert_eq!(handle.pending_overlay().await.local_pending_spent.len(), 1);
}

#[tokio::test]
async fn local_pending_spent_updates_existing_submitted_tx_hash() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let first_hash = FixedBytes::from([0x11; 32]);
    let replacement_hash = FixedBytes::from([0x22; 32]);

    handle
        .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(first_hash))
        .await;
    handle
        .mark_pending_spent_utxos(
            std::slice::from_ref(&wallet_utxo.utxo),
            Some(replacement_hash),
        )
        .await;

    let overlay = handle.pending_overlay().await;
    assert_eq!(overlay.local_pending_spent.len(), 1);
    assert_eq!(
        overlay.local_pending_spent[0].tx_hash,
        Some(replacement_hash)
    );
}

#[tokio::test]
async fn local_pending_spent_prunes_when_chain_pending_covers_key() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    let pending_spent = local_pending_spent_for(&wallet_utxo, submitted_at);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent.clone());
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay {
            pending_spent: vec![pending_spent],
            ..WalletPendingOverlay::default()
        })
        .await;

    let overlay = handle.pending_overlay().await;
    assert!(overlay.local_pending_spent.is_empty());
    assert_eq!(overlay.pending_spent.len(), 1);
}

#[tokio::test]
async fn local_pending_spent_prunes_when_confirmed_spent_covers_key() {
    let mut wallet_utxo = test_wallet_utxo(7);
    let pending_spent = local_pending_spent_for(&wallet_utxo, now_epoch_secs());
    wallet_utxo.spent = Some(source(9));
    let handle = test_wallet_handle(vec![wallet_utxo]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent);
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert!(
        handle
            .pending_overlay()
            .await
            .local_pending_spent
            .is_empty()
    );
}

#[tokio::test]
async fn clear_local_pending_spent_removes_manual_locks() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, now_epoch_secs()));
    }

    assert!(handle.clear_local_pending_spent().await);
    assert!(
        handle
            .pending_overlay()
            .await
            .local_pending_spent
            .is_empty()
    );
    assert!(!handle.clear_local_pending_spent().await);
}

#[test]
fn spent_output_discards_pending_output_poi_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x91; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            FixedBytes::from([0x92; 32]),
        ))
        .expect("store pending context");

    discard_pending_output_poi_contexts_for_spent_outputs(&store, chain_id, &[output_commitment]);

    assert!(
        store
            .get_pending_output_poi_context(chain_id, &output_commitment)
            .expect("load pending context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_candidates_skip_spent_utxos() {
    let list_key = FixedBytes::from([0x93; 32]);
    let mut spent = test_wallet_utxo(7);
    spent.utxo.poi.statuses.insert(list_key, PoiStatus::Missing);
    spent.spent = Some(source(9));
    let mut unspent = test_wallet_utxo(8);
    unspent
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let wallet_utxos = vec![spent, unspent];

    let candidates = output_poi_recovery_candidates(&wallet_utxos, &[list_key]);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].utxo.position, 8);
}

#[test]
fn indexed_delta_preserves_unmatched_utxo() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 3,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(!changed);
    assert!(wallet_utxos[0].spent.is_none());
}
