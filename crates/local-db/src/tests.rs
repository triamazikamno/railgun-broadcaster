use super::{
    CURRENT_SCHEMA_VERSION, DbConfig, DbStore, Meta, OutputPoiRecoveryRecord,
    OutputPoiRecoveryStatus, PendingFeeNoteAssuranceRecord, PendingOutputPoiContextRecord,
    PendingOutputPoiRole, WalletMeta,
};
use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::uint;
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-local-db-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn sample_record(chain_id: u64, public_tx_hash: FixedBytes<32>) -> PendingFeeNoteAssuranceRecord {
    PendingFeeNoteAssuranceRecord {
        chain_id,
        public_tx_hash,
        context: FeeNoteAssuranceContext {
            chain_type: 0,
            txid_version: "V3_PoseidonMerkle".to_string(),
            railgun_txid: uint!(5_U256),
            utxo_tree_in: 9,
            fee_commitment: FixedBytes::from([1u8; 32]),
            fee_note_npk: FixedBytes::from([2u8; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            required_poi_list_keys: vec![FixedBytes::from([4u8; 32])],
        },
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

fn sample_pending_output_record(
    chain_id: u64,
    output_commitment: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let list_key = FixedBytes::from([0x44; 32]);
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: "wallet-1".to_string(),
        txid_version: "V2_PoseidonMerkle".to_string(),
        output_commitment,
        output_npk: FixedBytes::from([0x66; 32]),
        utxo_tree_in: 9,
        railgun_txid: uint!(7_U256),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list_key, {
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))])
        })]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

#[test]
fn pending_fee_note_assurance_roundtrip_and_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(1, FixedBytes::from([0x11; 32]));
    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");

    let loaded = store
        .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("load assurance record")
        .expect("record present");
    assert_eq!(loaded.context.txid_version, record.context.txid_version);
    assert_eq!(loaded.context.railgun_txid, record.context.railgun_txid);
    assert_eq!(
        loaded.context.required_poi_list_keys,
        record.context.required_poi_list_keys
    );

    let records = store
        .list_pending_fee_note_assurance(record.chain_id)
        .expect("list pending assurance records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].public_tx_hash, record.public_tx_hash);

    assert!(
        store
            .list_terminal_fee_note_assurance(record.chain_id)
            .expect("list terminal assurance records")
            .is_empty()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn delete_pending_fee_note_assurance_removes_record() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(56, FixedBytes::from([0x22; 32]));
    let key = record.key();
    assert!(key.starts_with("56|"));

    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");
    store
        .delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("delete assurance record");

    assert!(
        store
            .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
            .expect("load deleted record")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn marking_fee_note_assurance_terminal_moves_record() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(99, FixedBytes::from([0x33; 32]));
    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");
    store
        .mark_fee_note_assurance_terminal(
            &record,
            super::FeeNoteAssuranceTerminalOutcome::CommitmentMismatch,
        )
        .expect("mark assurance record terminal");

    assert!(
        store
            .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
            .expect("load pending assurance record")
            .is_none()
    );
    assert!(
        store
            .list_pending_fee_note_assurance(record.chain_id)
            .expect("list pending assurance records")
            .is_empty()
    );

    let terminal = store
        .get_terminal_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("load terminal assurance record")
        .expect("terminal record present");
    assert_eq!(
        terminal.outcome,
        super::FeeNoteAssuranceTerminalOutcome::CommitmentMismatch
    );
    assert_eq!(terminal.context.railgun_txid, record.context.railgun_txid);

    let terminal_records = store
        .list_terminal_fee_note_assurance(record.chain_id)
        .expect("list terminal assurance records");
    assert_eq!(terminal_records.len(), 1);
    assert_eq!(terminal_records[0].public_tx_hash, record.public_tx_hash);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_poi_context_roundtrip_and_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_pending_output_record(1, FixedBytes::from([0x77; 32]));
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending output POI context");

    let loaded = store
        .get_pending_output_poi_context(record.chain_id, &record.output_commitment)
        .expect("load pending output POI context")
        .expect("record present");
    assert_eq!(loaded.wallet_id, record.wallet_id);
    assert_eq!(loaded.txid_version, record.txid_version);
    assert_eq!(loaded.output_npk, record.output_npk);
    assert_eq!(loaded.output_role, PendingOutputPoiRole::Recipient);
    assert_eq!(loaded.required_poi_list_keys, record.required_poi_list_keys);
    assert!(loaded.observation.is_none());
    assert!(loaded.submitted_poi_list_keys.is_empty());
    assert!(loaded.terminal_error.is_none());

    let records = store
        .list_pending_output_poi_contexts(record.chain_id)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);
    assert!(
        store
            .list_pending_output_poi_contexts(2)
            .expect("list other chain pending output POI contexts")
            .is_empty()
    );
    store
        .delete_pending_output_poi_context(record.chain_id, &record.output_commitment)
        .expect("delete pending output POI context");
    assert!(
        store
            .get_pending_output_poi_context(record.chain_id, &record.output_commitment)
            .expect("load deleted pending output POI context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_roundtrip_and_wallet_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = OutputPoiRecoveryRecord {
        chain_id: 1,
        wallet_id: "wallet-a".to_string(),
        output_commitment: FixedBytes::from([0x44; 32]),
        source_tx_hash: FixedBytes::from([0x55; 32]),
        tx_input: Some(vec![1, 2, 3]),
        status: OutputPoiRecoveryStatus::NotSelfOriginated,
        created_at: 10,
        updated_at: 20,
        last_detection_at: Some(20),
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 1,
        last_error: Some("external sender".to_string()),
    };
    let other_wallet = OutputPoiRecoveryRecord {
        wallet_id: "wallet-b".to_string(),
        output_commitment: FixedBytes::from([0x66; 32]),
        ..record.clone()
    };

    store
        .put_output_poi_recovery(&record)
        .expect("store recovery record");
    store
        .put_output_poi_recovery(&other_wallet)
        .expect("store other wallet recovery record");

    let loaded = store
        .get_output_poi_recovery(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("load recovery record")
        .expect("record present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::NotSelfOriginated);
    assert_eq!(loaded.source_tx_hash, record.source_tx_hash);
    assert_eq!(loaded.tx_input, record.tx_input);
    assert_eq!(loaded.last_error, record.last_error);

    let records = store
        .list_output_poi_recoveries(record.chain_id, &record.wallet_id)
        .expect("list wallet recovery records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn app_settings_records_are_transactional_plaintext_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    assert!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load missing settings")
            .is_none()
    );

    store
        .put_app_settings_record("wallet-settings", b"settings-v1")
        .expect("store settings");
    store
        .put_app_settings_record("other-settings", b"other")
        .expect("store other settings");

    assert_eq!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load settings")
            .expect("settings present"),
        b"settings-v1"
    );

    let records = store
        .list_app_settings_records("wallet")
        .expect("list settings records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key, "wallet-settings");
    assert_eq!(records[0].payload, b"settings-v1");

    store
        .delete_app_settings_record("wallet-settings")
        .expect("delete settings");
    assert!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load deleted settings")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn desktop_wallet_vault_records_are_isolated_by_prefix() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    store
        .put_desktop_wallet_vault_record("vault|meta", b"encrypted metadata")
        .expect("store metadata");
    store
        .put_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1", b"encrypted row 1")
        .expect("store row 1");
    store
        .put_desktop_wallet_vault_record("wallet-cache|opaque-b|row-2", b"encrypted row 2")
        .expect("store row 2");

    let meta = store
        .get_desktop_wallet_vault_record("vault|meta")
        .expect("load metadata")
        .expect("metadata present");
    assert_eq!(meta, b"encrypted metadata");

    assert!(
        !store
            .put_desktop_wallet_vault_record_if_absent("vault|meta", b"replacement")
            .expect("skip existing metadata")
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("vault|meta")
            .expect("load unchanged metadata")
            .expect("metadata present"),
        b"encrypted metadata"
    );
    assert!(
        store
            .put_desktop_wallet_vault_record_if_absent("vault|new", b"new metadata")
            .expect("insert missing metadata")
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("vault|new")
            .expect("load inserted metadata")
            .expect("metadata present"),
        b"new metadata"
    );

    let cache_a = store
        .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
        .expect("list cache records");
    assert_eq!(cache_a.len(), 1);
    assert_eq!(cache_a[0].key, "wallet-cache|opaque-a|row-1");
    assert_eq!(cache_a[0].payload, b"encrypted row 1");

    store
        .put_desktop_wallet_vault_records(&[
            (
                "wallet-cache|opaque-a|row-3".to_string(),
                b"encrypted row 3".to_vec(),
            ),
            (
                "wallet-chain-meta|opaque-a".to_string(),
                b"metadata".to_vec(),
            ),
        ])
        .expect("batch put cache records");
    let cache_a = store
        .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
        .expect("list updated cache records");
    assert_eq!(cache_a.len(), 2);
    assert!(
        store
            .get_desktop_wallet_vault_record("wallet-chain-meta|opaque-a")
            .expect("load metadata")
            .is_some()
    );

    store
        .replace_desktop_wallet_vault_prefix_with_records(
            "wallet-cache|opaque-a|",
            &[(
                "wallet-chain-meta|opaque-a".to_string(),
                b"reset-meta".to_vec(),
            )],
        )
        .expect("replace cache prefix");
    assert!(
        store
            .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
            .expect("list reset cache records")
            .is_empty()
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("wallet-chain-meta|opaque-a")
            .expect("load reset metadata")
            .expect("metadata present"),
        b"reset-meta"
    );

    store
        .delete_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1")
        .expect("delete cache record");
    assert!(
        store
            .get_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1")
            .expect("load deleted cache record")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn reopen_older_schema_db_backs_up_and_recreates() {
    let root_dir = temp_db_root();
    let wallet_id = "wallet-1";

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");

        let wallet_meta = WalletMeta {
            last_scanned_block: 42,
            updated_at: 99,
            last_scanned_block_hash: Some([7u8; 32]),
        };
        store
            .put_wallet_meta(wallet_id, &wallet_meta)
            .expect("write wallet meta");

        store
            .write_meta(&Meta {
                schema_version: 3,
                app_version: "0.0.0".to_string(),
                created_at: 123,
            })
            .expect("write schema-3 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");

    assert!(
        reopened
            .get_wallet_meta(wallet_id)
            .expect("load wallet meta")
            .is_none()
    );

    let meta = reopened
        .read_meta()
        .expect("read meta")
        .expect("meta present");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION);
    assert!(
        fs::read_dir(root_dir.join("railgun"))
            .expect("read railgun dir")
            .any(|entry| entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak."))
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
