use super::*;
use alloy::uint;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const TEST_PASSWORD: &str = "correct horse battery staple";
const TEST_WALLET_ID: &str = "wallet-1";
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const IMPORT_PRIVATE_KEY_ONE: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";
const IMPORT_PRIVATE_KEY_TWO: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000002";
static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_kdf() -> KdfParams {
    KdfParams::new(1024, 1, 1)
}

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-vault-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn desktop_store_with_vault() -> (PathBuf, Arc<DbStore>, DesktopVaultStore) {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    (root_dir, db, store)
}

fn import_wallet_with_metadata(
    store: &DesktopVaultStore,
    wallet_id: &str,
    label: &str,
) -> DesktopViewSession {
    let metadata = store
        .new_wallet_metadata(TEST_PASSWORD, wallet_id, 0, WalletSource::Imported, label)
        .expect("wallet metadata");
    store
        .import_wallet_mnemonic_with_metadata(
            TEST_PASSWORD,
            wallet_id,
            0,
            "english",
            TEST_MNEMONIC,
            &metadata,
        )
        .expect("import wallet with metadata");
    store
        .load_view_session(TEST_PASSWORD, wallet_id)
        .expect("load view session")
}

#[derive(Serialize)]
struct LegacyWalletMetadataBundle {
    wallet_uuid: String,
    label: String,
    derivation_index: u32,
}

#[test]
fn create_and_unlock_view() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let unlocked = unlock_view(&created.metadata, TEST_PASSWORD).expect("unlock view");

    let record = unlocked
        .encrypt_record(
            RecordKind::WalletChainMetadata,
            TEST_WALLET_ID,
            b"chain metadata",
        )
        .expect("encrypt");
    let plaintext = unlocked
        .decrypt_record(RecordKind::WalletChainMetadata, TEST_WALLET_ID, &record)
        .expect("decrypt");

    assert_eq!(&*plaintext, b"chain metadata");
}

#[test]
fn desktop_vault_store_persists_metadata() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");

    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let loaded = store.metadata().expect("load metadata");
    let unlocked = unlock_view(&loaded, TEST_PASSWORD).expect("unlock loaded metadata");
    let record = unlocked
        .encrypt_record(
            RecordKind::WalletChainMetadata,
            TEST_WALLET_ID,
            b"chain metadata",
        )
        .expect("encrypt");

    assert_eq!(loaded.version, current_vault_version());
    assert_eq!(loaded.kdf, test_kdf());
    assert!(
        unlocked
            .decrypt_record(RecordKind::WalletChainMetadata, TEST_WALLET_ID, &record)
            .is_ok()
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn create_vault_does_not_overwrite_existing_metadata() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));

    let created = store
        .create_vault_with_params(TEST_PASSWORD, test_kdf())
        .expect("create vault");
    assert!(matches!(
        store.create_vault_with_params("different password", test_kdf()),
        Err(VaultError::VaultAlreadyExists)
    ));

    let loaded = store.metadata().expect("load metadata");
    assert_eq!(loaded, created.metadata);
    assert!(store.unlock_view(TEST_PASSWORD).is_ok());

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn imported_wallet_stores_encrypted_view_and_spend_bundles() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_id = "opaque-wallet-id";

    let stored = store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let view_payload = db
        .get_desktop_wallet_vault_record(&stored.view_record_key)
        .expect("load view record")
        .expect("view record present");
    let spend_payload = db
        .get_desktop_wallet_vault_record(&stored.spend_record_key)
        .expect("load spend record")
        .expect("spend record present");
    let view_bundle = store
        .load_view_bundle(TEST_PASSWORD, wallet_id)
        .expect("load view bundle");
    let mut grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("create grant");
    let spend_bundle = store
        .load_spend_bundle(&mut grant, wallet_id)
        .expect("load spend bundle");

    assert_eq!(view_bundle.derivation_index, 0);
    assert_eq!(spend_bundle.derivation_index, 0);
    assert_eq!(spend_bundle.bip39_language, "english");
    assert_eq!(
        spend_bundle.bip39_entropy,
        bip39_entropy_from_mnemonic(mnemonic).expect("mnemonic entropy")
    );
    assert!(!contains_subsequence(&view_payload, mnemonic.as_bytes()));
    assert!(!contains_subsequence(&spend_payload, mnemonic.as_bytes()));

    grant.invalidate();
    assert!(matches!(
        store.load_spend_bundle(&mut grant, wallet_id),
        Err(VaultError::InvalidSpendGrant)
    ));
    let mut fresh_grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("create fresh grant");
    assert!(store.load_spend_bundle(&mut fresh_grant, wallet_id).is_ok());

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_with_metadata_stores_records_in_one_batch() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let seed = generate_seed_material().expect("generate seed");
    let wallet_id = "wallet-with-metadata";
    let metadata = WalletMetadataBundle {
        wallet_uuid: wallet_id.to_string(),
        label: "Primary wallet".to_string(),
        derivation_index: 0,
        source: WalletSource::Generated,
        status: WalletStatus::Active,
        display_order: 0,
    };

    let stored = store
        .store_generated_wallet_with_metadata(
            TEST_PASSWORD,
            wallet_id,
            0,
            "english",
            &seed,
            &metadata,
        )
        .expect("store wallet with metadata");

    assert!(
        db.get_desktop_wallet_vault_record(&stored.view_record_key)
            .expect("load view record")
            .is_some()
    );
    assert!(
        db.get_desktop_wallet_vault_record(&stored.spend_record_key)
            .expect("load spend record")
            .is_some()
    );
    let loaded = store
        .load_wallet_metadata(TEST_PASSWORD, wallet_id)
        .expect("load wallet metadata");
    assert_eq!(loaded.wallet_uuid, wallet_id);
    assert_eq!(loaded.label, "Primary wallet");
    assert_eq!(loaded.derivation_index, 0);

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_account_import_encrypts_secret_and_delete_removes_records() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session = import_wallet_with_metadata(&store, "public-secret-wallet", "Public A");
    let account = store
        .import_public_account(
            TEST_PASSWORD,
            &view_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("  Hot account  "),
            false,
        )
        .expect("import public account");
    let private_key = parse_public_evm_private_key(IMPORT_PRIVATE_KEY_ONE).expect("private key");
    let metadata_payload = db
        .get_desktop_wallet_vault_record(&public_account_metadata_record_key(
            &account.public_account_uuid,
        ))
        .expect("load public metadata record")
        .expect("public metadata record present");
    let secret_payload = db
        .get_desktop_wallet_vault_record(&public_account_secret_record_key(
            &account.public_account_uuid,
        ))
        .expect("load public secret record")
        .expect("public secret record present");
    let secret_record: EncryptedRecord =
        rmp_serde::from_slice(&secret_payload).expect("decode secret record");

    assert_eq!(account.label.as_deref(), Some("Hot account"));
    assert!(!contains_subsequence(&metadata_payload, b"Hot account"));
    assert!(!contains_subsequence(&metadata_payload, &*private_key));
    assert!(!contains_subsequence(&secret_payload, &*private_key));
    assert!(
        view_session
            .view
            .decrypt_record(
                RecordKind::PublicAccountSecret,
                &account.public_account_uuid,
                &secret_record,
            )
            .is_err()
    );

    let mut grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("create spend grant");
    let signing_key = store
        .public_account_signing_key(&mut grant, &view_session, &account.public_account_uuid)
        .expect("imported signing key");
    assert_eq!(&*signing_key, &*private_key);

    let deleted = store
        .delete_imported_public_account(&view_session, &account.public_account_uuid)
        .expect("delete imported account");
    assert_eq!(deleted.public_account_uuid, account.public_account_uuid);
    assert!(
        db.get_desktop_wallet_vault_record(&public_account_metadata_record_key(
            &account.public_account_uuid,
        ))
        .expect("load deleted metadata")
        .is_none()
    );
    assert!(
        db.get_desktop_wallet_vault_record(&public_account_secret_record_key(
            &account.public_account_uuid,
        ))
        .expect("load deleted secret")
        .is_none()
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn address_books_persist_encrypted_and_load_without_spend_unlock() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session = import_wallet_with_metadata(&store, "address-book-wallet", "Address Book");
    let private_address = railgun_recipient_for_derivation(7);
    let public_address = "0x1111111111111111111111111111111111111111";

    assert!(
        store
            .list_private_address_book_entries_for_session(&view_session)
            .expect("empty private address book")
            .is_empty()
    );
    assert!(
        store
            .list_public_address_book_entries_for_session(&view_session)
            .expect("empty public address book")
            .is_empty()
    );

    let private_entry = store
        .add_private_address_book_entry_for_session(
            &view_session,
            "  Private friend  ",
            &private_address,
        )
        .expect("save private address book entry");
    let public_entry = store
        .add_public_address_book_entry_for_session(
            &view_session,
            "  Public friend  ",
            public_address,
        )
        .expect("save public address book entry");
    let private_payload = db
        .get_desktop_wallet_vault_record(&private_address_book_record_key(
            &private_entry.entry_uuid,
        ))
        .expect("load private address book record")
        .expect("private address book record present");
    let public_payload = db
        .get_desktop_wallet_vault_record(&public_address_book_record_key(&public_entry.entry_uuid))
        .expect("load public address book record")
        .expect("public address book record present");

    assert_eq!(private_entry.label, "Private friend");
    assert_eq!(private_entry.address, private_address);
    assert_eq!(private_entry.display_order, 0);
    assert_eq!(public_entry.label, "Public friend");
    assert_eq!(public_entry.address.to_checksum(None), public_address);
    assert_eq!(public_entry.display_order, 0);
    assert!(!contains_subsequence(&private_payload, b"Private friend"));
    assert!(!contains_subsequence(
        &private_payload,
        private_address.as_bytes()
    ));
    assert!(!contains_subsequence(&public_payload, b"Public friend"));
    assert!(!contains_subsequence(&public_payload, b"1111111111111111"));

    drop(store);
    drop(db);

    let reopened = DesktopVaultStore::open(root_dir.clone()).expect("reopen vault store");
    let reloaded_session = reopened
        .load_view_session(TEST_PASSWORD, view_session.wallet_id())
        .expect("reload view session");
    let private_entries = reopened
        .list_private_address_book_entries_for_session(&reloaded_session)
        .expect("reload private address book without spend unlock");
    let public_entries = reopened
        .list_public_address_book_entries_for_session(&reloaded_session)
        .expect("reload public address book without spend unlock");

    assert_eq!(private_entries, vec![private_entry]);
    assert_eq!(public_entries, vec![public_entry]);

    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn address_book_validation_rejects_invalid_labels_addresses_and_duplicates() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session =
        import_wallet_with_metadata(&store, "address-book-validation", "Address Book");
    let private_address = railgun_recipient_for_derivation(8);
    let public_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    assert!(matches!(
        store.add_private_address_book_entry_for_session(&view_session, "   ", &private_address),
        Err(VaultError::InvalidAddressBookLabel)
    ));
    assert!(matches!(
        store.add_private_address_book_entry_for_session(
            &view_session,
            "Invalid private",
            "not-a-0zk-address",
        ),
        Err(VaultError::InvalidPrivateAddressBookAddress)
    ));
    let private_entry = store
        .add_private_address_book_entry_for_session(&view_session, "Private", &private_address)
        .expect("save private address book entry");
    assert!(matches!(
        store.add_private_address_book_entry_for_session(
            &view_session,
            "Private duplicate",
            &private_entry.address,
        ),
        Err(VaultError::DuplicatePrivateAddressBookAddress)
    ));
    assert!(matches!(
        store.add_private_address_book_entry_for_session(
            &view_session,
            "Active private wallet",
            &view_session.receive_address().expect("receive address"),
        ),
        Err(VaultError::DuplicatePrivateAddressBookAddress)
    ));

    assert!(matches!(
        store.add_public_address_book_entry_for_session(&view_session, "   ", public_address),
        Err(VaultError::InvalidAddressBookLabel)
    ));
    assert!(matches!(
        store.add_public_address_book_entry_for_session(
            &view_session,
            "Invalid public",
            "not-an-address",
        ),
        Err(VaultError::InvalidPublicAddressBookAddress)
    ));
    let public_entry = store
        .add_public_address_book_entry_for_session(&view_session, "Public", public_address)
        .expect("save public address book entry");
    assert!(matches!(
        store.add_public_address_book_entry_for_session(
            &view_session,
            "Public duplicate",
            &public_entry.address.to_checksum(None).to_ascii_uppercase(),
        ),
        Err(VaultError::DuplicatePublicAddressBookAddress)
    ));
    let active_public_address = store
        .list_active_public_accounts_for_session(&view_session)
        .expect("active public accounts")[0]
        .address
        .to_checksum(None);
    assert!(matches!(
        store.add_public_address_book_entry_for_session(
            &view_session,
            "Active public account",
            &active_public_address,
        ),
        Err(VaultError::DuplicatePublicAddressBookAddress)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_account_visibility_scope_duplicates_and_next_index() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let first_session = import_wallet_with_metadata(&store, "public-wallet-a", "Public A");
    let second_session = import_wallet_with_metadata(&store, "public-wallet-b", "Public B");
    let scoped = store
        .import_public_account(
            TEST_PASSWORD,
            &first_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("Scoped"),
            false,
        )
        .expect("import scoped account");
    let global = store
        .import_public_account(
            TEST_PASSWORD,
            &first_session,
            IMPORT_PRIVATE_KEY_TWO,
            Some("Global"),
            true,
        )
        .expect("import global account");

    let first_active = store
        .list_active_public_accounts_for_session(&first_session)
        .expect("first active accounts");
    let second_active = store
        .list_active_public_accounts_for_session(&second_session)
        .expect("second active accounts");
    assert!(
        first_active
            .iter()
            .any(|account| account.source == PublicAccountSource::Derived)
    );
    assert!(
        first_active
            .iter()
            .any(|account| account.public_account_uuid == scoped.public_account_uuid)
    );
    assert!(
        first_active
            .iter()
            .any(|account| account.public_account_uuid == global.public_account_uuid)
    );
    assert!(
        !second_active
            .iter()
            .any(|account| account.public_account_uuid == scoped.public_account_uuid)
    );
    assert!(
        second_active
            .iter()
            .any(|account| account.public_account_uuid == global.public_account_uuid)
    );

    assert!(matches!(
        store.import_public_account(
            TEST_PASSWORD,
            &first_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("Duplicate scoped"),
            false,
        ),
        Err(VaultError::DuplicatePublicAccountAddress)
    ));
    assert!(matches!(
        store.import_public_account(
            TEST_PASSWORD,
            &first_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("Duplicate global"),
            true,
        ),
        Err(VaultError::DuplicatePublicAccountAddress)
    ));
    assert!(matches!(
        store.import_public_account(
            TEST_PASSWORD,
            &second_session,
            IMPORT_PRIVATE_KEY_TWO,
            Some("Duplicate active global"),
            false,
        ),
        Err(VaultError::DuplicatePublicAccountAddress)
    ));

    let derived = store
        .add_derived_public_account(TEST_PASSWORD, &first_session, Some("Derived 1"))
        .expect("add derived account");
    assert_eq!(derived.derivation_index, Some(1));
    store
        .deactivate_derived_public_account(&first_session, &derived.public_account_uuid)
        .expect("deactivate derived account");
    let all_first_accounts = store
        .list_public_accounts_for_session(&first_session, true)
        .expect("first accounts including inactive");
    assert!(all_first_accounts.iter().any(|account| {
        account.public_account_uuid == derived.public_account_uuid
            && account.status == PublicAccountStatus::Inactive
    }));
    let relabeled_inactive = store
        .update_public_account_label(
            &first_session,
            &derived.public_account_uuid,
            Some("Inactive derived"),
        )
        .expect("edit inactive derived label");
    assert_eq!(relabeled_inactive.status, PublicAccountStatus::Inactive);
    assert_eq!(
        relabeled_inactive.label.as_deref(),
        Some("Inactive derived")
    );
    assert_eq!(
        store
            .next_derived_public_account_index_for_session(&first_session)
            .expect("next derived index"),
        2
    );
    let next = store
        .add_derived_public_account(TEST_PASSWORD, &first_session, Some("Derived 2"))
        .expect("add next derived account");
    assert_eq!(next.derivation_index, Some(2));
    assert!(
        !store
            .list_active_public_accounts_for_session(&first_session)
            .expect("active after deactivate")
            .iter()
            .any(|account| account.public_account_uuid == derived.public_account_uuid)
    );
    let activated = store
        .activate_derived_public_account(&first_session, &derived.public_account_uuid)
        .expect("activate derived account");
    assert_eq!(activated.status, PublicAccountStatus::Active);
    assert!(
        store
            .list_active_public_accounts_for_session(&first_session)
            .expect("active after activate")
            .iter()
            .any(|account| account.public_account_uuid == derived.public_account_uuid)
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn inactive_derived_account_activate_rejects_active_duplicate() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session = import_wallet_with_metadata(&store, "activate-duplicate-wallet", "Public A");
    let derived = store
        .add_derived_public_account(TEST_PASSWORD, &view_session, Some("Derived 1"))
        .expect("add derived account");
    store
        .deactivate_derived_public_account(&view_session, &derived.public_account_uuid)
        .expect("deactivate derived account");
    let derived_private_key =
        derive_public_evm_private_key_from_mnemonic(TEST_MNEMONIC, 1).expect("derived key");
    let derived_private_key_hex = format!("0x{}", alloy::hex::encode(derived_private_key));
    store
        .import_public_account(
            TEST_PASSWORD,
            &view_session,
            &derived_private_key_hex,
            Some("Imported duplicate"),
            false,
        )
        .expect("import inactive derived duplicate");

    assert!(matches!(
        store.activate_derived_public_account(&view_session, &derived.public_account_uuid),
        Err(VaultError::DuplicatePublicAccountAddress)
    ));
    let inactive_accounts = store
        .list_public_accounts_for_session(&view_session, true)
        .expect("accounts including inactive");
    assert!(inactive_accounts.iter().any(|account| {
        account.public_account_uuid == derived.public_account_uuid
            && account.status == PublicAccountStatus::Inactive
    }));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_account_status_reads_legacy_hidden_as_inactive() {
    let status: PublicAccountStatus =
        serde_json::from_str("\"Hidden\"").expect("legacy hidden status");

    assert_eq!(status, PublicAccountStatus::Inactive);
    assert_eq!(
        serde_json::to_string(&status).expect("serialize inactive status"),
        "\"Inactive\"",
    );
}

#[test]
fn derived_duplicate_address_is_rejected() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session = import_wallet_with_metadata(&store, "derived-duplicate-wallet", "Public A");
    let derived_private_key =
        derive_public_evm_private_key_from_mnemonic(TEST_MNEMONIC, 1).expect("derived key");
    let derived_private_key_hex = format!("0x{}", alloy::hex::encode(derived_private_key));
    store
        .import_public_account(
            TEST_PASSWORD,
            &view_session,
            &derived_private_key_hex,
            Some("Imported index 1"),
            false,
        )
        .expect("import duplicate derived address");

    assert!(matches!(
        store.add_derived_public_account(TEST_PASSWORD, &view_session, Some("Derived 1")),
        Err(VaultError::DuplicatePublicAccountAddress)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_account_signing_key_resolves_derived_and_imported_accounts() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let view_session = import_wallet_with_metadata(&store, "public-signing-wallet", "Public A");
    let derived = store
        .list_active_public_accounts_for_session(&view_session)
        .expect("active accounts")
        .into_iter()
        .find(|account| account.source == PublicAccountSource::Derived)
        .expect("derived account");
    assert!(
        db.get_desktop_wallet_vault_record(&public_account_secret_record_key(
            &derived.public_account_uuid,
        ))
        .expect("load derived secret record")
        .is_none()
    );

    let mut derived_grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("derived spend grant");
    let derived_key = store
        .public_account_signing_key(
            &mut derived_grant,
            &view_session,
            &derived.public_account_uuid,
        )
        .expect("derived signing key");
    assert_eq!(
        public_evm_address_from_private_key(&derived_key).expect("derived address"),
        derived.address
    );
    assert!(!derived_grant.is_valid());

    let inactive = store
        .deactivate_derived_public_account(&view_session, &derived.public_account_uuid)
        .expect("deactivate derived account");
    let mut inactive_grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("inactive derived spend grant");
    let inactive_key = store
        .public_account_signing_key(
            &mut inactive_grant,
            &view_session,
            &inactive.public_account_uuid,
        )
        .expect("inactive derived signing key");
    assert_eq!(
        public_evm_address_from_private_key(&inactive_key).expect("inactive derived address"),
        inactive.address
    );
    assert!(!inactive_grant.is_valid());

    let imported = store
        .import_public_account(
            TEST_PASSWORD,
            &view_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("Imported"),
            false,
        )
        .expect("import account");
    let expected_private_key =
        parse_public_evm_private_key(IMPORT_PRIVATE_KEY_ONE).expect("private key");
    let mut imported_grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("imported spend grant");
    let imported_key = store
        .public_account_signing_key(
            &mut imported_grant,
            &view_session,
            &imported.public_account_uuid,
        )
        .expect("imported signing key");
    assert_eq!(&*imported_key, &*expected_private_key);
    assert!(!imported_grant.is_valid());

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_metadata_flows_auto_create_initial_public_account() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let generated_seed = generate_seed_material().expect("generate seed");
    let generated_wallet_id = "generated-public-wallet";
    let generated_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            generated_wallet_id,
            0,
            WalletSource::Generated,
            "Generated",
        )
        .expect("generated wallet metadata");
    store
        .store_generated_wallet_with_metadata(
            TEST_PASSWORD,
            generated_wallet_id,
            0,
            "english",
            &generated_seed,
            &generated_metadata,
        )
        .expect("store generated wallet with metadata");
    let generated_session = store
        .load_view_session(TEST_PASSWORD, generated_wallet_id)
        .expect("generated view session");
    let generated_accounts = store
        .list_active_public_accounts_for_session(&generated_session)
        .expect("generated public accounts");
    assert_eq!(generated_accounts.len(), 1);
    assert_eq!(generated_accounts[0].source, PublicAccountSource::Derived);
    assert_eq!(generated_accounts[0].label.as_deref(), Some("Account #1"));
    assert_eq!(generated_accounts[0].derivation_index, Some(0));
    assert_eq!(
        generated_accounts[0].address,
        derive_public_evm_address_from_entropy(generated_seed.entropy.as_slice(), 0)
            .expect("generated public address")
    );

    let imported_wallet_id = "imported-public-wallet";
    let imported_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            imported_wallet_id,
            0,
            WalletSource::Imported,
            "Imported",
        )
        .expect("imported wallet metadata");
    store
        .import_wallet_mnemonic_with_metadata(
            TEST_PASSWORD,
            imported_wallet_id,
            0,
            "english",
            TEST_MNEMONIC,
            &imported_metadata,
        )
        .expect("import wallet with metadata");
    let imported_session = store
        .load_view_session(TEST_PASSWORD, imported_wallet_id)
        .expect("imported view session");
    let imported_accounts = store
        .list_active_public_accounts_for_session(&imported_session)
        .expect("imported public accounts");
    let imported_entropy = bip39_entropy_from_mnemonic(TEST_MNEMONIC).expect("mnemonic entropy");
    assert_eq!(imported_accounts.len(), 1);
    assert_eq!(imported_accounts[0].source, PublicAccountSource::Derived);
    assert_eq!(imported_accounts[0].label.as_deref(), Some("Account #1"));
    assert_eq!(imported_accounts[0].derivation_index, Some(0));
    assert_eq!(
        imported_accounts[0].address,
        derive_public_evm_address_from_entropy(&imported_entropy, 0)
            .expect("imported public address")
    );

    let legacy_wallet_id = "metadata-less-public-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, legacy_wallet_id, 0, "english", TEST_MNEMONIC)
        .expect("import metadata-less wallet");
    let legacy_session = store
        .load_view_session(TEST_PASSWORD, legacy_wallet_id)
        .expect("legacy view session");
    assert!(
        store
            .list_active_public_accounts_for_session(&legacy_session)
            .expect("legacy public accounts")
            .is_empty()
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_metadata_listing_defaults_and_synthesizes_records() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let legacy_wallet_id = "legacy-wallet";
    let missing_wallet_id = "missing-metadata-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, legacy_wallet_id, 0, "english", mnemonic)
        .expect("import legacy wallet");
    store
        .import_wallet_mnemonic(TEST_PASSWORD, missing_wallet_id, 1, "english", mnemonic)
        .expect("import metadata-less wallet");

    let legacy = LegacyWalletMetadataBundle {
        wallet_uuid: legacy_wallet_id.to_string(),
        label: "Legacy wallet".to_string(),
        derivation_index: 0,
    };
    let view = store.unlock_view(TEST_PASSWORD).expect("unlock view");
    let record = encrypt_serialized(
        view.view_dek(),
        RecordKind::WalletMetadata,
        legacy_wallet_id,
        &legacy,
    )
    .expect("encrypt legacy metadata");
    let (key, payload) = record
        .to_record_entry(wallet_metadata_record_key(legacy_wallet_id))
        .expect("encode legacy metadata");
    db.put_desktop_wallet_vault_records(&[(key, payload)])
        .expect("store legacy metadata");

    let metadata = store
        .list_wallet_metadata(TEST_PASSWORD)
        .expect("list wallet metadata");
    let legacy = metadata
        .iter()
        .find(|metadata| metadata.wallet_uuid == legacy_wallet_id)
        .expect("legacy metadata");
    let synthesized = metadata
        .iter()
        .find(|metadata| metadata.wallet_uuid == missing_wallet_id)
        .expect("synthesized metadata");

    assert_eq!(metadata.len(), 2);
    assert_eq!(legacy.status, WalletStatus::Active);
    assert_eq!(legacy.display_order, 0);
    assert_eq!(synthesized.label, "Wallet 2");
    assert_eq!(synthesized.derivation_index, 1);
    assert_eq!(synthesized.status, WalletStatus::Active);
    assert_eq!(synthesized.display_order, 1);

    let persisted_legacy = store
        .load_wallet_metadata(TEST_PASSWORD, legacy_wallet_id)
        .expect("load persisted legacy metadata");
    let persisted_synthesized = store
        .load_wallet_metadata(TEST_PASSWORD, missing_wallet_id)
        .expect("load synthesized metadata");
    assert_eq!(persisted_legacy, legacy.clone());
    assert_eq!(persisted_synthesized, synthesized.clone());

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_label_validation_defaults_update_reorder_and_deactivate() {
    let (root_dir, db, store) = desktop_store_with_vault();
    assert_eq!(
        store
            .default_wallet_label(TEST_PASSWORD)
            .expect("default label"),
        PRIMARY_WALLET_LABEL
    );

    let seed = generate_seed_material().expect("generate seed");
    let first_wallet_id = "first-wallet";
    let first_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            first_wallet_id,
            0,
            WalletSource::Generated,
            "  Primary wallet  ",
        )
        .expect("first wallet metadata");
    assert_eq!(first_metadata.label, PRIMARY_WALLET_LABEL);
    assert_eq!(first_metadata.display_order, 0);
    store
        .store_generated_wallet_with_metadata(
            TEST_PASSWORD,
            first_wallet_id,
            0,
            "english",
            &seed,
            &first_metadata,
        )
        .expect("store first wallet");
    assert_eq!(
        store
            .default_wallet_label(TEST_PASSWORD)
            .expect("second default label"),
        "Wallet 2"
    );
    assert!(matches!(
        store.new_wallet_metadata(
            TEST_PASSWORD,
            "duplicate",
            0,
            WalletSource::Imported,
            "primary wallet",
        ),
        Err(VaultError::DuplicateWalletLabel)
    ));
    assert!(matches!(
        store.new_wallet_metadata(TEST_PASSWORD, "empty", 0, WalletSource::Imported, "   "),
        Err(VaultError::InvalidWalletLabel)
    ));

    let second_wallet_id = "second-wallet";
    let second_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            second_wallet_id,
            0,
            WalletSource::Generated,
            "Wallet 2",
        )
        .expect("second wallet metadata");
    store
        .store_generated_wallet_with_metadata(
            TEST_PASSWORD,
            second_wallet_id,
            0,
            "english",
            &seed,
            &second_metadata,
        )
        .expect("store second wallet");

    let updated = store
        .update_wallet_label(TEST_PASSWORD, first_wallet_id, "  Main  ")
        .expect("update label");
    assert_eq!(updated.label, "Main");
    assert_eq!(updated.wallet_uuid, first_wallet_id);
    assert_eq!(updated.status, WalletStatus::Active);
    assert_eq!(updated.display_order, 0);
    assert!(matches!(
        store.update_wallet_label(TEST_PASSWORD, second_wallet_id, "main"),
        Err(VaultError::DuplicateWalletLabel)
    ));

    let reordered = store
        .reorder_active_wallets(
            TEST_PASSWORD,
            &[second_wallet_id.to_string(), first_wallet_id.to_string()],
        )
        .expect("reorder active wallets");
    assert_eq!(reordered[0].wallet_uuid, second_wallet_id);
    assert_eq!(reordered[0].display_order, 0);
    assert_eq!(reordered[1].wallet_uuid, first_wallet_id);
    assert_eq!(reordered[1].display_order, 1);
    assert!(matches!(
        store.reorder_active_wallets(TEST_PASSWORD, &[first_wallet_id.to_string()]),
        Err(VaultError::InvalidWalletOrder)
    ));

    let deactivated = store
        .deactivate_wallet(TEST_PASSWORD, second_wallet_id)
        .expect("deactivate second wallet");
    assert_eq!(deactivated.status, WalletStatus::Inactive);
    let active = store
        .active_wallet_metadata(TEST_PASSWORD)
        .expect("active metadata");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].wallet_uuid, first_wallet_id);
    assert!(
        store
            .load_view_session(TEST_PASSWORD, second_wallet_id)
            .is_ok()
    );
    assert!(matches!(
        store.deactivate_wallet(TEST_PASSWORD, first_wallet_id),
        Err(VaultError::LastActiveWallet)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn session_wallet_management_renames_hides_shows_reorders_and_guards_last_active() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let first_wallet_id = "session-wallet-a";
    let second_wallet_id = "session-wallet-b";
    let third_wallet_id = "session-wallet-c";
    let first_session = import_wallet_with_metadata(&store, first_wallet_id, "Alpha");
    let _second_session = import_wallet_with_metadata(&store, second_wallet_id, "Beta");
    let _third_session = import_wallet_with_metadata(&store, third_wallet_id, "Gamma");

    let metadata = store
        .list_wallet_metadata_for_session(&first_session, true)
        .expect("list all wallet metadata");
    assert_eq!(metadata.len(), 3);
    assert_eq!(
        metadata
            .iter()
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<Vec<_>>(),
        vec![first_wallet_id, second_wallet_id, third_wallet_id]
    );
    assert_eq!(
        store
            .list_wallet_metadata_for_session(&first_session, false)
            .expect("list active wallet metadata")
            .len(),
        3
    );

    let updated = store
        .update_wallet_label_for_session(&first_session, second_wallet_id, "  Main  ")
        .expect("rename wallet");
    assert_eq!(updated.label, "Main");
    assert!(matches!(
        store.update_wallet_label_for_session(&first_session, third_wallet_id, "alpha"),
        Err(VaultError::DuplicateWalletLabel)
    ));
    assert!(matches!(
        store.update_wallet_label_for_session(&first_session, third_wallet_id, "   "),
        Err(VaultError::InvalidWalletLabel)
    ));

    let hidden = store
        .set_wallet_active_for_session(&first_session, second_wallet_id, false)
        .expect("hide wallet");
    assert_eq!(hidden.status, WalletStatus::Inactive);
    let active = store
        .list_wallet_metadata_for_session(&first_session, false)
        .expect("list active after hide");
    assert_eq!(
        active
            .iter()
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<Vec<_>>(),
        vec![first_wallet_id, third_wallet_id]
    );
    assert!(
        store
            .load_view_session(TEST_PASSWORD, second_wallet_id)
            .is_ok()
    );

    let shown = store
        .set_wallet_active_for_session(&first_session, second_wallet_id, true)
        .expect("show wallet");
    assert_eq!(shown.status, WalletStatus::Active);
    let active = store
        .list_wallet_metadata_for_session(&first_session, false)
        .expect("list active after show");
    assert_eq!(
        active
            .iter()
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<Vec<_>>(),
        vec![first_wallet_id, third_wallet_id, second_wallet_id]
    );

    let reordered = store
        .reorder_active_wallets_for_session(
            &first_session,
            &[
                second_wallet_id.to_string(),
                first_wallet_id.to_string(),
                third_wallet_id.to_string(),
            ],
        )
        .expect("reorder active wallets");
    assert_eq!(reordered[0].wallet_uuid, second_wallet_id);
    assert_eq!(reordered[0].display_order, 0);
    assert_eq!(reordered[1].wallet_uuid, first_wallet_id);
    assert_eq!(reordered[1].display_order, 1);
    assert_eq!(reordered[2].wallet_uuid, third_wallet_id);
    assert_eq!(reordered[2].display_order, 2);
    assert!(matches!(
        store.reorder_active_wallets_for_session(&first_session, &[first_wallet_id.to_string()]),
        Err(VaultError::InvalidWalletOrder)
    ));

    store
        .set_wallet_active_for_session(&first_session, first_wallet_id, false)
        .expect("hide first wallet");
    store
        .set_wallet_active_for_session(&first_session, second_wallet_id, false)
        .expect("hide second wallet");
    assert!(matches!(
        store.set_wallet_active_for_session(&first_session, third_wallet_id, false),
        Err(VaultError::LastActiveWallet)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn permanent_wallet_delete_purges_wallet_scoped_records_and_guards_last_active() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let first_wallet_id = "delete-wallet-a";
    let second_wallet_id = "delete-wallet-b";
    let third_wallet_id = "delete-wallet-c";
    let first_session = import_wallet_with_metadata(&store, first_wallet_id, "Alpha");
    let second_session = import_wallet_with_metadata(&store, second_wallet_id, "Beta");
    let _third_session = import_wallet_with_metadata(&store, third_wallet_id, "Gamma");
    let first_chain = store
        .wallet_chain_metadata_for_session(
            &first_session,
            0,
            1,
            "0x1111111111111111111111111111111111111111",
            100,
        )
        .expect("first chain metadata");
    let second_chain = store
        .wallet_chain_metadata_for_session(
            &second_session,
            0,
            1,
            "0x2222222222222222222222222222222222222222",
            100,
        )
        .expect("second chain metadata");
    let first_cache_key =
        wallet_cache_row_record_key(&first_chain.wallet_chain_uuid, &[0x11; KEY_LEN]);
    let second_cache_key =
        wallet_cache_row_record_key(&second_chain.wallet_chain_uuid, &[0x22; KEY_LEN]);
    db.put_desktop_wallet_vault_record(&first_cache_key, b"first cache")
        .expect("store first cache row");
    db.put_desktop_wallet_vault_record(&second_cache_key, b"second cache")
        .expect("store second cache row");
    let private_account = store
        .import_public_account(
            TEST_PASSWORD,
            &second_session,
            IMPORT_PRIVATE_KEY_ONE,
            Some("Private"),
            false,
        )
        .expect("import private scoped account");
    let global_account = store
        .import_public_account(
            TEST_PASSWORD,
            &second_session,
            IMPORT_PRIVATE_KEY_TWO,
            Some("Global"),
            true,
        )
        .expect("import global account");
    let private_account_ids = store
        .list_public_accounts_for_session(&second_session, true)
        .expect("list second wallet public accounts")
        .into_iter()
        .filter_map(|account| match account.scope {
            PublicAccountScope::PrivateWallet { wallet_uuid }
                if wallet_uuid == second_wallet_id =>
            {
                Some(account.public_account_uuid)
            }
            PublicAccountScope::PrivateWallet { .. } | PublicAccountScope::Global => None,
        })
        .collect::<Vec<_>>();
    assert!(private_account_ids.contains(&private_account.public_account_uuid));

    let deleted = store
        .delete_wallet_for_session(&first_session, second_wallet_id)
        .expect("delete active wallet");
    assert_eq!(deleted.wallet_uuid, second_wallet_id);
    assert_eq!(deleted.status, WalletStatus::Active);
    assert!(
        store
            .load_view_session(TEST_PASSWORD, second_wallet_id)
            .is_err()
    );

    for key in [
        wallet_metadata_record_key(second_wallet_id),
        wallet_view_record_key(second_wallet_id),
        wallet_spend_record_key(second_wallet_id),
        wallet_chain_metadata_record_key(&second_chain.wallet_chain_uuid),
        second_cache_key,
    ] {
        assert!(
            db.get_desktop_wallet_vault_record(&key)
                .expect("load deleted record")
                .is_none(),
            "expected {key} to be deleted"
        );
    }
    for key in [
        wallet_metadata_record_key(first_wallet_id),
        wallet_view_record_key(first_wallet_id),
        wallet_spend_record_key(first_wallet_id),
        wallet_chain_metadata_record_key(&first_chain.wallet_chain_uuid),
        first_cache_key,
    ] {
        assert!(
            db.get_desktop_wallet_vault_record(&key)
                .expect("load retained record")
                .is_some(),
            "expected {key} to be retained"
        );
    }
    for account_id in private_account_ids {
        assert!(
            db.get_desktop_wallet_vault_record(&public_account_metadata_record_key(&account_id))
                .expect("load deleted public account metadata")
                .is_none()
        );
        assert!(
            db.get_desktop_wallet_vault_record(&public_account_secret_record_key(&account_id))
                .expect("load deleted public account secret")
                .is_none()
        );
    }
    assert!(
        db.get_desktop_wallet_vault_record(&public_account_metadata_record_key(
            &global_account.public_account_uuid,
        ))
        .expect("load global metadata")
        .is_some()
    );
    assert!(
        db.get_desktop_wallet_vault_record(&public_account_secret_record_key(
            &global_account.public_account_uuid,
        ))
        .expect("load global secret")
        .is_some()
    );

    store
        .set_wallet_active_for_session(&first_session, third_wallet_id, false)
        .expect("hide third wallet");
    let deleted_hidden = store
        .delete_wallet_for_session(&first_session, third_wallet_id)
        .expect("delete hidden wallet");
    assert_eq!(deleted_hidden.status, WalletStatus::Inactive);
    assert!(
        store
            .load_view_session(TEST_PASSWORD, third_wallet_id)
            .is_err()
    );
    assert!(matches!(
        store.delete_wallet_for_session(&first_session, first_wallet_id),
        Err(VaultError::LastActiveWallet)
    ));
    assert_eq!(
        store
            .list_wallet_metadata_for_session(&first_session, true)
            .expect("list remaining metadata")
            .iter()
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<Vec<_>>(),
        vec![first_wallet_id]
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn duplicate_seed_imports_keep_distinct_wallet_and_chain_ids() {
    let (root_dir, db, store) = desktop_store_with_vault();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let first_wallet_id = "duplicate-seed-a";
    let first_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            first_wallet_id,
            0,
            WalletSource::Imported,
            "Duplicate A",
        )
        .expect("first duplicate metadata");
    store
        .import_wallet_mnemonic_with_metadata(
            TEST_PASSWORD,
            first_wallet_id,
            0,
            "english",
            mnemonic,
            &first_metadata,
        )
        .expect("import first duplicate seed");

    let second_wallet_id = "duplicate-seed-b";
    let second_metadata = store
        .new_wallet_metadata(
            TEST_PASSWORD,
            second_wallet_id,
            0,
            WalletSource::Imported,
            "Duplicate B",
        )
        .expect("second duplicate metadata");
    store
        .import_wallet_mnemonic_with_metadata(
            TEST_PASSWORD,
            second_wallet_id,
            0,
            "english",
            mnemonic,
            &second_metadata,
        )
        .expect("import second duplicate seed");

    let first_session = store
        .load_view_session(TEST_PASSWORD, first_wallet_id)
        .expect("load first session");
    let second_session = store
        .load_view_session(TEST_PASSWORD, second_wallet_id)
        .expect("load second session");
    let first_chain = store
        .wallet_chain_metadata_for_session(
            &first_session,
            0,
            1,
            "0x1111111111111111111111111111111111111111",
            100,
        )
        .expect("first chain metadata");
    let second_chain = store
        .wallet_chain_metadata_for_session(
            &second_session,
            0,
            1,
            "0x1111111111111111111111111111111111111111",
            100,
        )
        .expect("second chain metadata");

    assert_ne!(first_wallet_id, second_wallet_id);
    assert_ne!(
        first_chain.wallet_chain_uuid,
        second_chain.wallet_chain_uuid
    );
    assert_eq!(first_chain.wallet_uuid, first_wallet_id);
    assert_eq!(second_chain.wallet_uuid, second_wallet_id);
    assert_eq!(
        first_session.scan_keys().master_public_key,
        second_session.scan_keys().master_public_key
    );
    assert_eq!(
        first_session.scan_keys().nullifying_key,
        second_session.scan_keys().nullifying_key
    );

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn generated_wallet_seed_material_stores_encrypted_bundles() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let seed = generate_seed_material().expect("generate seed");
    let wallet_id = "generated-wallet-id";

    let stored = store
        .store_generated_wallet(TEST_PASSWORD, wallet_id, 0, "english", &seed)
        .expect("store generated wallet");
    let view_payload = db
        .get_desktop_wallet_vault_record(&stored.view_record_key)
        .expect("load view record")
        .expect("view record present");
    let spend_payload = db
        .get_desktop_wallet_vault_record(&stored.spend_record_key)
        .expect("load spend record")
        .expect("spend record present");
    let mut grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("create grant");
    let spend_bundle = store
        .load_spend_bundle(&mut grant, wallet_id)
        .expect("load spend bundle");

    assert_eq!(spend_bundle.bip39_entropy, seed.entropy.as_slice());
    assert!(!contains_subsequence(
        &view_payload,
        seed.mnemonic.as_bytes()
    ));
    assert!(!contains_subsequence(
        &spend_payload,
        seed.mnemonic.as_bytes()
    ));
    assert!(!contains_subsequence(
        &view_payload,
        seed.entropy.as_slice()
    ));
    assert!(!contains_subsequence(
        &spend_payload,
        seed.entropy.as_slice()
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn first_view_session_loads_only_view_material() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    assert!(
        store
            .unlock_first_view_session(TEST_PASSWORD)
            .expect("unlock empty vault")
            .is_none()
    );

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_id = "first-view-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let view_session = store
        .unlock_first_view_session(TEST_PASSWORD)
        .expect("unlock first wallet")
        .expect("view session present");
    let wallet = WalletKeys::from_mnemonic(mnemonic, 0).expect("derive wallet");

    assert_eq!(view_session.wallet_id(), wallet_id);
    assert_eq!(view_session.derivation_index(), 0);
    assert_eq!(
        view_session.scan_keys().master_public_key,
        wallet.viewing.master_public_key
    );
    assert_eq!(
        view_session.scan_keys().nullifying_key,
        wallet.viewing.nullifying_key
    );
    assert!(matches!(
        store.unlock_first_view_session("wrong password"),
        Err(VaultError::UnlockFailed)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn view_session_receive_address_uses_all_chains_address() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_id = "receive-address-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let view_session = store
        .load_view_session(TEST_PASSWORD, wallet_id)
        .expect("load view session");
    let wallet = WalletKeys::from_mnemonic(mnemonic, 0).expect("derive wallet");
    let all_chains = wallet
        .viewing
        .derive_address(None)
        .expect("derive all-chains address")
        .to_string();
    let ethereum_scoped = wallet
        .viewing
        .derive_address(Some((0, 1)))
        .expect("derive ethereum-scoped address")
        .to_string();
    let bsc_scoped = wallet
        .viewing
        .derive_address(Some((0, 56)))
        .expect("derive bsc-scoped address")
        .to_string();

    assert_eq!(
        view_session.receive_address().expect("receive address"),
        all_chains
    );
    assert_ne!(all_chains, ethereum_scoped);
    assert_ne!(all_chains, bsc_scoped);

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn opaque_wallet_metadata_keeps_chain_details_encrypted() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let wallet_uuid = generate_opaque_id().expect("wallet uuid");
    let wallet_chain_uuid = generate_opaque_id().expect("wallet chain uuid");
    let wallet_metadata = WalletMetadataBundle {
        wallet_uuid: wallet_uuid.clone(),
        label: "primary wallet".to_string(),
        derivation_index: 0,
        source: WalletSource::Imported,
        status: WalletStatus::Active,
        display_order: 0,
    };
    let chain_metadata = WalletChainMetadataBundle {
        wallet_chain_uuid: wallet_chain_uuid.clone(),
        wallet_uuid: wallet_uuid.clone(),
        chain_type: 0,
        chain_id: 1,
        contract: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        start_block: 100,
        last_scanned_block: 200,
        last_scanned_block_hash: Some([9u8; KEY_LEN]),
        poi_read_source: None,
    };

    store
        .store_wallet_metadata(TEST_PASSWORD, &wallet_metadata)
        .expect("store wallet metadata");
    store
        .store_wallet_chain_metadata(TEST_PASSWORD, &chain_metadata)
        .expect("store chain metadata");
    let wallet_payload = db
        .get_desktop_wallet_vault_record(&wallet_metadata_record_key(&wallet_uuid))
        .expect("load wallet metadata record")
        .expect("wallet metadata present");
    let chain_payload = db
        .get_desktop_wallet_vault_record(&wallet_chain_metadata_record_key(&wallet_chain_uuid))
        .expect("load chain metadata record")
        .expect("chain metadata present");
    let loaded_wallet = store
        .load_wallet_metadata(TEST_PASSWORD, &wallet_uuid)
        .expect("load wallet metadata");
    let loaded_chain = store
        .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
        .expect("load chain metadata");

    assert_eq!(wallet_uuid.len(), 32);
    assert_eq!(wallet_chain_uuid.len(), 32);
    assert_eq!(loaded_wallet.label, "primary wallet");
    assert_eq!(loaded_chain.chain_id, 1);
    assert_eq!(loaded_chain.contract, chain_metadata.contract);
    assert!(!contains_subsequence(&wallet_payload, b"primary wallet"));
    assert!(!contains_subsequence(&chain_payload, b"1234567890abcdef"));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn software_spend_signer_requires_valid_grant() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_id = "spend-signer-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let mut grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("create grant");

    let signer = store
        .railgun_spend_signer(&mut grant, wallet_id)
        .expect("load signer");
    let signature = signer.sign_spend_message(uint!(7_U256));

    assert_ne!(signature, [U256::ZERO; 3]);
    assert!(!grant.is_valid());
    assert!(matches!(
        store.railgun_spend_signer(&mut grant, wallet_id),
        Err(VaultError::InvalidSpendGrant)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wrong_password_returns_generic_unlock_error() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let Err(error) = unlock_view(&created.metadata, "wrong password") else {
        panic!("unlock unexpectedly succeeded");
    };

    assert!(matches!(error, VaultError::UnlockFailed));
}

#[test]
fn tampered_wrapped_key_returns_generic_unlock_error() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let mut metadata = created.metadata;
    metadata.wrapped_view_dek.ciphertext[0] ^= 0x01;

    let Err(error) = unlock_view(&metadata, TEST_PASSWORD) else {
        panic!("unlock unexpectedly succeeded");
    };

    assert!(matches!(error, VaultError::UnlockFailed));
}

#[test]
fn view_and_spend_bundles_use_separate_keys() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let view_bundle = WalletViewBundle {
        derivation_index: 0,
        spending_public_key: [[1u8; KEY_LEN], [2u8; KEY_LEN]],
        viewing_private_key: [3u8; KEY_LEN],
        viewing_public_key: [4u8; KEY_LEN],
        nullifying_key: [5u8; KEY_LEN],
        master_public_key: [6u8; KEY_LEN],
    };
    let spend_bundle = WalletSpendBundle {
        derivation_index: 0,
        bip39_language: "english".to_string(),
        bip39_entropy: vec![7u8; 32],
    };

    let view_record = created
        .view
        .encrypt_view_bundle(TEST_WALLET_ID, &view_bundle)
        .expect("encrypt view bundle");
    let spend_record = created
        .spend
        .encrypt_spend_bundle(TEST_WALLET_ID, &spend_bundle)
        .expect("encrypt spend bundle");

    assert!(
        created
            .view
            .decrypt_view_bundle(TEST_WALLET_ID, &view_record)
            .is_ok()
    );
    assert!(
        created
            .spend
            .decrypt_spend_bundle(TEST_WALLET_ID, &spend_record)
            .is_ok()
    );
    assert!(
        created
            .view
            .decrypt_record(RecordKind::WalletSpendBundle, TEST_WALLET_ID, &spend_record)
            .is_err()
    );
    assert!(
        created
            .spend
            .decrypt_record(RecordKind::WalletViewBundle, TEST_WALLET_ID, &view_record)
            .is_err()
    );
}

#[test]
fn spend_grant_is_one_use_and_invalidates() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let mut grant = create_spend_grant(&created.metadata, TEST_PASSWORD).expect("grant");

    assert_eq!(grant.policy(), SpendGrantPolicy::OneUse);
    assert!(grant.is_valid());
    assert!(grant.spend_unlock().is_ok());

    grant.invalidate();

    assert!(!grant.is_valid());
    assert!(matches!(
        grant.spend_unlock(),
        Err(VaultError::InvalidSpendGrant)
    ));
}

#[test]
fn aad_binds_record_kind_and_id() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let record = created
        .view
        .encrypt_record(
            RecordKind::WalletChainMetadata,
            TEST_WALLET_ID,
            b"chain metadata",
        )
        .expect("encrypt");

    assert!(
        created
            .view
            .decrypt_record(RecordKind::WalletCacheRow, TEST_WALLET_ID, &record)
            .is_err()
    );
    assert!(
        created
            .view
            .decrypt_record(RecordKind::WalletChainMetadata, "other-wallet", &record)
            .is_err()
    );
}

#[test]
fn cache_row_ids_are_deterministic_and_context_bound() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let cache_keys = created
        .view
        .derive_cache_keys("opaque-wallet-chain-a")
        .expect("cache keys");
    let other_cache_keys = created
        .view
        .derive_cache_keys("opaque-wallet-chain-b")
        .expect("other cache keys");

    let row_id = cache_keys.row_id(4, 42, b"stable-utxo");
    let same_row_id = cache_keys.row_id(4, 42, b"stable-utxo");
    let other_position = cache_keys.row_id(4, 43, b"stable-utxo");
    let other_namespace = other_cache_keys.row_id(4, 42, b"stable-utxo");

    assert_eq!(row_id, same_row_id);
    assert_ne!(row_id, other_position);
    assert_ne!(row_id, other_namespace);
    assert_eq!(CacheKeys::row_record_id(&row_id).len(), 64);
}

#[test]
fn encrypted_cache_rows_are_bound_to_opaque_row_id() {
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    let cache_keys = created
        .view
        .derive_cache_keys("opaque-wallet-chain")
        .expect("cache keys");
    let row_id = cache_keys.row_id(4, 42, b"stable-utxo");
    let other_row_id = cache_keys.row_id(4, 43, b"stable-utxo");
    let record = cache_keys
        .encrypt_row(&row_id, b"private utxo payload")
        .expect("encrypt row");
    let mut tampered = record.clone();
    tampered.ciphertext[0] ^= 0x01;

    let plaintext = cache_keys
        .decrypt_row(&row_id, &record)
        .expect("decrypt row");
    assert_eq!(&*plaintext, b"private utxo payload");
    assert!(cache_keys.decrypt_row(&other_row_id, &record).is_err());
    assert!(cache_keys.decrypt_row(&row_id, &tampered).is_err());
}

#[test]
fn encrypted_cache_store_hides_wallet_history_details() {
    use alloy::primitives::{FixedBytes, U256};
    use railgun_wallet::{Note, Utxo, UtxoCommitmentKind, UtxoSource};
    use sync_service::WalletCacheStore;

    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_id = "encrypted-cache-wallet";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let view_session = Arc::new(
        store
            .load_view_session(TEST_PASSWORD, wallet_id)
            .expect("load view session"),
    );
    let chain_metadata = store
        .wallet_chain_metadata_for_session(
            view_session.as_ref(),
            0,
            1,
            "0x1111111111111111111111111111111111111111",
            100,
        )
        .expect("chain metadata");
    let wallet_chain_uuid = chain_metadata.wallet_chain_uuid.clone();
    let cache_store = DesktopEncryptedWalletCacheStore::new(
        Arc::clone(&db),
        Arc::clone(&view_session),
        chain_metadata,
    )
    .expect("encrypted cache store");
    let wallet_utxo = WalletUtxo {
        utxo: Utxo::new(
            Note {
                token_hash: U256::from_be_bytes([0x44; KEY_LEN]),
                value: U256::from_be_bytes([0x55; KEY_LEN]),
                random: [0x66; 16],
                npk: U256::from_be_bytes([0x77; KEY_LEN]),
            },
            7,
            42,
            UtxoSource {
                tx_hash: FixedBytes::from([0x88; KEY_LEN]),
                block_number: 123,
                block_timestamp: 1_700_000_123,
            },
            UtxoCommitmentKind::Transact,
        ),
        spent: Some(UtxoSource {
            tx_hash: FixedBytes::from([0x99; KEY_LEN]),
            block_number: 124,
            block_timestamp: 1_700_000_124,
        }),
    };

    cache_store
        .store_wallet_utxos(
            "ignored-cache-key",
            std::slice::from_ref(&wallet_utxo),
            Some(150),
            Some([0xaa; KEY_LEN]),
        )
        .expect("store encrypted cache");
    let rows = db
        .list_desktop_wallet_vault_records(&wallet_cache_row_prefix(&wallet_chain_uuid))
        .expect("list encrypted cache rows");
    let chain_payload = db
        .get_desktop_wallet_vault_record(&wallet_chain_metadata_record_key(&wallet_chain_uuid))
        .expect("load chain metadata record")
        .expect("chain metadata present");
    let loaded = cache_store
        .load_wallet_utxos("ignored-cache-key")
        .expect("load encrypted cache");
    let loaded_meta = store
        .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
        .expect("load updated chain metadata");

    assert_eq!(rows.len(), 1);
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded[0].utxo.note.token_hash,
        wallet_utxo.utxo.note.token_hash
    );
    assert_eq!(
        loaded[0].utxo.source.tx_hash,
        wallet_utxo.utxo.source.tx_hash
    );
    assert_eq!(loaded[0].spent, wallet_utxo.spent);
    assert_eq!(loaded_meta.last_scanned_block, 150);
    assert_eq!(loaded_meta.last_scanned_block_hash, Some([0xaa; KEY_LEN]));

    let row_key = rows[0].key.as_bytes();
    let row_payload = &rows[0].payload;
    assert!(!contains_subsequence(row_key, b"1111111111111111"));
    assert!(!contains_subsequence(row_payload, &[0x44; KEY_LEN]));
    assert!(!contains_subsequence(row_payload, &[0x55; KEY_LEN]));
    assert!(!contains_subsequence(row_payload, &[0x66; 16]));
    assert!(!contains_subsequence(row_payload, &[0x77; KEY_LEN]));
    assert!(!contains_subsequence(row_payload, &[0x88; KEY_LEN]));
    assert!(!contains_subsequence(row_payload, &[0x99; KEY_LEN]));
    assert!(!contains_subsequence(&chain_payload, b"1111111111111111"));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn encrypted_cache_upsert_does_not_delete_existing_rows() {
    use alloy::primitives::{FixedBytes, U256};
    use railgun_wallet::{Note, Utxo, UtxoCommitmentKind, UtxoSource};
    use sync_service::WalletCacheStore;

    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));
    let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
    store
        .put_metadata(&created.metadata)
        .expect("persist metadata");
    let wallet_id = "encrypted-cache-upsert-wallet";
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    store
        .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
        .expect("import wallet");
    let view_session = Arc::new(
        store
            .load_view_session(TEST_PASSWORD, wallet_id)
            .expect("load view session"),
    );
    let mut chain_metadata = store
        .wallet_chain_metadata_for_session(
            view_session.as_ref(),
            0,
            1,
            "0x1111111111111111111111111111111111111111",
            100,
        )
        .expect("chain metadata");
    let wallet_chain_uuid = chain_metadata.wallet_chain_uuid.clone();
    let cache_store = DesktopEncryptedWalletCacheStore::new(
        Arc::clone(&db),
        Arc::clone(&view_session),
        chain_metadata.clone(),
    )
    .expect("encrypted cache store");
    let first = WalletUtxo {
        utxo: Utxo::new(
            Note {
                token_hash: U256::from_be_bytes([0x11; KEY_LEN]),
                value: uint!(1_U256),
                random: [0x22; 16],
                npk: U256::from_be_bytes([0x33; KEY_LEN]),
            },
            3,
            1,
            UtxoSource {
                tx_hash: FixedBytes::from([0x44; KEY_LEN]),
                block_number: 101,
                block_timestamp: 1_700_000_101,
            },
            UtxoCommitmentKind::Transact,
        ),
        spent: None,
    };
    let mut second = first.clone();
    second.utxo.position = 2;
    second.utxo.source.tx_hash = FixedBytes::from([0x55; KEY_LEN]);
    let mut rewound_source = first.clone();
    rewound_source.utxo.position = 3;
    rewound_source.utxo.source = UtxoSource {
        tx_hash: FixedBytes::from([0x66; KEY_LEN]),
        block_number: 170,
        block_timestamp: 1_700_000_170,
    };
    let mut rewound_spend = first.clone();
    rewound_spend.utxo.position = 4;
    rewound_spend.utxo.source.tx_hash = FixedBytes::from([0x77; KEY_LEN]);
    rewound_spend.spent = Some(UtxoSource {
        tx_hash: FixedBytes::from([0x88; KEY_LEN]),
        block_number: 170,
        block_timestamp: 1_700_000_170,
    });

    cache_store
        .store_wallet_utxos(
            "ignored",
            &[first.clone(), second, rewound_source, rewound_spend],
            Some(110),
            None,
        )
        .expect("store full cache");
    cache_store
        .store_wallet_utxos("ignored", std::slice::from_ref(&first), Some(120), None)
        .expect("upsert partial cache");
    let loaded = cache_store
        .load_wallet_utxos("ignored")
        .expect("load upserted cache");
    assert_eq!(loaded.len(), 4);
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 1));
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 2));
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 3));
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 4));

    store
        .rewind_wallet_chain_cache_with_session(view_session.as_ref(), &mut chain_metadata, 150)
        .expect("rewind encrypted cache");
    let loaded = cache_store
        .load_wallet_utxos("ignored")
        .expect("load rewound cache");
    assert_eq!(loaded.len(), 3);
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 1));
    assert!(loaded.iter().any(|utxo| utxo.utxo.position == 2));
    assert!(!loaded.iter().any(|utxo| utxo.utxo.position == 3));
    assert!(
        loaded
            .iter()
            .any(|utxo| utxo.utxo.position == 4 && utxo.spent.is_none())
    );
    let metadata = store
        .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
        .expect("load rewound metadata");
    assert_eq!(metadata.last_scanned_block, 149);
    assert_eq!(metadata.last_scanned_block_hash, None);

    cache_store
        .replace_wallet_cache("ignored", std::slice::from_ref(&first), 160, None)
        .expect("replace encrypted cache");
    let loaded = cache_store
        .load_wallet_utxos("ignored")
        .expect("load replaced cache");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].utxo.position, 1);
    let metadata = store
        .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
        .expect("load replaced metadata");
    assert_eq!(metadata.last_scanned_block, 160);
    assert_eq!(metadata.last_scanned_block_hash, None);

    store
        .reset_wallet_chain_cache_with_session(view_session.as_ref(), &mut chain_metadata, 160)
        .expect("reset encrypted cache");
    assert!(
        cache_store
            .load_wallet_utxos("ignored")
            .expect("load reset cache")
            .is_empty()
    );
    let metadata = store
        .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
        .expect("load reset metadata");
    assert_eq!(metadata.last_scanned_block, 159);
    assert_eq!(metadata.last_scanned_block_hash, None);

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn desktop_vault_first_run_unlock_wallet_setup_and_spend_prompt_flow() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let store = DesktopVaultStore::from_db(Arc::clone(&db));

    assert!(!store.vault_exists().expect("inspect empty vault"));
    let created = store
        .create_vault_with_params(TEST_PASSWORD, test_kdf())
        .expect("create vault");
    assert_eq!(created.metadata.version, current_vault_version());
    assert!(store.vault_exists().expect("inspect created vault"));
    assert!(
        store
            .unlock_first_view_session(TEST_PASSWORD)
            .expect("unlock empty vault")
            .is_none()
    );

    let generated_seed = generate_seed_material().expect("generate wallet");
    store
        .store_generated_wallet(
            TEST_PASSWORD,
            "generated-wallet",
            0,
            "english",
            &generated_seed,
        )
        .expect("store generated wallet");
    let generated_session = store
        .unlock_first_view_session(TEST_PASSWORD)
        .expect("unlock generated wallet")
        .expect("generated session");
    assert_eq!(generated_session.wallet_id(), "generated-wallet");

    let imported_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    store
        .import_wallet_mnemonic(
            TEST_PASSWORD,
            "imported-wallet",
            0,
            "english",
            imported_mnemonic,
        )
        .expect("import wallet");
    let imported_session = store
        .load_view_session(TEST_PASSWORD, "imported-wallet")
        .expect("load imported wallet");
    assert_eq!(imported_session.wallet_id(), "imported-wallet");
    assert!(matches!(
        store.create_spend_grant("wrong password"),
        Err(VaultError::UnlockFailed)
    ));

    let mut grant = store
        .create_spend_grant(TEST_PASSWORD)
        .expect("fresh spend grant");
    let _signer = store
        .railgun_spend_signer(&mut grant, imported_session.wallet_id())
        .expect("spend signer from grant");
    assert!(!grant.is_valid());
    assert!(matches!(
        store.railgun_spend_signer(&mut grant, imported_session.wallet_id()),
        Err(VaultError::InvalidSpendGrant)
    ));

    drop(store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn railgun_recipient_for_derivation(derivation_index: u32) -> String {
    WalletKeys::from_mnemonic(TEST_MNEMONIC, derivation_index)
        .expect("derive wallet")
        .viewing
        .derive_address(None)
        .expect("derive receive address")
        .to_string()
}
