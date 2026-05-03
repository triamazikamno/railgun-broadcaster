use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, railgun_txid_leaf_hash};
use redb::{Database, ReadableDatabase, ReadableTable, Table, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const BLOB_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_index");
const MERKLE_FOREST_INDEX_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("merkle_forest_index");
const ZKEY_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zkey_index");
const WALLET_UTXO_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_utxo");
const WALLET_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_meta");
const PENDING_FEE_NOTE_ASSURANCE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("fee_note_assurance_pending");
const TERMINAL_FEE_NOTE_ASSURANCE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("fee_note_assurance_terminal");
const PENDING_OUTPUT_POI_CONTEXT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("pending_output_poi_context");
const OUTPUT_POI_RECOVERY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("output_poi_recovery");
const DESKTOP_WALLET_VAULT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("desktop_wallet_vault_v1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDbTable {
    Meta,
    BlobIndex,
    MerkleForestIndex,
    ZkeyIndex,
    WalletUtxo,
    WalletMeta,
    PendingFeeNoteAssurance,
    TerminalFeeNoteAssurance,
    PendingOutputPoiContext,
    OutputPoiRecovery,
    DesktopWalletVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDbTableDecodeKind {
    Meta,
    BlobMeta,
    MerkleForestMeta,
    ZkeyMeta,
    WalletUtxo,
    WalletMeta,
    PendingFeeNoteAssurance,
    TerminalFeeNoteAssurance,
    PendingOutputPoiContext,
    OutputPoiRecovery,
    DesktopWalletVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDbTableInfo {
    pub table: LocalDbTable,
    pub name: &'static str,
    pub decode_kind: LocalDbTableDecodeKind,
}

pub const LOCAL_DB_TABLES: &[LocalDbTableInfo] = &[
    LocalDbTableInfo {
        table: LocalDbTable::Meta,
        name: "meta",
        decode_kind: LocalDbTableDecodeKind::Meta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::BlobIndex,
        name: "blob_index",
        decode_kind: LocalDbTableDecodeKind::BlobMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::MerkleForestIndex,
        name: "merkle_forest_index",
        decode_kind: LocalDbTableDecodeKind::MerkleForestMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::ZkeyIndex,
        name: "zkey_index",
        decode_kind: LocalDbTableDecodeKind::ZkeyMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::WalletUtxo,
        name: "wallet_utxo",
        decode_kind: LocalDbTableDecodeKind::WalletUtxo,
    },
    LocalDbTableInfo {
        table: LocalDbTable::WalletMeta,
        name: "wallet_meta",
        decode_kind: LocalDbTableDecodeKind::WalletMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PendingFeeNoteAssurance,
        name: "fee_note_assurance_pending",
        decode_kind: LocalDbTableDecodeKind::PendingFeeNoteAssurance,
    },
    LocalDbTableInfo {
        table: LocalDbTable::TerminalFeeNoteAssurance,
        name: "fee_note_assurance_terminal",
        decode_kind: LocalDbTableDecodeKind::TerminalFeeNoteAssurance,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PendingOutputPoiContext,
        name: "pending_output_poi_context",
        decode_kind: LocalDbTableDecodeKind::PendingOutputPoiContext,
    },
    LocalDbTableInfo {
        table: LocalDbTable::OutputPoiRecovery,
        name: "output_poi_recovery",
        decode_kind: LocalDbTableDecodeKind::OutputPoiRecovery,
    },
    LocalDbTableInfo {
        table: LocalDbTable::DesktopWalletVault,
        name: "desktop_wallet_vault_v1",
        decode_kind: LocalDbTableDecodeKind::DesktopWalletVault,
    },
];

impl LocalDbTable {
    #[must_use]
    pub const fn definition(self) -> TableDefinition<'static, &'static str, &'static [u8]> {
        match self {
            Self::Meta => META_TABLE,
            Self::BlobIndex => BLOB_INDEX_TABLE,
            Self::MerkleForestIndex => MERKLE_FOREST_INDEX_TABLE,
            Self::ZkeyIndex => ZKEY_INDEX_TABLE,
            Self::WalletUtxo => WALLET_UTXO_TABLE,
            Self::WalletMeta => WALLET_META_TABLE,
            Self::PendingFeeNoteAssurance => PENDING_FEE_NOTE_ASSURANCE_TABLE,
            Self::TerminalFeeNoteAssurance => TERMINAL_FEE_NOTE_ASSURANCE_TABLE,
            Self::PendingOutputPoiContext => PENDING_OUTPUT_POI_CONTEXT_TABLE,
            Self::OutputPoiRecovery => OUTPUT_POI_RECOVERY_TABLE,
            Self::DesktopWalletVault => DESKTOP_WALLET_VAULT_TABLE,
        }
    }
}

impl LocalDbTableInfo {
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        LOCAL_DB_TABLES
            .iter()
            .copied()
            .find(|table| table.name == name)
    }
}

const META_KEY: &str = "meta";
const RAILGUN_DIR: &str = "railgun";
const BLOBS_DIR: &str = "blobs";

pub const CURRENT_SCHEMA_VERSION: u32 = 7;

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub root_dir: PathBuf,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("db"),
        }
    }
}

#[derive(Debug)]
pub struct DbStore {
    root_dir: PathBuf,
    db: Database,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("db error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("unsupported schema version {version}")]
    UnsupportedSchemaVersion { version: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub schema_version: u32,
    pub app_version: String,
    pub created_at: u64,
}

impl Meta {
    fn new() -> Result<Self, DbError> {
        Ok(Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: now_epoch_secs()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub format_version: u32,
    pub relative_path: String,
    pub content_hash: [u8; 32],
    pub created_at: u64,
    pub updated_at: u64,
    pub last_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleForestMeta {
    pub relative_path: String,
    pub last_block: u64,
    pub format_version: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkeyMeta {
    pub relative_path: String,
    pub zkey_hash: [u8; 32],
    pub format_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxoRecord {
    pub utxo_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMeta {
    pub last_scanned_block: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub last_scanned_block_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeeNoteAssuranceTerminalOutcome {
    RevertedReceipt,
    CommitmentMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFeeNoteAssuranceRecord {
    pub chain_id: u64,
    pub public_tx_hash: FixedBytes<32>,
    pub context: FeeNoteAssuranceContext,
}

impl PendingFeeNoteAssuranceRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.public_tx_hash)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, public_tx_hash: &FixedBytes<32>) -> String {
        format!("{chain_id}|{}", hex::encode(public_tx_hash))
    }

    #[must_use]
    pub fn prefix_for_chain(chain_id: u64) -> String {
        format!("{chain_id}|")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalFeeNoteAssuranceRecord {
    pub chain_id: u64,
    pub public_tx_hash: FixedBytes<32>,
    pub context: FeeNoteAssuranceContext,
    pub outcome: FeeNoteAssuranceTerminalOutcome,
}

impl TerminalFeeNoteAssuranceRecord {
    #[must_use]
    pub fn key(&self) -> String {
        PendingFeeNoteAssuranceRecord::key_for(self.chain_id, &self.public_tx_hash)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingOutputPoiRole {
    BroadcasterFee,
    Recipient,
    Change,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingOutputPoiObservation {
    pub output_tree: u64,
    pub output_position: u64,
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOutputPoiContextRecord {
    pub chain_id: u64,
    pub wallet_id: String,
    pub txid_version: String,
    pub output_commitment: FixedBytes<32>,
    pub output_npk: FixedBytes<32>,
    pub utxo_tree_in: u64,
    pub railgun_txid: U256,
    pub txid_merkleroot_index: Option<u64>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
    pub output_role: PendingOutputPoiRole,
    pub created_at: u64,
    pub source_operation_id: Option<String>,
    pub observation: Option<PendingOutputPoiObservation>,
    pub submitted_poi_list_keys: Vec<FixedBytes<32>>,
    pub terminal_error: Option<String>,
}

impl PendingOutputPoiContextRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.output_commitment)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, output_commitment: &FixedBytes<32>) -> String {
        format!("{chain_id}|{}", hex::encode(output_commitment))
    }

    #[must_use]
    pub fn prefix_for_chain(chain_id: u64) -> String {
        format!("{chain_id}|")
    }

    #[must_use]
    pub fn txid_leaf_hash(&self) -> Option<FixedBytes<32>> {
        if self.txid_merkleroot_index.is_none() {
            return Some(FixedBytes::from(
                railgun_txid_leaf_hash(self.railgun_txid, self.utxo_tree_in).to_be_bytes::<32>(),
            ));
        }

        let mut txid_leaf_hash = None;
        for per_leaf in self.pre_transaction_pois_per_txid_leaf_per_list.values() {
            for key in per_leaf.keys() {
                if txid_leaf_hash.is_some_and(|existing| existing != *key) {
                    return None;
                }
                txid_leaf_hash = Some(*key);
            }
        }
        txid_leaf_hash
    }

    #[must_use]
    pub fn list_keys(&self) -> Vec<FixedBytes<32>> {
        if self.required_poi_list_keys.is_empty() {
            self.pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect()
        } else {
            self.required_poi_list_keys.clone()
        }
    }

    #[must_use]
    pub fn missing_list_keys(&self) -> Vec<FixedBytes<32>> {
        self.list_keys()
            .into_iter()
            .filter(|list_key| !self.submitted_poi_list_keys.contains(list_key))
            .collect()
    }

    #[must_use]
    pub fn retain_poi_lists(
        &self,
        list_keys: &[FixedBytes<32>],
    ) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
        list_keys
            .iter()
            .filter_map(|list_key| {
                self.pre_transaction_pois_per_txid_leaf_per_list
                    .get(list_key)
                    .cloned()
                    .map(|per_leaf| (*list_key, per_leaf))
            })
            .collect()
    }

    pub fn observe(&mut self, observation: PendingOutputPoiObservation) -> bool {
        if self.observation.as_ref() == Some(&observation) {
            return false;
        }
        self.observation = Some(observation);
        true
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputPoiRecoveryStatus {
    Recoverable,
    Submitted,
    Valid,
    NotSelfOriginated,
    UnsupportedShape,
    MissingWalletInputs,
    MissingWalletOutputs,
    InputPoiNotValid,
    MissingMerkleProof,
    TxFetchFailed,
    DecodeFailed,
    ProofGenerationFailed,
    SubmitFailed,
}

impl OutputPoiRecoveryStatus {
    #[must_use]
    pub const fn is_permanent_skip(self) -> bool {
        matches!(
            self,
            Self::Valid
                | Self::NotSelfOriginated
                | Self::UnsupportedShape
                | Self::MissingWalletInputs
                | Self::MissingWalletOutputs
                | Self::DecodeFailed
        )
    }
}

#[derive(Debug, Clone)]
pub enum OutputPoiRecoveryAction {
    CacheTxInput {
        tx_input: Vec<u8>,
    },
    Detected {
        status: OutputPoiRecoveryStatus,
        retry_after: Option<Duration>,
        last_error: Option<String>,
        increment_attempts: bool,
    },
    Submitted {
        retry_after: Duration,
    },
    SubmitFailed {
        error: String,
        retry_after: Duration,
    },
    Valid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputPoiRecoveryRecord {
    pub chain_id: u64,
    pub wallet_id: String,
    pub output_commitment: FixedBytes<32>,
    pub source_tx_hash: FixedBytes<32>,
    pub tx_input: Option<Vec<u8>>,
    pub status: OutputPoiRecoveryStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_detection_at: Option<u64>,
    pub last_submission_at: Option<u64>,
    pub next_retry_at: Option<u64>,
    pub attempt_count: u32,
    pub last_error: Option<String>,
}

impl OutputPoiRecoveryRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.wallet_id, &self.output_commitment)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, wallet_id: &str, output_commitment: &FixedBytes<32>) -> String {
        format!("{chain_id}|{wallet_id}|{}", hex::encode(output_commitment))
    }

    #[must_use]
    pub fn prefix_for_wallet(chain_id: u64, wallet_id: &str) -> String {
        format!("{chain_id}|{wallet_id}|")
    }

    #[must_use]
    pub fn retry_allowed(&self, now: u64, force_retry: bool) -> bool {
        !self.status.is_permanent_skip()
            && (force_retry
                || self
                    .next_retry_at
                    .is_none_or(|next_retry_at| next_retry_at <= now))
    }

    #[must_use]
    pub fn submission_retry_allowed(&self, now: u64, force_retry: bool) -> bool {
        matches!(
            self.status,
            OutputPoiRecoveryStatus::Submitted
                | OutputPoiRecoveryStatus::SubmitFailed
                | OutputPoiRecoveryStatus::Recoverable
        ) && (force_retry
            || self
                .next_retry_at
                .is_some_and(|next_retry_at| next_retry_at <= now))
    }

    pub fn apply_action(&mut self, action: OutputPoiRecoveryAction, now: u64) {
        match action {
            OutputPoiRecoveryAction::CacheTxInput { tx_input } => {
                self.tx_input = Some(tx_input);
                self.updated_at = now;
                self.last_detection_at = Some(now);
            }
            OutputPoiRecoveryAction::Detected {
                status,
                retry_after,
                last_error,
                increment_attempts,
            } => {
                self.status = status;
                self.updated_at = now;
                self.last_detection_at = Some(now);
                self.next_retry_at =
                    retry_after.map(|duration| now.saturating_add(duration.as_secs()));
                self.last_error = last_error;
                if increment_attempts {
                    self.attempt_count = self.attempt_count.saturating_add(1);
                }
            }
            OutputPoiRecoveryAction::Submitted { retry_after } => {
                self.status = OutputPoiRecoveryStatus::Submitted;
                self.updated_at = now;
                self.last_submission_at = Some(now);
                self.next_retry_at = Some(now.saturating_add(retry_after.as_secs()));
                self.last_error = None;
                self.attempt_count = self.attempt_count.saturating_add(1);
            }
            OutputPoiRecoveryAction::SubmitFailed { error, retry_after } => {
                self.status = OutputPoiRecoveryStatus::SubmitFailed;
                self.updated_at = now;
                self.next_retry_at = Some(now.saturating_add(retry_after.as_secs()));
                self.last_error = Some(error);
                self.attempt_count = self.attempt_count.saturating_add(1);
            }
            OutputPoiRecoveryAction::Valid => {
                self.status = OutputPoiRecoveryStatus::Valid;
                self.updated_at = now;
                self.next_retry_at = None;
                self.last_error = None;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopWalletVaultRecord {
    pub key: String,
    pub payload: Vec<u8>,
}

impl DbStore {
    pub fn open(config: DbConfig) -> Result<Self, DbError> {
        let root_dir = config.root_dir;
        let railgun_dir = railgun_dir(&root_dir);
        std::fs::create_dir_all(&railgun_dir)?;
        let db_path = db_path(&root_dir);

        loop {
            let db = if db_path.exists() {
                Database::open(&db_path)?
            } else {
                Database::create(&db_path)?
            };

            let store = Self {
                root_dir: root_dir.clone(),
                db,
            };
            store.initialize_schema()?;

            match store.read_meta()? {
                None => {
                    let meta = Meta::new()?;
                    store.write_meta(&meta)?;
                    return Ok(store);
                }
                Some(meta) if meta.schema_version > CURRENT_SCHEMA_VERSION => {
                    drop(store);
                    backup_db(&db_path)?;
                    continue;
                }
                Some(meta) if meta.schema_version < CURRENT_SCHEMA_VERSION => {
                    if let Err(err) =
                        store.run_migrations(meta.schema_version, CURRENT_SCHEMA_VERSION)
                    {
                        if matches!(err, DbError::UnsupportedSchemaVersion { .. }) {
                            drop(store);
                            backup_db(&db_path)?;
                            continue;
                        }
                        return Err(err);
                    }

                    let meta = Meta {
                        schema_version: CURRENT_SCHEMA_VERSION,
                        app_version: env!("CARGO_PKG_VERSION").to_string(),
                        created_at: meta.created_at,
                    };
                    store.write_meta(&meta)?;
                    return Ok(store);
                }
                Some(_) => return Ok(store),
            }
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn railgun_dir(&self) -> PathBuf {
        railgun_dir(&self.root_dir)
    }

    pub fn db_path(&self) -> PathBuf {
        db_path(&self.root_dir)
    }

    pub fn blob_dir(&self) -> PathBuf {
        blobs_dir(&self.root_dir)
    }

    pub fn ensure_blob_dir(&self, kind: &str) -> Result<PathBuf, DbError> {
        let dir = self.blob_dir().join(kind);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn blob_path(&self, kind: &str, name: &str) -> PathBuf {
        self.blob_dir().join(kind).join(name)
    }

    pub fn resolve_path(&self, relative_path: &str) -> PathBuf {
        let path = PathBuf::from(relative_path);
        if path.is_absolute() {
            path
        } else {
            self.railgun_dir().join(path)
        }
    }

    pub fn relative_path(&self, path: &Path) -> String {
        if let Ok(relative) = path.strip_prefix(self.railgun_dir()) {
            relative.to_string_lossy().to_string()
        } else {
            path.to_string_lossy().to_string()
        }
    }

    pub fn relative_blob_path(kind: &str, name: &str) -> String {
        format!("{BLOBS_DIR}/{kind}/{name}")
    }

    fn list_decoded_by_prefix<T>(
        &self,
        table_def: TableDefinition<'static, &str, &[u8]>,
        prefix: &str,
    ) -> Result<Vec<T>, DbError>
    where
        T: DeserializeOwned,
    {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(table_def)?;
        let mut out = Vec::new();
        for entry in table.range(prefix..range_end.as_str())? {
            let (_, value) = entry?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }

    pub fn get_blob_meta(&self, kind: &str, id: &str) -> Result<Option<BlobMeta>, DbError> {
        let key = blob_index_key(kind, id);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOB_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_blob_meta(&self, kind: &str, id: &str, meta: &BlobMeta) -> Result<(), DbError> {
        let key = blob_index_key(kind, id);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BLOB_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
    ) -> Result<Option<MerkleForestMeta>, DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
        meta: &MerkleForestMeta,
    ) -> Result<(), DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_zkey_meta(&self, variant: &str) -> Result<Option<ZkeyMeta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ZKEY_INDEX_TABLE)?;
        match table.get(variant)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_zkey_meta(&self, variant: &str, meta: &ZkeyMeta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ZKEY_INDEX_TABLE)?;
            table.insert(variant, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_wallet_utxo(
        &self,
        wallet_id: &str,
        utxo_id: &str,
        payload: &[u8],
    ) -> Result<(), DbError> {
        let key = wallet_utxo_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            table.insert(key.as_str(), payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_wallet_utxo(&self, wallet_id: &str, utxo_id: &str) -> Result<(), DbError> {
        let key = wallet_utxo_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn clear_wallet_utxos(&self, wallet_id: &str) -> Result<(), DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            remove_table_prefix(&mut table, &prefix)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Atomically replace all UTXO entries for a wallet and update its
    /// metadata in a single transaction. This prevents partial state if the
    /// process is interrupted mid-write.
    pub fn batch_store_wallet_utxos(
        &self,
        wallet_id: &str,
        utxos: &[(String, Vec<u8>)],
        meta: Option<&WalletMeta>,
    ) -> Result<(), DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let txn = self.db.begin_write()?;
        {
            let mut utxo_table = txn.open_table(WALLET_UTXO_TABLE)?;
            remove_table_prefix(&mut utxo_table, &prefix)?;
            for (utxo_id, payload) in utxos {
                let key = wallet_utxo_key(wallet_id, utxo_id);
                utxo_table.insert(key.as_str(), payload.as_slice())?;
            }
            if let Some(meta) = meta {
                let data = encode(meta)?;
                let mut meta_table = txn.open_table(WALLET_META_TABLE)?;
                meta_table.insert(wallet_id, data.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_wallet_utxos(&self, wallet_id: &str) -> Result<Vec<WalletUtxoRecord>, DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let range_end = prefix_range_end(&prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_UTXO_TABLE)?;
        let mut out = Vec::new();
        for entry in table.range(prefix.as_str()..range_end.as_str())? {
            let (key, value) = entry?;
            let key = key.value();
            let utxo_id = key.strip_prefix(&prefix).unwrap_or(key).to_string();
            out.push(WalletUtxoRecord {
                utxo_id,
                payload: value.value().to_vec(),
            });
        }
        Ok(out)
    }

    pub fn get_wallet_meta(&self, wallet_id: &str) -> Result<Option<WalletMeta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_META_TABLE)?;
        match table.get(wallet_id)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_wallet_meta(&self, wallet_id: &str, meta: &WalletMeta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_META_TABLE)?;
            table.insert(wallet_id, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<Option<PendingFeeNoteAssuranceRecord>, DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_pending_fee_note_assurance(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
    ) -> Result<(), DbError> {
        let key = record.key();
        let data = encode(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_pending_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<PendingFeeNoteAssuranceRecord>, DbError> {
        let prefix = PendingFeeNoteAssuranceRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(PENDING_FEE_NOTE_ASSURANCE_TABLE, &prefix)
    }

    pub fn get_terminal_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<Option<TerminalFeeNoteAssuranceRecord>, DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_terminal_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<TerminalFeeNoteAssuranceRecord>, DbError> {
        let prefix = PendingFeeNoteAssuranceRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(TERMINAL_FEE_NOTE_ASSURANCE_TABLE, &prefix)
    }

    pub fn mark_fee_note_assurance_terminal(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
        outcome: FeeNoteAssuranceTerminalOutcome,
    ) -> Result<(), DbError> {
        let key = record.key();
        let terminal = TerminalFeeNoteAssuranceRecord {
            chain_id: record.chain_id,
            public_tx_hash: record.public_tx_hash,
            context: record.context.clone(),
            outcome,
        };
        let data = encode(&terminal)?;
        let txn = self.db.begin_write()?;
        {
            let mut pending_table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            pending_table.remove(key.as_str())?;

            let mut terminal_table = txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
            terminal_table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, DbError> {
        let key = PendingOutputPoiContextRecord::key_for(chain_id, output_commitment);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_pending_output_poi_context(
        &self,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<(), DbError> {
        let key = record.key();
        let data = encode(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_pending_output_poi_context(
        &self,
        chain_id: u64,
        output_commitment: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let key = PendingOutputPoiContextRecord::key_for(chain_id, output_commitment);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, DbError> {
        let prefix = PendingOutputPoiContextRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(PENDING_OUTPUT_POI_CONTEXT_TABLE, &prefix)
    }

    pub fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, DbError> {
        let key = OutputPoiRecoveryRecord::key_for(chain_id, wallet_id, output_commitment);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_output_poi_recovery(&self, record: &OutputPoiRecoveryRecord) -> Result<(), DbError> {
        let key = record.key();
        let data = encode(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, DbError> {
        let prefix = OutputPoiRecoveryRecord::prefix_for_wallet(chain_id, wallet_id);
        self.list_decoded_by_prefix(OUTPUT_POI_RECOVERY_TABLE, &prefix)
    }

    pub fn get_desktop_wallet_vault_record(&self, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        match table.get(key)? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    pub fn put_desktop_wallet_vault_record(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            table.insert(key, payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_desktop_wallet_vault_record_if_absent(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<bool, DbError> {
        let txn = self.db.begin_write()?;
        let inserted = {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            if table.get(key)?.is_some() {
                false
            } else {
                table.insert(key, payload)?;
                true
            }
        };
        txn.commit()?;
        Ok(inserted)
    }

    pub fn put_desktop_wallet_vault_records(
        &self,
        records: &[(String, Vec<u8>)],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            for (key, payload) in records {
                table.insert(key.as_str(), payload.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_desktop_wallet_vault_record(&self, key: &str) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            table.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn replace_desktop_wallet_vault_prefix_with_records(
        &self,
        prefix: &str,
        records: &[(String, Vec<u8>)],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            remove_table_prefix(&mut table, prefix)?;
            for (key, payload) in records {
                table.insert(key.as_str(), payload.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_desktop_wallet_vault_records(
        &self,
        prefix: &str,
    ) -> Result<Vec<DesktopWalletVaultRecord>, DbError> {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        let mut out = Vec::new();
        for entry in table.range(prefix..range_end.as_str())? {
            let (key, value) = entry?;
            out.push(DesktopWalletVaultRecord {
                key: key.value().to_string(),
                payload: value.value().to_vec(),
            });
        }
        Ok(out)
    }

    fn initialize_schema(&self) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        txn.open_table(META_TABLE)?;
        txn.open_table(BLOB_INDEX_TABLE)?;
        txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        txn.open_table(ZKEY_INDEX_TABLE)?;
        txn.open_table(WALLET_UTXO_TABLE)?;
        txn.open_table(WALLET_META_TABLE)?;
        txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
        txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
        txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
        txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
        txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        txn.commit()?;
        Ok(())
    }

    fn read_meta(&self) -> Result<Option<Meta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META_TABLE)?;
        match table.get(META_KEY)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    fn write_meta(&self, meta: &Meta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(META_KEY, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn run_migrations(&self, from: u32, to: u32) -> Result<(), DbError> {
        if from < to {
            return Err(DbError::UnsupportedSchemaVersion { version: from });
        }
        Ok(())
    }

    pub fn update_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract_address: &str,
        path: &Path,
        last_block: u64,
        format_version: u32,
        hash: [u8; 32],
    ) -> Result<(), DbError> {
        let meta = MerkleForestMeta {
            relative_path: self.relative_path(path),
            last_block,
            format_version,
            hash,
        };
        self.put_merkle_forest_meta(chain_id, contract_address, &meta)
    }
}

fn railgun_dir(root_dir: &Path) -> PathBuf {
    root_dir.join(RAILGUN_DIR)
}

fn db_path(root_dir: &Path) -> PathBuf {
    railgun_dir(root_dir).join("db.redb")
}

fn blobs_dir(root_dir: &Path) -> PathBuf {
    railgun_dir(root_dir).join(BLOBS_DIR)
}

fn backup_db(db_path: &Path) -> Result<(), DbError> {
    let ts = now_epoch_secs()?;
    let file_name = format!("db.redb.bak.{ts}");
    let backup_path = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(file_name);
    std::fs::rename(db_path, backup_path)?;
    Ok(())
}

fn now_epoch_secs() -> Result<u64, DbError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    Ok(now.as_secs())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DbError> {
    Ok(rmp_serde::to_vec_named(value)?)
}

fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, DbError> {
    Ok(rmp_serde::from_slice(data)?)
}

fn remove_table_prefix(table: &mut Table<'_, &str, &[u8]>, prefix: &str) -> Result<(), DbError> {
    let range_end = prefix_range_end(prefix);
    table.retain_in(prefix..range_end.as_str(), |_, _| false)?;
    Ok(())
}

fn prefix_range_end(prefix: &str) -> String {
    format!("{prefix}~")
}

fn blob_index_key(kind: &str, id: &str) -> String {
    format!("{kind}|{id}")
}

fn merkle_forest_key(chain_id: u64, contract: &str) -> String {
    format!("{chain_id}|{contract}")
}

fn wallet_utxo_key(wallet_id: &str, utxo_id: &str) -> String {
    format!("{wallet_id}|{utxo_id}")
}

fn wallet_utxo_prefix(wallet_id: &str) -> String {
    format!("{wallet_id}|")
}

#[cfg(test)]
mod tests {
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

    fn sample_record(
        chain_id: u64,
        public_tx_hash: FixedBytes<32>,
    ) -> PendingFeeNoteAssuranceRecord {
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
}
