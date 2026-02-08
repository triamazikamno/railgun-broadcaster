use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const BLOB_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_index");
const MERKLE_FOREST_INDEX_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("merkle_forest_index");
const ZKEY_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zkey_index");
const WALLET_UNSPENT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_unspent");
const WALLET_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_meta");

const META_KEY: &str = "meta";
const RAILGUN_DIR: &str = "railgun";
const BLOBS_DIR: &str = "blobs";

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

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
pub struct WalletUnspent {
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

    pub fn put_wallet_unspent(
        &self,
        wallet_id: &str,
        utxo_id: &str,
        payload: &[u8],
    ) -> Result<(), DbError> {
        let key = wallet_unspent_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UNSPENT_TABLE)?;
            table.insert(key.as_str(), payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_wallet_unspent(&self, wallet_id: &str, utxo_id: &str) -> Result<(), DbError> {
        let key = wallet_unspent_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UNSPENT_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn clear_wallet_unspent(&self, wallet_id: &str) -> Result<(), DbError> {
        let prefix = wallet_unspent_prefix(wallet_id);
        let range_end = format!("{prefix}~");
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UNSPENT_TABLE)?;
            let keys: Vec<String> = table
                .range(prefix.as_str()..range_end.as_str())?
                .map(|entry| entry.map(|(key, _)| key.value().to_string()))
                .collect::<Result<_, _>>()?;
            for key in keys {
                table.remove(key.as_str())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_wallet_unspent(&self, wallet_id: &str) -> Result<Vec<WalletUnspent>, DbError> {
        let prefix = wallet_unspent_prefix(wallet_id);
        let range_end = format!("{prefix}~");
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_UNSPENT_TABLE)?;
        let mut out = Vec::new();
        for entry in table.range(prefix.as_str()..range_end.as_str())? {
            let (key, value) = entry?;
            let key = key.value();
            let utxo_id = key.strip_prefix(&prefix).unwrap_or(key).to_string();
            out.push(WalletUnspent {
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

    fn initialize_schema(&self) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        txn.open_table(META_TABLE)?;
        txn.open_table(BLOB_INDEX_TABLE)?;
        txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        txn.open_table(ZKEY_INDEX_TABLE)?;
        txn.open_table(WALLET_UNSPENT_TABLE)?;
        txn.open_table(WALLET_META_TABLE)?;
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
        let mut version = from;
        while version < to {
            match version {
                0 => {}
                1 => {}
                _ => {
                    return Err(DbError::UnsupportedSchemaVersion { version });
                }
            }
            version += 1;
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

fn blob_index_key(kind: &str, id: &str) -> String {
    format!("{kind}|{id}")
}

fn merkle_forest_key(chain_id: u64, contract: &str) -> String {
    format!("{chain_id}|{contract}")
}

fn wallet_unspent_key(wallet_id: &str, utxo_id: &str) -> String {
    format!("{wallet_id}|{utxo_id}")
}

fn wallet_unspent_prefix(wallet_id: &str) -> String {
    format!("{wallet_id}|")
}
