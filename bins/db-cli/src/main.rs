use eyre::{Result, WrapErr, bail, eyre};
use local_db::{BlobMeta, MerkleForestMeta, Meta, WalletMeta, ZkeyMeta};
use redb::{Builder, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const BLOB_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_index");
const MERKLE_FOREST_INDEX_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("merkle_forest_index");
const ZKEY_INDEX_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zkey_index");
const WALLET_UNSPENT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_unspent");
const WALLET_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_meta");

#[derive(Debug, StructOpt)]
#[structopt(name = "db-cli")]
struct Options {
    #[structopt(long)]
    path: PathBuf,
    #[structopt(long)]
    table: Option<String>,
    #[structopt(long)]
    key: Option<String>,
    #[structopt(long)]
    prefix: Option<String>,
    #[structopt(long)]
    limit: Option<usize>,
    #[structopt(long)]
    raw: bool,
    #[structopt(long)]
    copy: bool,
}

#[derive(Clone, Copy, Debug)]
enum TableKind {
    Meta,
    BlobIndex,
    MerkleForestIndex,
    ZkeyIndex,
    WalletUnspent,
    WalletMeta,
}

impl TableKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "meta" => Some(Self::Meta),
            "blob_index" => Some(Self::BlobIndex),
            "merkle_forest_index" => Some(Self::MerkleForestIndex),
            "zkey_index" => Some(Self::ZkeyIndex),
            "wallet_unspent" => Some(Self::WalletUnspent),
            "wallet_meta" => Some(Self::WalletMeta),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::BlobIndex => "blob_index",
            Self::MerkleForestIndex => "merkle_forest_index",
            Self::ZkeyIndex => "zkey_index",
            Self::WalletUnspent => "wallet_unspent",
            Self::WalletMeta => "wallet_meta",
        }
    }
}

#[derive(Serialize)]
struct Entry<T> {
    key: String,
    value: T,
}

#[derive(Serialize)]
struct RawEntry {
    key: String,
    value_hex: String,
}

#[derive(Serialize)]
struct WalletUnspentValue {
    wallet_id: String,
    utxo_id: String,
    payload_hex: String,
}

fn main() -> Result<()> {
    let opt = Options::from_args();

    if opt.key.is_some() && opt.table.is_none() {
        bail!("--key requires --table");
    }
    if opt.prefix.is_some() && opt.table.is_none() {
        bail!("--prefix requires --table");
    }
    if opt.limit.is_some() && opt.table.is_none() {
        bail!("--limit requires --table");
    }
    if opt.key.is_some() && opt.prefix.is_some() {
        bail!("--key and --prefix are mutually exclusive");
    }

    let db_path = resolve_db_path(&opt.path);
    if !db_path.exists() {
        bail!("db not found: {}", db_path.display());
    }

    let open_path = if opt.copy {
        let copy_path = copy_db_path(&db_path);
        std::fs::copy(&db_path, &copy_path).wrap_err("copy db for repair")?;
        let mut db = Builder::new()
            .open(&copy_path)
            .wrap_err("open redb copy for repair")?;
        db.check_integrity().wrap_err("repair redb copy")?;
        copy_path
    } else {
        db_path.clone()
    };

    let db = match ReadOnlyDatabase::open(&open_path) {
        Ok(db) => db,
        Err(err) => {
            if matches!(err, redb::DatabaseError::RepairAborted) && !opt.copy {
                return Err(eyre!(
                    "database needs repair; rerun with --copy to work on a safe copy"
                ));
            }
            return Err(err).wrap_err("open redb");
        }
    };
    let txn = db.begin_read().wrap_err("begin read")?;

    let Some(table_name) = opt.table.as_deref() else {
        list_tables();
        return Ok(());
    };

    let table_kind =
        TableKind::from_name(table_name).ok_or_else(|| eyre!("unknown table: {table_name}"))?;

    let table = match table_kind {
        TableKind::Meta => txn.open_table(META_TABLE)?,
        TableKind::BlobIndex => txn.open_table(BLOB_INDEX_TABLE)?,
        TableKind::MerkleForestIndex => txn.open_table(MERKLE_FOREST_INDEX_TABLE)?,
        TableKind::ZkeyIndex => txn.open_table(ZKEY_INDEX_TABLE)?,
        TableKind::WalletUnspent => txn.open_table(WALLET_UNSPENT_TABLE)?,
        TableKind::WalletMeta => txn.open_table(WALLET_META_TABLE)?,
    };

    if let Some(key) = opt.key.as_deref() {
        match table.get(key)? {
            Some(value) => print_value(table_kind, key, value.value(), opt.raw)?,
            None => bail!("key not found: {key}"),
        }
        return Ok(());
    }

    let (_range_end, range) = if let Some(prefix) = opt.prefix.as_ref() {
        let end = format!("{prefix}~");
        let range = table.range(prefix.as_str()..end.as_str())?;
        (Some(end), range)
    } else {
        (None, table.range::<&str>(..)?)
    };

    let limit = opt.limit.unwrap_or(usize::MAX);
    for entry in range.take(limit) {
        let (key, value) = entry?;
        let key = key.value().to_string();
        print_value(table_kind, &key, value.value(), opt.raw)?;
    }

    Ok(())
}

fn resolve_db_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("railgun").join("db.redb")
    } else {
        path.to_path_buf()
    }
}

fn copy_db_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|file| file.to_string_lossy().to_string())
        .filter(|file| !file.is_empty())
        .unwrap_or_else(|| "db.redb".to_string());
    path.with_file_name(format!("{name}.copy"))
}

fn list_tables() {
    for table in [
        TableKind::Meta,
        TableKind::BlobIndex,
        TableKind::MerkleForestIndex,
        TableKind::ZkeyIndex,
        TableKind::WalletUnspent,
        TableKind::WalletMeta,
    ] {
        println!("{}", table.name());
    }
}

fn print_value(table: TableKind, key: &str, value: &[u8], raw: bool) -> Result<()> {
    if raw {
        let entry = RawEntry {
            key: key.to_string(),
            value_hex: format!("0x{}", hex::encode(value)),
        };
        return print_json(&entry);
    }

    match table {
        TableKind::Meta => print_decoded::<Meta>(key, value),
        TableKind::BlobIndex => print_decoded::<BlobMeta>(key, value),
        TableKind::MerkleForestIndex => print_decoded::<MerkleForestMeta>(key, value),
        TableKind::ZkeyIndex => print_decoded::<ZkeyMeta>(key, value),
        TableKind::WalletMeta => print_decoded::<WalletMeta>(key, value),
        TableKind::WalletUnspent => print_wallet_unspent(key, value),
    }
}

fn print_decoded<T>(key: &str, value: &[u8]) -> Result<()>
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T = rmp_serde::from_slice(value).wrap_err("decode msgpack")?;
    let entry = Entry {
        key: key.to_string(),
        value: decoded,
    };
    print_json(&entry)
}

fn print_wallet_unspent(key: &str, value: &[u8]) -> Result<()> {
    let (wallet_id, utxo_id) = split_wallet_key(key);
    let entry = Entry {
        key: key.to_string(),
        value: WalletUnspentValue {
            wallet_id,
            utxo_id,
            payload_hex: format!("0x{}", hex::encode(value)),
        },
    };
    print_json(&entry)
}

fn split_wallet_key(key: &str) -> (String, String) {
    let mut parts = key.splitn(2, '|');
    let wallet_id = parts.next().unwrap_or_default().to_string();
    let utxo_id = parts.next().unwrap_or_default().to_string();
    (wallet_id, utxo_id)
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let data = serde_json::to_string(value).wrap_err("serialize json")?;
    println!("{data}");
    Ok(())
}
