use alloy::hex;
use eyre::{Result, WrapErr, bail, eyre};
use local_db::{
    BlobMeta, LOCAL_DB_TABLES, LocalDbTableDecodeKind, LocalDbTableInfo, MerkleForestMeta, Meta,
    OutputPoiRecoveryRecord, PendingFeeNoteAssuranceRecord, PendingOutputPoiContextRecord,
    PoiArtifactCacheRecord, TerminalFeeNoteAssuranceRecord, WalletMeta, ZkeyMeta,
};
use redb::{Builder, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

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
struct WalletUtxoValue {
    wallet_id: String,
    utxo_id: String,
    payload_hex: String,
}

#[derive(Serialize)]
struct DesktopWalletVaultValue {
    payload_len: usize,
}

#[derive(Serialize)]
struct AppSettingsValue {
    payload_len: usize,
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

    let table_info = LocalDbTableInfo::by_name(table_name);
    if table_info.is_none() && !opt.raw {
        bail!("unknown table: {table_name}; use --raw to inspect unknown tables");
    }
    let table_def = table_info.map_or_else(
        || TableDefinition::new(table_name),
        |info| info.table.definition(),
    );
    let table = txn.open_table(table_def)?;

    if let Some(key) = opt.key.as_deref() {
        match table.get(key)? {
            Some(value) => print_value(table_info, key, value.value(), opt.raw)?,
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
        print_value(table_info, &key, value.value(), opt.raw)?;
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
    for table in LOCAL_DB_TABLES {
        println!("{}", table.name);
    }
}

fn print_value(table: Option<LocalDbTableInfo>, key: &str, value: &[u8], raw: bool) -> Result<()> {
    if raw {
        let entry = RawEntry {
            key: key.to_string(),
            value_hex: hex::encode_prefixed(value),
        };
        return print_json(&entry);
    }

    let Some(table) = table else {
        bail!("unknown table requires --raw");
    };
    match table.decode_kind {
        LocalDbTableDecodeKind::Meta => print_decoded::<Meta>(key, value),
        LocalDbTableDecodeKind::BlobMeta => print_decoded::<BlobMeta>(key, value),
        LocalDbTableDecodeKind::MerkleForestMeta => print_decoded::<MerkleForestMeta>(key, value),
        LocalDbTableDecodeKind::ZkeyMeta => print_decoded::<ZkeyMeta>(key, value),
        LocalDbTableDecodeKind::WalletMeta => print_decoded::<WalletMeta>(key, value),
        LocalDbTableDecodeKind::PendingFeeNoteAssurance => {
            print_decoded::<PendingFeeNoteAssuranceRecord>(key, value)
        }
        LocalDbTableDecodeKind::TerminalFeeNoteAssurance => {
            print_decoded::<TerminalFeeNoteAssuranceRecord>(key, value)
        }
        LocalDbTableDecodeKind::PendingOutputPoiContext => {
            print_decoded::<PendingOutputPoiContextRecord>(key, value)
        }
        LocalDbTableDecodeKind::OutputPoiRecovery => {
            print_decoded::<OutputPoiRecoveryRecord>(key, value)
        }
        LocalDbTableDecodeKind::PoiArtifactCache => {
            print_decoded::<PoiArtifactCacheRecord>(key, value)
        }
        LocalDbTableDecodeKind::AppSettings => print_app_settings(key, value),
        LocalDbTableDecodeKind::WalletUtxo => print_wallet_utxo(key, value),
        LocalDbTableDecodeKind::DesktopWalletVault => print_desktop_wallet_vault(key, value),
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

fn print_wallet_utxo(key: &str, value: &[u8]) -> Result<()> {
    let (wallet_id, utxo_id) = split_wallet_key(key);
    let entry = Entry {
        key: key.to_string(),
        value: WalletUtxoValue {
            wallet_id,
            utxo_id,
            payload_hex: hex::encode_prefixed(value),
        },
    };
    print_json(&entry)
}

fn print_desktop_wallet_vault(key: &str, value: &[u8]) -> Result<()> {
    let entry = Entry {
        key: key.to_string(),
        value: DesktopWalletVaultValue {
            payload_len: value.len(),
        },
    };
    print_json(&entry)
}

fn print_app_settings(key: &str, value: &[u8]) -> Result<()> {
    let entry = Entry {
        key: key.to_string(),
        value: AppSettingsValue {
            payload_len: value.len(),
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

#[cfg(test)]
mod tests {
    use super::AppSettingsValue;

    #[test]
    fn app_settings_value_redacts_payload_bytes() {
        let value = serde_json::to_value(AppSettingsValue { payload_len: 3 })
            .expect("serialize app settings value");

        assert_eq!(value["payload_len"], 3);
        assert!(value.get("payload_hex").is_none());
    }
}
