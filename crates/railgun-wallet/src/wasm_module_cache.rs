use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use local_db::{BlobMeta, DbError, DbStore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmer::{Module, Store};

const WASM_MODULE_CACHE_KIND: &str = "wasm-module";
const WASM_MODULE_CACHE_MAGIC: &[u8; 8] = b"RWMODCCH";
const WASM_MODULE_CACHE_FILE_VERSION: u32 = 1;
const WASM_MODULE_CACHE_FORMAT_VERSION: u32 = 1;
const WASM_MODULE_CACHE_ENGINE_VERSION: &str = "wasmer-6.1.0";

#[derive(Debug, Error)]
pub enum WasmModuleCacheError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("cache format mismatch")]
    FormatMismatch,
    #[error("cache version mismatch")]
    VersionMismatch,
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("module serialize failed: {0}")]
    Serialize(String),
    #[error("module deserialize failed: {0}")]
    Deserialize(String),
}

pub struct CachedWasmModule {
    pub module: Module,
    pub cache_hit: bool,
}

pub fn load_or_compile_wasm_module(
    db: Option<&DbStore>,
    store: &Store,
    variant: &str,
    compiler: &str,
    wasm: &[u8],
) -> Result<CachedWasmModule, WasmModuleCacheError> {
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let cache_id = module_cache_id(variant, compiler);
    if let Some(db) = db {
        match load_wasm_module_cache(db, store, &cache_id, wasm_hash) {
            Ok(Some(module)) => {
                return Ok(CachedWasmModule {
                    module,
                    cache_hit: true,
                });
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(
                ?err,
                variant,
                compiler,
                "failed to load compiled wasm module cache"
            ),
        }
    }

    let module =
        Module::new(store, wasm).map_err(|err| WasmModuleCacheError::Compile(err.to_string()))?;
    if let Some(db) = db
        && let Err(err) = write_wasm_module_cache(db, &cache_id, wasm_hash, &module)
    {
        tracing::warn!(
            ?err,
            variant,
            compiler,
            "failed to write compiled wasm module cache"
        );
    }

    Ok(CachedWasmModule {
        module,
        cache_hit: false,
    })
}

pub fn wasm_module_cache_exists(
    db: &DbStore,
    variant: &str,
    compiler: &str,
    wasm: &[u8],
) -> Result<bool, WasmModuleCacheError> {
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let cache_id = module_cache_id(variant, compiler);
    let Some(meta) = db.get_blob_meta(WASM_MODULE_CACHE_KIND, &cache_id)? else {
        return Ok(false);
    };
    if meta.format_version != WASM_MODULE_CACHE_FORMAT_VERSION || meta.content_hash != wasm_hash {
        return Ok(false);
    }
    Ok(db.resolve_path(&meta.relative_path).exists())
}

fn load_wasm_module_cache(
    db: &DbStore,
    store: &Store,
    cache_id: &str,
    wasm_hash: [u8; 32],
) -> Result<Option<Module>, WasmModuleCacheError> {
    let Some(meta) = db.get_blob_meta(WASM_MODULE_CACHE_KIND, cache_id)? else {
        return Ok(None);
    };
    if meta.format_version != WASM_MODULE_CACHE_FORMAT_VERSION || meta.content_hash != wasm_hash {
        return Ok(None);
    }

    let path = db.resolve_path(&meta.relative_path);
    if !path.exists() {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != WASM_MODULE_CACHE_MAGIC {
        return Err(WasmModuleCacheError::FormatMismatch);
    }
    let mut version_bytes = [0_u8; 4];
    file.read_exact(&mut version_bytes)?;
    if u32::from_le_bytes(version_bytes) != WASM_MODULE_CACHE_FILE_VERSION {
        return Err(WasmModuleCacheError::VersionMismatch);
    }
    let mut serialized = Vec::new();
    file.read_to_end(&mut serialized)?;

    // SAFETY: serialized modules are loaded only from the local cache after matching
    // the wasm hash, cache format version, compiler, OS/arch, and Wasmer version key.
    let module = unsafe { Module::deserialize(store, serialized) }
        .map_err(|err| WasmModuleCacheError::Deserialize(err.to_string()))?;
    Ok(Some(module))
}

fn write_wasm_module_cache(
    db: &DbStore,
    cache_id: &str,
    wasm_hash: [u8; 32],
    module: &Module,
) -> Result<(), WasmModuleCacheError> {
    db.ensure_blob_dir(WASM_MODULE_CACHE_KIND)?;
    let file_name = format!("{cache_id}.wasmer");
    let relative = DbStore::relative_blob_path(WASM_MODULE_CACHE_KIND, &file_name);
    let path = db.resolve_path(&relative);
    let tmp_path = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
    let serialized = module
        .serialize()
        .map_err(|err| WasmModuleCacheError::Serialize(err.to_string()))?;

    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(WASM_MODULE_CACHE_MAGIC)?;
        file.write_all(&WASM_MODULE_CACHE_FILE_VERSION.to_le_bytes())?;
        file.write_all(serialized.as_ref())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, &path)?;

    let now = now_epoch_secs();
    let created_at = db
        .get_blob_meta(WASM_MODULE_CACHE_KIND, cache_id)?
        .map_or(now, |meta| meta.created_at);
    db.put_blob_meta(
        WASM_MODULE_CACHE_KIND,
        cache_id,
        &BlobMeta {
            format_version: WASM_MODULE_CACHE_FORMAT_VERSION,
            relative_path: relative,
            content_hash: wasm_hash,
            created_at,
            updated_at: now,
            last_block: None,
        },
    )?;
    Ok(())
}

fn module_cache_id(variant: &str, compiler: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        safe_component(variant),
        safe_component(compiler),
        safe_component(std::env::consts::OS),
        safe_component(std::env::consts::ARCH),
        WASM_MODULE_CACHE_ENGINE_VERSION
    )
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use local_db::{DbConfig, DbStore};
    use wasmer::Store;

    use super::{WASM_MODULE_CACHE_KIND, load_or_compile_wasm_module, module_cache_id};

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-wallet-wasm-module-cache-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("{pid}-{counter}"))
    }

    #[test]
    fn compiled_wasm_module_cache_roundtrip() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let store = Store::default();
        let wasm = b"\0asm\x01\0\0\0";

        let first = load_or_compile_wasm_module(Some(&db), &store, "test/variant", "default", wasm)
            .expect("compile module");
        assert!(!first.cache_hit);
        drop(first);

        let meta = db
            .get_blob_meta(
                WASM_MODULE_CACHE_KIND,
                &module_cache_id("test/variant", "default"),
            )
            .expect("read blob meta")
            .expect("blob meta present");
        assert!(db.resolve_path(&meta.relative_path).exists());

        let second =
            load_or_compile_wasm_module(Some(&db), &store, "test/variant", "default", wasm)
                .expect("load cached module");
        assert!(second.cache_hit);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
