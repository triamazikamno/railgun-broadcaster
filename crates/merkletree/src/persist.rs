use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use thiserror::Error;

use crate::tree::MerkleForest;

pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleForestSnapshot {
    pub version: u32,
    pub chain_id: u64,
    pub contract_address: Address,
    pub last_processed_block: u64,
    pub forest: MerkleForest,
}

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("snapshot io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("snapshot encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("snapshot version unsupported: {version}")]
    UnsupportedVersion { version: u32 },
    #[error("snapshot metadata mismatch: {reason}")]
    MetadataMismatch { reason: String },
}

pub fn load_forest_snapshot(
    path: &Path,
    chain_id: u64,
    contract_address: Address,
) -> Result<Option<MerkleForestSnapshot>, PersistError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut snapshot: MerkleForestSnapshot = rmp_serde::from_slice(&data)?;
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(PersistError::UnsupportedVersion {
            version: snapshot.version,
        });
    }
    if snapshot.chain_id != chain_id {
        return Err(PersistError::MetadataMismatch {
            reason: format!(
                "chain id mismatch: expected {chain_id}, got {}",
                snapshot.chain_id
            ),
        });
    }
    if snapshot.contract_address != contract_address {
        return Err(PersistError::MetadataMismatch {
            reason: format!(
                "contract address mismatch: expected {contract_address}, got {}",
                snapshot.contract_address
            ),
        });
    }
    snapshot.forest.compute_roots();
    Ok(Some(snapshot))
}

pub fn write_forest_snapshot(
    path: &Path,
    chain_id: u64,
    contract_address: Address,
    last_processed_block: u64,
    forest: &MerkleForest,
) -> Result<(), PersistError> {
    #[derive(serde::Serialize)]
    struct MerkleForestSnapshotRef<'a> {
        version: u32,
        chain_id: u64,
        contract_address: Address,
        last_processed_block: u64,
        forest: &'a MerkleForest,
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let snapshot = MerkleForestSnapshotRef {
        version: SNAPSHOT_VERSION,
        chain_id,
        contract_address,
        last_processed_block,
        forest,
    };
    let data = rmp_serde::to_vec(&snapshot)?;
    let temp_path = temp_path(path);
    fs::write(&temp_path, data)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("forest.msgpack");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp_name = format!("{file_name}.tmp.{pid}.{nanos}");
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(temp_name);
    temp_path
}

#[cfg(test)]
mod tests {
    use super::{PersistError, load_forest_snapshot, write_forest_snapshot};
    use crate::tree::{MerkleForest, MerkleTreeUpdate};
    use alloy::primitives::{Address, U256};
    use std::fs;
    use std::path::PathBuf;

    fn temp_snapshot_path() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-tests");
        fs::create_dir_all(&dir).expect("create temp snapshot dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        dir.join(format!("forest-{pid}-{nanos}.msgpack"))
    }

    #[test]
    fn snapshot_roundtrip() {
        let path = temp_snapshot_path();
        let chain_id = 1;
        let contract_address = Address::from([0u8; 20]);
        let last_block = 123u64;

        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            })
            .expect("insert leaf");
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 1,
                hash: U256::from(2),
            })
            .expect("insert leaf");
        forest.compute_roots();

        write_forest_snapshot(&path, chain_id, contract_address, last_block, &forest)
            .expect("write snapshot");

        let snapshot = load_forest_snapshot(&path, chain_id, contract_address)
            .expect("load snapshot")
            .expect("snapshot missing");

        assert_eq!(snapshot.last_processed_block, last_block);
        assert_eq!(snapshot.forest.tree_count(), forest.tree_count());
        assert_eq!(snapshot.forest.leaf_count(), forest.leaf_count());
        assert_eq!(snapshot.forest.roots(), forest.roots());

        fs::remove_file(&path).expect("remove snapshot file");
    }

    #[test]
    fn snapshot_metadata_mismatch() {
        let path = temp_snapshot_path();
        let chain_id = 1;
        let contract_address = Address::from([0u8; 20]);

        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            })
            .expect("insert leaf");
        forest.compute_roots();

        write_forest_snapshot(&path, chain_id, contract_address, 5, &forest)
            .expect("write snapshot");

        let err = load_forest_snapshot(&path, chain_id + 1, contract_address)
            .expect_err("expected metadata mismatch");
        assert!(matches!(err, PersistError::MetadataMismatch { .. }));

        fs::remove_file(&path).expect("remove snapshot file");
    }
}
