use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::tree::normalize_tree_position;
use merkletree::tree::{MerkleForest, MerkleProof, MerkleTreeUpdate};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

use crate::error::PoiRpcError;
use crate::poi::{
    BlindedCommitmentData, BlockedShield, PoiMerkleProof, PoiRpcClient, PoiStatus,
    PoiSyncedListEvent,
};

pub const POI_CACHE_SNAPSHOT_VERSION: u32 = 1;
pub const POI_EVENTS_PAGE_SIZE: u64 = 500;
pub const POI_MERKLETREE_LEAVES_PAGE_SIZE: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCacheIdentity {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
}

impl PoiCacheIdentity {
    #[must_use]
    pub fn new(
        chain_type: u8,
        chain_id: u64,
        txid_version: impl Into<String>,
        list_key: FixedBytes<32>,
    ) -> Self {
        Self {
            chain_type,
            chain_id,
            txid_version: txid_version.into(),
            list_key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCachePosition {
    pub global_index: u64,
    pub tree_number: u32,
    pub tree_position: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoiCacheRootValidation {
    #[default]
    Pending,
    Validated {
        roots: BTreeMap<u32, FixedBytes<32>>,
    },
    Invalid {
        roots: BTreeMap<u32, FixedBytes<32>>,
    },
}

impl PoiCacheRootValidation {
    fn accepts(&self, roots: &BTreeMap<u32, FixedBytes<32>>) -> bool {
        matches!(self, Self::Validated { roots: validated } if validated == roots)
    }

    fn rejects(&self, roots: &BTreeMap<u32, FixedBytes<32>>) -> bool {
        matches!(self, Self::Invalid { roots: invalid } if invalid == roots)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCacheSyncProgress {
    pub next_event_index: u64,
    pub next_leaf_index: u64,
    pub blocked_shields_synced: bool,
    pub root_validation: PoiCacheRootValidation,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoiCacheSyncOutcome {
    pub events: usize,
    pub leaves: usize,
    pub blocked_shields: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoiCacheSnapshot {
    version: u32,
    identity: PoiCacheIdentity,
    progress: PoiCacheSyncProgress,
    forest: MerkleForest,
    status_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiStatus>,
    position_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiCachePosition>,
    blocked_shields_by_blinded_commitment: BTreeMap<FixedBytes<32>, BlockedShield>,
}

#[derive(Debug, Clone)]
pub struct PoiCache {
    snapshot: PoiCacheSnapshot,
}

#[derive(Debug, Error)]
pub enum PoiCacheError {
    #[error("POI cache io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("POI cache decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("POI cache encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("POI cache RPC error: {0}")]
    Rpc(#[from] PoiRpcError),
    #[error("POI cache merkle error: {0}")]
    Merkle(#[from] merkletree::errors::SyncError),
    #[error("POI cache snapshot version unsupported: {version}")]
    UnsupportedVersion { version: u32 },
    #[error("POI cache metadata mismatch: {reason}")]
    MetadataMismatch { reason: String },
    #[error("invalid POI cache hex field {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("POI cache page size must be non-zero")]
    InvalidPageSize,
    #[error("POI cache sync range overflow")]
    RangeOverflow,
    #[error("POI cache root validation required before proof generation")]
    RootValidationRequired,
    #[error("POI cache roots were rejected by the POI node")]
    InvalidRoots,
    #[error("missing POI cache proof data for blinded commitment {blinded_commitment}")]
    MissingCommitment { blinded_commitment: FixedBytes<32> },
    #[error(
        "POI cache proof leaf mismatch for blinded commitment {blinded_commitment}: got {leaf}"
    )]
    LeafMismatch {
        blinded_commitment: FixedBytes<32>,
        leaf: FixedBytes<32>,
    },
}

impl PoiCache {
    #[must_use]
    pub fn new(identity: PoiCacheIdentity) -> Self {
        Self {
            snapshot: PoiCacheSnapshot {
                version: POI_CACHE_SNAPSHOT_VERSION,
                identity,
                progress: PoiCacheSyncProgress::default(),
                forest: MerkleForest::new(),
                status_by_blinded_commitment: BTreeMap::new(),
                position_by_blinded_commitment: BTreeMap::new(),
                blocked_shields_by_blinded_commitment: BTreeMap::new(),
            },
        }
    }

    pub fn load(path: &Path, identity: &PoiCacheIdentity) -> Result<Option<Self>, PoiCacheError> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut snapshot: PoiCacheSnapshot = rmp_serde::from_slice(&data)?;
        if snapshot.version != POI_CACHE_SNAPSHOT_VERSION {
            return Err(PoiCacheError::UnsupportedVersion {
                version: snapshot.version,
            });
        }
        if &snapshot.identity != identity {
            return Err(PoiCacheError::MetadataMismatch {
                reason: "cache identity mismatch".to_string(),
            });
        }
        snapshot.forest.compute_roots();
        Ok(Some(Self { snapshot }))
    }

    pub fn write(&self, path: &Path) -> Result<(), PoiCacheError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = rmp_serde::to_vec_named(&self.snapshot)?;
        let temp_path = temp_path(path);
        fs::write(&temp_path, data)?;
        fs::rename(temp_path, path)?;
        Ok(())
    }

    #[must_use]
    pub const fn identity(&self) -> &PoiCacheIdentity {
        &self.snapshot.identity
    }

    #[must_use]
    pub const fn progress(&self) -> &PoiCacheSyncProgress {
        &self.snapshot.progress
    }

    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.snapshot.forest.leaf_count()
    }

    #[must_use]
    pub fn position(&self, blinded_commitment: &FixedBytes<32>) -> Option<PoiCachePosition> {
        self.snapshot
            .position_by_blinded_commitment
            .get(blinded_commitment)
            .copied()
    }

    #[must_use]
    pub fn status(&self, blinded_commitment: &FixedBytes<32>) -> PoiStatus {
        self.snapshot
            .status_by_blinded_commitment
            .get(blinded_commitment)
            .copied()
            .unwrap_or(PoiStatus::Missing)
    }

    #[must_use]
    pub fn status_for_data(&self, data: &BlindedCommitmentData) -> PoiStatus {
        self.status(&data.blinded_commitment)
    }

    pub fn current_roots(&mut self) -> BTreeMap<u32, FixedBytes<32>> {
        self.snapshot.forest.compute_roots();
        self.snapshot
            .forest
            .roots()
            .into_iter()
            .map(|(tree, root)| (tree, fixed_from_u256(root)))
            .collect()
    }

    pub fn apply_poi_events(
        &mut self,
        events: &[PoiSyncedListEvent],
    ) -> Result<usize, PoiCacheError> {
        for event in events {
            let blinded_commitment = parse_fixed_hex(
                &event.signed_poi_event.blinded_commitment,
                "signedPOIEvent.blindedCommitment",
            )?;
            self.snapshot
                .status_by_blinded_commitment
                .insert(blinded_commitment, PoiStatus::Valid);
            self.snapshot.progress.next_event_index = self
                .snapshot
                .progress
                .next_event_index
                .max(next_index(event.signed_poi_event.index)?);
        }
        Ok(events.len())
    }

    pub fn apply_poi_leaves(
        &mut self,
        start_index: u64,
        leaves: &[String],
    ) -> Result<usize, PoiCacheError> {
        let mut inserted = 0usize;
        for (offset, leaf) in leaves.iter().enumerate() {
            let global_index = start_index
                .checked_add(offset as u64)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let leaf = parse_u256_hex(leaf, "poiMerkletreeLeaf")?;
            if leaf != U256::ZERO {
                let (tree_number, tree_position) = normalize_tree_position(0, global_index);
                self.snapshot.forest.insert_leaf(MerkleTreeUpdate {
                    tree_number,
                    tree_position,
                    hash: leaf,
                })?;
                let blinded_commitment = fixed_from_u256(leaf);
                self.snapshot.position_by_blinded_commitment.insert(
                    blinded_commitment,
                    PoiCachePosition {
                        global_index,
                        tree_number,
                        tree_position,
                    },
                );
                self.snapshot
                    .status_by_blinded_commitment
                    .insert(blinded_commitment, PoiStatus::Valid);
                inserted += 1;
            }
            self.snapshot.progress.next_leaf_index = self
                .snapshot
                .progress
                .next_leaf_index
                .max(next_index(global_index)?);
        }
        if inserted > 0 {
            self.snapshot.progress.root_validation = PoiCacheRootValidation::Pending;
        }
        Ok(inserted)
    }

    pub fn apply_blocked_shields(
        &mut self,
        blocked_shields: &[BlockedShield],
    ) -> Result<usize, PoiCacheError> {
        for blocked_shield in blocked_shields {
            let blinded_commitment = parse_fixed_hex(
                &blocked_shield.blinded_commitment,
                "blockedShield.blindedCommitment",
            )?;
            self.snapshot
                .blocked_shields_by_blinded_commitment
                .insert(blinded_commitment, blocked_shield.clone());
            if self.status(&blinded_commitment) != PoiStatus::Valid {
                self.snapshot
                    .status_by_blinded_commitment
                    .insert(blinded_commitment, PoiStatus::ShieldBlocked);
            }
        }
        self.snapshot.progress.blocked_shields_synced = true;
        Ok(blocked_shields.len())
    }

    pub async fn sync(
        &mut self,
        client: &PoiRpcClient,
    ) -> Result<PoiCacheSyncOutcome, PoiCacheError> {
        self.sync_with_page_sizes(
            client,
            POI_EVENTS_PAGE_SIZE,
            POI_MERKLETREE_LEAVES_PAGE_SIZE,
        )
        .await
    }

    pub async fn sync_with_page_sizes(
        &mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
    ) -> Result<PoiCacheSyncOutcome, PoiCacheError> {
        if event_page_size == 0 || leaf_page_size == 0 {
            return Err(PoiCacheError::InvalidPageSize);
        }

        let sync_started = Instant::now();
        debug!(
            chain_type = self.snapshot.identity.chain_type,
            chain_id = self.snapshot.identity.chain_id,
            txid_version = %self.snapshot.identity.txid_version,
            list_key = %hex::encode(self.snapshot.identity.list_key),
            next_event_index = self.snapshot.progress.next_event_index,
            next_leaf_index = self.snapshot.progress.next_leaf_index,
            blocked_shields_synced = self.snapshot.progress.blocked_shields_synced,
            event_page_size,
            leaf_page_size,
            "local POI cache sync started"
        );

        let mut outcome = PoiCacheSyncOutcome::default();
        loop {
            let start_index = self.snapshot.progress.next_event_index;
            let end_index = start_index
                .checked_add(event_page_size - 1)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let page_started = Instant::now();
            let events = client
                .poi_events(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    start_index,
                    end_index,
                )
                .await?;
            if events.is_empty() {
                debug!(
                    chain_id = self.snapshot.identity.chain_id,
                    list_key = %hex::encode(self.snapshot.identity.list_key),
                    start_index,
                    end_index,
                    elapsed_ms = page_started.elapsed().as_millis(),
                    "local POI events sync reached empty page"
                );
                break;
            }
            let returned = events.len();
            let applied = self.apply_poi_events(&events)?;
            outcome.events += applied;
            debug!(
                chain_id = self.snapshot.identity.chain_id,
                list_key = %hex::encode(self.snapshot.identity.list_key),
                start_index,
                end_index,
                returned,
                applied,
                next_event_index = self.snapshot.progress.next_event_index,
                elapsed_ms = page_started.elapsed().as_millis(),
                events_per_sec = rate_per_sec(returned, page_started.elapsed()),
                "local POI events page synced"
            );
            if events.len() < event_page_size as usize {
                break;
            }
        }

        while self.snapshot.progress.next_leaf_index < self.snapshot.progress.next_event_index {
            let start_index = self.snapshot.progress.next_leaf_index;
            let remaining = self.snapshot.progress.next_event_index - start_index;
            let page_size = leaf_page_size.min(remaining);
            let end_index = start_index
                .checked_add(page_size)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let page_started = Instant::now();
            let leaves = client
                .poi_merkletree_leaves(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    start_index,
                    end_index,
                )
                .await?;
            if leaves.is_empty() {
                debug!(
                    chain_id = self.snapshot.identity.chain_id,
                    list_key = %hex::encode(self.snapshot.identity.list_key),
                    start_index,
                    end_index,
                    elapsed_ms = page_started.elapsed().as_millis(),
                    "local POI leaves sync reached empty page"
                );
                break;
            }
            let returned = leaves.len();
            let applied = self.apply_poi_leaves(start_index, &leaves)?;
            outcome.leaves += applied;
            debug!(
                chain_id = self.snapshot.identity.chain_id,
                list_key = %hex::encode(self.snapshot.identity.list_key),
                start_index,
                end_index,
                returned,
                applied,
                next_leaf_index = self.snapshot.progress.next_leaf_index,
                elapsed_ms = page_started.elapsed().as_millis(),
                leaves_per_sec = rate_per_sec(returned, page_started.elapsed()),
                "local POI leaves page synced"
            );
            if leaves.len() < page_size as usize {
                break;
            }
        }

        let blocked_started = Instant::now();
        let blocked_shields = client
            .filtered_blocked_shields(
                &self.snapshot.identity.txid_version,
                self.snapshot.identity.chain_type,
                self.snapshot.identity.chain_id,
                &self.snapshot.identity.list_key,
                None,
            )
            .await?;
        outcome.blocked_shields = self.apply_blocked_shields(&blocked_shields)?;
        debug!(
            chain_id = self.snapshot.identity.chain_id,
            list_key = %hex::encode(self.snapshot.identity.list_key),
            returned = blocked_shields.len(),
            applied = outcome.blocked_shields,
            elapsed_ms = blocked_started.elapsed().as_millis(),
            "local POI blocked shields synced"
        );

        debug!(
            chain_id = self.snapshot.identity.chain_id,
            list_key = %hex::encode(self.snapshot.identity.list_key),
            events = outcome.events,
            leaves = outcome.leaves,
            blocked_shields = outcome.blocked_shields,
            leaf_count = self.leaf_count(),
            elapsed_ms = sync_started.elapsed().as_millis(),
            "local POI cache sync finished"
        );

        Ok(outcome)
    }

    pub async fn validate_roots(&mut self, client: &PoiRpcClient) -> Result<bool, PoiCacheError> {
        let roots = self.current_roots();
        let root_hexes = roots.values().map(hex::encode).collect::<Vec<_>>();
        let accepted = !root_hexes.is_empty()
            && client
                .validate_poi_merkleroots(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    &root_hexes,
                )
                .await?;
        self.snapshot.progress.root_validation = if accepted {
            PoiCacheRootValidation::Validated { roots }
        } else {
            PoiCacheRootValidation::Invalid { roots }
        };
        Ok(accepted)
    }

    pub fn poi_merkle_proofs(
        &mut self,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PoiCacheError> {
        self.ensure_roots_validated()?;
        blinded_commitments
            .iter()
            .map(|blinded_commitment| self.poi_merkle_proof(blinded_commitment))
            .collect()
    }

    fn ensure_roots_validated(&mut self) -> Result<(), PoiCacheError> {
        let roots = self.current_roots();
        if self.snapshot.progress.root_validation.accepts(&roots) {
            Ok(())
        } else if self.snapshot.progress.root_validation.rejects(&roots) {
            Err(PoiCacheError::InvalidRoots)
        } else {
            Err(PoiCacheError::RootValidationRequired)
        }
    }

    fn poi_merkle_proof(
        &self,
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<PoiMerkleProof, PoiCacheError> {
        let position = self
            .snapshot
            .position_by_blinded_commitment
            .get(blinded_commitment)
            .ok_or(PoiCacheError::MissingCommitment {
                blinded_commitment: *blinded_commitment,
            })?;
        let proof = self
            .snapshot
            .forest
            .prove(position.tree_number, position.tree_position)
            .ok_or(PoiCacheError::MissingCommitment {
                blinded_commitment: *blinded_commitment,
            })?;
        let leaf = fixed_from_u256(proof.leaf);
        if leaf != *blinded_commitment {
            return Err(PoiCacheError::LeafMismatch {
                blinded_commitment: *blinded_commitment,
                leaf,
            });
        }
        Ok(poi_merkle_proof_from_cache(&proof))
    }
}

fn poi_merkle_proof_from_cache(proof: &MerkleProof) -> PoiMerkleProof {
    PoiMerkleProof {
        leaf: encode_u256_prefixed(proof.leaf),
        elements: proof
            .path_elements
            .iter()
            .copied()
            .map(encode_u256_prefixed)
            .collect(),
        indices: format!("0x{:064x}", U256::from(proof.leaf_index)),
        root: encode_u256_prefixed(proof.root),
    }
}

fn fixed_from_u256(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

fn encode_u256_prefixed(value: U256) -> String {
    hex::encode_prefixed(fixed_from_u256(value))
}

fn parse_fixed_hex(value: &str, field: &'static str) -> Result<FixedBytes<32>, PoiCacheError> {
    parse_u256_hex(value, field).map(fixed_from_u256)
}

fn parse_u256_hex(value: &str, field: &'static str) -> Result<U256, PoiCacheError> {
    let value_without_prefix = value.strip_prefix("0x").unwrap_or(value);
    if value_without_prefix.len() > 64 {
        return Err(PoiCacheError::InvalidHex {
            field,
            value: value.to_string(),
        });
    }
    if value_without_prefix.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(value_without_prefix, 16).map_err(|_| PoiCacheError::InvalidHex {
        field,
        value: value.to_string(),
    })
}

fn next_index(index: u64) -> Result<u64, PoiCacheError> {
    index.checked_add(1).ok_or(PoiCacheError::RangeOverflow)
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("poi-cache.msgpack");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp_name = format!("{file_name}.tmp.{pid}.{nanos}");
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(temp_name);
    temp_path
}

fn rate_per_sec(count: usize, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        0.0
    } else {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        f64::from(count) / secs
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::poi::{PoiEventType, SignedPoiEvent};

    struct MockJsonRpc {
        url: reqwest::Url,
        requests: Receiver<String>,
    }

    fn identity() -> PoiCacheIdentity {
        PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from([0x11; 32]))
    }

    fn temp_cache_path() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-tests");
        fs::create_dir_all(&dir).expect("create temp cache dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        dir.join(format!("poi-cache-{pid}-{nanos}.msgpack"))
    }

    fn event(index: u64, blinded_commitment: FixedBytes<32>) -> PoiSyncedListEvent {
        PoiSyncedListEvent {
            signed_poi_event: SignedPoiEvent {
                index,
                blinded_commitment: hex::encode_prefixed(blinded_commitment),
                signature: "signature".to_string(),
                event_type: PoiEventType::Shield,
            },
            validated_merkleroot: hex::encode(FixedBytes::from([0x44; 32])),
        }
    }

    fn blocked(blinded_commitment: FixedBytes<32>) -> BlockedShield {
        BlockedShield {
            commitment_hash: hex::encode_prefixed(FixedBytes::from([0x99; 32])),
            blinded_commitment: hex::encode_prefixed(blinded_commitment),
            block_reason: Some("blocked".to_string()),
            signature: "signature".to_string(),
        }
    }

    fn spawn_json_rpc(responses: Vec<String>) -> MockJsonRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
            .expect("mock url");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let body = read_http_body(&mut stream);
                tx.send(body).expect("send request body");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                stream.write_all(reply.as_bytes()).expect("write response");
            }
        });
        MockJsonRpc { url, requests: rx }
    }

    fn read_http_body(stream: &mut std::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "connection closed before request body");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some((body_start, content_length)) = request_body_bounds(&buffer)
                && buffer.len() >= body_start + content_length
            {
                return String::from_utf8_lossy(&buffer[body_start..body_start + content_length])
                    .to_string();
            }
        }
    }

    fn request_body_bounds(buffer: &[u8]) -> Option<(usize, usize)> {
        let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        Some((body_start, content_length))
    }

    fn json_rpc_result(result: &Value) -> String {
        json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    fn request_json(mock: &MockJsonRpc) -> Value {
        let body = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("receive request");
        serde_json::from_str(&body).expect("request json")
    }

    #[test]
    fn cache_snapshot_roundtrip_preserves_indexes_and_progress() {
        let path = temp_cache_path();
        let mut cache = PoiCache::new(identity());
        let valid_commitment = FixedBytes::from([0x22; 32]);
        let blocked_commitment = FixedBytes::from([0x33; 32]);
        let leaves = vec![hex::encode_prefixed(valid_commitment)];

        cache
            .apply_poi_events(&[event(0, valid_commitment)])
            .unwrap();
        cache.apply_poi_leaves(0, &leaves).unwrap();
        cache
            .apply_blocked_shields(&[blocked(blocked_commitment)])
            .unwrap();
        cache.write(&path).unwrap();

        let loaded = PoiCache::load(&path, &identity()).unwrap().unwrap();

        assert_eq!(loaded.progress().next_event_index, 1);
        assert_eq!(loaded.progress().next_leaf_index, 1);
        assert_eq!(loaded.leaf_count(), 1);
        assert_eq!(loaded.status(&valid_commitment), PoiStatus::Valid);
        assert_eq!(loaded.status(&blocked_commitment), PoiStatus::ShieldBlocked);
        assert_eq!(loaded.position(&valid_commitment).unwrap().global_index, 0);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn proof_generation_fails_closed_until_roots_are_validated() {
        let mut cache = PoiCache::new(identity());
        let blinded_commitment = FixedBytes::from([0x22; 32]);
        let leaves = vec![hex::encode_prefixed(blinded_commitment)];
        cache.apply_poi_leaves(0, &leaves).unwrap();

        let missing_validation = cache
            .poi_merkle_proofs(&[blinded_commitment])
            .expect_err("root validation should be required");
        assert!(matches!(
            missing_validation,
            PoiCacheError::RootValidationRequired
        ));

        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };
        let proofs = cache.poi_merkle_proofs(&[blinded_commitment]).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].leaf, hex::encode_prefixed(blinded_commitment));
        assert_eq!(proofs[0].elements.len(), broadcaster_core::tree::TREE_DEPTH);
        assert_eq!(
            proofs[0].indices,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );

        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Invalid { roots };
        let invalid_roots = cache
            .poi_merkle_proofs(&[blinded_commitment])
            .expect_err("rejected roots should fail closed");
        assert!(matches!(invalid_roots, PoiCacheError::InvalidRoots));
    }

    #[test]
    fn local_proofs_match_merkle_forest_for_representative_leaves() {
        let mut cache = PoiCache::new(identity());
        let commitments = [
            FixedBytes::from([0x22; 32]),
            FixedBytes::from([0x33; 32]),
            FixedBytes::from([0x44; 32]),
        ];
        let leaves = commitments
            .iter()
            .copied()
            .map(hex::encode_prefixed)
            .collect::<Vec<_>>();
        cache.apply_poi_leaves(0, &leaves).unwrap();
        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

        let mut expected_forest = MerkleForest::new();
        for (index, commitment) in commitments.iter().enumerate() {
            expected_forest
                .insert_leaf(MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: index as u64,
                    hash: U256::from_be_bytes(commitment.0),
                })
                .expect("insert expected leaf");
        }
        let expected = [commitments[0], commitments[2]]
            .iter()
            .map(|commitment| {
                let position = cache.position(commitment).expect("position");
                let proof = expected_forest
                    .prove(position.tree_number, position.tree_position)
                    .expect("expected proof");
                poi_merkle_proof_from_cache(&proof)
            })
            .collect::<Vec<_>>();

        let actual = cache
            .poi_merkle_proofs(&[commitments[0], commitments[2]])
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_local_proof_data_fails_closed() {
        let mut cache = PoiCache::new(identity());
        let present = FixedBytes::from([0x22; 32]);
        let missing = FixedBytes::from([0x33; 32]);
        cache
            .apply_poi_leaves(0, &[hex::encode_prefixed(present)])
            .unwrap();
        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

        let err = cache
            .poi_merkle_proofs(&[missing])
            .expect_err("missing proof data should fail closed");

        assert!(matches!(
            err,
            PoiCacheError::MissingCommitment {
                blinded_commitment
            } if blinded_commitment == missing
        ));
    }

    #[tokio::test]
    async fn sync_uses_paginated_bulk_methods_without_wallet_scoped_reads() {
        let commitment_0 = FixedBytes::from([0x22; 32]);
        let commitment_1 = FixedBytes::from([0x33; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment_0), event(1, commitment_1)])),
            json_rpc_result(&json!([])),
            json_rpc_result(&json!([
                hex::encode_prefixed(commitment_0),
                hex::encode_prefixed(commitment_1),
            ])),
            json_rpc_result(&json!([])),
        ]);
        let client = PoiRpcClient::new(mock.url.clone());
        let mut cache = PoiCache::new(identity());

        let outcome = cache.sync_with_page_sizes(&client, 2, 2).await.unwrap();

        assert_eq!(outcome.events, 2);
        assert_eq!(outcome.leaves, 2);
        assert_eq!(outcome.blocked_shields, 0);
        assert_eq!(cache.status(&commitment_0), PoiStatus::Valid);
        assert_eq!(cache.status(&commitment_1), PoiStatus::Valid);

        let requests = [
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
        ];
        let methods = requests
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec![
                "ppoi_poi_events",
                "ppoi_poi_events",
                "ppoi_poi_merkletree_leaves",
                "ppoi_blocked_shields",
            ]
        );
        assert!(!methods.contains(&"ppoi_pois_per_list"));
        assert!(!methods.contains(&"ppoi_merkle_proofs"));
        assert_eq!(requests[0]["params"]["startIndex"], 0);
        assert_eq!(requests[0]["params"]["endIndex"], 1);
        assert_eq!(requests[1]["params"]["startIndex"], 2);
        assert_eq!(requests[1]["params"]["endIndex"], 3);
        assert_eq!(requests[2]["params"]["startIndex"], 0);
        assert_eq!(requests[2]["params"]["endIndex"], 2);
        assert!(requests[3]["params"].get("bloomFilterSerialized").is_none());
    }
}
