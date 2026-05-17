use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::tree::normalize_tree_position;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord};
use poi::artifacts::{
    ArtifactDescriptor, BlockedShieldsArtifact, BlockedShieldsArtifactError, Manifest,
    ManifestEntry, ManifestError, Snapshot, SnapshotError, SnapshotKind, SnapshotReader,
    verify_blocked_shield, verify_poi_event,
};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity};
use poi::poi::{BlockedShield, SignedPoiEvent};
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig};

pub(crate) struct PoiArtifactIngestor {
    config: PoiArtifactSourceConfig,
    client: reqwest::Client,
}

impl PoiArtifactIngestor {
    pub(crate) const fn new(config: PoiArtifactSourceConfig, client: reqwest::Client) -> Self {
        Self { config, client }
    }

    pub(crate) async fn fetch_manifest(
        &self,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<Manifest, PoiArtifactError> {
        let manifest_url = self.manifest_url()?;
        let bytes = self.fetch_url(&manifest_url).await?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(PoiArtifactError::Json)?;
        manifest.verify_trusted_signature(&fixed_bytes(&self.config.trusted_publisher_pubkey))?;
        validate_manifest_sequence(&manifest, last_accepted_sequence)?;
        validate_manifest_freshness(
            &manifest,
            last_accepted_sequence,
            self.config.max_manifest_age,
            now,
        )?;
        Ok(manifest)
    }

    pub(crate) async fn fetch_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
    ) -> Result<Vec<u8>, PoiArtifactError> {
        let urls = self.artifact_urls(&descriptor.cid)?;
        let bytes = self.fetch_first_available(&urls).await?;
        descriptor.verify_bytes(&bytes)?;
        Ok(bytes)
    }

    pub(crate) async fn fetch_verified_cache(
        &self,
        identity: PoiCacheIdentity,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let manifest = self.fetch_manifest(last_accepted_sequence, now).await?;
        let entry = manifest_entry_for_identity(&manifest, &identity)?.clone();
        let mut cache = PoiCache::new(identity.clone());

        let base_bytes = self.fetch_artifact(&entry.base).await?;
        let base = SnapshotReader::read(&base_bytes)?;
        let mut next_start = validate_snapshot(&base, &identity, &entry, SnapshotKind::Base, 0)?;
        verify_snapshot_events(&base, &fixed_bytes(&identity.list_key))?;
        cache.apply_verified_artifact_events(&base.events)?;

        for delta_descriptor in &entry.deltas {
            let delta_bytes = self.fetch_artifact(delta_descriptor).await?;
            let delta = SnapshotReader::read(&delta_bytes)?;
            next_start =
                validate_snapshot(&delta, &identity, &entry, SnapshotKind::Delta, next_start)?;
            verify_snapshot_events(&delta, &fixed_bytes(&identity.list_key))?;
            cache.apply_verified_artifact_events(&delta.events)?;
        }

        let final_index = next_start
            .checked_sub(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        if final_index != entry.current_tip_index {
            return Err(PoiArtifactError::ReplayTipMismatch {
                expected: entry.current_tip_index,
                actual: final_index,
            });
        }

        let blocked_bytes = self.fetch_artifact(&entry.blocked_shields).await?;
        let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
        let blocked_records = validate_blocked_shields_artifact(&blocked, &identity)?;
        for record in &blocked_records {
            verify_blocked_shield(record, &fixed_bytes(&identity.list_key))?;
        }
        cache.apply_blocked_shields(&blocked_records)?;

        verify_manifest_root(&mut cache, &entry)?;
        let accepted_roots = cache.accept_current_roots();
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence = manifest.sequence,
            roots = accepted_roots.len(),
            "accepted POI artifact cache refresh"
        );

        Ok(PoiArtifactRefresh {
            manifest_sequence: manifest.sequence,
            cache,
            entry,
        })
    }

    pub(crate) async fn refresh_persisted_cache(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        now: SystemTime,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let persisted = load_persisted_cache(db, &identity)?;
        let last_sequence = persisted
            .as_ref()
            .map(|persisted| persisted.record.last_accepted_manifest_sequence);
        let refresh = self
            .refresh_verified_cache(identity, persisted, last_sequence, now)
            .await?;
        persist_refresh(db, refresh.identity(), &refresh)?;
        Ok(refresh)
    }

    async fn refresh_verified_cache(
        &self,
        identity: PoiCacheIdentity,
        persisted: Option<PersistedPoiArtifactCache>,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let manifest = self.fetch_manifest(last_accepted_sequence, now).await?;
        let entry = manifest_entry_for_identity(&manifest, &identity)?.clone();

        if let Some(persisted) = persisted
            && let Some(refresh) = self
                .try_incremental_refresh(&identity, manifest.sequence, &entry, persisted)
                .await?
        {
            return Ok(refresh);
        }

        self.fetch_verified_cache(identity, last_accepted_sequence, now)
            .await
    }

    async fn try_incremental_refresh(
        &self,
        identity: &PoiCacheIdentity,
        manifest_sequence: u64,
        entry: &ManifestEntry,
        persisted: PersistedPoiArtifactCache,
    ) -> Result<Option<PoiArtifactRefresh>, PoiArtifactError> {
        if !descriptor_matches_record(&entry.base, &persisted.record.base_descriptor) {
            return Ok(None);
        }
        if persisted.record.current_tip_index > entry.current_tip_index {
            return Ok(None);
        }

        let applied_delta_count =
            common_delta_prefix_len(&persisted.record.applied_delta_descriptors, &entry.deltas);
        if applied_delta_count != persisted.record.applied_delta_descriptors.len() {
            return Ok(None);
        }

        let mut cache = persisted.cache;
        let mut next_start = persisted
            .record
            .current_tip_index
            .checked_add(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;

        for delta_descriptor in entry.deltas.iter().skip(applied_delta_count) {
            let delta_bytes = self.fetch_artifact(delta_descriptor).await?;
            let delta = SnapshotReader::read(&delta_bytes)?;
            next_start =
                validate_snapshot(&delta, identity, entry, SnapshotKind::Delta, next_start)?;
            verify_snapshot_events(&delta, &fixed_bytes(&identity.list_key))?;
            cache.apply_verified_artifact_events(&delta.events)?;
        }

        let final_index = next_start
            .checked_sub(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        if final_index != entry.current_tip_index {
            return Err(PoiArtifactError::ReplayTipMismatch {
                expected: entry.current_tip_index,
                actual: final_index,
            });
        }

        if !descriptor_matches_record(
            &entry.blocked_shields,
            &persisted.record.blocked_shields_descriptor,
        ) {
            let blocked_bytes = self.fetch_artifact(&entry.blocked_shields).await?;
            let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
            let blocked_records = validate_blocked_shields_artifact(&blocked, identity)?;
            for record in &blocked_records {
                verify_blocked_shield(record, &fixed_bytes(&identity.list_key))?;
            }
            cache.apply_blocked_shields(&blocked_records)?;
        }

        verify_manifest_root(&mut cache, entry)?;
        cache.accept_current_roots();
        Ok(Some(PoiArtifactRefresh {
            manifest_sequence,
            cache,
            entry: entry.clone(),
        }))
    }

    fn manifest_url(&self) -> Result<Url, PoiArtifactError> {
        match &self.config.manifest_source {
            PoiArtifactManifestSource::Url(url) => Ok(url.clone()),
            PoiArtifactManifestSource::Cid(cid) => self.gateway_url("ipfs", cid),
            PoiArtifactManifestSource::IpnsName(name) => self.gateway_url("ipns", name),
        }
    }

    fn artifact_urls(&self, cid: &str) -> Result<Vec<Url>, PoiArtifactError> {
        self.config
            .gateway_urls
            .iter()
            .map(|gateway| gateway_url(gateway, "ipfs", cid))
            .collect()
    }

    fn gateway_url(&self, namespace: &'static str, value: &str) -> Result<Url, PoiArtifactError> {
        let Some(gateway) = self.config.gateway_urls.first() else {
            return Err(PoiArtifactError::NoGateways);
        };
        gateway_url(gateway, namespace, value)
    }

    async fn fetch_first_available(&self, urls: &[Url]) -> Result<Vec<u8>, PoiArtifactError> {
        if urls.is_empty() {
            return Err(PoiArtifactError::NoGateways);
        }
        let mut last_error = None;
        for url in urls {
            match self.fetch_url(url).await {
                Ok(bytes) => return Ok(bytes),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or(PoiArtifactError::NoGateways))
    }

    async fn fetch_url(&self, url: &Url) -> Result<Vec<u8>, PoiArtifactError> {
        let response = self.client.get(url.clone()).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(PoiArtifactError::HttpStatus {
                url: url.clone(),
                status,
            });
        }
        Ok(response.bytes().await?.to_vec())
    }
}

pub(crate) struct PoiArtifactRefresh {
    pub(crate) manifest_sequence: u64,
    pub(crate) cache: PoiCache,
    pub(crate) entry: ManifestEntry,
}

impl PoiArtifactRefresh {
    fn identity(&self) -> &PoiCacheIdentity {
        self.cache.identity()
    }
}

pub(crate) struct PersistedPoiArtifactCache {
    pub(crate) record: PoiArtifactCacheRecord,
    pub(crate) cache: PoiCache,
}

#[derive(Debug, Error)]
pub(crate) enum PoiArtifactError {
    #[error("POI artifact source has no gateway URLs configured")]
    NoGateways,
    #[error("POI artifact HTTP request failed")]
    Http(#[from] reqwest::Error),
    #[error("POI artifact HTTP request to {url} returned {status}")]
    HttpStatus {
        url: Url,
        status: reqwest::StatusCode,
    },
    #[error("POI artifact manifest JSON decode failed")]
    Json(#[source] serde_json::Error),
    #[error("POI artifact manifest verification failed")]
    Manifest(#[from] ManifestError),
    #[error("POI snapshot verification failed")]
    Snapshot(#[from] SnapshotError),
    #[error("blocked-shields artifact verification failed")]
    BlockedShieldsArtifact(#[from] BlockedShieldsArtifactError),
    #[error("POI artifact upstream signature verification failed")]
    Verify(#[from] poi::artifacts::VerifyError),
    #[error("POI artifact cache replay failed")]
    Cache(#[from] PoiCacheError),
    #[error("POI artifact cache persistence failed")]
    Db(#[from] local_db::DbError),
    #[error("manifest sequence rollback: previous={previous}, received={received}")]
    ManifestSequenceRollback { previous: u64, received: u64 },
    #[error("manifest is stale on first run: age={age:?}, max={max:?}")]
    ManifestStale { age: Duration, max: Duration },
    #[error("manifest issued_at_ms is in the future")]
    ManifestIssuedInFuture,
    #[error("manifest does not contain entry for chain_id={chain_id} list_key={list_key}")]
    MissingManifestEntry { chain_id: u64, list_key: String },
    #[error("invalid hex in {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("snapshot scope mismatch for {field}: expected {expected}, got {actual}")]
    SnapshotScopeMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("snapshot kind mismatch: expected {expected:?}, got {actual:?}")]
    SnapshotKindMismatch {
        expected: SnapshotKind,
        actual: SnapshotKind,
    },
    #[error("snapshot start index mismatch: expected {expected}, got {actual}")]
    SnapshotStartMismatch { expected: u64, actual: u64 },
    #[error("snapshot range overflow")]
    RangeOverflow,
    #[error("artifact replay tip mismatch: expected {expected}, got {actual}")]
    ReplayTipMismatch { expected: u64, actual: u64 },
    #[error("replayed POI root missing for tree {tree_number}")]
    MissingReplayRoot { tree_number: u32 },
    #[error("replayed POI root mismatch: expected {expected}, got {actual}")]
    ReplayRootMismatch { expected: String, actual: String },
}

pub(crate) fn load_persisted_cache(
    db: &DbStore,
    identity: &PoiCacheIdentity,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    let Some(record) = db.get_poi_artifact_cache(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )?
    else {
        return Ok(None);
    };
    let cache = PoiCache::from_bytes(&record.cache_payload, identity)?;
    Ok(Some(PersistedPoiArtifactCache { record, cache }))
}

pub(crate) fn persist_refresh(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    refresh: &PoiArtifactRefresh,
) -> Result<(), PoiArtifactError> {
    let current_tip_root = FixedBytes::from(decode_fixed_hex::<32>(
        "entry.current_tip_merkleroot",
        &refresh.entry.current_tip_merkleroot,
    )?);
    let record = PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        last_accepted_manifest_sequence: refresh.manifest_sequence,
        base_descriptor: descriptor_record(&refresh.entry.base),
        applied_delta_descriptors: refresh.entry.deltas.iter().map(descriptor_record).collect(),
        blocked_shields_descriptor: descriptor_record(&refresh.entry.blocked_shields),
        current_tip_index: refresh.entry.current_tip_index,
        current_tip_root,
        cache_payload: refresh.cache.to_bytes()?,
        updated_at: 0,
    };
    db.put_poi_artifact_cache(&record)?;
    Ok(())
}

fn validate_manifest_sequence(
    manifest: &Manifest,
    last_accepted_sequence: Option<u64>,
) -> Result<(), PoiArtifactError> {
    if let Some(previous) = last_accepted_sequence
        && manifest.sequence < previous
    {
        return Err(PoiArtifactError::ManifestSequenceRollback {
            previous,
            received: manifest.sequence,
        });
    }
    Ok(())
}

fn validate_manifest_freshness(
    manifest: &Manifest,
    last_accepted_sequence: Option<u64>,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), PoiArtifactError> {
    if last_accepted_sequence.is_some() {
        return Ok(());
    }
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = UNIX_EPOCH + Duration::from_millis(manifest.issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| PoiArtifactError::ManifestIssuedInFuture)?;
    if age > max_age {
        return Err(PoiArtifactError::ManifestStale { age, max: max_age });
    }
    Ok(())
}

fn manifest_entry_for_identity<'a>(
    manifest: &'a Manifest,
    identity: &PoiCacheIdentity,
) -> Result<&'a ManifestEntry, PoiArtifactError> {
    for entry in &manifest.entries {
        let list_key = decode_fixed_hex::<32>("entry.list_key", &entry.list_key)?;
        if entry.chain_id == identity.chain_id && list_key == fixed_bytes(&identity.list_key) {
            return Ok(entry);
        }
    }
    Err(PoiArtifactError::MissingManifestEntry {
        chain_id: identity.chain_id,
        list_key: hex::encode(identity.list_key),
    })
}

fn validate_snapshot(
    snapshot: &Snapshot,
    identity: &PoiCacheIdentity,
    entry: &ManifestEntry,
    expected_kind: SnapshotKind,
    expected_start: u64,
) -> Result<u64, PoiArtifactError> {
    if snapshot.header.kind != expected_kind {
        return Err(PoiArtifactError::SnapshotKindMismatch {
            expected: expected_kind,
            actual: snapshot.header.kind,
        });
    }
    if snapshot.header.start_index != expected_start {
        return Err(PoiArtifactError::SnapshotStartMismatch {
            expected: expected_start,
            actual: snapshot.header.start_index,
        });
    }
    require_scope_bytes(
        "list_key",
        &snapshot.header.list_key,
        &fixed_bytes(&identity.list_key),
    )?;
    require_scope_value("chain_id", snapshot.header.chain_id, identity.chain_id)?;
    require_scope_value(
        "chain_type",
        snapshot.header.chain_type,
        identity.chain_type,
    )?;
    let entry_list_key = decode_fixed_hex::<32>("entry.list_key", &entry.list_key)?;
    require_scope_bytes(
        "entry.list_key",
        &entry_list_key,
        &fixed_bytes(&identity.list_key),
    )?;
    require_scope_value("entry.chain_id", entry.chain_id, identity.chain_id)?;

    snapshot
        .header
        .end_index
        .checked_add(1)
        .ok_or(PoiArtifactError::RangeOverflow)
}

fn verify_snapshot_events(
    snapshot: &Snapshot,
    list_key: &[u8; 32],
) -> Result<(), PoiArtifactError> {
    for event in &snapshot.events {
        let signed = SignedPoiEvent {
            index: event.event_index,
            blinded_commitment: prefixed_hex(&event.blinded_commitment),
            signature: hex::encode(event.signature),
            event_type: event.event_type,
        };
        verify_poi_event(&signed, list_key)?;
    }
    Ok(())
}

fn validate_blocked_shields_artifact(
    artifact: &BlockedShieldsArtifact,
    identity: &PoiCacheIdentity,
) -> Result<Vec<BlockedShield>, PoiArtifactError> {
    require_scope_value(
        "blocked_shields.format_version",
        artifact.format_version,
        poi::artifacts::snapshot::format::FORMAT_VERSION,
    )?;
    let list_key = decode_fixed_hex::<32>("blocked_shields.list_key", &artifact.list_key)?;
    require_scope_bytes(
        "blocked_shields.list_key",
        &list_key,
        &fixed_bytes(&identity.list_key),
    )?;
    require_scope_value(
        "blocked_shields.chain_id",
        artifact.chain_id,
        identity.chain_id,
    )?;
    require_scope_value(
        "blocked_shields.chain_type",
        artifact.chain_type,
        identity.chain_type,
    )?;
    Ok(artifact
        .blocked_shields
        .iter()
        .cloned()
        .map(|record| record.into_signed_blocked_shield())
        .collect())
}

fn verify_manifest_root(
    cache: &mut PoiCache,
    entry: &ManifestEntry,
) -> Result<(), PoiArtifactError> {
    let expected_root = FixedBytes::from(decode_fixed_hex::<32>(
        "entry.current_tip_merkleroot",
        &entry.current_tip_merkleroot,
    )?);
    let (tree_number, _) = normalize_tree_position(0, entry.current_tip_index);
    let roots = cache.current_roots();
    let actual = roots
        .get(&tree_number)
        .copied()
        .ok_or(PoiArtifactError::MissingReplayRoot { tree_number })?;
    if actual != expected_root {
        return Err(PoiArtifactError::ReplayRootMismatch {
            expected: prefixed_hex(expected_root.as_slice()),
            actual: prefixed_hex(actual.as_slice()),
        });
    }
    Ok(())
}

fn gateway_url(
    gateway: &Url,
    namespace: &'static str,
    value: &str,
) -> Result<Url, PoiArtifactError> {
    let mut url = gateway.clone();
    let path = gateway.path().trim_end_matches('/');
    let namespace_suffix = format!("/{namespace}");
    let new_path = if path.ends_with(&namespace_suffix) {
        format!("{path}/{value}")
    } else if path.is_empty() {
        format!("/{namespace}/{value}")
    } else {
        format!("{path}/{namespace}/{value}")
    };
    url.set_path(&new_path);
    Ok(url)
}

fn require_scope_bytes(
    field: &'static str,
    actual: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), PoiArtifactError> {
    if actual == expected {
        return Ok(());
    }
    Err(PoiArtifactError::SnapshotScopeMismatch {
        field,
        expected: prefixed_hex(expected),
        actual: prefixed_hex(actual),
    })
}

fn require_scope_value<T>(
    field: &'static str,
    actual: T,
    expected: T,
) -> Result<(), PoiArtifactError>
where
    T: Copy + PartialEq + ToString,
{
    if actual == expected {
        return Ok(());
    }
    Err(PoiArtifactError::SnapshotScopeMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], PoiArtifactError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|_| {
        PoiArtifactError::InvalidHex {
            field,
            value: value.to_string(),
        }
    })?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PoiArtifactError::InvalidByteLen {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

fn descriptor_record(descriptor: &ArtifactDescriptor) -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: descriptor.cid.clone(),
        sha256: descriptor.sha256.clone(),
        byte_size: descriptor.byte_size,
    }
}

fn descriptor_matches_record(
    descriptor: &ArtifactDescriptor,
    record: &PoiArtifactDescriptorRecord,
) -> bool {
    descriptor.cid == record.cid
        && descriptor.sha256 == record.sha256
        && descriptor.byte_size == record.byte_size
}

fn common_delta_prefix_len(
    records: &[PoiArtifactDescriptorRecord],
    descriptors: &[ArtifactDescriptor],
) -> usize {
    records
        .iter()
        .zip(descriptors.iter())
        .take_while(|(record, descriptor)| descriptor_matches_record(descriptor, record))
        .count()
}

fn fixed_bytes(value: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use poi::artifacts::{SnapshotEvent, SnapshotHeader, snapshot::format};

    #[test]
    fn manifest_sequence_rollback_is_rejected() {
        let manifest = Manifest::new(2, 1_700_000_000_000, 4, "publisher".to_string(), vec![]);

        assert!(matches!(
            validate_manifest_sequence(&manifest, Some(5)),
            Err(PoiArtifactError::ManifestSequenceRollback {
                previous: 5,
                received: 4,
            })
        ));
    }

    #[test]
    fn stale_first_run_manifest_is_rejected() {
        let manifest = Manifest::new(2, 1_000, 1, "publisher".to_string(), vec![]);
        let now = UNIX_EPOCH + Duration::from_secs(10);

        assert!(matches!(
            validate_manifest_freshness(&manifest, None, Some(Duration::from_secs(1)), now),
            Err(PoiArtifactError::ManifestStale { .. })
        ));
        validate_manifest_freshness(&manifest, Some(1), Some(Duration::from_secs(1)), now)
            .expect("persisted sequence skips first-run freshness check");
    }

    #[test]
    fn snapshot_ranges_must_be_base_then_contiguous_deltas() {
        let identity = test_identity();
        let entry = test_entry(&identity, 2, [0_u8; 32]);
        let base = snapshot(&identity, SnapshotKind::Base, 0, 1);
        let delta = snapshot(&identity, SnapshotKind::Delta, 2, 2);
        let gap = snapshot(&identity, SnapshotKind::Delta, 3, 3);

        let next = validate_snapshot(&base, &identity, &entry, SnapshotKind::Base, 0)
            .expect("valid base snapshot");
        assert_eq!(next, 2);
        let next = validate_snapshot(&delta, &identity, &entry, SnapshotKind::Delta, next)
            .expect("valid contiguous delta");
        assert_eq!(next, 3);
        assert!(matches!(
            validate_snapshot(&gap, &identity, &entry, SnapshotKind::Delta, 2),
            Err(PoiArtifactError::SnapshotStartMismatch {
                expected: 2,
                actual: 3,
            })
        ));
    }

    #[test]
    fn replayed_cache_root_must_match_manifest_tip() {
        let identity = test_identity();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x44; 32],
                signature: [0_u8; 64],
                event_type: poi::poi::PoiEventType::Transact,
            }])
            .expect("apply event");
        let root = cache.current_roots().remove(&0).expect("root");
        let entry = test_entry(&identity, 0, *root);

        verify_manifest_root(&mut cache, &entry).expect("matching replay root");

        let mismatched = test_entry(&identity, 0, [0x55; 32]);
        assert!(matches!(
            verify_manifest_root(&mut cache, &mismatched),
            Err(PoiArtifactError::ReplayRootMismatch { .. })
        ));
    }

    #[test]
    fn blocked_shield_artifact_scope_and_signatures_are_verified() {
        let list_key = [
            0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e,
            0xc5, 0xf9, 0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69,
            0x14, 0x46, 0xd2, 0x2c,
        ];
        let identity = PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from(list_key));
        let signed = poi::poi::SignedBlockedShield {
            commitment_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            blinded_commitment:
                "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            block_reason: None,
            signature: "d6af83166868a93f3f3702f30ccf36a343193613925c3817752339b938eba3c6796adf2652544be5c0fc027025c889340fcdd3762313a66398f970d37a67ae03"
                .to_string(),
        };
        let artifact = BlockedShieldsArtifact::from_signed_records(
            format::FORMAT_VERSION,
            &list_key,
            identity.chain_id,
            identity.chain_type,
            &[0_u8; 32],
            &[signed],
        );

        let records = validate_blocked_shields_artifact(&artifact, &identity)
            .expect("valid blocked-shields scope");
        for record in &records {
            verify_blocked_shield(record, &list_key).expect("valid blocked-shield signature");
        }

        assert_eq!(records.len(), 1);
    }

    fn test_identity() -> PoiCacheIdentity {
        PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from([0x11; 32]))
    }

    fn test_entry(
        identity: &PoiCacheIdentity,
        current_tip_index: u64,
        current_tip_merkleroot: [u8; 32],
    ) -> ManifestEntry {
        ManifestEntry {
            list_key: prefixed_hex(identity.list_key.as_slice()),
            chain_id: identity.chain_id,
            base: descriptor("base"),
            deltas: vec![descriptor("delta")],
            blocked_shields: descriptor("blocked"),
            current_tip_index,
            current_tip_merkleroot: prefixed_hex(&current_tip_merkleroot),
        }
    }

    fn descriptor(cid: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: cid.to_string(),
            sha256: prefixed_hex(&[0_u8; 32]),
            byte_size: 0,
        }
    }

    fn snapshot(
        identity: &PoiCacheIdentity,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
    ) -> Snapshot {
        Snapshot {
            header: SnapshotHeader {
                format_version: format::FORMAT_VERSION,
                header_len: format::HEADER_LEN_U16,
                list_key: fixed_bytes(&identity.list_key),
                chain_id: identity.chain_id,
                chain_type: identity.chain_type,
                kind,
                start_index,
                end_index,
                event_count: end_index - start_index + 1,
                blocked_shield_count: 0,
                tip_merkleroot: [0_u8; 32],
                upstream_endpoint_hash: [0_u8; 32],
                created_at_unix_seconds: 1_700_000_000,
                events_offset: format::HEADER_LEN_U64,
                blocked_shields_offset: format::HEADER_LEN_U64,
            },
            events: Vec::new(),
            blocked_shields: Vec::new(),
        }
    }
}
