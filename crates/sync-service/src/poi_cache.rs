use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::DbStore;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::{PoiRpcClient, default_active_poi_list_keys};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use crate::poi_artifacts::{PersistedPoiArtifactCache, PoiArtifactIngestor, load_persisted_cache};
use crate::types::{LocalPoiCaches, PoiArtifactSourceConfig};
use crate::wallet::{
    LivePoiTailError, LivePoiTailOutcome, sync_live_poi_event_tail, wallet_poi_status_client,
};

const EVM_CHAIN_TYPE: u8 = 0;
const POI_ARTIFACT_CACHE_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
const POI_ARTIFACT_CACHE_LIVE_TAIL_INTERVAL: Duration = Duration::from_secs(60);

struct ChainPoiCacheState {
    local_caches: LocalPoiCaches,
}

struct ChainPoiCacheLoop {
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    artifact_config: PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: LocalPoiCaches,
    active_list_keys: Vec<FixedBytes<32>>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    cancel: CancellationToken,
}

pub struct PoiCacheService {
    db: Arc<DbStore>,
    artifact_config: PoiArtifactSourceConfig,
    http_client: Option<reqwest::Client>,
    chains: RwLock<HashMap<u64, ChainPoiCacheState>>,
    cancel: CancellationToken,
}

impl PoiCacheService {
    #[must_use]
    pub fn new(
        db: Arc<DbStore>,
        artifact_config: PoiArtifactSourceConfig,
        http_client: Option<reqwest::Client>,
    ) -> Self {
        Self {
            db,
            artifact_config,
            http_client,
            chains: RwLock::new(HashMap::new()),
            cancel: CancellationToken::new(),
        }
    }

    pub async fn start_chains(&self, chain_ids: impl IntoIterator<Item = u64>) {
        for chain_id in chain_ids {
            self.start_chain(chain_id).await;
        }
    }

    pub async fn start_chain(&self, chain_id: u64) -> LocalPoiCaches {
        if let Some(existing) = self.local_caches(chain_id).await {
            return existing;
        }

        let local_caches = Arc::new(RwLock::new(BTreeMap::new()));
        {
            let mut chains = self.chains.write().await;
            if let Some(existing) = chains.get(&chain_id) {
                return Arc::clone(&existing.local_caches);
            }
            chains.insert(
                chain_id,
                ChainPoiCacheState {
                    local_caches: Arc::clone(&local_caches),
                },
            );
        }

        let active_list_keys = default_active_poi_list_keys();
        let preloaded_caches = install_persisted_chain_poi_caches(
            self.db.as_ref(),
            chain_id,
            &local_caches,
            &active_list_keys,
        )
        .await;
        spawn_chain_poi_cache_loop(ChainPoiCacheLoop {
            db: Arc::clone(&self.db),
            http_client: self.http_client.clone(),
            artifact_config: self.artifact_config.clone(),
            chain_id,
            local_caches: Arc::clone(&local_caches),
            active_list_keys,
            preloaded_caches,
            cancel: self.cancel.child_token(),
        });
        local_caches
    }

    pub async fn local_caches(&self, chain_id: u64) -> Option<LocalPoiCaches> {
        self.chains
            .read()
            .await
            .get(&chain_id)
            .map(|state| Arc::clone(&state.local_caches))
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for PoiCacheService {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn spawn_chain_poi_cache_loop(task: ChainPoiCacheLoop) {
    let chain_id = task.chain_id;
    tokio::spawn(
        async move {
            run_chain_poi_cache_loop(task).await;
        }
        .instrument(tracing::info_span!("poi_artifact_cache", chain_id)),
    );
}

async fn run_chain_poi_cache_loop(mut task: ChainPoiCacheLoop) {
    let chain_id = task.chain_id;
    info!(
        chain_id,
        list_count = task.active_list_keys.len(),
        "starting chain-scoped artifact POI cache service"
    );
    let live_tail_client = task
        .http_client
        .as_ref()
        .and_then(|client| wallet_poi_status_client(Some(client)));
    let mut last_artifact_sync = Instant::now() - POI_ARTIFACT_CACHE_SYNC_INTERVAL;
    loop {
        let caches_available = chain_poi_caches_available_for_lists(
            chain_id,
            &task.local_caches,
            &task.active_list_keys,
        )
        .await;
        if !caches_available || last_artifact_sync.elapsed() >= POI_ARTIFACT_CACHE_SYNC_INTERVAL {
            sync_chain_poi_artifact_caches(
                task.db.as_ref(),
                task.http_client.as_ref(),
                &task.artifact_config,
                chain_id,
                &task.local_caches,
                &task.active_list_keys,
                std::mem::take(&mut task.preloaded_caches),
            )
            .await;
            last_artifact_sync = Instant::now();
        } else if let Some(client) = live_tail_client.as_ref() {
            sync_chain_poi_live_tails(client, chain_id, &task.local_caches, &task.active_list_keys)
                .await;
        }

        tokio::select! {
            _ = task.cancel.cancelled() => break,
            _ = tokio::time::sleep(POI_ARTIFACT_CACHE_LIVE_TAIL_INTERVAL) => {}
        }
    }
    info!(chain_id, "chain-scoped artifact POI cache service stopped");
}

async fn sync_chain_poi_artifact_caches(
    db: &DbStore,
    http_client: Option<&reqwest::Client>,
    artifact_config: &PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    mut preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
) {
    let ingestor = PoiArtifactIngestor::new(
        artifact_config.clone(),
        http_client.cloned().unwrap_or_else(reqwest::Client::new),
    );
    let live_tail_client = http_client.and_then(|client| wallet_poi_status_client(Some(client)));
    for list_key in active_list_keys {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        let sync_started = Instant::now();
        let artifact_refresh_started = Instant::now();
        let preloaded_cache = preloaded_caches.remove(list_key);
        let artifact_refresh = if let Some(preloaded_cache) = preloaded_cache {
            ingestor
                .refresh_persisted_cache_with_preloaded(
                    db,
                    identity.clone(),
                    Some(preloaded_cache),
                    0,
                    SystemTime::now(),
                )
                .await
        } else {
            ingestor
                .refresh_persisted_cache(db, identity.clone(), SystemTime::now())
                .await
        };
        let artifact_refresh_elapsed_ms = artifact_refresh_started.elapsed().as_millis();
        match artifact_refresh {
            Ok(refresh) => {
                let manifest_sequence = refresh.manifest_sequence;
                let artifact_tip_index = refresh.entry.current_tip_index;
                let mut cache = refresh.cache;
                let live_tail_started = Instant::now();
                let live_tail = if let Some(client) = live_tail_client.as_ref() {
                    match live_tail_candidate_cache(client, &cache).await {
                        Ok((tailed_cache, outcome)) => {
                            cache = tailed_cache;
                            Some(outcome)
                        }
                        Err(err) => {
                            warn!(
                                ?err,
                                chain_id,
                                list_key = %hex::encode(list_key),
                                "live POI event tail failed; using artifact checkpoint"
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let live_tail_elapsed_ms = live_tail_started.elapsed().as_millis();
                let local_tip_index = cache.progress().next_event_index.saturating_sub(1);
                let install_started = Instant::now();
                let install_lock_started = Instant::now();
                let mut caches = local_caches.write().await;
                let install_lock_wait_elapsed_ms = install_lock_started.elapsed().as_millis();
                let installed = install_cache_if_not_behind(&mut caches, *list_key, cache);
                drop(caches);
                info!(
                    chain_id,
                    list_key = %hex::encode(list_key),
                    manifest_sequence,
                    artifact_tip_index,
                    local_tip_index,
                    live_tail_events = live_tail.as_ref().map_or(0, |outcome| outcome.events),
                    live_tail_pages = live_tail.as_ref().map_or(0, |outcome| outcome.pages),
                    live_tail_start_index = live_tail.as_ref().map_or(local_tip_index.saturating_add(1), |outcome| outcome.start_index),
                    live_tail_next_event_index = live_tail.as_ref().map_or(local_tip_index.saturating_add(1), |outcome| outcome.next_event_index),
                    base_cid = %refresh.entry.base.cid,
                    delta_count = refresh.entry.deltas.len(),
                    blocked_shields_cid = %refresh.entry.blocked_shields.cid,
                    artifact_refresh_elapsed_ms,
                    live_tail_elapsed_ms,
                    installed,
                    install_lock_wait_elapsed_ms,
                    install_elapsed_ms = install_started.elapsed().as_millis(),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "chain-scoped artifact POI cache sync complete"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    chain_id,
                    list_key = %hex::encode(list_key),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "chain-scoped artifact POI cache sync failed; using last accepted local cache state if available"
                );
                match load_persisted_cache(db, &identity) {
                    Ok(Some(persisted)) => {
                        let mut cache = persisted.cache;
                        if let Some(client) = live_tail_client.as_ref() {
                            match live_tail_candidate_cache(client, &cache).await {
                                Ok((tailed_cache, _outcome)) => {
                                    cache = tailed_cache;
                                }
                                Err(err) => warn!(
                                    ?err,
                                    chain_id,
                                    list_key = %hex::encode(list_key),
                                    "live POI event tail failed after artifact refresh error"
                                ),
                            }
                        }
                        let mut caches = local_caches.write().await;
                        let installed = install_cache_if_not_behind(&mut caches, *list_key, cache);
                        if !installed {
                            debug!(
                                chain_id,
                                list_key = %hex::encode(list_key),
                                "persisted artifact POI cache install skipped; current cache is newer"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(err) => warn!(
                        ?err,
                        chain_id,
                        list_key = %hex::encode(list_key),
                        "failed to load persisted artifact POI cache after refresh error"
                    ),
                }
            }
        }
    }
}

async fn live_tail_candidate_cache(
    client: &PoiRpcClient,
    cache: &PoiCache,
) -> Result<(PoiCache, LivePoiTailOutcome), LivePoiTailError> {
    let mut tailed_cache = cache.clone();
    let outcome = sync_live_poi_event_tail(client, &mut tailed_cache).await?;
    Ok((tailed_cache, outcome))
}

fn install_cache_if_not_behind(
    caches: &mut BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
    cache: PoiCache,
) -> bool {
    if caches.get(&list_key).is_some_and(|current| {
        current.progress().next_event_index > cache.progress().next_event_index
    }) {
        return false;
    }
    caches.insert(list_key, cache);
    true
}

async fn install_persisted_chain_poi_caches(
    db: &DbStore,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let started = Instant::now();
    let mut loaded = BTreeMap::new();
    for list_key in active_list_keys {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        match load_persisted_cache(db, &identity) {
            Ok(Some(persisted)) => {
                loaded.insert(*list_key, persisted);
            }
            Ok(None) => {}
            Err(err) => warn!(
                ?err,
                chain_id,
                list_key = %hex::encode(list_key),
                "failed to load persisted artifact POI cache"
            ),
        }
    }

    let loaded_count = loaded.len();
    if loaded_count > 0 {
        let lock_started = Instant::now();
        let mut caches = local_caches.write().await;
        let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
        for (list_key, persisted) in &loaded {
            caches.insert(*list_key, persisted.cache.clone());
        }
        info!(
            chain_id,
            loaded_count,
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "installed persisted chain-scoped artifact POI cache"
        );
    }

    loaded
}

async fn chain_poi_caches_available_for_lists(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    if active_list_keys.is_empty() {
        return true;
    }
    let caches = local_caches.read().await;
    active_list_keys.iter().all(|list_key| {
        caches.get(list_key).is_some_and(|cache| {
            cache.identity().chain_type == EVM_CHAIN_TYPE
                && cache.identity().chain_id == chain_id
                && cache.identity().txid_version == DEFAULT_TXID_VERSION
                && cache.progress().next_event_index > 0
        })
    })
}

async fn sync_chain_poi_live_tails(
    client: &PoiRpcClient,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) {
    for list_key in active_list_keys {
        let Some(mut cache) = local_caches.read().await.get(list_key).cloned() else {
            continue;
        };
        let original_next_event_index = cache.progress().next_event_index;
        if original_next_event_index == 0 {
            continue;
        }
        let started = Instant::now();
        match sync_live_poi_event_tail(client, &mut cache).await {
            Ok(outcome) => {
                if outcome.events > 0 {
                    if install_tailed_poi_cache_if_current(
                        local_caches,
                        *list_key,
                        cache,
                        original_next_event_index,
                    )
                    .await
                    {
                        info!(
                            chain_id,
                            list_key = %hex::encode(list_key),
                            events = outcome.events,
                            pages = outcome.pages,
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            elapsed_ms = started.elapsed().as_millis(),
                            "chain-scoped live POI event tail applied"
                        );
                    } else {
                        debug!(
                            chain_id,
                            list_key = %hex::encode(list_key),
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            "chain-scoped live POI event tail install skipped; cache already advanced"
                        );
                    }
                } else {
                    debug!(
                        chain_id,
                        list_key = %hex::encode(list_key),
                        start_index = outcome.start_index,
                        elapsed_ms = started.elapsed().as_millis(),
                        "chain-scoped live POI event tail already current"
                    );
                }
            }
            Err(err) => warn!(
                ?err,
                chain_id,
                list_key = %hex::encode(list_key),
                elapsed_ms = started.elapsed().as_millis(),
                "chain-scoped live POI event tail failed"
            ),
        }
    }
}

async fn install_tailed_poi_cache_if_current(
    local_caches: &LocalPoiCaches,
    list_key: FixedBytes<32>,
    cache: PoiCache,
    expected_next_event_index: u64,
) -> bool {
    let mut caches = local_caches.write().await;
    let Some(current) = caches.get(&list_key) else {
        return false;
    };
    if current.progress().next_event_index != expected_next_event_index {
        return false;
    }
    caches.insert(list_key, cache);
    true
}

#[cfg(test)]
mod tests {
    use super::{
        EVM_CHAIN_TYPE, PoiCacheService, install_cache_if_not_behind, live_tail_candidate_cache,
    };
    use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig};
    use crate::wallet::LivePoiTailError;
    use alloy::hex;
    use alloy::primitives::FixedBytes;
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::{DbConfig, DbStore};
    use poi::artifacts::SnapshotEvent;
    use poi::cache::{PoiCache, PoiCacheIdentity};
    use poi::poi::{PoiEventType, PoiRpcClient, PoiSyncedListEvent, SignedPoiEvent};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use url::Url;

    struct MockPoiRpc {
        url: Url,
        requests: Receiver<serde_json::Value>,
    }

    fn temp_db_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "railgun-poi-cache-service-test-{}-{nanos}",
            std::process::id()
        ))
    }

    fn artifact_config() -> PoiArtifactSourceConfig {
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
            ),
            gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
            max_manifest_age: None,
        }
    }

    fn snapshot_event(index: u64, blinded_commitment: FixedBytes<32>) -> SnapshotEvent {
        SnapshotEvent {
            event_index: index,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }
    }

    fn cache_with_events(identity: PoiCacheIdentity, events: &[SnapshotEvent]) -> PoiCache {
        let mut cache = PoiCache::new(identity);
        cache
            .apply_verified_artifact_events(events)
            .expect("apply cache events");
        cache.accept_current_roots();
        cache
    }

    fn signed_event(
        signing_key: &SigningKey,
        index: u64,
        blinded_commitment: FixedBytes<32>,
    ) -> SignedPoiEvent {
        let mut event = SignedPoiEvent {
            index,
            blinded_commitment: hex::encode_prefixed(blinded_commitment),
            signature: String::new(),
            event_type: PoiEventType::Transact,
        };
        event.signature = hex::encode(
            signing_key
                .sign(&poi::artifacts::verify::canonical_poi_event_message(&event))
                .to_bytes(),
        );
        event
    }

    fn spawn_poi_rpc(result: serde_json::Value) -> MockPoiRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock POI RPC");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock POI RPC URL");
        let (tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut bytes = Vec::new();
            let mut buf = [0_u8; 1024];
            let (body_start, content_length) = loop {
                let read = stream.read(&mut buf).expect("read request");
                assert!(read > 0, "mock POI RPC closed before request body");
                bytes.extend_from_slice(&buf[..read]);
                if let Some(lengths) = http_body_bounds(&bytes) {
                    break lengths;
                }
            };
            let body = &bytes[body_start..body_start + content_length];
            let request: serde_json::Value = serde_json::from_slice(body).expect("request JSON");
            tx.send(request.clone()).expect("record request");
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": result,
            })
            .to_string();
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(headers.as_bytes()).expect("write headers");
            stream.write_all(response.as_bytes()).expect("write body");
        });
        MockPoiRpc { url, requests }
    }

    fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
        let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
        let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
        let content_length = headers.lines().find_map(|line| {
            line.strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
        })?;
        (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
    }

    #[tokio::test]
    async fn poi_cache_service_reuses_chain_cache_handle() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(db, artifact_config(), None);

        let first = service.start_chain(1).await;
        let second = service.start_chain(1).await;
        let other_chain = service.start_chain(137).await;

        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other_chain));
        service.shutdown();
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn artifact_candidate_install_does_not_roll_back_advanced_cache() {
        let list_key = FixedBytes::from([0x11; 32]);
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let live_tail_commitment = FixedBytes::from([0x33; 32]);
        let current_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, artifact_commitment),
                snapshot_event(1, live_tail_commitment),
            ],
        );
        let artifact_candidate =
            cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let mut caches = BTreeMap::from([(list_key, current_cache)]);

        let installed = install_cache_if_not_behind(&mut caches, list_key, artifact_candidate);

        let current = caches.get(&list_key).expect("current cache");
        assert!(!installed);
        assert_eq!(current.progress().next_event_index, 2);
        assert!(current.position(&live_tail_commitment).is_some());
    }

    #[tokio::test]
    async fn failed_live_tail_candidate_does_not_mutate_artifact_cache() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let tailed_commitment = FixedBytes::from([0x33; 32]);
        let cache = cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let original_next_event_index = cache.progress().next_event_index;
        let event = signed_event(&signing_key, 1, tailed_commitment);
        let events = vec![PoiSyncedListEvent {
            signed_poi_event: event,
            validated_merkleroot: hex::encode_prefixed(FixedBytes::from([0xff; 32])),
        }];
        let mock = spawn_poi_rpc(serde_json::to_value(events).expect("events JSON"));
        let client = PoiRpcClient::new(mock.url.clone());

        let err = live_tail_candidate_cache(&client, &cache)
            .await
            .expect_err("root mismatch should reject candidate cache");

        assert!(matches!(err, LivePoiTailError::RootMismatch { .. }));
        assert_eq!(cache.progress().next_event_index, original_next_event_index);
        assert!(cache.position(&tailed_commitment).is_none());
        let request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("remote event request");
        assert_eq!(request["method"], "ppoi_poi_events");
    }
}
