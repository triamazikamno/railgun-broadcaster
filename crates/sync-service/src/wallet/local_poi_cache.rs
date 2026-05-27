use super::*;

pub(super) async fn sync_local_poi_caches(
    db: &DbStore,
    http_client: Option<&reqwest::Client>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    mut preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
) {
    let Some(local_caches) = cfg.local_poi_caches.as_ref() else {
        return;
    };
    let PoiReadSource::IndexedArtifacts(artifact_config) = &cfg.poi_read_source else {
        return;
    };
    let ingestor = PoiArtifactIngestor::new(
        artifact_config.clone(),
        http_client.cloned().unwrap_or_else(reqwest::Client::new),
    );
    let live_tail_client = http_client.and_then(|client| wallet_poi_status_client(Some(client)));
    for list_key in active_list_keys {
        let identity = PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            DEFAULT_TXID_VERSION,
            *list_key,
        );
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
                    match sync_live_poi_event_tail(client, &mut cache).await {
                        Ok(outcome) => Some(outcome),
                        Err(err) => {
                            warn!(
                                ?err,
                                cache_key = %cfg.cache_key,
                                chain_id = cfg.chain.chain_id,
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
                caches.insert(*list_key, cache);
                drop(caches);
                info!(
                    cache_key = %cfg.cache_key,
                    chain_id = cfg.chain.chain_id,
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
                    install_lock_wait_elapsed_ms,
                    install_elapsed_ms = install_started.elapsed().as_millis(),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "artifact POI cache sync complete"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    chain_id = cfg.chain.chain_id,
                    list_key = %hex::encode(list_key),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "artifact POI cache sync failed; using last accepted local cache state if available"
                );
                match load_persisted_cache(db, &identity) {
                    Ok(Some(persisted)) => {
                        let mut cache = persisted.cache;
                        if let Some(client) = live_tail_client.as_ref()
                            && let Err(err) = sync_live_poi_event_tail(client, &mut cache).await
                        {
                            warn!(
                                ?err,
                                cache_key = %cfg.cache_key,
                                chain_id = cfg.chain.chain_id,
                                list_key = %hex::encode(list_key),
                                "live POI event tail failed after artifact refresh error"
                            );
                        }
                        local_caches.write().await.insert(*list_key, cache);
                    }
                    Ok(None) => {}
                    Err(err) => warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        chain_id = cfg.chain.chain_id,
                        list_key = %hex::encode(list_key),
                        "failed to load persisted artifact POI cache after refresh error"
                    ),
                }
            }
        }
    }
}

pub(super) async fn install_persisted_local_poi_caches(
    db: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return BTreeMap::new();
    }
    let Some(local_caches) = cfg.local_poi_caches.as_ref() else {
        return BTreeMap::new();
    };

    let started = Instant::now();
    let mut loaded = BTreeMap::new();
    for list_key in active_list_keys {
        let identity = PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            DEFAULT_TXID_VERSION,
            *list_key,
        );
        match load_persisted_cache(db, &identity) {
            Ok(Some(persisted)) => {
                loaded.insert(*list_key, persisted);
            }
            Ok(None) => {}
            Err(err) => warn!(
                ?err,
                cache_key = %cfg.cache_key,
                chain_id = cfg.chain.chain_id,
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
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            loaded_count,
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "installed persisted artifact POI cache"
        );
    }

    loaded
}

pub(super) async fn local_poi_caches_available_for_lists(
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return true;
    }
    if active_list_keys.is_empty() {
        return true;
    }
    let Some(local_caches) = cfg.local_poi_caches.as_ref() else {
        return false;
    };
    let caches = local_caches.read().await;
    active_list_keys.iter().all(|list_key| {
        caches.get(list_key).is_some_and(|cache| {
            cache.identity().chain_type == EVM_CHAIN_TYPE
                && cache.identity().chain_id == cfg.chain.chain_id
                && cache.identity().txid_version == DEFAULT_TXID_VERSION
                && cache.progress().next_event_index > 0
        })
    })
}

pub(super) async fn sync_local_poi_live_tails(
    client: &PoiRpcClient,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
) {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return;
    }
    let Some(local_caches) = cfg.local_poi_caches.as_ref() else {
        return;
    };
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
                            cache_key = %cfg.cache_key,
                            chain_id = cfg.chain.chain_id,
                            list_key = %hex::encode(list_key),
                            events = outcome.events,
                            pages = outcome.pages,
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            elapsed_ms = started.elapsed().as_millis(),
                            "live POI event tail applied"
                        );
                    } else {
                        debug!(
                            cache_key = %cfg.cache_key,
                            chain_id = cfg.chain.chain_id,
                            list_key = %hex::encode(list_key),
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            "live POI event tail install skipped; cache already advanced"
                        );
                    }
                } else {
                    debug!(
                        cache_key = %cfg.cache_key,
                        chain_id = cfg.chain.chain_id,
                        list_key = %hex::encode(list_key),
                        start_index = outcome.start_index,
                        elapsed_ms = started.elapsed().as_millis(),
                        "live POI event tail already current"
                    );
                }
            }
            Err(err) => warn!(
                ?err,
                cache_key = %cfg.cache_key,
                chain_id = cfg.chain.chain_id,
                list_key = %hex::encode(list_key),
                elapsed_ms = started.elapsed().as_millis(),
                "live POI event tail failed"
            ),
        }
    }
}

pub(super) async fn install_tailed_poi_cache_if_current(
    local_caches: &WalletLocalPoiCaches,
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

pub(super) fn spawn_startup_artifact_poi_cache_warmup(
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    cfg: WalletConfig,
    active_list_keys: Vec<FixedBytes<32>>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return None;
    }
    info!(
        cache_key = %cfg.cache_key,
        chain_id = cfg.chain.chain_id,
        list_count = active_list_keys.len(),
        "warming artifact POI cache"
    );
    Some(tokio::spawn(async move {
        sync_local_poi_caches(
            db.as_ref(),
            http_client.as_ref(),
            &cfg,
            &active_list_keys,
            preloaded_caches,
        )
        .await;
    }))
}

pub(super) async fn await_startup_artifact_poi_cache_warmup(
    startup_warmup: &mut Option<tokio::task::JoinHandle<()>>,
    cfg: &WalletConfig,
    reason: &'static str,
) {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return;
    }
    let Some(handle) = startup_warmup.take() else {
        return;
    };
    info!(
        cache_key = %cfg.cache_key,
        chain_id = cfg.chain.chain_id,
        reason,
        "waiting for startup artifact POI cache warmup"
    );
    match handle.await {
        Ok(()) => debug!(
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            reason,
            "startup artifact POI cache warmup complete"
        ),
        Err(err) => warn!(
            ?err,
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            reason,
            "startup artifact POI cache warmup task failed"
        ),
    }
}

pub(super) async fn local_poi_caches_ready_for_refresh(
    startup_warmup: &mut Option<tokio::task::JoinHandle<()>>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    reason: &'static str,
) -> bool {
    if !matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return true;
    }
    if local_poi_caches_available_for_lists(cfg, active_list_keys).await {
        return true;
    }
    await_startup_artifact_poi_cache_warmup(startup_warmup, cfg, reason).await;
    local_poi_caches_available_for_lists(cfg, active_list_keys).await
}

pub(super) fn log_local_poi_cache_unavailable(cfg: &WalletConfig, reason: &'static str) {
    warn!(
        cache_key = %cfg.cache_key,
        chain_id = cfg.chain.chain_id,
        reason,
        "artifact POI local cache unavailable; skipping local POI refresh"
    );
}

pub(super) async fn refresh_wallet_poi_statuses_selected_with_config(
    remote_client: &PoiRpcClient,
    _db: &DbStore,
    _http_client: Option<&reqwest::Client>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    wallet_utxos: &mut [WalletUtxo],
    selection: WalletPoiRefreshSelection,
) -> bool {
    match &cfg.poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => {
            let local_caches = cfg.local_poi_caches.as_ref().cloned().unwrap_or_else(|| {
                warn!(
                    cache_key = %cfg.cache_key,
                    chain_id = cfg.chain.chain_id,
                    "artifact POI read source missing local cache handle"
                );
                Arc::new(RwLock::new(BTreeMap::new()))
            });
            let reader = LocalPoiStatusReader::new(local_caches);
            refresh_wallet_poi_statuses_selected(
                &reader,
                cfg.chain.chain_id,
                active_list_keys,
                wallet_utxos,
                selection,
            )
            .await
        }
        PoiReadSource::PoiProxy => {
            refresh_wallet_poi_statuses_selected(
                remote_client,
                cfg.chain.chain_id,
                active_list_keys,
                wallet_utxos,
                selection,
            )
            .await
        }
    }
}
