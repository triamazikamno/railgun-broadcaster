use super::*;

fn set_poi_refreshing(sender: &watch::Sender<bool>, value: bool, cache_key: &str) {
    if let Err(err) = sender.send(value) {
        debug!(?err, cache_key, "failed to send wallet POI refresh state");
    }
}

pub(crate) fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> WalletHandle {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let pending_overlay = Arc::new(RwLock::new(WalletPendingOverlay::default()));
    let last_scanned_state = Arc::new(AtomicU64::new(initial_last_scanned));
    let WalletWorkerServices {
        db,
        rpcs,
        http_client,
        forest,
    } = services;
    let cache_store = wallet_cache_store(&db, &cfg);
    let (ready_tx, ready_rx) = watch::channel(false);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        utxos: utxos.clone(),
        pending_overlay,
        last_scanned: last_scanned_state,
        ready_rx,
        rev_rx,
        poi_refreshing_rx,
        poi_read_source: cfg.poi_read_source.clone(),
        local_poi_caches: cfg.local_poi_caches.clone(),
        poi_refresh_tx,
        rev_tx,
    };

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    tokio::spawn(async move {
        let worker_started = Instant::now();
        let mut last_scanned = initial_last_scanned;
        let snapshot = utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %cfg.cache_key,
            total = snapshot.len(),
            unspent,
            spent,
            last_scanned,
            "loaded wallet cache"
        );
        drop(snapshot);

        let mut backfill_complete_block: Option<u64> = None;
        let mut persist_state = WalletPersistState::default();
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(last_scanned, worker_started);
        let poi_status_client = wallet_poi_status_client(http_client.as_ref());
        let active_poi_list_keys = default_active_poi_list_keys();
        let mut last_live_tail_poll = Instant::now();
        let preloaded_poi_caches = if cfg.manage_local_poi_cache {
            install_persisted_local_poi_caches(db.as_ref(), &cfg, &active_poi_list_keys).await
        } else {
            BTreeMap::new()
        };
        let mut startup_artifact_warmup = if cfg.manage_local_poi_cache {
            spawn_startup_artifact_poi_cache_warmup(
                Arc::clone(&db),
                http_client.clone(),
                cfg.clone(),
                active_poi_list_keys.clone(),
                preloaded_poi_caches,
            )
        } else {
            debug!(
                cache_key = %cfg.cache_key,
                chain_id = cfg.chain.chain_id,
                "wallet using externally managed artifact POI cache"
            );
            None
        };

        if poi_status_client.is_some() {
            let locked = utxos.read().await;
            debug!(
                cache_key = %cfg.cache_key,
                poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys),
                "startup wallet POI status refresh will run after backfill if needed"
            );
        }

        let mut readiness_started = worker_started;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if backfill_complete_block.is_none() {
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh skipped until backfill complete"
                        );
                        continue;
                    }
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "manual_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "manual_poi_refresh");
                        set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                        continue;
                    }
                    let changed = refresh_wallet_poi_statuses_and_persist_with_config(
                        client,
                        db.as_ref(),
                        http_client.as_ref(),
                        WalletPoiStatusRefreshPersist {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            active_list_keys: &active_poi_list_keys,
                            utxos: &utxos,
                            last_scanned,
                            persist_state: &mut persist_state,
                        },
                        WalletPoiRefreshSelection::Recoverable,
                    ).await;
                    let pending_verification = verify_submitted_pending_output_pois_with_config(
                        client,
                        &cfg,
                        db.as_ref(),
                        &active_poi_list_keys,
                    ).await;
                    let forced_pending_attempts = if refresh_request.force_output_poi_recovery {
                        let snapshot = utxos.read().await.clone();
                        force_resubmit_matching_pending_output_pois(
                            db.as_ref(),
                            &cfg,
                            &snapshot,
                            &active_poi_list_keys,
                            client as &dyn PendingOutputPoiSubmitter,
                        ).await
                    } else {
                        0
                    };
                    let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        db: db.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: refresh_request.force_output_poi_recovery,
                    }).await;
                    let force_submission_retry = refresh_request.force_output_poi_recovery
                        && recovered == 0
                        && forced_pending_attempts == 0;
                    process_pending_output_poi_observations_inner(
                        db.as_ref(),
                        cfg.chain.chain_id,
                        &[],
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        force_submission_retry,
                    ).await;
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                    debug!(
                        cache_key = %cfg.cache_key,
                        pending_completed = pending_verification.completed,
                        pending_still_missing = pending_verification.pending,
                        pending_errors = pending_verification.errors,
                        "manual wallet POI refresh pending context verification complete"
                    );
                    worker_handle.notify_if_changed(changed);
                }
                _ = tokio::time::sleep(WALLET_POI_REFRESH_INTERVAL), if poi_status_client.is_some() && backfill_complete_block.is_some() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if cfg.manage_local_poi_cache
                        && last_live_tail_poll.elapsed() >= WALLET_POI_LIVE_TAIL_INTERVAL
                    {
                        sync_local_poi_live_tails(client, &cfg, &active_poi_list_keys).await;
                        last_live_tail_poll = Instant::now();
                    }
                    let now = now_epoch_secs();
                    let selection = WalletPoiRefreshSelection::RecoverableStale { now };
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            selection,
                        )
                    };
                    if !refresh_needed {
                        let snapshot = utxos.read().await.clone();
                        mark_valid_output_poi_recoveries(db.as_ref(), &cfg, &snapshot, &active_poi_list_keys);
                        verify_submitted_pending_output_pois_with_config(
                            client,
                            &cfg,
                            db.as_ref(),
                            &active_poi_list_keys,
                        ).await;
                        process_pending_output_poi_observations_inner(
                            db.as_ref(),
                            cfg.chain.chain_id,
                            &[],
                            Some(client as &dyn PendingOutputPoiSubmitter),
                            false,
                        ).await;
                        continue;
                    }
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "periodic_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "periodic_poi_refresh");
                        set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                        continue;
                    }
                    let changed = refresh_wallet_poi_statuses_and_persist_with_config(
                        client,
                        db.as_ref(),
                        http_client.as_ref(),
                        WalletPoiStatusRefreshPersist {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            active_list_keys: &active_poi_list_keys,
                            utxos: &utxos,
                            last_scanned,
                            persist_state: &mut persist_state,
                        },
                        selection,
                    ).await;
                    let pending_verification = verify_submitted_pending_output_pois_with_config(
                        client,
                        &cfg,
                        db.as_ref(),
                        &active_poi_list_keys,
                    ).await;
                    recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        db: db.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: false,
                    }).await;
                    process_pending_output_poi_observations_inner(
                        db.as_ref(),
                        cfg.chain.chain_id,
                        &[],
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        false,
                    ).await;
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                    debug!(
                        cache_key = %cfg.cache_key,
                        pending_completed = pending_verification.completed,
                        pending_still_missing = pending_verification.pending,
                        pending_errors = pending_verification.errors,
                        "periodic wallet POI refresh pending context verification complete"
                    );
                    worker_handle.notify_if_changed(changed);
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::IndexedDelta { from_block, to_block, delta } => {
                            if to_block <= last_scanned {
                                continue;
                            }
                            let delta = *delta;
                            let delta_utxos = delta.utxos.len();
                            let delta_nullifiers = delta.nullifiers.len();
                            let commitment_observations = delta.commitment_observations.len();
                            debug!(
                                cache_key = %cfg.cache_key,
                                from_block,
                                to_block,
                                last_scanned,
                                delta_utxos,
                                delta_nullifiers,
                                commitment_observations,
                                "applying indexed wallet delta"
                            );
                            let poi_observation_started = Instant::now();
                            process_pending_output_poi_observations(
                                db.as_ref(),
                                cfg.chain.chain_id,
                                &delta.commitment_observations,
                                None,
                            )
                            .await;
                            let apply_started = Instant::now();
                            let outcome = apply_wallet_delta_with_outcome(&cfg, &utxos, delta).await;
                            discard_pending_output_poi_contexts_for_spent_outputs(
                                db.as_ref(),
                                cfg.chain.chain_id,
                                &outcome.spent_output_commitments,
                            );
                            let changed = outcome.changed;
                            last_scanned = to_block;
                            worker_handle.set_last_scanned(last_scanned);
                            let snapshot = utxos.read().await;
                            let (unspent, spent) = wallet_utxo_counts(&snapshot);
                            let persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                snapshot: &snapshot,
                                last_scanned,
                                last_scanned_block_hash: None,
                                changed,
                                persist_state: &mut persist_state,
                                live_metadata_flush: Some(&mut live_metadata_flush),
                                error_message: "failed to persist indexed wallet cache",
                            });
                            debug!(
                                cache_key = %cfg.cache_key,
                                last_scanned,
                                total = snapshot.len(),
                                unspent,
                                spent,
                                changed,
                                poi_status_deferred = poi_status_client.is_some(),
                                persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                needs_full_persist = persist_state.needs_full_persist,
                                poi_observation_elapsed_ms = poi_observation_started.elapsed().as_millis(),
                                elapsed_ms = apply_started.elapsed().as_millis(),
                                "indexed wallet delta complete"
                            );
                            worker_handle.notify_if_changed(changed);
                        }
                        BackfillEvent::Logs(batch) => {
                            if batch.to_block <= last_scanned {
                                continue;
                            }
                            debug!(
                                cache_key = %cfg.cache_key,
                                from_block = batch.from_block,
                                to_block = batch.to_block,
                                last_scanned,
                                logs = batch.logs.len(),
                                "applying wallet backfill logs"
                            );
                            match apply_wallet_logs(db.as_ref(), None, &cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, changed)) => {
                                    last_scanned = updated_last_scanned;
                                    worker_handle.set_last_scanned(last_scanned);
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                        cache_store: cache_store.as_ref(),
                                        cfg: &cfg,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: batch.to_block_hash,
                                        changed,
                                        persist_state: &mut persist_state,
                                        live_metadata_flush: Some(&mut live_metadata_flush),
                                        error_message: "failed to persist wallet cache",
                                    });
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        poi_status_deferred = poi_status_client.is_some(),
                                        persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet backfill batch complete"
                                    );
                                    worker_handle.notify_if_changed(changed);
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to apply backfill logs");
                                }
                            }
                        }
                        BackfillEvent::Done { last_block } => {
                            let should_persist = last_scanned < last_block
                                || persist_state.needs_full_persist
                                || persist_state.pending_cache_reset.is_some();
                            if last_scanned < last_block {
                                last_scanned = last_block;
                                worker_handle.set_last_scanned(last_scanned);
                            }
                            let snapshot = utxos.read().await;
                            if should_persist
                                && let Err(err) = persist_state.persist_progress(
                                    cache_store.as_ref(),
                                    WalletProgressPersist {
                                        cache_key: &cfg.cache_key,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: None,
                                        changed: false,
                                    },
                                )
                            {
                                warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                            }
                            if should_persist {
                                live_metadata_flush.mark_persisted(last_scanned, Instant::now());
                            }
                            drop(snapshot);
                            let mut pre_ready_poi_status_changed = false;
                            let mut pre_ready_poi_status_refresh_elapsed_ms = 0_u128;
                            let mut pre_ready_local_cache_available = false;
                            if let Some(client) = poi_status_client.as_ref() {
                                let refresh_needed = {
                                    let locked = utxos.read().await;
                                    wallet_poi_status_refresh_needed_for_selection(
                                        &locked,
                                        &active_poi_list_keys,
                                        WalletPoiRefreshSelection::RequiredOrRecoverable,
                                    )
                                };
                                if refresh_needed {
                                    pre_ready_local_cache_available = local_poi_caches_available_for_lists(
                                        &cfg,
                                        &active_poi_list_keys,
                                    ).await;
                                    if pre_ready_local_cache_available {
                                        let status_refresh_started = Instant::now();
                                        pre_ready_poi_status_changed = refresh_wallet_poi_statuses_and_persist_with_config(
                                            client,
                                            db.as_ref(),
                                            http_client.as_ref(),
                                            WalletPoiStatusRefreshPersist {
                                                cache_store: cache_store.as_ref(),
                                                cfg: &cfg,
                                                active_list_keys: &active_poi_list_keys,
                                                utxos: &utxos,
                                                last_scanned,
                                                persist_state: &mut persist_state,
                                            },
                                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                                        )
                                        .await;
                                        pre_ready_poi_status_refresh_elapsed_ms =
                                            status_refresh_started.elapsed().as_millis();
                                        worker_handle.notify_if_changed(pre_ready_poi_status_changed);
                                        debug!(
                                            cache_key = %cfg.cache_key,
                                            changed = pre_ready_poi_status_changed,
                                            status_refresh_elapsed_ms = pre_ready_poi_status_refresh_elapsed_ms,
                                            "pre-ready wallet POI status refresh visible"
                                        );
                                        tokio::task::yield_now().await;
                                    }
                                }
                            }
                            let snapshot = utxos.read().await;
                            let (unspent, spent) = wallet_utxo_counts(&snapshot);
                            backfill_complete_block = Some(last_block);
                            if let Err(err) = ready_tx.send(true) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send ready state");
                            }
                            worker_handle.notify_if_changed(pre_ready_poi_status_changed);
                            info!(
                                cache_key = %cfg.cache_key,
                                last_scanned,
                                total = snapshot.len(),
                                unspent,
                                spent,
                                pre_ready_poi_status_changed,
                                pre_ready_local_cache_available,
                                pre_ready_poi_status_refresh_elapsed_ms,
                                ready_elapsed_ms = readiness_started.elapsed().as_millis(),
                                worker_elapsed_ms = worker_started.elapsed().as_millis(),
                                "wallet backfill complete"
                            );
                            drop(snapshot);
                            tokio::task::yield_now().await;

                            if let Some(client) = poi_status_client.as_ref() {
                                let post_ready_poi_started = Instant::now();
                                let pending_observations_started = Instant::now();
                                process_pending_output_poi_observations(
                                    db.as_ref(),
                                    cfg.chain.chain_id,
                                    &[],
                                    Some(client as &dyn PendingOutputPoiSubmitter),
                                ).await;
                                let pending_observations_elapsed_ms =
                                    pending_observations_started.elapsed().as_millis();

                                let refresh_needed = {
                                    let locked = utxos.read().await;
                                    wallet_poi_status_refresh_needed_for_selection(
                                        &locked,
                                        &active_poi_list_keys,
                                        WalletPoiRefreshSelection::RequiredOrRecoverable,
                                    )
                                };
                                if refresh_needed {
                                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                                    let warmup_wait_started = Instant::now();
                                    let local_cache_available = local_poi_caches_ready_for_refresh(
                                        &mut startup_artifact_warmup,
                                        &cfg,
                                        &active_poi_list_keys,
                                        "post_ready_poi_refresh",
                                    ).await;
                                    let warmup_wait_elapsed_ms =
                                        warmup_wait_started.elapsed().as_millis();
                                    if !local_cache_available {
                                        log_local_poi_cache_unavailable(&cfg, "post_ready_poi_refresh");
                                        set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                                        continue;
                                    }
                                    let status_refresh_started = Instant::now();
                                    let changed = refresh_wallet_poi_statuses_and_persist_with_config(
                                        client,
                                        db.as_ref(),
                                        http_client.as_ref(),
                                        WalletPoiStatusRefreshPersist {
                                            cache_store: cache_store.as_ref(),
                                            cfg: &cfg,
                                            active_list_keys: &active_poi_list_keys,
                                            utxos: &utxos,
                                            last_scanned,
                                            persist_state: &mut persist_state,
                                        },
                                        WalletPoiRefreshSelection::RequiredOrRecoverable,
                                    )
                                    .await;
                                    let status_refresh_elapsed_ms =
                                        status_refresh_started.elapsed().as_millis();
                                    worker_handle.notify_if_changed(changed);
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        changed,
                                        status_refresh_elapsed_ms,
                                        elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                        "post-ready wallet POI status refresh visible"
                                    );
                                    tokio::task::yield_now().await;
                                    let pending_verification = verify_submitted_pending_output_pois_with_config(
                                        client,
                                        &cfg,
                                        db.as_ref(),
                                        &active_poi_list_keys,
                                    )
                                    .await;
                                    let output_recovery_started = Instant::now();
                                    let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                        db: db.as_ref(),
                                        cfg: &cfg,
                                        rpcs: rpcs.as_ref(),
                                        http_client: http_client.as_ref(),
                                        forest: &forest,
                                        utxos: &utxos,
                                        client,
                                        active_list_keys: &active_poi_list_keys,
                                        force_retry: false,
                                    }).await;
                                    let output_recovery_elapsed_ms =
                                        output_recovery_started.elapsed().as_millis();
                                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                                    worker_handle.notify_if_changed(recovered > 0);
                                    info!(
                                        cache_key = %cfg.cache_key,
                                        changed,
                                        recovered,
                                        pending_observations_elapsed_ms,
                                        local_cache_available,
                                        warmup_wait_elapsed_ms,
                                        status_refresh_elapsed_ms,
                                        output_recovery_elapsed_ms,
                                        pending_completed = pending_verification.completed,
                                        pending_still_missing = pending_verification.pending,
                                        pending_errors = pending_verification.errors,
                                        elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                        "post-ready wallet POI maintenance complete"
                                    );
                                } else {
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        pending_observations_elapsed_ms,
                                        elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                        "post-ready wallet POI status refresh not needed"
                                    );
                                }
                            }
                        }
                        BackfillEvent::Reset { from_block } => {
                            readiness_started = Instant::now();
                            last_scanned = from_block.saturating_sub(1);
                            worker_handle.set_last_scanned(last_scanned);
                            let (changed, snapshot) = {
                                let mut locked = utxos.write().await;
                                let changed = rewind_wallet_utxos(&mut locked, from_block);
                                (changed, locked.clone())
                            };
                            let (unspent, spent) = wallet_utxo_counts(&snapshot);
                            match cache_store.replace_wallet_cache(
                                &cfg.cache_key,
                                &snapshot,
                                last_scanned,
                                None,
                            ) {
                                Ok(()) => {
                                    persist_state.needs_full_persist = false;
                                    persist_state.pending_cache_reset = None;
                                    live_metadata_flush.mark_persisted(last_scanned, Instant::now());
                                }
                                Err(err) => {
                                    persist_state.needs_full_persist = true;
                                    persist_state.pending_cache_reset = Some(last_scanned);
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to rewind wallet cache");
                                }
                            }
                            worker_handle.notify_if_changed(changed);
                            backfill_complete_block = None;
                            if let Err(err) = ready_tx.send(false) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send ready state");
                            }
                            info!(
                                cache_key = %cfg.cache_key,
                                from_block,
                                last_scanned,
                                total = snapshot.len(),
                                unspent,
                                spent,
                                changed,
                                "wallet cache rewound"
                            );
                        }
                    }
                }
                result = live_rx.recv() => {
                    match result {
                        Ok(batch) => {
                            if cfg.sync_to_block.is_some() {
                                continue;
                            }
                            if backfill_complete_block.is_none()
                                || batch.to_block <= last_scanned
                            {
                                continue;
                            }
                            if batch.logs.is_empty() {
                                last_scanned = batch.to_block;
                                worker_handle.set_last_scanned(last_scanned);
                                let should_persist = persist_state.needs_full_persist
                                    || persist_state.pending_cache_reset.is_some()
                                    || live_metadata_flush
                                        .should_flush(last_scanned, Instant::now());
                                let mut persist_outcome = WalletProgressPersistOutcome::default();
                                if should_persist {
                                    let snapshot = utxos.read().await;
                                    persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                        cache_store: cache_store.as_ref(),
                                        cfg: &cfg,
                                        snapshot: &snapshot,
                                        last_scanned,
                                        last_scanned_block_hash: batch.to_block_hash,
                                        changed: false,
                                        persist_state: &mut persist_state,
                                        live_metadata_flush: Some(&mut live_metadata_flush),
                                        error_message: "failed to persist empty wallet live batch progress",
                                    });
                                }
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    last_scanned,
                                    metadata_persisted = persist_outcome.persisted_progress,
                                    persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                    needs_full_persist = persist_state.needs_full_persist,
                                    "wallet empty live batch complete"
                                );
                                continue;
                            }
                            let poi_submitter = poi_status_client
                                .as_ref()
                                .map(|client| client as &dyn PendingOutputPoiSubmitter);
                            match apply_wallet_logs(db.as_ref(), poi_submitter, &cfg, &utxos, &batch, last_scanned).await {
                                Ok((updated_last_scanned, mut changed)) => {
                                    last_scanned = updated_last_scanned;
                                    worker_handle.set_last_scanned(last_scanned);
                                    if changed
                                        && let Some(client) = poi_status_client.as_ref()
                                    {
                                        let mut locked = utxos.write().await;
                                        changed |= refresh_wallet_poi_statuses_selected_with_config(
                                            client,
                                            db.as_ref(),
                                            http_client.as_ref(),
                                            &cfg,
                                            &active_poi_list_keys,
                                            &mut locked,
                                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                                        ).await;
                                        verify_submitted_pending_output_pois_with_config(
                                            client,
                                            &cfg,
                                            db.as_ref(),
                                            &active_poi_list_keys,
                                        ).await;
                                    }
                                    if changed
                                        && let Some(client) = poi_status_client.as_ref()
                                    {
                                        recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                            db: db.as_ref(),
                                            cfg: &cfg,
                                            rpcs: rpcs.as_ref(),
                                            http_client: http_client.as_ref(),
                                            forest: &forest,
                                            utxos: &utxos,
                                            client,
                                            active_list_keys: &active_poi_list_keys,
                                            force_retry: false,
                                        }).await;
                                    }
                                    let snapshot = utxos.read().await;
                                    let (unspent, spent) = wallet_utxo_counts(&snapshot);
                                    let should_persist = changed
                                        || persist_state.needs_full_persist
                                        || persist_state.pending_cache_reset.is_some()
                                        || live_metadata_flush
                                            .should_flush(last_scanned, Instant::now());
                                    let mut persist_outcome = WalletProgressPersistOutcome::default();
                                    if should_persist {
                                        persist_outcome = persist_wallet_snapshot(WalletSnapshotPersist {
                                            cache_store: cache_store.as_ref(),
                                            cfg: &cfg,
                                            snapshot: &snapshot,
                                            last_scanned,
                                            last_scanned_block_hash: batch.to_block_hash,
                                            changed,
                                            persist_state: &mut persist_state,
                                            live_metadata_flush: Some(&mut live_metadata_flush),
                                            error_message: "failed to persist wallet cache",
                                        });
                                    }
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        last_scanned,
                                        total = snapshot.len(),
                                        unspent,
                                        spent,
                                        changed,
                                        metadata_persisted = persist_outcome.persisted_progress,
                                        persisted_full_snapshot = persist_outcome.persisted_full_snapshot,
                                        needs_full_persist = persist_state.needs_full_persist,
                                        "wallet live batch complete"
                                    );
                                    worker_handle.notify_if_changed(changed);
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to apply live logs");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!(cache_key = %cfg.cache_key, "wallet live log receiver lagged");
                        }
                    }
                }
            }
        }
    }.instrument(tracing::info_span!("wallet", chain_id)));

    handle
}

pub(crate) fn wallet_cache_store(
    db: &Arc<DbStore>,
    cfg: &WalletConfig,
) -> Arc<dyn WalletCacheStore> {
    cfg.cache_store
        .clone()
        .unwrap_or_else(|| Arc::clone(db) as Arc<dyn WalletCacheStore>)
}

pub(super) fn dedupe_wallet_utxos(utxos: &mut Vec<WalletUtxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|wallet_utxo| seen.insert((wallet_utxo.utxo.tree, wallet_utxo.utxo.position)));
}

fn wallet_utxo_counts(utxos: &[WalletUtxo]) -> (usize, usize) {
    let spent = utxos.iter().filter(|utxo| utxo.is_spent()).count();
    (utxos.len().saturating_sub(spent), spent)
}
