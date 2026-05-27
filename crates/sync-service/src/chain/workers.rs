use super::*;

pub(super) fn spawn_head_poller(service: Arc<ChainService>, rpcs: Arc<QueryRpcPool>) {
    let cancel = service.cancel.clone();
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                // Poll first, then sleep.  This ensures the very first poll
                // happens immediately instead of after a full poll_interval
                // delay, which is critical for fast safe_head availability.
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => { continue; }
                    }
                };
                match rpc.provider.get_block_number().await {
                    Ok(head) => {
                        let safe_head = head
                            .saturating_sub(service.chain.finality_depth)
                            .max(service.chain.deployment_block);
                        if service.head_tx.receiver_count() > 0 {
                            let _ = service.head_tx.send(head);
                        }
                        if let Err(err) = service.safe_head_tx.send(safe_head) {
                            debug!(?err, safe_head, "failed to send safe head update");
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to fetch latest block");
                        rpcs.mark_bad_provider(&rpc);
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(service.chain.poll_interval) => {}
                }
            }
        }
        .instrument(tracing::info_span!("sync_head", chain_id)),
    );
}

pub(super) fn spawn_pending_tip_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut head_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                let safe_head = *safe_head_rx.borrow();
                let head = *head_rx.borrow();
                refresh_pending_tip_overlays(
                    &service,
                    &rpcs,
                    archive_provider.as_ref(),
                    safe_head,
                    head,
                )
                .await;

                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = head_rx.changed() => {},
                    _ = safe_head_rx.changed() => {},
                    _ = tokio::time::sleep(service.chain.poll_interval) => {},
                }
            }
        }
        .instrument(tracing::info_span!("pending_tip", chain_id)),
    );
}

pub(super) async fn refresh_pending_tip_overlays(
    service: &Arc<ChainService>,
    rpcs: &Arc<QueryRpcPool>,
    archive_provider: Option<&DynProvider>,
    safe_head: u64,
    head: u64,
) {
    let registrations = {
        let wallets = service.wallets.read().await;
        wallets
            .iter()
            .map(|(cache_key, registration)| {
                let handle = registration.handle.clone();
                let from_block = pending_tip_from_block(
                    safe_head,
                    handle.last_scanned(),
                    service.chain.block_range,
                );
                let target_block = registration
                    .sync_to_block
                    .map_or(head, |limit| limit.min(head));
                PendingTipWalletRegistration {
                    cache_key: cache_key.clone(),
                    cfg: registration.cfg.clone(),
                    handle,
                    from_block,
                    target_block,
                }
            })
            .collect::<Vec<_>>()
    };
    if registrations.is_empty() {
        return;
    }

    let Some(fetch_to_block) = registrations
        .iter()
        .filter(|registration| registration.target_block >= registration.from_block)
        .map(|registration| registration.target_block)
        .max()
    else {
        clear_pending_tip_overlays(registrations).await;
        return;
    };

    let Some(rpc) = rpcs.random_provider() else {
        warn!(
            safe_head,
            head, "no healthy rpc providers available for pending wallet tip"
        );
        return;
    };

    let provider_head = match rpc.provider.get_block_number().await {
        Ok(provider_head) => provider_head,
        Err(err) => {
            warn!(
                ?err,
                rpc = rpc.url.as_str(),
                "failed to fetch pending wallet tip provider head"
            );
            rpcs.mark_bad_provider(&rpc);
            return;
        }
    };
    if !pending_tip_provider_covers_target(provider_head, fetch_to_block) {
        debug!(
            rpc = rpc.url.as_str(),
            provider_head,
            fetch_to_block,
            "pending wallet tip provider is behind; preserving existing overlay"
        );
        return;
    }

    let from_block = registrations
        .iter()
        .filter(|registration| registration.target_block >= registration.from_block)
        .map(|registration| registration.from_block)
        .min()
        .unwrap_or(fetch_to_block);
    let mut logs = match service
        .chain
        .fetch_logs_for_range(&rpc.provider, archive_provider, from_block, fetch_to_block)
        .await
    {
        Ok(logs) => logs,
        Err(err) => {
            warn!(
                ?err,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip logs"
            );
            if err.should_mark_rpc_unhealthy() && !err.is_block_range_beyond_current_head() {
                rpcs.mark_bad_provider(&rpc);
            }
            return;
        }
    };
    sort_logs(&mut logs);

    let block_timestamps = match service
        .chain
        .fetch_log_block_timestamps(&rpc.provider, archive_provider, &logs)
        .await
    {
        Ok(block_timestamps) => block_timestamps,
        Err(err) => {
            warn!(
                ?err,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip timestamps"
            );
            if err.should_mark_rpc_unhealthy() {
                rpcs.mark_bad_provider(&rpc);
            }
            return;
        }
    };

    for registration in registrations {
        if registration.target_block < registration.from_block {
            registration
                .handle
                .set_chain_pending_overlay(WalletPendingOverlay::default())
                .await;
            continue;
        }

        let wallet_logs = logs
            .iter()
            .filter(|log| {
                log.block_number.is_some_and(|block| {
                    block >= registration.from_block && block <= registration.target_block
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let delta = if wallet_logs.is_empty() {
            WalletLogDelta {
                utxos: Vec::new(),
                nullifiers: Vec::new(),
                commitment_observations: Vec::new(),
            }
        } else {
            match parse_wallet_delta_from_logs(
                &wallet_logs,
                &block_timestamps,
                &registration.cfg.scan_keys,
            ) {
                Ok(delta) => delta,
                Err(err) => {
                    warn!(?err, cache_key = %registration.cache_key, from_block = registration.from_block, to_block = registration.target_block, "failed to parse pending wallet tip logs");
                    continue;
                }
            }
        };

        let confirmed = registration.handle.utxos.read().await;
        let overlay = pending_overlay_from_delta(&registration.cfg, &confirmed, delta);
        drop(confirmed);
        registration.handle.set_chain_pending_overlay(overlay).await;
    }
}

pub(super) async fn clear_pending_tip_overlays(registrations: Vec<PendingTipWalletRegistration>) {
    for registration in registrations {
        registration
            .handle
            .set_chain_pending_overlay(WalletPendingOverlay::default())
            .await;
    }
}

pub(super) fn pending_tip_from_block(
    safe_head: u64,
    wallet_last_scanned: u64,
    sticky_block_range: u64,
) -> u64 {
    if wallet_last_scanned < safe_head
        && safe_head.saturating_sub(wallet_last_scanned) <= sticky_block_range
    {
        wallet_last_scanned.saturating_add(1)
    } else {
        safe_head.saturating_add(1)
    }
}

pub(super) const fn pending_tip_provider_covers_target(
    provider_head: u64,
    target_block: u64,
) -> bool {
    provider_head >= target_block
}

pub(super) fn spawn_txid_public_cache_loop(service: Arc<ChainService>, cancel: CancellationToken) {
    let Some(endpoint) = service.chain.quick_sync_endpoint.clone() else {
        return;
    };
    let chain_id = service.chain.chain_id;
    let http_client = service.chain.http_client.clone();
    let db = service.db.clone();
    tokio::spawn(
        async move {
            loop {
                let key = TxidPublicCacheKey {
                    chain_type: EVM_CHAIN_TYPE,
                    chain_id,
                    txid_version: DEFAULT_TXID_VERSION,
                };
                if let Err(err) =
                    sync_txid_public_cache_to_graph_tip(&db, &endpoint, http_client.as_ref(), key)
                        .await
                {
                    warn!(?err, chain_id, "TXID public cache background sync failed");
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(TXID_PUBLIC_CACHE_SYNC_INTERVAL) => {}
                }
            }
        }
        .instrument(tracing::info_span!("txid_public_cache", chain_id)),
    );
}

pub(super) fn spawn_live_log_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut forest_last_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    cancel: CancellationToken,
) {
    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = safe_head_rx.changed() => {},
                    _ = forest_last_rx.changed() => {},
                }

                let safe_head = *safe_head_rx.borrow();
                if safe_head == 0 && service.chain.deployment_block > 0 {
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                }
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::time::sleep(service.chain.poll_interval).await;
                    continue;
                };
                if let Err(err) = service
                    .check_forest_reorg(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        rpc.url.as_str(),
                        &snapshot_path,
                        safe_head,
                        last_processed,
                    )
                    .await
                {
                    debug!(?err, rpc = rpc.url.as_str(), "reorg check failed");
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    continue;
                }

                let from_block = last_processed.saturating_add(1);
                let to_block = min(from_block + service.chain.block_range - 1, safe_head);
                match service
                    .chain
                    .fetch_logs_for_range(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        from_block,
                        to_block,
                    )
                    .await
                {
                    Ok(mut logs) => {
                        sort_logs(&mut logs);
                        let block_timestamps = if service.live_log_tx.receiver_count() > 0 {
                            match service
                                .chain
                                .fetch_log_block_timestamps(
                                    &rpc.provider,
                                    archive_provider.as_ref(),
                                    &logs,
                                )
                                .await
                            {
                                Ok(block_timestamps) => block_timestamps,
                                Err(err) => {
                                    warn!(?err, "failed to fetch log block timestamps");
                                    if err.should_mark_rpc_unhealthy() {
                                        rpcs.mark_bad_provider(&rpc);
                                    }
                                    continue;
                                }
                            }
                        } else {
                            HashMap::new()
                        };
                        let to_block_hash = service
                            .chain
                            .fetch_confirmed_block_hash(
                                &rpc.provider,
                                archive_provider.as_ref(),
                                to_block,
                            )
                            .await
                            .unwrap_or_else(|err| {
                                warn!(?err, to_block, "failed to fetch confirmed block hash");
                                None
                            });
                        let batch = Arc::new(LogBatch {
                            from_block,
                            to_block,
                            logs,
                            block_timestamps,
                            to_block_hash,
                        });

                        let batch_hash = batch.to_block_hash;
                        if let Err(err) = service.apply_forest_updates(&batch).await {
                            warn!(?err, "failed to apply forest updates");
                        } else {
                            let log_count = batch.logs.len();
                            if service.live_log_tx.send(batch).is_err() {
                                debug!(
                                    from_block,
                                    to_block, log_count, "failed to broadcast live log batch"
                                );
                            }
                            if let Err(err) = service.forest_last_tx.send(to_block) {
                                debug!(?err, to_block, "failed to send forest progress update");
                            }
                            if let Err(err) = service
                                .persist_forest_snapshot(&snapshot_path, to_block, batch_hash)
                                .await
                            {
                                warn!(?err, "failed to persist forest snapshot");
                            }
                        }
                    }
                    Err(err) => {
                        if err.is_rpc_throttled() {
                            warn!(
                                rpc = rpc.url.as_str(),
                                "rpc is throttled, will retry with another..."
                            );
                        } else {
                            warn!(
                                ?err,
                                rpc = rpc.url.as_str(),
                                "failed to fetch logs, retrying..."
                            );
                        }
                        if err.should_mark_rpc_unhealthy() {
                            rpcs.mark_bad_provider(&rpc);
                        }
                    }
                }
            }
        }
        .instrument(tracing::info_span!("sync_live")),
    );
}

pub(super) fn spawn_backfill_loop(
    service: Arc<ChainService>,
    mut backfill_rx: mpsc::Receiver<BackfillRequest>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut cursors: HashMap<String, WalletBackfill> = HashMap::new();
        loop {
            if cursors.is_empty() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    Some(request) = backfill_rx.recv() => {
                        match request {
                            BackfillRequest::Add { cache_key, from_block, to_block, sender } => {
                                cursors.insert(cache_key, WalletBackfill { from_block, target_block: to_block, sender });
                            }
                            BackfillRequest::Reset { cache_key, from_block } => {
                                if let Some(cursor) = cursors.get_mut(&cache_key) {
                                    cursor.from_block = from_block;
                                }
                            }
                            BackfillRequest::Remove { cache_key } => {
                                cursors.remove(&cache_key);
                            }
                        }
                    }
                    _ = safe_head_rx.changed() => {},
                }
                // Re-enter the loop immediately so that pending requests in
                // backfill_rx are picked up without an unnecessary poll_interval
                // delay.
                continue;
            }

            let safe_head = *safe_head_rx.borrow();
            if safe_head > 0 {
                for cursor in cursors.values_mut().filter(|cursor| cursor.target_block == 0) {
                    cursor.target_block = safe_head;
                }
            }

            let done_keys: Vec<_> = cursors
                .iter()
                .filter(|(_, cursor)| cursor.target_block > 0 && cursor.from_block > cursor.target_block)
                .map(|(key, _)| key.clone())
                .collect();
            for key in done_keys {
                if let Some(cursor) = cursors.remove(&key)
                    && let Err(err) = cursor
                        .sender
                        .send(BackfillEvent::Done {
                            last_block: cursor.target_block,
                        })
                        .await
                {
                    debug!(?err, cache_key = %key, "failed to send backfill done");
                }
            }

            let min_from = cursors.values().map(|cursor| cursor.from_block).min();
            debug!(block=?min_from, "scanning wallet events");
            let Some(from_block) = min_from else {
                continue;
            };
            let Some(target_block) = cursors
                .values()
                .filter(|cursor| cursor.from_block == from_block)
                .map(|cursor| cursor.target_block)
                .filter(|target_block| *target_block > 0)
                .min()
            else {
                if safe_head == 0 {
                    // safe_head not yet available — the head poller hasn't
                    // successfully fetched a block number yet.  Wait for it
                    // instead of prematurely marking wallets as done.
                    debug!("safe_head is 0, waiting for head poller before backfill");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = safe_head_rx.changed() => { continue; }
                    }
                }
                continue;
            };
            let Some(rpc) = rpcs.random_provider() else {
                warn!("no healthy rpc providers available");
                tokio::time::sleep(service.chain.poll_interval).await;
                continue;
            };
            let to_block = min(from_block + service.chain.block_range - 1, target_block);
            let fetch_logs_started = Instant::now();
            match service.chain.fetch_logs_for_range(
                &rpc.provider,
                archive_provider.as_ref(),
                from_block,
                to_block,
            )
            .await
            {
                Ok(mut logs) => {
                    debug!(
                        from_block,
                        to_block,
                        num_logs = logs.len(),
                        elapsed_ms = fetch_logs_started.elapsed().as_millis(),
                        "fetched backfill logs"
                    );
                    sort_logs(&mut logs);
                    let timestamps_started = Instant::now();
                    let block_timestamps = match service
                        .chain
                        .fetch_log_block_timestamps(&rpc.provider, archive_provider.as_ref(), &logs)
                        .await
                    {
                        Ok(block_timestamps) => block_timestamps,
                        Err(err) => {
                            warn!(?err, "failed to fetch backfill log block timestamps");
                            if err.should_mark_rpc_unhealthy() {
                                rpcs.mark_bad_provider(&rpc);
                            } else {
                                tokio::time::sleep(service.chain.poll_interval).await;
                            }
                            continue;
                        }
                    };
                    debug!(
                        from_block,
                        to_block,
                        num_logs = logs.len(),
                        elapsed_ms = timestamps_started.elapsed().as_millis(),
                        "fetched backfill log block timestamps"
                    );
                    let block_hash_started = Instant::now();
                    let to_block_hash = service.chain.fetch_block_hash(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        to_block,
                    )
                    .await
                    .unwrap_or_else(|err| {
                        warn!(?err, to_block, "failed to fetch backfill block hash");
                        None
                    });
                    debug!(
                        to_block,
                        elapsed_ms = block_hash_started.elapsed().as_millis(),
                        "fetched backfill block hash"
                    );
                    let batch = Arc::new(LogBatch {
                        from_block,
                        to_block,
                        logs,
                        block_timestamps,
                        to_block_hash,
                    });

                    let keys: Vec<String> = cursors.keys().cloned().collect();
                    for key in keys {
                        if let Some(cursor) = cursors.get_mut(&key)
                            && cursor.from_block <= to_block
                        {
                            if let Err(err) =
                                cursor.sender.send(BackfillEvent::Logs(batch.clone())).await
                            {
                                debug!(
                                    ?err,
                                    cache_key = %key,
                                    "failed to send backfill logs"
                                );
                            }
                            cursor.from_block = to_block.saturating_add(1);
                            if cursor.from_block > cursor.target_block {
                                if let Err(err) = cursor
                                    .sender
                                    .send(BackfillEvent::Done {
                                        last_block: cursor.target_block,
                                    })
                                    .await
                                {
                                    debug!(
                                        ?err,
                                        cache_key = %key,
                                        "failed to send backfill done"
                                    );
                                }
                                cursors.remove(&key);
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        rpc = rpc.url.as_str(),
                        "failed to fetch backfill logs"
                    );
                    if err.should_mark_rpc_unhealthy() {
                        rpcs.mark_bad_provider(&rpc);
                    } else {
                        tokio::time::sleep(service.chain.poll_interval).await;
                    }
                }
            }
        }
    }.instrument(tracing::info_span!("sync_backfill")));
}
