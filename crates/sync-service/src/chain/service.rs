use super::*;

impl ChainService {
    pub async fn start(db: Arc<DbStore>, chain: ChainConfig) -> Result<Arc<Self>, ChainError> {
        if chain.archive_until_block > 0
            && chain.archive_rpc_url.is_none()
            && chain.deployment_block <= chain.archive_until_block
            && chain.quick_sync_endpoint.is_none()
        {
            return Err(ChainError::ArchiveRpcRequired(chain.archive_until_block));
        }
        let archive_provider = match chain.archive_rpc_url.as_ref() {
            Some(url) => Some(
                build_provider(url)
                    .await
                    .map_err(ChainError::ProviderBuild)?,
            ),
            None => None,
        };

        let rpcs = chain.rpcs.clone();
        let rpc = rpcs
            .random_provider()
            .ok_or_else(|| ChainError::NoHealthyRpc)?;
        let (initial_head, initial_safe_head) = fetch_initial_head(&chain, &rpc.provider).await;

        let (forest, last_processed, snapshot_path, last_anchor) = db
            .load_or_initialize_forest(
                &chain,
                initial_safe_head,
                Some(&rpc.provider),
                archive_provider.as_ref(),
            )
            .await?;

        let (head_tx, _head_rx) = watch::channel(initial_head);
        let (safe_head_tx, safe_head_rx) = watch::channel(initial_safe_head);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let service = Arc::new(Self {
            chain,
            db,
            forest,
            head_tx,
            safe_head_tx,
            forest_last_tx,
            live_log_tx,
            backfill_tx,
            archive_provider: archive_provider.clone(),
            wallets: RwLock::new(HashMap::new()),
            cancel: cancel.clone(),
            anchor_last: AtomicU64::new(last_anchor),
        });

        spawn_head_poller(service.clone(), rpcs.clone());
        spawn_live_log_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            forest_last_rx,
            safe_head_rx.clone(),
            snapshot_path,
            cancel.clone(),
        );
        spawn_txid_public_cache_loop(service.clone(), cancel.clone());
        spawn_pending_tip_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            service.head_tx.subscribe(),
            safe_head_rx.clone(),
            cancel.clone(),
        );
        spawn_backfill_loop(
            service.clone(),
            backfill_rx,
            rpcs,
            archive_provider,
            safe_head_rx,
            cancel,
        );

        Ok(service)
    }

    #[must_use]
    pub fn handle(&self) -> ChainHandle {
        ChainHandle {
            forest: self.forest.clone(),
            head_rx: self.head_tx.subscribe(),
            safe_head_rx: self.safe_head_tx.subscribe(),
            forest_last_rx: self.forest_last_tx.subscribe(),
            live_log_rx: self.live_log_tx.subscribe(),
        }
    }

    pub async fn wallet_handle(&self, cache_key: &str) -> Option<WalletHandle> {
        self.wallets
            .read()
            .await
            .get(cache_key)
            .map(|registration| registration.handle.clone())
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), ChainError> {
        let (backfill_sender, start_block, sync_to_block) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key).ok_or(ChainError::WalletNotFound)?;
            (
                registration.backfill_sender.clone(),
                registration.start_block,
                registration.sync_to_block,
            )
        };

        let reset_from = from_block.unwrap_or(start_block);
        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, sync_to_block);
        backfill_sender
            .send(BackfillEvent::Reset {
                from_block: reset_from,
            })
            .await?;

        self.backfill_tx
            .send(BackfillRequest::Add {
                cache_key: cache_key.to_string(),
                from_block: reset_from,
                to_block: sync_target,
                sender: backfill_sender,
            })
            .await?;

        info!(cache_key = %cache_key, from_block = reset_from, "wallet reset requested");
        Ok(())
    }

    pub async fn register_wallet(self: &Arc<Self>, cfg: WalletConfig) -> WalletHandle {
        let cache_key = cfg.cache_key.clone();
        if let Some(existing) = self.wallets.read().await.get(&cache_key) {
            return existing.handle.clone();
        }

        let mut cfg = cfg;
        let start_block = cfg.start_block.unwrap_or(self.chain.deployment_block);
        cfg.start_block = Some(start_block);

        let mut last_scanned = start_block.saturating_sub(1);
        let cache_store = wallet_cache_store(&self.db, &cfg);
        if let Ok(Some(meta)) = cache_store.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }

        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, cfg.sync_to_block);
        info!(
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            start_block,
            last_scanned,
            safe_head,
            sync_to_block = ?cfg.sync_to_block,
            sync_target,
            indexed_wallet_catch_up = cfg.use_indexed_wallet_catch_up,
            "registering wallet sync"
        );

        let initial_utxos = match cache_store.load_wallet_utxos(&cfg.cache_key) {
            Ok(cached) => cached,
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to load wallet cache");
                Vec::new()
            }
        };
        if last_scanned < start_block {
            last_scanned = start_block.saturating_sub(1);
        }

        let cancel = self.cancel.child_token();
        let live_rx = self.live_log_tx.subscribe();
        let (backfill_sender, backfill_rx) = mpsc::channel(128);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: self.db.clone(),
                rpcs: self.chain.rpcs.clone(),
                http_client: self.chain.http_client.clone(),
                forest: self.forest.clone(),
            },
            cfg.clone(),
            live_rx,
            backfill_rx,
            cancel.clone(),
            initial_utxos,
            last_scanned,
        );

        self.wallets.write().await.insert(
            cache_key,
            WalletRegistration {
                handle: handle.clone(),
                cfg: cfg.clone(),
                cancel: cancel.clone(),
                backfill_sender: backfill_sender.clone(),
                start_block,
                sync_to_block: cfg.sync_to_block,
            },
        );

        let service = Arc::clone(self);
        let catch_up_cfg = cfg.clone();
        let catch_up_handle = handle.clone();
        let catch_up_cancel = cancel;
        tokio::spawn(async move {
            if service
                .hedged_wallet_startup_sync(
                    &catch_up_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    backfill_sender.clone(),
                    &catch_up_cancel,
                )
                .await
            {
                return;
            }

            let mut checkpoint = last_scanned;
            if catch_up_cfg.use_indexed_wallet_catch_up {
                checkpoint = service
                    .indexed_wallet_catch_up(
                        &catch_up_cfg,
                        start_block,
                        checkpoint,
                        sync_target,
                        &catch_up_handle,
                        &catch_up_cancel,
                    )
                    .await;
            } else {
                debug!(cache_key = %catch_up_cfg.cache_key, "indexed wallet catch-up disabled");
            }
            if catch_up_cancel.is_cancelled() {
                return;
            }
            service
                .enqueue_wallet_backfill(
                    &catch_up_cfg.cache_key,
                    start_block,
                    checkpoint,
                    sync_target,
                    backfill_sender,
                )
                .await;
        });

        handle
    }

    async fn enqueue_wallet_backfill(
        &self,
        cache_key: &str,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        backfill_sender: mpsc::Sender<BackfillEvent>,
    ) {
        let from_block = wallet_backfill_from_block(last_scanned, start_block);

        // When safe_head has not been set yet (still 0) we cannot tell whether
        // the wallet is caught up, so we always enqueue a backfill request and
        // let the backfill loop wait for safe_head to become available.
        let needs_backfill = sync_target == 0 || from_block <= sync_target;

        if needs_backfill {
            if self
                .backfill_tx
                .send(BackfillRequest::Add {
                    cache_key: cache_key.to_string(),
                    from_block,
                    to_block: sync_target,
                    sender: backfill_sender.clone(),
                })
                .await
                .is_err()
            {
                warn!(
                    cache_key,
                    "backfill loop unavailable, sending done as fallback"
                );
                let _ = backfill_sender
                    .send(BackfillEvent::Done {
                        last_block: sync_target,
                    })
                    .await;
            }
        } else if let Err(err) = backfill_sender
            .send(BackfillEvent::Done {
                last_block: sync_target,
            })
            .await
        {
            debug!(?err, cache_key, "failed to send backfill done");
        }
    }

    async fn hedged_wallet_startup_sync(
        self: &Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        backfill_sender: mpsc::Sender<BackfillEvent>,
        cancel: &CancellationToken,
    ) -> bool {
        if !cfg.use_indexed_wallet_catch_up
            || self.chain.quick_sync_endpoint.is_none()
            || !should_hedge_wallet_startup(
                last_scanned,
                start_block,
                sync_target,
                self.chain.block_range,
            )
        {
            return false;
        }

        let started = Instant::now();
        info!(
            cache_key = %cfg.cache_key,
            start_block,
            last_scanned,
            sync_target,
            block_range = self.chain.block_range,
            "wallet startup hedge started"
        );

        let hedge_cancel = cancel.child_token();
        let (result_tx, mut result_rx) = mpsc::channel(2);

        let rpc_service = Arc::clone(self);
        let rpc_cfg = cfg.clone();
        let rpc_cancel = hedge_cancel.child_token();
        let rpc_result_tx = result_tx.clone();
        let rpc_handle = tokio::spawn(async move {
            let result = rpc_service
                .wallet_startup_rpc_candidate(
                    &rpc_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    rpc_cancel,
                )
                .await;
            let _ = rpc_result_tx
                .send((WalletStartupSyncStrategy::Rpc, result))
                .await;
        });

        let indexed_service = Arc::clone(self);
        let indexed_cfg = cfg.clone();
        let indexed_cancel = hedge_cancel.child_token();
        let indexed_result_tx = result_tx.clone();
        let indexed_handle = tokio::spawn(async move {
            let result = indexed_service
                .wallet_startup_indexed_candidate(
                    &indexed_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    indexed_cancel,
                )
                .await;
            let _ = indexed_result_tx
                .send((WalletStartupSyncStrategy::Indexed, result))
                .await;
        });
        drop(result_tx);

        let mut failures = 0_u8;
        while let Some((strategy, result)) = result_rx.recv().await {
            match result {
                Ok(candidate) => {
                    hedge_cancel.cancel();
                    rpc_handle.abort();
                    indexed_handle.abort();
                    let sent = send_wallet_startup_events(
                        &cfg.cache_key,
                        candidate.events,
                        sync_target,
                        &backfill_sender,
                    )
                    .await;
                    info!(
                        cache_key = %cfg.cache_key,
                        winner = candidate.strategy.as_str(),
                        reported_by = strategy.as_str(),
                        candidate_elapsed_ms = candidate.elapsed_ms,
                        elapsed_ms = started.elapsed().as_millis(),
                        cancelled_loser = true,
                        sent,
                        "wallet startup hedge complete"
                    );
                    return sent;
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    debug!(
                        err = %err,
                        cache_key = %cfg.cache_key,
                        strategy = strategy.as_str(),
                        failures,
                        "wallet startup hedge candidate failed"
                    );
                    if failures >= 2 {
                        break;
                    }
                }
            }
        }

        hedge_cancel.cancel();
        rpc_handle.abort();
        indexed_handle.abort();
        warn!(
            cache_key = %cfg.cache_key,
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup hedge failed; falling back to indexed-then-rpc startup sync"
        );
        false
    }

    async fn wallet_startup_rpc_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let from_block = wallet_backfill_from_block(last_scanned, start_block);
        let events = self
            .fetch_wallet_rpc_backfill_events(from_block, sync_target, &cancel)
            .await?;
        debug!(
            cache_key = %cfg.cache_key,
            from_block,
            sync_target,
            events = events.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup RPC candidate complete"
        );
        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Rpc,
            events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn wallet_startup_indexed_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let endpoint = self
            .chain
            .quick_sync_endpoint
            .clone()
            .ok_or(WalletStartupSyncError::Cancelled)?;
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let probe_started = Instant::now();
        let probe = wait_or_cancel(&cancel, client.probe_indexed_wallet_support()).await??;
        debug!(
            cache_key = %cfg.cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet hedge probe complete"
        );

        let target = probe.height.min(sync_target);
        let mut from_block = wallet_backfill_from_block(last_scanned, start_block);
        let progress_start = from_block;
        let progress_tx = cfg
            .progress_tx
            .clone()
            .or_else(|| self.chain.progress_tx.clone());
        let mut checkpoint = last_scanned;
        let mut events = Vec::new();
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            sync_target,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet hedge target"
        );

        if from_block <= target {
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    progress_start,
                    target,
                ),
            );
        }

        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
            let page_started = Instant::now();
            let page_kind = indexed_wallet_page_kind(from_block, self.chain.v2_start_block);
            let to_block = indexed_wallet_to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let page = wait_or_cancel(
                &cancel,
                fetch_indexed_wallet_page(&client, page_kind, from_block, to_block),
            )
            .await??;
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            let parse_started = Instant::now();
            let delta = parse_indexed_wallet_delta(
                &page.transact_commitments,
                &page.shield_commitments,
                &page.legacy_encrypted_commitments,
                &page.legacy_generated_commitments,
                &page.nullifiers,
                &cfg.scan_keys,
            );
            let delta_utxos = delta.utxos.len();
            let delta_nullifiers = delta.nullifiers.len();
            let commitment_observations = delta.commitment_observations.len();
            let parse_elapsed_ms = parse_started.elapsed().as_millis();
            checkpoint = page.checkpoint_block;
            events.push(BackfillEvent::IndexedDelta {
                from_block,
                to_block: checkpoint,
                delta: Box::new(delta),
            });
            debug!(
                cache_key = %cfg.cache_key,
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                transact_rows = page.transact_rows,
                shield_rows = page.shield_rows,
                legacy_encrypted_rows = page.legacy_encrypted_rows,
                legacy_generated_rows = page.legacy_generated_rows,
                nullifier_rows = page.nullifier_rows,
                delta_utxos,
                delta_nullifiers,
                commitment_observations,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet hedge page complete"
            );
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    checkpoint,
                    target,
                ),
            );
            from_block = checkpoint.saturating_add(1);
        }

        if checkpoint < sync_target {
            let tail_from = wallet_backfill_from_block(checkpoint, start_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(tail_from, sync_target, &cancel)
                .await?;
            events.append(&mut tail_events);
        }

        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Indexed,
            events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn fetch_wallet_rpc_backfill_events(
        &self,
        from_block: u64,
        to_block: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<BackfillEvent>, WalletStartupSyncError> {
        if from_block > to_block {
            return Ok(Vec::new());
        }
        let rpc = self
            .chain
            .rpcs
            .random_provider()
            .ok_or(ChainError::NoHealthyRpc)?;
        let started = Instant::now();
        let fetch_logs_started = Instant::now();
        let mut logs = match wait_or_cancel(
            cancel,
            self.chain.fetch_logs_for_range(
                &rpc.provider,
                self.archive_provider.as_ref(),
                from_block,
                to_block,
            ),
        )
        .await?
        {
            Ok(logs) => logs,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = fetch_logs_started.elapsed().as_millis(),
            "fetched hedged wallet RPC logs"
        );
        sort_logs(&mut logs);

        let timestamps_started = Instant::now();
        let block_timestamps = match wait_or_cancel(
            cancel,
            self.chain.fetch_log_block_timestamps(
                &rpc.provider,
                self.archive_provider.as_ref(),
                &logs,
            ),
        )
        .await?
        {
            Ok(block_timestamps) => block_timestamps,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = timestamps_started.elapsed().as_millis(),
            "fetched hedged wallet RPC log block timestamps"
        );

        let block_hash_started = Instant::now();
        let to_block_hash = match wait_or_cancel(
            cancel,
            self.chain
                .fetch_block_hash(&rpc.provider, self.archive_provider.as_ref(), to_block),
        )
        .await?
        {
            Ok(hash) => hash,
            Err(err) => {
                warn!(
                    ?err,
                    to_block, "failed to fetch hedged wallet RPC block hash"
                );
                None
            }
        };
        debug!(
            to_block,
            elapsed_ms = block_hash_started.elapsed().as_millis(),
            "fetched hedged wallet RPC block hash"
        );

        let batch = Arc::new(LogBatch {
            from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
        });
        debug!(
            from_block,
            to_block,
            elapsed_ms = started.elapsed().as_millis(),
            "hedged wallet RPC backfill candidate complete"
        );
        Ok(vec![BackfillEvent::Logs(batch)])
    }

    pub async fn unregister_wallet(&self, cache_key: &str) {
        if let Some((_key, registration)) = self.wallets.write().await.remove_entry(cache_key) {
            registration.cancel.cancel();
            if self
                .backfill_tx
                .send(BackfillRequest::Remove {
                    cache_key: cache_key.to_string(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cache_key, "failed to remove backfill cursor");
            }
        }
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    async fn indexed_wallet_catch_up(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        safe_head: u64,
        handle: &WalletHandle,
        cancel: &CancellationToken,
    ) -> u64 {
        if safe_head == 0 {
            debug!(cache_key = %cfg.cache_key, "safe head unavailable; skipping indexed wallet catch-up");
            return last_scanned;
        }
        let Some(endpoint) = self.chain.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cfg.cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return last_scanned;
        };
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let catch_up_started = Instant::now();
        let probe_started = Instant::now();
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return last_scanned;
            }
        };
        debug!(
            cache_key = %cfg.cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet probe complete"
        );
        let target = probe.height.min(safe_head);
        let mut from_block = last_scanned.saturating_add(1).max(start_block);
        let progress_start = from_block;
        let progress_tx = cfg
            .progress_tx
            .clone()
            .or_else(|| self.chain.progress_tx.clone());
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            safe_head,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet catch-up target"
        );
        if from_block > target {
            debug!(
                cache_key = %cfg.cache_key,
                elapsed_ms = catch_up_started.elapsed().as_millis(),
                "indexed wallet catch-up skipped; cache already at target"
            );
            return last_scanned;
        }
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                progress_start,
                target,
            ),
        );

        let cache_store = wallet_cache_store(&self.db, cfg);
        let mut checkpoint = last_scanned;
        while from_block <= target {
            if cancel.is_cancelled() {
                return checkpoint;
            }
            let page_started = Instant::now();
            let page_kind = indexed_wallet_page_kind(from_block, self.chain.v2_start_block);
            let to_block = indexed_wallet_to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let page =
                match fetch_indexed_wallet_page(&client, page_kind, from_block, to_block).await {
                    Ok(page) => page,
                    Err(err) => {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet catch-up page failed; using RPC backfill"
                        );
                        return checkpoint;
                    }
                };
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            if cancel.is_cancelled() {
                return checkpoint;
            }
            let parse_started = Instant::now();
            let delta = parse_indexed_wallet_delta(
                &page.transact_commitments,
                &page.shield_commitments,
                &page.legacy_encrypted_commitments,
                &page.legacy_generated_commitments,
                &page.nullifiers,
                &cfg.scan_keys,
            );
            let delta_utxos = delta.utxos.len();
            let delta_nullifiers = delta.nullifiers.len();
            let commitment_observations = delta.commitment_observations.len();
            let parse_elapsed_ms = parse_started.elapsed().as_millis();
            let poi_observation_started = Instant::now();
            process_pending_output_poi_observations(
                self.db.as_ref(),
                self.chain.chain_id,
                &delta.commitment_observations,
                None,
            )
            .await;
            let poi_observation_elapsed_ms = poi_observation_started.elapsed().as_millis();
            let lock_wait_started = Instant::now();
            let mut wallet_utxos = handle.utxos.write().await;
            let lock_wait_elapsed_ms = lock_wait_started.elapsed().as_millis();
            let apply_started = Instant::now();
            let changed = apply_wallet_delta_to_vec(cfg, &mut wallet_utxos, delta);
            let apply_elapsed_ms = apply_started.elapsed().as_millis();
            let (indexed_total, indexed_unspent, indexed_spent, persist_elapsed_ms) = {
                let indexed_spent = wallet_utxos.iter().filter(|utxo| utxo.is_spent()).count();
                let indexed_unspent = wallet_utxos.len().saturating_sub(indexed_spent);
                let persist_started = Instant::now();
                if let Err(err) = cache_store.store_wallet_utxos(
                    &cfg.cache_key,
                    &wallet_utxos,
                    Some(page.checkpoint_block),
                    None,
                ) {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        fallback_from = checkpoint,
                        "failed to persist indexed wallet checkpoint; using RPC backfill"
                    );
                    return checkpoint;
                }
                let persist_elapsed_ms = persist_started.elapsed().as_millis();
                (
                    wallet_utxos.len(),
                    indexed_unspent,
                    indexed_spent,
                    persist_elapsed_ms,
                )
            };
            drop(wallet_utxos);
            if changed {
                handle.notify_changed();
            }
            checkpoint = page.checkpoint_block;
            debug!(
                cache_key = %cfg.cache_key,
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                transact_rows = page.transact_rows,
                shield_rows = page.shield_rows,
                legacy_encrypted_rows = page.legacy_encrypted_rows,
                legacy_generated_rows = page.legacy_generated_rows,
                nullifier_rows = page.nullifier_rows,
                total = indexed_total,
                unspent = indexed_unspent,
                spent = indexed_spent,
                delta_utxos,
                delta_nullifiers,
                commitment_observations,
                poi_status_deferred = true,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                poi_observation_elapsed_ms,
                lock_wait_elapsed_ms,
                apply_elapsed_ms,
                persist_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet catch-up page complete"
            );
            from_block = checkpoint.saturating_add(1);
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    checkpoint,
                    target,
                ),
            );
        }
        info!(
            cache_key = %cfg.cache_key,
            checkpoint,
            target,
            elapsed_ms = catch_up_started.elapsed().as_millis(),
            "indexed wallet catch-up complete"
        );
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                target,
                target,
            ),
        );
        checkpoint
    }
}

async fn fetch_initial_head(chain: &ChainConfig, provider: &DynProvider) -> (u64, u64) {
    for attempt in 0..3u32 {
        match provider.get_block_number().await {
            Ok(head) => {
                let safe_head = head
                    .saturating_sub(chain.finality_depth)
                    .max(chain.deployment_block);
                return (head, safe_head);
            }
            Err(err) => {
                warn!(
                    ?err,
                    attempt, "failed to fetch initial block number, retrying..."
                );
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
                }
            }
        }
    }
    (0, 0)
}
