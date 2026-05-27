use super::*;

pub(crate) fn wallet_poi_status_refresh_needed(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    wallet_poi_status_refresh_needed_for_selection(
        wallet_utxos,
        active_list_keys,
        WalletPoiRefreshSelection::Required,
    )
}

pub(super) fn wallet_poi_status_refresh_needed_for_selection(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    selection: WalletPoiRefreshSelection,
) -> bool {
    !active_list_keys.is_empty()
        && wallet_utxos.iter().any(|wallet_utxo| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
}

pub(super) fn blinded_commitment_type(kind: UtxoCommitmentKind) -> BlindedCommitmentType {
    match kind {
        UtxoCommitmentKind::Shield => BlindedCommitmentType::Shield,
        UtxoCommitmentKind::Transact => BlindedCommitmentType::Transact,
    }
}

pub(crate) fn wallet_poi_status_client(
    http_client: Option<&reqwest::Client>,
) -> Option<PoiRpcClient> {
    let url = Url::parse(DEFAULT_WALLET_POI_RPC_URL).ok()?;
    Some(match http_client {
        Some(http_client) => PoiRpcClient::with_http_client(url, http_client.clone()),
        None => PoiRpcClient::new(url),
    })
}

pub(crate) struct WalletWorkerServices {
    pub db: Arc<DbStore>,
    pub rpcs: Arc<QueryRpcPool>,
    pub http_client: Option<reqwest::Client>,
    pub forest: Arc<RwLock<MerkleForest>>,
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

impl WalletHandle {
    pub async fn wait_until_ready(&mut self) {
        while !*self.ready_rx.borrow() {
            if self.ready_rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub(crate) fn notify_changed(&self) {
        let rev = self.rev_rx.borrow().wrapping_add(1);
        if let Err(err) = self.rev_tx.send(rev) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet revision");
        }
    }

    pub(super) fn notify_if_changed(&self, changed: bool) {
        if changed {
            self.notify_changed();
        }
    }
}

#[derive(Default)]
pub(super) struct WalletPersistState {
    pub(super) needs_full_persist: bool,
    pub(super) pending_cache_reset: Option<u64>,
}

impl WalletPersistState {
    pub(super) fn persist_progress(
        &mut self,
        cache_store: &dyn WalletCacheStore,
        request: WalletProgressPersist<'_>,
    ) -> Result<bool, WalletCacheError> {
        if let Some(reset_last_scanned) = self.pending_cache_reset {
            let reset_started = Instant::now();
            cache_store.reset_wallet_cache(request.cache_key, reset_last_scanned)?;
            self.pending_cache_reset = None;
            self.needs_full_persist = true;
            debug!(
                cache_key = %request.cache_key,
                reset_last_scanned,
                elapsed_ms = reset_started.elapsed().as_millis(),
                "reset wallet cache before persisting progress"
            );
        }

        let full_persist = request.changed || self.needs_full_persist;
        if full_persist {
            let persist_started = Instant::now();
            return match cache_store.store_wallet_utxos(
                request.cache_key,
                request.snapshot,
                Some(request.last_scanned),
                request.last_scanned_block_hash,
            ) {
                Ok(()) => {
                    self.needs_full_persist = false;
                    debug!(
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "persisted wallet full snapshot"
                    );
                    Ok(true)
                }
                Err(err) => {
                    self.needs_full_persist = true;
                    debug!(
                        ?err,
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "failed to persist wallet full snapshot"
                    );
                    Err(err)
                }
            };
        }

        let meta_started = Instant::now();
        cache_store.update_wallet_meta(
            request.cache_key,
            request.last_scanned,
            request.last_scanned_block_hash,
        )?;
        debug!(
            cache_key = %request.cache_key,
            last_scanned = request.last_scanned,
            elapsed_ms = meta_started.elapsed().as_millis(),
            "persisted wallet metadata progress"
        );
        Ok(false)
    }
}

pub(super) struct WalletLiveMetadataFlush {
    pub(super) last_persisted_block: u64,
    pub(super) last_persisted_at: Instant,
}

impl WalletLiveMetadataFlush {
    pub(super) fn new(last_persisted_block: u64, now: Instant) -> Self {
        Self {
            last_persisted_block,
            last_persisted_at: now,
        }
    }

    pub(super) fn should_flush(&self, last_scanned: u64, now: Instant) -> bool {
        last_scanned.saturating_sub(self.last_persisted_block) >= WALLET_METADATA_LIVE_FLUSH_BLOCKS
            || now.duration_since(self.last_persisted_at) >= WALLET_METADATA_LIVE_FLUSH_INTERVAL
    }

    pub(super) fn mark_persisted(&mut self, last_persisted_block: u64, now: Instant) {
        self.last_persisted_block = last_persisted_block;
        self.last_persisted_at = now;
    }
}

pub(super) struct WalletProgressPersist<'a> {
    pub(super) cache_key: &'a str,
    pub(super) snapshot: &'a [WalletUtxo],
    pub(super) last_scanned: u64,
    pub(super) last_scanned_block_hash: Option<[u8; 32]>,
    pub(super) changed: bool,
}

#[derive(Default)]
pub(super) struct WalletProgressPersistOutcome {
    pub(super) persisted_full_snapshot: bool,
    pub(super) persisted_progress: bool,
}

pub(super) struct WalletSnapshotPersist<'a> {
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) snapshot: &'a [WalletUtxo],
    pub(super) last_scanned: u64,
    pub(super) last_scanned_block_hash: Option<[u8; 32]>,
    pub(super) changed: bool,
    pub(super) persist_state: &'a mut WalletPersistState,
    pub(super) live_metadata_flush: Option<&'a mut WalletLiveMetadataFlush>,
    pub(super) error_message: &'static str,
}

pub(super) struct WalletPoiStatusRefreshPersist<'a> {
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) last_scanned: u64,
    pub(super) persist_state: &'a mut WalletPersistState,
}

pub(super) fn persist_wallet_snapshot(
    request: WalletSnapshotPersist<'_>,
) -> WalletProgressPersistOutcome {
    let WalletSnapshotPersist {
        cache_store,
        cfg,
        snapshot,
        last_scanned,
        last_scanned_block_hash,
        changed,
        persist_state,
        live_metadata_flush,
        error_message,
    } = request;

    match persist_state.persist_progress(
        cache_store,
        WalletProgressPersist {
            cache_key: &cfg.cache_key,
            snapshot,
            last_scanned,
            last_scanned_block_hash,
            changed,
        },
    ) {
        Ok(persisted_full_snapshot) => {
            if let Some(live_metadata_flush) = live_metadata_flush {
                live_metadata_flush.mark_persisted(last_scanned, Instant::now());
            }
            WalletProgressPersistOutcome {
                persisted_full_snapshot,
                persisted_progress: true,
            }
        }
        Err(err) => {
            warn!(?err, cache_key = %cfg.cache_key, "{error_message}");
            WalletProgressPersistOutcome::default()
        }
    }
}

pub(super) async fn refresh_wallet_poi_statuses_and_persist(
    client: &dyn PoiStatusReader,
    persist: WalletPoiStatusRefreshPersist<'_>,
    selection: WalletPoiRefreshSelection,
) -> bool {
    let started = Instant::now();
    let selection_label = selection.as_str();
    let lock_wait_started = Instant::now();
    let mut locked = persist.utxos.write().await;
    let lock_wait_elapsed_ms = lock_wait_started.elapsed().as_millis();
    let changed = refresh_wallet_poi_statuses_selected(
        client,
        persist.cfg.chain.chain_id,
        persist.active_list_keys,
        &mut locked,
        selection,
    )
    .await;
    if !changed {
        debug!(
            cache_key = %persist.cfg.cache_key,
            selection = selection_label,
            changed,
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "wallet POI status refresh persistence skipped"
        );
        return false;
    }

    let persist_started = Instant::now();
    if let Err(err) = persist.persist_state.persist_progress(
        persist.cache_store,
        WalletProgressPersist {
            cache_key: &persist.cfg.cache_key,
            snapshot: &locked,
            last_scanned: persist.last_scanned,
            last_scanned_block_hash: None,
            changed: true,
        },
    ) {
        warn!(?err, cache_key = %persist.cfg.cache_key, "failed to persist wallet POI status refresh");
    }
    debug!(
        cache_key = %persist.cfg.cache_key,
        selection = selection_label,
        changed,
        rows = locked.len(),
        lock_wait_elapsed_ms,
        persist_elapsed_ms = persist_started.elapsed().as_millis(),
        elapsed_ms = started.elapsed().as_millis(),
        "wallet POI status refresh persisted"
    );
    true
}

pub(super) async fn refresh_wallet_poi_statuses_and_persist_with_config(
    remote_client: &PoiRpcClient,
    _db: &DbStore,
    _http_client: Option<&reqwest::Client>,
    persist: WalletPoiStatusRefreshPersist<'_>,
    selection: WalletPoiRefreshSelection,
) -> bool {
    match &persist.cfg.poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => {
            let local_caches = persist
                .cfg
                .local_poi_caches
                .as_ref()
                .cloned()
                .unwrap_or_else(|| {
                    warn!(
                        cache_key = %persist.cfg.cache_key,
                        chain_id = persist.cfg.chain.chain_id,
                        "artifact POI read source missing local cache handle"
                    );
                    Arc::new(RwLock::new(BTreeMap::new()))
                });
            let reader = LocalPoiStatusReader::new(local_caches);
            refresh_wallet_poi_statuses_and_persist(&reader, persist, selection).await
        }
        PoiReadSource::PoiProxy => {
            refresh_wallet_poi_statuses_and_persist(remote_client, persist, selection).await
        }
    }
}

pub(super) struct OutputPoiRecoveryRun<'a> {
    pub(super) db: &'a DbStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) rpcs: &'a QueryRpcPool,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) forest: &'a Arc<RwLock<MerkleForest>>,
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) client: &'a PoiRpcClient,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) force_retry: bool,
}

pub(super) async fn recover_missing_output_pois_from_wallet(
    run: OutputPoiRecoveryRun<'_>,
) -> usize {
    if run.cfg.spending_public_key.is_none() || run.cfg.poi_recovery_prover.is_none() {
        return 0;
    }
    let snapshot = run.utxos.read().await.clone();
    mark_valid_output_poi_recoveries(run.db, run.cfg, &snapshot, run.active_list_keys);
    if output_poi_recovery_candidates(&snapshot, run.active_list_keys).is_empty() {
        return 0;
    }
    let forest = run.forest.read().await.clone();
    let local_proof_source = match &run.cfg.poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => {
            let local_caches = run
                .cfg
                .local_poi_caches
                .as_ref()
                .cloned()
                .unwrap_or_else(|| {
                    warn!(
                        cache_key = %run.cfg.cache_key,
                        chain_id = run.cfg.chain.chain_id,
                        "artifact POI read source missing local cache handle"
                    );
                    Arc::new(RwLock::new(BTreeMap::new()))
                });
            Some(LocalPoiMerkleProofSource::new(local_caches))
        }
        PoiReadSource::PoiProxy => None,
    };
    let proof_source: &(dyn PoiMerkleProofSource + '_);
    if let Some(source) = local_proof_source.as_ref() {
        proof_source = source;
    } else {
        proof_source = run.client;
    }
    recover_missing_output_pois(OutputPoiRecoveryRequest {
        db: run.db,
        cfg: run.cfg,
        rpcs: run.rpcs,
        http_client: run.http_client,
        forest: &forest,
        poi_client: run.client,
        proof_source,
        local_proof_source: local_proof_source.as_ref(),
        submitter: run.client,
        active_list_keys: run.active_list_keys,
        wallet_utxos: &snapshot,
        force_retry: run.force_retry,
    })
    .await
}
