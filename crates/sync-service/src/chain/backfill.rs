use super::*;

pub(super) struct WalletBackfill {
    pub(super) from_block: u64,
    pub(super) target_block: u64,
    pub(super) sender: mpsc::Sender<BackfillEvent>,
}

impl ChainService {
    pub(super) async fn apply_forest_updates(
        &self,
        batch: &SharedLogBatch,
    ) -> Result<(), ChainError> {
        let mut forest = self.forest.write().await;
        forest.apply_commitment_updates_from_logs(&batch.logs)?;
        forest.compute_roots();
        Ok(())
    }
    pub(super) async fn reset_forest_state(
        &self,
        snapshot_path: &Path,
        last_processed: u64,
    ) -> Result<u64, ChainError> {
        let mut forest = self.forest.write().await;
        let mut reset_block = self.chain.deployment_block.saturating_sub(1);

        if let Ok(Some((anchor_path, anchor_block))) = self.db.find_latest_anchor(&self.chain) {
            match MerkleForestSnapshot::load(&anchor_path, self.chain.chain_id, self.chain.contract)
            {
                Ok(Some(snapshot)) => {
                    *forest = snapshot.forest;
                    reset_block = snapshot.last_processed_block;
                    MerkleForestSnapshot::write(
                        snapshot_path,
                        self.chain.chain_id,
                        self.chain.contract,
                        reset_block,
                        &forest,
                    )?;
                    self.anchor_last.store(anchor_block, Ordering::Relaxed);
                    info!(
                        from = last_processed,
                        to = reset_block,
                        anchor = %anchor_path.display(),
                        "forest reset to anchor"
                    );
                }
                Ok(None) => {
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
                Err(err) => {
                    warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
            }
        } else {
            *forest = MerkleForest::new();
            self.anchor_last.store(0, Ordering::Relaxed);
        }

        MerkleForestSnapshot::write(
            snapshot_path,
            self.chain.chain_id,
            self.chain.contract,
            reset_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
            snapshot_path,
            reset_block,
            SNAPSHOT_VERSION,
            [0u8; 32],
        )?;
        if let Err(err) = self.forest_last_tx.send(reset_block) {
            debug!(?err, reset_block, "failed to send forest reset update");
        }
        info!(
            from = last_processed,
            to = reset_block,
            "forest state reset"
        );
        Ok(reset_block)
    }

    pub(super) async fn reset_wallets(&self, safe_head: u64, reset_from_block: u64) {
        let wallets = self.wallets.read().await;
        for (cache_key, registration) in wallets.iter() {
            let from_block =
                wallet_reorg_backfill_from_block(reset_from_block, registration.start_block);
            let sync_target = wallet_sync_target(safe_head, registration.sync_to_block);
            if let Err(err) = registration
                .backfill_sender
                .send(BackfillEvent::Reset { from_block })
                .await
            {
                debug!(
                    ?err,
                    cache_key = %cache_key,
                    "failed to send wallet rewind"
                );
            }
            if self
                .backfill_tx
                .send(BackfillRequest::Add {
                    cache_key: cache_key.clone(),
                    from_block,
                    to_block: sync_target,
                    sender: registration.backfill_sender.clone(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cache_key, "failed to enqueue wallet backfill");
            }
        }
    }

    pub(super) async fn check_forest_reorg(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        rpc_url: &str,
        snapshot_path: &Path,
        safe_head: u64,
        last_processed: u64,
    ) -> Result<(), ChainError> {
        if last_processed < self.chain.deployment_block {
            return Ok(());
        }
        let meta = self
            .db
            .get_merkle_forest_meta(self.chain.chain_id, &self.chain.contract.to_string())?;
        let Some(meta) = meta else {
            return Ok(());
        };
        if meta.hash == [0u8; 32] {
            return Ok(());
        }

        if meta.last_block != last_processed {
            warn!(
                chain_id = self.chain.chain_id,
                contract = %self.chain.contract,
                rpc = rpc_url,
                safe_head,
                last_processed,
                meta_last_block = meta.last_block,
                stored_hash = %FixedBytes::<32>::from(meta.hash),
                "skipping reorg check because forest metadata block does not match progress"
            );
            return Ok(());
        }

        let current_hash = self
            .chain
            .fetch_confirmed_block_hash(provider, archive_provider, last_processed)
            .await?;
        match forest_reorg_decision(last_processed, meta.last_block, meta.hash, current_hash) {
            ForestReorgDecision::Skip => {
                debug!(
                    chain_id = self.chain.chain_id,
                    contract = %self.chain.contract,
                    rpc = rpc_url,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    "skipping reorg check without a confirmed block hash"
                );
            }
            ForestReorgDecision::Match => {}
            ForestReorgDecision::Mismatch => {
                let current_hash = current_hash.expect("mismatch requires confirmed hash");
                warn!(
                    chain_id = self.chain.chain_id,
                    contract = %self.chain.contract,
                    rpc = rpc_url,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    stored_hash = %FixedBytes::<32>::from(meta.hash),
                    current_hash = %FixedBytes::<32>::from(current_hash),
                    "detected confirmed reorg, rewinding forest and wallet caches"
                );
                let reset_block = self
                    .reset_forest_state(snapshot_path, last_processed)
                    .await?;
                self.reset_wallets(safe_head, reset_block.saturating_add(1))
                    .await;
            }
        }
        Ok(())
    }

    pub(super) async fn persist_forest_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        block_hash: Option<[u8; 32]>,
    ) -> Result<(), ChainError> {
        let forest = self.forest.read().await;
        MerkleForestSnapshot::write(
            snapshot_path,
            self.chain.chain_id,
            self.chain.contract,
            last_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
            snapshot_path,
            last_block,
            SNAPSHOT_VERSION,
            block_hash.unwrap_or([0u8; 32]),
        )?;

        self.maybe_write_anchor_snapshot(snapshot_path, last_block, &forest)?;

        Ok(())
    }

    pub(super) fn maybe_write_anchor_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        forest: &MerkleForest,
    ) -> Result<(), PersistError> {
        let interval = self.chain.anchor_interval;
        if interval == 0 {
            return Ok(());
        }
        let last_anchor = self.anchor_last.load(Ordering::Relaxed);
        if last_block < last_anchor.saturating_add(interval) {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        std::fs::create_dir_all(&anchor_dir)?;
        let file_name = anchor_file_name(self.chain.chain_id, self.chain.contract, last_block);
        let relative = DbStore::relative_blob_path("merkle_forest/anchors", &file_name);
        let path = self.db.resolve_path(&relative);
        MerkleForestSnapshot::write(
            &path,
            self.chain.chain_id,
            self.chain.contract,
            last_block,
            forest,
        )?;
        self.anchor_last.store(last_block, Ordering::Relaxed);
        if path.as_path() != snapshot_path {
            debug!(path = %path.display(), block = last_block, "wrote anchor snapshot");
        }
        if let Err(err) = self.prune_anchor_snapshots(snapshot_path) {
            warn!(?err, "failed to prune anchor snapshots");
        }
        Ok(())
    }

    pub(super) fn prune_anchor_snapshots(&self, snapshot_path: &Path) -> Result<(), PersistError> {
        let retention = self.chain.anchor_retention;
        if retention == 0 {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        if !anchor_dir.exists() {
            return Ok(());
        }
        let mut anchors = Vec::with_capacity(retention + 8);
        for entry in std::fs::read_dir(&anchor_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(self.chain.chain_id, self.chain.contract, name)
            {
                anchors.push((entry.path(), block));
            }
        }
        if anchors.len() <= retention {
            return Ok(());
        }
        anchors.sort_by_key(|(_, block)| *block);
        let mut keep = HashSet::new();
        for (path, _) in anchors.iter().rev().take(retention) {
            keep.insert(path.clone());
        }
        if snapshot_path.starts_with(&anchor_dir) {
            keep.insert(snapshot_path.to_path_buf());
        }
        for (path, block) in anchors {
            if keep.contains(&path) {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    debug!(path = %path.display(), block, "pruned anchor snapshot");
                }
                Err(err) => {
                    warn!(?err, path = %path.display(), block, "failed to prune anchor snapshot");
                }
            }
        }
        Ok(())
    }
}

impl ChainConfig {
    pub(super) async fn fetch_confirmed_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let Some(first_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            return Ok(None);
        };

        let Some(second_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            debug!(
                block_number,
                "block hash confirmation read returned no block"
            );
            return Ok(None);
        };

        if second_hash != first_hash {
            debug!(
                block_number,
                first_hash = %FixedBytes::<32>::from(first_hash),
                second_hash = %FixedBytes::<32>::from(second_hash),
                "block hash changed between confirmation reads"
            );
            return Ok(None);
        }

        Ok(Some(first_hash))
    }

    pub(super) async fn fetch_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let provider = if self.archive_until_block > 0 && block_number <= self.archive_until_block {
            archive_provider.ok_or(ChainError::ArchiveRpcRequired(self.archive_until_block))?
        } else {
            provider
        };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.hash.0))
    }

    pub(super) async fn fetch_block_timestamp(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<u64>, ChainError> {
        let provider = if self.archive_until_block > 0 && block_number <= self.archive_until_block {
            archive_provider.ok_or(ChainError::ArchiveRpcRequired(self.archive_until_block))?
        } else {
            provider
        };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.timestamp))
    }

    pub(super) async fn fetch_log_block_timestamps(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        logs: &[Log],
    ) -> Result<HashMap<u64, u64>, ChainError> {
        let mut block_numbers = logs
            .iter()
            .filter_map(|log| log.block_number)
            .collect::<Vec<_>>();
        block_numbers.sort_unstable();
        block_numbers.dedup();

        let mut timestamps = HashMap::with_capacity(block_numbers.len());
        for block_number in block_numbers {
            if let Some(timestamp) = self
                .fetch_block_timestamp(provider, archive_provider, block_number)
                .await?
            {
                timestamps.insert(block_number, timestamp);
            }
        }
        Ok(timestamps)
    }

    pub(super) async fn fetch_logs_for_range(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, ChainError> {
        let mut logs = Vec::new();
        let archive_until_block = self.archive_until_block;

        if archive_until_block > 0 && from_block <= archive_until_block {
            let archive_end = to_block.min(archive_until_block);
            let archive_provider =
                archive_provider.ok_or(ChainError::ArchiveRpcRequired(archive_until_block))?;
            let archive_logs = fetch_logs_for_range_with_provider(
                archive_provider,
                self.contract,
                from_block,
                archive_end,
                self.v2_start_block,
                self.legacy_shield_block,
            )
            .await?;
            logs.extend(archive_logs);
        }

        if to_block > archive_until_block {
            let standard_start = if archive_until_block > 0 {
                from_block.max(archive_until_block + 1)
            } else {
                from_block
            };
            let standard_logs = fetch_logs_for_range_with_provider(
                provider,
                self.contract,
                standard_start,
                to_block,
                self.v2_start_block,
                self.legacy_shield_block,
            )
            .await?;
            logs.extend(standard_logs);
        }

        Ok(logs)
    }
}
