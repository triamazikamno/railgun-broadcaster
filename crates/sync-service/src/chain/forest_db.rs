use super::*;

#[async_trait]
pub trait MerkleForestDbExt {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError>;
    fn anchor_dir(&self) -> PathBuf;
    fn find_latest_anchor(&self, chain: &ChainConfig)
    -> Result<Option<(PathBuf, u64)>, ChainError>;
}

#[async_trait]
impl MerkleForestDbExt for DbStore {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError> {
        let mut forest = MerkleForest::new();
        let mut last_processed = chain.deployment_block.saturating_sub(1);
        let file_name = format!("forest-{}-{}.msgpack", chain.chain_id, chain.contract);
        self.ensure_blob_dir("merkle_forest")?;
        let relative = DbStore::relative_blob_path("merkle_forest", &file_name);
        let mut snapshot_path = self.resolve_path(&relative);
        let mut last_anchor = 0;

        if let Ok(Some(meta)) =
            self.get_merkle_forest_meta(chain.chain_id, &chain.contract.to_string())
        {
            let path = self.resolve_path(&meta.relative_path);
            match MerkleForestSnapshot::load(&path, chain.chain_id, chain.contract) {
                Ok(Some(snapshot)) => {
                    forest = snapshot.forest;
                    last_processed = snapshot.last_processed_block;
                    snapshot_path = path;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?err, path = %path.display(), "failed to load merkle forest snapshot");
                }
            }
        }

        if let Ok(Some((anchor_path, anchor_block))) = self.find_latest_anchor(chain) {
            last_anchor = anchor_block;
            if last_processed < anchor_block {
                match MerkleForestSnapshot::load(&anchor_path, chain.chain_id, chain.contract) {
                    Ok(Some(snapshot)) => {
                        forest = snapshot.forest;
                        last_processed = snapshot.last_processed_block;
                        snapshot_path = anchor_path;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    }
                }
            }
        }

        if let Some(endpoint) = chain.quick_sync_endpoint.clone() {
            let client = match chain.http_client.clone() {
                Some(http_client) => {
                    QuickSyncClient::with_http_client(endpoint.clone(), http_client)
                }
                None => QuickSyncClient::new(endpoint.clone()),
            };
            match client.fetch_squid_height().await {
                Ok(indexed_height) => {
                    let target = indexed_height.min(safe_head);
                    info!(
                        chain_id = chain.chain_id,
                        indexed_height,
                        safe_head,
                        current_block = last_processed,
                        target,
                        "indexed forest catch-up target"
                    );
                    if target > last_processed {
                        let start_block =
                            last_processed.saturating_add(1).max(chain.deployment_block);
                        if start_block <= target {
                            let mut candidate = forest.clone();
                            let config = QuickSyncConfig {
                                endpoint,
                                start_block,
                                end_block: Some(target),
                                page_size: DEFAULT_PAGE_SIZE,
                                http_client: chain.http_client.clone(),
                            };
                            let progress_tx = chain.progress_tx.clone();
                            send_sync_progress(
                                progress_tx.as_ref(),
                                SyncProgressUpdate::new(
                                    SyncProgressStage::SynchronizingCommitments,
                                    start_block,
                                    start_block,
                                    target,
                                ),
                            );
                            match run_quick_sync_into_with_progress(
                                &mut candidate,
                                config,
                                |progress| {
                                    send_sync_progress(
                                        progress_tx.as_ref(),
                                        SyncProgressUpdate::new(
                                            SyncProgressStage::SynchronizingCommitments,
                                            progress.start_block,
                                            progress.latest_block,
                                            target,
                                        ),
                                    );
                                },
                            )
                            .await
                            {
                                Ok(progress) => {
                                    let block_hash = match provider {
                                        Some(provider) => chain
                                            .fetch_confirmed_block_hash(
                                                provider,
                                                archive_provider,
                                                target,
                                            )
                                            .await
                                            .unwrap_or_else(|err| {
                                                warn!(
                                                    ?err,
                                                    target,
                                                    "failed to fetch confirmed indexed forest target block hash"
                                                );
                                                None
                                            }),
                                        None => None,
                                    };
                                    match persist_indexed_forest_snapshot(
                                        self,
                                        chain,
                                        &snapshot_path,
                                        target,
                                        block_hash,
                                        &candidate,
                                    ) {
                                        Ok(()) => {
                                            forest = candidate;
                                            last_processed = target;
                                            send_sync_progress(
                                                progress_tx.as_ref(),
                                                SyncProgressUpdate::new(
                                                    SyncProgressStage::SynchronizingCommitments,
                                                    start_block,
                                                    target,
                                                    target,
                                                ),
                                            );
                                            info!(
                                                chain_id = chain.chain_id,
                                                from_block = start_block,
                                                target,
                                                commitments = progress.commitments,
                                                "indexed forest catch-up complete"
                                            );
                                        }
                                        Err(err) => {
                                            if let Some(error) = indexed_catch_up_unavailable(
                                                chain,
                                                last_processed,
                                                archive_provider,
                                                &err,
                                            ) {
                                                return Err(error);
                                            }
                                            warn!(
                                                ?err,
                                                fallback_from = last_processed,
                                                "indexed forest catch-up persistence failed; falling back to RPC"
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    if let Some(error) = indexed_catch_up_unavailable(
                                        chain,
                                        last_processed,
                                        archive_provider,
                                        &err,
                                    ) {
                                        return Err(error);
                                    }
                                    warn!(
                                        ?err,
                                        fallback_from = last_processed,
                                        "indexed forest catch-up failed; falling back to RPC"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    if let Some(error) =
                        indexed_catch_up_unavailable(chain, last_processed, archive_provider, &err)
                    {
                        return Err(error);
                    }
                    warn!(
                        ?err,
                        "indexed forest status query failed; falling back to RPC"
                    );
                }
            }
        }

        Ok((
            Arc::new(RwLock::new(forest)),
            last_processed,
            snapshot_path,
            last_anchor,
        ))
    }

    fn anchor_dir(&self) -> PathBuf {
        self.blob_dir().join("merkle_forest").join("anchors")
    }

    fn find_latest_anchor(
        &self,
        chain: &ChainConfig,
    ) -> Result<Option<(PathBuf, u64)>, ChainError> {
        let dir = self.anchor_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut latest: Option<(PathBuf, u64)> = None;
        for entry in std::fs::read_dir(&dir).map_err(PersistError::Io)? {
            let entry = entry.map_err(PersistError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(chain.chain_id, chain.contract, name) {
                let path = entry.path();
                match &latest {
                    Some((_, latest_block)) if *latest_block >= block => {}
                    _ => latest = Some((path, block)),
                }
            }
        }
        Ok(latest)
    }
}

fn persist_indexed_forest_snapshot(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    last_block: u64,
    block_hash: Option<[u8; 32]>,
    forest: &MerkleForest,
) -> Result<(), ChainError> {
    MerkleForestSnapshot::write(
        snapshot_path,
        chain.chain_id,
        chain.contract,
        last_block,
        forest,
    )?;
    db.update_merkle_forest_meta(
        chain.chain_id,
        &chain.contract.to_string(),
        snapshot_path,
        last_block,
        SNAPSHOT_VERSION,
        block_hash.unwrap_or([0u8; 32]),
    )?;
    Ok(())
}
