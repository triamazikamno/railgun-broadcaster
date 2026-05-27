use super::*;
use eyre::eyre;

pub(super) async fn snapshot_from_handle(chain_id: u64, handle: &WalletHandle) -> ListUtxosOutput {
    let utxos = handle.utxos.read().await.clone();
    let pending_overlay = handle.pending_overlay().await;
    let local_pending_spent_count = pending_overlay.local_pending_spent.len();
    let confirmed_utxos = utxos.clone();
    let (utxo_outputs, totals) = utxo_outputs_from_utxos(utxos);
    let mut utxo_outputs = utxo_outputs;
    apply_pending_overlay_to_outputs(&confirmed_utxos, pending_overlay, &mut utxo_outputs);
    let unspent_count = utxo_outputs.iter().filter(|utxo| !utxo.is_spent).count();
    let spent_count = utxo_outputs.len().saturating_sub(unspent_count);

    ListUtxosOutput {
        chain_id,
        cache_key: handle.cache_key.clone(),
        utxo_count: utxo_outputs.len(),
        unspent_count,
        spent_count,
        local_pending_spent_count,
        utxos: utxo_outputs,
        totals,
    }
}

pub(super) struct SyncedViewWallet {
    pub(super) db: Arc<DbStore>,
    pub(super) sync_manager: Arc<SyncManager>,
    pub(super) chain_key: ChainKey,
    pub(super) start_block: u64,
    pub(super) handle: WalletHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DesktopWalletChainStart {
    pub(crate) start_block: u64,
    pub(crate) last_scanned_block: u64,
}

pub(crate) fn resolve_desktop_wallet_chain_start(
    policy: DesktopWalletSyncStartPolicy,
    existing_metadata: Option<&vault::WalletChainMetadataBundle>,
    init_block_number: Option<u64>,
    deployment_block: u64,
    safe_head: Option<u64>,
    rewind_wallet_cache: bool,
) -> Result<DesktopWalletChainStart> {
    if let Some(metadata) = existing_metadata
        && !rewind_wallet_cache
    {
        return Ok(DesktopWalletChainStart {
            start_block: metadata.start_block,
            last_scanned_block: metadata.last_scanned_block,
        });
    }

    if rewind_wallet_cache {
        let start_block = init_block_number.unwrap_or(deployment_block);
        return Ok(DesktopWalletChainStart {
            start_block,
            last_scanned_block: start_block.saturating_sub(1),
        });
    }

    match policy {
        DesktopWalletSyncStartPolicy::ImportedHistoricalBackfill => {
            let start_block = init_block_number.unwrap_or(deployment_block);
            Ok(DesktopWalletChainStart {
                start_block,
                last_scanned_block: start_block.saturating_sub(1),
            })
        }
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill => {
            let safe_head = safe_head.ok_or_else(|| {
                eyre!("chain safe head unavailable for generated wallet; retry sync later")
            })?;
            let start_block = safe_head
                .checked_add(1)
                .ok_or_else(|| eyre!("chain safe head overflow for generated wallet"))?;
            Ok(DesktopWalletChainStart {
                start_block,
                last_scanned_block: safe_head,
            })
        }
    }
}

pub(super) async fn setup_synced_view_wallet_with_store(
    view_session: Arc<vault::DesktopViewSession>,
    chain_id: u64,
    sync_start_policy: DesktopWalletSyncStartPolicy,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    effective_chain: Option<settings::EffectiveChainConfig>,
    poi_read_source: PoiReadSource,
    shared_local_poi_caches: Option<WalletLocalPoiCaches>,
    rewind_wallet_cache: bool,
    rpc_url_override: Option<Url>,
    http: &HttpContext,
    progress_tx: Option<SyncProgressSender>,
    wait_until_ready: bool,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
) -> Result<SyncedViewWallet> {
    let chain_defaults = chain_defaults_for_chain(chain_id)?;
    let effective_contract = effective_chain
        .as_ref()
        .map(|chain| parse_effective_address("railgun contract", &chain.railgun_contract))
        .transpose()?;
    let chain_key = ChainKey {
        chain_id: chain_defaults.chain_id,
        contract: effective_contract.unwrap_or(chain_defaults.contract),
    };

    let effective_use_indexed_wallet_catch_up = effective_chain
        .as_ref()
        .map_or(use_indexed_wallet_catch_up, |chain| {
            use_indexed_wallet_catch_up && chain.quick_sync_enabled
        });
    let chain_cfg = chain_config(
        &chain_defaults,
        rpc_url_override,
        effective_chain.as_ref(),
        http,
        progress_tx.clone(),
    )?;
    let wallet_quick_sync_endpoint = chain_cfg.quick_sync_endpoint.clone();
    let chain_service = sync_manager
        .add_chain(chain_cfg)
        .await
        .wrap_err("register chain sync service")?;

    let vault_store = vault::DesktopVaultStore::from_db(Arc::clone(&db));
    let contract = chain_key.contract.to_checksum(None);
    let existing_wallet_chain_metadata = vault_store
        .find_wallet_chain_metadata_for_session(view_session.as_ref(), 0, chain_id, &contract)
        .wrap_err("load encrypted wallet chain metadata")?;
    let chain_handle = chain_service.handle();
    let safe_head = *chain_handle.safe_head_rx.borrow();
    let safe_head = (safe_head > 0).then_some(safe_head);
    let deployment_block = effective_chain
        .as_ref()
        .map_or(chain_defaults.deployment_block, |chain| {
            chain.deployment_block
        });
    let resolved_start = resolve_desktop_wallet_chain_start(
        sync_start_policy,
        existing_wallet_chain_metadata.as_ref(),
        init_block_number,
        deployment_block,
        safe_head,
        rewind_wallet_cache,
    )?;
    tracing::info!(
        chain_id,
        start_block = resolved_start.start_block,
        last_scanned_block = resolved_start.last_scanned_block,
        sync_to_block,
        effective_use_indexed_wallet_catch_up,
        poi_read_source = ?poi_read_source,
        sync_start_policy = ?sync_start_policy,
        "starting desktop view wallet sync"
    );
    let mut wallet_chain_metadata = match existing_wallet_chain_metadata {
        Some(metadata) => metadata,
        None => vault_store
            .create_wallet_chain_metadata_for_session(
                view_session.as_ref(),
                0,
                chain_id,
                &contract,
                resolved_start.start_block,
                resolved_start.last_scanned_block,
            )
            .wrap_err("create encrypted wallet chain metadata")?,
    };
    let start_block = resolved_start.start_block;
    if rewind_wallet_cache {
        wallet_chain_metadata.start_block = start_block;
        vault_store
            .rewind_wallet_chain_cache_with_session(
                view_session.as_ref(),
                &mut wallet_chain_metadata,
                start_block,
            )
            .wrap_err("rewind encrypted wallet cache")?;
        tracing::info!(
            chain_id,
            start_block,
            wallet_chain_uuid = %wallet_chain_metadata.wallet_chain_uuid,
            "rewound encrypted desktop wallet cache"
        );
    }
    let selected_poi_read_source = poi_read_source_label(&poi_read_source);
    if wallet_chain_metadata.poi_read_source.as_deref() != Some(selected_poi_read_source) {
        wallet_chain_metadata.poi_read_source = Some(selected_poi_read_source.to_string());
        vault_store
            .store_wallet_chain_metadata_with_session(view_session.as_ref(), &wallet_chain_metadata)
            .wrap_err("persist selected POI read source")?;
    }
    let cache_key = wallet_chain_metadata.wallet_chain_uuid.clone();
    let (local_poi_caches, manage_local_poi_cache) = wallet_local_poi_caches(
        &poi_read_source,
        chain_id,
        &cache_key,
        shared_local_poi_caches,
    );
    let cache_store = Arc::new(
        vault::DesktopEncryptedWalletCacheStore::new(
            Arc::clone(&db),
            Arc::clone(&view_session),
            wallet_chain_metadata,
        )
        .wrap_err("create encrypted wallet cache")?,
    );
    let scan_keys = view_session.scan_keys();
    let poi_recovery_prover = ProverService::new_with_db(artifact_source(http), Arc::clone(&db));
    let wallet_cfg = WalletConfig {
        chain: chain_key,
        cache_key,
        start_block: Some(start_block),
        sync_to_block,
        quick_sync_endpoint: wallet_quick_sync_endpoint,
        scan_keys,
        spending_public_key: Some(view_session.spending_public_key()),
        progress_tx,
        cache_store: Some(cache_store),
        poi_recovery_prover: Some(poi_recovery_prover),
        poi_read_source,
        local_poi_caches,
        manage_local_poi_cache,
        use_indexed_wallet_catch_up: effective_use_indexed_wallet_catch_up,
    };

    let mut handle = sync_manager
        .add_wallet(wallet_cfg)
        .await
        .wrap_err("register wallet sync worker")?;
    if wait_until_ready {
        handle.wait_until_ready().await;
    }

    Ok(SyncedViewWallet {
        db,
        sync_manager,
        chain_key,
        start_block,
        handle,
    })
}

pub(crate) fn chain_defaults_for_chain(chain_id: u64) -> Result<ChainConfigDefaults> {
    ChainConfigDefaults::for_chain(chain_id).ok_or_else(|| eyre!("unsupported chain id {chain_id}"))
}

pub(crate) fn chain_config(
    defaults: &ChainConfigDefaults,
    rpc_url_override: Option<Url>,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    http: &HttpContext,
    progress_tx: Option<SyncProgressSender>,
) -> Result<ChainConfig> {
    let rpc_urls = if effective_chain.is_some() {
        effective_rpc_urls_for_chain(defaults, effective_chain)?
    } else if let Some(rpc_url) = rpc_url_override {
        vec![rpc_url]
    } else {
        defaults.rpc_urls.clone()
    };
    let quick_sync_endpoint = effective_chain
        .filter(|chain| chain.quick_sync_enabled)
        .and_then(|chain| chain.quick_sync_endpoint.as_ref())
        .map(|url| Url::parse(url).wrap_err_with(|| format!("parse quick-sync URL {url}")))
        .transpose()?
        .or_else(|| {
            effective_chain
                .is_none()
                .then(|| defaults.quick_sync_endpoint.clone())
                .flatten()
        });
    let contract = effective_chain
        .map(|chain| parse_effective_address("railgun contract", &chain.railgun_contract))
        .transpose()?
        .unwrap_or(defaults.contract);
    let archive_rpc_url = effective_chain
        .and_then(|chain| chain.archive_rpc_url.as_ref())
        .map(|url| Url::parse(url).wrap_err_with(|| format!("parse archive RPC URL {url}")))
        .transpose()?;
    let query_rpc_pool = Arc::new(QueryRpcPool::with_http_client(
        rpc_urls,
        DEFAULT_QUERY_RPC_COOLDOWN,
        http.client.clone(),
    ));

    Ok(ChainConfig {
        chain_id: defaults.chain_id,
        contract,
        rpcs: query_rpc_pool,
        archive_rpc_url,
        archive_until_block: effective_chain.map_or(defaults.archive_until_block, |chain| {
            chain.archive_until_block
        }),
        deployment_block: effective_chain
            .map_or(defaults.deployment_block, |chain| chain.deployment_block),
        v2_start_block: effective_chain
            .map_or(defaults.v2_start_block, |chain| chain.v2_start_block),
        legacy_shield_block: effective_chain.map_or(defaults.legacy_shield_block, |chain| {
            chain.legacy_shield_block
        }),
        block_range: effective_chain
            .and_then(|chain| chain.block_range)
            .unwrap_or(DEFAULT_BLOCK_RANGE),
        indexed_wallet_block_range: effective_chain
            .map_or(defaults.indexed_wallet_block_range, |chain| {
                chain.indexed_wallet_block_range
            }),
        poll_interval: effective_chain
            .and_then(|chain| chain.poll_interval_secs)
            .map_or(DEFAULT_POLL_INTERVAL, Duration::from_secs),
        finality_depth: effective_chain
            .map_or(defaults.finality_depth, |chain| chain.finality_depth),
        quick_sync_endpoint,
        anchor_interval: defaults.anchor_interval,
        anchor_retention: defaults.anchor_retention,
        http_client: Some(http.client.clone()),
        progress_tx,
    })
}

pub(super) fn parse_effective_address(label: &str, value: &str) -> Result<Address> {
    Address::from_str(value).wrap_err_with(|| format!("parse effective {label} address"))
}

pub(super) fn wallet_local_poi_caches(
    poi_read_source: &PoiReadSource,
    chain_id: u64,
    cache_key: &str,
    shared_local_poi_caches: Option<WalletLocalPoiCaches>,
) -> (Option<WalletLocalPoiCaches>, bool) {
    if !matches!(poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return (None, false);
    }

    if let Some(local_poi_caches) = shared_local_poi_caches {
        tracing::info!(
            chain_id,
            cache_key,
            "using shared chain-scoped local POI cache for wallet session"
        );
        return (Some(local_poi_caches), false);
    }

    tracing::info!(
        chain_id,
        cache_key,
        "local POI cache enabled for wallet session"
    );
    (Some(Arc::new(RwLock::new(BTreeMap::new()))), true)
}

pub(super) const fn poi_read_source_label(poi_read_source: &PoiReadSource) -> &'static str {
    match poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => "indexed-artifacts",
        PoiReadSource::PoiProxy => "poi-proxy",
    }
}

pub(super) fn artifact_source(http: &HttpContext) -> ArtifactSource {
    match http.proxy_url.as_ref() {
        Some(url) => ArtifactSource::default().with_proxy(url.clone()),
        None => ArtifactSource::default(),
    }
}

pub(super) async fn buffered_gas_price_with_policy(
    provider: &(impl Provider + Clone),
    numerator: u128,
    denominator: u128,
) -> Result<u128> {
    if denominator == 0 {
        return Err(eyre!(
            "gas price buffer denominator must be greater than zero"
        ));
    }
    let gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")?;
    Ok(gas_price * numerator / denominator)
}
