use super::*;

pub struct WalletSessionStore {
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
}

impl WalletSessionStore {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        let db = Arc::new(DbStore::open(DbConfig { root_dir: db_path }).wrap_err("open local db")?);
        Ok(Self::from_db(db))
    }

    #[must_use]
    pub fn from_db(db: Arc<DbStore>) -> Self {
        let sync_manager = Arc::new(SyncManager::new(Arc::clone(&db)));

        Self { db, sync_manager }
    }

    pub async fn start_view_wallet_session(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
    ) -> Result<WalletSession> {
        self.start_view_wallet_session_with_wait(request, rpc_url_override, http, true)
            .await
    }

    pub async fn start_view_wallet_session_immediate(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
    ) -> Result<WalletSession> {
        self.start_view_wallet_session_with_wait(request, rpc_url_override, http, false)
            .await
    }

    async fn start_view_wallet_session_with_wait(
        &self,
        request: ViewWalletChainSessionRequest,
        rpc_url_override: Option<Url>,
        http: &HttpContext,
        wait_until_ready: bool,
    ) -> Result<WalletSession> {
        let chain_id = request.chain_id;
        let synced = setup_synced_view_wallet_with_store(
            request.view_session,
            chain_id,
            request.sync_start_policy,
            request.init_block_number,
            request.sync_to_block,
            request.use_indexed_wallet_catch_up,
            request.effective_chain.clone(),
            request.poi_read_source.clone(),
            request.local_poi_caches.clone(),
            request.rewind_wallet_cache,
            rpc_url_override,
            http,
            request.progress_tx.clone(),
            wait_until_ready,
            Arc::clone(&self.db),
            Arc::clone(&self.sync_manager),
        )
        .await?;

        wallet_session_from_view_synced(chain_id, synced).await
    }

    pub async fn shutdown(&self) {
        self.sync_manager.shutdown().await;
    }
}

async fn wallet_session_from_view_synced(
    chain_id: u64,
    synced: SyncedViewWallet,
) -> Result<WalletSession> {
    wallet_session_from_parts(
        chain_id,
        synced.db,
        synced.sync_manager,
        synced.chain_key,
        synced.start_block,
        synced.handle,
    )
    .await
}

async fn wallet_session_from_parts(
    chain_id: u64,
    db: Arc<DbStore>,
    sync_manager: Arc<SyncManager>,
    chain_key: ChainKey,
    start_block: u64,
    handle: WalletHandle,
) -> Result<WalletSession> {
    let mut rev_rx = handle.rev_rx.clone();
    let initial_snapshot = Arc::new(snapshot_from_handle(chain_id, &handle).await);
    let (snapshots_tx, snapshots_rx) = watch::channel(initial_snapshot);
    let cache_key = handle.cache_key.clone();
    let ready_rx = handle.ready_rx.clone();
    let poi_refreshing_rx = handle.poi_refreshing_rx.clone();
    let snapshot_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            if rev_rx.changed().await.is_err() {
                break;
            }
            let snapshot = Arc::new(snapshot_from_handle(chain_id, &snapshot_handle).await);
            if snapshots_tx.send(snapshot).is_err() {
                break;
            }
        }
    });

    Ok(WalletSession {
        chain_id,
        cache_key,
        start_block,
        ready_rx,
        snapshots_rx,
        poi_refreshing_rx,
        db,
        sync_manager,
        chain_key,
        handle,
    })
}
