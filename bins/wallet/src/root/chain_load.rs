use std::sync::Arc;

use gpui::{Context, ParentElement, SharedString, Styled, Window, div, px, rgb};
use gpui_component::{WindowExt, progress::Progress as UiProgress};
use tokio::runtime::Handle;
use tokio::sync::{OnceCell, watch};
use ui::theme::{self, APP_TEXT_SIZE};
use wallet_ops::{
    DesktopWalletSyncStartPolicy, HttpContext, ListUtxosOutput, PoiCacheService, PoiReadSource,
    SyncProgressUpdate, ViewWalletChainSessionRequest, WalletSessionStore,
    vault::{DesktopVaultStore, WalletSource},
};

use super::utxo::should_focus_utxo_table;
use super::{WalletRoot, WalletTab};

pub(super) enum ChainUtxoState {
    Idle,
    Loading {
        progress: Option<SyncProgressUpdate>,
    },
    Syncing {
        snapshot: Arc<ListUtxosOutput>,
        progress: Option<SyncProgressUpdate>,
        session: Arc<wallet_ops::WalletSession>,
        poi_refreshing: bool,
    },
    Ready {
        snapshot: Arc<ListUtxosOutput>,
        session: Arc<wallet_ops::WalletSession>,
        poi_refreshing: bool,
    },
    Error {
        message: Arc<str>,
        start_block: Option<u64>,
    },
}

impl ChainUtxoState {
    pub(super) const fn snapshot(&self) -> Option<&Arc<ListUtxosOutput>> {
        match self {
            Self::Syncing { snapshot, .. } | Self::Ready { snapshot, .. } => Some(snapshot),
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => None,
        }
    }

    pub(super) const fn progress(&self) -> Option<SyncProgressUpdate> {
        match self {
            Self::Loading { progress } | Self::Syncing { progress, .. } => *progress,
            Self::Idle | Self::Ready { .. } | Self::Error { .. } => None,
        }
    }

    pub(super) fn start_block(&self) -> Option<u64> {
        match self {
            Self::Syncing { session, .. } | Self::Ready { session, .. } => {
                Some(session.start_block)
            }
            Self::Error { start_block, .. } => *start_block,
            Self::Idle | Self::Loading { .. } => None,
        }
    }

    pub(super) const fn renders_table(&self) -> bool {
        matches!(
            self,
            Self::Loading { .. } | Self::Syncing { .. } | Self::Ready { .. }
        )
    }

    pub(super) const fn is_syncing(&self) -> bool {
        matches!(self, Self::Loading { .. } | Self::Syncing { .. })
    }

    pub(super) const fn poi_refreshing(&self) -> bool {
        match self {
            Self::Syncing { poi_refreshing, .. } | Self::Ready { poi_refreshing, .. } => {
                *poi_refreshing
            }
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => false,
        }
    }

    pub(super) fn poi_refresh_session(&self) -> Option<Arc<wallet_ops::WalletSession>> {
        match self {
            Self::Syncing { session, .. } | Self::Ready { session, .. } => Some(session.clone()),
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => None,
        }
    }
}

#[derive(Clone)]
pub(super) struct ChainLoadOverrides {
    pub(super) init_block_number: Option<u64>,
    pub(super) sync_to_block: Option<u64>,
    pub(super) use_indexed_wallet_catch_up: bool,
    pub(super) rewind_wallet_cache: bool,
}

pub(super) const fn chain_load_overrides() -> ChainLoadOverrides {
    ChainLoadOverrides {
        init_block_number: None,
        sync_to_block: None,
        use_indexed_wallet_catch_up: true,
        rewind_wallet_cache: false,
    }
}

pub(super) fn wallet_generation_matches(
    selected_wallet_id: Option<&str>,
    active_wallet_generation: u64,
    wallet_id: &str,
    generation: u64,
) -> bool {
    active_wallet_generation == generation && selected_wallet_id == Some(wallet_id)
}

pub(super) fn start_shared_poi_cache_service(
    poi_read_source: &PoiReadSource,
    vault_store: Option<&Arc<DesktopVaultStore>>,
    http: &HttpContext,
    runtime: &Handle,
    chain_ids: &[u64],
) -> Option<Arc<PoiCacheService>> {
    let PoiReadSource::IndexedArtifacts(artifact_config) = poi_read_source else {
        return None;
    };
    let Some(vault_store) = vault_store else {
        tracing::warn!("artifact POI cache service disabled because wallet DB is unavailable");
        return None;
    };

    let service = Arc::new(PoiCacheService::new(
        vault_store.db(),
        artifact_config.clone(),
        Some(http.client.clone()),
    ));
    let startup_service = Arc::clone(&service);
    let chain_ids = chain_ids.to_vec();
    runtime.spawn(async move {
        startup_service.start_chains(chain_ids).await;
    });
    Some(service)
}

pub(super) fn loading_summary(progress: Option<SyncProgressUpdate>) -> String {
    progress.map_or_else(
        || "Preparing wallet sync...".to_string(),
        |progress| format!("{} · {}%", progress.stage.label(), progress.percent()),
    )
}

pub(super) fn sync_status_bar(progress: Option<SyncProgressUpdate>) -> gpui::Div {
    let title = progress.map_or("Preparing wallet sync", |progress| progress.stage.label());
    let percent = progress.map_or(0, SyncProgressUpdate::percent);
    let detail = progress.map_or_else(
        || "Waiting for indexed sync progress...".to_string(),
        progress_detail,
    );
    div()
        .h(px(36.0))
        .flex_none()
        .flex()
        .items_center()
        .gap_3()
        .px(px(12.0))
        .bg(rgb(theme::SURFACE))
        .border_t_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .min_w(px(170.0))
                .text_color(rgb(theme::TEXT))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(
            UiProgress::new()
                .w(px(190.0))
                .h(px(6.0))
                .value(f32::from(percent)),
        )
        .child(
            div()
                .w(px(42.0))
                .text_color(rgb(theme::INFO))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(SharedString::from(format!("{percent}%"))),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(detail)),
        )
}

pub(super) fn progress_detail(progress: SyncProgressUpdate) -> String {
    let current = progress
        .current_block
        .max(progress.start_block)
        .min(progress.target_block);
    format!("Block {current} of {}", progress.target_block)
}

impl WalletRoot {
    pub(super) fn selected_wallet_source(&self) -> WalletSource {
        let Some(selected_wallet_id) = self.selected_wallet_id.as_ref() else {
            return WalletSource::Imported;
        };
        self.wallet_options
            .iter()
            .find(|option| option.wallet_id.as_ref() == selected_wallet_id.as_ref())
            .map_or(WalletSource::Imported, |option| option.source)
    }

    fn selected_wallet_sync_start_policy(&self) -> DesktopWalletSyncStartPolicy {
        DesktopWalletSyncStartPolicy::from(self.selected_wallet_source())
    }

    pub(super) fn selected_chain_wallet_start_block(&self) -> Option<u64> {
        self.chain_states
            .get(&self.selected_chain)
            .and_then(ChainUtxoState::start_block)
    }

    pub(super) fn is_active_wallet_generation(&self, wallet_id: &str, generation: u64) -> bool {
        wallet_generation_matches(
            self.selected_wallet_id.as_deref(),
            self.active_wallet_generation,
            wallet_id,
            generation,
        )
    }

    pub(super) fn reset_wallet_scoped_state(&mut self, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        self.session_store = Arc::new(OnceCell::new());
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.clear_public_wallet_runtime_state();
        self.private_action_form = None;
        self.clear_private_broadcaster_progress_state();
        self.broadcaster_picker = None;
        self.active_wallet_tab = WalletTab::default();
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
    }

    pub(super) fn ensure_chain_load(&mut self, chain_id: u64, cx: &mut Context<'_, Self>) {
        let overrides = chain_load_overrides();
        self.start_chain_load(chain_id, &overrides, false, cx);
    }

    pub(super) fn start_chain_load(
        &mut self,
        chain_id: u64,
        overrides: &ChainLoadOverrides,
        force: bool,
        cx: &mut Context<'_, Self>,
    ) {
        if matches!(
            self.chain_states.get(&chain_id),
            Some(
                ChainUtxoState::Loading { .. }
                    | ChainUtxoState::Syncing { .. }
                    | ChainUtxoState::Ready { .. }
            )
        ) && !force
        {
            return;
        }

        let previous_start_block = self
            .chain_states
            .get(&chain_id)
            .and_then(ChainUtxoState::start_block);

        let previous_session = if force {
            match self.chain_states.remove(&chain_id) {
                Some(
                    ChainUtxoState::Syncing { session, .. } | ChainUtxoState::Ready { session, .. },
                ) => Some(session),
                Some(state) => {
                    self.chain_states.insert(chain_id, state);
                    None
                }
                None => None,
            }
        } else {
            None
        };

        self.chain_states
            .insert(chain_id, ChainUtxoState::Loading { progress: None });
        self.sync_utxo_table(cx);

        let Some(view_session) = self.view_session.clone() else {
            self.chain_states.insert(
                chain_id,
                ChainUtxoState::Error {
                    message: Arc::from("wallet vault is locked"),
                    start_block: previous_start_block,
                },
            );
            self.sync_utxo_table(cx);
            cx.notify();
            return;
        };
        let active_wallet_id: Arc<str> = Arc::from(view_session.wallet_id().to_owned());
        let active_wallet_generation = self.active_wallet_generation;
        let (progress_tx, mut progress_rx) = watch::channel(None);
        let request = ViewWalletChainSessionRequest {
            view_session,
            chain_id,
            effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
            sync_start_policy: self.selected_wallet_sync_start_policy(),
            init_block_number: overrides.init_block_number,
            sync_to_block: overrides.sync_to_block,
            use_indexed_wallet_catch_up: overrides.use_indexed_wallet_catch_up,
            poi_read_source: self.poi_read_source.clone(),
            rewind_wallet_cache: overrides.rewind_wallet_cache,
            progress_tx: Some(progress_tx),
            local_poi_caches: None,
        };
        let db_path = self.options.db_path.clone();
        let http = self.http.clone();
        let poi_cache_service = self.poi_cache_service.clone();
        let session_store = Arc::clone(&self.session_store);
        let vault_db = self.vault_store.as_ref().map(|store| store.db());
        let join = self.runtime.spawn(async move {
            if let Some(previous_session) = previous_session {
                previous_session.stop().await?;
            }
            let mut request = request;
            if let Some(poi_cache_service) = poi_cache_service.as_ref() {
                request.local_poi_caches = Some(poi_cache_service.start_chain(chain_id).await);
            }
            let store = session_store
                .get_or_try_init(|| {
                    let db_path = db_path.clone();
                    let vault_db = vault_db.clone();
                    async move {
                        Ok::<Arc<WalletSessionStore>, eyre::Report>(Arc::new(match vault_db {
                            Some(db) => WalletSessionStore::from_db(db),
                            None => WalletSessionStore::open(db_path)?,
                        }))
                    }
                })
                .await?
                .clone();
            store
                .start_view_wallet_session_immediate(request, None, &http)
                .await
        });

        let progress_wallet_id = Arc::clone(&active_wallet_id);
        cx.spawn(async move |this, cx| {
            loop {
                if progress_rx.changed().await.is_err() {
                    break;
                }
                let progress = *progress_rx.borrow();
                let should_continue = this.update(cx, |root, cx| {
                    if !root.is_active_wallet_generation(
                        progress_wallet_id.as_ref(),
                        active_wallet_generation,
                    ) {
                        return false;
                    }
                    match root.chain_states.get_mut(&chain_id) {
                        Some(
                            ChainUtxoState::Loading { progress: state }
                            | ChainUtxoState::Syncing {
                                progress: state, ..
                            },
                        ) => *state = progress,
                        Some(
                            ChainUtxoState::Idle
                            | ChainUtxoState::Ready { .. }
                            | ChainUtxoState::Error { .. },
                        )
                        | None => return false,
                    }
                    cx.notify();
                    true
                });
                if !matches!(should_continue, Ok(true)) {
                    break;
                }
            }
        })
        .detach();

        let result_wallet_id = active_wallet_id;
        cx.spawn(async move |this, cx| {
            let session = match join.await {
                Ok(Ok(session)) => Arc::new(session),
                Ok(Err(error)) => {
                    let _ = this.update(cx, |root, cx| {
                        if !root.is_active_wallet_generation(
                            result_wallet_id.as_ref(),
                            active_wallet_generation,
                        ) {
                            return;
                        }
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error {
                                message: Arc::from(error.to_string()),
                                start_block: previous_start_block,
                            },
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
                        cx.notify();
                    });
                    return;
                }
                Err(error) => {
                    let _ = this.update(cx, |root, cx| {
                        if !root.is_active_wallet_generation(
                            result_wallet_id.as_ref(),
                            active_wallet_generation,
                        ) {
                            return;
                        }
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error {
                                message: Arc::from(format!("wallet UTXO task failed: {error}")),
                                start_block: previous_start_block,
                            },
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
                        cx.notify();
                    });
                    return;
                }
            };

            let mut snapshots_rx = session.snapshots_rx.clone();
            let mut ready_rx = session.ready_rx.clone();
            let mut poi_refreshing_rx = session.poi_refreshing_rx.clone();
            let initial_snapshot = snapshots_rx.borrow().clone();
            let mut ready = *ready_rx.borrow();
            let initial_poi_refreshing = *poi_refreshing_rx.borrow();

            let _ = this.update(cx, |root, cx| {
                if !root.is_active_wallet_generation(
                    result_wallet_id.as_ref(),
                    active_wallet_generation,
                ) {
                    return;
                }
                let progress = root
                    .chain_states
                    .get(&chain_id)
                    .and_then(ChainUtxoState::progress);
                let state = if ready {
                    ChainUtxoState::Ready {
                        snapshot: initial_snapshot.clone(),
                        session: session.clone(),
                        poi_refreshing: initial_poi_refreshing,
                    }
                } else {
                    ChainUtxoState::Syncing {
                        snapshot: initial_snapshot.clone(),
                        progress,
                        session: session.clone(),
                        poi_refreshing: initial_poi_refreshing,
                    }
                };
                root.chain_states.insert(chain_id, state);
                if root.selected_chain == chain_id {
                    root.sync_utxo_table(cx);
                    root.focus_utxo_table_on_render = should_focus_utxo_table(
                        root.active_activity,
                        root.active_wallet_tab,
                        root.chain_states.get(&chain_id),
                    );
                }
                cx.notify();
            });

            loop {
                tokio::select! {
                    changed = snapshots_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let snapshot = snapshots_rx.borrow().clone();
                        let should_continue = this.update(cx, |root, cx| {
                            if !root.is_active_wallet_generation(
                                result_wallet_id.as_ref(),
                                active_wallet_generation,
                            ) {
                                return false;
                            }
                            {
                                let Some(state) = root.chain_states.get_mut(&chain_id) else {
                                    return false;
                                };
                                match state {
                                    ChainUtxoState::Syncing { snapshot: current, .. }
                                    | ChainUtxoState::Ready { snapshot: current, .. } => {
                                        *current = snapshot.clone();
                                    }
                                    ChainUtxoState::Idle
                                    | ChainUtxoState::Loading { .. }
                                    | ChainUtxoState::Error { .. } => return false,
                                }
                            }
                            root.refresh_open_form_assets_for_snapshot(&snapshot, cx);
                            if root.selected_chain == chain_id {
                                root.sync_utxo_table(cx);
                            }
                            cx.notify();
                            true
                        });
                        if !matches!(should_continue, Ok(true)) {
                            break;
                        }
                    }
                    changed = ready_rx.changed(), if !ready => {
                        if changed.is_err() {
                            ready = true;
                            continue;
                        }
                        ready = *ready_rx.borrow();
                        if !ready {
                            continue;
                        }
                        let should_continue = this.update(cx, |root, cx| {
                            if !root.is_active_wallet_generation(
                                result_wallet_id.as_ref(),
                                active_wallet_generation,
                            ) {
                                return false;
                            }
                            let Some(state) = root.chain_states.remove(&chain_id) else {
                                return false;
                            };
                            match state {
                                ChainUtxoState::Syncing { snapshot, session, poi_refreshing, .. } => {
                                    root.chain_states.insert(
                                        chain_id,
                                        ChainUtxoState::Ready { snapshot, session, poi_refreshing },
                                    );
                                    if root.selected_chain == chain_id {
                                        root.sync_utxo_table(cx);
                                    }
                                    cx.notify();
                                    true
                                }
                                ChainUtxoState::Ready { .. } => {
                                    root.chain_states.insert(chain_id, state);
                                    true
                                }
                                ChainUtxoState::Idle
                                | ChainUtxoState::Loading { .. }
                                | ChainUtxoState::Error { .. } => {
                                    root.chain_states.insert(chain_id, state);
                                    false
                                }
                            }
                        });
                        if !matches!(should_continue, Ok(true)) {
                            break;
                        }
                    }
                    changed = poi_refreshing_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let poi_refreshing = *poi_refreshing_rx.borrow();
                        let should_continue = this.update(cx, |root, cx| {
                            if !root.is_active_wallet_generation(
                                result_wallet_id.as_ref(),
                                active_wallet_generation,
                            ) {
                                return false;
                            }
                            let Some(state) = root.chain_states.get_mut(&chain_id) else {
                                return false;
                            };
                            match state {
                                ChainUtxoState::Syncing { poi_refreshing: state, .. }
                                | ChainUtxoState::Ready { poi_refreshing: state, .. } => {
                                    *state = poi_refreshing;
                                }
                                ChainUtxoState::Idle
                                | ChainUtxoState::Loading { .. }
                                | ChainUtxoState::Error { .. } => return false,
                            }
                            if root.selected_chain == chain_id {
                                root.sync_utxo_table(cx);
                            }
                            cx.notify();
                            true
                        });
                        if !matches!(should_continue, Ok(true)) {
                            break;
                        }
                    }
                }
            }
        })
        .detach();
    }

    pub(super) fn select_chain(
        &mut self,
        chain_id: u64,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.selected_chain == chain_id {
            return;
        }
        window.close_all_dialogs(cx);
        self.selected_chain = chain_id;
        self.sync_broadcaster_monitor_chain_filter(chain_id, window, cx);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.private_action_form = None;
        self.clear_private_broadcaster_progress_state();
        self.broadcaster_picker = None;
        self.local_pending_spent_clear_confirming = false;
        self.clear_public_chain_balance_state();
        self.sync_utxo_table(cx);
        if self.active_wallet_tab == WalletTab::Public {
            self.schedule_public_balance_refresh(cx);
        }
        if should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&chain_id),
        ) {
            self.focus_utxo_table_on_render = true;
        }
        self.ensure_chain_load(chain_id, cx);
        cx.notify();
    }

    pub(super) fn sync_broadcaster_monitor_chain_filter(
        &self,
        chain_id: u64,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.monitor.update(cx, |monitor, cx| {
            monitor.set_chain_filter(chain_id, window, cx);
        });
    }
}
