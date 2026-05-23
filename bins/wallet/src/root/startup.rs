use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use broadcaster_monitor::{EventRx, EventTx, Shared};
use broadcaster_monitor_waku::{
    RelayNetworkConfig, WakuMonitorConfig, spawn_workers_until_shutdown,
};
use eyre::WrapErr;
use gpui::{
    AppContext, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window,
    div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    IconName, Root, Sizable, WindowExt, button::ButtonVariants, progress::Progress as UiProgress,
    spinner::Spinner,
};
use tokio::runtime::Handle;
use tokio::sync::watch;
use ui::controls::{app_button, app_button_base, app_muted_text, app_strong_text};
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::theme;
use wallet_ops::{
    BroadcasterFeePolicy, HttpContext, PoiReadSource, PublicBroadcasterWakuClient,
    TokenAnchorRateCache, WalletNetworkConfig, WalletNetworkMode, WalletNetworkProgress,
    WalletNetworkProgressStage, build_wallet_network_context_with_progress,
    settings::{
        EffectiveChainConfig, EffectiveTokenRegistry, WalletSettings,
        build_effective_chain_configs, build_effective_token_registry, load_wallet_settings,
        save_wallet_settings,
    },
    spawn_token_anchor_refresh_worker,
    vault::DesktopVaultStore,
};

use super::settings::{
    StartupSettingsSummary, WalletSettingsEditor, settings_dialog_dimensions,
    startup_settings_action_state,
};
use super::shell::{WalletAppOptions, render_wallet_hero_screen, render_wallet_window_frame};
use super::{WalletRoot, format_report_chain, rgb_with_alpha};

struct WalletStartupReady {
    http: HttpContext,
    waku: Arc<PublicBroadcasterWakuClient>,
    waku_worker_shutdown: watch::Sender<bool>,
    vault_store: Arc<DesktopVaultStore>,
    chain_ids: Vec<u64>,
    effective_chain_configs: BTreeMap<u64, EffectiveChainConfig>,
    effective_token_registry: EffectiveTokenRegistry,
    public_balance_refresh_interval: Duration,
    public_broadcaster_policy: BroadcasterFeePolicy,
    public_broadcaster_response_timeout: Duration,
    public_broadcaster_republish_interval: Duration,
    default_allow_suspicious_broadcasters: bool,
    poi_read_source: PoiReadSource,
}

enum StartupNetworkContext {
    Build,
    Reuse(Box<HttpContext>),
}

pub(super) struct WalletStartupRoot {
    options: WalletAppOptions,
    runtime: Handle,
    monitor_state: Shared,
    event_tx: EventTx,
    event_rx: EventRx,
    chain_ids: Vec<u64>,
    logs: LogStore,
    progress: WalletNetworkProgress,
    error: Option<Arc<str>>,
    vault_store: Option<Arc<DesktopVaultStore>>,
    wallet_root: Option<Entity<WalletRoot>>,
    startup_generation: u64,
}

impl WalletStartupRoot {
    pub(super) fn new(
        options: WalletAppOptions,
        runtime: Handle,
        monitor_state: Shared,
        event_tx: EventTx,
        event_rx: EventRx,
        chain_ids: &[u64],
        logs: LogStore,
        window: &Window,
        cx: &Context<'_, Self>,
    ) -> Self {
        let chain_ids = chain_ids.to_vec();
        let progress = WalletNetworkProgress::initial();
        let (vault_store, error) = match DesktopVaultStore::open(options.db_path.clone()) {
            Ok(store) => (Some(Arc::new(store)), None),
            Err(error) => (
                None,
                Some(Arc::from(format!(
                    "Failed to open wallet database: {error}"
                ))),
            ),
        };
        let root = Self {
            options,
            runtime,
            monitor_state,
            event_tx: event_tx.clone(),
            event_rx,
            chain_ids,
            logs,
            progress,
            error,
            vault_store: vault_store.clone(),
            wallet_root: None,
            startup_generation: 1,
        };
        if let Some(vault_store) = vault_store {
            let (progress_tx, progress_rx) = watch::channel(root.progress.clone());
            root.spawn_startup_tasks(
                1,
                event_tx,
                StartupNetworkContext::Build,
                progress_tx,
                progress_rx,
                vault_store,
                window,
                cx,
            );
        }
        root
    }

    fn spawn_startup_tasks(
        &self,
        generation: u64,
        event_tx: EventTx,
        network_context: StartupNetworkContext,
        progress_tx: watch::Sender<WalletNetworkProgress>,
        mut progress_rx: watch::Receiver<WalletNetworkProgress>,
        vault_store: Arc<DesktopVaultStore>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let progress = progress_rx.borrow().clone();
                if this
                    .update(cx, |root, cx| {
                        if root.startup_generation != generation {
                            return;
                        }
                        root.progress = progress;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        let options = self.options.clone();
        let chain_ids = self.chain_ids.clone();
        let monitor_state = self.monitor_state.clone();
        let startup = self.runtime.spawn(async move {
            build_wallet_startup(
                options,
                chain_ids,
                monitor_state,
                event_tx,
                network_context,
                progress_tx,
                vault_store,
            )
            .await
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = startup.await;
            let _ = this.update_in(cx, |root, window, cx| match result {
                _ if root.startup_generation != generation => {
                    tracing::debug!(generation, "ignoring stale wallet startup result");
                }
                Ok(Ok(ready)) => root.finish_startup(ready, window, cx),
                Ok(Err(error)) => root.fail_startup(format_report_chain(&error), cx),
                Err(error) => root.fail_startup(format!("Wallet startup task failed: {error}"), cx),
            });
        })
        .detach();
    }

    fn finish_startup(
        &mut self,
        ready: WalletStartupReady,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let event_rx = self.event_rx.clone();
        let logs = self.logs.clone();
        let monitor_state = self.monitor_state.clone();
        let public_broadcaster_anchor_cache = Arc::new(TokenAnchorRateCache::new());
        let enabled_chain_ids = ready.chain_ids.clone();
        let anchor_effective_chains = ready.effective_chain_configs.clone();
        let anchor_token_registry = ready.effective_token_registry.clone();
        let public_broadcaster_anchor_refresh = spawn_token_anchor_refresh_worker(
            &self.runtime,
            Arc::clone(&public_broadcaster_anchor_cache),
            enabled_chain_ids.clone(),
            anchor_effective_chains,
            anchor_token_registry,
            ready.http.clone(),
        );
        let fee_anchor_lookup: broadcaster_monitor_gpui::FeeAnchorLookup = Arc::new({
            let public_broadcaster_anchor_cache = Arc::clone(&public_broadcaster_anchor_cache);
            move |chain_id, token| public_broadcaster_anchor_cache.cached_rate(chain_id, token)
        });
        let wallet_monitor_event_rx = event_rx.clone();
        let monitor = cx.new(|cx| {
            broadcaster_monitor_gpui::BroadcasterMonitorPane::new(
                self.monitor_state.clone(),
                event_rx,
                &enabled_chain_ids,
                fee_anchor_lookup,
                window,
                cx,
            )
        });
        let logs = cx.new(|cx| LogsPane::new(logs, window, cx));
        let startup_root = cx.entity();
        let root = cx.new(|cx| {
            WalletRoot::new(
                self.options.clone(),
                ready.http,
                ready.waku_worker_shutdown,
                ready.vault_store,
                &enabled_chain_ids,
                ready.effective_chain_configs,
                ready.effective_token_registry,
                ready.public_balance_refresh_interval,
                ready.public_broadcaster_policy,
                ready.public_broadcaster_response_timeout,
                ready.public_broadcaster_republish_interval,
                ready.default_allow_suspicious_broadcasters,
                ready.poi_read_source,
                self.runtime.clone(),
                monitor_state,
                ready.waku,
                public_broadcaster_anchor_cache,
                public_broadcaster_anchor_refresh,
                wallet_monitor_event_rx,
                monitor,
                logs,
                &startup_root,
                window,
                cx,
            )
        });
        self.error = None;
        self.wallet_root = Some(root);
        cx.notify();
    }

    fn fail_startup(&mut self, message: String, cx: &mut Context<'_, Self>) {
        tracing::error!(error = %message, "wallet startup failed");
        self.error = Some(Arc::from(message));
        cx.notify();
    }

    fn startup_vault_store(&mut self) -> Result<Arc<DesktopVaultStore>, String> {
        if let Some(store) = self.vault_store.as_ref() {
            return Ok(Arc::clone(store));
        }
        match DesktopVaultStore::open(self.options.db_path.clone()) {
            Ok(store) => {
                let store = Arc::new(store);
                self.vault_store = Some(Arc::clone(&store));
                Ok(store)
            }
            Err(error) => Err(format!("Failed to open wallet database: {error}")),
        }
    }

    pub(super) fn retry_startup(&mut self, window: &Window, cx: &mut Context<'_, Self>) {
        self.retry_startup_with_network_context(None, window, cx);
    }

    pub(super) fn retry_startup_with_network_context(
        &mut self,
        reusable_http: Option<HttpContext>,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let vault_store = match self.startup_vault_store() {
            Ok(store) => store,
            Err(message) => {
                self.wallet_root = None;
                self.fail_startup(message, cx);
                return;
            }
        };
        self.startup_generation = self.startup_generation.saturating_add(1);
        self.wallet_root = None;
        self.error = None;
        self.progress = WalletNetworkProgress::initial();
        let rev = self.monitor_state.write().clear();
        let _ = self.event_tx.send(rev);
        let (progress_tx, progress_rx) = watch::channel(self.progress.clone());
        let network_context = reusable_http.map_or(StartupNetworkContext::Build, |http| {
            StartupNetworkContext::Reuse(Box::new(http))
        });
        self.spawn_startup_tasks(
            self.startup_generation,
            self.event_tx.clone(),
            network_context,
            progress_tx,
            progress_rx,
            vault_store,
            window,
            cx,
        );
        cx.notify();
    }

    fn reset_settings_and_retry(&mut self, window: &Window, cx: &mut Context<'_, Self>) {
        let store = match self.startup_vault_store() {
            Ok(store) => store,
            Err(message) => {
                self.fail_startup(message, cx);
                return;
            }
        };
        let db = store.db();
        match save_wallet_settings(db.as_ref(), &WalletSettings::default()) {
            Ok(()) => self.retry_startup(window, cx),
            Err(error) => {
                self.fail_startup(format!("Failed to reset wallet settings: {error}"), cx);
            }
        }
    }

    fn open_startup_settings_dialog(&self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let root = cx.entity();
        let (editor, summary) = match self.vault_store.clone() {
            Some(store) => {
                let db = store.db();
                match load_wallet_settings(db.as_ref()) {
                    Ok(settings) => {
                        let runtime = self.runtime.clone();
                        let startup_root = root.clone();
                        (
                            Some(cx.new(move |_| {
                                WalletSettingsEditor::new(
                                    store,
                                    runtime,
                                    settings,
                                    Some(startup_root),
                                    None,
                                )
                            })),
                            None,
                        )
                    }
                    Err(error) => (
                        None,
                        Some(StartupSettingsSummary::error(format!(
                            "Failed to load wallet settings: {error}"
                        ))),
                    ),
                }
            }
            None => (
                None,
                Some(StartupSettingsSummary::error(
                    self.error.as_ref().map_or_else(
                        || "Wallet database is unavailable".to_string(),
                        ToString::to_string,
                    ),
                )),
            ),
        };
        let (dialog_width, content_height, dialog_max_height) = settings_dialog_dimensions(window);
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let reset_root = root.clone();
            let retry_root = root.clone();
            let content = if let Some(editor) = editor.clone() {
                div()
                    .h(content_height)
                    .min_h(px(0.0))
                    .child(editor)
                    .into_any_element()
            } else {
                let summary = summary.clone().unwrap_or_else(|| {
                    StartupSettingsSummary::error("Settings are unavailable".to_string())
                });
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Settings are stored in the selected wallet database and are readable before vault unlock.",
                    ))
                    .child(summary.render())
                    .child(
                        div()
                            .mt(px(8.0))
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                app_button("startup-settings-reset", "Reset settings").on_click(
                                    move |_event, window, cx| {
                                        window.close_all_dialogs(cx);
                                        reset_root.update(cx, |root, cx| {
                                            root.reset_settings_and_retry(window, cx);
                                        });
                                    },
                                ),
                            )
                            .child(
                                app_button("startup-settings-retry", "Retry startup")
                                    .primary()
                                    .on_click(move |_event, window, cx| {
                                        window.close_all_dialogs(cx);
                                        retry_root.update(cx, |root, cx| {
                                            root.retry_startup(window, cx);
                                        });
                                    }),
                            ),
                    )
                    .into_any_element()
            };
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .margin_top(px(16.0))
                .title(app_strong_text("Startup Settings"))
                .child(content)
        });
    }

    fn render_splash(&self, window: &Window, cx: &Context<'_, Self>) -> gpui::AnyElement {
        let root = cx.entity();
        let has_error = self.error.is_some();
        let accent = if has_error {
            theme::DANGER
        } else {
            theme::INFO
        };
        let percent = self.progress.percent.unwrap_or(0);
        let action_state = startup_settings_action_state(has_error);
        let stage = if has_error {
            "Network startup failed"
        } else {
            self.progress.stage.label()
        };
        let detail = self
            .error
            .as_ref()
            .map_or_else(|| self.progress.detail.to_string(), ToString::to_string);
        let card = div()
            .w_full()
            .p(px(24.0))
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(rgb(theme::BORDER_STRONG))
            .bg(rgb_with_alpha(theme::SURFACE_ELEVATED, 0.86))
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .size(px(34.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_full()
                            .bg(rgb(theme::SURFACE))
                            .border_1()
                            .border_color(rgb(accent))
                            .when(!has_error, |this| {
                                this.child(
                                    Spinner::new()
                                        .icon(IconName::LoaderCircle)
                                        .color(rgb(accent).into())
                                        .with_size(px(18.0)),
                                )
                            })
                            .when(has_error, |this| {
                                this.child(img(icons::globe_icon_path()).size(px(17.0)))
                            }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(rgb(accent))
                                    .child(stage),
                            )
                            .child(
                                div()
                                    .text_color(rgb(theme::TEXT_MUTED))
                                    .child(SharedString::from(detail)),
                            ),
                    ),
            )
            .child(
                div()
                    .mt(px(16.0))
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        UiProgress::new()
                            .flex_1()
                            .h(px(7.0))
                            .value(f32::from(percent)),
                    )
                    .child(
                        div()
                            .w(px(42.0))
                            .text_color(rgb(accent))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(format!("{percent}%"))),
                    ),
            )
            .when(action_state.reset || action_state.retry, |this| {
                let retry_root = root.clone();
                let reset_root = root.clone();
                this.child(
                    div()
                        .mt(px(14.0))
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(theme::DANGER))
                        .bg(rgb(theme::SURFACE))
                        .p(px(12.0))
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(
                            "Wallet networking failed closed. No direct network fallback was started.",
                        ),
                )
                .child(
                    div()
                        .mt(px(14.0))
                        .flex()
                        .gap_2()
                        .justify_end()
                        .when(action_state.reset, |this| {
                            this.child(
                                app_button("wallet-startup-reset-settings", "Reset settings")
                                    .on_click(move |_event, window, cx| {
                                        reset_root.update(cx, |root, cx| {
                                            root.reset_settings_and_retry(window, cx);
                                        });
                                    }),
                            )
                        })
                        .when(action_state.retry, |this| {
                            this.child(
                                app_button("wallet-startup-retry", "Retry startup")
                                    .primary()
                                    .on_click(move |_event, window, cx| {
                                        retry_root.update(cx, |root, cx| {
                                            root.retry_startup(window, cx);
                                        });
                                    }),
                            )
                        }),
                )
            })
            .into_any_element();

        render_wallet_hero_screen(window, card)
            .when(action_state.settings, |this| {
                this.child(Self::render_startup_settings_gear(root))
            })
            .into_any_element()
    }

    fn render_startup_settings_gear(root: Entity<Self>) -> gpui::Div {
        div().absolute().right(px(24.0)).bottom(px(24.0)).child(
            app_button_base("wallet-startup-settings")
                .outline()
                .h(px(40.0))
                .w(px(40.0))
                .tooltip("Settings")
                .icon(IconName::Settings)
                .on_click(move |_event, window, cx| {
                    root.update(cx, |root, cx| {
                        root.open_startup_settings_dialog(window, cx);
                    });
                }),
        )
    }
}

impl Render for WalletStartupRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let titlebar_color = self
            .wallet_root
            .as_ref()
            .map_or(theme::BACKGROUND, |root| root.read(cx).titlebar_color());
        let content = if let Some(root) = self.wallet_root.as_ref() {
            div().size_full().child(root.clone()).into_any_element()
        } else {
            self.render_splash(window, cx)
        };

        div()
            .relative()
            .size_full()
            .child(render_wallet_window_frame(content, window, titlebar_color))
            .children(Root::render_dialog_layer(window, cx))
            .children(Root::render_notification_layer(window, cx))
    }
}

async fn build_wallet_startup(
    options: WalletAppOptions,
    _chain_ids: Vec<u64>,
    monitor_state: Shared,
    event_tx: EventTx,
    network_context: StartupNetworkContext,
    progress_tx: watch::Sender<WalletNetworkProgress>,
    vault_store: Arc<DesktopVaultStore>,
) -> eyre::Result<WalletStartupReady> {
    let settings = load_validated_startup_settings(&vault_store)?;
    let proxy_url = settings
        .network
        .proxy_url
        .as_deref()
        .map(reqwest::Url::parse)
        .transpose()
        .wrap_err("parse wallet settings proxy URL")?;
    let chain_ids = settings.chains.enabled_chain_ids();
    let effective_chain_configs = build_effective_chain_configs(&settings)
        .map_err(|error| eyre::eyre!("wallet chain settings are invalid: {error}"))?;
    let effective_token_registry = build_effective_token_registry(&settings)
        .map_err(|error| eyre::eyre!("wallet token settings are invalid: {error}"))?;
    let poi_read_source = settings
        .poi_read_source()
        .map_err(|error| eyre::eyre!("wallet POI settings are invalid: {error}"))?;

    let http = startup_http_context(
        &options,
        &settings,
        proxy_url.as_ref(),
        network_context,
        progress_tx,
    )
    .await?;

    let waku_network = match http.network_mode() {
        WalletNetworkMode::Tor => {
            let tor_client = http
                .arti_client_provider()
                .ok_or_else(|| eyre::eyre!("Tor Waku profile requires an Arti client"))?;
            RelayNetworkConfig::tor_with_client_provider(tor_client, http.client.clone())
        }
        WalletNetworkMode::Proxy => RelayNetworkConfig::proxy(http.client.clone()),
        WalletNetworkMode::Direct => RelayNetworkConfig::direct(),
    };
    let waku_config = WakuMonitorConfig {
        chain_ids: chain_ids.clone(),
        cluster_id: Some(settings.waku.cluster_id),
        shard_id: Some(settings.waku.shard_id),
        doh_endpoint: settings.waku.doh_endpoint.clone(),
        doh_fallback_endpoints: settings.waku.doh_fallback_endpoints.clone(),
        max_peers: Some(settings.waku.max_peers),
        peer_connection_timeout: Some(Duration::from_secs(
            settings.waku.peer_connection_timeout_secs,
        )),
        nwaku_url: settings.waku.nwaku_url.clone(),
        network: waku_network,
    };

    tracing::info!(
        chains = ?chain_ids,
        network_mode = %http.network_mode(),
        network_status = http.network_status_label(),
        network_detail = %http.network_status_detail(),
        "starting wallet"
    );

    let waku = waku_config
        .build_client()
        .wrap_err("construct wallet Waku client")?;
    let worker_waku = Arc::clone(&waku);
    let (waku_worker_shutdown, waku_worker_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(error) = spawn_workers_until_shutdown(
            waku_config,
            worker_waku,
            monitor_state,
            event_tx,
            waku_worker_shutdown_rx,
        )
        .await
        {
            tracing::error!(%error, "wallet broadcaster monitor workers failed to start");
        }
    });

    Ok(WalletStartupReady {
        http,
        waku,
        waku_worker_shutdown,
        vault_store,
        chain_ids,
        effective_chain_configs,
        effective_token_registry,
        public_balance_refresh_interval: Duration::from_secs(
            settings.runtime.public_balance_refresh_interval_secs,
        ),
        public_broadcaster_policy: settings.broadcaster.fee_policy(),
        public_broadcaster_response_timeout: Duration::from_secs(
            settings.broadcaster.response_timeout_secs,
        ),
        public_broadcaster_republish_interval: Duration::from_secs(
            settings.broadcaster.republish_interval_secs,
        ),
        default_allow_suspicious_broadcasters: settings
            .broadcaster
            .allow_suspicious_broadcasters_by_default,
        poi_read_source,
    })
}

async fn startup_http_context(
    options: &WalletAppOptions,
    settings: &WalletSettings,
    proxy_url: Option<&reqwest::Url>,
    network_context: StartupNetworkContext,
    progress_tx: watch::Sender<WalletNetworkProgress>,
) -> eyre::Result<HttpContext> {
    if let StartupNetworkContext::Reuse(http) = network_context {
        if reusable_http_context_matches_settings(&http, settings, proxy_url) {
            tracing::info!(
                network_mode = %http.network_mode(),
                "reusing active wallet network context"
            );
            let _ = progress_tx.send(WalletNetworkProgress::new(
                Some(http.network_mode()),
                WalletNetworkProgressStage::Ready,
                Some(100),
                format!(
                    "Reusing active {} network context",
                    http.network_mode().as_str()
                ),
            ));
            return Ok(*http);
        }
        tracing::warn!(
            active_network_mode = %http.network_mode(),
            settings_network_mode = %settings.wallet_network_mode(),
            "active wallet network context does not match settings; rebuilding"
        );
    }

    build_wallet_network_context_with_progress(
        WalletNetworkConfig {
            network_mode: Some(settings.wallet_network_mode()),
            proxy: proxy_url,
            data_dir: &options.db_path,
        },
        progress_tx,
    )
    .await
}

fn reusable_http_context_matches_settings(
    http: &HttpContext,
    settings: &WalletSettings,
    proxy_url: Option<&reqwest::Url>,
) -> bool {
    if http.network_mode() != settings.wallet_network_mode() {
        return false;
    }
    match settings.wallet_network_mode() {
        WalletNetworkMode::Proxy => http.user_proxy_url.as_ref() == proxy_url,
        WalletNetworkMode::Tor | WalletNetworkMode::Direct => proxy_url.is_none(),
    }
}

pub(super) fn load_validated_startup_settings(
    vault_store: &DesktopVaultStore,
) -> eyre::Result<WalletSettings> {
    let db = vault_store.db();
    let settings = load_wallet_settings(db.as_ref()).wrap_err("load wallet settings")?;
    settings
        .validate()
        .map_err(|error| eyre::eyre!("wallet settings are invalid: {error}"))?;
    Ok(settings)
}
