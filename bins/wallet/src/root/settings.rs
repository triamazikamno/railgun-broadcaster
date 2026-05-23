use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use broadcaster_monitor_waku::{DEFAULT_DOH_ENDPOINT, DEFAULT_TOR_DOH_ENDPOINT};
use gpui::{
    App, AppContext as _, Axis, Context, ElementId, Entity, Focusable, FontWeight,
    InteractiveElement, IntoElement, ParentElement, Pixels, Render, SharedString, Styled,
    Subscription, WeakEntity, Window, div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, IndexPath, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    dialog::DialogButtonProps,
    group_box::GroupBoxVariant,
    input::{Input, InputEvent, InputState, NumberInput, NumberInputEvent, StepAction},
    label::Label,
    select::{Select, SelectDelegate, SelectEvent, SelectItem, SelectState},
    setting::{
        NumberFieldOptions, SettingField, SettingGroup, SettingItem, SettingPage,
        Settings as ComponentSettings,
    },
    slider::{Slider, SliderEvent, SliderState},
    switch::Switch,
};
use railgun_ui::{chain_icon_path, chain_name, short_address};
use tokio::runtime::Handle;
use tokio::sync::watch;
use ui::controls::{app_button, app_button_base, app_muted_text, app_strong_text, app_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY};
use wallet_ops::{
    HttpContext, ProverCacheBuildProgress, WalletDbStore, WalletNetworkConfig, WalletNetworkMode,
    begin_prover_cache_build, build_cache_with_context_and_progress_with_session,
    build_wallet_network_context,
    settings::{
        BuiltInTokenOverride, ChainContractSettings, ChainDeploymentSettings,
        ChainSettingsOverride, CustomTokenSettings, NetworkModeSetting, PoiReadSourceSetting,
        PriceAnchorSettings, TokenKey, TokenPriceAnchorOverride, WakuDirectPeerSetting,
        WalletSettings, build_effective_chain_configs, build_effective_token_registry,
        default_chain_contract_settings, default_chain_quick_sync_endpoint,
        default_chain_rpc_endpoints, default_token_price_anchor_overrides,
        default_waku_direct_peers, default_waku_dns_enr_trees, save_wallet_settings,
        should_show_chain_deployment_metadata_settings,
    },
    vault::DesktopVaultStore,
};

use crate::assets::RailgunActionIcon;

use super::WalletRoot;
use super::startup::WalletStartupRoot;
use super::ui_helpers::{rgb_with_alpha, secondary_dialog_content_width};
use super::wallet_header::ChainSelectItem;

#[derive(Clone)]
pub(super) struct StartupSettingsSummary {
    rows: Vec<(&'static str, String)>,
    error: Option<String>,
}

impl StartupSettingsSummary {
    pub(super) const fn error(message: String) -> Self {
        Self {
            rows: Vec::new(),
            error: Some(message),
        }
    }

    pub(super) fn render(&self) -> gpui::Div {
        if let Some(error) = self.error.as_ref() {
            return div()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::DANGER))
                .bg(rgb(theme::SURFACE))
                .p(px(12.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(SharedString::from(error.clone()));
        }

        self.rows.iter().fold(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER))
                .bg(rgb(theme::SURFACE))
                .p(px(12.0)),
            |body, (label, value)| {
                body.child(
                    div()
                        .flex()
                        .justify_between()
                        .gap_3()
                        .child(app_muted_text(*label))
                        .child(
                            div()
                                .text_color(rgb(theme::TEXT))
                                .child(SharedString::from(value.clone())),
                        ),
                )
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StartupSettingsActionState {
    pub(super) settings: bool,
    pub(super) reset: bool,
    pub(super) retry: bool,
}

pub(super) const fn startup_settings_action_state(has_error: bool) -> StartupSettingsActionState {
    StartupSettingsActionState {
        settings: true,
        reset: has_error,
        retry: has_error,
    }
}

#[derive(Clone)]
struct ProverCacheBuildParams {
    db: Arc<WalletDbStore>,
    db_path: PathBuf,
    network_mode: WalletNetworkMode,
    proxy: Option<reqwest::Url>,
    reusable_http: Option<HttpContext>,
}

struct PreparedProverCacheBuild {
    params: ProverCacheBuildParams,
    reuse_active_network: bool,
}

pub(super) struct WalletSettingsEditor {
    vault_store: Arc<DesktopVaultStore>,
    runtime: Handle,
    saved: WalletSettings,
    draft: WalletSettings,
    field_sync_revision: u64,
    validation_error: Option<Arc<str>>,
    status: Option<Arc<str>>,
    cache_building: bool,
    cache_build_progress: Option<ProverCacheBuildProgress>,
    startup_root: Option<Entity<WalletStartupRoot>>,
    active_root: Option<WeakEntity<WalletRoot>>,
}

struct SyncedStringFieldState {
    input: Entity<InputState>,
    synced_revision: u64,
    ignore_next_change: bool,
    _subscription: Subscription,
}

struct SyncedNumberFieldState {
    input: Entity<InputState>,
    synced_revision: u64,
    ignore_next_change: bool,
    _subscriptions: Vec<Subscription>,
}

struct SyncedAnchorRangeSliderState {
    slider: Entity<SliderState>,
    synced_revision: u64,
    _subscription: Subscription,
}

const ANCHOR_BPS_SLIDER_MIN: f32 = 0.0;
const ANCHOR_BPS_SLIDER_MAX: f32 = 100_000.0;
const ANCHOR_BPS_SLIDER_STEP: f32 = 10.0;
const ANCHOR_BPS_SLIDER_MAX_BPS: u64 = 100_000;
const PROXY_WAKU_DISCLAIMER: &str = "Proxy mode disables embedded Waku libp2p transports to prevent proxy bypass. Public broadcaster discovery and Waku relay are unavailable in Proxy mode.";

#[derive(Clone)]
enum SettingsUrlListKind {
    ChainRpc { chain_id: u64, chain_label: String },
    PoiGateway,
    WakuDnsEnrTree,
    WakuDohFallback,
}

impl SettingsUrlListKind {
    const fn empty_text(&self) -> &'static str {
        match self {
            Self::ChainRpc { .. } => "No RPC endpoints configured.",
            Self::PoiGateway => "No artifact gateways configured.",
            Self::WakuDnsEnrTree => "No DNS ENR trees configured. DNS bootstrap is disabled.",
            Self::WakuDohFallback => "No DoH fallback endpoints configured.",
        }
    }

    const fn dialog_help(&self) -> &'static str {
        match self {
            Self::ChainRpc { .. } => "Enter an HTTP(S) RPC endpoint for this chain.",
            Self::PoiGateway => "Enter an HTTP(S) gateway URL for indexed POI artifact reads.",
            Self::WakuDnsEnrTree => "Enter an enrtree:// DNS discovery tree URL.",
            Self::WakuDohFallback => "Enter an HTTP(S) DNS-over-HTTPS fallback endpoint.",
        }
    }

    fn add_id(&self) -> SharedString {
        SharedString::from(match self {
            Self::ChainRpc { chain_id, .. } => format!("wallet-settings-rpc-add-{chain_id}"),
            Self::PoiGateway => "wallet-settings-poi-gateway-add".to_string(),
            Self::WakuDnsEnrTree => "wallet-settings-waku-dns-enr-tree-add".to_string(),
            Self::WakuDohFallback => "wallet-settings-waku-doh-fallback-add".to_string(),
        })
    }

    fn row_id(&self, index: usize) -> SharedString {
        SharedString::from(match self {
            Self::ChainRpc { chain_id, .. } => {
                format!("wallet-settings-rpc-row-{chain_id}-{index}")
            }
            Self::PoiGateway => format!("wallet-settings-poi-gateway-row-{index}"),
            Self::WakuDnsEnrTree => format!("wallet-settings-waku-dns-enr-tree-row-{index}"),
            Self::WakuDohFallback => format!("wallet-settings-waku-doh-fallback-row-{index}"),
        })
    }

    fn edit_id(&self, index: usize) -> SharedString {
        SharedString::from(match self {
            Self::ChainRpc { chain_id, .. } => {
                format!("wallet-settings-rpc-edit-{chain_id}-{index}")
            }
            Self::PoiGateway => format!("wallet-settings-poi-gateway-edit-{index}"),
            Self::WakuDnsEnrTree => format!("wallet-settings-waku-dns-enr-tree-edit-{index}"),
            Self::WakuDohFallback => format!("wallet-settings-waku-doh-fallback-edit-{index}"),
        })
    }

    fn remove_id(&self, index: usize) -> SharedString {
        SharedString::from(match self {
            Self::ChainRpc { chain_id, .. } => {
                format!("wallet-settings-rpc-remove-{chain_id}-{index}")
            }
            Self::PoiGateway => format!("wallet-settings-poi-gateway-remove-{index}"),
            Self::WakuDnsEnrTree => format!("wallet-settings-waku-dns-enr-tree-remove-{index}"),
            Self::WakuDohFallback => format!("wallet-settings-waku-doh-fallback-remove-{index}"),
        })
    }

    fn dialog_title(&self, is_edit: bool) -> String {
        match self {
            Self::ChainRpc { chain_label, .. } => {
                if is_edit {
                    format!("Edit {chain_label} RPC")
                } else {
                    format!("Add {chain_label} RPC")
                }
            }
            Self::PoiGateway => {
                if is_edit {
                    "Edit artifact gateway".to_string()
                } else {
                    "Add artifact gateway".to_string()
                }
            }
            Self::WakuDnsEnrTree => {
                if is_edit {
                    "Edit DNS ENR tree".to_string()
                } else {
                    "Add DNS ENR tree".to_string()
                }
            }
            Self::WakuDohFallback => {
                if is_edit {
                    "Edit DoH fallback endpoint".to_string()
                } else {
                    "Add DoH fallback endpoint".to_string()
                }
            }
        }
    }

    fn endpoints(&self, settings: &WalletSettings) -> Vec<String> {
        match self {
            Self::ChainRpc { chain_id, .. } => display_chain_rpc_endpoints(settings, *chain_id),
            Self::PoiGateway => settings.poi.artifact.gateway_urls.clone(),
            Self::WakuDnsEnrTree => display_waku_dns_enr_trees(settings),
            Self::WakuDohFallback => display_waku_doh_fallback_endpoints(settings),
        }
    }

    fn set_endpoint(&self, settings: &mut WalletSettings, index: usize, value: &str) {
        match self {
            Self::ChainRpc { chain_id, .. } => {
                set_chain_rpc_endpoint(settings, *chain_id, index, value);
            }
            Self::PoiGateway => set_poi_gateway_url(settings, index, value),
            Self::WakuDnsEnrTree => set_waku_dns_enr_tree(settings, index, value),
            Self::WakuDohFallback => set_waku_doh_fallback_endpoint(settings, index, value),
        }
    }

    fn add_endpoint(&self, settings: &mut WalletSettings, value: &str) {
        match self {
            Self::ChainRpc { chain_id, .. } => add_chain_rpc_endpoint(settings, *chain_id, value),
            Self::PoiGateway => add_poi_gateway_url(settings, value),
            Self::WakuDnsEnrTree => add_waku_dns_enr_tree(settings, value),
            Self::WakuDohFallback => add_waku_doh_fallback_endpoint(settings, value),
        }
    }

    fn remove_endpoint(&self, settings: &mut WalletSettings, index: usize) {
        match self {
            Self::ChainRpc { chain_id, .. } => {
                remove_chain_rpc_endpoint(settings, *chain_id, index);
            }
            Self::PoiGateway => remove_poi_gateway_url(settings, index),
            Self::WakuDnsEnrTree => remove_waku_dns_enr_tree(settings, index),
            Self::WakuDohFallback => remove_waku_doh_fallback_endpoint(settings, index),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DisplayTokenEntry {
    pub(super) chain_id: u64,
    pub(super) token_address: String,
    pub(super) symbol: String,
    pub(super) decimals: u8,
    pub(super) icon_path: Option<String>,
    pub(super) built_in: bool,
    custom_index: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DisplayPriceAnchorEntry {
    pub(super) key: TokenKey,
    pub(super) price_anchor: PriceAnchorSettings,
    pub(super) token_symbol: Option<String>,
    pub(super) built_in_default: bool,
    override_index: Option<usize>,
}

#[derive(Clone)]
enum TokenEditTarget {
    AddCustom,
    BuiltIn(TokenKey),
    Custom(usize),
}

#[derive(Clone)]
enum PriceAnchorEditTarget {
    Add,
    Edit(DisplayPriceAnchorEntry),
}

#[derive(Clone)]
struct TokenDialogValues {
    chain_id: u64,
    token_address: String,
    symbol: String,
    decimals: u8,
    icon_path: Option<String>,
}

#[derive(Clone)]
struct TokenDialogInputs {
    chain_id: Entity<InputState>,
    token_address: Entity<InputState>,
    symbol: Entity<InputState>,
    decimals: Entity<InputState>,
    icon_path: Entity<InputState>,
}

#[derive(Clone)]
struct WakuDirectPeerDialogInputs {
    peer_id: Entity<InputState>,
    addr: Entity<InputState>,
}

#[derive(Clone)]
struct PriceAnchorDialogInputs {
    chain_id: Entity<SelectState<Vec<ChainSelectItem>>>,
    token_address: Entity<InputState>,
    anchor_type: Entity<SelectState<Vec<PriceAnchorTypeSelectItem>>>,
    selected_anchor_type: Entity<InputState>,
    fixed_rate: Entity<InputState>,
    oracle_chain_id: Entity<SelectState<Vec<ChainSelectItem>>>,
    oracle_address: Entity<InputState>,
    oracle_token_decimals: Entity<InputState>,
    oracle_decimals: Entity<InputState>,
    oracle_is_inversed: Entity<SelectState<Vec<BoolSelectItem>>>,
    product_scale_decimals: Entity<InputState>,
    product_components: Vec<ProductAnchorComponentDialogInputs>,
}

#[derive(Clone)]
struct ProductAnchorComponentDialogInputs {
    anchor_type: Entity<SelectState<Vec<PriceAnchorTypeSelectItem>>>,
    selected_anchor_type: Entity<InputState>,
    fixed_rate: Entity<InputState>,
    oracle_chain_id: Entity<SelectState<Vec<ChainSelectItem>>>,
    oracle_address: Entity<InputState>,
    oracle_token_decimals: Entity<InputState>,
    oracle_decimals: Entity<InputState>,
    oracle_is_inversed: Entity<SelectState<Vec<BoolSelectItem>>>,
}

#[derive(Clone, Copy)]
struct PriceAnchorTypeSelectItem {
    value: &'static str,
    label: &'static str,
}

impl SelectItem for PriceAnchorTypeSelectItem {
    type Value = &'static str;

    fn title(&self) -> SharedString {
        SharedString::from(self.label)
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }
}

#[derive(Clone, Copy)]
struct BoolSelectItem {
    value: bool,
    label: &'static str,
}

impl SelectItem for BoolSelectItem {
    type Value = bool;

    fn title(&self) -> SharedString {
        SharedString::from(self.label)
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }
}

#[derive(Clone, Debug)]
pub(super) struct PriceAnchorDialogValues {
    pub(super) chain_id: u64,
    pub(super) token_address: String,
    pub(super) anchor_type: &'static str,
    pub(super) fixed_rate: String,
    pub(super) oracle_chain_id: u64,
    pub(super) oracle_address: String,
    pub(super) oracle_token_decimals: String,
    pub(super) oracle_decimals: String,
    pub(super) oracle_is_inversed: bool,
    pub(super) product_scale_decimals: String,
    pub(super) product_components: Vec<PriceAnchorComponentDialogValues>,
}

#[derive(Clone, Debug)]
pub(super) struct PriceAnchorComponentDialogValues {
    pub(super) anchor_type: &'static str,
    pub(super) fixed_rate: String,
    pub(super) oracle_chain_id: u64,
    pub(super) oracle_address: String,
    pub(super) oracle_token_decimals: String,
    pub(super) oracle_decimals: String,
    pub(super) oracle_is_inversed: bool,
}

impl WalletSettingsEditor {
    pub(super) fn new(
        vault_store: Arc<DesktopVaultStore>,
        runtime: Handle,
        settings: WalletSettings,
        startup_root: Option<Entity<WalletStartupRoot>>,
        active_root: Option<WeakEntity<WalletRoot>>,
    ) -> Self {
        let mut editor = Self {
            vault_store,
            runtime,
            saved: settings.clone(),
            draft: settings,
            field_sync_revision: 0,
            validation_error: None,
            status: None,
            cache_building: false,
            cache_build_progress: None,
            startup_root,
            active_root,
        };
        editor.refresh_validation();
        editor
    }

    fn refresh_validation(&mut self) {
        self.validation_error = self
            .draft
            .validate()
            .err()
            .map(|error| Arc::from(error.to_string()));
    }

    fn draft_changed(&mut self, cx: &mut Context<'_, Self>) {
        self.status = None;
        self.refresh_validation();
        cx.notify();
    }

    const fn sync_fields_from_draft(&mut self) {
        self.field_sync_revision = self.field_sync_revision.wrapping_add(1);
    }

    fn programmatic_draft_changed(&mut self, cx: &mut Context<'_, Self>) {
        self.sync_fields_from_draft();
        self.draft_changed(cx);
    }

    fn is_dirty(&self) -> bool {
        self.draft != self.saved
    }

    fn render_status_indicator(&self) -> gpui::Div {
        let (label, color) = if self.validation_error.is_some() {
            ("Invalid", theme::DANGER)
        } else if !self.is_dirty() {
            ("Saved", theme::SUCCESS)
        } else {
            match classify_settings_apply_mode(&self.saved, &self.draft) {
                SettingsApplyMode::NetworkingRestart => ("Restart required", theme::WARNING),
                SettingsApplyMode::NewRequests | SettingsApplyMode::FutureSessions => {
                    ("Unsaved", theme::WARNING)
                }
                SettingsApplyMode::Clean => ("Saved", theme::SUCCESS),
            }
        };

        div()
            .w_full()
            .flex()
            .justify_end()
            .items_center()
            .gap_2()
            .text_size(px(12.0))
            .text_color(rgb(theme::TEXT_MUTED))
            .child(div().size(px(7.0)).rounded_full().bg(rgb(color)))
            .child(label)
    }

    fn render_status_message(&self) -> Option<gpui::Div> {
        let status = self.status.as_ref()?;
        if status.as_ref() == "Settings saved" {
            return None;
        }
        Some(settings_info_banner(status.to_string()))
    }

    fn save_draft(&mut self, cx: &mut Context<'_, Self>) -> bool {
        if classify_settings_apply_mode(&self.saved, &self.draft)
            == SettingsApplyMode::NetworkingRestart
        {
            self.status = Some(Arc::from(
                "Use Apply and restart networking for networking changes",
            ));
            cx.notify();
            return false;
        }
        self.persist_draft(cx)
    }

    fn persist_draft(&mut self, cx: &mut Context<'_, Self>) -> bool {
        self.refresh_validation();
        if self.validation_error.is_some() {
            self.status = Some(Arc::from("Fix validation errors before saving settings"));
            cx.notify();
            return false;
        }
        let apply_mode = classify_settings_apply_mode(&self.saved, &self.draft);
        let db = self.vault_store.db();
        match save_wallet_settings(db.as_ref(), &self.draft) {
            Ok(()) => {
                self.saved = self.draft.clone();
                self.apply_saved_settings_to_active_root(apply_mode, cx);
                self.status = Some(Arc::from("Settings saved"));
                cx.notify();
                true
            }
            Err(error) => {
                self.status = Some(Arc::from(format!("Failed to save settings: {error}")));
                cx.notify();
                false
            }
        }
    }

    fn discard_changes(&mut self, cx: &mut Context<'_, Self>) {
        self.draft = settings_draft_after_discard(&self.saved);
        self.sync_fields_from_draft();
        self.refresh_validation();
        cx.notify();
    }

    fn reset_defaults(&mut self, cx: &mut Context<'_, Self>) {
        self.draft = WalletSettings::default();
        self.sync_fields_from_draft();
        self.refresh_validation();
        cx.notify();
    }

    fn apply_and_restart(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let reusable_http = if settings_restart_reuses_active_network(&self.saved, &self.draft) {
            self.active_root.as_ref().and_then(|root| {
                root.update(cx, |root, _cx| root.reusable_network_context())
                    .ok()
            })
        } else {
            None
        };
        if !self.persist_draft(cx) {
            return;
        }
        window.close_all_dialogs(cx);
        if let Some(root) = self.startup_root.clone() {
            root.update(cx, |root, cx| {
                root.retry_startup_with_network_context(reusable_http, window, cx);
            });
        }
    }

    fn apply_saved_settings_to_active_root(
        &self,
        apply_mode: SettingsApplyMode,
        cx: &mut Context<'_, Self>,
    ) {
        if apply_mode != SettingsApplyMode::NewRequests {
            return;
        }
        let Some(root) = self.active_root.as_ref() else {
            return;
        };
        let settings = self.saved.clone();
        let _ = root.update(cx, |root, cx| {
            root.apply_saved_request_settings(&settings, cx);
        });
    }

    fn prepare_prover_cache_build(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Result<PreparedProverCacheBuild, Arc<str>> {
        if self.cache_building || self.cache_build_progress.is_some() {
            return Err(Arc::from("Prover cache build is already running"));
        }
        self.refresh_validation();
        if self.validation_error.is_some() {
            return Err(Arc::from(
                "Fix validation errors before building prover cache",
            ));
        }
        let proxy = self
            .draft
            .network
            .proxy_url
            .as_deref()
            .map(reqwest::Url::parse)
            .transpose()
            .map_err(|error| Arc::from(format!("Invalid proxy URL: {error}")))?;
        let db = self.vault_store.db();
        let db_path = db.root_dir().to_path_buf();
        let network_mode = self.draft.wallet_network_mode();
        let reuse_active_network = settings_restart_reuses_active_network(&self.saved, &self.draft);
        cx.notify();
        Ok(PreparedProverCacheBuild {
            params: ProverCacheBuildParams {
                db,
                db_path,
                network_mode,
                proxy,
                reusable_http: None,
            },
            reuse_active_network,
        })
    }

    fn build_prover_cache(&mut self, cx: &mut Context<'_, Self>) {
        let prepared = match self.prepare_prover_cache_build(cx) {
            Ok(prepared) => prepared,
            Err(message) => {
                self.status = Some(message);
                cx.notify();
                return;
            }
        };
        let initial_progress = ProverCacheBuildProgress::preparing();
        if let Some(root) = self.active_root.as_ref() {
            let editor = cx.entity();
            let params = prepared.params.clone();
            let reuse_active_network = prepared.reuse_active_network;
            let start = root.update(cx, |root, cx| {
                let mut params = params;
                let reusable_http = if reuse_active_network {
                    Some(root.reusable_network_context())
                } else {
                    None
                };
                params.reusable_http = reusable_http;
                root.start_prover_cache_build_from_settings(editor, params, cx)
            });
            match start {
                Ok(Ok(())) => {
                    self.mark_cache_build_started(initial_progress, cx);
                    return;
                }
                Ok(Err(message)) => {
                    self.status = Some(message);
                    cx.notify();
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "falling back to local prover cache build task");
                }
            }
        }

        self.start_local_prover_cache_build(prepared.params, initial_progress, cx);
    }

    fn mark_cache_build_started(
        &mut self,
        initial_progress: ProverCacheBuildProgress,
        cx: &mut Context<'_, Self>,
    ) {
        self.cache_building = true;
        self.status = Some(Arc::from("Building prover cache..."));
        self.cache_build_progress = Some(initial_progress);
        cx.notify();
    }

    fn start_local_prover_cache_build(
        &mut self,
        params: ProverCacheBuildParams,
        initial_progress: ProverCacheBuildProgress,
        cx: &mut Context<'_, Self>,
    ) {
        let ProverCacheBuildParams {
            db,
            db_path,
            network_mode,
            proxy,
            reusable_http,
        } = params;
        let session = match begin_prover_cache_build(&db_path) {
            Ok(session) => session,
            Err(error) => {
                self.status = Some(Arc::from(error.to_string()));
                cx.notify();
                return;
            }
        };
        self.mark_cache_build_started(initial_progress.clone(), cx);
        let (progress_tx, mut progress_rx) = watch::channel(initial_progress);
        let join = self.runtime.spawn(async move {
            let http = if let Some(http) = reusable_http {
                http
            } else {
                build_wallet_network_context(WalletNetworkConfig {
                    network_mode: Some(network_mode),
                    proxy: proxy.as_ref(),
                    data_dir: &db_path,
                })
                .await?
            };
            build_cache_with_context_and_progress_with_session(
                db,
                &http,
                session,
                move |progress| {
                    let _ = progress_tx.send(progress);
                },
            )
            .await
        });
        cx.spawn(async move |this, cx| {
            tokio::pin!(join);
            let mut progress_open = true;
            loop {
                tokio::select! {
                    result = &mut join => {
                        let _ = this.update(cx, |editor, cx| {
                            editor.cache_building = false;
                            editor.cache_build_progress = None;
                            editor.status = Some(Arc::from(match result {
                                Ok(Ok(report)) => format!(
                                    "Prover cache build complete: {}/{} variants succeeded",
                                    report.succeeded_variants, report.total_variants
                                ),
                                Ok(Err(error)) => format!("Prover cache build failed: {error}"),
                                Err(error) => format!("Prover cache task failed: {error}"),
                            }));
                            cx.notify();
                        });
                        break;
                    }
                    changed = progress_rx.changed(), if progress_open => {
                        if changed.is_err() {
                            progress_open = false;
                            continue;
                        }
                        let progress = progress_rx.borrow().clone();
                        let editor_progress = progress.clone();
                        let _ = this.update(cx, |editor, cx| {
                            editor.cache_build_progress = Some(editor_progress);
                            cx.notify();
                        });
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn shared_string_field(
        field_id: impl Into<String>,
        editor: Entity<Self>,
        get: impl Fn(&WalletSettings) -> String + 'static,
        set: impl Fn(&mut WalletSettings, String) + 'static,
    ) -> SettingField<SharedString> {
        let field_id = field_id.into();
        let get = Rc::new(get);
        let set = Rc::new(set);
        SettingField::render(move |options, window, cx| {
            let (value, revision) = {
                let editor = editor.read(cx);
                (
                    SharedString::from(get(&editor.draft)),
                    editor.field_sync_revision,
                )
            };
            let state = window.use_keyed_state(
                SharedString::from(format!("wallet-settings-string-{field_id}")),
                cx,
                {
                    let value = value.clone();
                    let set = set.clone();
                    let editor = editor.clone();
                    move |window, cx| {
                        let input = cx.new(|cx| InputState::new(window, cx).default_value(value));
                        let subscription = cx.subscribe_in(&input, window, {
                            let set = set.clone();
                            let editor = editor.clone();
                            move |state: &mut SyncedStringFieldState,
                                  input,
                                  event: &InputEvent,
                                  _window,
                                  cx| {
                                if !matches!(event, InputEvent::Change) {
                                    return;
                                }
                                if state.ignore_next_change {
                                    state.ignore_next_change = false;
                                    return;
                                }
                                let value = input.read(cx).value().to_string();
                                editor.update(cx, |editor, cx| {
                                    set(&mut editor.draft, value);
                                    editor.draft_changed(cx);
                                });
                            }
                        });
                        SyncedStringFieldState {
                            input,
                            synced_revision: revision,
                            ignore_next_change: false,
                            _subscription: subscription,
                        }
                    }
                },
            );

            state.update(cx, |state, cx| {
                if state.synced_revision == revision {
                    return;
                }
                state.synced_revision = revision;
                if state.input.read(cx).value().as_ref() == value.as_ref() {
                    return;
                }
                state.ignore_next_change = true;
                state
                    .input
                    .update(cx, |input, cx| input.set_value(value.clone(), window, cx));
            });

            let input = state.read(cx).input.clone();
            settings_text_input(&input)
                .with_size(options.size)
                .map(|this| {
                    if matches!(options.layout, Axis::Horizontal) {
                        this.w_64()
                    } else {
                        this.w_full()
                    }
                })
        })
    }

    fn settings_switch_item(
        row_id: impl Into<String>,
        label: impl Into<String>,
        editor: Entity<Self>,
        _icon_chain_id: Option<u64>,
        get: impl Fn(&WalletSettings) -> bool + 'static,
        set: impl Fn(&mut WalletSettings, bool) + 'static,
    ) -> SettingItem {
        let row_id = row_id.into();
        let label = label.into();
        let get = Rc::new(get);
        let set = Rc::new(set);
        SettingItem::new(
            label,
            SettingField::<SharedString>::render(move |options, _window, cx| {
                let checked = get(&editor.read(cx).draft);
                let set_editor = editor.clone();
                let set_from_switch = set.clone();
                div()
                    .id(SharedString::from(row_id.clone()))
                    .flex()
                    .items_center()
                    .child(
                        Switch::new(SharedString::from(format!("{row_id}-switch")))
                            .checked(checked)
                            .with_size(options.size)
                            .on_click(move |enabled, _window, cx| {
                                set_editor.update(cx, |editor, cx| {
                                    set_from_switch(&mut editor.draft, *enabled);
                                    editor.draft_changed(cx);
                                });
                            }),
                    )
            }),
        )
    }

    fn chain_enabled_item(editor: Entity<Self>, chain_id: u64) -> SettingItem {
        let label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), ToString::to_string);
        Self::settings_switch_item(
            format!("wallet-settings-chain-row-{chain_id}"),
            label,
            editor,
            Some(chain_id),
            move |settings| {
                settings
                    .chains
                    .per_chain
                    .get(&chain_id)
                    .is_none_or(|chain| chain.enabled)
            },
            move |settings, enabled| {
                settings
                    .chains
                    .per_chain
                    .entry(chain_id)
                    .or_default()
                    .enabled = enabled;
            },
        )
    }

    fn broadcaster_anchor_range_item(editor: Entity<Self>) -> SettingItem {
        SettingItem::new(
            "Accepted fee range",
            SettingField::<SharedString>::render(move |_options, window, cx| {
                let (min_bps, max_bps, revision) = {
                    let editor = editor.read(cx);
                    let (min_bps, max_bps) = broadcaster_anchor_bps_range(&editor.draft);
                    (min_bps, max_bps, editor.field_sync_revision)
                };
                let state = window.use_keyed_state(
                    SharedString::from("wallet-settings-broadcaster-anchor-range-slider"),
                    cx,
                    {
                        let editor = editor.clone();
                        move |_window, cx| {
                            let slider = cx.new(|_| {
                                SliderState::new()
                                    .min(ANCHOR_BPS_SLIDER_MIN)
                                    .max(ANCHOR_BPS_SLIDER_MAX)
                                    .step(ANCHOR_BPS_SLIDER_STEP)
                                    .default_value(
                                        anchor_bps_to_slider_value(min_bps)
                                            ..anchor_bps_to_slider_value(max_bps),
                                    )
                            });
                            let subscription = cx.subscribe(&slider, {
                                let editor = editor.clone();
                                move |_state: &mut SyncedAnchorRangeSliderState,
                                      _slider,
                                      event: &SliderEvent,
                                      cx| {
                                    let SliderEvent::Change(value) = event;
                                    editor.update(cx, |editor, cx| {
                                        set_broadcaster_anchor_bps_range(
                                            &mut editor.draft,
                                            value.start(),
                                            value.end(),
                                        );
                                        editor.draft_changed(cx);
                                    });
                                }
                            });
                            SyncedAnchorRangeSliderState {
                                slider,
                                synced_revision: revision,
                                _subscription: subscription,
                            }
                        }
                    },
                );

                state.update(cx, |state, cx| {
                    if state.synced_revision == revision {
                        return;
                    }
                    state.synced_revision = revision;
                    state.slider.update(cx, |slider, cx| {
                        slider.set_value(
                            anchor_bps_to_slider_value(min_bps)
                                ..anchor_bps_to_slider_value(max_bps),
                            window,
                            cx,
                        );
                    });
                });

                let slider = state.read(cx).slider.clone();
                div()
                    .w_full()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div().flex().items_center().justify_end().child(
                            div()
                                .text_size(px(12.0))
                                .font_family(APP_MONO_FONT_FAMILY)
                                .text_color(rgb(theme::TEXT))
                                .child(format_anchor_bps_percent_range(min_bps, max_bps)),
                        ),
                    )
                    .child(Slider::new(&slider).w_full())
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .text_size(px(12.0))
                            .line_height(px(16.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(format_anchor_premium_range(min_bps, max_bps))
                            .child(format!(
                                "Fees outside this range are marked suspicious. {}.",
                                format_anchor_bps_exact_range(min_bps, max_bps)
                            )),
                    )
            }),
        )
        .description("Public broadcaster fees outside this percentage range are marked suspicious.")
        .layout(Axis::Vertical)
    }

    fn number_field(
        field_id: impl Into<String>,
        editor: Entity<Self>,
        options: NumberFieldOptions,
        get: impl Fn(&WalletSettings) -> f64 + 'static,
        set: impl Fn(&mut WalletSettings, f64) + 'static,
    ) -> SettingField<SharedString> {
        let field_id = field_id.into();
        let get = Rc::new(get);
        let set = Rc::new(set);
        SettingField::render(move |render_options, window, cx| {
            let (value, revision) = {
                let editor = editor.read(cx);
                (get(&editor.draft), editor.field_sync_revision)
            };
            let value_text = SharedString::from(value.to_string());
            let state = window.use_keyed_state(
                SharedString::from(format!("wallet-settings-number-{field_id}")),
                cx,
                {
                    let value_text = value_text.clone();
                    let set = set.clone();
                    let editor = editor.clone();
                    let number_options = options.clone();
                    move |window, cx| {
                        let input = cx.new(|cx| {
                            InputState::new(window, cx).default_value(value_text.clone())
                        });
                        let subscriptions = vec![
                            cx.subscribe_in(&input, window, {
                                let number_options = number_options.clone();
                                move |_, input, event: &NumberInputEvent, window, cx| {
                                    let NumberInputEvent::Step(action) = event;
                                    input.update(cx, |input, cx| {
                                        if let Ok(value) = input.value().parse::<f64>() {
                                            let new_value = match action {
                                                StepAction::Increment => {
                                                    value + number_options.step
                                                }
                                                StepAction::Decrement => {
                                                    value - number_options.step
                                                }
                                            }
                                            .clamp(number_options.min, number_options.max);
                                            input.set_value(new_value.to_string(), window, cx);
                                        }
                                    });
                                }
                            }),
                            cx.subscribe_in(&input, window, {
                                let set = set.clone();
                                let editor = editor.clone();
                                let number_options = number_options.clone();
                                move |state: &mut SyncedNumberFieldState,
                                      input,
                                      event: &InputEvent,
                                      window,
                                      cx| {
                                    if !matches!(event, InputEvent::Change) {
                                        return;
                                    }
                                    if state.ignore_next_change {
                                        state.ignore_next_change = false;
                                        return;
                                    }
                                    input.update(cx, |input, cx| {
                                        let Ok(value) = input.value().parse::<f64>() else {
                                            return;
                                        };
                                        let clamped =
                                            value.clamp(number_options.min, number_options.max);
                                        let was_clamped = value < number_options.min
                                            || value > number_options.max;
                                        editor.update(cx, |editor, cx| {
                                            set(&mut editor.draft, clamped);
                                            editor.draft_changed(cx);
                                        });
                                        if was_clamped {
                                            state.ignore_next_change = true;
                                            input.set_value(clamped.to_string(), window, cx);
                                        }
                                    });
                                }
                            }),
                        ];
                        SyncedNumberFieldState {
                            input,
                            synced_revision: revision,
                            ignore_next_change: false,
                            _subscriptions: subscriptions,
                        }
                    }
                },
            );

            state.update(cx, |state, cx| {
                if state.synced_revision == revision {
                    return;
                }
                state.synced_revision = revision;
                if state.input.read(cx).value().as_ref() == value_text.as_ref() {
                    return;
                }
                state.ignore_next_change = true;
                state.input.update(cx, |input, cx| {
                    input.set_value(value_text.clone(), window, cx);
                });
            });

            let input = state.read(cx).input.clone();
            NumberInput::new(&input)
                .with_size(render_options.size)
                .map(|this| {
                    if matches!(render_options.layout, Axis::Horizontal) {
                        this.w_32()
                    } else {
                        this.w_full()
                    }
                })
        })
    }

    fn dropdown_field(
        editor: Entity<Self>,
        options: Vec<(SharedString, SharedString)>,
        get: impl Fn(&WalletSettings) -> SharedString + 'static,
        set: impl Fn(&mut WalletSettings, SharedString) + 'static,
    ) -> SettingField<SharedString> {
        let get_editor = editor.clone();
        let set_editor = editor;
        SettingField::dropdown(
            options,
            move |cx| get(&get_editor.read(cx).draft),
            move |value, cx| {
                set_editor.update(cx, |editor, cx| {
                    set(&mut editor.draft, value);
                    editor.programmatic_draft_changed(cx);
                });
            },
        )
    }

    fn open_settings_url_dialog(
        &self,
        kind: &SettingsUrlListKind,
        index: Option<usize>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let initial_value = index
            .and_then(|index| kind.endpoints(&self.draft).get(index).cloned())
            .unwrap_or_default();
        let input = cx.new(|cx| InputState::new(window, cx).default_value(initial_value));
        let title = kind.dialog_title(index.is_some());
        let help = kind.dialog_help();
        let action_label = SharedString::from(if index.is_some() { "Save" } else { "Add" });
        let dialog_width = (window.viewport_size().width * 0.92).min(px(560.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let editor = cx.entity();
        let dialog_input = input.clone();
        let save_kind = kind.clone();
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let save_editor = editor.clone();
            let save_input = dialog_input.clone();
            let save_kind = save_kind.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(title.clone()))
                .button_props(DialogButtonProps::default().ok_text(action_label.clone()))
                .footer(|ok, cancel, window, cx| vec![cancel(window, cx), ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    let value = save_input.read(cx).value().trim().to_string();
                    let save_kind = save_kind.clone();
                    save_editor.update(cx, |editor, cx| {
                        match index {
                            Some(index) => save_kind.set_endpoint(&mut editor.draft, index, &value),
                            None => save_kind.add_endpoint(&mut editor.draft, &value),
                        }
                        editor.programmatic_draft_changed(cx);
                    });
                    true
                })
                .child(render_settings_url_dialog_content(
                    &dialog_input,
                    content_width,
                    help,
                ))
        });
        let focus_input = input;
        cx.defer_in(window, move |_editor, window, cx| {
            focus_input.read(cx).focus_handle(cx).focus(window);
        });
    }

    fn render_settings_url_list(
        editor: &Entity<Self>,
        kind: &SettingsUrlListKind,
        endpoints: Vec<String>,
    ) -> gpui::Div {
        let add_editor = editor.clone();
        let add_kind = kind.clone();
        let body =
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().flex().justify_end().child(
                    settings_icon_button(kind.add_id(), IconName::Plus, "Add").on_click(
                        move |_event, window, cx| {
                            let kind = add_kind.clone();
                            add_editor.update(cx, |editor, cx| {
                                editor.open_settings_url_dialog(&kind, None, window, cx);
                            });
                        },
                    ),
                ));

        let endpoint_count = endpoints.len();
        let mut list = div().w_full().flex().flex_col();
        if endpoints.is_empty() {
            list = list.child(app_muted_text(kind.empty_text()).py(px(8.0)));
        }
        for (index, endpoint) in endpoints.into_iter().enumerate() {
            let edit_editor = editor.clone();
            let edit_kind = kind.clone();
            let remove_editor = editor.clone();
            let remove_kind = kind.clone();
            list = list.child(
                div()
                    .id(kind.row_id(index))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px(px(2.0))
                    .py(px(9.0))
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                    .when(index + 1 < endpoint_count, |this| {
                        this.border_b_1()
                            .border_color(rgb_with_alpha(theme::BORDER_SUBTLE, 0.45))
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .truncate()
                            .font_family(APP_MONO_FONT_FAMILY)
                            .text_size(px(13.0))
                            .line_height(px(18.0))
                            .text_color(rgb(theme::TEXT))
                            .child(SharedString::from(endpoint)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_1()
                            .child(
                                settings_icon_button(
                                    kind.edit_id(index),
                                    Icon::new(RailgunActionIcon::Pencil),
                                    "Edit",
                                )
                                .on_click(
                                    move |_event, window, cx| {
                                        let kind = edit_kind.clone();
                                        edit_editor.update(cx, |editor, cx| {
                                            editor.open_settings_url_dialog(
                                                &kind,
                                                Some(index),
                                                window,
                                                cx,
                                            );
                                        });
                                    },
                                ),
                            )
                            .child(
                                settings_danger_icon_button(
                                    kind.remove_id(index),
                                    Icon::new(RailgunActionIcon::Trash2),
                                    "Remove",
                                )
                                .on_click(
                                    move |_event, _window, cx| {
                                        let kind = remove_kind.clone();
                                        remove_editor.update(cx, |editor, cx| {
                                            kind.remove_endpoint(&mut editor.draft, index);
                                            editor.programmatic_draft_changed(cx);
                                        });
                                    },
                                ),
                            ),
                    ),
            );
        }
        body.child(list)
    }

    fn settings_url_list_item(
        title: impl Into<SharedString>,
        editor: Entity<Self>,
        kind: SettingsUrlListKind,
        endpoints: Vec<String>,
    ) -> SettingItem {
        SettingItem::new(
            title,
            SettingField::<SharedString>::render(move |_options, _window, _cx| {
                Self::render_settings_url_list(&editor, &kind, endpoints.clone())
            }),
        )
        .layout(Axis::Vertical)
    }

    fn open_waku_direct_peer_dialog(
        &self,
        index: Option<usize>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let initial = index
            .and_then(|index| display_waku_direct_peers(&self.draft).get(index).cloned())
            .unwrap_or_default();
        let inputs = WakuDirectPeerDialogInputs {
            peer_id: cx.new(|cx| InputState::new(window, cx).default_value(initial.peer_id)),
            addr: cx.new(|cx| InputState::new(window, cx).default_value(initial.addr)),
        };
        let title = if index.is_some() {
            "Edit direct peer"
        } else {
            "Add direct peer"
        };
        let action_label = SharedString::from(if index.is_some() { "Save" } else { "Add" });
        let dialog_width = (window.viewport_size().width * 0.92).min(px(620.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let editor = cx.entity();
        let dialog_inputs = inputs.clone();
        let save_inputs = inputs.clone();
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let save_editor = editor.clone();
            let save_inputs = save_inputs.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(title))
                .button_props(DialogButtonProps::default().ok_text(action_label.clone()))
                .footer(|ok, cancel, window, cx| vec![cancel(window, cx), ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    let peer = waku_direct_peer_from_dialog_inputs(&save_inputs, cx);
                    save_editor.update(cx, |editor, cx| {
                        match index {
                            Some(index) => set_waku_direct_peer(&mut editor.draft, index, peer),
                            None => add_waku_direct_peer(&mut editor.draft, peer),
                        }
                        editor.programmatic_draft_changed(cx);
                    });
                    true
                })
                .child(render_waku_direct_peer_dialog_content(
                    &dialog_inputs,
                    content_width,
                ))
        });
        let focus_input = inputs.peer_id;
        cx.defer_in(window, move |_editor, window, cx| {
            focus_input.read(cx).focus_handle(cx).focus(window);
        });
    }

    fn render_waku_direct_peer_list(
        editor: &Entity<Self>,
        peers: Vec<WakuDirectPeerSetting>,
    ) -> gpui::Div {
        let add_editor = editor.clone();
        let body = div().w_full().flex().flex_col().gap_2().child(
            div().flex().justify_end().child(
                settings_icon_button(
                    "wallet-settings-waku-direct-peer-add",
                    IconName::Plus,
                    "Add",
                )
                .on_click(move |_event, window, cx| {
                    add_editor.update(cx, |editor, cx| {
                        editor.open_waku_direct_peer_dialog(None, window, cx);
                    });
                }),
            ),
        );

        let peer_count = peers.len();
        let mut list = div().w_full().flex().flex_col();
        if peers.is_empty() {
            list = list.child(app_muted_text("No additional direct peers configured.").py(px(8.0)));
        }
        for (index, peer) in peers.into_iter().enumerate() {
            let edit_editor = editor.clone();
            let remove_editor = editor.clone();
            list = list.child(
                div()
                    .id(SharedString::from(format!(
                        "wallet-settings-waku-direct-peer-row-{index}"
                    )))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px(px(2.0))
                    .py(px(9.0))
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                    .when(index + 1 < peer_count, |this| {
                        this.border_b_1()
                            .border_color(rgb_with_alpha(theme::BORDER_SUBTLE, 0.45))
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .truncate()
                                    .font_family(APP_MONO_FONT_FAMILY)
                                    .text_size(px(13.0))
                                    .line_height(px(18.0))
                                    .text_color(rgb(theme::TEXT))
                                    .child(SharedString::from(peer.peer_id)),
                            )
                            .child(
                                div()
                                    .truncate()
                                    .font_family(APP_MONO_FONT_FAMILY)
                                    .text_size(px(12.0))
                                    .line_height(px(16.0))
                                    .text_color(rgb(theme::TEXT_SUBTLE))
                                    .child(SharedString::from(peer.addr)),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_1()
                            .child(
                                settings_icon_button(
                                    SharedString::from(format!(
                                        "wallet-settings-waku-direct-peer-edit-{index}"
                                    )),
                                    Icon::new(RailgunActionIcon::Pencil),
                                    "Edit",
                                )
                                .on_click(
                                    move |_event, window, cx| {
                                        edit_editor.update(cx, |editor, cx| {
                                            editor.open_waku_direct_peer_dialog(
                                                Some(index),
                                                window,
                                                cx,
                                            );
                                        });
                                    },
                                ),
                            )
                            .child(
                                settings_danger_icon_button(
                                    SharedString::from(format!(
                                        "wallet-settings-waku-direct-peer-remove-{index}"
                                    )),
                                    Icon::new(RailgunActionIcon::Trash2),
                                    "Remove",
                                )
                                .on_click(
                                    move |_event, _window, cx| {
                                        remove_editor.update(cx, |editor, cx| {
                                            remove_waku_direct_peer(&mut editor.draft, index);
                                            editor.programmatic_draft_changed(cx);
                                        });
                                    },
                                ),
                            ),
                    ),
            );
        }
        body.child(list)
    }

    fn waku_direct_peer_list_item(
        editor: Entity<Self>,
        peers: Vec<WakuDirectPeerSetting>,
    ) -> SettingItem {
        SettingItem::new(
            "Direct peers",
            SettingField::<SharedString>::render(move |_options, _window, _cx| {
                Self::render_waku_direct_peer_list(&editor, peers.clone())
            }),
        )
        .description(
            "Additional libp2p peers to dial directly. Each row is one peer ID and one multiaddr.",
        )
        .layout(Axis::Vertical)
    }

    fn open_token_dialog(
        &self,
        target: &TokenEditTarget,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let values = token_dialog_values(&self.draft, target);
        let inputs = TokenDialogInputs {
            chain_id: cx
                .new(|cx| InputState::new(window, cx).default_value(values.chain_id.to_string())),
            token_address: cx
                .new(|cx| InputState::new(window, cx).default_value(values.token_address.clone())),
            symbol: cx.new(|cx| InputState::new(window, cx).default_value(values.symbol.clone())),
            decimals: cx
                .new(|cx| InputState::new(window, cx).default_value(values.decimals.to_string())),
            icon_path: cx.new(|cx| {
                InputState::new(window, cx)
                    .default_value(values.icon_path.clone().unwrap_or_default())
            }),
        };
        let title = match &target {
            TokenEditTarget::AddCustom => "Add custom token".to_string(),
            TokenEditTarget::BuiltIn(_) => "Edit built-in token".to_string(),
            TokenEditTarget::Custom(_) => "Edit custom token".to_string(),
        };
        let action_label = SharedString::from(if matches!(target, TokenEditTarget::AddCustom) {
            "Add"
        } else {
            "Save"
        });
        let readonly_identity = matches!(target, TokenEditTarget::BuiltIn(_));
        let dialog_width = (window.viewport_size().width * 0.92).min(px(620.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let editor = cx.entity();
        let save_inputs = inputs.clone();
        let save_target = target.clone();
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let save_editor = editor.clone();
            let save_inputs = save_inputs.clone();
            let render_inputs = save_inputs.clone();
            let save_target = save_target.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(title.clone()))
                .button_props(DialogButtonProps::default().ok_text(action_label.clone()))
                .footer(|ok, cancel, window, cx| vec![cancel(window, cx), ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    let values = match token_dialog_values_from_inputs(&save_inputs, cx) {
                        Ok(values) => values,
                        Err(error) => {
                            save_editor.update(cx, |editor, cx| {
                                editor.status = Some(Arc::from(error));
                                cx.notify();
                            });
                            return false;
                        }
                    };
                    let target = save_target.clone();
                    save_editor.update(cx, |editor, cx| {
                        apply_token_dialog_values(&mut editor.draft, &target, values);
                        editor.programmatic_draft_changed(cx);
                    });
                    true
                })
                .child(render_token_dialog_content(
                    &render_inputs,
                    content_width,
                    readonly_identity,
                ))
        });
        let focus_input = if readonly_identity {
            inputs.symbol
        } else {
            inputs.chain_id
        };
        cx.defer_in(window, move |_editor, window, cx| {
            focus_input.read(cx).focus_handle(cx).focus(window);
        });
    }

    fn open_price_anchor_dialog(
        &self,
        target: &PriceAnchorEditTarget,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let values = price_anchor_dialog_values(&self.draft, target);
        let chain_items = price_anchor_chain_select_items();
        let selected_chain_index = chain_select_index(&chain_items, values.chain_id);
        let selected_oracle_chain_index = chain_select_index(&chain_items, values.oracle_chain_id);
        let anchor_type_items = price_anchor_type_select_items();
        let selected_anchor_type_index =
            price_anchor_type_select_index(&anchor_type_items, values.anchor_type);
        let inputs = PriceAnchorDialogInputs {
            chain_id: cx
                .new(|cx| SelectState::new(chain_items.clone(), selected_chain_index, window, cx)),
            token_address: cx
                .new(|cx| InputState::new(window, cx).default_value(values.token_address.clone())),
            anchor_type: cx.new(|cx| {
                SelectState::new(anchor_type_items, selected_anchor_type_index, window, cx)
            }),
            selected_anchor_type: cx
                .new(|cx| InputState::new(window, cx).default_value(values.anchor_type)),
            fixed_rate: cx
                .new(|cx| InputState::new(window, cx).default_value(values.fixed_rate.clone())),
            oracle_chain_id: cx.new(|cx| {
                SelectState::new(chain_items.clone(), selected_oracle_chain_index, window, cx)
            }),
            oracle_address: cx
                .new(|cx| InputState::new(window, cx).default_value(values.oracle_address.clone())),
            oracle_token_decimals: cx.new(|cx| {
                InputState::new(window, cx).default_value(values.oracle_token_decimals.clone())
            }),
            oracle_decimals: cx.new(|cx| {
                InputState::new(window, cx).default_value(values.oracle_decimals.clone())
            }),
            oracle_is_inversed: cx.new(|cx| {
                SelectState::new(
                    bool_select_items(),
                    Some(bool_select_index(values.oracle_is_inversed)),
                    window,
                    cx,
                )
            }),
            product_scale_decimals: cx.new(|cx| {
                InputState::new(window, cx).default_value(values.product_scale_decimals.clone())
            }),
            product_components: values
                .product_components
                .iter()
                .take(2)
                .map(|component| {
                    Self::product_anchor_component_dialog_inputs(
                        component,
                        chain_items.clone(),
                        window,
                        cx,
                    )
                })
                .collect(),
        };
        let selected_anchor_type = inputs.selected_anchor_type.clone();
        Self::subscribe_price_anchor_type_select(
            &inputs.anchor_type,
            selected_anchor_type,
            window,
            cx,
        );
        for component in &inputs.product_components {
            Self::subscribe_price_anchor_type_select(
                &component.anchor_type,
                component.selected_anchor_type.clone(),
                window,
                cx,
            );
        }
        let viewport_size = window.viewport_size();
        let dialog_width = (viewport_size.width * 0.92).min(px(620.0));
        let dialog_max_height = viewport_size.height * 0.84;
        let content_width = secondary_dialog_content_width(dialog_width);
        let editor = cx.entity();
        let save_inputs = inputs.clone();
        let save_target = target.clone();
        let title = match target {
            PriceAnchorEditTarget::Add => "Add price anchor",
            PriceAnchorEditTarget::Edit(_) => "Edit price anchor",
        };
        let action_label = SharedString::from(if matches!(target, PriceAnchorEditTarget::Add) {
            "Add"
        } else {
            "Save"
        });
        window.open_dialog(cx, move |dialog, _window, cx| {
            let save_editor = editor.clone();
            let save_inputs = save_inputs.clone();
            let render_inputs = save_inputs.clone();
            let save_target = save_target.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text(title))
                .button_props(DialogButtonProps::default().ok_text(action_label.clone()))
                .footer(|ok, cancel, window, cx| vec![cancel(window, cx), ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    let anchor = match price_anchor_override_from_dialog_inputs(&save_inputs, cx) {
                        Ok(anchor) => anchor,
                        Err(error) => {
                            save_editor.update(cx, |editor, cx| {
                                editor.status = Some(Arc::from(error));
                                cx.notify();
                            });
                            return false;
                        }
                    };
                    let target = save_target.clone();
                    save_editor.update(cx, |editor, cx| {
                        apply_price_anchor_dialog_values(&mut editor.draft, &target, anchor);
                        editor.programmatic_draft_changed(cx);
                    });
                    true
                })
                .child(render_price_anchor_dialog_content(
                    &render_inputs,
                    content_width,
                    cx,
                ))
        });
        let focus_input = inputs.chain_id;
        cx.defer_in(window, move |_editor, window, cx| {
            focus_input.read(cx).focus_handle(cx).focus(window);
        });
    }

    fn product_anchor_component_dialog_inputs(
        values: &PriceAnchorComponentDialogValues,
        chain_items: Vec<ChainSelectItem>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> ProductAnchorComponentDialogInputs {
        let component_type_items = product_component_type_select_items();
        let selected_component_type_index =
            price_anchor_type_select_index(&component_type_items, values.anchor_type);
        let selected_oracle_chain_index = chain_select_index(&chain_items, values.oracle_chain_id);
        ProductAnchorComponentDialogInputs {
            anchor_type: cx.new(|cx| {
                SelectState::new(
                    component_type_items,
                    selected_component_type_index,
                    window,
                    cx,
                )
            }),
            selected_anchor_type: cx
                .new(|cx| InputState::new(window, cx).default_value(values.anchor_type)),
            fixed_rate: cx
                .new(|cx| InputState::new(window, cx).default_value(values.fixed_rate.clone())),
            oracle_chain_id: cx
                .new(|cx| SelectState::new(chain_items, selected_oracle_chain_index, window, cx)),
            oracle_address: cx
                .new(|cx| InputState::new(window, cx).default_value(values.oracle_address.clone())),
            oracle_token_decimals: cx.new(|cx| {
                InputState::new(window, cx).default_value(values.oracle_token_decimals.clone())
            }),
            oracle_decimals: cx.new(|cx| {
                InputState::new(window, cx).default_value(values.oracle_decimals.clone())
            }),
            oracle_is_inversed: cx.new(|cx| {
                SelectState::new(
                    bool_select_items(),
                    Some(bool_select_index(values.oracle_is_inversed)),
                    window,
                    cx,
                )
            }),
        }
    }

    fn subscribe_price_anchor_type_select(
        select: &Entity<SelectState<Vec<PriceAnchorTypeSelectItem>>>,
        selected_anchor_type: Entity<InputState>,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        cx.subscribe_in(
            select,
            window,
            move |_editor,
                  _select,
                  event: &SelectEvent<Vec<PriceAnchorTypeSelectItem>>,
                  window,
                  cx| {
                if let SelectEvent::Confirm(Some(anchor_type)) = event {
                    selected_anchor_type.update(cx, |input, cx| {
                        input.set_value((*anchor_type).to_string(), window, cx);
                    });
                    cx.notify();
                }
            },
        )
        .detach();
    }

    fn render_token_list(editor: &Entity<Self>, entries: Vec<DisplayTokenEntry>) -> gpui::Div {
        let add_editor = editor.clone();
        let body = div().w_full().flex().flex_col().gap_2().child(
            div().flex().child(
                app_button_base("wallet-settings-token-add")
                    .icon(IconName::Plus)
                    .outline()
                    .child(app_text("Add token"))
                    .on_click(move |_event, window, cx| {
                        add_editor.update(cx, |editor, cx| {
                            editor.open_token_dialog(&TokenEditTarget::AddCustom, window, cx);
                        });
                    }),
            ),
        );
        if entries.is_empty() {
            return body.child(app_muted_text("No tokens configured.").py(px(8.0)));
        }

        let mut list = div().w_full().flex().flex_col();
        let mut current_chain = None;
        let token_count = entries.len();
        for (index, entry) in entries.into_iter().enumerate() {
            if current_chain != Some(entry.chain_id) {
                current_chain = Some(entry.chain_id);
                list = list.child(settings_token_chain_header(entry.chain_id));
            }
            let edit_editor = editor.clone();
            let remove_editor = editor.clone();
            let edit_target = if entry.built_in {
                TokenEditTarget::BuiltIn(TokenKey {
                    chain_id: entry.chain_id,
                    token_address: entry.token_address.clone(),
                })
            } else {
                TokenEditTarget::Custom(entry.custom_index.unwrap_or(index))
            };
            let remove_index = entry.custom_index;
            list = list.child(
                div()
                    .id(SharedString::from(format!(
                        "wallet-settings-token-row-{}-{}",
                        entry.chain_id, entry.token_address
                    )))
                    .flex()
                    .items_center()
                    .gap_3()
                    .px(px(2.0))
                    .py(px(9.0))
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                    .when(index + 1 < token_count, |this| {
                        this.border_b_1()
                            .border_color(rgb_with_alpha(theme::BORDER_SUBTLE, 0.45))
                    })
                    .child(render_token_entry_summary(&entry))
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_1()
                            .child(
                                settings_icon_button(
                                    SharedString::from(format!(
                                        "wallet-settings-token-edit-{index}"
                                    )),
                                    Icon::new(RailgunActionIcon::Pencil),
                                    "Edit",
                                )
                                .on_click(
                                    move |_event, window, cx| {
                                        let target = edit_target.clone();
                                        edit_editor.update(cx, |editor, cx| {
                                            editor.open_token_dialog(&target, window, cx);
                                        });
                                    },
                                ),
                            )
                            .when(!entry.built_in, |this| {
                                this.child(
                                    settings_danger_icon_button(
                                        SharedString::from(format!(
                                            "wallet-settings-token-remove-{index}"
                                        )),
                                        Icon::new(RailgunActionIcon::Trash2),
                                        "Remove",
                                    )
                                    .on_click(
                                        move |_event, _window, cx| {
                                            if let Some(index) = remove_index {
                                                remove_editor.update(cx, |editor, cx| {
                                                    remove_custom_token(&mut editor.draft, index);
                                                    editor.programmatic_draft_changed(cx);
                                                });
                                            }
                                        },
                                    ),
                                )
                            }),
                    ),
            );
        }
        body.child(list)
    }

    fn render_price_anchor_list(
        editor: &Entity<Self>,
        entries: Vec<DisplayPriceAnchorEntry>,
    ) -> gpui::Div {
        let add_editor = editor.clone();
        let body = div().w_full().flex().flex_col().gap_2().child(
            div().flex().child(
                app_button_base("wallet-settings-price-anchor-add")
                    .icon(IconName::Plus)
                    .outline()
                    .child(app_text("Add price anchor"))
                    .on_click(move |_event, window, cx| {
                        add_editor.update(cx, |editor, cx| {
                            editor.open_price_anchor_dialog(
                                &PriceAnchorEditTarget::Add,
                                window,
                                cx,
                            );
                        });
                    }),
            ),
        );

        if entries.is_empty() {
            return body.child(app_muted_text("No price anchors configured.").py(px(8.0)));
        }

        let mut list = div().w_full().flex().flex_col();
        let mut current_chain = None;
        let anchor_count = entries.len();
        for (index, entry) in entries.into_iter().enumerate() {
            if current_chain != Some(entry.key.chain_id) {
                current_chain = Some(entry.key.chain_id);
                list = list.child(settings_token_chain_header(entry.key.chain_id));
            }
            let edit_editor = editor.clone();
            let remove_editor = editor.clone();
            let edit_target = PriceAnchorEditTarget::Edit(entry.clone());
            let remove_entry = entry.clone();
            let can_remove = entry.override_index.is_some();
            list = list.child(
                div()
                    .id(SharedString::from(format!(
                        "wallet-settings-price-anchor-row-{}-{}",
                        entry.key.chain_id, entry.key.token_address
                    )))
                    .flex()
                    .items_center()
                    .gap_3()
                    .px(px(2.0))
                    .py(px(9.0))
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                    .when(index + 1 < anchor_count, |this| {
                        this.border_b_1()
                            .border_color(rgb_with_alpha(theme::BORDER_SUBTLE, 0.45))
                    })
                    .child(render_price_anchor_entry_summary(&entry))
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_1()
                            .child(
                                settings_icon_button(
                                    SharedString::from(format!(
                                        "wallet-settings-price-anchor-edit-{index}"
                                    )),
                                    Icon::new(RailgunActionIcon::Pencil),
                                    "Edit",
                                )
                                .on_click(
                                    move |_event, window, cx| {
                                        let target = edit_target.clone();
                                        edit_editor.update(cx, |editor, cx| {
                                            editor.open_price_anchor_dialog(&target, window, cx);
                                        });
                                    },
                                ),
                            )
                            .when(can_remove, |this| {
                                this.child(
                                    settings_danger_icon_button(
                                        SharedString::from(format!(
                                            "wallet-settings-price-anchor-remove-{index}"
                                        )),
                                        Icon::new(RailgunActionIcon::Trash2),
                                        "Remove",
                                    )
                                    .on_click(
                                        move |_event, _window, cx| {
                                            let entry = remove_entry.clone();
                                            remove_editor.update(cx, |editor, cx| {
                                                remove_display_price_anchor_override(
                                                    &mut editor.draft,
                                                    &entry,
                                                );
                                                editor.programmatic_draft_changed(cx);
                                            });
                                        },
                                    ),
                                )
                            }),
                    ),
            );
        }

        body.child(list)
    }

    fn chain_quick_sync_endpoint_field(
        editor: Entity<Self>,
        chain_id: u64,
    ) -> SettingField<SharedString> {
        Self::shared_string_field(
            format!("chain-{chain_id}-quick-sync-endpoint"),
            editor,
            move |settings| display_chain_quick_sync_endpoint(settings, chain_id),
            move |settings, value| {
                settings
                    .chains
                    .per_chain
                    .entry(chain_id)
                    .or_default()
                    .quick_sync
                    .endpoint = non_empty_setting(&value);
            },
        )
    }

    fn chain_contract_field(
        field_id: impl Into<String>,
        editor: Entity<Self>,
        chain_id: u64,
        get: impl Fn(&ChainContractSettings) -> Option<&String> + 'static,
        set: impl Fn(&mut ChainSettingsOverride, Option<String>) + 'static,
    ) -> SettingField<SharedString> {
        Self::shared_string_field(
            field_id,
            editor,
            move |settings| {
                let contracts = display_chain_contract_settings(settings, chain_id);
                get(&contracts).cloned().unwrap_or_default()
            },
            move |settings, value| {
                let chain = settings.chains.per_chain.entry(chain_id).or_default();
                set(chain, non_empty_setting(&value));
            },
        )
    }

    fn chain_deployment_block_field(
        field_id: impl Into<String>,
        editor: Entity<Self>,
        chain_id: u64,
        get: impl Fn(&ChainDeploymentSettings) -> Option<u64> + 'static,
        set: impl Fn(&mut ChainDeploymentSettings, Option<u64>) + 'static,
    ) -> SettingField<SharedString> {
        Self::shared_string_field(
            field_id,
            editor,
            move |settings| {
                settings
                    .chains
                    .per_chain
                    .get(&chain_id)
                    .and_then(|chain| get(&chain.deployment))
                    .map_or_else(String::new, |value| value.to_string())
            },
            move |settings, value| {
                let chain = settings.chains.per_chain.entry(chain_id).or_default();
                set(&mut chain.deployment, optional_u64_setting(&value));
            },
        )
    }

    fn chain_archive_rpc_field(editor: Entity<Self>, chain_id: u64) -> SettingField<SharedString> {
        Self::shared_string_field(
            format!("chain-{chain_id}-archive-rpc"),
            editor,
            move |settings| {
                settings
                    .chains
                    .per_chain
                    .get(&chain_id)
                    .and_then(|chain| chain.deployment.archive_rpc_url.clone())
                    .unwrap_or_default()
            },
            move |settings, value| {
                settings
                    .chains
                    .per_chain
                    .entry(chain_id)
                    .or_default()
                    .deployment
                    .archive_rpc_url = non_empty_setting(&value);
            },
        )
    }
}

impl WalletRoot {
    fn reusable_network_context(&self) -> HttpContext {
        self.http.clone()
    }

    pub(super) fn start_background_prover_cache_build(&mut self, cx: &mut Context<'_, Self>) {
        if self.is_prover_cache_building() {
            return;
        }
        let Some(editor) = self.settings_editor.clone() else {
            self.vault_error = Some(Arc::from(self.settings_error.as_ref().map_or_else(
                || "Settings are unavailable".to_string(),
                ToString::to_string,
            )));
            cx.notify();
            return;
        };
        let prepared = editor.update(cx, WalletSettingsEditor::prepare_prover_cache_build);
        let params = match prepared {
            Ok(prepared) => {
                let mut params = prepared.params;
                if prepared.reuse_active_network {
                    params.reusable_http = Some(self.reusable_network_context());
                }
                params
            }
            Err(message) => {
                editor.update(cx, |editor, cx| {
                    editor.status = Some(message);
                    cx.notify();
                });
                return;
            }
        };
        match self.start_prover_cache_build_from_settings(editor.clone(), params, cx) {
            Ok(()) => {
                editor.update(cx, |editor, cx| {
                    editor.mark_cache_build_started(ProverCacheBuildProgress::preparing(), cx);
                });
            }
            Err(message) => {
                editor.update(cx, |editor, cx| {
                    editor.status = Some(message);
                    cx.notify();
                });
            }
        }
    }

    fn start_prover_cache_build_from_settings(
        &mut self,
        editor: Entity<WalletSettingsEditor>,
        params: ProverCacheBuildParams,
        cx: &mut Context<'_, Self>,
    ) -> Result<(), Arc<str>> {
        if self.is_prover_cache_building() {
            return Err(Arc::from("Prover cache build is already running"));
        }

        let ProverCacheBuildParams {
            db,
            db_path,
            network_mode,
            proxy,
            reusable_http,
        } = params;
        let session = match begin_prover_cache_build(&db_path) {
            Ok(session) => session,
            Err(error) => return Err(Arc::from(error.to_string())),
        };
        let initial_progress = ProverCacheBuildProgress::preparing();
        self.prover_cache_build_completed = false;
        self.prover_cache_build_progress = Some(initial_progress.clone());
        self.prover_cache_build_popover_open = false;
        let (progress_tx, mut progress_rx) = watch::channel(initial_progress);
        let runtime = self.runtime.clone();
        let join = runtime.spawn(async move {
            let http = if let Some(http) = reusable_http {
                http
            } else {
                build_wallet_network_context(WalletNetworkConfig {
                    network_mode: Some(network_mode),
                    proxy: proxy.as_ref(),
                    data_dir: &db_path,
                })
                .await?
            };
            build_cache_with_context_and_progress_with_session(
                db,
                &http,
                session,
                move |progress| {
                    let _ = progress_tx.send(progress);
                },
            )
            .await
        });

        cx.spawn(async move |this, cx| {
            tokio::pin!(join);
            let mut progress_open = true;
            loop {
                tokio::select! {
                    result = &mut join => {
                        let succeeded = result.as_ref().is_ok_and(Result::is_ok);
                        let _ = this.update(cx, |root, cx| {
                            root.finish_prover_cache_build_progress(cx);
                            if succeeded {
                                root.prover_cache_build_completed = true;
                            }
                        });
                        let _ = editor.update(cx, |editor, cx| {
                            editor.cache_building = false;
                            editor.cache_build_progress = None;
                            editor.status = Some(Arc::from(match result {
                                Ok(Ok(report)) => format!(
                                    "Prover cache build complete: {}/{} variants succeeded",
                                    report.succeeded_variants, report.total_variants
                                ),
                                Ok(Err(error)) => format!("Prover cache build failed: {error}"),
                                Err(error) => format!("Prover cache task failed: {error}"),
                            }));
                            cx.notify();
                        });
                        break;
                    }
                    changed = progress_rx.changed(), if progress_open => {
                        if changed.is_err() {
                            progress_open = false;
                            continue;
                        }
                        let progress = progress_rx.borrow().clone();
                        let editor_progress = progress.clone();
                        let _ = this.update(cx, |root, cx| {
                            root.update_prover_cache_build_progress(progress, cx);
                        });
                        let _ = editor.update(cx, |editor, cx| {
                            editor.cache_build_progress = Some(editor_progress);
                            cx.notify();
                        });
                    }
                }
            }
        })
        .detach();
        cx.notify();
        Ok(())
    }

    fn apply_saved_request_settings(
        &mut self,
        settings: &WalletSettings,
        cx: &mut Context<'_, Self>,
    ) {
        let new_policy = settings.broadcaster.fee_policy();
        let fee_policy_bounds_changed = self.public_broadcaster_policy.min_anchor_bps
            != new_policy.min_anchor_bps
            || self.public_broadcaster_policy.max_anchor_bps != new_policy.max_anchor_bps;

        if let Ok(effective_chain_configs) = build_effective_chain_configs(settings) {
            self.effective_chain_configs = effective_chain_configs;
        }
        self.public_broadcaster_policy = new_policy;
        self.public_broadcaster_response_timeout =
            Duration::from_secs(settings.broadcaster.response_timeout_secs);
        self.public_broadcaster_republish_interval =
            Duration::from_secs(settings.broadcaster.republish_interval_secs);
        self.default_allow_suspicious_broadcasters = settings
            .broadcaster
            .allow_suspicious_broadcasters_by_default;

        if fee_policy_bounds_changed {
            for form in self.send_forms.values_mut() {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
            }
            for form in self.unshield_forms.values_mut() {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
            }
        }

        cx.notify();
    }
}

impl Render for WalletSettingsEditor {
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let editor = cx.entity();
        let network_mode = Self::dropdown_field(
            editor.clone(),
            vec![
                (
                    SharedString::from("tor"),
                    SharedString::from("Built-in Tor"),
                ),
                (SharedString::from("proxy"), SharedString::from("Proxy")),
                (SharedString::from("direct"), SharedString::from("Direct")),
            ],
            |settings| SharedString::from(network_mode_value(settings.network.mode)),
            |settings, value| {
                settings.network.mode = network_mode_from_value(value.as_ref());
                if !should_show_proxy_url_setting(settings.network.mode) {
                    settings.network.proxy_url = None;
                }
            },
        );
        let proxy_url = Self::shared_string_field(
            "network-proxy-url",
            editor.clone(),
            |settings| settings.network.proxy_url.clone().unwrap_or_default(),
            |settings, value| {
                settings.network.proxy_url = non_empty_setting(&value);
            },
        );
        let poi_source = Self::dropdown_field(
            editor.clone(),
            vec![
                (
                    SharedString::from("indexed-artifacts"),
                    SharedString::from("Indexed artifacts"),
                ),
                (
                    SharedString::from("poi-proxy"),
                    SharedString::from("POI proxy"),
                ),
            ],
            |settings| SharedString::from(poi_source_value(settings.poi.read_source)),
            |settings, value| {
                settings.poi.read_source = poi_source_from_value(value.as_ref());
            },
        );
        let poi_publisher = Self::shared_string_field(
            "poi-publisher-public-key",
            editor.clone(),
            |settings| settings.poi.artifact.publisher_pubkey.clone(),
            |settings, value| {
                settings.poi.artifact.publisher_pubkey = value;
            },
        );
        let poi_ipns = Self::shared_string_field(
            "poi-ipns-name",
            editor.clone(),
            |settings| match &settings.poi.artifact.manifest_source {
                wallet_ops::settings::PoiArtifactManifestSourceSetting::IpnsName(name) => {
                    name.clone()
                }
                _ => String::new(),
            },
            |settings, value| {
                settings.poi.artifact.manifest_source =
                    wallet_ops::settings::PoiArtifactManifestSourceSetting::IpnsName(value);
            },
        );
        let poi_reset_editor = editor.clone();
        let waku_number_options = NumberFieldOptions {
            min: 0.0,
            max: f64::from(u32::MAX),
            step: 1.0,
        };
        let positive_number_options = NumberFieldOptions {
            min: 1.0,
            max: 86_400.0,
            step: 1.0,
        };
        let waku_cluster = Self::number_field(
            "waku-cluster-id",
            editor.clone(),
            waku_number_options.clone(),
            |settings| f64::from(settings.waku.cluster_id),
            |settings, value| settings.waku.cluster_id = value as u32,
        );
        let waku_shard = Self::number_field(
            "waku-shard-id",
            editor.clone(),
            waku_number_options,
            |settings| f64::from(settings.waku.shard_id),
            |settings, value| settings.waku.shard_id = value as u32,
        );
        let waku_max_peers = Self::number_field(
            "waku-max-peers",
            editor.clone(),
            positive_number_options.clone(),
            |settings| settings.waku.max_peers as f64,
            |settings, value| settings.waku.max_peers = value as usize,
        );
        let waku_timeout = Self::number_field(
            "waku-peer-timeout-seconds",
            editor.clone(),
            positive_number_options.clone(),
            |settings| settings.waku.peer_connection_timeout_secs as f64,
            |settings, value| settings.waku.peer_connection_timeout_secs = value as u64,
        );
        let broadcaster_timeout = Self::number_field(
            "broadcaster-response-timeout-seconds",
            editor.clone(),
            positive_number_options.clone(),
            |settings| settings.broadcaster.response_timeout_secs as f64,
            |settings, value| settings.broadcaster.response_timeout_secs = value as u64,
        );
        let broadcaster_republish_interval = Self::number_field(
            "broadcaster-republish-interval-seconds",
            editor.clone(),
            positive_number_options,
            |settings| settings.broadcaster.republish_interval_secs as f64,
            |settings, value| settings.broadcaster.republish_interval_secs = value as u64,
        );
        let waku_doh = Self::shared_string_field(
            "waku-doh-endpoint",
            editor.clone(),
            display_waku_doh_endpoint,
            |settings, value| settings.waku.doh_endpoint = non_empty_setting(&value),
        );
        let waku_nwaku = Self::shared_string_field(
            "waku-nwaku-rest-url",
            editor.clone(),
            |settings| settings.waku.nwaku_url.clone().unwrap_or_default(),
            |settings, value| settings.waku.nwaku_url = non_empty_setting(&value),
        );
        let waku_dns_enr_kind = SettingsUrlListKind::WakuDnsEnrTree;
        let waku_dns_enr_trees = waku_dns_enr_kind.endpoints(&self.draft);
        let waku_dns_enr_editor = editor.clone();
        let waku_direct_peers = display_waku_direct_peers(&self.draft);
        let waku_direct_peers_editor = editor.clone();
        let waku_doh_fallback_kind = SettingsUrlListKind::WakuDohFallback;
        let waku_doh_fallback_endpoints = waku_doh_fallback_kind.endpoints(&self.draft);
        let waku_doh_fallback_editor = editor.clone();

        let mut chain_group = settings_group().item(settings_section_header("Enabled chains"));
        for chain_id in railgun_ui::DEFAULT_CHAINS {
            let chain_id = *chain_id;
            chain_group = chain_group.item(Self::chain_enabled_item(editor.clone(), chain_id));
        }

        let poi_gateway_kind = SettingsUrlListKind::PoiGateway;
        let poi_gateway_endpoints = poi_gateway_kind.endpoints(&self.draft);
        let poi_gateway_editor = editor.clone();
        let poi_gateway_group = settings_group()
            .item(settings_section_header("Artifact gateways"))
            .item(Self::settings_url_list_item(
                "Artifact gateway URLs",
                poi_gateway_editor,
                poi_gateway_kind,
                poi_gateway_endpoints,
            ));

        let mut chains_page = SettingPage::new("Chains").group(chain_group);
        for chain_id in railgun_ui::DEFAULT_CHAINS {
            let chain_id = *chain_id;
            let label =
                chain_name(chain_id).map_or_else(|| chain_id.to_string(), ToString::to_string);
            let rpc_kind = SettingsUrlListKind::ChainRpc {
                chain_id,
                chain_label: label.clone(),
            };
            let endpoints = rpc_kind.endpoints(&self.draft);
            let rpc_editor = editor.clone();
            let group = settings_group()
                .item(settings_chain_section_header(
                    chain_id,
                    format!("{label} endpoints"),
                ))
                .item(
                    SettingItem::new(
                        "Quick-sync endpoint",
                        Self::chain_quick_sync_endpoint_field(editor.clone(), chain_id),
                    )
                    .layout(Axis::Vertical),
                )
                .item(Self::settings_url_list_item(
                    format!("{label} RPC endpoints"),
                    rpc_editor,
                    rpc_kind,
                    endpoints,
                ));
            chains_page = chains_page.group(group);
        }

        let mut contracts_page = SettingPage::new("Contracts")
            .description("Advanced chain contract overrides. WARNING: Do not modify unless you know what you are doing. Modifying these can lead to unexpected behavior and loss of funds.");
        for chain_id in railgun_ui::DEFAULT_CHAINS {
            let chain_id = *chain_id;
            let label =
                chain_name(chain_id).map_or_else(|| chain_id.to_string(), ToString::to_string);
            contracts_page = contracts_page.group(
                settings_group()
                    .item(settings_chain_section_header(
                        chain_id,
                        format!("{label} contracts"),
                    ))
                    .item(
                        SettingItem::new(
                            "Railgun contract",
                            Self::chain_contract_field(
                                format!("chain-{chain_id}-railgun-contract"),
                                editor.clone(),
                                chain_id,
                                |contracts| contracts.railgun_contract.as_ref(),
                                |chain, value| chain.contracts.railgun_contract = value,
                            ),
                        )
                        .layout(Axis::Vertical),
                    )
                    .item(
                        SettingItem::new(
                            "Relay adapter",
                            Self::chain_contract_field(
                                format!("chain-{chain_id}-relay-adapter"),
                                editor.clone(),
                                chain_id,
                                |contracts| contracts.relay_adapt_contract.as_ref(),
                                |chain, value| chain.contracts.relay_adapt_contract = value,
                            ),
                        )
                        .layout(Axis::Vertical),
                    )
                    .item(
                        SettingItem::new(
                            "Relay adapter 7702",
                            Self::chain_contract_field(
                                format!("chain-{chain_id}-relay-adapter-7702"),
                                editor.clone(),
                                chain_id,
                                |contracts| contracts.relay_adapt_7702_contract.as_ref(),
                                |chain, value| chain.contracts.relay_adapt_7702_contract = value,
                            ),
                        )
                        .layout(Axis::Vertical),
                    )
                    .item(
                        SettingItem::new(
                            "Wrapped native token",
                            Self::chain_contract_field(
                                format!("chain-{chain_id}-wrapped-native-token"),
                                editor.clone(),
                                chain_id,
                                |contracts| contracts.wrapped_native_token.as_ref(),
                                |chain, value| chain.contracts.wrapped_native_token = value,
                            ),
                        )
                        .layout(Axis::Vertical),
                    )
                    .item(
                        SettingItem::new(
                            "Multicall contract",
                            Self::chain_contract_field(
                                format!("chain-{chain_id}-multicall-contract"),
                                editor.clone(),
                                chain_id,
                                |contracts| contracts.multicall_contract.as_ref(),
                                |chain, value| chain.contracts.multicall_contract = value,
                            ),
                        )
                        .layout(Axis::Vertical),
                    ),
            );
            let show_deployment_metadata =
                self.draft
                    .chains
                    .per_chain
                    .get(&chain_id)
                    .is_some_and(|chain| {
                        should_show_chain_deployment_metadata_settings(chain_id, chain)
                    });
            if show_deployment_metadata {
                let reset_editor = editor.clone();
                contracts_page = contracts_page.group(
                    settings_group()
                        .item(settings_chain_section_header(
                            chain_id,
                            format!("{label} deployment metadata"),
                        ))
                        .item(
                            SettingItem::new(
                                "Deployment block",
                                Self::chain_deployment_block_field(
                                    format!("chain-{chain_id}-deployment-block"),
                                    editor.clone(),
                                    chain_id,
                                    |deployment| deployment.deployment_block,
                                    |deployment, value| deployment.deployment_block = value,
                                ),
                            )
                            .layout(Axis::Vertical),
                        )
                        .item(
                            SettingItem::new(
                                "V2 start block",
                                Self::chain_deployment_block_field(
                                    format!("chain-{chain_id}-v2-start-block"),
                                    editor.clone(),
                                    chain_id,
                                    |deployment| deployment.v2_start_block,
                                    |deployment, value| deployment.v2_start_block = value,
                                ),
                            )
                            .layout(Axis::Vertical),
                        )
                        .item(
                            SettingItem::new(
                                "Legacy shield block",
                                Self::chain_deployment_block_field(
                                    format!("chain-{chain_id}-legacy-shield-block"),
                                    editor.clone(),
                                    chain_id,
                                    |deployment| deployment.legacy_shield_block,
                                    |deployment, value| deployment.legacy_shield_block = value,
                                ),
                            )
                            .layout(Axis::Vertical),
                        )
                        .item(
                            SettingItem::new(
                                "Archive until block",
                                Self::chain_deployment_block_field(
                                    format!("chain-{chain_id}-archive-until-block"),
                                    editor.clone(),
                                    chain_id,
                                    |deployment| deployment.archive_until_block,
                                    |deployment, value| deployment.archive_until_block = value,
                                ),
                            )
                            .layout(Axis::Vertical),
                        )
                        .item(
                            SettingItem::new(
                                "Archive RPC URL",
                                Self::chain_archive_rpc_field(editor.clone(), chain_id),
                            )
                            .layout(Axis::Vertical),
                        )
                        .item(SettingItem::new(
                            "Clear deployment metadata",
                            SettingField::<SharedString>::render(move |_options, _window, _cx| {
                                let reset_editor = reset_editor.clone();
                                app_button(
                                    SharedString::from(format!(
                                        "wallet-settings-deployment-reset-{chain_id}"
                                    )),
                                    "Clear",
                                )
                                .on_click(
                                    move |_event, _window, cx| {
                                        reset_editor.update(cx, |editor, cx| {
                                            editor
                                                .draft
                                                .chains
                                                .per_chain
                                                .entry(chain_id)
                                                .or_default()
                                                .deployment = ChainDeploymentSettings::default();
                                            editor.programmatic_draft_changed(cx);
                                        });
                                    },
                                )
                            }),
                        )),
                );
            }
        }

        let mut token_page = SettingPage::new("Tokens");
        let token_entries = display_token_entries(&self.draft);
        let token_editor = editor.clone();
        token_page = token_page.group(
            settings_group().item(
                SettingItem::new(
                    "Tokens",
                    SettingField::<SharedString>::render(move |_options, _window, _cx| {
                        Self::render_token_list(&token_editor, token_entries.clone())
                    }),
                )
                .description("Known token metadata, built-in token overrides, and custom tokens.")
                .layout(Axis::Vertical),
            ),
        );

        let price_anchor_entries = display_price_anchor_entries(&self.draft);
        let price_anchor_editor = editor.clone();
        token_page = token_page.group(
            settings_group().item(
                SettingItem::new(
                    "Price oracles",
                    SettingField::<SharedString>::render(move |_options, _window, _cx| {
                        Self::render_price_anchor_list(
                            &price_anchor_editor,
                            price_anchor_entries.clone(),
                        )
                    }),
                )
                .description("Token price anchors used to evaluate public broadcaster fees.")
                .layout(Axis::Vertical),
            ),
        );

        let save_editor = editor.clone();
        let discard_editor = editor.clone();
        let reset_editor = editor.clone();
        let cache_editor = editor.clone();
        let apply_editor = editor.clone();
        let mut privacy_group =
            settings_group().item(SettingItem::new("Network mode", network_mode));
        if should_show_proxy_waku_disclaimer(self.draft.network.mode) {
            privacy_group = privacy_group.item(SettingItem::render(|_options, _window, _cx| {
                settings_warning_banner(PROXY_WAKU_DISCLAIMER)
            }));
        }
        if should_show_proxy_url_setting(self.draft.network.mode) {
            privacy_group =
                privacy_group.item(SettingItem::new("Proxy URL", proxy_url).layout(Axis::Vertical));
        }
        let privacy_page = SettingPage::new("Privacy")
            .group(privacy_group)
            .group(
                settings_group()
                    .item(settings_section_header("POI"))
                    .item(SettingItem::new("POI source", poi_source).description("'Indexed artifacts' downloads snapshots containing POI data from IPFS. Because no POI proxy is queried, a POI proxy operator cannot associate your UTXO activity with your IP address or wallet. 'POI proxy'  mode is less private: the proxy receives requests containing blind commitment hashes associated with UTXOs you are receiving or preparing to spend. Use this mode only if you trust the POI proxy operator."))
                    .item(
                        SettingItem::new("Publisher public key", poi_publisher)
                            .layout(Axis::Vertical),
                    )
                    .item(SettingItem::new("IPNS name", poi_ipns).layout(Axis::Vertical))
                    .item(SettingItem::new(
                        "Reset POI artifact defaults",
                        SettingField::<SharedString>::render(move |_options, _window, _cx| {
                            let reset_editor = poi_reset_editor.clone();
                            app_button("wallet-settings-poi-official-preset", "Reset to default")
                                .on_click(move |_event, _window, cx| {
                                    reset_editor.update(cx, |editor, cx| {
                                        editor.draft.poi.reset_artifact_to_official_preset();
                                        editor.programmatic_draft_changed(cx);
                                    });
                                })
                        }),
                    )),
            )
            .group(poi_gateway_group);
        let public_broadcasters_page = SettingPage::new("Public Broadcasters")
            .group(
                settings_group()
                    .item(Self::broadcaster_anchor_range_item(editor.clone()))
                    .item(Self::settings_switch_item(
                        "wallet-settings-broadcaster-allow-suspicious",
                        "Allow suspicious by default",
                        editor,
                        None,
                        |settings| {
                            settings
                                .broadcaster
                                .allow_suspicious_broadcasters_by_default
                        },
                        |settings, value| {
                            settings
                                .broadcaster
                                .allow_suspicious_broadcasters_by_default = value;
                        },
                    ))
                    .item(SettingItem::new(
                        "Response timeout seconds",
                        broadcaster_timeout,
                    ))
                    .item(SettingItem::new(
                        "Republish interval seconds",
                        broadcaster_republish_interval,
                    )),
            )
            .group(
                settings_group()
                    .item(settings_section_header("Waku connectivity"))
                    .item(SettingItem::new("Cluster ID", waku_cluster))
                    .item(SettingItem::new("Shard ID", waku_shard))
                    .item(Self::settings_url_list_item(
                        "DNS ENR trees",
                        waku_dns_enr_editor,
                        waku_dns_enr_kind,
                        waku_dns_enr_trees,
                    ))
                    .item(Self::waku_direct_peer_list_item(
                        waku_direct_peers_editor,
                        waku_direct_peers,
                    ))
                    .item(SettingItem::new("DoH endpoint", waku_doh).layout(Axis::Vertical))
                    .item(Self::settings_url_list_item(
                        "DoH fallback endpoints",
                        waku_doh_fallback_editor,
                        waku_doh_fallback_kind,
                        waku_doh_fallback_endpoints,
                    ))
                    .item(SettingItem::new("Max peers", waku_max_peers))
                    .item(SettingItem::new("Peer timeout seconds", waku_timeout))
                    .item(SettingItem::new("nwaku REST URL", waku_nwaku).layout(Axis::Vertical)),
            );
        div()
            .size_full()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap_3()
            .child(self.render_status_indicator())
            .when_some(self.validation_error.clone(), |this, error| {
                this.child(settings_danger_banner(error.to_string()))
            })
            .when_some(self.render_status_message(), |this, status| {
                this.child(status)
            })
            .child(
                div()
                    .w_full()
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_hidden()
                    .child(
                        ComponentSettings::new("wallet-settings-editor")
                            .sidebar_width(px(190.0))
                            .with_group_variant(GroupBoxVariant::Normal)
                            .page(privacy_page)
                            .page(chains_page)
                            .page(contracts_page)
                            .page(token_page)
                            .page(public_broadcasters_page),
                    ),
            )
            .child(
                div()
                    .flex_none()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .child(
                        app_button("wallet-settings-build-cache", "Build prover cache")
                            .disabled(self.cache_building || self.validation_error.is_some())
                            .on_click(move |_event, _window, cx| {
                                cache_editor.update(cx, |editor, cx| {
                                    editor.build_prover_cache(cx);
                                });
                            }),
                    )
                    .child(
                        app_button("wallet-settings-discard", "Discard")
                            .disabled(!self.is_dirty())
                            .on_click(move |_event, _window, cx| {
                                discard_editor.update(cx, |editor, cx| {
                                    editor.discard_changes(cx);
                                });
                            }),
                    )
                    .child(
                        app_button("wallet-settings-reset", "Reset to defaults").on_click(
                            move |_event, _window, cx| {
                                reset_editor.update(cx, |editor, cx| {
                                    editor.reset_defaults(cx);
                                });
                            },
                        ),
                    )
                    .child(
                        app_button("wallet-settings-save", "Save")
                            .disabled(!settings_save_action_enabled(
                                &self.saved,
                                &self.draft,
                                self.validation_error.is_some(),
                            ))
                            .on_click(move |_event, _window, cx| {
                                save_editor.update(cx, |editor, cx| {
                                    editor.save_draft(cx);
                                });
                            }),
                    )
                    .child(
                        app_button("wallet-settings-apply-restart", "Apply")
                            .primary()
                            .disabled(!settings_restart_action_enabled(
                                &self.saved,
                                &self.draft,
                                self.validation_error.is_some(),
                            ))
                            .on_click(move |_event, window, cx| {
                                apply_editor.update(cx, |editor, cx| {
                                    editor.apply_and_restart(window, cx);
                                });
                            }),
                    ),
            )
    }
}

pub(super) fn settings_dialog_dimensions(window: &Window) -> (Pixels, Pixels, Pixels) {
    let viewport = window.viewport_size();
    let width = (viewport.width * 0.94).min(px(920.0));
    let content_height = (viewport.height - px(120.0)).max(px(180.0)).min(px(620.0));
    let max_height = (viewport.height - px(32.0)).max(px(240.0));
    (width, content_height, max_height)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SettingsApplyMode {
    Clean,
    NetworkingRestart,
    NewRequests,
    FutureSessions,
}

pub(super) fn classify_settings_apply_mode(
    saved: &WalletSettings,
    draft: &WalletSettings,
) -> SettingsApplyMode {
    if draft == saved {
        return SettingsApplyMode::Clean;
    }
    if draft.network != saved.network
        || draft.chains != saved.chains
        || draft.poi != saved.poi
        || draft.waku != saved.waku
    {
        SettingsApplyMode::NetworkingRestart
    } else if draft.broadcaster != saved.broadcaster || draft.gas != saved.gas {
        SettingsApplyMode::NewRequests
    } else {
        SettingsApplyMode::FutureSessions
    }
}

pub(super) fn settings_save_action_enabled(
    saved: &WalletSettings,
    draft: &WalletSettings,
    has_validation_error: bool,
) -> bool {
    !has_validation_error
        && draft != saved
        && classify_settings_apply_mode(saved, draft) != SettingsApplyMode::NetworkingRestart
}

pub(super) fn settings_restart_action_enabled(
    saved: &WalletSettings,
    draft: &WalletSettings,
    has_validation_error: bool,
) -> bool {
    !has_validation_error && draft != saved
}

pub(super) fn settings_restart_reuses_active_network(
    saved: &WalletSettings,
    draft: &WalletSettings,
) -> bool {
    saved.network == draft.network
}

const fn broadcaster_anchor_bps_range(settings: &WalletSettings) -> (u64, u64) {
    let min_bps = settings.broadcaster.min_anchor_bps;
    let max_bps = settings.broadcaster.max_anchor_bps;
    if min_bps <= max_bps {
        (min_bps, max_bps)
    } else {
        (max_bps, min_bps)
    }
}

fn set_broadcaster_anchor_bps_range(settings: &mut WalletSettings, start: f32, end: f32) {
    let min_bps = anchor_slider_value_to_bps(start.min(end));
    let max_bps = anchor_slider_value_to_bps(start.max(end));
    settings.broadcaster.min_anchor_bps = min_bps;
    settings.broadcaster.max_anchor_bps = max_bps;
}

#[allow(clippy::cast_precision_loss)]
fn anchor_bps_to_slider_value(bps: u64) -> f32 {
    bps.min(ANCHOR_BPS_SLIDER_MAX_BPS) as f32
}

#[allow(clippy::cast_sign_loss)]
fn anchor_slider_value_to_bps(value: f32) -> u64 {
    value
        .round()
        .clamp(ANCHOR_BPS_SLIDER_MIN, ANCHOR_BPS_SLIDER_MAX) as u64
}

pub(super) fn format_anchor_bps_percent(bps: u64) -> String {
    let whole = bps / 100;
    let fractional = bps % 100;
    if fractional == 0 {
        format!("{whole}%")
    } else if fractional.is_multiple_of(10) {
        format!("{whole}.{}%", fractional / 10)
    } else {
        format!("{whole}.{fractional:02}%")
    }
}

pub(super) fn format_anchor_bps_percent_range(min_bps: u64, max_bps: u64) -> String {
    format!(
        "{} - {} of price anchor",
        format_anchor_bps_percent(min_bps),
        format_anchor_bps_percent(max_bps)
    )
}

pub(super) fn format_anchor_premium_range(min_bps: u64, max_bps: u64) -> String {
    format!(
        "Allows {} to {} vs anchor",
        format_anchor_premium_bps(min_bps),
        format_anchor_premium_bps(max_bps)
    )
}

fn format_anchor_premium_bps(bps: u64) -> String {
    let premium = i128::from(bps) - 10_000;
    if premium == 0 {
        return "0%".to_string();
    }
    let sign = if premium > 0 { "+" } else { "-" };
    let abs_bps = premium.unsigned_abs();
    format!("{sign}{}", format_anchor_bps_percent(abs_bps as u64))
}

pub(super) fn format_anchor_bps_exact_range(min_bps: u64, max_bps: u64) -> String {
    format!(
        "{} - {} bps",
        format_u64_grouped(min_bps),
        format_u64_grouped(max_bps)
    )
}

fn format_u64_grouped(value: u64) -> String {
    let raw = value.to_string();
    let mut formatted = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, ch) in raw.chars().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(ch);
    }
    formatted
}

pub(super) fn settings_draft_after_discard(saved: &WalletSettings) -> WalletSettings {
    saved.clone()
}

const SETTINGS_GROUP_CONTENT_INDENT: Pixels = px(16.0);
const SETTINGS_GROUP_HEADER_OFFSET: Pixels = px(-16.0);

fn settings_group() -> SettingGroup {
    SettingGroup::new().pl(SETTINGS_GROUP_CONTENT_INDENT)
}

fn settings_section_header(title: impl Into<String>) -> SettingItem {
    let title = title.into();
    SettingItem::render(move |_options, _window, _cx| {
        settings_section_header_element(&title, None, None)
    })
}

fn settings_chain_section_header(chain_id: u64, title: impl Into<String>) -> SettingItem {
    let title = title.into();
    SettingItem::render(move |_options, _window, _cx| {
        settings_section_header_element(&title, None, Some(chain_id))
    })
}

fn settings_section_header_element(
    title: &str,
    description: Option<&str>,
    chain_id: Option<u64>,
) -> gpui::Div {
    let mut title_row = div().flex().items_center().gap_2();
    if let Some(path) = chain_id.and_then(chain_icon_path) {
        title_row = title_row.child(img(path).size(px(16.0)).flex_none());
    }
    title_row = title_row.child(
        div()
            .font_family(APP_MONO_FONT_FAMILY)
            .font_weight(FontWeight::SEMIBOLD)
            .text_size(px(12.0))
            .line_height(px(16.0))
            .text_color(rgb(theme::TEXT_MUTED))
            .child(SharedString::from(title.to_ascii_uppercase())),
    );

    div()
        .w_full()
        .ml(SETTINGS_GROUP_HEADER_OFFSET)
        .flex()
        .flex_col()
        .gap_1()
        .child(title_row)
        .when_some(description, |this, description| {
            this.child(
                div()
                    .text_size(px(12.0))
                    .line_height(px(16.0))
                    .text_color(rgb(theme::TEXT_SUBTLE))
                    .child(SharedString::from(description.to_string())),
            )
        })
}

fn settings_danger_banner(message: impl Into<SharedString>) -> gpui::Div {
    settings_banner(message, theme::DANGER, theme::DANGER_BG)
}

fn settings_info_banner(message: impl Into<SharedString>) -> gpui::Div {
    settings_banner(message, theme::BORDER, theme::SURFACE_HOVER_SUBTLE)
}

fn settings_warning_banner(message: impl Into<SharedString>) -> gpui::Div {
    settings_banner(message, theme::WARNING, theme::WARNING_BG)
}

fn settings_banner(message: impl Into<SharedString>, border: u32, bg: u32) -> gpui::Div {
    div()
        .w_full()
        .flex()
        .items_start()
        .gap_2()
        .rounded_md()
        .border_1()
        .border_color(rgb(border))
        .bg(rgb(bg))
        .px(px(10.0))
        .py(px(7.0))
        .text_size(px(12.0))
        .line_height(px(16.0))
        .text_color(rgb(theme::TEXT))
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .whitespace_normal()
                .child(message.into()),
        )
}

fn settings_text_input(input: &Entity<InputState>) -> Input {
    Input::new(input)
        .w_full()
        .rounded_md()
        .bg(rgb(theme::SETTINGS_INPUT_SURFACE))
        .border_color(rgb_with_alpha(theme::BORDER_SUBTLE, 0.55))
        .px(px(12.0))
        .py(px(9.0))
        .font_family(APP_MONO_FONT_FAMILY)
        .text_size(px(13.0))
        .line_height(px(18.0))
        .text_color(rgb(theme::TEXT))
}

fn render_token_dialog_content(
    inputs: &TokenDialogInputs,
    content_width: Pixels,
    readonly_identity: bool,
) -> gpui::Div {
    div()
        .w(content_width)
        .flex()
        .flex_col()
        .gap_3()
        .child(settings_dialog_field(
            "Chain ID",
            &inputs.chain_id,
            readonly_identity,
        ))
        .child(settings_dialog_field(
            "Token address",
            &inputs.token_address,
            readonly_identity,
        ))
        .child(settings_dialog_field("Symbol", &inputs.symbol, false))
        .child(settings_dialog_field("Decimals", &inputs.decimals, false))
        .child(settings_dialog_field("Icon path", &inputs.icon_path, false))
}

fn render_price_anchor_dialog_content(
    inputs: &PriceAnchorDialogInputs,
    content_width: Pixels,
    cx: &App,
) -> gpui::Div {
    let anchor_type = inputs.selected_anchor_type.read(cx).value().to_string();
    let mut content = div()
        .w(content_width)
        .flex()
        .flex_col()
        .gap_3()
        .child(app_muted_text(
            "Configure the price anchor fields before adding the override.",
        ))
        .child(settings_dialog_select_field(
            "Token chain",
            &inputs.chain_id,
            content_width,
        ))
        .child(settings_dialog_field(
            "Token address",
            &inputs.token_address,
            false,
        ))
        .child(settings_dialog_select_field(
            "Anchor type",
            &inputs.anchor_type,
            content_width,
        ));

    match anchor_type.as_str() {
        "oracle" => {
            content = content
                .child(settings_dialog_select_field(
                    "Oracle chain",
                    &inputs.oracle_chain_id,
                    content_width,
                ))
                .child(settings_dialog_field(
                    "Oracle address",
                    &inputs.oracle_address,
                    false,
                ))
                .child(settings_dialog_field(
                    "Token decimals",
                    &inputs.oracle_token_decimals,
                    false,
                ))
                .child(settings_dialog_field(
                    "Oracle decimals",
                    &inputs.oracle_decimals,
                    false,
                ))
                .child(settings_dialog_select_field(
                    "Inverse oracle",
                    &inputs.oracle_is_inversed,
                    content_width,
                ));
        }
        "product" => {
            content = content.child(settings_dialog_field(
                "Scale decimals",
                &inputs.product_scale_decimals,
                false,
            ));
            for (index, component) in inputs.product_components.iter().enumerate() {
                content = content.child(render_price_anchor_product_component_dialog_content(
                    index,
                    component,
                    content_width,
                    cx,
                ));
            }
        }
        _ => {
            content = content.child(settings_dialog_field(
                "Fixed rate",
                &inputs.fixed_rate,
                false,
            ));
        }
    }

    content
}

fn render_price_anchor_product_component_dialog_content(
    index: usize,
    component: &ProductAnchorComponentDialogInputs,
    content_width: Pixels,
    cx: &App,
) -> gpui::Div {
    let anchor_type = component.selected_anchor_type.read(cx).value().to_string();
    let mut content = div()
        .w_full()
        .flex()
        .flex_col()
        .gap_3()
        .pt(px(4.0))
        .child(settings_dialog_subsection_label(format!(
            "Component {}",
            index + 1
        )))
        .child(settings_dialog_select_field(
            "Component type",
            &component.anchor_type,
            content_width,
        ));

    match anchor_type.as_str() {
        "oracle" => {
            content = content
                .child(settings_dialog_select_field(
                    "Oracle chain",
                    &component.oracle_chain_id,
                    content_width,
                ))
                .child(settings_dialog_field(
                    "Oracle address",
                    &component.oracle_address,
                    false,
                ))
                .child(settings_dialog_field(
                    "Token decimals",
                    &component.oracle_token_decimals,
                    false,
                ))
                .child(settings_dialog_field(
                    "Oracle decimals",
                    &component.oracle_decimals,
                    false,
                ))
                .child(settings_dialog_select_field(
                    "Inverse oracle",
                    &component.oracle_is_inversed,
                    content_width,
                ));
        }
        _ => {
            content = content.child(settings_dialog_field(
                "Fixed rate",
                &component.fixed_rate,
                false,
            ));
        }
    }

    content
}

fn settings_dialog_field(
    label: impl Into<SharedString>,
    input: &Entity<InputState>,
    readonly: bool,
) -> gpui::Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .child(Label::new(label).text_sm())
        .child(settings_text_input(input).disabled(readonly))
}

fn settings_dialog_subsection_label(label: impl Into<SharedString>) -> gpui::Div {
    div()
        .font_family(APP_MONO_FONT_FAMILY)
        .font_weight(FontWeight::SEMIBOLD)
        .text_size(px(12.0))
        .line_height(px(16.0))
        .text_color(rgb(theme::TEXT_MUTED))
        .child(label.into())
}

fn settings_dialog_select_field<D>(
    label: impl Into<SharedString>,
    select: &Entity<SelectState<D>>,
    menu_width: Pixels,
) -> gpui::Div
where
    D: SelectDelegate + 'static,
{
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .child(Label::new(label).text_sm())
        .child(
            div().w_full().h(px(36.0)).child(
                Select::new(select)
                    .small()
                    .w_full()
                    .h(px(36.0))
                    .menu_width(menu_width),
            ),
        )
}

fn render_token_entry_summary(entry: &DisplayTokenEntry) -> gpui::Div {
    let badge = if entry.built_in { "Built-in" } else { "Custom" };
    div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .font_family(APP_MONO_FONT_FAMILY)
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_size(px(13.0))
                        .line_height(px(18.0))
                        .text_color(rgb(theme::TEXT))
                        .child(SharedString::from(entry.symbol.clone())),
                )
                .child(
                    div()
                        .rounded_sm()
                        .bg(rgb_with_alpha(theme::SURFACE_HOVER_SUBTLE, 0.75))
                        .px(px(6.0))
                        .py(px(2.0))
                        .text_size(px(11.0))
                        .line_height(px(14.0))
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(badge),
                )
                .child(
                    div()
                        .text_size(px(12.0))
                        .line_height(px(16.0))
                        .text_color(rgb(theme::TEXT_SUBTLE))
                        .child(format!("{} decimals", entry.decimals)),
                ),
        )
        .child(
            div()
                .truncate()
                .font_family(APP_MONO_FONT_FAMILY)
                .text_size(px(12.0))
                .line_height(px(16.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(SharedString::from(entry.token_address.clone())),
        )
}

fn render_price_anchor_entry_summary(entry: &DisplayPriceAnchorEntry) -> gpui::Div {
    let source = if entry.built_in_default {
        "Built-in default"
    } else {
        "Override"
    };
    let primary_label = price_anchor_token_primary_label(entry);
    let token_address = entry.key.token_address.clone();
    let mut body = div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .font_family(APP_MONO_FONT_FAMILY)
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_size(px(13.0))
                        .line_height(px(18.0))
                        .text_color(rgb(theme::TEXT))
                        .child(SharedString::from(primary_label)),
                )
                .child(settings_badge(price_anchor_type_display(
                    &entry.price_anchor,
                )))
                .child(settings_badge(source)),
        )
        .child(
            div()
                .truncate()
                .text_size(px(12.0))
                .line_height(px(16.0))
                .text_color(rgb(theme::TEXT_SUBTLE))
                .child(SharedString::from(price_anchor_summary(
                    &entry.price_anchor,
                ))),
        );
    if entry.token_symbol.is_some() {
        body = body.child(
            div()
                .truncate()
                .font_family(APP_MONO_FONT_FAMILY)
                .text_size(px(12.0))
                .line_height(px(16.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(SharedString::from(token_address)),
        );
    }
    body
}

fn settings_badge(label: impl Into<SharedString>) -> gpui::Div {
    div()
        .rounded_sm()
        .bg(rgb_with_alpha(theme::SURFACE_HOVER_SUBTLE, 0.75))
        .px(px(6.0))
        .py(px(2.0))
        .text_size(px(11.0))
        .line_height(px(14.0))
        .text_color(rgb(theme::TEXT_MUTED))
        .child(label.into())
}

pub(super) fn price_anchor_token_primary_label(entry: &DisplayPriceAnchorEntry) -> String {
    entry
        .token_symbol
        .clone()
        .unwrap_or_else(|| short_token_address(&entry.key.token_address))
}

fn short_token_address(token_address: &str) -> String {
    token_address.parse::<Address>().map_or_else(
        |_| token_address.to_string(),
        |address| short_address(&address),
    )
}

const fn price_anchor_type_display(anchor: &PriceAnchorSettings) -> &'static str {
    match anchor {
        PriceAnchorSettings::Fixed { .. } => "Fixed",
        PriceAnchorSettings::Oracle { .. } => "Oracle",
        PriceAnchorSettings::Product { .. } => "Product",
    }
}

fn price_anchor_summary(anchor: &PriceAnchorSettings) -> String {
    match anchor {
        PriceAnchorSettings::Fixed { rate } => format!("Fixed rate {rate}"),
        PriceAnchorSettings::Oracle {
            chain_id,
            oracle_address,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => {
            let chain =
                chain_name(*chain_id).map_or_else(|| chain_id.to_string(), ToString::to_string);
            let inverse = if *is_inversed { ", inverse" } else { "" };
            format!(
                "Oracle {} on {chain}, {token_decimals}/{oracle_decimals} decimals{inverse}",
                short_token_address(oracle_address)
            )
        }
        PriceAnchorSettings::Product {
            components,
            scale_decimals,
        } => format!(
            "Product of {} components, scale {scale_decimals} decimals",
            components.len()
        ),
    }
}

fn settings_token_chain_header(chain_id: u64) -> gpui::Div {
    let mut row = div()
        .flex()
        .items_center()
        .gap_2()
        .pt(px(10.0))
        .pb(px(4.0))
        .font_family(APP_MONO_FONT_FAMILY)
        .font_weight(FontWeight::SEMIBOLD)
        .text_size(px(11.0))
        .line_height(px(14.0))
        .text_color(rgb(theme::TEXT_SUBTLE));
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(px(16.0)).flex_none());
    }
    row.child(SharedString::from(
        chain_name(chain_id)
            .map_or_else(|| chain_id.to_string(), ToString::to_string)
            .to_ascii_uppercase(),
    ))
}

fn settings_icon_button(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> Button {
    app_button_base(id)
        .icon(icon)
        .ghost()
        .xsmall()
        .compact()
        .tooltip(tooltip)
}

fn settings_danger_icon_button(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> Button {
    app_button_base(id)
        .icon(icon)
        .ghost()
        .xsmall()
        .compact()
        .tooltip(tooltip)
        .text_color(rgb(theme::DANGER))
}

fn render_settings_url_dialog_content(
    input: &Entity<InputState>,
    content_width: Pixels,
    help: &'static str,
) -> gpui::Div {
    div()
        .w(content_width)
        .flex()
        .flex_col()
        .gap_3()
        .child(app_muted_text(help))
        .child(settings_text_input(input))
}

fn render_waku_direct_peer_dialog_content(
    inputs: &WakuDirectPeerDialogInputs,
    content_width: Pixels,
) -> gpui::Div {
    div()
        .w(content_width)
        .flex()
        .flex_col()
        .gap_3()
        .child(app_muted_text(
            "Enter one libp2p peer ID and one multiaddr. Add another row for additional addresses.",
        ))
        .child(dialog_text_field("Peer ID", &inputs.peer_id))
        .child(dialog_text_field("Multiaddr", &inputs.addr))
}

fn dialog_text_field(label: &'static str, input: &Entity<InputState>) -> gpui::Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .child(app_muted_text(label))
        .child(settings_text_input(input))
}

fn price_anchor_type_select_items() -> Vec<PriceAnchorTypeSelectItem> {
    vec![
        PriceAnchorTypeSelectItem {
            value: "fixed",
            label: "Fixed",
        },
        PriceAnchorTypeSelectItem {
            value: "oracle",
            label: "Oracle",
        },
        PriceAnchorTypeSelectItem {
            value: "product",
            label: "Product",
        },
    ]
}

fn product_component_type_select_items() -> Vec<PriceAnchorTypeSelectItem> {
    vec![
        PriceAnchorTypeSelectItem {
            value: "fixed",
            label: "Fixed",
        },
        PriceAnchorTypeSelectItem {
            value: "oracle",
            label: "Oracle",
        },
    ]
}

fn price_anchor_chain_select_items() -> Vec<ChainSelectItem> {
    railgun_ui::DEFAULT_CHAINS
        .iter()
        .map(|chain_id| ChainSelectItem {
            chain_id: *chain_id,
        })
        .collect()
}

fn bool_select_items() -> Vec<BoolSelectItem> {
    vec![
        BoolSelectItem {
            value: false,
            label: "No",
        },
        BoolSelectItem {
            value: true,
            label: "Yes",
        },
    ]
}

fn chain_select_index(items: &[ChainSelectItem], chain_id: u64) -> Option<IndexPath> {
    (!items.is_empty()).then(|| {
        IndexPath::default().row(
            items
                .iter()
                .position(|item| item.chain_id == chain_id)
                .unwrap_or_default(),
        )
    })
}

fn price_anchor_type_select_index(
    items: &[PriceAnchorTypeSelectItem],
    value: &str,
) -> Option<IndexPath> {
    (!items.is_empty()).then(|| {
        IndexPath::default().row(
            items
                .iter()
                .position(|item| item.value.eq_ignore_ascii_case(value))
                .unwrap_or_default(),
        )
    })
}

fn bool_select_index(value: bool) -> IndexPath {
    IndexPath::default().row(usize::from(value))
}

pub(super) fn display_token_entries(settings: &WalletSettings) -> Vec<DisplayTokenEntry> {
    let custom_indexes = settings
        .tokens
        .custom_tokens
        .iter()
        .enumerate()
        .map(|(index, token)| {
            (
                normalized_token_key(token.chain_id, &token.token_address),
                index,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut entries = match build_effective_token_registry(settings) {
        Ok(registry) => registry
            .tokens
            .into_values()
            .map(|token| {
                let key = normalized_token_key(token.chain_id, &token.token_address);
                DisplayTokenEntry {
                    chain_id: token.chain_id,
                    token_address: token.token_address,
                    symbol: token.symbol,
                    decimals: token.decimals,
                    icon_path: token.icon_path,
                    built_in: token.built_in,
                    custom_index: custom_indexes.get(&key).copied(),
                }
            })
            .collect(),
        Err(_) => default_token_entries(),
    };
    entries.sort_by(|left, right| {
        (
            left.chain_id,
            left.symbol.to_ascii_lowercase(),
            left.token_address.to_ascii_lowercase(),
        )
            .cmp(&(
                right.chain_id,
                right.symbol.to_ascii_lowercase(),
                right.token_address.to_ascii_lowercase(),
            ))
    });
    entries
}

fn default_token_entries() -> Vec<DisplayTokenEntry> {
    railgun_ui::DEFAULT_CHAINS
        .iter()
        .flat_map(|chain_id| railgun_ui::known_tokens_for_chain(*chain_id))
        .map(|token| DisplayTokenEntry {
            chain_id: token.chain_id,
            token_address: token.token.to_string(),
            symbol: token.symbol.to_string(),
            decimals: token.decimals,
            icon_path: None,
            built_in: true,
            custom_index: None,
        })
        .collect()
}

pub(super) fn display_price_anchor_entries(
    settings: &WalletSettings,
) -> Vec<DisplayPriceAnchorEntry> {
    let token_symbols = display_token_entries(settings)
        .into_iter()
        .map(|token| {
            (
                normalized_token_key(token.chain_id, &token.token_address),
                token.symbol,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut entries = default_token_price_anchor_overrides()
        .into_iter()
        .map(|anchor| {
            let key = token_key_tuple(&anchor.key);
            (
                key.clone(),
                DisplayPriceAnchorEntry {
                    key: anchor.key,
                    price_anchor: anchor.price_anchor,
                    token_symbol: token_symbols.get(&key).cloned(),
                    built_in_default: true,
                    override_index: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (index, anchor) in settings.tokens.price_anchors.iter().enumerate() {
        let key = token_key_tuple(&anchor.key);
        entries.insert(
            key.clone(),
            DisplayPriceAnchorEntry {
                key: anchor.key.clone(),
                price_anchor: anchor.price_anchor.clone(),
                token_symbol: token_symbols.get(&key).cloned(),
                built_in_default: false,
                override_index: Some(index),
            },
        );
    }

    entries.into_values().collect()
}

fn remove_display_price_anchor_override(
    settings: &mut WalletSettings,
    entry: &DisplayPriceAnchorEntry,
) {
    if let Some(index) = display_price_anchor_override_index(settings, entry) {
        settings.tokens.price_anchors.remove(index);
    }
}

fn display_price_anchor_override_index(
    settings: &WalletSettings,
    entry: &DisplayPriceAnchorEntry,
) -> Option<usize> {
    entry
        .override_index
        .filter(|index| *index < settings.tokens.price_anchors.len())
        .or_else(|| {
            settings
                .tokens
                .price_anchors
                .iter()
                .position(|anchor| token_keys_match(&anchor.key, &entry.key))
        })
}

fn price_anchor_dialog_values(
    settings: &WalletSettings,
    target: &PriceAnchorEditTarget,
) -> PriceAnchorDialogValues {
    match target {
        PriceAnchorEditTarget::Add => default_price_anchor_dialog_values(),
        PriceAnchorEditTarget::Edit(entry) => {
            let anchor = current_display_price_anchor_for_entry(settings, entry);
            price_anchor_dialog_values_from_override(&anchor)
        }
    }
}

fn current_display_price_anchor_for_entry(
    settings: &WalletSettings,
    entry: &DisplayPriceAnchorEntry,
) -> TokenPriceAnchorOverride {
    display_price_anchor_override_index(settings, entry).map_or_else(
        || TokenPriceAnchorOverride {
            key: entry.key.clone(),
            price_anchor: entry.price_anchor.clone(),
        },
        |index| settings.tokens.price_anchors[index].clone(),
    )
}

fn default_price_anchor_dialog_values() -> PriceAnchorDialogValues {
    PriceAnchorDialogValues {
        chain_id: railgun_ui::DEFAULT_CHAINS[0],
        token_address: Address::ZERO.to_string(),
        anchor_type: "fixed",
        fixed_rate: fixed_anchor_rate_value(&PriceAnchorSettings::default()),
        oracle_chain_id: railgun_ui::DEFAULT_CHAINS[0],
        oracle_address: Address::ZERO.to_string(),
        oracle_token_decimals: "18".to_string(),
        oracle_decimals: "8".to_string(),
        oracle_is_inversed: false,
        product_scale_decimals: "18".to_string(),
        product_components: default_price_anchor_component_dialog_values(),
    }
}

fn default_price_anchor_component_dialog_values() -> Vec<PriceAnchorComponentDialogValues> {
    vec![
        price_anchor_component_dialog_values_from_anchor(&default_price_anchor_for_type("oracle")),
        price_anchor_component_dialog_values_from_anchor(&default_price_anchor_for_type("oracle")),
    ]
}

fn price_anchor_dialog_values_from_override(
    anchor: &TokenPriceAnchorOverride,
) -> PriceAnchorDialogValues {
    let mut values = default_price_anchor_dialog_values();
    values.chain_id = anchor.key.chain_id;
    values.token_address.clone_from(&anchor.key.token_address);
    match &anchor.price_anchor {
        PriceAnchorSettings::Fixed { rate } => {
            values.anchor_type = "fixed";
            values.fixed_rate.clone_from(rate);
        }
        PriceAnchorSettings::Oracle {
            chain_id,
            oracle_address,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => {
            values.anchor_type = "oracle";
            values.oracle_chain_id = *chain_id;
            values.oracle_address.clone_from(oracle_address);
            values.oracle_token_decimals = token_decimals.to_string();
            values.oracle_decimals = oracle_decimals.to_string();
            values.oracle_is_inversed = *is_inversed;
        }
        PriceAnchorSettings::Product {
            components,
            scale_decimals,
        } => {
            values.anchor_type = "product";
            values.product_scale_decimals = scale_decimals.to_string();
            values.product_components = components
                .iter()
                .take(2)
                .map(price_anchor_component_dialog_values_from_anchor)
                .collect();
            while values.product_components.len() < 2 {
                values
                    .product_components
                    .push(price_anchor_component_dialog_values_from_anchor(
                        &default_price_anchor_for_type("oracle"),
                    ));
            }
        }
    }
    values
}

#[cfg(test)]
pub(super) fn price_anchor_dialog_values_from_entry(
    entry: &DisplayPriceAnchorEntry,
) -> PriceAnchorDialogValues {
    price_anchor_dialog_values_from_override(&TokenPriceAnchorOverride {
        key: entry.key.clone(),
        price_anchor: entry.price_anchor.clone(),
    })
}

fn price_anchor_component_dialog_values_from_anchor(
    anchor: &PriceAnchorSettings,
) -> PriceAnchorComponentDialogValues {
    match anchor {
        PriceAnchorSettings::Fixed { rate } => PriceAnchorComponentDialogValues {
            anchor_type: "fixed",
            fixed_rate: rate.clone(),
            ..default_price_anchor_component_dialog_value()
        },
        PriceAnchorSettings::Oracle {
            chain_id,
            oracle_address,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => PriceAnchorComponentDialogValues {
            anchor_type: "oracle",
            fixed_rate: "1000000000000000000".to_string(),
            oracle_chain_id: *chain_id,
            oracle_address: oracle_address.clone(),
            oracle_token_decimals: token_decimals.to_string(),
            oracle_decimals: oracle_decimals.to_string(),
            oracle_is_inversed: *is_inversed,
        },
        PriceAnchorSettings::Product { .. } => default_price_anchor_component_dialog_value(),
    }
}

fn default_price_anchor_component_dialog_value() -> PriceAnchorComponentDialogValues {
    PriceAnchorComponentDialogValues {
        anchor_type: "oracle",
        fixed_rate: "1000000000000000000".to_string(),
        oracle_chain_id: railgun_ui::DEFAULT_CHAINS[0],
        oracle_address: Address::ZERO.to_string(),
        oracle_token_decimals: "18".to_string(),
        oracle_decimals: "8".to_string(),
        oracle_is_inversed: false,
    }
}

fn apply_price_anchor_dialog_values(
    settings: &mut WalletSettings,
    target: &PriceAnchorEditTarget,
    anchor: TokenPriceAnchorOverride,
) {
    match target {
        PriceAnchorEditTarget::Add => settings.tokens.price_anchors.push(anchor),
        PriceAnchorEditTarget::Edit(entry) => set_price_anchor_override(settings, entry, anchor),
    }
}

pub(super) fn set_price_anchor_override(
    settings: &mut WalletSettings,
    entry: &DisplayPriceAnchorEntry,
    anchor: TokenPriceAnchorOverride,
) {
    if let Some(index) = display_price_anchor_override_index(settings, entry) {
        settings.tokens.price_anchors[index] = anchor;
    } else {
        settings.tokens.price_anchors.push(anchor);
    }
}

fn token_dialog_values(settings: &WalletSettings, target: &TokenEditTarget) -> TokenDialogValues {
    match target {
        TokenEditTarget::AddCustom => TokenDialogValues {
            chain_id: railgun_ui::DEFAULT_CHAINS[0],
            token_address: Address::ZERO.to_string(),
            symbol: String::new(),
            decimals: 18,
            icon_path: None,
        },
        TokenEditTarget::BuiltIn(key) => display_token_entries(settings)
            .into_iter()
            .find(|entry| token_key_matches_entry(key, entry))
            .map_or_else(
                || TokenDialogValues {
                    chain_id: key.chain_id,
                    token_address: key.token_address.clone(),
                    symbol: String::new(),
                    decimals: 18,
                    icon_path: None,
                },
                |entry| TokenDialogValues {
                    chain_id: entry.chain_id,
                    token_address: entry.token_address,
                    symbol: entry.symbol,
                    decimals: entry.decimals,
                    icon_path: entry.icon_path,
                },
            ),
        TokenEditTarget::Custom(index) => settings.tokens.custom_tokens.get(*index).map_or_else(
            || token_dialog_values(settings, &TokenEditTarget::AddCustom),
            |token| TokenDialogValues {
                chain_id: token.chain_id,
                token_address: token.token_address.clone(),
                symbol: token.symbol.clone(),
                decimals: token.decimals,
                icon_path: token.icon_path.clone(),
            },
        ),
    }
}

fn token_dialog_values_from_inputs(
    inputs: &TokenDialogInputs,
    cx: &App,
) -> Result<TokenDialogValues, String> {
    let chain_id = inputs
        .chain_id
        .read(cx)
        .value()
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("Invalid token chain ID: {error}"))?;
    let decimals = inputs
        .decimals
        .read(cx)
        .value()
        .trim()
        .parse::<u8>()
        .map_err(|error| format!("Invalid token decimals: {error}"))?;
    Ok(TokenDialogValues {
        chain_id,
        token_address: inputs.token_address.read(cx).value().trim().to_string(),
        symbol: inputs.symbol.read(cx).value().trim().to_string(),
        decimals,
        icon_path: non_empty_setting(inputs.icon_path.read(cx).value().as_ref()),
    })
}

fn waku_direct_peer_from_dialog_inputs(
    inputs: &WakuDirectPeerDialogInputs,
    cx: &App,
) -> WakuDirectPeerSetting {
    WakuDirectPeerSetting {
        peer_id: inputs.peer_id.read(cx).value().trim().to_string(),
        addr: inputs.addr.read(cx).value().trim().to_string(),
    }
}

fn price_anchor_override_from_dialog_inputs(
    inputs: &PriceAnchorDialogInputs,
    cx: &App,
) -> Result<TokenPriceAnchorOverride, String> {
    let chain_id = inputs
        .chain_id
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select a token chain".to_string())?;
    let anchor_type = inputs
        .anchor_type
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select an anchor type".to_string())?;
    let oracle_chain_id = inputs
        .oracle_chain_id
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select an oracle chain".to_string())?;
    let oracle_is_inversed = inputs
        .oracle_is_inversed
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select whether the oracle is inverse".to_string())?;
    let product_components = inputs
        .product_components
        .iter()
        .map(|component| price_anchor_component_dialog_values(component, cx))
        .collect::<Result<Vec<_>, _>>()?;

    price_anchor_override_from_dialog_values(&PriceAnchorDialogValues {
        chain_id,
        token_address: inputs.token_address.read(cx).value().trim().to_string(),
        anchor_type,
        fixed_rate: inputs.fixed_rate.read(cx).value().trim().to_string(),
        oracle_chain_id,
        oracle_address: inputs.oracle_address.read(cx).value().trim().to_string(),
        oracle_token_decimals: inputs
            .oracle_token_decimals
            .read(cx)
            .value()
            .trim()
            .to_string(),
        oracle_decimals: inputs.oracle_decimals.read(cx).value().trim().to_string(),
        oracle_is_inversed,
        product_scale_decimals: inputs
            .product_scale_decimals
            .read(cx)
            .value()
            .trim()
            .to_string(),
        product_components,
    })
}

fn price_anchor_component_dialog_values(
    inputs: &ProductAnchorComponentDialogInputs,
    cx: &App,
) -> Result<PriceAnchorComponentDialogValues, String> {
    let anchor_type = inputs
        .anchor_type
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select a component type".to_string())?;
    let oracle_chain_id = inputs
        .oracle_chain_id
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select a component oracle chain".to_string())?;
    let oracle_is_inversed = inputs
        .oracle_is_inversed
        .read(cx)
        .selected_value()
        .copied()
        .ok_or_else(|| "Select whether the component oracle is inverse".to_string())?;

    Ok(PriceAnchorComponentDialogValues {
        anchor_type,
        fixed_rate: inputs.fixed_rate.read(cx).value().trim().to_string(),
        oracle_chain_id,
        oracle_address: inputs.oracle_address.read(cx).value().trim().to_string(),
        oracle_token_decimals: inputs
            .oracle_token_decimals
            .read(cx)
            .value()
            .trim()
            .to_string(),
        oracle_decimals: inputs.oracle_decimals.read(cx).value().trim().to_string(),
        oracle_is_inversed,
    })
}

pub(super) fn price_anchor_override_from_dialog_values(
    values: &PriceAnchorDialogValues,
) -> Result<TokenPriceAnchorOverride, String> {
    let token_address = values.token_address.trim();
    if token_address.is_empty() {
        return Err("Token address must not be empty".to_string());
    }
    let anchor_type = parse_price_anchor_type(values.anchor_type)?;
    let price_anchor = match anchor_type {
        "oracle" => PriceAnchorSettings::Oracle {
            chain_id: values.oracle_chain_id,
            oracle_address: values.oracle_address.trim().to_string(),
            token_decimals: parse_price_anchor_u8(
                "Oracle token decimals",
                &values.oracle_token_decimals,
            )?,
            oracle_decimals: parse_price_anchor_u8("Oracle decimals", &values.oracle_decimals)?,
            is_inversed: values.oracle_is_inversed,
        },
        "product" => PriceAnchorSettings::Product {
            components: product_components_from_dialog_values(&values.product_components)?,
            scale_decimals: parse_price_anchor_u8(
                "Product scale decimals",
                &values.product_scale_decimals,
            )?,
        },
        _ => PriceAnchorSettings::Fixed {
            rate: values.fixed_rate.trim().to_string(),
        },
    };

    Ok(TokenPriceAnchorOverride {
        key: TokenKey {
            chain_id: values.chain_id,
            token_address: token_address.to_string(),
        },
        price_anchor,
    })
}

fn product_components_from_dialog_values(
    values: &[PriceAnchorComponentDialogValues],
) -> Result<Vec<PriceAnchorSettings>, String> {
    if values.is_empty() {
        return Err("Product anchor must include at least one component".to_string());
    }
    values
        .iter()
        .enumerate()
        .map(|(index, component)| price_anchor_component_from_dialog_values(index, component))
        .collect()
}

fn price_anchor_component_from_dialog_values(
    index: usize,
    values: &PriceAnchorComponentDialogValues,
) -> Result<PriceAnchorSettings, String> {
    match parse_product_component_anchor_type(values.anchor_type)? {
        "oracle" => Ok(PriceAnchorSettings::Oracle {
            chain_id: values.oracle_chain_id,
            oracle_address: values.oracle_address.trim().to_string(),
            token_decimals: parse_price_anchor_u8(
                &format!("Component {} token decimals", index + 1),
                &values.oracle_token_decimals,
            )?,
            oracle_decimals: parse_price_anchor_u8(
                &format!("Component {} oracle decimals", index + 1),
                &values.oracle_decimals,
            )?,
            is_inversed: values.oracle_is_inversed,
        }),
        _ => Ok(PriceAnchorSettings::Fixed {
            rate: values.fixed_rate.trim().to_string(),
        }),
    }
}

fn parse_price_anchor_u8(field: &str, value: &str) -> Result<u8, String> {
    value
        .trim()
        .parse::<u8>()
        .map_err(|error| format!("Invalid {field}: {error}"))
}

fn apply_token_dialog_values(
    settings: &mut WalletSettings,
    target: &TokenEditTarget,
    values: TokenDialogValues,
) {
    match target {
        TokenEditTarget::AddCustom => settings.tokens.custom_tokens.push(CustomTokenSettings {
            chain_id: values.chain_id,
            token_address: values.token_address,
            symbol: values.symbol,
            decimals: values.decimals,
            icon_path: values.icon_path,
            price_anchor: None,
        }),
        TokenEditTarget::BuiltIn(key) => set_built_in_token_override(settings, key, values),
        TokenEditTarget::Custom(index) => {
            if let Some(token) = settings.tokens.custom_tokens.get_mut(*index) {
                token.chain_id = values.chain_id;
                token.token_address = values.token_address;
                token.symbol = values.symbol;
                token.decimals = values.decimals;
                token.icon_path = values.icon_path;
            }
        }
    }
}

fn set_built_in_token_override(
    settings: &mut WalletSettings,
    key: &TokenKey,
    values: TokenDialogValues,
) {
    let default = key
        .token_address
        .parse::<Address>()
        .ok()
        .and_then(|address| railgun_ui::lookup_token(key.chain_id, &address));
    let position = settings
        .tokens
        .built_in_overrides
        .iter()
        .position(|override_settings| token_keys_match(&override_settings.key, key));
    let existing_anchor = position.and_then(|index| {
        settings.tokens.built_in_overrides[index]
            .price_anchor
            .clone()
    });
    let mut override_settings = BuiltInTokenOverride {
        key: key.clone(),
        price_anchor: existing_anchor,
        ..BuiltInTokenOverride::default()
    };
    override_settings.symbol = default.map_or_else(
        || non_empty_setting(&values.symbol),
        |token| (values.symbol != token.symbol).then_some(values.symbol.clone()),
    );
    override_settings.decimals = default.map_or(Some(values.decimals), |token| {
        (values.decimals != token.decimals).then_some(values.decimals)
    });
    override_settings.icon_path = values.icon_path;

    let is_empty = override_settings.symbol.is_none()
        && override_settings.decimals.is_none()
        && override_settings.icon_path.is_none()
        && override_settings.price_anchor.is_none();
    match (position, is_empty) {
        (Some(index), true) => {
            settings.tokens.built_in_overrides.remove(index);
        }
        (Some(index), false) => settings.tokens.built_in_overrides[index] = override_settings,
        (None, false) => settings.tokens.built_in_overrides.push(override_settings),
        (None, true) => {}
    }
}

fn remove_custom_token(settings: &mut WalletSettings, index: usize) {
    if index < settings.tokens.custom_tokens.len() {
        settings.tokens.custom_tokens.remove(index);
    }
}

fn token_key_matches_entry(key: &TokenKey, entry: &DisplayTokenEntry) -> bool {
    normalized_token_key(key.chain_id, &key.token_address)
        == normalized_token_key(entry.chain_id, &entry.token_address)
}

fn token_keys_match(left: &TokenKey, right: &TokenKey) -> bool {
    token_key_tuple(left) == token_key_tuple(right)
}

fn token_key_tuple(key: &TokenKey) -> (u64, String) {
    normalized_token_key(key.chain_id, &key.token_address)
}

fn normalized_token_key(chain_id: u64, token_address: &str) -> (u64, String) {
    (chain_id, normalize_token_address(token_address))
}

fn normalize_token_address(token_address: &str) -> String {
    token_address.parse::<Address>().map_or_else(
        |_| token_address.trim().to_ascii_lowercase(),
        |address| address.to_string().to_ascii_lowercase(),
    )
}

pub(super) fn display_chain_rpc_endpoints(settings: &WalletSettings, chain_id: u64) -> Vec<String> {
    settings
        .chains
        .per_chain
        .get(&chain_id)
        .filter(|chain| !chain.rpc_endpoints.is_empty())
        .map_or_else(
            || default_chain_rpc_endpoints(chain_id).unwrap_or_default(),
            |chain| chain.rpc_endpoints.clone(),
        )
}

pub(super) fn display_chain_quick_sync_endpoint(
    settings: &WalletSettings,
    chain_id: u64,
) -> String {
    settings
        .chains
        .per_chain
        .get(&chain_id)
        .and_then(|chain| chain.quick_sync.endpoint.clone())
        .unwrap_or_else(|| default_chain_quick_sync_endpoint(chain_id).unwrap_or_default())
}

pub(super) fn display_chain_contract_settings(
    settings: &WalletSettings,
    chain_id: u64,
) -> ChainContractSettings {
    let mut contracts = default_chain_contract_settings(chain_id).unwrap_or_default();
    if let Some(overrides) = settings.chains.per_chain.get(&chain_id) {
        if let Some(value) = overrides.contracts.railgun_contract.as_ref() {
            contracts.railgun_contract = Some(value.clone());
        }
        if let Some(value) = overrides.contracts.relay_adapt_contract.as_ref() {
            contracts.relay_adapt_contract = Some(value.clone());
        }
        if let Some(value) = overrides.contracts.relay_adapt_7702_contract.as_ref() {
            contracts.relay_adapt_7702_contract = Some(value.clone());
        }
        if let Some(value) = overrides.contracts.wrapped_native_token.as_ref() {
            contracts.wrapped_native_token = Some(value.clone());
        }
        if let Some(value) = overrides.contracts.multicall_contract.as_ref() {
            contracts.multicall_contract = Some(value.clone());
        }
    }
    contracts
}

pub(super) fn display_waku_doh_endpoint(settings: &WalletSettings) -> String {
    settings
        .waku
        .doh_endpoint
        .clone()
        .unwrap_or_else(|| default_waku_doh_endpoint(settings.network.mode).to_string())
}

const fn default_waku_doh_endpoint(mode: NetworkModeSetting) -> &'static str {
    match mode {
        NetworkModeSetting::Tor => DEFAULT_TOR_DOH_ENDPOINT,
        NetworkModeSetting::Proxy | NetworkModeSetting::Direct => DEFAULT_DOH_ENDPOINT,
    }
}

pub(super) fn display_waku_doh_fallback_endpoints(settings: &WalletSettings) -> Vec<String> {
    settings
        .waku
        .doh_fallback_endpoints
        .clone()
        .unwrap_or_else(|| default_waku_doh_fallback_endpoints(settings.network.mode))
}

pub(super) fn display_waku_dns_enr_trees(settings: &WalletSettings) -> Vec<String> {
    settings
        .waku
        .dns_enr_trees
        .clone()
        .unwrap_or_else(default_waku_dns_enr_trees)
}

pub(super) fn display_waku_direct_peers(settings: &WalletSettings) -> Vec<WakuDirectPeerSetting> {
    settings
        .waku
        .direct_peers
        .clone()
        .unwrap_or_else(default_waku_direct_peers)
}

fn default_waku_doh_fallback_endpoints(mode: NetworkModeSetting) -> Vec<String> {
    match mode {
        NetworkModeSetting::Tor => vec![DEFAULT_DOH_ENDPOINT.to_string()],
        NetworkModeSetting::Proxy | NetworkModeSetting::Direct => Vec::new(),
    }
}

fn materialize_chain_rpc_endpoints(
    settings: &mut WalletSettings,
    chain_id: u64,
) -> &mut Vec<String> {
    let chain = settings.chains.per_chain.entry(chain_id).or_default();
    if chain.rpc_endpoints.is_empty() {
        chain.rpc_endpoints = default_chain_rpc_endpoints(chain_id).unwrap_or_default();
    }
    &mut chain.rpc_endpoints
}

fn materialize_waku_doh_fallback_endpoints(settings: &mut WalletSettings) -> &mut Vec<String> {
    if settings.waku.doh_fallback_endpoints.is_none() {
        settings.waku.doh_fallback_endpoints =
            Some(default_waku_doh_fallback_endpoints(settings.network.mode));
    }
    settings
        .waku
        .doh_fallback_endpoints
        .as_mut()
        .expect("fallback endpoints were just initialized")
}

fn materialize_waku_dns_enr_trees(settings: &mut WalletSettings) -> &mut Vec<String> {
    if settings.waku.dns_enr_trees.is_none() {
        settings.waku.dns_enr_trees = Some(default_waku_dns_enr_trees());
    }
    settings
        .waku
        .dns_enr_trees
        .as_mut()
        .expect("DNS ENR trees were just initialized")
}

fn materialize_waku_direct_peers(settings: &mut WalletSettings) -> &mut Vec<WakuDirectPeerSetting> {
    if settings.waku.direct_peers.is_none() {
        settings.waku.direct_peers = Some(default_waku_direct_peers());
    }
    settings
        .waku
        .direct_peers
        .as_mut()
        .expect("direct peers were just initialized")
}

pub(super) fn set_chain_rpc_endpoint(
    settings: &mut WalletSettings,
    chain_id: u64,
    index: usize,
    value: &str,
) {
    let endpoints = materialize_chain_rpc_endpoints(settings, chain_id);
    if endpoints.len() <= index {
        endpoints.resize(index + 1, String::new());
    }
    endpoints[index] = value.trim().to_string();
}

pub(super) fn set_waku_doh_fallback_endpoint(
    settings: &mut WalletSettings,
    index: usize,
    value: &str,
) {
    let endpoints = materialize_waku_doh_fallback_endpoints(settings);
    if endpoints.len() <= index {
        endpoints.resize(index + 1, String::new());
    }
    endpoints[index] = value.trim().to_string();
}

pub(super) fn set_waku_dns_enr_tree(settings: &mut WalletSettings, index: usize, value: &str) {
    let trees = materialize_waku_dns_enr_trees(settings);
    if trees.len() <= index {
        trees.resize(index + 1, String::new());
    }
    trees[index] = value.trim().to_string();
}

pub(super) fn add_chain_rpc_endpoint(settings: &mut WalletSettings, chain_id: u64, value: &str) {
    materialize_chain_rpc_endpoints(settings, chain_id).push(value.trim().to_string());
}

pub(super) fn add_waku_doh_fallback_endpoint(settings: &mut WalletSettings, value: &str) {
    materialize_waku_doh_fallback_endpoints(settings).push(value.trim().to_string());
}

pub(super) fn add_waku_dns_enr_tree(settings: &mut WalletSettings, value: &str) {
    materialize_waku_dns_enr_trees(settings).push(value.trim().to_string());
}

pub(super) fn remove_chain_rpc_endpoint(
    settings: &mut WalletSettings,
    chain_id: u64,
    index: usize,
) {
    let endpoints = materialize_chain_rpc_endpoints(settings, chain_id);
    if index < endpoints.len() {
        endpoints.remove(index);
    }
}

pub(super) fn remove_waku_doh_fallback_endpoint(settings: &mut WalletSettings, index: usize) {
    let endpoints = materialize_waku_doh_fallback_endpoints(settings);
    if index < endpoints.len() {
        endpoints.remove(index);
    }
}

pub(super) fn remove_waku_dns_enr_tree(settings: &mut WalletSettings, index: usize) {
    let trees = materialize_waku_dns_enr_trees(settings);
    if index < trees.len() {
        trees.remove(index);
    }
}

pub(super) fn set_waku_direct_peer(
    settings: &mut WalletSettings,
    index: usize,
    peer: WakuDirectPeerSetting,
) {
    let peers = materialize_waku_direct_peers(settings);
    if peers.len() <= index {
        peers.resize(index + 1, WakuDirectPeerSetting::default());
    }
    peers[index] = peer;
}

pub(super) fn add_waku_direct_peer(settings: &mut WalletSettings, peer: WakuDirectPeerSetting) {
    materialize_waku_direct_peers(settings).push(peer);
}

pub(super) fn remove_waku_direct_peer(settings: &mut WalletSettings, index: usize) {
    let peers = materialize_waku_direct_peers(settings);
    if index < peers.len() {
        peers.remove(index);
    }
}

pub(super) fn set_poi_gateway_url(settings: &mut WalletSettings, index: usize, value: &str) {
    if let Some(gateway) = settings.poi.artifact.gateway_urls.get_mut(index) {
        *gateway = value.trim().to_string();
    }
}

pub(super) fn add_poi_gateway_url(settings: &mut WalletSettings, value: &str) {
    settings
        .poi
        .artifact
        .gateway_urls
        .push(value.trim().to_string());
}

pub(super) fn remove_poi_gateway_url(settings: &mut WalletSettings, index: usize) {
    if index < settings.poi.artifact.gateway_urls.len() {
        settings.poi.artifact.gateway_urls.remove(index);
    }
}

const fn network_mode_value(mode: NetworkModeSetting) -> &'static str {
    match mode {
        NetworkModeSetting::Tor => "tor",
        NetworkModeSetting::Proxy => "proxy",
        NetworkModeSetting::Direct => "direct",
    }
}

fn network_mode_from_value(value: &str) -> NetworkModeSetting {
    match value {
        "proxy" => NetworkModeSetting::Proxy,
        "direct" => NetworkModeSetting::Direct,
        _ => NetworkModeSetting::Tor,
    }
}

pub(super) const fn should_show_proxy_url_setting(mode: NetworkModeSetting) -> bool {
    matches!(mode, NetworkModeSetting::Proxy)
}

pub(super) const fn should_show_proxy_waku_disclaimer(mode: NetworkModeSetting) -> bool {
    matches!(mode, NetworkModeSetting::Proxy)
}

const fn poi_source_value(source: PoiReadSourceSetting) -> &'static str {
    match source {
        PoiReadSourceSetting::IndexedArtifacts => "indexed-artifacts",
        PoiReadSourceSetting::PoiProxy => "poi-proxy",
    }
}

fn poi_source_from_value(value: &str) -> PoiReadSourceSetting {
    match value {
        "poi-proxy" => PoiReadSourceSetting::PoiProxy,
        _ => PoiReadSourceSetting::IndexedArtifacts,
    }
}

fn non_empty_setting(value: &str) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn optional_u64_setting(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        value.parse().ok()
    }
}

fn parse_price_anchor_type(value: &str) -> Result<&'static str, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("fixed") {
        Ok("fixed")
    } else if value.eq_ignore_ascii_case("oracle") {
        Ok("oracle")
    } else if value.eq_ignore_ascii_case("product") {
        Ok("product")
    } else {
        Err("Anchor type must be fixed, oracle, or product".to_string())
    }
}

fn parse_product_component_anchor_type(value: &str) -> Result<&'static str, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("fixed") {
        Ok("fixed")
    } else if value.eq_ignore_ascii_case("oracle") {
        Ok("oracle")
    } else {
        Err("Product component type must be fixed or oracle".to_string())
    }
}

fn default_price_anchor_for_type(value: &str) -> PriceAnchorSettings {
    match value {
        "oracle" => PriceAnchorSettings::Oracle {
            chain_id: railgun_ui::DEFAULT_CHAINS[0],
            oracle_address: Address::ZERO.to_string(),
            token_decimals: 18,
            oracle_decimals: 8,
            is_inversed: false,
        },
        "product" => PriceAnchorSettings::Product {
            components: default_product_anchor_components(),
            scale_decimals: 18,
        },
        _ => PriceAnchorSettings::default(),
    }
}

fn default_product_anchor_components() -> Vec<PriceAnchorSettings> {
    vec![
        default_price_anchor_for_type("oracle"),
        default_price_anchor_for_type("oracle"),
    ]
}

fn fixed_anchor_rate_value(anchor: &PriceAnchorSettings) -> String {
    match anchor {
        PriceAnchorSettings::Fixed { rate } => rate.clone(),
        _ => String::new(),
    }
}
