use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256};
use broadcaster_monitor::{EventRx, EventTx, Shared};
use broadcaster_monitor_waku::{RelayNetworkConfig, WakuViewerConfig, spawn_workers};
use chrono::{DateTime, Local, Utc};
use eyre::WrapErr;
use gpui::ObjectFit;
use gpui::{
    Animation, AnimationExt as _, App, AppContext, Bounds, Context, ElementId, Entity, Focusable,
    InteractiveElement, IntoElement, KeyBinding, MouseButton, ParentElement, Pixels, Point, Render,
    SharedString, StatefulInteractiveElement, Styled, StyledImage as _, WeakEntity, Window,
    WindowBounds, WindowOptions, div, img, prelude::FluentBuilder as _, px, rgb, size,
};
use gpui_component::{
    Disableable, Icon, IconName, IndexPath, Root, Selectable, Sizable, StyledExt, TitleBar,
    WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    checkbox::Checkbox,
    collapsible::Collapsible,
    dialog::DialogButtonProps,
    divider::Divider,
    input::{Input, InputEvent, InputState},
    list::{List, ListDelegate, ListItem, ListState},
    menu::{DropdownMenu, PopupMenuItem},
    popover::Popover,
    progress::Progress as UiProgress,
    resizable::{ResizableState, resizable_panel, v_resizable},
    scroll::ScrollableElement,
    select::{SearchableVec, Select, SelectEvent, SelectItem, SelectState},
    sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
    spinner::Spinner,
    tab::{Tab, TabBar},
    table::{Column, Table, TableDelegate, TableEvent, TableState},
    tag::Tag,
    tooltip::Tooltip,
};
use qrcodegen::{QrCode, QrCodeEcc};
use railgun_ui::{
    DEFAULT_CHAINS, chain_icon_path, chain_name, format_broadcaster_address_label,
    format_scaled_amount, format_token_amount, lookup_token, short_address, token_icon_path,
};
use tokio::runtime::Handle;
use tokio::sync::{OnceCell, mpsc, watch};
use ui::clipboard::{clipboard_with_toast, copy_to_clipboard_with_toast};
use ui::controls::{app_button, app_button_base, app_input, app_muted_text, app_strong_text};
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::theme::{self, APP_FONT_FAMILY, APP_MONO_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    BroadcasterFeePolicy, BroadcasterFeePolicyStatus, DesktopSendCalldataRequest,
    DesktopSendPublicBroadcasterEstimateRequest, DesktopSendPublicBroadcasterRequest,
    DesktopUnshieldCalldataRequest, DesktopUnshieldPublicBroadcasterEstimateRequest,
    DesktopUnshieldPublicBroadcasterRequest, DesktopWalletSyncStartPolicy, HttpContext,
    ListUtxosOutput, PreparedSendCall, PreparedUnshieldCall, PublicActionProgressStatus,
    PublicActionProgressStep, PublicActionProgressUpdate, PublicAssetId, PublicBalanceAmount,
    PublicBalanceEntry, PublicBalanceSnapshot, PublicBroadcasterCandidate,
    PublicBroadcasterCostEstimate, PublicBroadcasterFeeBreakdown, PublicBroadcasterFeeMargin,
    PublicBroadcasterFeeMode, PublicBroadcasterResultKind, PublicBroadcasterSelection,
    PublicBroadcasterSubmissionResult, PublicBroadcasterWakuClient, PublicSendRequest,
    PublicShieldRequest, SyncProgressUpdate, TokenAnchorRateCache, TokenAnchorRefreshHandle,
    TokenTotal, TransactionGenerationStage, UtxoOutput, ViewWalletChainSessionRequest,
    WalletNetworkConfig, WalletNetworkHealth, WalletNetworkHealthState, WalletNetworkMode,
    WalletNetworkProgress, WalletSessionStore, build_wallet_network_context_with_progress,
    estimate_desktop_send_public_broadcaster_cost,
    estimate_desktop_unshield_public_broadcaster_cost, estimate_public_native_action_gas_reserve,
    fee_policy_eligible_public_broadcasters, fixed_token_anchor_rate, is_wrapped_native_token,
    max_broadcaster_fee_token_amount_from_outputs as planner_max_broadcaster_fee_token_amount_from_outputs,
    max_send_amount_from_outputs as planner_max_send_amount_from_outputs,
    max_unshield_amount_from_outputs as planner_max_unshield_amount_from_outputs,
    parse_railgun_recipient, parse_send_amount, parse_unshield_amount,
    prepare_desktop_send_calldata, prepare_desktop_unshield_calldata,
    public_balance_refresh_interval_secs, public_broadcaster_candidates_for_asset,
    public_broadcaster_fee_breakdown, public_broadcaster_service_gas_price,
    refresh_public_balances, request_tor_state_reset, select_public_broadcaster_with_policy,
    sort_specific_public_broadcasters, spawn_token_anchor_refresh_worker,
    submit_desktop_send_public_broadcaster, submit_desktop_unshield_public_broadcaster,
    submit_public_send_with_progress, submit_public_shield_with_progress,
    vault::{
        DesktopVaultStore, DesktopViewSession, GeneratedSeedMaterial, PRIMARY_WALLET_LABEL,
        PublicAccountMetadata, PublicAccountSource, PublicAccountStatus, VaultError,
        WalletMetadataBundle, WalletSource, WalletStatus, default_wallet_label_for_metadata,
        generate_opaque_id, generate_seed_material, public_account_default_label,
        sort_wallet_metadata,
    },
};
use zeroize::Zeroizing;

use crate::assets::{
    HEMATITE_HERO_PATH, HERO_WORDMARK_PATH, LOGO_ICON_PATH, RailgunActionIcon,
    RailgunNetworkStatusIcon, RailgunPublicAccountIcon, RailgunSidebarIcon, SIDEBAR_WORDMARK_PATH,
    WARM_GLOW_PATH,
};

const SIDEBAR_WIDTH: Pixels = px(220.0);
const SIDEBAR_AUTO_COLLAPSE_WIDTH: Pixels = px(900.0);
const LOGS_DRAWER_HEIGHT: Pixels = px(260.0);
const LOGS_DRAWER_MIN_HEIGHT: Pixels = px(160.0);
const LOGS_DRAWER_MAX_HEIGHT: Pixels = px(600.0);
const BROADCASTER_PICKER_MAX_HEIGHT: Pixels = px(680.0);
const BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const PRIVATE_ACTION_FORM_MAX_HEIGHT: Pixels = px(760.0);
const PRIVATE_ASSET_LIST_WIDTH: Pixels = px(760.0);
const PUBLIC_ACCOUNT_DIALOG_WIDTH: Pixels = px(460.0);
const PUBLIC_ADDRESS_QR_DIALOG_WIDTH: Pixels = px(440.0);
const PUBLIC_ACTION_DIALOG_WIDTH: Pixels = px(520.0);
const PUBLIC_ACCOUNT_IDENTICON_SIZE: Pixels = px(40.0);
const PUBLIC_ACCOUNT_IDENTICON_CELL_SIZE: Pixels = px(8.0);
const PUBLIC_ADDRESS_QR_MODULE_SIZE: Pixels = px(6.0);
const PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES: i32 = 4;
const PUBLIC_ADDRESS_QR_FOREGROUND: u32 = 0x1e3c67;
const PUBLIC_ADDRESS_QR_BACKGROUND: u32 = 0xffffff;
const PUBLIC_BALANCE_CHIP_MIN_WIDTH: Pixels = px(184.0);
const PUBLIC_BALANCE_CHIP_ACTION_SLOT_SIZE: Pixels = px(24.0);
const PUBLIC_BALANCE_CHIP_ACTION_ICON_SIZE: Pixels = px(20.0);
const PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE: usize = 5;
const PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS: usize = 3;
const PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT: usize =
    PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE * PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE;
const PUBLIC_ACCOUNT_IDENTICON_COLORS: [u32; 8] = [
    theme::PRIMARY,
    theme::SUCCESS,
    theme::WARNING_STRONG,
    theme::WARNING,
    theme::DANGER,
    theme::PURPLE,
    theme::BLUE,
    theme::OLIVE,
];
const HERO_STAGE_MAX_WIDTH: Pixels = px(1440.0);
const HERO_WIDE_BREAKPOINT: Pixels = px(1280.0);
const HERO_MEDIUM_BREAKPOINT: Pixels = px(720.0);
const HERO_CARD_MAX_WIDTH: Pixels = px(520.0);
const DIALOG_CONTENT_HORIZONTAL_INSET: Pixels = px(56.0);
const NETWORK_HEALTH_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TOR_HEALTH_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const TOR_EXIT_IP_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TOR_EXIT_IP_QUERY_URL: &str = "https://ifconfig.me/ip";
const UNSHIELD_SPINNER_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const UTXO_AGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const COST_ESTIMATE_DEBOUNCE: Duration = Duration::from_secs(1);
const PUBLIC_BROADCASTER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
const SECONDS_PER_MONTH: u64 = 30 * SECONDS_PER_DAY;
const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;
const TABLE_KEY_CONTEXT: &str = "Table";
const COST_ESTIMATE_DETAIL_TEXT_SIZE: Pixels = px(12.0);

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageUp;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageDown;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoHome;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoEnd;

pub(crate) fn install_utxo_navigation_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("pageup", UtxoPageUp, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("pagedown", UtxoPageDown, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("home", UtxoHome, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("end", UtxoEnd, Some(TABLE_KEY_CONTEXT)),
    ]);
}

#[derive(Clone)]
pub(crate) struct WalletAppOptions {
    db_path: PathBuf,
    proxy: Option<reqwest::Url>,
    network_mode: Option<WalletNetworkMode>,
    local_poi_cache: bool,
}

impl From<crate::cli::Options> for WalletAppOptions {
    fn from(value: crate::cli::Options) -> Self {
        Self {
            db_path: value.db_path.unwrap_or_else(crate::cli::default_db_path),
            proxy: value.proxy,
            network_mode: value.network_mode,
            local_poi_cache: value.local_poi_cache,
        }
    }
}

pub(crate) fn open_wallet_window(
    app: &mut App,
    options: WalletAppOptions,
    runtime: Handle,
    monitor: Shared,
    event_tx: EventTx,
    event_rx: EventRx,
    chain_ids: &[u64],
    logs: LogStore,
) {
    wallet_ops::vault::enable_best_effort_runtime_hardening();
    let chain_ids = chain_ids.to_vec();
    let window_options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: Point::default(),
            size: size(px(1_360.0), px(860.0)),
        })),
        titlebar: Some(wallet_titlebar_options()),
        window_decorations: Some(gpui::WindowDecorations::Client),
        ..Default::default()
    };

    if let Err(error) = app.open_window(window_options, |window, cx| {
        let root = cx.new(|cx| {
            WalletStartupRoot::new(
                options, runtime, monitor, event_tx, event_rx, &chain_ids, logs, window, cx,
            )
        });
        cx.new(|cx| Root::new(root, window, cx))
    }) {
        tracing::error!(%error, "failed to open wallet window");
    }
}

fn wallet_titlebar_options() -> gpui::TitlebarOptions {
    let mut options = TitleBar::title_bar_options();
    options.title = Some(SharedString::from("RailOxide"));
    options
}

fn render_wallet_window_frame(
    content: gpui::AnyElement,
    window: &Window,
    titlebar_color: u32,
) -> gpui::Div {
    div()
        .relative()
        .size_full()
        .flex()
        .flex_col()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .text_color(rgb(theme::TEXT))
        .font_family(APP_FONT_FAMILY)
        .text_size(APP_TEXT_SIZE)
        .when(should_render_wallet_title_bar(window), |this| {
            this.child(render_wallet_title_bar(titlebar_color))
        })
        .child(div().flex_1().min_w(px(0.0)).min_h(px(0.0)).child(content))
}

fn should_render_wallet_title_bar(window: &Window) -> bool {
    !cfg!(any(target_os = "linux", target_os = "freebsd"))
        || matches!(
            window.window_decorations(),
            gpui::Decorations::Client { .. }
        )
}

fn render_wallet_title_bar(titlebar_color: u32) -> TitleBar {
    TitleBar::new()
        .bg(rgb(titlebar_color))
        .border_color(rgb(titlebar_color))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .min_w(px(0.0))
                .child(img(LOGO_ICON_PATH).size(px(16.0)))
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .text_size(px(13.0))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("RailOxide"),
                ),
        )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WalletHeroLayout {
    Wide,
    Medium,
    Narrow,
}

fn wallet_hero_layout(window: &Window) -> WalletHeroLayout {
    let viewport = window.viewport_size();
    if viewport.width >= HERO_WIDE_BREAKPOINT && viewport.width >= viewport.height * 1.4 {
        WalletHeroLayout::Wide
    } else if viewport.width >= HERO_MEDIUM_BREAKPOINT {
        WalletHeroLayout::Medium
    } else {
        WalletHeroLayout::Narrow
    }
}

fn render_wallet_hero_screen(window: &Window, card: gpui::AnyElement) -> gpui::Div {
    let viewport = window.viewport_size();
    let layout = wallet_hero_layout(window);
    let stage_width = (viewport.width - px(96.0))
        .max(px(0.0))
        .min(HERO_STAGE_MAX_WIDTH);
    let card_width = (viewport.width - px(48.0))
        .max(px(0.0))
        .min(HERO_CARD_MAX_WIDTH);

    let stage = if layout == WalletHeroLayout::Wide {
        div()
            .w(stage_width)
            .flex()
            .items_center()
            .gap_6()
            .child(
                render_wallet_brand_block(window, layout)
                    .w(px(560.0))
                    .flex_none(),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .justify_end()
                    .child(div().w(card_width).child(card)),
            )
    } else {
        div()
            .w(card_width)
            .flex()
            .flex_col()
            .items_center()
            .gap_6()
            .child(render_wallet_brand_block(window, layout).w_full())
            .child(div().w_full().child(card))
    };

    div()
        .relative()
        .size_full()
        .overflow_hidden()
        .bg(rgb(theme::BACKGROUND))
        .text_color(rgb(theme::TEXT))
        .font_family(APP_FONT_FAMILY)
        .text_size(APP_TEXT_SIZE)
        .child(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .px(px(24.0))
                .child(stage),
        )
}

fn render_wallet_brand_block(window: &Window, layout: WalletHeroLayout) -> gpui::Div {
    let viewport = window.viewport_size();
    let show_mineral = layout != WalletHeroLayout::Narrow;
    let mineral_size = match layout {
        WalletHeroLayout::Wide => (viewport.height * 0.42).min(px(500.0)).max(px(360.0)),
        WalletHeroLayout::Medium => (viewport.width * 0.24).min(px(320.0)).max(px(210.0)),
        WalletHeroLayout::Narrow => px(0.0),
    };
    let wordmark_width = match layout {
        WalletHeroLayout::Wide => px(400.0),
        WalletHeroLayout::Medium => (viewport.width * 0.44).min(px(360.0)).max(px(260.0)),
        WalletHeroLayout::Narrow => (viewport.width * 0.66).min(px(360.0)).max(px(220.0)),
    };
    let wordmark_height = wordmark_width * (23.0 / 166.0);
    let art_size = mineral_size * 1.5;
    let horizontal_mineral_offset = (art_size - mineral_size) / 2.0;
    let vertical_glow_offset = (mineral_size - art_size) / 2.0;

    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_6()
        .when(show_mineral, |this| {
            this.child(
                div()
                    .relative()
                    .w(art_size)
                    .h(mineral_size)
                    .child(
                        img(WARM_GLOW_PATH)
                            .absolute()
                            .top(vertical_glow_offset)
                            .left_0()
                            .size(art_size)
                            .object_fit(ObjectFit::Fill),
                    )
                    .child(
                        img(HEMATITE_HERO_PATH)
                            .absolute()
                            .top_0()
                            .left(horizontal_mineral_offset)
                            .size(mineral_size)
                            .object_fit(ObjectFit::Contain),
                    ),
            )
        })
        .child(
            img(HERO_WORDMARK_PATH)
                .w(wordmark_width)
                .h(wordmark_height)
                .object_fit(ObjectFit::Contain),
        )
}

fn rgb_with_alpha(hex: u32, alpha: f32) -> gpui::Rgba {
    let mut color = rgb(hex);
    color.a = alpha;
    color
}

const fn network_health_color(health: &WalletNetworkHealth) -> u32 {
    match (health.mode, health.state) {
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Ready) => theme::SUCCESS,
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Reconnecting) => theme::WARNING,
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Degraded) => theme::DANGER,
        (WalletNetworkMode::Proxy, _) => theme::PRIMARY,
        (WalletNetworkMode::Direct, _) => theme::TEXT_MUTED,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum TorExitIpQueryState {
    #[default]
    Idle,
    Querying,
    Success(IpAddr),
    Error(Arc<str>),
}

fn render_network_status_popover_content(
    root: Entity<WalletRoot>,
    health: &WalletNetworkHealth,
    color: u32,
    error: Option<Arc<str>>,
    exit_ip_query: TorExitIpQueryState,
    reset_confirming: bool,
) -> gpui::Div {
    let session_root = root.clone();
    let query_root = root.clone();
    let reset_root = root.clone();
    let cancel_reset_root = root.clone();
    let confirm_reset_root = root;
    let exit_ip_querying = matches!(exit_ip_query, TorExitIpQueryState::Querying);
    div()
        .w(px(300.0))
        .flex()
        .flex_col()
        .gap_3()
        .text_size(APP_TEXT_SIZE)
        .text_color(rgb(theme::TEXT))
        .on_mouse_down(MouseButton::Left, |_event, _window, cx| {
            cx.stop_propagation();
        })
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    Icon::new(RailgunNetworkStatusIcon::Tor)
                        .small()
                        .text_color(rgb(color)),
                )
                .child(
                    app_strong_text(health.label())
                        .text_size(px(14.0))
                        .text_color(rgb(color)),
                ),
        )
        .child(
            div()
                .text_size(px(12.0))
                .line_height(px(18.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(health.detail.to_string()),
        )
        .when_some(error, |this, error| {
            this.child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::DANGER))
                    .bg(rgb_with_alpha(theme::DANGER, 0.08))
                    .p(px(10.0))
                    .text_size(px(12.0))
                    .line_height(px(17.0))
                    .text_color(rgb(theme::DANGER))
                    .child(error.to_string()),
            )
        })
        .when(health.mode == WalletNetworkMode::Tor, |this| {
            this.child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::SURFACE))
                    .p(px(10.0))
                    .text_size(px(12.0))
                    .line_height(px(17.0))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(
                        "Future wallet HTTP/RPC requests use the active Tor session. Waku peers reconnect and rediscover using the new Tor session.",
                    ),
            )
            .child(
                app_button("wallet-network-new-tor-session", "New Tor session")
                    .outline()
                    .small()
                    .on_click(move |_event, _window, cx| {
                        cx.stop_propagation();
                        session_root.update(cx, |root, cx| {
                            root.start_new_tor_session(cx);
                        });
                    }),
            )
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::SURFACE))
                    .p(px(10.0))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.0))
                            .line_height(px(17.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(
                                "Contacts https://ifconfig.me/ip through Tor.",
                            ),
                    )
                    .child(
                        app_button(
                            "wallet-network-query-exit-ip",
                            if exit_ip_querying {
                                "Querying..."
                            } else {
                                "Query exit IP"
                            },
                        )
                        .outline()
                        .small()
                        .loading(exit_ip_querying)
                        .disabled(exit_ip_querying)
                        .on_click(move |_event, _window, cx| {
                            cx.stop_propagation();
                            query_root.update(cx, |root, cx| {
                                root.query_tor_exit_ip(cx);
                            });
                        }),
                    )
                    .when(!matches!(exit_ip_query, TorExitIpQueryState::Idle), |this| {
                        this.child(match exit_ip_query {
                            TorExitIpQueryState::Idle => div().into_any_element(),
                            TorExitIpQueryState::Querying => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child("Querying exit IP through Tor...")
                                .into_any_element(),
                            TorExitIpQueryState::Success(ip) => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::SUCCESS))
                                .child(format!("Exit IP: {ip}"))
                                .into_any_element(),
                            TorExitIpQueryState::Error(error) => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::DANGER))
                                .child(error.to_string())
                                .into_any_element(),
                        })
                    }),
            )
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(if reset_confirming {
                        theme::DANGER
                    } else {
                        theme::BORDER
                    }))
                    .bg(if reset_confirming {
                        rgb_with_alpha(theme::DANGER, 0.08)
                    } else {
                        rgb(theme::SURFACE)
                    })
                    .p(px(10.0))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.0))
                            .line_height(px(17.0))
                            .text_color(rgb(if reset_confirming {
                                theme::DANGER
                            } else {
                                theme::TEXT_MUTED
                            }))
                            .child(if reset_confirming {
                                "Clears Tor cache and guard state only. Wallet data is not deleted. The wallet will quit, and Tor state will be reset on next startup."
                            } else {
                                "If Tor hidden-service connectivity gets stuck, reset only Tor cache and guard state on next startup. Wallet data is not deleted."
                            }),
                    )
                    .when(!reset_confirming, |this| {
                        this.child(
                            app_button("wallet-network-reset-tor-state", "Reset Tor state")
                                .outline()
                                .small()
                                .danger()
                                .on_click(move |_event, _window, cx| {
                                    cx.stop_propagation();
                                    reset_root.update(cx, |root, cx| {
                                        root.begin_tor_state_reset_confirmation(cx);
                                    });
                                }),
                        )
                    })
                    .when(reset_confirming, |this| {
                        this.child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    app_button("wallet-network-cancel-tor-reset", "Cancel")
                                        .outline()
                                        .small()
                                        .on_click(move |_event, _window, cx| {
                                            cx.stop_propagation();
                                            cancel_reset_root.update(cx, |root, cx| {
                                                root.cancel_tor_state_reset_confirmation(cx);
                                            });
                                        }),
                                )
                                .child(
                                    app_button("wallet-network-confirm-tor-reset", "Quit and reset")
                                        .small()
                                        .danger()
                                        .on_click(move |_event, _window, cx| {
                                            cx.stop_propagation();
                                            confirm_reset_root.update(cx, |root, cx| {
                                                root.quit_and_reset_tor_state(cx);
                                            });
                                        }),
                                ),
                        )
                    }),
            )
        })
}

async fn query_exit_ip_through_tor(proxy_url: reqwest::Url) -> eyre::Result<IpAddr> {
    let proxy = reqwest::Proxy::all(proxy_url.as_str())
        .wrap_err_with(|| format!("invalid Tor proxy URL {proxy_url}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .pool_max_idle_per_host(0)
        .build()
        .wrap_err("build one-shot Tor exit IP query client")?;
    let response = client
        .get(TOR_EXIT_IP_QUERY_URL)
        .timeout(TOR_EXIT_IP_QUERY_TIMEOUT)
        .send()
        .await
        .wrap_err("query Tor exit IP")?
        .error_for_status()
        .wrap_err("ifconfig.me returned an error status")?;
    let body = response
        .text()
        .await
        .wrap_err("read Tor exit IP response")?;
    let value = body.trim();
    value
        .parse::<IpAddr>()
        .wrap_err_with(|| format!("ifconfig.me returned a non-IP response: {value:?}"))
}

async fn retry_tor_bootstrap(http: &HttpContext, runtime: &Handle) {
    let Some(arti_client) = http.arti_client() else {
        return;
    };

    let retry = runtime.spawn(async move {
        tokio::time::timeout(TOR_HEALTH_RETRY_TIMEOUT, arti_client.bootstrap()).await
    });
    match retry.await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::debug!(%error, "Tor bootstrap retry failed during health check");
        }
        Ok(Err(_elapsed)) => {
            tracing::debug!(
                timeout_secs = TOR_HEALTH_RETRY_TIMEOUT.as_secs(),
                "Tor bootstrap retry still pending during health check"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "Tor bootstrap retry task failed during health check");
        }
    }
}

struct WalletStartupReady {
    http: HttpContext,
    waku: Arc<PublicBroadcasterWakuClient>,
}

struct WalletStartupRoot {
    options: WalletAppOptions,
    runtime: Handle,
    monitor_state: Shared,
    event_rx: Option<EventRx>,
    chain_ids: Vec<u64>,
    logs: Option<LogStore>,
    progress: WalletNetworkProgress,
    error: Option<Arc<str>>,
    wallet_root: Option<Entity<WalletRoot>>,
}

impl WalletStartupRoot {
    fn new(
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
        let (progress_tx, progress_rx) = watch::channel(progress.clone());
        let root = Self {
            options,
            runtime,
            monitor_state,
            event_rx: Some(event_rx),
            chain_ids,
            logs: Some(logs),
            progress,
            error: None,
            wallet_root: None,
        };
        root.spawn_startup_tasks(event_tx, progress_tx, progress_rx, window, cx);
        root
    }

    fn spawn_startup_tasks(
        &self,
        event_tx: EventTx,
        progress_tx: watch::Sender<WalletNetworkProgress>,
        mut progress_rx: watch::Receiver<WalletNetworkProgress>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let progress = progress_rx.borrow().clone();
                if this
                    .update(cx, |root, cx| {
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
            build_wallet_startup(options, chain_ids, monitor_state, event_tx, progress_tx).await
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = startup.await;
            let _ = this.update_in(cx, |root, window, cx| match result {
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
        let Some(event_rx) = self.event_rx.take() else {
            self.fail_startup(
                "Wallet startup event receiver was already consumed".to_string(),
                cx,
            );
            return;
        };
        let Some(logs) = self.logs.take() else {
            self.fail_startup(
                "Wallet startup log store was already consumed".to_string(),
                cx,
            );
            return;
        };
        let monitor_state = self.monitor_state.clone();
        let public_broadcaster_anchor_cache = Arc::new(TokenAnchorRateCache::new());
        let public_broadcaster_anchor_refresh = spawn_token_anchor_refresh_worker(
            &self.runtime,
            Arc::clone(&public_broadcaster_anchor_cache),
            self.chain_ids.clone(),
            ready.http.clone(),
        );
        let fee_anchor_lookup: broadcaster_monitor_gpui::FeeAnchorLookup = Arc::new({
            let public_broadcaster_anchor_cache = Arc::clone(&public_broadcaster_anchor_cache);
            move |chain_id, token| public_broadcaster_anchor_cache.cached_rate(chain_id, token)
        });
        let monitor = cx.new(|cx| {
            broadcaster_monitor_gpui::BroadcasterMonitorPane::new(
                self.monitor_state.clone(),
                event_rx,
                &self.chain_ids,
                fee_anchor_lookup,
                window,
                cx,
            )
        });
        let logs = cx.new(|cx| LogsPane::new(logs, window, cx));
        let root = cx.new(|cx| {
            WalletRoot::new(
                self.options.clone(),
                ready.http,
                self.runtime.clone(),
                monitor_state,
                ready.waku,
                public_broadcaster_anchor_cache,
                public_broadcaster_anchor_refresh,
                monitor,
                logs,
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

    fn render_splash(&self, window: &mut Window, cx: &mut Context<'_, Self>) -> gpui::AnyElement {
        let has_error = self.error.is_some();
        let accent = if has_error {
            theme::DANGER
        } else {
            theme::INFO
        };
        let percent = self.progress.percent.unwrap_or(0);
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
            .when(has_error, |this| {
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
            })
            .into_any_element();

        render_wallet_hero_screen(window, card)
            .children(Root::render_notification_layer(window, cx))
            .into_any_element()
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

        render_wallet_window_frame(content, window, titlebar_color)
    }
}

async fn build_wallet_startup(
    options: WalletAppOptions,
    chain_ids: Vec<u64>,
    monitor_state: Shared,
    event_tx: EventTx,
    progress_tx: watch::Sender<WalletNetworkProgress>,
) -> eyre::Result<WalletStartupReady> {
    let http = build_wallet_network_context_with_progress(
        WalletNetworkConfig {
            network_mode: options.network_mode,
            proxy: options.proxy.as_ref(),
            data_dir: &options.db_path,
        },
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
    let waku_config = WakuViewerConfig {
        chain_ids: chain_ids.clone(),
        cluster_id: None,
        shard_id: None,
        doh_endpoint: None,
        max_peers: None,
        peer_connection_timeout: None,
        nwaku_url: None,
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
    tokio::spawn(async move {
        if let Err(error) = spawn_workers(waku_config, worker_waku, monitor_state, event_tx).await {
            tracing::error!(%error, "wallet broadcaster monitor workers failed to start");
        }
    });

    Ok(WalletStartupReady { http, waku })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Activity {
    Wallet,
    Broadcaster,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WalletTab {
    #[default]
    Private,
    Public,
    Activity,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DeliveryMode {
    #[default]
    ManualCalldata,
    PublicBroadcaster,
    SelfBroadcast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryFormKind {
    Send,
    Unshield,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicActionMode {
    Shield,
    Send,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicActionStepStatus {
    NotStarted,
    Pending,
    Done,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicActionStepState {
    step: PublicActionProgressStep,
    status: PublicActionStepStatus,
    tx_hash: Option<Arc<str>>,
    message: Option<Arc<str>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum BroadcasterChoice {
    #[default]
    Random,
    Specific {
        railgun_address: String,
    },
}

struct BroadcasterPickerState {
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    query_input: Entity<InputState>,
    list: Entity<ListState<BroadcasterPickerDelegate>>,
    fee_bonus_popover_open: bool,
}

struct PrivateActionFormState {
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
}

struct PrivateActionDialogContent {
    root: Entity<WalletRoot>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
}

#[derive(Clone, Copy)]
enum PublicAccountDialogKind {
    Derive,
    Import,
    EditLabel,
}

impl PublicAccountDialogKind {
    const fn title(self) -> &'static str {
        match self {
            Self::Derive => "Derive from private",
            Self::Import => "Import private key",
            Self::EditLabel => "Edit account label",
        }
    }
}

struct PublicAccountDialogContent {
    root: Entity<WalletRoot>,
    kind: PublicAccountDialogKind,
    content_width: Pixels,
}

struct PublicActionDialogContent {
    root: Entity<WalletRoot>,
    content_width: Pixels,
}

impl PrivateActionDialogContent {
    fn new(
        root: Entity<WalletRoot>,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self { root, kind, key }
    }
}

impl Render for PrivateActionDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        match self.kind {
            DeliveryFormKind::Send => self
                .root
                .read(cx)
                .render_send_form(self.root.clone(), self.key),
            DeliveryFormKind::Unshield => self
                .root
                .read(cx)
                .render_unshield_form(self.root.clone(), self.key),
        }
    }
}

impl PublicAccountDialogContent {
    fn new(
        root: Entity<WalletRoot>,
        kind: PublicAccountDialogKind,
        content_width: Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            kind,
            content_width,
        }
    }
}

impl Render for PublicAccountDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root.read(cx).render_public_account_dialog_content(
            self.root.clone(),
            self.kind,
            self.content_width,
        )
    }
}

impl PublicActionDialogContent {
    fn new(root: Entity<WalletRoot>, content_width: Pixels, cx: &mut Context<'_, Self>) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for PublicActionDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_public_action_dialog_content(self.root.clone(), self.content_width)
    }
}

struct BroadcasterPickerDialogContent {
    root: Entity<WalletRoot>,
}

impl BroadcasterPickerDialogContent {
    fn new(root: Entity<WalletRoot>, cx: &mut Context<'_, Self>) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self { root }
    }
}

impl Render for BroadcasterPickerDialogContent {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let Some(snapshot) = self
            .root
            .read(cx)
            .broadcaster_picker_dialog_snapshot(window, cx)
        else {
            return div();
        };
        let BroadcasterPickerDialogSnapshot {
            query_input,
            list,
            rows,
            empty_message,
            generating,
            query,
            filtered_count,
            total_count,
            list_height,
            show_all_broadcasters,
            fee_bonus_popover_open,
            kind,
            key,
        } = snapshot;
        list.update(cx, |list, cx| {
            let content = BroadcasterPickerContent {
                rows,
                empty_message,
                generating,
                query,
            };
            if list.delegate_mut().set_content(content, cx) {
                cx.notify();
            }
        });

        let toggle_root = self.root.clone();
        div()
            .w_full()
            .h_full()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_input(&query_input).small().disabled(generating)),
                    )
                    .child(
                        Checkbox::new(delivery_element_id(key, kind, "show-all-broadcasters"))
                            .label("Show all broadcasters")
                            .checked(show_all_broadcasters)
                            .xsmall()
                            .disabled(generating)
                            .on_click(move |checked, _window, cx| {
                                let checked = *checked;
                                toggle_root.update(cx, |root, cx| {
                                    root.set_allow_suspicious_broadcasters(kind, key, checked, cx);
                                });
                            }),
                    ),
            )
            .child(render_broadcaster_picker_header(
                &self.root,
                &query_input,
                filtered_count,
                total_count,
                fee_bonus_popover_open,
            ))
            .child(
                List::new(&list)
                    .p(px(8.0))
                    .h(list_height)
                    .min_h(px(0.0))
                    .w_full()
                    .bg(rgb(theme::SURFACE)),
            )
    }
}

struct RepairCacheDialogContent {
    root: Entity<WalletRoot>,
    content_width: Pixels,
}

impl RepairCacheDialogContent {
    fn new(root: Entity<WalletRoot>, content_width: Pixels, cx: &mut Context<'_, Self>) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for RepairCacheDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_repair_cache_dialog_content(self.content_width)
    }
}

struct AddWalletDialogContent {
    root: Entity<WalletRoot>,
    content_width: Pixels,
}

impl AddWalletDialogContent {
    fn new(root: Entity<WalletRoot>, content_width: Pixels, cx: &mut Context<'_, Self>) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for AddWalletDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_add_wallet_dialog_content(self.root.clone(), self.content_width)
    }
}

#[derive(Clone, PartialEq)]
struct BroadcasterPickerRow {
    railgun_address: String,
    label: String,
    fee_label: String,
    fee_warning: Option<String>,
    reliability: f64,
    selected: bool,
}

#[derive(Clone, PartialEq)]
struct BroadcasterPickerContent {
    rows: Vec<BroadcasterPickerRow>,
    empty_message: SharedString,
    generating: bool,
    query: String,
}

struct BroadcasterPickerDialogSnapshot {
    query_input: Entity<InputState>,
    list: Entity<ListState<BroadcasterPickerDelegate>>,
    rows: Vec<BroadcasterPickerRow>,
    empty_message: SharedString,
    generating: bool,
    query: String,
    filtered_count: usize,
    total_count: usize,
    list_height: Pixels,
    show_all_broadcasters: bool,
    fee_bonus_popover_open: bool,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
}

struct BroadcasterPickerDelegate {
    root: WeakEntity<WalletRoot>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generating: bool,
    rows: Vec<BroadcasterPickerRow>,
    empty_message: SharedString,
    query: String,
    pending_content: Option<BroadcasterPickerContent>,
    last_live_update: Option<Instant>,
    live_update_scheduled: bool,
}

impl BroadcasterPickerDelegate {
    fn new(root: WeakEntity<WalletRoot>, kind: DeliveryFormKind, key: UnshieldAssetKey) -> Self {
        Self {
            root,
            kind,
            key,
            generating: false,
            rows: Vec::new(),
            empty_message: SharedString::from("No broadcasters match this search."),
            query: String::new(),
            pending_content: None,
            last_live_update: None,
            live_update_scheduled: false,
        }
    }

    fn set_content(
        &mut self,
        content: BroadcasterPickerContent,
        cx: &Context<'_, ListState<Self>>,
    ) -> bool {
        if self.current_content_matches(&content) {
            return false;
        }

        if self.should_apply_immediately(&content) {
            self.pending_content = None;
            self.apply_content(content);
            self.last_live_update = Some(Instant::now());
            return true;
        }

        if self.last_live_update.is_some_and(|last_update| {
            last_update.elapsed() >= BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL
        }) {
            self.pending_content = None;
            self.apply_content(content);
            self.last_live_update = Some(Instant::now());
            return true;
        }

        if self.pending_content.as_ref() == Some(&content) {
            return false;
        }

        self.pending_content = Some(content);
        if !self.live_update_scheduled {
            self.live_update_scheduled = true;
            let remaining = self.last_live_update.map_or(
                BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL,
                |last_update| {
                    BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL.saturating_sub(last_update.elapsed())
                },
            );
            cx.spawn(async move |this, cx| {
                cx.background_executor().timer(remaining).await;
                let _ = this.update(cx, |list, cx| {
                    let delegate = list.delegate_mut();
                    delegate.live_update_scheduled = false;
                    let Some(content) = delegate.pending_content.take() else {
                        return;
                    };
                    if !delegate.current_content_matches(&content) {
                        delegate.apply_content(content);
                        delegate.last_live_update = Some(Instant::now());
                        cx.notify();
                    }
                });
            })
            .detach();
        }
        false
    }

    fn current_content_matches(&self, content: &BroadcasterPickerContent) -> bool {
        self.rows == content.rows
            && self.empty_message == content.empty_message
            && self.generating == content.generating
            && self.query == content.query
    }

    fn should_apply_immediately(&self, content: &BroadcasterPickerContent) -> bool {
        self.last_live_update.is_none()
            || self.query != content.query
            || self.generating != content.generating
            || selected_broadcaster_address(&self.rows)
                != selected_broadcaster_address(&content.rows)
    }

    fn apply_content(&mut self, content: BroadcasterPickerContent) {
        self.rows = content.rows;
        self.empty_message = content.empty_message;
        self.generating = content.generating;
        self.query = content.query;
    }
}

fn selected_broadcaster_address(rows: &[BroadcasterPickerRow]) -> Option<&str> {
    rows.iter()
        .find(|row| row.selected)
        .map(|row| row.railgun_address.as_str())
}

impl ListDelegate for BroadcasterPickerDelegate {
    type Item = ListItem;

    fn items_count(&self, _section: usize, _cx: &App) -> usize {
        self.rows.len()
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn render_item(
        &mut self,
        ix: IndexPath,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) -> Option<Self::Item> {
        let row = self.rows.get(ix.row)?.clone();
        let root = self.root.clone();
        let kind = self.kind;
        let key = self.key;
        let selected = row.selected;
        let railgun_address = row.railgun_address.clone();
        Some(
            ListItem::new(SharedString::from(format!(
                "broadcaster-picker-list-row-{}",
                stable_broadcaster_element_suffix(&row.railgun_address)
            )))
            .h(px(64.0))
            .px(px(12.0))
            .py(px(0.0))
            .rounded_md()
            .border_1()
            .border_color(if selected {
                rgb(theme::SUCCESS)
            } else {
                rgb(theme::SURFACE)
            })
            .disabled(self.generating)
            .on_click(move |_event, window, cx| {
                cx.stop_propagation();
                let railgun_address = railgun_address.clone();
                let _ = root.update(cx, |root, cx| {
                    root.choose_broadcaster_from_picker(kind, key, railgun_address, window, cx);
                });
            })
            .child(render_broadcaster_picker_row(&row)),
        )
    }

    fn render_empty(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) -> impl IntoElement {
        div()
            .p(px(16.0))
            .rounded_md()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER))
            .child(app_muted_text(self.empty_message.clone()))
    }

    fn set_selected_index(
        &mut self,
        _ix: Option<IndexPath>,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) {
    }

    fn is_eof(&self, _cx: &App) -> bool {
        false
    }
}

enum SendResult {
    Manual(PreparedSendCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
}

enum UnshieldResult {
    Manual(PreparedUnshieldCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
}

impl WalletTab {
    const ALL: [Self; 3] = [Self::Private, Self::Public, Self::Activity];

    const fn label(self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::Public => "Public",
            Self::Activity => "Activity",
        }
    }

    fn icon_path(self) -> PathBuf {
        match self {
            Self::Private => icons::shield_check_icon_path(),
            Self::Public => icons::globe_icon_path(),
            Self::Activity => icons::activity_icon_path(),
        }
    }

    const fn shows_utxos(self) -> bool {
        matches!(self, Self::Activity)
    }
}

#[derive(Clone)]
struct WalletOption {
    wallet_id: Arc<str>,
    label: Arc<str>,
    source: WalletSource,
}

#[derive(Clone)]
struct WalletSelectItem {
    wallet_id: Arc<str>,
    label: Arc<str>,
}

impl SelectItem for WalletSelectItem {
    type Value = Arc<str>;

    fn title(&self) -> SharedString {
        SharedString::from(self.label.to_string())
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(wallet_label_row(SharedString::from(self.label.to_string())).into_any_element())
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        wallet_label_row(SharedString::from(self.label.to_string()))
    }

    fn value(&self) -> &Self::Value {
        &self.wallet_id
    }

    fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        self.label.to_lowercase().contains(&query) || self.wallet_id.to_lowercase().contains(&query)
    }
}

#[derive(Clone, Copy)]
struct ChainSelectItem {
    chain_id: u64,
}

impl SelectItem for ChainSelectItem {
    type Value = u64;

    fn title(&self) -> SharedString {
        SharedString::from(
            chain_name(self.chain_id).map_or_else(|| self.chain_id.to_string(), str::to_owned),
        )
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(chain_label_row(self.chain_id).into_any_element())
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        chain_label_row(self.chain_id)
    }

    fn value(&self) -> &Self::Value {
        &self.chain_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateActionMetric {
    label: &'static str,
    amount: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CostEstimateStatus {
    Estimating,
}

#[derive(Clone, Eq, PartialEq)]
struct UnshieldAsset {
    chain_id: u64,
    token: Address,
    label: String,
    decimals: Option<u8>,
    total: U256,
    poi_verified_total: U256,
    max_batched: U256,
    icon_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicBroadcasterFeeTokenOption {
    token: Address,
    label: String,
    decimals: Option<u8>,
    max_spendable: U256,
    eligible_broadcaster_count: usize,
    icon_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct UnshieldAssetKey {
    chain_id: u64,
    token: Address,
}

impl UnshieldAssetKey {
    const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }

    const fn from_asset(asset: &UnshieldAsset) -> Self {
        Self::new(asset.chain_id, asset.token)
    }
}

struct UnshieldFormState {
    asset: UnshieldAsset,
    recipient_input: Entity<InputState>,
    amount_input: Entity<InputState>,
    password_input: Entity<InputState>,
    unwrap: bool,
    delivery_mode: DeliveryMode,
    selected_fee_token: Address,
    broadcaster_choice: BroadcasterChoice,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    allow_suspicious_broadcasters: bool,
    transaction_fee_breakdown_open: bool,
    pending_programmatic_amount_input: Option<String>,
    cost_estimate_pending: bool,
    estimating_cost: bool,
    cost_estimate: Option<PublicBroadcasterCostEstimate>,
    estimate_id: u64,
    generation_id: u64,
    generating: bool,
    generation_stage: TransactionGenerationStage,
    error: Option<Arc<str>>,
    result: Option<UnshieldResult>,
}

struct SendFormState {
    asset: UnshieldAsset,
    recipient_input: Entity<InputState>,
    amount_input: Entity<InputState>,
    password_input: Entity<InputState>,
    delivery_mode: DeliveryMode,
    selected_fee_token: Address,
    broadcaster_choice: BroadcasterChoice,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    allow_suspicious_broadcasters: bool,
    transaction_fee_breakdown_open: bool,
    pending_programmatic_amount_input: Option<String>,
    cost_estimate_pending: bool,
    estimating_cost: bool,
    cost_estimate: Option<PublicBroadcasterCostEstimate>,
    estimate_id: u64,
    generation_id: u64,
    generating: bool,
    generation_stage: TransactionGenerationStage,
    error: Option<Arc<str>>,
    result: Option<SendResult>,
}

struct PublicAccountFormState {
    add_label_input: Entity<InputState>,
    add_password_input: Entity<InputState>,
    import_label_input: Entity<InputState>,
    import_private_key_input: Entity<InputState>,
    import_password_input: Entity<InputState>,
    edit_label_input: Entity<InputState>,
    search_input: Entity<InputState>,
    send_recipient_input: Entity<InputState>,
    send_amount_input: Entity<InputState>,
    send_password_input: Entity<InputState>,
    shield_amount_input: Entity<InputState>,
    shield_password_input: Entity<InputState>,
    import_global: bool,
    selected_account_uuid: Option<Arc<str>>,
    editing_account_uuid: Option<Arc<str>>,
    search_query: Arc<str>,
    selected_asset: Option<PublicAssetId>,
    action_mode: PublicActionMode,
    action_generation: u64,
    action_progress: Vec<PublicActionStepState>,
    expanded_action_error_steps: BTreeSet<PublicActionProgressStep>,
    next_derived_index: Option<u32>,
    next_account_label_number: u32,
    error: Option<Arc<str>>,
    send_error: Option<Arc<str>>,
    shield_error: Option<Arc<str>>,
    adding_account: bool,
    importing_account: bool,
    sending: bool,
    shielding: bool,
    active_accounts_open: bool,
    inactive_accounts_open: bool,
    pending_global_delete_uuid: Option<Arc<str>>,
}

enum ChainUtxoState {
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
    const fn snapshot(&self) -> Option<&Arc<ListUtxosOutput>> {
        match self {
            Self::Syncing { snapshot, .. } | Self::Ready { snapshot, .. } => Some(snapshot),
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => None,
        }
    }

    const fn progress(&self) -> Option<SyncProgressUpdate> {
        match self {
            Self::Loading { progress } | Self::Syncing { progress, .. } => *progress,
            Self::Idle | Self::Ready { .. } | Self::Error { .. } => None,
        }
    }

    fn start_block(&self) -> Option<u64> {
        match self {
            Self::Syncing { session, .. } | Self::Ready { session, .. } => {
                Some(session.start_block)
            }
            Self::Error { start_block, .. } => *start_block,
            Self::Idle | Self::Loading { .. } => None,
        }
    }

    const fn renders_table(&self) -> bool {
        matches!(
            self,
            Self::Loading { .. } | Self::Syncing { .. } | Self::Ready { .. }
        )
    }

    const fn is_syncing(&self) -> bool {
        matches!(self, Self::Loading { .. } | Self::Syncing { .. })
    }

    const fn poi_refreshing(&self) -> bool {
        match self {
            Self::Syncing { poi_refreshing, .. } | Self::Ready { poi_refreshing, .. } => {
                *poi_refreshing
            }
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => false,
        }
    }

    fn poi_refresh_session(&self) -> Option<Arc<wallet_ops::WalletSession>> {
        match self {
            Self::Syncing { session, .. } | Self::Ready { session, .. } => Some(session.clone()),
            Self::Idle | Self::Loading { .. } | Self::Error { .. } => None,
        }
    }
}

enum VaultState {
    CreateVault,
    UnlockVault,
    SetupWallet,
    ViewUnlocked,
    Error(Arc<str>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WalletSetupMode {
    Choose,
    GeneratedReview,
    Import,
}

#[derive(Clone, Copy)]
enum UtxoNavigation {
    PageUp,
    PageDown,
    Home,
    End,
}

#[derive(Clone)]
struct ChainLoadOverrides {
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rewind_wallet_cache: bool,
}

const fn chain_load_overrides() -> ChainLoadOverrides {
    ChainLoadOverrides {
        init_block_number: None,
        sync_to_block: None,
        use_indexed_wallet_catch_up: true,
        rewind_wallet_cache: false,
    }
}

fn wallet_options_from_metadata(mut metadata: Vec<WalletMetadataBundle>) -> Vec<WalletOption> {
    metadata.retain(|metadata| metadata.status == WalletStatus::Active);
    sort_wallet_metadata(&mut metadata);
    metadata
        .into_iter()
        .map(|metadata| WalletOption {
            wallet_id: Arc::from(metadata.wallet_uuid),
            label: Arc::from(metadata.label),
            source: metadata.source,
        })
        .collect()
}

fn wallet_generation_matches(
    selected_wallet_id: Option<&str>,
    active_wallet_generation: u64,
    wallet_id: &str,
    generation: u64,
) -> bool {
    active_wallet_generation == generation && selected_wallet_id == Some(wallet_id)
}

pub(crate) struct WalletRoot {
    options: WalletAppOptions,
    vault_store: Option<Arc<DesktopVaultStore>>,
    vault_state: VaultState,
    wallet_setup_mode: WalletSetupMode,
    vault_error: Option<Arc<str>>,
    unlock_in_progress: bool,
    repair_cache_error: Option<Arc<str>>,
    setup_password: Option<Zeroizing<String>>,
    view_session: Option<Arc<DesktopViewSession>>,
    generated_seed: Option<GeneratedSeedMaterial>,
    http: HttpContext,
    network_health: WalletNetworkHealth,
    network_status_popover_open: bool,
    network_status_error: Option<Arc<str>>,
    tor_exit_ip_query: TorExitIpQueryState,
    tor_state_reset_confirming: bool,
    runtime: Handle,
    monitor_state: Shared,
    waku: Arc<PublicBroadcasterWakuClient>,
    public_broadcaster_anchor_cache: Arc<TokenAnchorRateCache>,
    public_broadcaster_anchor_refresh: TokenAnchorRefreshHandle,
    monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
    logs: Entity<LogsPane>,
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    sidebar_manually_collapsed: bool,
    sidebar_narrow_expanded: bool,
    wallet_select: Entity<SelectState<SearchableVec<WalletSelectItem>>>,
    wallet_metadata: Vec<WalletMetadataBundle>,
    wallet_options: Vec<WalletOption>,
    selected_wallet_id: Option<Arc<str>>,
    active_wallet_generation: u64,
    wallet_switch_generation: u64,
    selected_chain: u64,
    chain_select: Entity<SelectState<Vec<ChainSelectItem>>>,
    chain_states: BTreeMap<u64, ChainUtxoState>,
    session_store: Arc<OnceCell<Arc<WalletSessionStore>>>,
    unlock_password_input: Entity<InputState>,
    new_password_input: Entity<InputState>,
    confirm_password_input: Entity<InputState>,
    wallet_name_input: Entity<InputState>,
    add_wallet_password_input: Entity<InputState>,
    import_mnemonic_input: Entity<InputState>,
    public_accounts: Vec<PublicAccountMetadata>,
    public_form: PublicAccountFormState,
    public_balance_snapshot: Option<Arc<PublicBalanceSnapshot>>,
    public_balance_error: Option<Arc<str>>,
    public_balance_refreshing: bool,
    public_balance_generation: u64,
    public_inactive_balance_error: Option<Arc<str>>,
    public_inactive_balance_refreshing: bool,
    public_inactive_balance_generation: u64,
    send_forms: BTreeMap<UnshieldAssetKey, SendFormState>,
    private_action_form: Option<PrivateActionFormState>,
    send_generation_seq: u64,
    unshield_generation_seq: u64,
    cost_estimate_seq: u64,
    unshield_forms: BTreeMap<UnshieldAssetKey, UnshieldFormState>,
    broadcaster_picker: Option<BroadcasterPickerState>,
    unshield_spinner_tick: usize,
    repair_cache_block_input: Entity<InputState>,
    tx_search_input: Entity<InputState>,
    tx_search_query: Arc<str>,
    show_spent_utxos: bool,
    utxo_table: Entity<TableState<UtxoDelegate>>,
    focus_vault_input_on_render: bool,
    focus_utxo_table_on_render: bool,
    focus_public_account_search_on_render: bool,
    logs_open: bool,
    drawer_split: Entity<ResizableState>,
}

impl WalletRoot {
    fn new(
        options: WalletAppOptions,
        http: HttpContext,
        runtime: Handle,
        monitor_state: Shared,
        waku: Arc<PublicBroadcasterWakuClient>,
        public_broadcaster_anchor_cache: Arc<TokenAnchorRateCache>,
        public_broadcaster_anchor_refresh: TokenAnchorRefreshHandle,
        monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
        logs: Entity<LogsPane>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let chain_ids = DEFAULT_CHAINS.to_vec();
        let chain_select_items: Vec<_> = chain_ids
            .iter()
            .copied()
            .map(|chain_id| ChainSelectItem { chain_id })
            .collect();
        let initial_chain_id = DEFAULT_CHAINS[0];
        let selected_chain_index = Some(IndexPath::default().row(0));
        let mut chain_states = BTreeMap::new();
        for chain_id in &chain_ids {
            chain_states.insert(*chain_id, ChainUtxoState::Idle);
        }
        let vault_store = match DesktopVaultStore::open(options.db_path.clone()) {
            Ok(store) => Some(Arc::new(store)),
            Err(error) => {
                tracing::error!(%error, "failed to open desktop wallet vault store");
                None
            }
        };
        let (vault_state, vault_error) = match vault_store.as_ref() {
            Some(store) => match store.vault_exists() {
                Ok(true) => (VaultState::UnlockVault, None),
                Ok(false) => (VaultState::CreateVault, None),
                Err(error) => (
                    VaultState::Error(Arc::from("Failed to inspect wallet vault storage")),
                    Some(Arc::from(error.to_string())),
                ),
            },
            None => (
                VaultState::Error(Arc::from("Failed to open wallet vault storage")),
                None,
            ),
        };
        let focus_vault_input_on_render = matches!(
            vault_state,
            VaultState::CreateVault | VaultState::UnlockVault
        );
        let unlock_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        let new_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("new vault password")
                .masked(true)
        });
        let confirm_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("confirm vault password")
                .masked(true)
        });
        let wallet_name_input = cx.new(|cx| InputState::new(window, cx).placeholder("wallet name"));
        let add_wallet_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        let import_mnemonic_input = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(3, 6)
                .placeholder("paste recovery phrase")
        });
        let public_account_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search accounts"));
        let public_form = PublicAccountFormState {
            add_label_input: cx.new(|cx| InputState::new(window, cx).placeholder("account label")),
            add_password_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("vault password")
                    .masked(true)
            }),
            import_label_input: cx
                .new(|cx| InputState::new(window, cx).placeholder("account label")),
            import_private_key_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("private key hex")
                    .masked(true)
            }),
            import_password_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("vault password")
                    .masked(true)
            }),
            edit_label_input: cx.new(|cx| InputState::new(window, cx).placeholder("account label")),
            search_input: public_account_search_input.clone(),
            send_recipient_input: cx
                .new(|cx| InputState::new(window, cx).placeholder("0x recipient")),
            send_amount_input: cx.new(|cx| InputState::new(window, cx).placeholder("amount")),
            send_password_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("vault password")
                    .masked(true)
            }),
            shield_amount_input: cx.new(|cx| InputState::new(window, cx).placeholder("amount")),
            shield_password_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("vault password")
                    .masked(true)
            }),
            import_global: false,
            selected_account_uuid: None,
            editing_account_uuid: None,
            search_query: Arc::from(""),
            selected_asset: None,
            action_mode: PublicActionMode::Shield,
            action_generation: 0,
            action_progress: Vec::new(),
            expanded_action_error_steps: BTreeSet::new(),
            next_derived_index: None,
            next_account_label_number: 1,
            error: None,
            send_error: None,
            shield_error: None,
            adding_account: false,
            importing_account: false,
            sending: false,
            shielding: false,
            active_accounts_open: true,
            inactive_accounts_open: false,
            pending_global_delete_uuid: None,
        };
        let repair_cache_block_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("0 = deployment block"));
        let tx_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search tx hash"));
        let chain_select =
            cx.new(|cx| SelectState::new(chain_select_items, selected_chain_index, window, cx));
        let wallet_select = cx.new(|cx| {
            SelectState::new(SearchableVec::new(Vec::new()), None, window, cx).searchable(true)
        });
        let utxo_table =
            cx.new(|cx| TableState::new(UtxoDelegate::new(tx_search_input.clone()), window, cx));
        let network_health = http.network_health();
        let root = Self {
            selected_chain: initial_chain_id,
            options,
            vault_store,
            vault_state,
            wallet_setup_mode: WalletSetupMode::Choose,
            vault_error,
            unlock_in_progress: false,
            repair_cache_error: None,
            setup_password: None,
            view_session: None,
            generated_seed: None,
            http,
            network_health,
            network_status_popover_open: false,
            network_status_error: None,
            tor_exit_ip_query: TorExitIpQueryState::Idle,
            tor_state_reset_confirming: false,
            runtime,
            monitor_state,
            waku,
            public_broadcaster_anchor_cache,
            public_broadcaster_anchor_refresh,
            monitor,
            logs,
            active_activity: Activity::Wallet,
            active_wallet_tab: WalletTab::default(),
            sidebar_manually_collapsed: false,
            sidebar_narrow_expanded: false,
            wallet_select: wallet_select.clone(),
            wallet_metadata: Vec::new(),
            wallet_options: Vec::new(),
            selected_wallet_id: None,
            active_wallet_generation: 0,
            wallet_switch_generation: 0,
            chain_select: chain_select.clone(),
            chain_states,
            session_store: Arc::new(OnceCell::new()),
            unlock_password_input,
            new_password_input,
            confirm_password_input,
            wallet_name_input,
            add_wallet_password_input,
            import_mnemonic_input,
            public_accounts: Vec::new(),
            public_form,
            public_balance_snapshot: None,
            public_balance_error: None,
            public_balance_refreshing: false,
            public_balance_generation: 0,
            public_inactive_balance_error: None,
            public_inactive_balance_refreshing: false,
            public_inactive_balance_generation: 0,
            send_forms: BTreeMap::new(),
            private_action_form: None,
            send_generation_seq: 0,
            unshield_generation_seq: 0,
            cost_estimate_seq: 0,
            unshield_forms: BTreeMap::new(),
            broadcaster_picker: None,
            unshield_spinner_tick: 0,
            repair_cache_block_input,
            tx_search_input: tx_search_input.clone(),
            tx_search_query: Arc::from(""),
            show_spent_utxos: false,
            utxo_table,
            focus_vault_input_on_render,
            focus_utxo_table_on_render: false,
            focus_public_account_search_on_render: false,
            logs_open: false,
            drawer_split: cx.new(|_| ResizableState::default()),
        };
        cx.subscribe(&tx_search_input, |this, input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                let query = input.read(cx).value().trim().to_ascii_lowercase();
                this.tx_search_query = Arc::from(query);
                this.sync_utxo_table(cx);
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(
            &public_account_search_input,
            |this, input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    let query = input.read(cx).value().trim().to_ascii_lowercase();
                    this.public_form.search_query = Arc::from(query);
                    cx.notify();
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &chain_select,
            window,
            |this, _select, event: &SelectEvent<Vec<ChainSelectItem>>, window, cx| {
                let SelectEvent::Confirm(Some(chain_id)) = event else {
                    return;
                };
                this.select_chain(*chain_id, window, cx);
                cx.defer_in(window, |_this, window, _cx| {
                    window.blur();
                });
            },
        )
        .detach();
        cx.subscribe_in(
            &wallet_select,
            window,
            |this, _select, event: &SelectEvent<SearchableVec<WalletSelectItem>>, window, cx| {
                let SelectEvent::Confirm(Some(value)) = event else {
                    return;
                };
                this.select_wallet(value.as_ref(), window, cx);
                cx.defer_in(window, |_this, window, _cx| {
                    window.blur();
                });
            },
        )
        .detach();
        cx.subscribe_in(
            &root.unlock_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.unlock_vault_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.new_password_input,
            window,
            |this, input, event: &InputEvent, window, cx| {
                if !matches!(event, InputEvent::PressEnter { .. }) {
                    return;
                }
                let password_entered = !input.read(cx).value().trim().is_empty();
                let confirm_empty = this
                    .confirm_password_input
                    .read(cx)
                    .value()
                    .trim()
                    .is_empty();
                if password_entered && confirm_empty {
                    this.confirm_password_input
                        .read(cx)
                        .focus_handle(cx)
                        .focus(window);
                } else {
                    this.create_vault_from_inputs(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.confirm_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.create_vault_from_inputs(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &root.repair_cache_block_input,
            |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.repair_wallet_cache_from_input(cx);
                }
            },
        )
        .detach();
        cx.subscribe(&root.utxo_table, |_, table, event: &TableEvent, cx| {
            if let TableEvent::ColumnWidthsChanged(widths) = event {
                table.update(cx, |table, cx| {
                    table.delegate_mut().set_column_widths(widths);
                    cx.notify();
                });
            }
        })
        .detach();
        cx.subscribe_in(
            &root.public_form.add_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.add_public_derived_account_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.import_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.import_public_account_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.edit_label_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.update_selected_public_account_label(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.send_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.submit_public_send_from_form(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.shield_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.submit_public_shield_from_form(window, cx);
                }
            },
        )
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(UTXO_AGE_REFRESH_INTERVAL)
                    .await;
                if this
                    .update(cx, |root, cx| {
                        if matches!(
                            root.chain_states.get(&root.selected_chain),
                            Some(state) if state.snapshot().is_some()
                        ) {
                            root.utxo_table.update(cx, |_table, cx| cx.notify());
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(UNSHIELD_SPINNER_REFRESH_INTERVAL)
                    .await;
                if this
                    .update(cx, |root, cx| {
                        if root.send_forms.values().any(|form| {
                            form.generating || form.cost_estimate_pending || form.estimating_cost
                        }) || root.unshield_forms.values().any(|form| {
                            form.generating || form.cost_estimate_pending || form.estimating_cost
                        }) {
                            root.unshield_spinner_tick = root.unshield_spinner_tick.wrapping_add(1);
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            let interval = Duration::from_secs(public_balance_refresh_interval_secs());
            loop {
                cx.background_executor().timer(interval).await;
                if this
                    .update(cx, |root, cx| {
                        if root.active_wallet_tab == WalletTab::Public {
                            root.schedule_public_balance_refresh(cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        root.spawn_network_health_monitor(cx);
        root
    }

    fn spawn_network_health_monitor(&self, cx: &Context<'_, Self>) {
        if self.http.network_mode() != WalletNetworkMode::Tor {
            return;
        }

        let http = self.http.clone();
        let runtime = self.runtime.clone();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(NETWORK_HEALTH_REFRESH_INTERVAL)
                    .await;
                let health = http.network_health();
                let Ok(should_retry) = this.update(cx, |root, cx| {
                    let should_retry = health.state != WalletNetworkHealthState::Ready;
                    root.set_network_health(health, cx);
                    should_retry
                }) else {
                    break;
                };

                if should_retry {
                    retry_tor_bootstrap(&http, &runtime).await;
                    let health = http.network_health();
                    if this
                        .update(cx, |root, cx| root.set_network_health(health, cx))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        })
        .detach();
    }

    fn set_network_health(&mut self, health: WalletNetworkHealth, cx: &mut Context<'_, Self>) {
        if self.network_health != health {
            self.network_health = health;
            cx.notify();
        }
    }

    fn set_network_status_popover_open(&mut self, open: bool, cx: &mut Context<'_, Self>) {
        if !open {
            self.network_status_error = None;
            self.tor_exit_ip_query = TorExitIpQueryState::Idle;
            self.tor_state_reset_confirming = false;
        }
        if self.network_status_popover_open != open {
            self.network_status_popover_open = open;
            cx.notify();
        } else if !open {
            cx.notify();
        }
    }

    fn start_new_tor_session(&mut self, cx: &mut Context<'_, Self>) {
        match self.http.start_new_tor_session() {
            Ok(generation) => {
                let waku_refreshed = self.waku.refresh_network_session();
                tracing::info!(
                    tor_session_generation = generation,
                    waku_refreshed,
                    "started new Tor session"
                );
                self.network_status_error = None;
                self.tor_exit_ip_query = TorExitIpQueryState::Idle;
                self.network_health = self.http.network_health();
            }
            Err(error) => {
                tracing::warn!(%error, "failed to start new Tor session");
                self.network_status_error = Some(Arc::from(format_report_chain(&error)));
            }
        }
        cx.notify();
    }

    fn query_tor_exit_ip(&mut self, cx: &mut Context<'_, Self>) {
        if self.http.network_mode() != WalletNetworkMode::Tor
            || matches!(self.tor_exit_ip_query, TorExitIpQueryState::Querying)
        {
            return;
        }

        self.network_status_error = None;
        self.tor_exit_ip_query = TorExitIpQueryState::Querying;
        cx.notify();

        let Some(proxy_url) = self.http.proxy_url.clone() else {
            self.tor_exit_ip_query = TorExitIpQueryState::Error(Arc::from(
                "Exit IP query requires the built-in Tor SOCKS bridge",
            ));
            cx.notify();
            return;
        };
        let query = self
            .runtime
            .spawn(async move { query_exit_ip_through_tor(proxy_url).await });
        cx.spawn(async move |this, cx| {
            let state = match query.await {
                Ok(Ok(ip)) => TorExitIpQueryState::Success(ip),
                Ok(Err(error)) => {
                    TorExitIpQueryState::Error(Arc::from(format_report_chain(&error)))
                }
                Err(error) => TorExitIpQueryState::Error(Arc::from(format!(
                    "Exit IP query task failed: {error}"
                ))),
            };
            let _ = this.update(cx, |root, cx| {
                root.tor_exit_ip_query = state;
                cx.notify();
            });
        })
        .detach();
    }

    fn begin_tor_state_reset_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.network_status_error = None;
        self.tor_exit_ip_query = TorExitIpQueryState::Idle;
        self.tor_state_reset_confirming = true;
        cx.notify();
    }

    fn cancel_tor_state_reset_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.tor_state_reset_confirming = false;
        cx.notify();
    }

    fn quit_and_reset_tor_state(&mut self, cx: &mut Context<'_, Self>) {
        match request_tor_state_reset(&self.options.db_path) {
            Ok(marker_path) => {
                tracing::warn!(
                    marker_path = %marker_path.display(),
                    "requested Tor state reset on next wallet startup; quitting wallet"
                );
                cx.quit();
            }
            Err(error) => {
                tracing::warn!(%error, "failed to request Tor state reset");
                self.network_status_error = Some(Arc::from(format_report_chain(&error)));
                self.tor_state_reset_confirming = false;
                cx.notify();
            }
        }
    }

    fn set_wallet_name_input(&self, value: &str, window: &mut Window, cx: &mut Context<'_, Self>) {
        let value = value.to_owned();
        self.wallet_name_input
            .update(cx, |input, cx| input.set_value(&value, window, cx));
    }

    fn set_default_wallet_name_from_password(
        &self,
        password: &str,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let label = self
            .vault_store
            .as_ref()
            .and_then(|store| store.default_wallet_label(password).ok())
            .unwrap_or_else(|| PRIMARY_WALLET_LABEL.to_owned());
        Self::defer_wallet_name_input(label, window, cx);
    }

    fn defer_wallet_name_input(value: String, window: &Window, cx: &mut Context<'_, Self>) {
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&value, window, cx);
        });
    }

    fn selected_wallet_source(&self) -> WalletSource {
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

    fn selected_chain_wallet_start_block(&self) -> Option<u64> {
        self.chain_states
            .get(&self.selected_chain)
            .and_then(ChainUtxoState::start_block)
    }

    fn is_active_wallet_generation(&self, wallet_id: &str, generation: u64) -> bool {
        wallet_generation_matches(
            self.selected_wallet_id.as_deref(),
            self.active_wallet_generation,
            wallet_id,
            generation,
        )
    }

    fn reset_wallet_scoped_state(&mut self, cx: &mut Context<'_, Self>) {
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
        self.broadcaster_picker = None;
        self.active_wallet_tab = WalletTab::default();
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
    }

    fn clear_public_wallet_runtime_state(&mut self) {
        self.public_accounts.clear();
        self.public_balance_snapshot = None;
        self.public_balance_error = None;
        self.public_balance_refreshing = false;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_refreshing = false;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        self.public_form.selected_account_uuid = None;
        self.public_form.editing_account_uuid = None;
        self.public_form.selected_asset = None;
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.next_derived_index = None;
        self.public_form.next_account_label_number = 1;
        self.public_form.error = None;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.public_form.adding_account = false;
        self.public_form.importing_account = false;
        self.public_form.sending = false;
        self.public_form.shielding = false;
        self.public_form.active_accounts_open = true;
        self.public_form.inactive_accounts_open = false;
        self.public_form.pending_global_delete_uuid = None;
    }

    fn reset_public_wallet_state(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        self.clear_public_wallet_runtime_state();
        for input in [
            &self.public_form.add_label_input,
            &self.public_form.add_password_input,
            &self.public_form.import_label_input,
            &self.public_form.import_private_key_input,
            &self.public_form.import_password_input,
            &self.public_form.edit_label_input,
            &self.public_form.send_recipient_input,
            &self.public_form.send_amount_input,
            &self.public_form.send_password_input,
            &self.public_form.shield_amount_input,
            &self.public_form.shield_password_input,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.public_form.import_global = false;
        self.public_form.action_mode = PublicActionMode::Shield;
    }

    fn clear_public_account_dialog_inputs(
        &mut self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let default_label =
            public_account_default_label(self.public_form.next_account_label_number);
        match kind {
            PublicAccountDialogKind::Derive => {
                self.public_form
                    .add_label_input
                    .update(cx, |input, cx| input.set_value(&default_label, window, cx));
                self.public_form
                    .add_password_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
            PublicAccountDialogKind::Import => {
                self.public_form
                    .import_label_input
                    .update(cx, |input, cx| input.set_value(&default_label, window, cx));
                self.public_form
                    .import_private_key_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form
                    .import_password_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form.import_global = false;
            }
            PublicAccountDialogKind::EditLabel => {
                self.public_form.editing_account_uuid = None;
                self.public_form
                    .edit_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
        }
    }

    fn reload_public_accounts(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let Some(store) = self.vault_store.as_ref() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            return;
        };
        let Some(view_session) = self.view_session.as_ref() else {
            self.public_accounts.clear();
            self.public_form.selected_account_uuid = None;
            return;
        };
        match store.list_public_accounts_for_session(view_session.as_ref(), true) {
            Ok(accounts) => {
                self.public_form.next_account_label_number =
                    next_public_account_label_number(accounts.len());
                let selected = self
                    .public_form
                    .selected_account_uuid
                    .as_ref()
                    .filter(|selected| {
                        accounts.iter().any(|account| {
                            account.public_account_uuid.as_str() == selected.as_ref()
                        })
                    })
                    .cloned()
                    .or_else(|| {
                        accounts
                            .iter()
                            .find(|account| account.status == PublicAccountStatus::Active)
                            .map(|account| Arc::from(account.public_account_uuid.as_str()))
                    });
                self.public_accounts = accounts;
                self.public_form.selected_account_uuid = selected;
                self.public_form.next_derived_index = store
                    .next_derived_public_account_index_for_session(view_session.as_ref())
                    .ok();
                self.sync_public_edit_label_input(window, cx);
            }
            Err(error) => {
                tracing::warn!(
                    error_kind = vault_error_kind(&error),
                    "load public accounts failed"
                );
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
    }

    fn sync_public_edit_label_input(&self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let account_uuid = self
            .public_form
            .editing_account_uuid
            .as_ref()
            .or(self.public_form.selected_account_uuid.as_ref());
        let label = self
            .public_account_for_uuid(account_uuid.map(AsRef::as_ref))
            .and_then(|account| account.label.clone())
            .unwrap_or_default();
        self.public_form
            .edit_label_input
            .update(cx, |input, cx| input.set_value(&label, window, cx));
    }

    fn selected_public_account(&self) -> Option<&PublicAccountMetadata> {
        self.public_account_for_uuid(
            self.public_form
                .selected_account_uuid
                .as_ref()
                .map(AsRef::as_ref),
        )
    }

    fn public_account_for_uuid(
        &self,
        public_account_uuid: Option<&str>,
    ) -> Option<&PublicAccountMetadata> {
        let selected = public_account_uuid?;
        self.public_accounts
            .iter()
            .find(|account| account.public_account_uuid == selected)
    }

    fn set_public_selected_balance(
        &mut self,
        public_account_uuid: Arc<str>,
        asset: PublicAssetId,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.public_form.selected_account_uuid = Some(public_account_uuid);
        self.public_form.selected_asset = Some(asset);
        self.public_form.pending_global_delete_uuid = None;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.sync_public_edit_label_input(window, cx);
        cx.notify();
    }

    fn clear_public_action_dialog_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        for input in [
            &self.public_form.send_recipient_input,
            &self.public_form.send_amount_input,
            &self.public_form.send_password_input,
            &self.public_form.shield_amount_input,
            &self.public_form.shield_password_input,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        if !self.public_form.sending && !self.public_form.shielding {
            self.public_form.action_progress.clear();
            self.public_form.expanded_action_error_steps.clear();
        }
    }

    fn selected_public_balance_entry(&self) -> Option<PublicBalanceEntry> {
        let public_account_uuid = self.public_form.selected_account_uuid.as_deref()?;
        let asset = self.public_form.selected_asset?;
        let status = self
            .public_account_for_uuid(Some(public_account_uuid))?
            .status;
        self.public_balance_entry(public_account_uuid, asset, status)
    }

    fn public_balance_entry(
        &self,
        public_account_uuid: &str,
        asset: PublicAssetId,
        status: PublicAccountStatus,
    ) -> Option<PublicBalanceEntry> {
        public_balance_entry_for_chain(
            self.public_balance_snapshot.as_deref(),
            self.selected_chain,
            public_account_uuid,
            asset,
            status,
        )
    }

    fn set_public_action_mode(
        &mut self,
        mode: PublicActionMode,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_mode == mode {
            return;
        }
        self.public_form.action_mode = mode;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
        cx.notify();
    }

    fn start_public_action_progress(
        &mut self,
        mode: PublicActionMode,
        asset: PublicAssetId,
    ) -> u64 {
        self.public_form.action_generation = self.public_form.action_generation.wrapping_add(1);
        let generation = self.public_form.action_generation;
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.action_progress = public_action_progress_steps(mode, asset)
            .into_iter()
            .map(|step| PublicActionStepState {
                step,
                status: PublicActionStepStatus::NotStarted,
                tx_hash: None,
                message: None,
            })
            .collect();
        if let Some(first) = self.public_form.action_progress.first_mut() {
            first.status = PublicActionStepStatus::Pending;
        }
        generation
    }

    fn apply_public_action_progress_update(
        &mut self,
        generation: u64,
        update: PublicActionProgressUpdate,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation {
            return;
        }
        let Some(step) = self
            .public_form
            .action_progress
            .iter_mut()
            .find(|step| step.step == update.step)
        else {
            return;
        };
        step.status = match update.status {
            PublicActionProgressStatus::Pending => PublicActionStepStatus::Pending,
            PublicActionProgressStatus::Done => PublicActionStepStatus::Done,
            PublicActionProgressStatus::Error => PublicActionStepStatus::Error,
        };
        if let Some(tx_hash) = update.tx_hash {
            step.tx_hash = Some(Arc::from(tx_hash));
        }
        if let Some(message) = update.message {
            step.message = Some(Arc::from(message));
        } else if update.status != PublicActionProgressStatus::Error {
            step.message = None;
        }
        cx.notify();
    }

    fn fail_public_action_progress(
        &mut self,
        generation: u64,
        message: String,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation {
            return;
        }
        if let Some(step) = self
            .public_form
            .action_progress
            .iter_mut()
            .find(|step| step.status == PublicActionStepStatus::Error)
        {
            let replace_message = match step.message.as_ref() {
                Some(existing) => message.len() > existing.len(),
                None => true,
            };
            if replace_message {
                step.message = Some(Arc::from(message));
            }
            cx.notify();
            return;
        }
        let step_index = self
            .public_form
            .action_progress
            .iter()
            .position(|step| step.status == PublicActionStepStatus::Pending)
            .or_else(|| {
                self.public_form
                    .action_progress
                    .iter()
                    .position(|step| step.status == PublicActionStepStatus::NotStarted)
            })
            .or_else(|| self.public_form.action_progress.len().checked_sub(1));
        if let Some(step_index) = step_index {
            let step = &mut self.public_form.action_progress[step_index];
            step.status = PublicActionStepStatus::Error;
            step.message = Some(Arc::from(message));
            cx.notify();
        }
    }

    fn spawn_public_action_progress_listener(
        generation: u64,
        chain_id: u64,
        active_wallet_id: Option<Arc<str>>,
        mut progress_rx: mpsc::UnboundedReceiver<PublicActionProgressUpdate>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while let Some(update) = progress_rx.recv().await {
                let _ = this.update(cx, |root, cx| {
                    if root.selected_wallet_id != active_wallet_id
                        || root.selected_chain != chain_id
                    {
                        return;
                    }
                    root.apply_public_action_progress_update(generation, update, cx);
                });
            }
        })
        .detach();
    }

    fn set_public_action_error_details_open(
        &mut self,
        step: PublicActionProgressStep,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        if open {
            self.public_form.expanded_action_error_steps.insert(step);
        } else {
            self.public_form.expanded_action_error_steps.remove(&step);
        }
        cx.notify();
    }

    fn set_public_action_amount_to_max(
        &mut self,
        mode: PublicActionMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(entry) = self.selected_public_balance_entry() else {
            return;
        };
        let Some(amount) = entry.amount.amount() else {
            return;
        };
        let decimals = entry.asset.decimals;
        if entry.asset.id != PublicAssetId::Native {
            self.set_public_action_amount_input(mode, amount, decimals, window, cx);
            self.set_public_action_error(mode, None);
            cx.notify();
            return;
        }

        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            return;
        };
        let chain_id = self.selected_chain;
        let selected_wallet_id = self.selected_wallet_id.clone();
        let symbol = entry.asset.symbol;
        let http = self.http.clone();
        let steps = public_action_progress_steps(mode, PublicAssetId::Native);
        let join = self.runtime.spawn(async move {
            estimate_public_native_action_gas_reserve(chain_id, &steps, &http).await
        });
        self.set_public_action_error(mode, None);
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if root.selected_wallet_id != selected_wallet_id
                    || root.selected_chain != chain_id
                    || root.public_form.action_mode != mode
                    || root.public_form.selected_asset != Some(PublicAssetId::Native)
                    || root.public_form.selected_account_uuid.as_deref()
                        != Some(public_account_uuid.as_ref())
                {
                    return;
                }
                match result {
                    Ok(Ok(reserve)) => {
                        match public_action_max_amount_after_reserve(amount, reserve) {
                            Some(max_amount) => {
                                root.set_public_action_amount_input(
                                    mode, max_amount, decimals, window, cx,
                                );
                                root.set_public_action_error(mode, None);
                            }
                            None => root.set_public_action_error(
                                mode,
                                Some(Arc::from(format!(
                                    "Not enough {symbol} balance after estimated gas"
                                ))),
                            ),
                        }
                    }
                    Ok(Err(error)) => root.set_public_action_error(
                        mode,
                        Some(Arc::from(format!(
                            "Could not estimate gas reserve for Max: {}",
                            format_report_chain(&error)
                        ))),
                    ),
                    Err(error) => root.set_public_action_error(
                        mode,
                        Some(Arc::from(format!(
                            "Could not estimate gas reserve for Max: {error}"
                        ))),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn set_public_action_amount_input(
        &self,
        mode: PublicActionMode,
        amount: U256,
        decimals: u8,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let value = format_send_amount_input(amount, Some(decimals));
        let input = match mode {
            PublicActionMode::Shield => &self.public_form.shield_amount_input,
            PublicActionMode::Send => &self.public_form.send_amount_input,
        };
        input.update(cx, |input, cx| input.set_value(value, window, cx));
    }

    fn set_public_action_error(&mut self, mode: PublicActionMode, message: Option<Arc<str>>) {
        match mode {
            PublicActionMode::Shield => self.public_form.shield_error = message,
            PublicActionMode::Send => self.public_form.send_error = message,
        }
    }

    fn clear_public_chain_balance_state(&mut self) {
        self.public_balance_snapshot = None;
        self.public_balance_error = None;
        self.public_balance_refreshing = false;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_refreshing = false;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        self.public_form.selected_asset = None;
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
    }

    fn set_public_account_section_open(
        &mut self,
        status: PublicAccountStatus,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let current = match status {
            PublicAccountStatus::Active => &mut self.public_form.active_accounts_open,
            PublicAccountStatus::Inactive => &mut self.public_form.inactive_accounts_open,
        };
        if *current != open {
            *current = open;
            cx.notify();
        }
    }

    fn has_active_public_accounts(&self) -> bool {
        self.public_accounts
            .iter()
            .any(|account| account.status == PublicAccountStatus::Active)
    }

    fn schedule_public_balance_refresh(&mut self, cx: &mut Context<'_, Self>) {
        let accounts = self
            .public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect::<Vec<_>>();
        if self.public_balance_refreshing || accounts.is_empty() {
            return;
        }
        let chain_id = self.selected_chain;
        let account_ids = accounts
            .iter()
            .map(|account| account.public_account_uuid.clone())
            .collect::<Vec<_>>();
        let http = self.http.clone();
        self.public_balance_refreshing = true;
        self.public_balance_error = None;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        let generation = self.public_balance_generation;
        let active_wallet_id = self.selected_wallet_id.clone();
        let join = self
            .runtime
            .spawn(async move { refresh_public_balances(chain_id, &accounts, &http).await });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.public_balance_generation != generation {
                    return;
                }
                root.public_balance_refreshing = false;
                let current_account_ids = root
                    .public_accounts
                    .iter()
                    .filter(|account| account.status == PublicAccountStatus::Active)
                    .map(|account| account.public_account_uuid.as_str())
                    .collect::<Vec<_>>();
                let account_set_unchanged = current_account_ids.len() == account_ids.len()
                    && current_account_ids
                        .into_iter()
                        .eq(account_ids.iter().map(String::as_str));
                if root.selected_wallet_id != active_wallet_id
                    || root.selected_chain != chain_id
                    || !account_set_unchanged
                {
                    if root.active_wallet_tab == WalletTab::Public
                        && root.has_active_public_accounts()
                    {
                        root.schedule_public_balance_refresh(cx);
                    }
                    cx.notify();
                    return;
                }
                match result {
                    Ok(Ok(snapshot)) => {
                        root.public_balance_snapshot =
                            Some(Arc::new(merge_public_balance_snapshot(
                                root.public_balance_snapshot.as_deref(),
                                snapshot,
                                PublicAccountStatus::Active,
                            )));
                        root.public_balance_error = None;
                    }
                    Ok(Err(error)) => {
                        root.public_balance_error = Some(Arc::from(format_report_chain(&error)));
                    }
                    Err(error) => {
                        root.public_balance_error =
                            Some(Arc::from(format!("Public balance refresh failed: {error}")));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn schedule_inactive_public_balance_refresh(&mut self, cx: &mut Context<'_, Self>) {
        let accounts = self
            .public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Inactive)
            .cloned()
            .collect::<Vec<_>>();
        if self.public_inactive_balance_refreshing || accounts.is_empty() {
            return;
        }
        let chain_id = self.selected_chain;
        let account_ids = accounts
            .iter()
            .map(|account| account.public_account_uuid.clone())
            .collect::<Vec<_>>();
        let http = self.http.clone();
        self.public_inactive_balance_refreshing = true;
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        let generation = self.public_inactive_balance_generation;
        let active_wallet_id = self.selected_wallet_id.clone();
        let join = self
            .runtime
            .spawn(async move { refresh_public_balances(chain_id, &accounts, &http).await });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.public_inactive_balance_generation != generation {
                    return;
                }
                root.public_inactive_balance_refreshing = false;
                let current_account_ids = root
                    .public_accounts
                    .iter()
                    .filter(|account| account.status == PublicAccountStatus::Inactive)
                    .map(|account| account.public_account_uuid.as_str())
                    .collect::<Vec<_>>();
                let account_set_unchanged = current_account_ids.len() == account_ids.len()
                    && current_account_ids
                        .into_iter()
                        .eq(account_ids.iter().map(String::as_str));
                if root.selected_wallet_id != active_wallet_id
                    || root.selected_chain != chain_id
                    || !account_set_unchanged
                {
                    if root.active_wallet_tab == WalletTab::Public
                        && root.public_form.inactive_accounts_open
                        && root
                            .public_accounts
                            .iter()
                            .any(|account| account.status == PublicAccountStatus::Inactive)
                    {
                        root.schedule_inactive_public_balance_refresh(cx);
                    }
                    cx.notify();
                    return;
                }
                match result {
                    Ok(Ok(snapshot)) => {
                        root.public_balance_snapshot =
                            Some(Arc::new(merge_public_balance_snapshot(
                                root.public_balance_snapshot.as_deref(),
                                snapshot,
                                PublicAccountStatus::Inactive,
                            )));
                        root.public_inactive_balance_error = None;
                    }
                    Ok(Err(error)) => {
                        root.public_inactive_balance_error =
                            Some(Arc::from(format_report_chain(&error)));
                    }
                    Err(error) => {
                        root.public_inactive_balance_error = Some(Arc::from(format!(
                            "Inactive public balance refresh failed: {error}"
                        )));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn add_public_derived_account_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.adding_account {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .add_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        let password = Self::read_and_clear_input(&self.public_form.add_password_input, window, cx);
        if password.trim().is_empty() {
            self.public_form.error = Some(Arc::from("Enter the vault password to add an account"));
            cx.notify();
            return;
        }
        self.public_form.adding_account = true;
        self.public_form.error = None;
        let result = store.add_derived_public_account(
            password.as_str(),
            view_session.as_ref(),
            Some(&label),
        );
        self.public_form.adding_account = false;
        match result {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.public_form
                    .add_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => {
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
        cx.notify();
    }

    fn import_public_account_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.importing_account {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .import_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        let private_key =
            Self::read_and_clear_input(&self.public_form.import_private_key_input, window, cx);
        let password =
            Self::read_and_clear_input(&self.public_form.import_password_input, window, cx);
        if private_key.trim().is_empty() || password.trim().is_empty() {
            self.public_form.error = Some(Arc::from(
                "Enter a private key and vault password to import an account",
            ));
            cx.notify();
            return;
        }
        let global = self.public_form.import_global;
        self.public_form.importing_account = true;
        self.public_form.error = None;
        let result = store.import_public_account(
            password.as_str(),
            view_session.as_ref(),
            private_key.as_str(),
            Some(&label),
            global,
        );
        self.public_form.importing_account = false;
        match result {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.public_form
                    .import_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form.import_global = false;
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => {
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
        cx.notify();
    }

    fn update_selected_public_account_label(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        let Some(account_uuid) = self
            .public_form
            .editing_account_uuid
            .clone()
            .or_else(|| self.public_form.selected_account_uuid.clone())
        else {
            self.public_form.error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .edit_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        match store.update_public_account_label(
            view_session.as_ref(),
            account_uuid.as_ref(),
            Some(&label),
        ) {
            Ok(_) => {
                self.public_form.editing_account_uuid = None;
                self.reload_public_accounts(window, cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    fn deactivate_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .deactivate_derived_public_account(view_session.as_ref(), public_account_uuid.as_ref())
        {
            Ok(_) => {
                if self.public_form.selected_account_uuid.as_deref() == Some(public_account_uuid) {
                    self.public_form.selected_account_uuid = None;
                }
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    fn activate_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .activate_derived_public_account(view_session.as_ref(), public_account_uuid.as_ref())
        {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    fn delete_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(account) = self
            .public_account_for_uuid(Some(public_account_uuid))
            .cloned()
        else {
            return;
        };
        if account.is_global()
            && self.public_form.pending_global_delete_uuid.as_deref()
                != Some(account.public_account_uuid.as_str())
        {
            self.public_form.pending_global_delete_uuid =
                Some(Arc::from(account.public_account_uuid.as_str()));
            cx.notify();
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .delete_imported_public_account(view_session.as_ref(), &account.public_account_uuid)
        {
            Ok(_) => {
                if self.public_form.selected_account_uuid.as_deref() == Some(public_account_uuid) {
                    self.public_form.selected_account_uuid = None;
                }
                self.public_form.pending_global_delete_uuid = None;
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    fn submit_public_send_from_form(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.public_form.sending {
            return;
        }
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.send_error = Some(Arc::from("Select an asset to send"));
            cx.notify();
            return;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.send_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let amount_input = self
            .public_form
            .send_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(
            &amount_input,
            public_asset_decimals(self.selected_chain, asset),
        ) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.send_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return;
            }
            Err(error) => {
                self.public_form.send_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return;
            }
        };
        let Some(recipient) = parse_address(
            self.public_form
                .send_recipient_input
                .read(cx)
                .value()
                .as_ref(),
        ) else {
            self.public_form.send_error = Some(Arc::from("Enter a valid EVM recipient address"));
            cx.notify();
            return;
        };
        let vault_password =
            Self::read_and_clear_input(&self.public_form.send_password_input, window, cx);
        if vault_password.trim().is_empty() {
            self.public_form.send_error = Some(Arc::from("Enter the vault password to send"));
            cx.notify();
            return;
        }
        self.public_form.sending = true;
        self.public_form.send_error = None;
        let chain_id = self.selected_chain;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let generation = self.start_public_action_progress(PublicActionMode::Send, asset);
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
        let request = PublicSendRequest {
            chain_id,
            view_session,
            vault_store,
            vault_password,
            public_account_uuid: public_account_uuid.to_string(),
            asset,
            amount,
            recipient,
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_send_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if root.public_form.action_generation != generation {
                    return;
                }
                root.public_form.sending = false;
                match result {
                    Ok(Ok(_result)) => {
                        match root
                            .public_account_for_uuid(Some(submitted_public_account_uuid.as_ref()))
                            .map(|account| account.status)
                        {
                            Some(PublicAccountStatus::Inactive) => {
                                root.schedule_inactive_public_balance_refresh(cx);
                            }
                            _ => root.schedule_public_balance_refresh(cx),
                        }
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.send_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public send task failed: {error}");
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.send_error = Some(Arc::from(message));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn submit_public_shield_from_form(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.public_form.shielding {
            return;
        }
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.shield_error = Some(Arc::from("Select an asset to shield"));
            cx.notify();
            return;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.shield_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let amount_input = self
            .public_form
            .shield_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(
            &amount_input,
            public_asset_decimals(self.selected_chain, asset),
        ) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.shield_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return;
            }
            Err(error) => {
                self.public_form.shield_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return;
            }
        };
        let vault_password =
            Self::read_and_clear_input(&self.public_form.shield_password_input, window, cx);
        if vault_password.trim().is_empty() {
            self.public_form.shield_error = Some(Arc::from("Enter the vault password to shield"));
            cx.notify();
            return;
        }
        self.public_form.shielding = true;
        self.public_form.shield_error = None;
        let chain_id = self.selected_chain;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let generation = self.start_public_action_progress(PublicActionMode::Shield, asset);
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
        let request = PublicShieldRequest {
            chain_id,
            view_session,
            vault_store,
            vault_password,
            public_account_uuid: public_account_uuid.to_string(),
            asset,
            amount,
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_shield_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if root.public_form.action_generation != generation {
                    return;
                }
                root.public_form.shielding = false;
                match result {
                    Ok(Ok(_result)) => {
                        match root
                            .public_account_for_uuid(Some(submitted_public_account_uuid.as_ref()))
                            .map(|account| account.status)
                        {
                            Some(PublicAccountStatus::Inactive) => {
                                root.schedule_inactive_public_balance_refresh(cx);
                            }
                            _ => root.schedule_public_balance_refresh(cx),
                        }
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.shield_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public shield task failed: {error}");
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.shield_error = Some(Arc::from(message));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn ensure_chain_load(&mut self, chain_id: u64, cx: &mut Context<'_, Self>) {
        let overrides = chain_load_overrides();
        self.start_chain_load(chain_id, &overrides, false, cx);
    }

    fn start_chain_load(
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
            sync_start_policy: self.selected_wallet_sync_start_policy(),
            init_block_number: overrides.init_block_number,
            sync_to_block: overrides.sync_to_block,
            use_indexed_wallet_catch_up: overrides.use_indexed_wallet_catch_up,
            use_local_poi_cache: self.options.local_poi_cache,
            rewind_wallet_cache: overrides.rewind_wallet_cache,
            progress_tx: Some(progress_tx),
        };
        let db_path = self.options.db_path.clone();
        let http = self.http.clone();
        let session_store = Arc::clone(&self.session_store);
        let vault_db = self.vault_store.as_ref().map(|store| store.db());
        let join = self.runtime.spawn(async move {
            if let Some(previous_session) = previous_session {
                previous_session.stop().await?;
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

    fn sync_utxo_table(&self, cx: &mut Context<'_, Self>) {
        let (rows, poi_refresh_session, poi_refreshing) =
            match self.chain_states.get(&self.selected_chain) {
                Some(state) => {
                    let rows = state.snapshot().map_or_else(Vec::new, |snapshot| {
                        display_rows_from_output(
                            snapshot,
                            self.tx_search_query.as_ref(),
                            self.show_spent_utxos,
                        )
                    });
                    (rows, state.poi_refresh_session(), state.poi_refreshing())
                }
                _ => (Vec::new(), None, false),
            };
        self.utxo_table.update(cx, |state, cx| {
            state.delegate_mut().set_rows(rows);
            state
                .delegate_mut()
                .set_poi_refresh_state(poi_refresh_session, poi_refreshing);
            cx.notify();
        });
    }

    fn select_chain(&mut self, chain_id: u64, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.selected_chain == chain_id {
            return;
        }
        window.close_all_dialogs(cx);
        self.selected_chain = chain_id;
        self.sync_broadcaster_monitor_chain_filter(chain_id, window, cx);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.private_action_form = None;
        self.broadcaster_picker = None;
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

    fn sync_broadcaster_monitor_chain_filter(
        &self,
        chain_id: u64,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.monitor.update(cx, |monitor, cx| {
            monitor.set_chain_filter(chain_id, window, cx);
        });
    }

    fn select_wallet(&mut self, wallet_id: &str, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.selected_wallet_id.as_deref() == Some(wallet_id) {
            return;
        }
        window.close_all_dialogs(cx);
        self.switch_active_wallet(wallet_id, window, cx);
    }

    fn open_add_wallet_dialog(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        window.close_all_dialogs(cx);
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        let label = default_wallet_label_for_metadata(&self.wallet_metadata);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(px(520.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| AddWalletDialogContent::new(root, content_width, cx));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Add wallet"))
                .child(content.clone())
        });
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&label, window, cx);
            root.add_wallet_password_input
                .update(cx, |input, cx| input.set_value("", window, cx));
        });
    }

    fn open_public_account_dialog(
        &mut self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.public_form.error = None;
        self.clear_public_account_dialog_inputs(kind, window, cx);
        let root = cx.entity();
        let content_root = root.clone();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACCOUNT_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content =
            cx.new(|cx| PublicAccountDialogContent::new(content_root, kind, content_width, cx));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(kind.title()))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.public_form.error = None;
                        root.clear_public_account_dialog_inputs(kind, window, cx);
                    });
                })
                .child(content.clone())
        });
        cx.defer_in(window, move |root, window, cx| {
            root.focus_public_account_dialog_input(kind, window, cx);
        });
    }

    fn open_public_account_edit_dialog(
        &mut self,
        public_account_uuid: Arc<str>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.public_form.error = None;
        self.public_form.editing_account_uuid = Some(public_account_uuid);
        self.sync_public_edit_label_input(window, cx);
        let root = cx.entity();
        let content_root = root.clone();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACCOUNT_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| {
            PublicAccountDialogContent::new(
                content_root,
                PublicAccountDialogKind::EditLabel,
                content_width,
                cx,
            )
        });
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(PublicAccountDialogKind::EditLabel.title()))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.public_form.error = None;
                        root.clear_public_account_dialog_inputs(
                            PublicAccountDialogKind::EditLabel,
                            window,
                            cx,
                        );
                    });
                })
                .child(content.clone())
        });
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_account_dialog_input(PublicAccountDialogKind::EditLabel, window, cx);
        });
    }

    fn open_public_address_qr_dialog(
        &self,
        public_account_uuid: &str,
        label: Option<String>,
        address: Address,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let dialog_width =
            (window.viewport_size().width * 0.92).min(PUBLIC_ADDRESS_QR_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let address_text = SharedString::from(public_address_qr_payload(address));
        let account_label = label.map(SharedString::from);
        let chain_label = chain_name(self.selected_chain)
            .map_or_else(|| format!("chain {}", self.selected_chain), str::to_owned);
        let copy_id = SharedString::from(format!(
            "wallet-public-address-qr-copy-{public_account_uuid}"
        ));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Public account address"))
                .child(render_public_address_qr_dialog_content(
                    account_label.clone(),
                    address_text.clone(),
                    &chain_label,
                    copy_id.clone(),
                    content_width,
                ))
        });
    }

    fn open_public_action_dialog(
        &mut self,
        public_account_uuid: Arc<str>,
        asset: PublicAssetId,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.set_public_selected_balance(public_account_uuid, asset, window, cx);
        self.public_form.action_mode = PublicActionMode::Shield;
        self.clear_public_action_dialog_inputs(window, cx);
        let root = cx.entity();
        let content_root = root.clone();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACTION_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| PublicActionDialogContent::new(content_root, content_width, cx));
        let asset_label = public_asset_label(self.selected_chain, asset);
        let icon_path = public_asset_icon_path(self.selected_chain, asset);
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .title(public_action_title_row(
                    asset_label.clone(),
                    icon_path.clone(),
                ))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.clear_public_action_dialog_inputs(window, cx);
                    });
                })
                .child(content.clone())
        });
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
    }

    fn focus_public_account_dialog_input(
        &self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        match kind {
            PublicAccountDialogKind::Derive => self
                .public_form
                .add_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicAccountDialogKind::Import => self
                .public_form
                .import_private_key_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicAccountDialogKind::EditLabel => self
                .public_form
                .edit_label_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
        }
    }

    fn focus_public_action_dialog_input(&self, window: &mut Window, cx: &Context<'_, Self>) {
        match self.public_form.action_mode {
            PublicActionMode::Shield => self
                .public_form
                .shield_amount_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicActionMode::Send => self
                .public_form
                .send_recipient_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
        }
    }

    fn switch_active_wallet(
        &mut self,
        wallet_id: &str,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(current_session) = self.view_session.clone() else {
            self.set_vault_error("Wallet vault is locked", cx);
            return;
        };

        let current_wallet_id: Arc<str> = Arc::from(current_session.wallet_id().to_owned());
        let active_wallet_generation = self.active_wallet_generation;
        self.wallet_switch_generation = self.wallet_switch_generation.wrapping_add(1);
        let switch_generation = self.wallet_switch_generation;
        self.vault_error = None;
        let wallet_id_string = wallet_id.to_owned();
        let metadata = self.wallet_metadata.clone();
        let join = self.runtime.spawn_blocking(move || {
            store.load_view_session_with_view_session(current_session.as_ref(), &wallet_id_string)
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if root.wallet_switch_generation != switch_generation
                    || !root.is_active_wallet_generation(
                        current_wallet_id.as_ref(),
                        active_wallet_generation,
                    )
                {
                    return;
                }
                match result {
                    Ok(Ok(session)) => root.install_view_session(session, metadata, window, cx),
                    Ok(Err(error)) => {
                        root.handle_vault_error(&error, cx);
                        root.sync_wallet_select(window, cx);
                    }
                    Err(error) => {
                        root.set_vault_error(
                            format!("Failed to switch wallet: {error}").as_str(),
                            cx,
                        );
                        root.sync_wallet_select(window, cx);
                    }
                }
            });
        })
        .detach();
        cx.notify();
    }

    #[allow(dead_code)]
    fn deactivate_wallet_and_switch(
        &mut self,
        wallet_id: &str,
        password: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        if let Err(error) = store.deactivate_wallet(password, wallet_id) {
            self.handle_vault_error(&error, cx);
            return;
        }
        let metadata = match store.list_wallet_metadata(password) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        self.wallet_metadata.clone_from(&metadata);
        self.wallet_options = wallet_options_from_metadata(metadata.clone());

        if self.selected_wallet_id.as_deref() != Some(wallet_id) {
            self.sync_wallet_select(window, cx);
            cx.notify();
            return;
        }

        let Some(next_wallet_id) = self
            .wallet_options
            .first()
            .map(|option| Arc::clone(&option.wallet_id))
        else {
            self.set_vault_error("No active wallet remains after deactivation", cx);
            return;
        };
        match store.load_view_session(password, next_wallet_id.as_ref()) {
            Ok(session) => self.install_view_session(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn select_wallet_tab(&mut self, tab: WalletTab, cx: &mut Context<'_, Self>) {
        if self.active_wallet_tab == tab {
            return;
        }
        self.active_wallet_tab = tab;
        self.focus_utxo_table_on_render = should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&self.selected_chain),
        );
        if tab == WalletTab::Public {
            self.focus_public_account_search_on_render = true;
            self.schedule_public_balance_refresh(cx);
        }
        cx.notify();
    }

    fn set_spent_visibility(&mut self, show_spent: bool, cx: &mut Context<'_, Self>) {
        if self.show_spent_utxos == show_spent {
            return;
        }
        self.show_spent_utxos = show_spent;
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn repair_wallet_cache_from_input(&mut self, cx: &mut Context<'_, Self>) -> bool {
        if self
            .chain_states
            .get(&self.selected_chain)
            .is_some_and(ChainUtxoState::is_syncing)
        {
            self.repair_cache_error = Some(Arc::from(
                "Wait for wallet sync to finish before repairing the cache",
            ));
            cx.notify();
            return false;
        }

        let raw_block = self.repair_cache_block_input.read(cx).value();
        let rewind_from = match parse_repair_cache_block(raw_block.as_ref()) {
            Ok(rewind_from) => rewind_from,
            Err(message) => {
                self.repair_cache_error = Some(Arc::from(message));
                cx.notify();
                return false;
            }
        };

        let mut overrides = chain_load_overrides();
        overrides.init_block_number = rewind_from;
        overrides.sync_to_block = None;
        overrides.rewind_wallet_cache = true;
        self.repair_cache_error = None;
        self.start_chain_load(self.selected_chain, &overrides, true, cx);
        cx.notify();
        true
    }

    fn focus_utxo_table_if_requested(&mut self, window: &mut Window, cx: &Context<'_, Self>) {
        if !self.focus_utxo_table_on_render
            || !should_focus_utxo_table(
                self.active_activity,
                self.active_wallet_tab,
                self.chain_states.get(&self.selected_chain),
            )
        {
            return;
        }
        if self
            .tx_search_input
            .read(cx)
            .focus_handle(cx)
            .is_focused(window)
        {
            return;
        }

        self.utxo_table.read(cx).focus_handle(cx).focus(window);
        self.focus_utxo_table_on_render = false;
    }

    fn focus_public_account_search_if_requested(
        &mut self,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        if !self.focus_public_account_search_on_render
            || self.active_activity != Activity::Wallet
            || self.active_wallet_tab != WalletTab::Public
        {
            return;
        }

        self.public_form
            .search_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        self.focus_public_account_search_on_render = false;
    }

    fn focus_vault_input_if_requested(&mut self, window: &mut Window, cx: &Context<'_, Self>) {
        if !self.focus_vault_input_on_render {
            return;
        }

        match self.vault_state {
            VaultState::CreateVault => self
                .new_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::UnlockVault => self
                .unlock_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet if self.wallet_setup_mode == WalletSetupMode::Import => self
                .import_mnemonic_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet | VaultState::ViewUnlocked | VaultState::Error(_) => {}
        }
        self.focus_vault_input_on_render = false;
    }

    fn apply_public_broadcaster_error_amount_adjustments(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule = Vec::new();

        for (key, form) in &mut self.send_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if let Some(adjusted) = amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                cx,
            ) {
                form.pending_programmatic_amount_input = Some(adjusted.clone());
                form.amount_input
                    .update(cx, |input, cx| input.set_value(adjusted, window, cx));
                form.error = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Send, *key));
            }
        }

        for (key, form) in &mut self.unshield_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if let Some(adjusted) = amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                cx,
            ) {
                form.pending_programmatic_amount_input = Some(adjusted.clone());
                form.amount_input
                    .update(cx, |input, cx| input.set_value(adjusted, window, cx));
                form.error = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Unshield, *key));
            }
        }

        for (kind, key) in reschedule {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn refresh_open_form_assets_for_snapshot(
        &mut self,
        snapshot: &ListUtxosOutput,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule_estimates = Vec::new();
        for (key, form) in &mut self.send_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(snapshot, &form.asset, true);
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Send, *key));
            }
        }
        for (key, form) in &mut self.unshield_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(snapshot, &form.asset, false);
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Unshield, *key));
            }
        }
        for (kind, key) in reschedule_estimates {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn create_vault_from_inputs(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.new_password_input, window, cx);
        let confirm = Self::read_and_clear_input(&self.confirm_password_input, window, cx);

        if password.trim().is_empty() {
            self.set_vault_error("Enter a vault password to continue", cx);
            return;
        }
        if password.as_str() != confirm.as_str() {
            self.set_vault_error("Vault passwords do not match", cx);
            return;
        }

        match store.create_vault(password.as_str()) {
            Ok(_) => {
                Self::defer_wallet_name_input(PRIMARY_WALLET_LABEL.to_owned(), window, cx);
                self.setup_password = Some(password);
                self.vault_error = None;
                self.vault_state = VaultState::SetupWallet;
                self.wallet_setup_mode = WalletSetupMode::Choose;
                cx.notify();
            }
            Err(VaultError::VaultAlreadyExists) => {
                self.vault_state = VaultState::UnlockVault;
                self.focus_vault_input_on_render = true;
                self.set_vault_error("A wallet vault already exists. Unlock it to continue.", cx);
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn unlock_vault_from_input(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.unlock_in_progress {
            return;
        }
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.unlock_password_input, window, cx);
        if password.trim().is_empty() {
            self.set_vault_error("Enter the vault password to continue", cx);
            return;
        }

        let store = Arc::clone(store);
        self.unlock_in_progress = true;
        self.vault_error = None;
        cx.notify();

        let join = self.runtime.spawn_blocking(move || {
            let metadata = store.list_wallet_metadata(password.as_str())?;
            let active = wallet_options_from_metadata(metadata.clone());
            let Some(wallet_id) = active.first().map(|option| option.wallet_id.to_string()) else {
                return Ok((None, metadata, password));
            };
            let session = store.load_view_session(password.as_str(), &wallet_id)?;
            Ok((Some(session), metadata, password))
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                root.unlock_in_progress = false;
                match result {
                    Ok(Ok((Some(session), metadata, _password))) => {
                        root.enter_view_unlocked(session, metadata, window, cx);
                    }
                    Ok(Ok((None, _metadata, password))) => {
                        root.set_default_wallet_name_from_password(password.as_str(), window, cx);
                        root.setup_password = Some(password);
                        root.vault_error = None;
                        root.vault_state = VaultState::SetupWallet;
                        root.wallet_setup_mode = WalletSetupMode::Choose;
                        cx.notify();
                    }
                    Ok(Err(error)) => {
                        root.focus_vault_input_on_render = true;
                        root.handle_vault_error(&error, cx);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "desktop wallet vault unlock task failed");
                        root.focus_vault_input_on_render = true;
                        root.set_vault_error(
                            "Unlock failed. Check the password and try again.",
                            cx,
                        );
                    }
                }
            });
        })
        .detach();
    }

    fn choose_generated_wallet(&mut self, cx: &mut Context<'_, Self>) {
        match generate_seed_material() {
            Ok(seed) => {
                self.generated_seed = Some(seed);
                self.vault_error = None;
                self.wallet_setup_mode = WalletSetupMode::GeneratedReview;
                cx.notify();
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn choose_import_wallet(&mut self, window: &Window, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Import;
        cx.notify();
        cx.defer_in(window, |root, window, cx| {
            if root.wallet_setup_mode == WalletSetupMode::Import {
                root.import_mnemonic_input
                    .read(cx)
                    .focus_handle(cx)
                    .focus(window);
            }
        });
    }

    fn back_to_wallet_setup_choice(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        cx.notify();
    }

    fn wallet_creation_password(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            let password = Self::read_and_clear_input(&self.add_wallet_password_input, window, cx);
            if password.trim().is_empty() {
                self.set_vault_error("Enter the vault password to add a wallet", cx);
                return None;
            }
            return Some(password);
        }
        let Some(password) = self.setup_password.as_ref() else {
            self.set_vault_error("Unlock the wallet vault before adding a wallet", cx);
            return None;
        };
        Some(Zeroizing::new(password.to_string()))
    }

    fn wallet_name_from_input(&self, cx: &Context<'_, Self>) -> String {
        self.wallet_name_input.read(cx).value().to_string()
    }

    fn store_generated_wallet(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };
        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let Some(seed) = self.generated_seed.as_ref() else {
                self.set_vault_error("Generate a recovery phrase before creating the wallet", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Generated,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .store_generated_wallet_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    seed,
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn store_imported_wallet(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let mnemonic = Self::read_and_clear_input(&self.import_mnemonic_input, window, cx);
        if mnemonic.trim().is_empty() {
            self.set_vault_error("Paste a recovery phrase to import", cx);
            return;
        }
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };

        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Imported,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .import_wallet_mnemonic_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    mnemonic.as_str(),
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn install_view_session(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let session = Arc::new(session);
        let wallet_id: Arc<str> = Arc::from(session.wallet_id().to_owned());
        window.close_all_dialogs(cx);
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.view_session = Some(session);
        self.wallet_metadata = metadata;
        self.wallet_options = wallet_options_from_metadata(self.wallet_metadata.clone());
        self.selected_wallet_id = Some(wallet_id);
        self.sync_wallet_select(window, cx);
        self.reset_wallet_scoped_state(cx);
        self.reload_public_accounts(window, cx);
        self.setup_password = None;
        self.generated_seed = None;
        self.add_wallet_password_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.vault_state = VaultState::ViewUnlocked;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.ensure_chain_load(self.selected_chain, cx);
        cx.notify();
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn sync_wallet_select(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let items: Vec<_> = self
            .wallet_options
            .iter()
            .map(|option| WalletSelectItem {
                wallet_id: Arc::clone(&option.wallet_id),
                label: Arc::clone(&option.label),
            })
            .collect();
        let selected_wallet_id = self.selected_wallet_id.clone();
        self.wallet_select.update(cx, |select, cx| {
            select.set_items(SearchableVec::new(items), window, cx);
            if let Some(wallet_id) = selected_wallet_id.as_ref() {
                select.set_selected_value(wallet_id, window, cx);
            } else {
                select.set_selected_index(None, window, cx);
            }
        });
    }

    fn enter_view_unlocked(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.install_view_session(session, metadata, window, cx);
    }

    fn lock_vault(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        window.close_all_dialogs(cx);
        self.view_session = None;
        self.wallet_metadata.clear();
        self.wallet_options.clear();
        self.selected_wallet_id = None;
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.sync_wallet_select(window, cx);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.reset_public_wallet_state(window, cx);
        self.private_action_form = None;
        self.broadcaster_picker = None;
        self.active_wallet_tab = WalletTab::default();
        self.setup_password = None;
        self.generated_seed = None;
        self.vault_error = None;
        self.repair_cache_error = None;
        self.vault_state = VaultState::UnlockVault;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.session_store = Arc::new(OnceCell::new());
        self.focus_vault_input_on_render = true;
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn close_send_form(&mut self, key: UnshieldAssetKey, cx: &mut Context<'_, Self>) {
        self.send_forms.remove(&key);
        if self
            .private_action_form
            .as_ref()
            .is_some_and(|form| form.kind == DeliveryFormKind::Send && form.key == key)
        {
            self.private_action_form = None;
            self.broadcaster_picker = None;
        }
        cx.notify();
    }

    fn close_unshield_form(&mut self, key: UnshieldAssetKey, cx: &mut Context<'_, Self>) {
        self.unshield_forms.remove(&key);
        if self
            .private_action_form
            .as_ref()
            .is_some_and(|form| form.kind == DeliveryFormKind::Unshield && form.key == key)
        {
            self.private_action_form = None;
            self.broadcaster_picker = None;
        }
        cx.notify();
    }

    fn open_private_action_dialog(
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        title_action: &'static str,
        asset_label: String,
        icon_path: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        let content = cx.new(|cx| PrivateActionDialogContent::new(root.clone(), kind, key, cx));
        window.open_dialog(cx, move |dialog, window, _cx| {
            let dialog_width = (window.viewport_size().width * 0.92).min(PRIVATE_ASSET_LIST_WIDTH);
            let max_height =
                (window.viewport_size().height * 0.88).min(PRIVATE_ACTION_FORM_MAX_HEIGHT);
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .h(max_height)
                .title(private_action_title_row(
                    title_action,
                    &asset_label,
                    icon_path.clone(),
                ))
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| match kind {
                        DeliveryFormKind::Send => root.close_send_form(key, cx),
                        DeliveryFormKind::Unshield => root.close_unshield_form(key, cx),
                    });
                })
                .child(content.clone())
        });
    }

    fn open_repair_cache_dialog(window: &mut Window, cx: &mut Context<'_, Self>) {
        let root = cx.entity();
        let content_root = root.clone();
        let dialog_width = (window.viewport_size().width * 0.92).min(px(420.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| RepairCacheDialogContent::new(content_root, content_width, cx));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let submit_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text("Repair wallet cache"))
                .button_props(DialogButtonProps::default().ok_text("Repair"))
                .footer(|ok, _, window, cx| vec![ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    submit_root.update(cx, Self::repair_wallet_cache_from_input)
                })
                .child(content.clone())
        });
    }

    fn open_send_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let key = UnshieldAssetKey::from_asset(&asset);
        let dialog_asset_label = asset.label.clone();
        let dialog_icon_path = asset.icon_path.clone();
        let amount = format_send_amount_input(asset.max_batched, asset.decimals);
        let amount_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("amount");
            input.set_value(&amount, window, cx);
            input
        });
        let recipient_input = cx.new(|cx| InputState::new(window, cx).placeholder("0zk recipient"));
        let focus_recipient_input = recipient_input.clone();
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.generate_send_calldata_from_form(key, window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    if this.consume_programmatic_amount_input_change(
                        DeliveryFormKind::Send,
                        key,
                        cx,
                    ) {
                        return;
                    }
                    this.clear_send_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.broadcaster_picker = None;
        let selected_fee_token =
            self.default_public_broadcaster_fee_token(key.chain_id, key.token, false, false);
        self.send_forms.insert(
            key,
            SendFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                delivery_mode: DeliveryMode::ManualCalldata,
                selected_fee_token,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                allow_suspicious_broadcasters: false,
                transaction_fee_breakdown_open: true,
                pending_programmatic_amount_input: None,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        self.private_action_form = Some(PrivateActionFormState {
            kind: DeliveryFormKind::Send,
            key,
        });
        Self::open_private_action_dialog(
            DeliveryFormKind::Send,
            key,
            "Send",
            dialog_asset_label,
            dialog_icon_path,
            window,
            cx,
        );
        focus_recipient_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        cx.notify();
    }

    fn clear_send_form_text_edit_state(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none()
                && form.error.is_none()
                && !form.cost_estimate_pending
                && !form.estimating_cost)
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
    }

    fn consume_programmatic_amount_input_change(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &Context<'_, Self>,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                let Some(expected) = form.pending_programmatic_amount_input.take() else {
                    return false;
                };
                form.amount_input.read(cx).value().as_ref() == expected
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                let Some(expected) = form.pending_programmatic_amount_input.take() else {
                    return false;
                };
                form.amount_input.read(cx).value().as_ref() == expected
            }),
        }
    }

    fn set_private_action_metric_amount(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        amount: U256,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = self.set_programmatic_amount_input(kind, key, amount, window, cx);
        if changed {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn set_programmatic_amount_input(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        amount: U256,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating {
                    return false;
                }
                let value = format_send_amount_input(amount, form.asset.decimals);
                form.pending_programmatic_amount_input = Some(value.clone());
                form.error = None;
                form.result = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.amount_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating {
                    return false;
                }
                let value = format_unshield_amount_input(amount, form.asset.decimals);
                form.pending_programmatic_amount_input = Some(value.clone());
                form.error = None;
                form.result = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.amount_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
                true
            }),
        }
    }

    fn set_send_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode || mode == DeliveryMode::SelfBroadcast {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.delivery_mode = mode;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted.is_some() {
            form.cost_estimate = None;
        }
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_fee_token(
        &mut self,
        key: UnshieldAssetKey,
        fee_token: Address,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, action_token, current_choice, generating, allow_suspicious)) =
            self.send_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating {
            return;
        }
        let policy = Self::public_broadcaster_fee_policy(allow_suspicious);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, false, policy);
        let reset_specific =
            !broadcaster_choice_supported_by_candidates(&current_choice, &candidates, policy);
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.selected_fee_token == fee_token && !reset_specific {
            return;
        }
        form.selected_fee_token = fee_token;
        if fee_token != action_token {
            form.broadcaster_fee_mode = PublicBroadcasterFeeMode::AddToAmount;
        }
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_allow_suspicious_broadcasters(
        &mut self,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, fee_token, choice, generating, current_allow)) =
            self.send_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating || current_allow == allow {
            return;
        }
        let policy = Self::public_broadcaster_fee_policy(allow);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, false, policy);
        let preserve_estimate =
            should_preserve_estimate_after_broadcaster_policy_change(&choice, &candidates, policy);
        let reset_specific =
            matches!(choice, BroadcasterChoice::Specific { .. }) && !preserve_estimate;
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        form.allow_suspicious_broadcasters = allow;
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        let should_reestimate = !preserve_estimate || matches!(choice, BroadcasterChoice::Random);
        if should_reestimate {
            form.error = None;
            form.result = None;
            form.estimate_id = 0;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
        }
        cx.notify();
        if should_reestimate {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
            self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
        }
    }

    fn set_send_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || form.selected_fee_token != form.asset.token
            || form.broadcaster_fee_mode == fee_mode
        {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn schedule_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        if !self.can_schedule_public_broadcaster_cost_estimate(kind, key) {
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = false;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = false;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
        }
        cx.notify();

        match kind {
            DeliveryFormKind::Send => self.estimate_send_public_broadcaster_cost_from_form(key, cx),
            DeliveryFormKind::Unshield => {
                self.estimate_unshield_public_broadcaster_cost_from_form(key, cx);
            }
        }
    }

    fn debounce_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        if !self.can_schedule_public_broadcaster_cost_estimate(kind, key) {
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
        }
        cx.notify();

        cx.spawn(async move |this, cx| {
            tokio::time::sleep(COST_ESTIMATE_DEBOUNCE).await;
            let _ = this.update(cx, |root, cx| {
                let current_id = match kind {
                    DeliveryFormKind::Send => {
                        root.send_forms.get(&key).map(|form| form.estimate_id)
                    }
                    DeliveryFormKind::Unshield => {
                        root.unshield_forms.get(&key).map(|form| form.estimate_id)
                    }
                };
                if current_id != Some(estimate_id) {
                    return;
                }
                match kind {
                    DeliveryFormKind::Send => {
                        root.estimate_send_public_broadcaster_cost_from_form(key, cx);
                    }
                    DeliveryFormKind::Unshield => {
                        root.estimate_unshield_public_broadcaster_cost_from_form(key, cx);
                    }
                }
            });
        })
        .detach();
    }

    fn can_schedule_public_broadcaster_cost_estimate(
        &self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
        }
    }

    fn clear_pending_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
        };
        if changed {
            cx.notify();
        }
    }

    fn estimate_send_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let recipient = form.recipient_input.read(cx).value().trim().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        if parse_railgun_recipient(recipient.as_str()).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) | Err(_) => {
                self.clear_pending_public_broadcaster_cost_estimate(
                    DeliveryFormKind::Send,
                    key,
                    cx,
                );
                return;
            }
        };
        if amount > asset.max_batched {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let policy = Self::public_broadcaster_fee_policy(allow_suspicious_broadcasters);
        let candidates =
            self.current_public_broadcaster_candidates(asset.chain_id, fee_token, false, policy);
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster_with_policy(&candidates, &selection, policy).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopSendPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            session,
            token: asset.token,
            fee_token,
            amount,
            recipient,
            fee_rows,
            selection,
            fee_mode,
            allow_suspicious_broadcasters,
            anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_send_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("send cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.send_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn monitor_fee_rows(&self) -> Vec<broadcaster_monitor::FeeRow> {
        self.monitor_state.read().fee_rows()
    }

    fn public_broadcaster_fee_policy(allow_suspicious_broadcasters: bool) -> BroadcasterFeePolicy {
        BroadcasterFeePolicy::default()
            .with_allow_suspicious_broadcasters(allow_suspicious_broadcasters)
    }

    fn current_public_broadcaster_candidates(
        &self,
        chain_id: u64,
        token: Address,
        unwrap: bool,
        policy: BroadcasterFeePolicy,
    ) -> Vec<PublicBroadcasterCandidate> {
        public_broadcaster_candidates_for_asset(
            &self.monitor_fee_rows(),
            chain_id,
            token,
            unwrap,
            policy,
            self.public_broadcaster_anchor_cache
                .cached_rate(chain_id, token),
        )
        .unwrap_or_default()
    }

    fn current_public_broadcaster_fee_token_options(
        &self,
        chain_id: u64,
        unwrap: bool,
        policy: BroadcasterFeePolicy,
    ) -> Vec<PublicBroadcasterFeeTokenOption> {
        let Some(snapshot) = self
            .chain_states
            .get(&chain_id)
            .and_then(|state| state.snapshot())
        else {
            return Vec::new();
        };
        let fee_rows = self.monitor_fee_rows();
        public_broadcaster_fee_token_options_from_snapshot(
            snapshot,
            &fee_rows,
            unwrap,
            policy,
            |token| {
                self.public_broadcaster_anchor_cache
                    .cached_rate(chain_id, token)
            },
        )
    }

    fn default_public_broadcaster_fee_token(
        &self,
        chain_id: u64,
        action_token: Address,
        unwrap: bool,
        allow_suspicious_broadcasters: bool,
    ) -> Address {
        let policy = Self::public_broadcaster_fee_policy(allow_suspicious_broadcasters);
        let options = self.current_public_broadcaster_fee_token_options(chain_id, unwrap, policy);
        resolve_selected_public_broadcaster_fee_token(action_token, action_token, &options)
    }

    fn public_broadcaster_selection(choice: &BroadcasterChoice) -> PublicBroadcasterSelection {
        match choice {
            BroadcasterChoice::Random => PublicBroadcasterSelection::Random,
            BroadcasterChoice::Specific { railgun_address } => {
                PublicBroadcasterSelection::Specific {
                    railgun_address: railgun_address.clone(),
                }
            }
        }
    }

    fn refresh_public_broadcaster_anchor(
        &self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &Context<'_, Self>,
    ) {
        let Some((_chain_id, _token)) = (match kind {
            DeliveryFormKind::Send => self
                .send_forms
                .get(&key)
                .map(|form| (form.asset.chain_id, form.selected_fee_token)),
            DeliveryFormKind::Unshield => self
                .unshield_forms
                .get(&key)
                .map(|form| (form.asset.chain_id, form.selected_fee_token)),
        }) else {
            return;
        };
        self.public_broadcaster_anchor_refresh.wake();
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(2)).await;
            let _ = this.update(cx, |_root, cx| cx.notify());
        })
        .detach();
    }

    fn set_allow_suspicious_broadcasters(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        match kind {
            DeliveryFormKind::Send => self.set_send_allow_suspicious_broadcasters(key, allow, cx),
            DeliveryFormKind::Unshield => {
                self.set_unshield_allow_suspicious_broadcasters(key, allow, cx);
            }
        }
    }

    fn set_transaction_fee_breakdown_open(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.transaction_fee_breakdown_open == open {
                    false
                } else {
                    form.transaction_fee_breakdown_open = open;
                    true
                }
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.transaction_fee_breakdown_open == open {
                    false
                } else {
                    form.transaction_fee_breakdown_open = open;
                    true
                }
            }),
        };
        if changed {
            cx.notify();
        }
    }

    fn set_broadcaster_picker_fee_bonus_popover_open(
        &mut self,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(picker) = self.broadcaster_picker.as_mut() else {
            return;
        };
        if picker.fee_bonus_popover_open == open {
            return;
        }
        picker.fee_bonus_popover_open = open;
        cx.notify();
    }

    fn open_broadcaster_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.broadcaster_picker.is_some() {
            return;
        }
        let Some((asset_label, chain_id, fee_token)) = (match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).map(|form| {
                (
                    form.asset.label.clone(),
                    form.asset.chain_id,
                    form.selected_fee_token,
                )
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.label.clone(),
                    form.asset.chain_id,
                    form.selected_fee_token,
                )
            }),
        }) else {
            return;
        };

        let query_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search broadcasters"));
        let focus_query_input = query_input.clone();
        cx.subscribe(&query_input, |_this, _input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        })
        .detach();
        let root = cx.weak_entity();
        let list = cx.new(|cx| {
            ListState::new(BroadcasterPickerDelegate::new(root, kind, key), window, cx)
                .selectable(false)
        });
        self.broadcaster_picker = Some(BroadcasterPickerState {
            kind,
            key,
            query_input,
            list,
            fee_bonus_popover_open: false,
        });
        self.refresh_public_broadcaster_anchor(kind, key, cx);
        Self::open_broadcaster_picker_dialog(
            format!(
                "{asset_label} · fee token {}",
                token_display_label(chain_id, fee_token)
            ),
            chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned),
            window,
            cx,
        );
        cx.defer_in(window, move |_this, window, cx| {
            focus_query_input.read(cx).focus_handle(cx).focus(window);
        });
        cx.notify();
    }

    fn open_broadcaster_picker_dialog(
        asset_label: String,
        chain_label: String,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        let content_root = root.clone();
        let content = cx.new(|cx| BroadcasterPickerDialogContent::new(content_root, cx));
        window.open_dialog(cx, move |dialog, window, _cx| {
            let dialog_width = (window.viewport_size().width * 0.92).min(PRIVATE_ASSET_LIST_WIDTH);
            let max_height =
                (window.viewport_size().height * 0.82).min(BROADCASTER_PICKER_MAX_HEIGHT);
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .h(max_height)
                .title(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_strong_text("Choose public broadcaster"))
                        .child(app_muted_text(format!("{asset_label} on {chain_label}"))),
                )
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.close_broadcaster_picker(cx);
                    });
                })
                .child(content.clone())
        });
    }

    fn close_broadcaster_picker(&mut self, cx: &mut Context<'_, Self>) {
        self.broadcaster_picker = None;
        cx.notify();
    }

    fn choose_broadcaster_from_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        railgun_address: String,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let choice = BroadcasterChoice::Specific { railgun_address };
        match kind {
            DeliveryFormKind::Send => self.set_send_broadcaster_choice(key, choice, cx),
            DeliveryFormKind::Unshield => self.set_unshield_broadcaster_choice(key, choice, cx),
        }
        self.broadcaster_picker = None;
        cx.notify();
        window.close_dialog(cx);
    }

    fn generate_send_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let broadcaster_fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_send_form_error(key, "Unlock the wallet vault before sending", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_send_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_send_form_error(key, "Wait for wallet sync to finish before sending", cx);
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_send_form_error(
                key,
                "No POI-verified private notes are spendable in a batched send",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        if let Err(error) = parse_railgun_recipient(recipient_raw.as_str()) {
            self.set_send_form_error(key, error.to_string(), cx);
            return;
        }
        let recipient = recipient_raw.trim().to_string();
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_send_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_send_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_send_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let policy = Self::public_broadcaster_fee_policy(allow_suspicious_broadcasters);
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                fee_token,
                false,
                policy,
            );
            if let Err(error) = select_public_broadcaster_with_policy(
                &candidates,
                &Self::public_broadcaster_selection(&broadcaster_choice),
                policy,
            ) {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_send_form_error(key, "Enter the vault password to prepare this send", cx);
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.send_generation_seq = self.send_generation_seq.wrapping_add(1);
        let generation_id = self.send_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopSendCalldataRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_send_calldata(request, &http)
                        .await
                        .map(SendResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopSendPublicBroadcasterRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_selection(&broadcaster_choice),
                    fee_mode: broadcaster_fee_mode,
                    allow_suspicious_broadcasters,
                    anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
                    waku,
                    response_timeout: PUBLIC_BROADCASTER_RESPONSE_TIMEOUT,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_send_public_broadcaster(request, &http)
                        .await
                        .map(|result| SendResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                self.set_send_form_error(key, "Self-broadcast is not available yet", cx);
                return;
            }
        };
        Self::watch_send_generation_stage(key, generation_id, progress_rx, cx);
        cx.spawn(async move |this, cx| {
            let result = join
                .await
                .unwrap_or_else(|error| Err(eyre::eyre!("send generation task failed: {error}")));
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.send_forms.get_mut(&key) else {
                    return;
                };
                if form.asset.chain_id != chain_id || form.asset.token != token {
                    return;
                }
                if form.generation_id != generation_id || !form.generating {
                    return;
                }
                form.generating = false;
                match result {
                    Ok(result) => {
                        form.error = None;
                        form.result = Some(result);
                    }
                    Err(error) => {
                        form.result = None;
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_send_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update(cx, |root, cx| {
                        let Some(form) = root.send_forms.get_mut(&key) else {
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            return;
                        }
                        form.generation_stage = stage;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn set_send_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generating = false;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message.into());
            cx.notify();
        }
    }

    fn open_unshield_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let key = UnshieldAssetKey::from_asset(&asset);
        let dialog_asset_label = asset.label.clone();
        let dialog_icon_path = asset.icon_path.clone();
        let amount = format_unshield_amount_input(asset.max_batched, asset.decimals);
        let amount_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("amount");
            input.set_value(&amount, window, cx);
            input
        });
        let recipient_input = cx.new(|cx| InputState::new(window, cx).placeholder("0x recipient"));
        let focus_recipient_input = recipient_input.clone();
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.generate_unshield_calldata_from_form(key, window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_unshield_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    if this.consume_programmatic_amount_input_change(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    ) {
                        return;
                    }
                    this.clear_unshield_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.broadcaster_picker = None;
        let selected_fee_token =
            self.default_public_broadcaster_fee_token(key.chain_id, key.token, false, false);
        self.unshield_forms.insert(
            key,
            UnshieldFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                unwrap: false,
                delivery_mode: DeliveryMode::ManualCalldata,
                selected_fee_token,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                allow_suspicious_broadcasters: false,
                transaction_fee_breakdown_open: true,
                pending_programmatic_amount_input: None,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        self.private_action_form = Some(PrivateActionFormState {
            kind: DeliveryFormKind::Unshield,
            key,
        });
        Self::open_private_action_dialog(
            DeliveryFormKind::Unshield,
            key,
            "Unshield",
            dialog_asset_label,
            dialog_icon_path,
            window,
            cx,
        );
        focus_recipient_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        cx.notify();
    }

    fn set_unshield_unwrap(
        &mut self,
        key: UnshieldAssetKey,
        unwrap: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if !is_wrapped_native_token(form.asset.chain_id, form.asset.token)
            || form.generating
            || form.unwrap == unwrap
        {
            return;
        }
        form.unwrap = unwrap;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || form.selected_fee_token != form.asset.token
            || form.broadcaster_fee_mode == fee_mode
        {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        cx.notify();
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn clear_unshield_form_text_edit_state(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none()
                && form.error.is_none()
                && !form.cost_estimate_pending
                && !form.estimating_cost)
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
    }

    fn set_unshield_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode || mode == DeliveryMode::SelfBroadcast {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.delivery_mode = mode;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted.is_some() {
            form.cost_estimate = None;
        }
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_fee_token(
        &mut self,
        key: UnshieldAssetKey,
        fee_token: Address,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, action_token, unwrap, current_choice, generating, allow_suspicious)) =
            self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.unwrap,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating {
            return;
        }
        let policy = Self::public_broadcaster_fee_policy(allow_suspicious);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, unwrap, policy);
        let reset_specific =
            !broadcaster_choice_supported_by_candidates(&current_choice, &candidates, policy);
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.selected_fee_token == fee_token && !reset_specific {
            return;
        }
        form.selected_fee_token = fee_token;
        if fee_token != action_token {
            form.broadcaster_fee_mode = PublicBroadcasterFeeMode::AddToAmount;
        }
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_allow_suspicious_broadcasters(
        &mut self,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, fee_token, unwrap, choice, generating, current_allow)) =
            self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    form.unwrap,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating || current_allow == allow {
            return;
        }
        let policy = Self::public_broadcaster_fee_policy(allow);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, unwrap, policy);
        let preserve_estimate =
            should_preserve_estimate_after_broadcaster_policy_change(&choice, &candidates, policy);
        let reset_specific =
            matches!(choice, BroadcasterChoice::Specific { .. }) && !preserve_estimate;
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        form.allow_suspicious_broadcasters = allow;
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        let should_reestimate = !preserve_estimate || matches!(choice, BroadcasterChoice::Random);
        if should_reestimate {
            form.error = None;
            form.result = None;
            form.estimate_id = 0;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
        }
        cx.notify();
        if should_reestimate {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
            self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
        }
    }

    fn estimate_unshield_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_raw = form.recipient_input.read(cx).value().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        let Ok(recipient) = recipient_raw.trim().parse::<Address>() else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) | Err(_) => {
                self.clear_pending_public_broadcaster_cost_estimate(
                    DeliveryFormKind::Unshield,
                    key,
                    cx,
                );
                return;
            }
        };
        if amount > asset.max_batched {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let policy = Self::public_broadcaster_fee_policy(allow_suspicious_broadcasters);
        let candidates =
            self.current_public_broadcaster_candidates(asset.chain_id, fee_token, unwrap, policy);
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster_with_policy(&candidates, &selection, policy).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopUnshieldPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            session,
            token: asset.token,
            fee_token,
            amount,
            recipient,
            unwrap,
            fee_rows,
            selection,
            fee_mode,
            allow_suspicious_broadcasters,
            anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_unshield_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("unshield cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn generate_unshield_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let broadcaster_fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_unshield_form_error(key, "Unlock the wallet vault before unshielding", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_unshield_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_unshield_form_error(
                key,
                "Wait for wallet sync to finish before unshielding",
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_unshield_form_error(
                key,
                "No POI-verified private notes are spendable in a batched unshield",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        let Some(recipient) = parse_address(recipient_raw.trim()) else {
            self.set_unshield_form_error(key, "Enter a valid public EVM recipient address", cx);
            return;
        };
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_unshield_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_unshield_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_unshield_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let policy = Self::public_broadcaster_fee_policy(allow_suspicious_broadcasters);
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                fee_token,
                unwrap,
                policy,
            );
            if let Err(error) = select_public_broadcaster_with_policy(
                &candidates,
                &Self::public_broadcaster_selection(&broadcaster_choice),
                policy,
            ) {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_unshield_form_error(
                key,
                "Enter the vault password to prepare this unshield",
                cx,
            );
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.unshield_generation_seq = self.unshield_generation_seq.wrapping_add(1);
        let generation_id = self.unshield_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopUnshieldCalldataRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_unshield_calldata(request, &http)
                        .await
                        .map(UnshieldResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopUnshieldPublicBroadcasterRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_selection(&broadcaster_choice),
                    fee_mode: broadcaster_fee_mode,
                    allow_suspicious_broadcasters,
                    anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
                    waku,
                    response_timeout: PUBLIC_BROADCASTER_RESPONSE_TIMEOUT,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_unshield_public_broadcaster(request, &http)
                        .await
                        .map(|result| UnshieldResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                self.set_unshield_form_error(key, "Self-broadcast is not available yet", cx);
                return;
            }
        };
        Self::watch_unshield_generation_stage(key, generation_id, progress_rx, cx);
        cx.spawn(async move |this, cx| {
            let result = join.await.unwrap_or_else(|error| {
                Err(eyre::eyre!("unshield generation task failed: {error}"))
            });
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.asset.chain_id != chain_id || form.asset.token != token {
                    return;
                }
                if form.generation_id != generation_id || !form.generating {
                    return;
                }
                form.generating = false;
                match result {
                    Ok(result) => {
                        form.error = None;
                        form.result = Some(result);
                    }
                    Err(error) => {
                        form.result = None;
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_unshield_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update(cx, |root, cx| {
                        let Some(form) = root.unshield_forms.get_mut(&key) else {
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            return;
                        }
                        form.generation_stage = stage;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn set_unshield_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generating = false;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message.into());
            cx.notify();
        }
    }

    fn read_and_clear_input(
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Zeroizing<String> {
        let value = Zeroizing::new(input.read(cx).value().to_string());
        input.update(cx, |input, cx| input.set_value("", window, cx));
        value
    }

    fn handle_vault_error(&mut self, error: &VaultError, cx: &mut Context<'_, Self>) {
        tracing::warn!(
            error_kind = vault_error_kind(error),
            "desktop wallet vault operation failed"
        );
        let message: Arc<str> = match error {
            VaultError::UnlockFailed => "Unlock failed. Check the password and try again.".into(),
            VaultError::Key(_) => "Invalid recovery phrase. Paste it again to retry.".into(),
            VaultError::VaultNotFound => {
                "Wallet vault not found. Create a new vault to continue.".into()
            }
            _ => "Wallet vault operation failed. See logs for non-sensitive diagnostics.".into(),
        };
        self.set_vault_error(message, cx);
    }

    fn set_vault_error(&mut self, message: impl Into<Arc<str>>, cx: &mut Context<'_, Self>) {
        self.vault_error = Some(message.into());
        cx.notify();
    }

    fn render_sidebar(
        &self,
        root: Entity<Self>,
        collapsed: bool,
        sidebar_is_narrow: bool,
    ) -> impl IntoElement {
        let wallet_root = root.clone();
        let broadcaster_root = root.clone();
        let logs_root = root.clone();
        let network_root = root.clone();

        Sidebar::left()
            .w(SIDEBAR_WIDTH)
            .collapsed(collapsed)
            .header(Self::render_sidebar_header(
                root,
                collapsed,
                sidebar_is_narrow,
            ))
            .child(
                SidebarMenu::new()
                    .child(
                        SidebarMenuItem::new("Wallets")
                            .icon(Icon::new(RailgunSidebarIcon::Wallet).size_4())
                            .active(self.active_activity == Activity::Wallet)
                            .on_click(move |_event, _window, cx| {
                                wallet_root.update(cx, |root, cx| {
                                    root.active_activity = Activity::Wallet;
                                    if root.active_wallet_tab == WalletTab::Public {
                                        root.focus_public_account_search_on_render = true;
                                    }
                                    root.focus_utxo_table_on_render = should_focus_utxo_table(
                                        root.active_activity,
                                        root.active_wallet_tab,
                                        root.chain_states.get(&root.selected_chain),
                                    );
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        SidebarMenuItem::new("Public broadcasters")
                            .icon(Icon::new(RailgunSidebarIcon::Broadcaster).size_4())
                            .active(self.active_activity == Activity::Broadcaster)
                            .on_click(move |_event, window, cx| {
                                broadcaster_root.update(cx, |root, cx| {
                                    root.sync_broadcaster_monitor_chain_filter(
                                        root.selected_chain,
                                        window,
                                        cx,
                                    );
                                    root.active_activity = Activity::Broadcaster;
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .footer(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .gap_1()
                    .when(!collapsed, Styled::items_start)
                    .when(collapsed, Styled::items_center)
                    .child(self.render_network_status_pill(&network_root, collapsed))
                    .child(
                        SidebarMenuItem::new("Logs")
                            .icon(Icon::new(RailgunSidebarIcon::Logs).size_4())
                            .active(self.logs_open)
                            .collapsed(collapsed)
                            .on_click(move |_event, _window, cx| {
                                logs_root.update(cx, |root, cx| {
                                    root.logs_open = !root.logs_open;
                                    cx.notify();
                                });
                            }),
                    ),
            )
    }

    fn render_network_status_pill(&self, root: &Entity<Self>, collapsed: bool) -> impl IntoElement {
        let health = self.network_health.clone();
        let color = network_health_color(&health);
        let label = health.label();
        let tooltip = health.detail.to_string();
        let popover_root = root.clone();
        let content_root = root.clone();
        let network_status_error = self.network_status_error.clone();
        let tor_exit_ip_query = self.tor_exit_ip_query.clone();
        let tor_state_reset_confirming = self.tor_state_reset_confirming;

        let trigger = Button::new("wallet-network-status-pill-trigger")
            .text()
            .tab_stop(false)
            .tooltip(tooltip)
            .child(Self::render_network_status_chip(collapsed, color, label));

        Popover::new("wallet-network-status-popover")
            .open(self.network_status_popover_open)
            .on_open_change(move |open, _window, cx| {
                popover_root.update(cx, |root, cx| {
                    root.set_network_status_popover_open(*open, cx);
                });
            })
            .trigger(trigger)
            .content(move |_state, _window, _cx| {
                render_network_status_popover_content(
                    content_root.clone(),
                    &health,
                    color,
                    network_status_error.clone(),
                    tor_exit_ip_query.clone(),
                    tor_state_reset_confirming,
                )
            })
    }

    fn render_network_status_chip(
        collapsed: bool,
        color: u32,
        label: &'static str,
    ) -> gpui::AnyElement {
        if collapsed {
            return div()
                .id("wallet-network-status-pill-collapsed")
                .h(px(32.0))
                .px_2()
                .flex()
                .items_center()
                .justify_center()
                .rounded_lg()
                .border_1()
                .border_color(rgb(color))
                .bg(rgb_with_alpha(color, 0.08))
                .text_color(rgb(color))
                .cursor_pointer()
                .hover(|this| this.bg(rgb_with_alpha(color, 0.14)))
                .child(
                    Icon::new(RailgunNetworkStatusIcon::Tor)
                        .small()
                        .text_color(rgb(color)),
                )
                .into_any_element();
        }

        div()
            .id("wallet-network-status-pill")
            .h_7()
            .px_2()
            .flex()
            .items_center()
            .gap_2()
            .rounded_lg()
            .border_1()
            .border_color(rgb(color))
            .bg(rgb_with_alpha(color, 0.08))
            .text_color(rgb(color))
            .cursor_pointer()
            .hover(|this| this.bg(rgb_with_alpha(color, 0.14)))
            .child(
                Icon::new(RailgunNetworkStatusIcon::Tor)
                    .small()
                    .text_color(rgb(color)),
            )
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_size(px(13.0))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .line_height(gpui::relative(1.0))
                    .text_color(rgb(color))
                    .child(label),
            )
            .into_any_element()
    }

    fn render_sidebar_header(
        root: Entity<Self>,
        collapsed: bool,
        sidebar_is_narrow: bool,
    ) -> impl IntoElement {
        Self::render_sidebar_brand(root, collapsed, sidebar_is_narrow)
    }

    fn render_sidebar_brand(
        root: Entity<Self>,
        collapsed: bool,
        sidebar_is_narrow: bool,
    ) -> impl IntoElement {
        div()
            .id("sidebar-brand-toggle")
            .w_full()
            .flex()
            .items_center()
            .gap_2()
            .cursor_pointer()
            .on_click(move |_event, _window, cx| {
                root.update(cx, |root, cx| {
                    if sidebar_is_narrow {
                        root.sidebar_narrow_expanded = !root.sidebar_narrow_expanded;
                    } else {
                        root.sidebar_manually_collapsed = !root.sidebar_manually_collapsed;
                    }
                    cx.notify();
                });
            })
            .when(!collapsed, |this| {
                this.child(Self::render_sidebar_logo()).child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .flex()
                        .line_height(gpui::relative(1.2))
                        .child(Self::render_sidebar_wordmark()),
                )
            })
            .when(collapsed, |this| {
                this.justify_center().child(Self::render_sidebar_logo())
            })
    }

    fn render_sidebar_logo() -> impl IntoElement {
        img(LOGO_ICON_PATH).size(px(32.0)).flex_none()
    }

    fn render_sidebar_wordmark() -> impl IntoElement {
        img(SIDEBAR_WORDMARK_PATH)
            .w(px(154.0))
            .h(px(21.3))
            .flex_none()
    }

    const fn vault_dialog_title(&self) -> &'static str {
        match &self.vault_state {
            VaultState::CreateVault => "Create wallet vault",
            VaultState::UnlockVault => "Unlock wallet",
            VaultState::SetupWallet => match self.wallet_setup_mode {
                WalletSetupMode::Choose => "Add your first wallet",
                WalletSetupMode::GeneratedReview => "Save recovery phrase",
                WalletSetupMode::Import => "Import wallet",
            },
            VaultState::ViewUnlocked => "Wallet",
            VaultState::Error(_) => "Wallet vault unavailable",
        }
    }

    fn render_vault_dialog_content(&self, root: Entity<Self>) -> gpui::AnyElement {
        match &self.vault_state {
            VaultState::CreateVault => self.render_create_vault(root).into_any_element(),
            VaultState::UnlockVault => self.render_unlock_vault(root).into_any_element(),
            VaultState::SetupWallet => self.render_wallet_setup(root).into_any_element(),
            VaultState::ViewUnlocked => div().into_any_element(),
            VaultState::Error(message) => self.render_vault_fatal(message).into_any_element(),
        }
    }

    fn render_locked_vault_screen(&self, root: Entity<Self>, window: &Window) -> gpui::Div {
        let card = self.render_vault_card(root);
        render_wallet_hero_screen(window, card)
    }

    const fn titlebar_color(&self) -> u32 {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            theme::SURFACE
        } else {
            theme::BACKGROUND
        }
    }

    fn render_vault_card(&self, root: Entity<Self>) -> gpui::AnyElement {
        div()
            .w_full()
            .p(px(28.0))
            .flex()
            .flex_col()
            .gap_5()
            .rounded_lg()
            .border_1()
            .border_color(rgb(theme::BORDER_STRONG))
            .bg(rgb_with_alpha(theme::SURFACE_ELEVATED, 0.86))
            .child(
                app_strong_text(self.vault_dialog_title())
                    .text_size(px(22.0))
                    .line_height(px(28.0)),
            )
            .child(self.render_vault_dialog_content(root))
            .into_any_element()
    }

    fn render_add_wallet_dialog_content(
        &self,
        root: Entity<Self>,
        content_width: Pixels,
    ) -> gpui::AnyElement {
        div()
            .w(content_width)
            .child(self.render_wallet_setup(root))
            .into_any_element()
    }

    fn render_create_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut body = vault_dialog_body(
            "Choose one password for this desktop wallet vault. It will be required every time the app starts.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.new_password_input))
            .child(app_input(&self.confirm_password_input))
            .child(
                app_button("create-wallet-vault", "Create vault")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.create_vault_from_inputs(window, cx);
                        });
                    }),
            )
            .child(
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("No OS keychain or mnemonic startup argument is used in v1."),
            )
    }

    fn render_unlock_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut body =
            vault_dialog_body("Enter the vault password to view wallet balances and history.");
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.unlock_password_input).disabled(self.unlock_in_progress))
            .child(
                app_button("unlock-wallet-vault", "Unlock vault")
                    .primary()
                    .w_full()
                    .loading(self.unlock_in_progress)
                    .disabled(self.unlock_in_progress)
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.unlock_vault_from_input(window, cx);
                        });
                    }),
            )
    }

    fn render_wallet_setup(&self, root: Entity<Self>) -> gpui::AnyElement {
        match self.wallet_setup_mode {
            WalletSetupMode::Choose => self.render_wallet_setup_choice(root),
            WalletSetupMode::GeneratedReview => self.render_generated_wallet_review(root),
            WalletSetupMode::Import => self.render_import_wallet(root),
        }
    }

    fn render_wallet_setup_choice(&self, root: Entity<Self>) -> gpui::AnyElement {
        let generate_root = root.clone();
        let import_root = root;
        let mut body = vault_dialog_body(
            "Generate a new recovery phrase or import an existing one. Seed material will be encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(
            app_button("generate-vault-wallet", "Generate new wallet")
                .primary()
                .w_full()
                .on_click(move |_event, _window, cx| {
                    generate_root.update(cx, |root, cx| {
                        root.choose_generated_wallet(cx);
                    });
                }),
        )
        .child(
            app_button("import-vault-wallet", "Import recovery phrase")
                .outline()
                .w_full()
                .on_click(move |_event, window, cx| {
                    import_root.update(cx, |root, cx| {
                        root.choose_import_wallet(window, cx);
                    });
                }),
        )
        .into_any_element()
    }

    fn render_generated_wallet_review(&self, root: Entity<Self>) -> gpui::AnyElement {
        let confirm_root = root.clone();
        let back_root = root;
        let phrase = self
            .generated_seed
            .as_ref()
            .map_or_else(String::new, |seed| seed.mnemonic.to_string());
        let mut body = vault_dialog_body(
            "Write this phrase down before continuing. It is shown once and then encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body = body.child(app_input(&self.wallet_name_input));
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            body = body.child(app_input(&self.add_wallet_password_input));
        }

        body.child(
            div()
                .w_full()
                .p(px(14.0))
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER_STRONG))
                .bg(rgb(theme::SURFACE_ELEVATED))
                .text_color(rgb(theme::WARNING))
                .text_size(APP_TEXT_SIZE)
                .line_height(px(21.0))
                .child(SharedString::from(phrase)),
        )
        .child(
            app_button("confirm-generated-wallet", "I saved it, create wallet")
                .primary()
                .w_full()
                .on_click(move |_event, window, cx| {
                    confirm_root.update(cx, |root, cx| {
                        root.store_generated_wallet(window, cx);
                    });
                }),
        )
        .child(
            app_button("back-generated-wallet", "Back")
                .ghost()
                .w_full()
                .on_click(move |_event, window, cx| {
                    back_root.update(cx, |root, cx| {
                        root.back_to_wallet_setup_choice(window, cx);
                    });
                }),
        )
        .into_any_element()
    }

    fn render_import_wallet(&self, root: Entity<Self>) -> gpui::AnyElement {
        let import_root = root.clone();
        let back_root = root;
        let mut body = vault_dialog_body(
            "Paste the recovery phrase. The phrase is validated, converted to canonical entropy, and cleared from the input.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.wallet_name_input))
            .when(
                matches!(self.vault_state, VaultState::ViewUnlocked),
                |this| this.child(app_input(&self.add_wallet_password_input)),
            )
            .child(app_input(&self.import_mnemonic_input))
            .child(
                app_button("store-imported-wallet", "Import wallet")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        import_root.update(cx, |root, cx| {
                            root.store_imported_wallet(window, cx);
                        });
                    }),
            )
            .child(
                app_button("back-import-wallet", "Back")
                    .ghost()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        back_root.update(cx, |root, cx| {
                            root.back_to_wallet_setup_choice(window, cx);
                        });
                    }),
            )
            .into_any_element()
    }

    fn render_vault_fatal(&self, message: &str) -> gpui::Div {
        let mut body = vault_dialog_body(SharedString::from(message.to_owned()));
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }
        body
    }

    fn render_vault_error(&self) -> Option<gpui::AnyElement> {
        self.vault_error.as_ref().map(|message| {
            div()
                .w_full()
                .p(px(10.0))
                .rounded_md()
                .bg(rgb(theme::DANGER_BG))
                .border_1()
                .border_color(rgb(theme::DANGER))
                .text_color(rgb(theme::DANGER))
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(message.to_string()))
                .into_any_element()
        })
    }

    fn render_workspace(&self, root: Entity<Self>, window: &Window) -> impl IntoElement {
        if self.logs_open {
            div().size_full().min_w(px(0.0)).min_h(px(0.0)).child(
                v_resizable("wallet-logs-drawer")
                    .with_state(&self.drawer_split)
                    .child(
                        resizable_panel().child(
                            div()
                                .size_full()
                                .min_w(px(0.0))
                                .min_h(px(0.0))
                                .child(self.render_active_content(&root, window)),
                        ),
                    )
                    .child(
                        resizable_panel()
                            .size(LOGS_DRAWER_HEIGHT)
                            .size_range(LOGS_DRAWER_MIN_HEIGHT..LOGS_DRAWER_MAX_HEIGHT)
                            .child(
                                div()
                                    .size_full()
                                    .min_w(px(0.0))
                                    .min_h(px(0.0))
                                    .child(self.render_logs_drawer(root)),
                            ),
                    ),
            )
        } else {
            div()
                .size_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .child(self.render_active_content(&root, window))
        }
    }

    fn render_active_content(&self, root: &Entity<Self>, window: &Window) -> gpui::AnyElement {
        match self.active_activity {
            Activity::Wallet => self.render_wallet_view(root, window).into_any_element(),
            Activity::Broadcaster => self.monitor.clone().into_any_element(),
        }
    }

    fn render_wallet_view(&self, root: &Entity<Self>, window: &Window) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .child(self.render_wallet_header(root))
            .child(self.render_wallet_tabs(root))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .p(px(12.0))
                    .child(self.render_wallet_content(root, window)),
            )
            .children(self.render_sync_status_bar())
    }

    fn render_sync_status_bar(&self) -> Option<gpui::AnyElement> {
        let progress = self
            .chain_states
            .get(&self.selected_chain)
            .filter(|state| state.is_syncing())
            .map(ChainUtxoState::progress)?;
        Some(sync_status_bar(progress).into_any_element())
    }

    fn render_wallet_header(&self, root: &Entity<Self>) -> impl IntoElement {
        let lock_root = root.clone();
        let receive_address = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok());

        div()
            .h(px(52.0))
            .flex_none()
            .flex()
            .items_center()
            .gap_3()
            .px(px(14.0))
            .bg(rgb(theme::SURFACE))
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(self.render_wallet_selector())
                    .child(Self::render_add_wallet_button(root.clone())),
            )
            .child(self.render_chain_selector())
            .child(div().flex_1())
            .children(receive_address.clone().map(|address| {
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .text_color(rgb(theme::TEAL))
                    .child(SharedString::from(short_hash(&address)))
                    .child(clipboard_with_toast("wallet-receive-address-copy", address))
            }))
            .children(receive_address.map(|_| header_divider()))
            .child(self.render_repair_cache_button(root.clone()))
            .child(
                app_button_base("wallet-lock-vault")
                    .outline()
                    .xsmall()
                    .px(px(10.0))
                    .py(px(15.0))
                    .tooltip("Lock vault")
                    .child(img(icons::lock_icon_path()).size(px(12.0)).flex_none())
                    .on_click(move |_event, window, cx| {
                        lock_root.update(cx, |root, cx| {
                            root.lock_vault(window, cx);
                        });
                    }),
            )
    }

    fn render_repair_cache_button(&self, root: Entity<Self>) -> impl IntoElement {
        let disabled = matches!(
            self.chain_states.get(&self.selected_chain),
            Some(state) if state.is_syncing()
        );

        app_button_base("wallet-repair-cache-trigger")
            .outline()
            .xsmall()
            .px(px(10.0))
            .py(px(15.0))
            .disabled(disabled)
            .tooltip("Repair wallet cache")
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(img(icons::wrench_icon_path()).size(px(12.0)).flex_none()),
            )
            .on_click(move |_event, window, cx| {
                root.update(cx, |_root, cx| {
                    Self::open_repair_cache_dialog(window, cx);
                });
            })
    }

    fn render_repair_cache_dialog_content(&self, content_width: Pixels) -> gpui::Div {
        let input = self.repair_cache_block_input.clone();
        let error = self.repair_cache_error.clone();
        let start_block = self.selected_chain_wallet_start_block();
        let help_text = repair_cache_help_text(start_block.is_some());
        let start_block_hint = start_block.map(|start_block| {
            let hint_input = input.clone();
            let value = start_block.to_string();
            let label = match self.selected_wallet_source() {
                WalletSource::Generated => "generated wallet start block",
                WalletSource::Imported => "wallet init block",
            };

            div()
                .id("wallet-repair-current-start-block")
                .w_full()
                .px(px(8.0))
                .py(px(6.0))
                .rounded_sm()
                .cursor_pointer()
                .text_size(APP_TEXT_SIZE)
                .text_color(rgb(theme::PRIMARY))
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                .tooltip(|window, cx| {
                    Tooltip::new("Fill repair block with this start block").build(window, cx)
                })
                .on_click(move |_event, window, cx| {
                    hint_input.update(cx, |input, cx| {
                        input.set_value(&value, window, cx);
                    });
                })
                .child(SharedString::from(format!("Use {label}: {start_block}")))
        });

        div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .child(app_muted_text(help_text))
            .children(start_block_hint)
            .child(app_input(&input))
            .children(error.as_ref().map(|message| {
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::DANGER))
                    .child(SharedString::from(message.to_string()))
            }))
    }

    fn render_wallet_selector(&self) -> impl IntoElement {
        div().h(px(24.0)).w(px(180.0)).flex().items_center().child(
            Select::new(&self.wallet_select)
                .appearance(false)
                .small()
                .w(px(180.0))
                .h(px(24.0))
                .menu_width(px(220.0))
                .search_placeholder("Search wallets"),
        )
    }

    fn render_add_wallet_button(root: Entity<Self>) -> impl IntoElement {
        app_button_base("wallet-add-wallet-trigger")
            .outline()
            .xsmall()
            .h(px(24.0))
            .w(px(28.0))
            .tooltip("Add wallet")
            .icon(IconName::Plus)
            .on_click(move |_event, window, cx| {
                root.update(cx, |root, cx| {
                    root.open_add_wallet_dialog(window, cx);
                });
            })
    }

    fn render_wallet_tabs(&self, root: &Entity<Self>) -> impl IntoElement {
        let selected_index = WalletTab::ALL
            .iter()
            .position(|tab| *tab == self.active_wallet_tab)
            .unwrap_or(0);
        let tab_root = root.clone();

        TabBar::new("wallet-tabs")
            .underline()
            .w_full()
            .flex_none()
            .px(px(14.0))
            .selected_index(selected_index)
            .on_click(move |index, _window, cx| {
                let Some(tab) = WalletTab::ALL.get(*index).copied() else {
                    return;
                };
                tab_root.update(cx, |root, cx| {
                    root.select_wallet_tab(tab, cx);
                });
            })
            .children(WalletTab::ALL.into_iter().map(|tab| {
                Tab::new()
                    .min_w(px(92.0))
                    .label(tab.label())
                    .prefix(img(tab.icon_path()).size(px(16.0)).flex_none())
            }))
    }

    fn render_wallet_content(&self, root: &Entity<Self>, window: &Window) -> gpui::AnyElement {
        match self.active_wallet_tab {
            WalletTab::Private => self.render_private_assets_body(root),
            WalletTab::Public => self.render_public_wallet_body(root),
            WalletTab::Activity => self.render_utxo_body(root, window).into_any_element(),
        }
    }

    fn render_chain_error_body(&self, root: &Entity<Self>, message: &str) -> gpui::Div {
        let can_retry =
            matches!(self.vault_state, VaultState::ViewUnlocked) && self.view_session.is_some();
        let retry_root = root.clone();

        div()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_3()
            .child(
                div()
                    .max_w(px(520.0))
                    .text_color(rgb(theme::DANGER))
                    .text_align(gpui::TextAlign::Center)
                    .child(SharedString::from(message.to_owned())),
            )
            .when(can_retry, |this| {
                this.child(
                    app_button("wallet-chain-retry-sync", "Retry sync")
                        .outline()
                        .small()
                        .on_click(move |_event, _window, cx| {
                            retry_root.update(cx, |root, cx| {
                                if root.view_session.is_none() {
                                    return;
                                }
                                let chain_id = root.selected_chain;
                                let overrides = chain_load_overrides();
                                root.start_chain_load(chain_id, &overrides, true, cx);
                            });
                        }),
                )
            })
    }

    fn render_private_assets_body(&self, root: &Entity<Self>) -> gpui::AnyElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Error { message, .. }) => self
                .render_chain_error_body(root, message.as_ref())
                .into_any_element(),
            Some(ChainUtxoState::Loading { progress }) => {
                centered_message(loading_summary(*progress)).into_any_element()
            }
            Some(ChainUtxoState::Syncing {
                snapshot, progress, ..
            }) => Self::render_private_asset_snapshot(root, snapshot, false, true, *progress),
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                Self::render_private_asset_snapshot(root, snapshot, true, false, None)
            }
            Some(ChainUtxoState::Idle) | None => {
                centered_message("Select a chain to load private balances").into_any_element()
            }
        }
    }

    fn render_private_asset_snapshot(
        root: &Entity<Self>,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
        syncing: bool,
        progress: Option<SyncProgressUpdate>,
    ) -> gpui::AnyElement {
        let assets = format_private_asset_rows(snapshot.chain_id, &snapshot.totals);
        if assets.is_empty() {
            return centered_message(if syncing {
                loading_summary(progress)
            } else {
                "No private assets found".to_string()
            })
            .into_any_element();
        }

        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_y_scrollbar()
            .child(
                div()
                    .w(PRIVATE_ASSET_LIST_WIDTH)
                    .max_w_full()
                    .mx_auto()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .children(assets.into_iter().enumerate().map(|(ix, asset)| {
                        Self::render_private_asset_row(
                            root.clone(),
                            ix,
                            asset,
                            snapshot,
                            chain_ready,
                        )
                        .into_any_element()
                    })),
            )
            .into_any_element()
    }

    fn render_private_asset_row(
        root: Entity<Self>,
        ix: usize,
        asset: FormattedTokenTotal,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
    ) -> gpui::Div {
        let send_asset = build_send_asset(snapshot, &asset);
        let can_send = chain_ready && send_asset.is_some();
        let unshield_asset = build_unshield_asset(snapshot, &asset);
        let can_unshield = chain_ready && unshield_asset.is_some();
        let send_tooltip = if can_send {
            "Prepare private send calldata"
        } else if chain_ready {
            "Token cannot be sent from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let unshield_tooltip = if can_unshield {
            "Prepare unshield calldata"
        } else if chain_ready {
            "Token cannot be unshielded from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let send_opacity = if can_send { 1.0 } else { 0.5 };
        let unshield_opacity = if can_unshield { 1.0 } else { 0.5 };
        let show_pending_poi = should_show_pending_poi_amount(asset.pending_poi_total);
        let pending_poi_amount = asset.pending_poi_amount.clone();
        let send_root = root.clone();
        let unshield_root = root;

        div()
            .w_full()
            .flex()
            .items_center()
            .gap_4()
            .p(px(16.0))
            .rounded_lg()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .items_center()
                    .text_size(theme::ASSET_SYMBOL_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(private_asset_label_row(
                        SharedString::from(asset.label.clone()),
                        asset.icon_path,
                    )),
            )
            .child(
                div()
                    .min_w(px(150.0))
                    .flex()
                    .flex_col()
                    .items_end()
                    .child(
                        div()
                            .text_color(rgb(theme::WARNING))
                            .text_size(theme::BALANCE_TEXT_SIZE)
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(asset.amount)),
                    )
                    .when(show_pending_poi, |column| {
                        column.child(
                            app_muted_text(format!("*Pending POI: {pending_poi_amount}"))
                                .whitespace_nowrap()
                                .text_align(gpui::TextAlign::Right),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-send-{ix}")),
                            "Send",
                        )
                        .child(Icon::new(RailgunActionIcon::Send).small())
                        .outline()
                        .disabled(!can_send)
                        .opacity(send_opacity)
                        .tooltip(send_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = send_asset.clone() else {
                                return;
                            };
                            send_root.update(cx, |root, cx| {
                                root.open_send_form(asset, window, cx);
                            });
                        }),
                    )
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-unshield-{ix}")),
                            "Unshield",
                        )
                        .child(Icon::new(IconName::Globe).small())
                        .outline()
                        .disabled(!can_unshield)
                        .opacity(unshield_opacity)
                        .tooltip(unshield_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = unshield_asset.clone() else {
                                return;
                            };
                            unshield_root.update(cx, |root, cx| {
                                root.open_unshield_form(asset, window, cx);
                            });
                        }),
                    ),
            )
    }

    fn render_send_form(&self, root: Entity<Self>, key: UnshieldAssetKey) -> gpui::Div {
        let Some(form) = self.send_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let delivery_root = root.clone();
        let metrics_root = root.clone();
        let chooser_root = root.clone();
        let estimate_root = root.clone();
        let result_root = root.clone();
        let submit_root = root;
        let mut public_broadcaster_submit_disabled = false;

        let mut card =
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(render_private_action_metrics(
                    metrics_root,
                    key,
                    DeliveryFormKind::Send,
                    asset,
                    form.generating,
                ));

        if asset.total > asset.max_batched {
            card = card.child(Alert::warning(
                send_element_id(key, "spend-capacity-warning"),
                "Spend capacity is limited by private note fragmentation and POI verification status. One send can spend up to 8 proof chunks.",
            ).small());
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Send,
            form.delivery_mode,
            form.generating,
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let policy = Self::public_broadcaster_fee_policy(form.allow_suspicious_broadcasters);
            let fee_token_options =
                self.current_public_broadcaster_fee_token_options(asset.chain_id, false, policy);
            let selected_fee_token_count = selected_fee_token_eligible_broadcaster_count(
                &fee_token_options,
                form.selected_fee_token,
            )
            .unwrap_or_default();
            let has_eligible_fee_token = fee_token_options
                .iter()
                .any(|option| option.eligible_broadcaster_count > 0);
            public_broadcaster_submit_disabled =
                public_broadcaster_submit_disabled_for_fee_token_options(
                    &fee_token_options,
                    form.selected_fee_token,
                );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                form.selected_fee_token,
                false,
                policy,
            );
            let visible_candidates = fee_policy_eligible_public_broadcasters(&candidates, policy);
            if !has_eligible_fee_token {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Send, "fee-token-warning"),
                        "No POI-spendable wallet token currently has an eligible public broadcaster. Manual calldata remains available.",
                    )
                    .small(),
                );
            } else if selected_fee_token_count == 0 {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Send, "fee-token-warning"),
                        "Choose a fee token with at least one eligible public broadcaster before submitting.",
                    )
                    .small(),
                );
            }
            card = card.child(render_public_broadcaster_settings(
                chooser_root,
                key,
                DeliveryFormKind::Send,
                form.allow_suspicious_broadcasters,
                asset.token,
                form.broadcaster_fee_mode,
                &form.broadcaster_choice,
                visible_candidates,
                &fee_token_options,
                form.selected_fee_token,
                form.generating,
            ));
            if let Some(warning) = selected_broadcaster_fee_warning(
                &form.broadcaster_choice,
                &candidates,
                form.allow_suspicious_broadcasters,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Send, "fee-policy-warning"),
                        warning,
                    )
                    .small(),
                );
            }
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Recipient 0zk address"))
                            .child(
                                private_action_input(&form.recipient_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        div()
                            .w(px(220.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text(unit_hint))
                            .child(
                                private_action_input(&form.amount_input).disabled(form.generating),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Vault password"))
                            .child(
                                private_action_input(&form.password_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        app_button(
                            send_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(form.generating || public_broadcaster_submit_disabled)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_send_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if form.delivery_mode == DeliveryMode::PublicBroadcaster && form.result.is_none() {
            if let Some(estimate) = form.cost_estimate.as_ref() {
                let anchor_rate = self
                    .public_broadcaster_anchor_cache
                    .cached_rate(asset.chain_id, estimate.fee_token);
                card = card.child(render_public_broadcaster_cost_estimate(
                    estimate_root,
                    key,
                    DeliveryFormKind::Send,
                    asset,
                    estimate,
                    anchor_rate,
                    form.transaction_fee_breakdown_open,
                    form.estimating_cost,
                ));
            } else if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            }
        }

        if form.generating {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                Alert::error(
                    send_element_id(key, "form-error"),
                    format_form_error_for_asset(error, asset, form.selected_fee_token),
                )
                .small(),
            );
        }

        if let Some(result) = form.result.as_ref() {
            card = card.child(match result {
                SendResult::Manual(result) => render_send_result(key, result),
                SendResult::PublicBroadcaster(result) => {
                    let anchor_rate = self
                        .public_broadcaster_anchor_cache
                        .cached_rate(asset.chain_id, result.fee_token);
                    render_public_broadcaster_result(
                        result_root,
                        key,
                        DeliveryFormKind::Send,
                        result,
                        anchor_rate,
                        form.transaction_fee_breakdown_open,
                    )
                }
            });
        }

        card
    }

    fn render_unshield_form(&self, root: Entity<Self>, key: UnshieldAssetKey) -> gpui::Div {
        let Some(form) = self.unshield_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unwrap_supported = is_wrapped_native_token(asset.chain_id, asset.token);
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let delivery_root = root.clone();
        let metrics_root = root.clone();
        let chooser_root = root.clone();
        let output_root = root.clone();
        let estimate_root = root.clone();
        let result_root = root.clone();
        let submit_root = root;
        let mut public_broadcaster_submit_disabled = false;

        let mut card =
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(render_private_action_metrics(
                    metrics_root,
                    key,
                    DeliveryFormKind::Unshield,
                    asset,
                    form.generating,
                ));

        if asset.total > asset.max_batched {
            card = card.child(Alert::warning(
                unshield_element_id(key, "spend-capacity-warning"),
                "Spend capacity is limited by private note fragmentation and POI verification status. One unshield can spend up to 8 proof chunks.",
            ).small());
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Unshield,
            form.delivery_mode,
            form.generating,
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let policy = Self::public_broadcaster_fee_policy(form.allow_suspicious_broadcasters);
            let fee_token_options = self.current_public_broadcaster_fee_token_options(
                asset.chain_id,
                form.unwrap,
                policy,
            );
            let selected_fee_token_count = selected_fee_token_eligible_broadcaster_count(
                &fee_token_options,
                form.selected_fee_token,
            )
            .unwrap_or_default();
            let has_eligible_fee_token = fee_token_options
                .iter()
                .any(|option| option.eligible_broadcaster_count > 0);
            public_broadcaster_submit_disabled =
                public_broadcaster_submit_disabled_for_fee_token_options(
                    &fee_token_options,
                    form.selected_fee_token,
                );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                form.selected_fee_token,
                form.unwrap,
                policy,
            );
            let visible_candidates = fee_policy_eligible_public_broadcasters(&candidates, policy);
            if !has_eligible_fee_token {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Unshield, "fee-token-warning"),
                        "No POI-spendable wallet token currently has an eligible public broadcaster. Manual calldata remains available.",
                    )
                    .small(),
                );
            } else if selected_fee_token_count == 0 {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Unshield, "fee-token-warning"),
                        "Choose a fee token with at least one eligible public broadcaster before submitting.",
                    )
                    .small(),
                );
            }
            card = card.child(render_public_broadcaster_settings(
                chooser_root,
                key,
                DeliveryFormKind::Unshield,
                form.allow_suspicious_broadcasters,
                asset.token,
                form.broadcaster_fee_mode,
                &form.broadcaster_choice,
                visible_candidates,
                &fee_token_options,
                form.selected_fee_token,
                form.generating,
            ));
            if let Some(warning) = selected_broadcaster_fee_warning(
                &form.broadcaster_choice,
                &candidates,
                form.allow_suspicious_broadcasters,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Unshield, "fee-policy-warning"),
                        warning,
                    )
                    .small(),
                );
            }
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Recipient"))
                            .child(
                                private_action_input(&form.recipient_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .children(unwrap_supported.then(|| {
                        render_unshield_output_toggle(
                            output_root.clone(),
                            key,
                            asset.chain_id,
                            form.unwrap,
                            form.generating,
                        )
                    }))
                    .child(
                        div()
                            .w(px(220.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text(unit_hint))
                            .child(
                                private_action_input(&form.amount_input).disabled(form.generating),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Vault password"))
                            .child(
                                private_action_input(&form.password_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        app_button(
                            unshield_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(form.generating || public_broadcaster_submit_disabled)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_unshield_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if form.delivery_mode == DeliveryMode::PublicBroadcaster && form.result.is_none() {
            if let Some(estimate) = form.cost_estimate.as_ref() {
                let anchor_rate = self
                    .public_broadcaster_anchor_cache
                    .cached_rate(asset.chain_id, estimate.fee_token);
                card = card.child(render_public_broadcaster_cost_estimate(
                    estimate_root,
                    key,
                    DeliveryFormKind::Unshield,
                    asset,
                    estimate,
                    anchor_rate,
                    form.transaction_fee_breakdown_open,
                    form.estimating_cost,
                ));
            } else if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            }
        }

        if form.generating {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                Alert::error(
                    unshield_element_id(key, "form-error"),
                    format_form_error_for_asset(error, asset, form.selected_fee_token),
                )
                .small(),
            );
        }

        if let Some(result) = form.result.as_ref() {
            card = card.child(match result {
                UnshieldResult::Manual(result) => render_unshield_result(key, result),
                UnshieldResult::PublicBroadcaster(result) => {
                    let anchor_rate = self
                        .public_broadcaster_anchor_cache
                        .cached_rate(asset.chain_id, result.fee_token);
                    render_public_broadcaster_result(
                        result_root,
                        key,
                        DeliveryFormKind::Unshield,
                        result,
                        anchor_rate,
                        form.transaction_fee_breakdown_open,
                    )
                }
            });
        }

        card
    }

    fn render_public_wallet_body(&self, root: &Entity<Self>) -> gpui::AnyElement {
        let refresh_root = root.clone();

        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_y_scrollbar()
            .child(
                div()
                    .w(px(980.0))
                    .max_w_full()
                    .mx_auto()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().flex_1().min_w(px(0.0)))
                            .child(
                                app_button(
                                    "wallet-public-refresh",
                                    if self.public_balance_refreshing {
                                        "Refreshing..."
                                    } else {
                                        "Refresh"
                                    },
                                )
                                .outline()
                                .small()
                                .loading(self.public_balance_refreshing)
                                .disabled(
                                    self.public_balance_refreshing
                                        || !self.has_active_public_accounts(),
                                )
                                .on_click(
                                    move |_event, _window, cx| {
                                        refresh_root.update(cx, |root, cx| {
                                            root.schedule_public_balance_refresh(cx);
                                        });
                                    },
                                ),
                            )
                            .child(self.render_public_add_account_dropdown(root)),
                    )
                    .children(self.public_balance_error.as_ref().map(|message| {
                        Alert::warning("wallet-public-balance-error", message.to_string())
                            .title("Public balances unavailable")
                            .small()
                    }))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-error", message.to_string()).small()
                    }))
                    .child(self.render_public_account_list(root)),
            )
            .into_any_element()
    }

    fn render_public_add_account_dropdown(&self, root: &Entity<Self>) -> impl IntoElement {
        let derive_root = root.clone();
        let import_root = root.clone();
        app_button("wallet-public-add-account-trigger", "Add account")
            .primary()
            .small()
            .dropdown_caret(true)
            .disabled(
                self.vault_store.is_none()
                    || self.view_session.is_none()
                    || self.public_form.adding_account
                    || self.public_form.importing_account,
            )
            .dropdown_menu(move |menu, _window, _cx| {
                let derive_root = derive_root.clone();
                let import_root = import_root.clone();
                menu.min_w(px(190.0))
                    .item(PopupMenuItem::new("Derive from private").on_click(
                        move |_event, window, cx| {
                            derive_root.update(cx, |root, cx| {
                                root.open_public_account_dialog(
                                    PublicAccountDialogKind::Derive,
                                    window,
                                    cx,
                                );
                            });
                        },
                    ))
                    .item(PopupMenuItem::new("Import private key").on_click(
                        move |_event, window, cx| {
                            import_root.update(cx, |root, cx| {
                                root.open_public_account_dialog(
                                    PublicAccountDialogKind::Import,
                                    window,
                                    cx,
                                );
                            });
                        },
                    ))
            })
    }

    fn render_public_account_dialog_content(
        &self,
        root: Entity<Self>,
        kind: PublicAccountDialogKind,
        content_width: Pixels,
    ) -> gpui::Div {
        match kind {
            PublicAccountDialogKind::Derive => {
                let add_root = root;
                let next_index = self.public_form.next_derived_index.map_or_else(
                    || "Next index unavailable".to_string(),
                    |index| format!("Next derived index: {index}"),
                );
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Derive a Public EVM account from the selected Private wallet mnemonic.",
                    ))
                    .child(app_muted_text(next_index))
                    .child(app_input(&self.public_form.add_label_input))
                    .child(app_input(&self.public_form.add_password_input))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-add-derived-error", message.to_string()).small()
                    }))
                    .child(
                        app_button(
                            "wallet-public-add-derived-submit",
                            if self.public_form.adding_account {
                                "Deriving..."
                            } else {
                                "Derive account"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.adding_account)
                        .disabled(self.public_form.adding_account)
                        .on_click(move |_event, window, cx| {
                            add_root.update(cx, |root, cx| {
                                root.add_public_derived_account_from_input(window, cx);
                            });
                        }),
                    )
            }
            PublicAccountDialogKind::Import => {
                let import_root = root.clone();
                let global_root = root;
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Import an EVM private key as a vaulted Public account.",
                    ))
                    .child(app_input(&self.public_form.import_label_input))
                    .child(app_input(&self.public_form.import_private_key_input))
                    .child(app_input(&self.public_form.import_password_input))
                    .child(
                        Checkbox::new("wallet-public-import-global")
                            .label("Global account")
                            .checked(self.public_form.import_global)
                            .small()
                            .on_click(move |checked, _window, cx| {
                                let checked = *checked;
                                global_root.update(cx, |root, cx| {
                                    root.public_form.import_global = checked;
                                    cx.notify();
                                });
                            }),
                    )
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-import-error", message.to_string()).small()
                    }))
                    .child(
                        app_button(
                            "wallet-public-import-submit",
                            if self.public_form.importing_account {
                                "Importing..."
                            } else {
                                "Import account"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.importing_account)
                        .disabled(self.public_form.importing_account)
                        .on_click(move |_event, window, cx| {
                            import_root.update(cx, |root, cx| {
                                root.import_public_account_from_input(window, cx);
                            });
                        }),
                    )
            }
            PublicAccountDialogKind::EditLabel => {
                let save_root = root;
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_input(&self.public_form.edit_label_input))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-edit-label-error", message.to_string()).small()
                    }))
                    .child(
                        app_button("wallet-public-save-label", "Save")
                            .primary()
                            .small()
                            .on_click(move |_event, window, cx| {
                                save_root.update(cx, |root, cx| {
                                    root.update_selected_public_account_label(window, cx);
                                });
                            }),
                    )
            }
        }
    }

    fn render_public_account_list(&self, root: &Entity<Self>) -> gpui::Div {
        let search_query = self.public_form.search_query.as_ref();
        let search_active = !search_query.is_empty();
        let clear_search_input = self.public_form.search_input.clone();
        let search_input =
            app_input(&self.public_form.search_input)
                .small()
                .when(search_active, |input| {
                    input.suffix(
                        app_button_base("wallet-public-account-search-clear")
                            .ghost()
                            .xsmall()
                            .tooltip("Clear search")
                            .icon(IconName::Close)
                            .on_click(move |_event, window, cx| {
                                clear_search_input.update(cx, |input, cx| {
                                    input.set_value("", window, cx);
                                });
                            }),
                    )
                });
        let mut card = div().w_full().flex().flex_col().gap_4();
        let controls = div()
            .w_full()
            .flex()
            .items_center()
            .justify_start()
            .gap_2()
            .child(div().w(px(260.0)).child(search_input));
        card = card.child(controls);
        if self.public_accounts.is_empty() {
            return card.child(app_muted_text(
                "No Public accounts yet. Add a derived account or import a private key.",
            ));
        }
        let accounts = if search_active {
            self.public_accounts
                .iter()
                .filter(|account| public_account_matches_search(account, search_query))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            self.public_accounts.clone()
        };
        if accounts.is_empty() {
            return card.child(app_muted_text("No Public accounts match this search."));
        }

        let active_accounts = accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect::<Vec<_>>();
        let inactive_accounts = accounts
            .into_iter()
            .filter(|account| account.status == PublicAccountStatus::Inactive)
            .collect::<Vec<_>>();
        let active_open =
            self.public_form.active_accounts_open || (search_active && !active_accounts.is_empty());
        let inactive_open = self.public_form.inactive_accounts_open
            || (search_active && !inactive_accounts.is_empty());
        card = card
            .child(self.render_public_account_section(
                root,
                PublicAccountStatus::Active,
                "Active",
                &active_accounts,
                active_open,
            ))
            .child(self.render_public_account_section(
                root,
                PublicAccountStatus::Inactive,
                "Inactive",
                &inactive_accounts,
                inactive_open,
            ));
        card
    }

    fn render_public_account_section(
        &self,
        root: &Entity<Self>,
        status: PublicAccountStatus,
        title: &'static str,
        accounts: &[PublicAccountMetadata],
        open: bool,
    ) -> impl IntoElement {
        let section_id = public_account_status_id(status);
        let toggle_root = root.clone();
        let fetch_root = root.clone();
        let toggle_button_root = root.clone();
        let count = accounts.len();
        let mut header_actions = div()
            .flex()
            .flex_none()
            .items_center()
            .justify_end()
            .gap_2();
        if status == PublicAccountStatus::Inactive && open && count > 0 {
            header_actions = header_actions.child(
                app_button(
                    "wallet-public-inactive-fetch-balances",
                    if self.public_inactive_balance_refreshing {
                        "Fetching..."
                    } else {
                        "Fetch balances"
                    },
                )
                .outline()
                .xsmall()
                .loading(self.public_inactive_balance_refreshing)
                .disabled(self.public_inactive_balance_refreshing)
                .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                    cx.stop_propagation();
                })
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    fetch_root.update(cx, |root, cx| {
                        root.schedule_inactive_public_balance_refresh(cx);
                    });
                }),
            );
        }
        header_actions = header_actions.child(
            app_button_base(SharedString::from(format!(
                "wallet-public-{section_id}-accounts-toggle"
            )))
            .ghost()
            .xsmall()
            .text_color(rgb(theme::PRIMARY))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(if open { "Hide" } else { "Show" })
                    .child(
                        Icon::new(if open {
                            IconName::ChevronUp
                        } else {
                            IconName::ChevronDown
                        })
                        .xsmall()
                        .text_color(rgb(theme::PRIMARY)),
                    ),
            )
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .on_click(move |_event, _window, cx| {
                cx.stop_propagation();
                toggle_button_root.update(cx, |root, cx| {
                    root.set_public_account_section_open(status, !open, cx);
                });
            }),
        );
        let header = div()
            .id(SharedString::from(format!(
                "wallet-public-{section_id}-accounts-header"
            )))
            .w_full()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .px(px(10.0))
            .py(px(3.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .cursor_pointer()
            .on_click(move |_event, _window, cx| {
                toggle_root.update(cx, |root, cx| {
                    root.set_public_account_section_open(status, !open, cx);
                });
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(12.0))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(SharedString::from(format!(
                        "{} · {count}",
                        title.to_ascii_uppercase()
                    ))),
            )
            .child(header_actions);

        let mut content = div().w_full().flex().flex_col().gap_3().pt(px(4.0));
        if status == PublicAccountStatus::Inactive {
            content =
                content.children(self.public_inactive_balance_error.as_ref().map(|message| {
                    Alert::warning("wallet-public-inactive-balance-error", message.to_string())
                        .title("Inactive balances unavailable")
                        .small()
                }));
        }
        if accounts.is_empty() {
            content = content.child(app_muted_text(if status == PublicAccountStatus::Active {
                "No active Public accounts."
            } else {
                "No inactive Public accounts."
            }));
        } else {
            for account in accounts {
                content = content.child(self.render_public_account_card(root, account));
            }
        }

        Collapsible::new()
            .open(open)
            .w_full()
            .child(header)
            .content(content)
    }

    fn render_public_account_card(
        &self,
        root: &Entity<Self>,
        account: &PublicAccountMetadata,
    ) -> gpui::Div {
        let selected = self
            .public_form
            .selected_account_uuid
            .as_ref()
            .is_some_and(|selected| selected.as_ref() == account.public_account_uuid);
        let account_uuid = Arc::from(account.public_account_uuid.as_str());
        let row_group = SharedString::from(format!(
            "wallet-public-account-row-{}",
            account.public_account_uuid
        ));
        let edit_root = root.clone();
        let address_dialog_root = root.clone();
        let deactivate_root = root.clone();
        let activate_root = root.clone();
        let delete_root = root.clone();
        let address_display = short_address(&account.address);
        let edit_uuid = Arc::clone(&account_uuid);
        let address_dialog_uuid = Arc::clone(&account_uuid);
        let address_dialog_address = account.address;
        let source_badge = public_account_metadata_badge(
            SharedString::from(format!(
                "wallet-public-account-source-{}",
                account.public_account_uuid
            )),
            Icon::new(public_account_source_icon(account.source)),
            public_account_source_label(account.source),
        );
        let mut metadata_badges = div().flex().items_center().gap_1().child(source_badge);
        if account.is_global() {
            metadata_badges = metadata_badges.child(public_account_metadata_badge(
                SharedString::from(format!(
                    "wallet-public-account-scope-{}",
                    account.public_account_uuid
                )),
                Icon::new(RailgunPublicAccountIcon::Global),
                "Available across wallets",
            ));
        }
        let account_label = public_account_display_label(account);
        let address_dialog_label = account_label.clone();
        let action_buttons = div()
            .group(row_group.clone())
            .flex()
            .flex_none()
            .items_center()
            .gap_1()
            .opacity(0.0)
            .group_hover(row_group.clone(), |this| this.opacity(1.0))
            .hover(|this| this.opacity(1.0))
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .child(
                public_account_icon_button(
                    SharedString::from(format!(
                        "wallet-public-edit-{}",
                        account.public_account_uuid
                    )),
                    Icon::new(RailgunActionIcon::Pencil),
                    "Edit label",
                )
                .on_click(move |_event, window, cx| {
                    let account_uuid = Arc::clone(&edit_uuid);
                    edit_root.update(cx, |root, cx| {
                        root.open_public_account_edit_dialog(account_uuid, window, cx);
                    });
                }),
            );
        let action_buttons = match account.source {
            PublicAccountSource::Derived => {
                let status_uuid = Arc::clone(&account_uuid);
                let inactive = account.status == PublicAccountStatus::Inactive;
                action_buttons.child(
                    public_account_icon_button(
                        SharedString::from(format!(
                            "wallet-public-{}-{}",
                            if inactive { "activate" } else { "deactivate" },
                            account.public_account_uuid
                        )),
                        if inactive {
                            IconName::Eye
                        } else {
                            IconName::EyeOff
                        },
                        if inactive {
                            "Activate account"
                        } else {
                            "Deactivate account"
                        },
                    )
                    .on_click(move |_event, window, cx| {
                        let account_uuid = Arc::clone(&status_uuid);
                        if inactive {
                            activate_root.update(cx, |root, cx| {
                                root.activate_public_account(&account_uuid, window, cx);
                            });
                        } else {
                            deactivate_root.update(cx, |root, cx| {
                                root.deactivate_public_account(&account_uuid, window, cx);
                            });
                        }
                    }),
                )
            }
            PublicAccountSource::Imported => {
                let delete_uuid = Arc::clone(&account_uuid);
                let confirming_global_delete = account.is_global()
                    && self.public_form.pending_global_delete_uuid.as_deref()
                        == Some(account.public_account_uuid.as_str());
                action_buttons.child(
                    public_account_icon_button(
                        SharedString::from(format!(
                            "wallet-public-delete-{}",
                            account.public_account_uuid
                        )),
                        Icon::new(RailgunActionIcon::Trash2),
                        if confirming_global_delete {
                            "Confirm global delete"
                        } else {
                            "Delete account"
                        },
                    )
                    .danger()
                    .on_click(move |_event, window, cx| {
                        let account_uuid = Arc::clone(&delete_uuid);
                        delete_root.update(cx, |root, cx| {
                            root.delete_public_account(&account_uuid, window, cx);
                        });
                    }),
                )
            }
        };
        let account_label = account_label.map_or_else(
            || {
                app_strong_text(" ")
                    .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                    .whitespace_nowrap()
                    .opacity(0.0)
            },
            |label| {
                app_strong_text(label)
                    .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                    .whitespace_nowrap()
            },
        );
        let mut account_content = div()
            .w_full()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().min_w(px(0.0)).child(account_label))
                    .child(action_buttons),
            )
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .min_w(px(0.0))
                            .flex_1()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!(
                                        "wallet-public-address-qr-action-{}",
                                        account.public_account_uuid
                                    )))
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .rounded_sm()
                                    .px(px(2.0))
                                    .py(px(1.0))
                                    .cursor_pointer()
                                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                                    .tooltip(|window, cx| {
                                        Tooltip::new("Show address QR code").build(window, cx)
                                    })
                                    .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                                        cx.stop_propagation();
                                    })
                                    .on_click(move |_event, window, cx| {
                                        cx.stop_propagation();
                                        let account_uuid = Arc::clone(&address_dialog_uuid);
                                        let label = address_dialog_label.clone();
                                        address_dialog_root.update(cx, |root, cx| {
                                            root.open_public_address_qr_dialog(
                                                account_uuid.as_ref(),
                                                label,
                                                address_dialog_address,
                                                window,
                                                cx,
                                            );
                                        });
                                    })
                                    .child(
                                        app_muted_text(address_display)
                                            .font_family(APP_MONO_FONT_FAMILY)
                                            .text_size(theme::ACCOUNT_ADDRESS_TEXT_SIZE)
                                            .text_color(rgb(theme::TEXT_SUBTLE))
                                            .whitespace_nowrap(),
                                    )
                                    .child(
                                        div()
                                            .group(row_group.clone())
                                            .flex_none()
                                            .opacity(0.0)
                                            .group_hover(row_group.clone(), |this| {
                                                this.opacity(1.0)
                                            })
                                            .child(
                                                Icon::new(RailgunActionIcon::QrCode)
                                                    .xsmall()
                                                    .text_color(rgb(theme::TEXT)),
                                            ),
                                    ),
                            ),
                    )
                    .child(metadata_badges),
            );

        let visible_balances =
            self.public_account_visible_balances(&account.public_account_uuid, account.status);
        if !visible_balances.is_empty() {
            let mut balance_chips = div().w_full().flex().flex_wrap().gap_2().pt(px(2.0));
            for (balance_index, entry) in visible_balances.iter().enumerate() {
                balance_chips = balance_chips.child(self.render_public_account_balance_chip(
                    root,
                    Arc::clone(&account_uuid),
                    selected,
                    balance_index,
                    entry,
                ));
            }
            account_content = account_content.child(balance_chips);
        }
        let mut account_card = div()
            .group(row_group)
            .w_full()
            .flex()
            .flex_col()
            .gap_2()
            .p(px(14.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .hover(|row| row.border_color(rgb(theme::PRIMARY)))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_4()
                    .child(render_public_account_identicon(&account.address))
                    .child(account_content),
            );
        if account.is_global()
            && self.public_form.pending_global_delete_uuid.as_deref()
                == Some(account.public_account_uuid.as_str())
        {
            account_card = account_card.child(
                Alert::warning(
                    SharedString::from(format!(
                        "wallet-public-global-delete-warning-{}",
                        account.public_account_uuid
                    )),
                    "Deleting this global account removes it from every Private wallet.",
                )
                .small(),
            );
        }
        account_card
    }

    fn render_public_account_balance_chip(
        &self,
        root: &Entity<Self>,
        account_uuid: Arc<str>,
        selected_account: bool,
        index: usize,
        entry: &PublicBalanceEntry,
    ) -> impl IntoElement {
        let select_root = root.clone();
        let asset = entry.asset.id;
        let selected = selected_account && self.public_form.selected_asset == Some(asset);
        let icon_path = public_asset_icon_path(self.selected_chain, asset);
        let amount_label = public_balance_amount_label(&entry.amount, entry.asset.decimals);
        let symbol = entry.asset.symbol;
        let tooltip = SharedString::from(format!("Shield/send {symbol}"));
        let balance_id = SharedString::from(format!(
            "wallet-public-account-balance-{}-{index}",
            account_uuid.as_ref()
        ));
        let balance_group = SharedString::from(format!(
            "wallet-public-account-balance-group-{}-{index}",
            account_uuid.as_ref()
        ));
        let mut asset_label = div().flex().items_center().gap_1();
        if let Some(path) = icon_path {
            asset_label = asset_label.child(img(path).size(px(16.0)).rounded_full().flex_none());
        }
        div()
            .id(balance_id)
            .group(balance_group.clone())
            .min_w(PUBLIC_BALANCE_CHIP_MIN_WIDTH)
            .flex_none()
            .flex()
            .items_center()
            .gap_2()
            .px(px(8.0))
            .py(px(5.0))
            .rounded_md()
            .border_1()
            .border_color(if selected {
                rgb(theme::PRIMARY)
            } else {
                rgb(theme::BORDER_SUBTLE)
            })
            .bg(if selected {
                rgb(theme::SURFACE_HOVER_SUBTLE)
            } else {
                rgb(theme::SURFACE)
            })
            .text_size(APP_TEXT_SIZE)
            .cursor_pointer()
            .hover(|this| {
                this.bg(rgb(theme::SURFACE_ELEVATED))
                    .border_color(if selected {
                        rgb(theme::PRIMARY)
                    } else {
                        rgb(theme::BORDER)
                    })
            })
            .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .on_click(move |_event, window, cx| {
                let account_uuid = Arc::clone(&account_uuid);
                select_root.update(cx, |root, cx| {
                    root.open_public_action_dialog(account_uuid, asset, window, cx);
                });
            })
            .child(
                asset_label
                    .flex_none()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(SharedString::from(symbol)),
            )
            .child(
                div()
                    .flex_none()
                    .text_color(rgb(theme::WARNING))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(SharedString::from(amount_label)),
            )
            .child(div().flex_1())
            .child(
                div()
                    .group(balance_group.clone())
                    .size(PUBLIC_BALANCE_CHIP_ACTION_SLOT_SIZE)
                    .flex_none()
                    .flex()
                    .items_center()
                    .justify_center()
                    .opacity(0.0)
                    .group_hover(balance_group, |this| this.opacity(1.0))
                    .hover(|this| this.opacity(1.0))
                    .child(
                        Icon::new(RailgunActionIcon::Shield)
                            .with_size(PUBLIC_BALANCE_CHIP_ACTION_ICON_SIZE)
                            .text_color(rgb(theme::WARNING_STRONG)),
                    ),
            )
    }

    fn render_public_action_dialog_content(
        &self,
        root: Entity<Self>,
        content_width: Pixels,
    ) -> gpui::Div {
        let mode = self.public_form.action_mode;
        let account = self.selected_public_account();
        let selected_asset = self.public_form.selected_asset;
        let balance_entry = self.selected_public_balance_entry();
        let asset_label = selected_asset.map_or_else(
            || "selected asset".to_string(),
            |asset| public_asset_label(self.selected_chain, asset),
        );
        let disabled = account.is_none() || selected_asset.is_none();
        let submitting = self.public_form.sending || self.public_form.shielding;
        let mode_root = root.clone();
        let submit_root = root.clone();
        let stepper_root = root.clone();
        let max_root = root;
        let show_form_errors = self.public_form.action_progress.is_empty();
        let max_label = balance_entry.as_ref().and_then(public_action_max_label);
        let amount_hint = format!("{asset_label} amount");
        let mut content = div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .children(account.map(|account| {
                app_muted_text(format!("From {}", short_address(&account.address)))
                    .font_family(APP_MONO_FONT_FAMILY)
            }))
            .child(
                ButtonGroup::new("wallet-public-action-mode-toggle")
                    .w_full()
                    .outline()
                    .disabled(submitting)
                    .child(public_action_segment_button(
                        "wallet-public-action-mode-shield".into(),
                        "Shield",
                        Icon::new(RailgunActionIcon::Shield),
                        mode == PublicActionMode::Shield,
                    ))
                    .child(public_action_segment_button(
                        "wallet-public-action-mode-send".into(),
                        "Send",
                        Icon::new(RailgunActionIcon::Send),
                        mode == PublicActionMode::Send,
                    ))
                    .on_click(move |selected, window, cx| {
                        let Some(index) = selected.first() else {
                            return;
                        };
                        let mode = if *index == 0 {
                            PublicActionMode::Shield
                        } else {
                            PublicActionMode::Send
                        };
                        mode_root.update(cx, |root, cx| {
                            root.set_public_action_mode(mode, window, cx);
                        });
                    }),
            );

        match mode {
            PublicActionMode::Shield => {
                content = content
                    .child(render_public_action_amount_input(
                        max_root,
                        PublicActionMode::Shield,
                        &self.public_form.shield_amount_input,
                        amount_hint,
                        max_label,
                        disabled || self.public_form.shielding,
                    ))
                    .child(
                        app_input(&self.public_form.shield_password_input)
                            .disabled(disabled || self.public_form.shielding),
                    )
                    .child(
                        app_button(
                            "wallet-public-shield",
                            if self.public_form.shielding {
                                "Shielding..."
                            } else {
                                "Shield"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.shielding)
                        .disabled(disabled || self.public_form.shielding)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.submit_public_shield_from_form(window, cx);
                            });
                        }),
                    );
                if show_form_errors && let Some(error) = self.public_form.shield_error.as_ref() {
                    content = content.child(
                        Alert::error("wallet-public-shield-error", error.to_string()).small(),
                    );
                }
            }
            PublicActionMode::Send => {
                content = content
                    .child(
                        app_input(&self.public_form.send_recipient_input)
                            .disabled(disabled || self.public_form.sending),
                    )
                    .child(render_public_action_amount_input(
                        max_root,
                        PublicActionMode::Send,
                        &self.public_form.send_amount_input,
                        amount_hint,
                        max_label,
                        disabled || self.public_form.sending,
                    ))
                    .child(
                        app_input(&self.public_form.send_password_input)
                            .disabled(disabled || self.public_form.sending),
                    )
                    .child(
                        app_button(
                            "wallet-public-send",
                            if self.public_form.sending {
                                "Sending..."
                            } else {
                                "Send publicly"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.sending)
                        .disabled(disabled || self.public_form.sending)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.submit_public_send_from_form(window, cx);
                            });
                        }),
                    );
                if show_form_errors && let Some(error) = self.public_form.send_error.as_ref() {
                    content = content
                        .child(Alert::error("wallet-public-send-error", error.to_string()).small());
                }
            }
        }

        if !self.public_form.action_progress.is_empty() {
            let action_asset_label = selected_asset.map_or_else(
                || asset_label.clone(),
                |asset| public_action_asset_label(self.selected_chain, asset),
            );
            content = content.child(render_public_action_stepper(
                &stepper_root,
                &self.public_form.action_progress,
                &self.public_form.expanded_action_error_steps,
                &action_asset_label,
            ));
        }
        content
    }

    fn public_account_visible_balances(
        &self,
        public_account_uuid: &str,
        status: PublicAccountStatus,
    ) -> Vec<PublicBalanceEntry> {
        public_account_visible_balances_for_chain(
            self.public_balance_snapshot.as_deref(),
            self.selected_chain,
            public_account_uuid,
            status,
        )
    }

    fn render_chain_selector(&self) -> impl IntoElement {
        div().h(px(24.0)).w(px(130.0)).flex().items_center().child(
            Select::new(&self.chain_select)
                .appearance(false)
                .small()
                .w(px(130.0))
                .h(px(24.0))
                .menu_width(px(150.0)),
        )
    }

    fn render_utxo_body(&self, root: &Entity<Self>, window: &Window) -> impl IntoElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Error { message, .. }) => {
                self.render_chain_error_body(root, message.as_ref())
            }
            Some(ChainUtxoState::Ready { snapshot, .. }) if snapshot.utxo_count == 0 => {
                centered_message("No UTXOs found")
            }
            Some(state) if state.renders_table() => div()
                .size_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .gap_2()
                .child(self.render_utxo_controls(root.clone()))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .min_h(px(0.0))
                        .on_mouse_down(MouseButton::Left, {
                            let table = self.utxo_table.clone();
                            move |_event, window, cx| {
                                table.update(cx, |table, cx| {
                                    table.focus_handle(cx).focus(window);
                                });
                            }
                        })
                        .on_action(window.listener_for(root, Self::on_action_utxo_page_up))
                        .on_action(window.listener_for(root, Self::on_action_utxo_page_down))
                        .on_action(window.listener_for(root, Self::on_action_utxo_home))
                        .on_action(window.listener_for(root, Self::on_action_utxo_end))
                        .child(Table::new(&self.utxo_table)),
                ),
            _ => centered_message("Select a chain to load UTXOs"),
        }
    }

    fn render_utxo_controls(&self, root: Entity<Self>) -> impl IntoElement {
        let search_active = !self.tx_search_query.is_empty();
        let clear_search_input = self.tx_search_input.clone();
        let clear_search_table = self.utxo_table.clone();
        let search_input = app_input(&self.tx_search_input)
            .small()
            .when(search_active, |input| {
                input.suffix(
                    app_button_base("wallet-search-clear")
                        .ghost()
                        .xsmall()
                        .tooltip("Clear search")
                        .icon(IconName::Close)
                        .on_click(move |_event, window, cx| {
                            clear_search_input.update(cx, |input, cx| {
                                input.set_value("", window, cx);
                            });
                            clear_search_table.update(cx, |table, cx| {
                                table.focus_handle(cx).focus(window);
                            });
                        }),
                )
            });
        let spent_toggle = Checkbox::new("wallet-toggle-spent-utxos")
            .label("Show spent")
            .checked(self.show_spent_utxos)
            .xsmall()
            .disabled(search_active)
            .opacity(if search_active { 0.45 } else { 1.0 })
            .on_click(move |checked, _window, cx| {
                let checked = *checked;
                root.update(cx, |root, cx| {
                    root.set_spent_visibility(checked, cx);
                });
            });

        div()
            .flex_none()
            .flex()
            .items_center()
            .justify_start()
            .gap_2()
            .child(div().w(px(280.0)).child(search_input))
            .child(spent_toggle)
    }

    fn on_action_utxo_page_up(
        &mut self,
        _: &UtxoPageUp,
        _: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.navigate_utxo_table(UtxoNavigation::PageUp, cx);
    }

    fn on_action_utxo_page_down(
        &mut self,
        _: &UtxoPageDown,
        _: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.navigate_utxo_table(UtxoNavigation::PageDown, cx);
    }

    fn on_action_utxo_home(&mut self, _: &UtxoHome, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.navigate_utxo_table(UtxoNavigation::Home, cx);
    }

    fn on_action_utxo_end(&mut self, _: &UtxoEnd, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.navigate_utxo_table(UtxoNavigation::End, cx);
    }

    fn navigate_utxo_table(&self, navigation: UtxoNavigation, cx: &mut Context<'_, Self>) {
        if !should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&self.selected_chain),
        ) {
            return;
        }

        self.utxo_table.update(cx, |table, cx| {
            let rows_count = table.delegate().rows_count(cx);
            if rows_count == 0 {
                return;
            }

            let visible_rows = table.visible_range().rows().clone();
            let page_size = visible_rows.len().saturating_sub(1).max(1);
            let last_row = rows_count.saturating_sub(1);
            let selected_row = table.selected_row();
            let target_row = match navigation {
                UtxoNavigation::Home => 0,
                UtxoNavigation::End => last_row,
                UtxoNavigation::PageUp => selected_row
                    .unwrap_or(visible_rows.start)
                    .saturating_sub(page_size),
                UtxoNavigation::PageDown => selected_row
                    .unwrap_or_else(|| visible_rows.end.saturating_sub(1))
                    .saturating_add(page_size)
                    .min(last_row),
            };

            table.set_selected_row(target_row, cx);
        });
    }

    fn render_logs_drawer(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .h(px(34.0))
                    .flex()
                    .items_center()
                    .px(px(12.0))
                    .bg(rgb(theme::SURFACE))
                    .border_b_1()
                    .border_color(rgb(theme::BORDER))
                    .child(img(icons::logs_icon_path()).size(px(16.0)).flex_none())
                    .child(
                        div()
                            .ml(px(8.0))
                            .text_color(rgb(theme::TEXT))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Logs"),
                    )
                    .child(div().flex_1())
                    .child(
                        app_button_base("close-wallet-logs-drawer")
                            .ghost()
                            .xsmall()
                            .tooltip("Hide logs")
                            .icon(IconName::Close)
                            .on_click(move |_event, _window, cx| {
                                root.update(cx, |root, cx| {
                                    root.logs_open = false;
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.logs.clone()),
            )
    }

    fn broadcaster_picker_dialog_snapshot(
        &self,
        window: &Window,
        cx: &App,
    ) -> Option<BroadcasterPickerDialogSnapshot> {
        let picker = self.broadcaster_picker.as_ref()?;
        let (chain_id, token, unwrap, current_choice, generating, show_all_broadcasters) =
            (match picker.kind {
                DeliveryFormKind::Send => self.send_forms.get(&picker.key).map(|form| {
                    (
                        form.asset.chain_id,
                        form.selected_fee_token,
                        false,
                        form.broadcaster_choice.clone(),
                        form.generating,
                        form.allow_suspicious_broadcasters,
                    )
                }),
                DeliveryFormKind::Unshield => self.unshield_forms.get(&picker.key).map(|form| {
                    (
                        form.asset.chain_id,
                        form.selected_fee_token,
                        form.unwrap,
                        form.broadcaster_choice.clone(),
                        form.generating,
                        form.allow_suspicious_broadcasters,
                    )
                }),
            })?;
        let query = picker
            .query_input
            .read(cx)
            .value()
            .trim()
            .to_ascii_lowercase();
        let policy = Self::public_broadcaster_fee_policy(show_all_broadcasters);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, token, unwrap, policy);
        let candidates = if show_all_broadcasters {
            candidates
        } else {
            fee_policy_eligible_public_broadcasters(&candidates, policy)
        };
        let candidates = sort_specific_public_broadcasters(candidates);
        let total_count = candidates.len();
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| broadcaster_candidate_matches_query(candidate, &query))
            .collect();
        let filtered_count = candidates.len();
        let list_height = (window.viewport_size().height * 0.52).min(px(440.0));
        let empty_message = SharedString::from(if total_count == 0 {
            "No eligible broadcaster currently advertises this token."
        } else {
            "No broadcasters match this search."
        });
        let rows = candidates
            .iter()
            .map(|candidate| BroadcasterPickerRow {
                railgun_address: candidate.railgun_address.clone(),
                label: broadcaster_candidate_label(candidate),
                fee_label: broadcaster_candidate_fee_label(candidate),
                fee_warning: broadcaster_candidate_fee_warning(candidate),
                reliability: candidate.reliability,
                selected: matches!(
                    current_choice,
                    BroadcasterChoice::Specific { railgun_address: ref selected } if selected == &candidate.railgun_address
                ),
            })
            .collect::<Vec<_>>();
        Some(BroadcasterPickerDialogSnapshot {
            query_input: picker.query_input.clone(),
            list: picker.list.clone(),
            rows,
            empty_message,
            generating,
            query,
            filtered_count,
            total_count,
            list_height,
            show_all_broadcasters,
            fee_bonus_popover_open: picker.fee_bonus_popover_open,
            kind: picker.kind,
            key: picker.key,
        })
    }
}

impl Render for WalletRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.apply_public_broadcaster_error_amount_adjustments(window, cx);
        self.focus_vault_input_if_requested(window, cx);
        self.focus_utxo_table_if_requested(window, cx);
        self.focus_public_account_search_if_requested(window, cx);

        let root = cx.entity();
        if !matches!(self.vault_state, VaultState::ViewUnlocked) {
            return self
                .render_locked_vault_screen(root, window)
                .children(Root::render_notification_layer(window, cx));
        }
        let sidebar_is_narrow = window.viewport_size().width < SIDEBAR_AUTO_COLLAPSE_WIDTH;
        if !sidebar_is_narrow {
            self.sidebar_narrow_expanded = false;
        }
        let sidebar_collapsed = if sidebar_is_narrow {
            !self.sidebar_narrow_expanded
        } else {
            self.sidebar_manually_collapsed
        };

        div()
            .relative()
            .size_full()
            .flex()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .text_color(rgb(theme::TEXT))
            .font_family(APP_FONT_FAMILY)
            .text_size(APP_TEXT_SIZE)
            .child(self.render_sidebar(root.clone(), sidebar_collapsed, sidebar_is_narrow))
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.render_workspace(root, window)),
            )
            .children(Root::render_dialog_layer(window, cx))
            .children(Root::render_notification_layer(window, cx))
    }
}

#[derive(Clone)]
struct UtxoDisplayRow {
    tree_position: String,
    token: String,
    token_icon_path: Option<PathBuf>,
    amount: String,
    poi_status: String,
    poi_spendable: bool,
    source_tx_hash: String,
    source_block_timestamp: u64,
    spent_tx_hash: Option<String>,
    token_address: String,
    is_spent: bool,
}

struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 7],
    tx_search_input: Entity<InputState>,
    poi_refresh_session: Option<Arc<wallet_ops::WalletSession>>,
    poi_refreshing: bool,
}

impl UtxoDelegate {
    fn new(tx_search_input: Entity<InputState>) -> Self {
        Self {
            rows: Arc::from(Vec::<UtxoDisplayRow>::new()),
            columns: [
                Column::new("tree_position", "tree/position")
                    .width(px(120.0))
                    .movable(false),
                Column::new("generated", "generated")
                    .width(px(130.0))
                    .movable(false),
                Column::new("token", "token")
                    .width(px(150.0))
                    .movable(false),
                Column::new("amount", "amount")
                    .width(px(160.0))
                    .movable(false),
                Column::new("poi", "POI").width(px(130.0)).movable(false),
                Column::new("source_tx", "source tx")
                    .width(px(200.0))
                    .movable(false),
                Column::new("spent_tx", "spent tx")
                    .width(px(200.0))
                    .movable(false),
            ],
            tx_search_input,
            poi_refresh_session: None,
            poi_refreshing: false,
        }
    }

    fn set_rows(&mut self, rows: Vec<UtxoDisplayRow>) {
        self.rows = Arc::from(rows);
    }

    fn set_column_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    fn set_poi_refresh_state(
        &mut self,
        session: Option<Arc<wallet_ops::WalletSession>>,
        refreshing: bool,
    ) {
        self.poi_refresh_session = session;
        self.poi_refreshing = refreshing;
    }
}

impl TableDelegate for UtxoDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        if col_ix != 4 {
            return div()
                .size_full()
                .child(self.columns[col_ix].name.clone())
                .into_any_element();
        }

        let session = self.poi_refresh_session.clone();
        let refreshing = self.poi_refreshing;
        let can_refresh = session.is_some();
        let action = div()
            .id("wallet-poi-refresh")
            .size(px(18.0))
            .flex()
            .items_center()
            .justify_center()
            .rounded_sm()
            .when(refreshing, |this| {
                this.child(
                    Spinner::new()
                        .icon(IconName::LoaderCircle)
                        .color(rgb(theme::TEXT_MUTED).into())
                        .with_size(px(13.0)),
                )
            })
            .when(!refreshing, |this| {
                this.when(can_refresh, |this| {
                    this.cursor_pointer()
                        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                        .tooltip(|window, cx| {
                            Tooltip::new("Refresh POI statuses").build(window, cx)
                        })
                        .on_click(move |_event, _window, cx| {
                            cx.stop_propagation();
                            let Some(session) = session.clone() else {
                                return;
                            };
                            cx.spawn(async move |_cx| {
                                session.refresh_poi_statuses().await;
                            })
                            .detach();
                        })
                })
                .child(
                    img(icons::refresh_ccw_icon_path())
                        .size(px(13.0))
                        .flex_none(),
                )
            })
            .into_any_element();

        div()
            .size_full()
            .flex()
            .items_center()
            .justify_between()
            .gap_1()
            .child("POI")
            .child(action)
            .into_any_element()
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> gpui::Stateful<gpui::Div> {
        let row = div().id(("row", row_ix));
        if self.rows.get(row_ix).is_some_and(|row| row.is_spent) {
            return row.bg(rgb(theme::SPENT_ROW_BG));
        }
        row
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row_ix];
        match col_ix {
            0 => div()
                .text_color(utxo_cell_text_color(row, rgb(theme::TEXT)))
                .child(SharedString::from(row.tree_position.clone()))
                .into_any_element(),
            1 => {
                let tooltip = SharedString::from(local_datetime_label(row.source_block_timestamp));
                div()
                    .id(SharedString::from(format!("wallet-generated-{row_ix}")))
                    .text_color(utxo_cell_text_color(row, rgb(theme::TEXT_MUTED)))
                    .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
                    .child(SharedString::from(generated_age_label(
                        row.source_block_timestamp,
                    )))
                    .into_any_element()
            }
            2 => {
                let address = row.token_address.clone();
                let group = SharedString::from(format!("wallet-token-cell-group-{row_ix}"));
                div()
                    .group(group.clone())
                    .id(SharedString::from(format!("wallet-token-cell-{row_ix}")))
                    .flex()
                    .items_center()
                    .gap_1()
                    .font_bold()
                    .text_color(utxo_cell_text_color(row, rgb(theme::TEXT)))
                    .child(token_label_row(
                        SharedString::from(row.token.clone()),
                        row.token_icon_path.clone(),
                        px(14.0),
                    ))
                    .child(
                        div()
                            .id(SharedString::from(format!(
                                "wallet-token-address-copy-action-{row_ix}"
                            )))
                            .group(group.clone())
                            .flex_none()
                            .opacity(0.0)
                            .group_hover(group, |this| this.opacity(1.0))
                            .hover(|this| this.opacity(1.0))
                            .tooltip(|window, cx| {
                                Tooltip::new("Copy token address").build(window, cx)
                            })
                            .child(clipboard_with_toast(
                                SharedString::from(format!(
                                    "wallet-token-address-clipboard-{row_ix}"
                                )),
                                address,
                            )),
                    )
                    .into_any_element()
            }
            3 => div()
                .text_color(utxo_cell_text_color(row, rgb(theme::WARNING)))
                .child(SharedString::from(row.amount.clone()))
                .into_any_element(),
            4 => div()
                .opacity(if row.is_spent { 0.6 } else { 1.0 })
                .child(
                    if row.poi_spendable {
                        Tag::success()
                    } else {
                        Tag::warning()
                    }
                    .small()
                    .outline()
                    .child(SharedString::from(row.poi_status.clone())),
                )
                .into_any_element(),
            5 => tx_hash_cell(
                row,
                row_ix,
                "source",
                &row.source_tx_hash,
                rgb(theme::TEAL),
                self.tx_search_input.clone(),
            ),
            _ => match row.spent_tx_hash.as_deref() {
                Some(tx_hash) => tx_hash_cell(
                    row,
                    row_ix,
                    "spent",
                    tx_hash,
                    rgb(theme::DANGER),
                    self.tx_search_input.clone(),
                ),
                None => div()
                    .text_color(rgb(theme::TEXT_SUBTLE))
                    .child("-")
                    .into_any_element(),
            },
        }
    }
}

fn tx_hash_cell(
    row: &UtxoDisplayRow,
    row_ix: usize,
    kind: &'static str,
    tx_hash: &str,
    color: gpui::Rgba,
    tx_search_input: Entity<InputState>,
) -> gpui::AnyElement {
    let display_hash = short_hash(tx_hash);
    let search_hash = tx_hash.to_string();
    let group = SharedString::from(format!("wallet-{kind}-tx-group-{row_ix}"));

    div()
        .group(group.clone())
        .id(SharedString::from(format!("wallet-{kind}-tx-{row_ix}")))
        .flex()
        .items_center()
        .gap_1()
        .child(
            div()
                .id(SharedString::from(format!(
                    "wallet-{kind}-tx-copy-{row_ix}"
                )))
                .flex_none()
                .font_family(APP_MONO_FONT_FAMILY)
                .text_color(utxo_cell_text_color(row, color))
                .child(SharedString::from(display_hash)),
        )
        .child(
            div()
                .id(SharedString::from(format!(
                    "wallet-{kind}-tx-actions-{row_ix}"
                )))
                .group(group.clone())
                .flex()
                .flex_none()
                .items_center()
                .gap_1()
                .opacity(0.0)
                .group_hover(group, |this| this.opacity(1.0))
                .hover(|this| this.opacity(1.0))
                .child(
                    div()
                        .id(SharedString::from(format!(
                            "wallet-{kind}-tx-copy-action-{row_ix}"
                        )))
                        .tooltip(|window, cx| {
                            Tooltip::new("Copy transaction hash").build(window, cx)
                        })
                        .child(clipboard_with_toast(
                            SharedString::from(format!("wallet-{kind}-tx-clipboard-{row_ix}")),
                            tx_hash.to_string(),
                        )),
                )
                .child(
                    app_button_base(SharedString::from(format!(
                        "wallet-{kind}-tx-search-{row_ix}"
                    )))
                    .ghost()
                    .xsmall()
                    .tooltip("Filter by this transaction")
                    .icon(IconName::Search)
                    .on_click(move |_event, window, cx| {
                        tx_search_input.update(cx, |input, cx| {
                            input.set_value(search_hash.clone(), window, cx);
                        });
                    }),
                ),
        )
        .into_any_element()
}

fn utxo_cell_text_color(row: &UtxoDisplayRow, color: gpui::Rgba) -> gpui::Rgba {
    if row.is_spent {
        rgb(theme::SPENT_TEXT)
    } else {
        color
    }
}

fn should_focus_utxo_table(
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    state: Option<&ChainUtxoState>,
) -> bool {
    active_activity == Activity::Wallet
        && active_wallet_tab.shows_utxos()
        && state.is_some_and(ChainUtxoState::renders_table)
}

fn centered_message(message: impl Into<SharedString>) -> gpui::Div {
    let message = message.into();
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .child(message)
}

fn private_action_input(state: &Entity<InputState>) -> Input {
    Input::new(state).px(px(12.0)).py(px(8.0))
}

fn render_public_action_amount_input(
    root: Entity<WalletRoot>,
    mode: PublicActionMode,
    input: &Entity<InputState>,
    label: String,
    max_label: Option<String>,
    disabled: bool,
) -> gpui::Div {
    let max_root = root;
    let max_id = match mode {
        PublicActionMode::Shield => "wallet-public-shield-max",
        PublicActionMode::Send => "wallet-public-send-max",
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(app_muted_text(label))
                .children(max_label.map(|label| {
                    app_button(max_id, format!("Max: {label}"))
                        .link()
                        .xsmall()
                        .compact()
                        .disabled(disabled)
                        .on_click(move |_event, window, cx| {
                            max_root.update(cx, |root, cx| {
                                root.set_public_action_amount_to_max(mode, window, cx);
                            });
                        })
                })),
        )
        .child(app_input(input).disabled(disabled))
}

fn public_action_segment_button(
    id: SharedString,
    label: &'static str,
    icon: impl Into<Icon>,
    selected: bool,
) -> Button {
    let button = Button::new(id)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_1()
                .text_size(APP_TEXT_SIZE)
                .child(icon.into().small())
                .child(label),
        );
    if selected { button.primary() } else { button }
}

fn public_action_title_row(label: String, icon_path: Option<PathBuf>) -> gpui::Div {
    div().flex().items_center().gap_1().child(token_label_row(
        SharedString::from(label),
        icon_path,
        px(20.0),
    ))
}

fn public_action_max_label(entry: &PublicBalanceEntry) -> Option<String> {
    if entry.asset.id == PublicAssetId::Native {
        return entry
            .amount
            .amount()
            .map(|_| format!("{} after est. gas", entry.asset.symbol));
    }
    entry.amount.amount().map(|_| {
        format!(
            "{} {}",
            public_balance_amount_label(&entry.amount, entry.asset.decimals),
            entry.asset.symbol,
        )
    })
}

fn public_action_max_amount_after_reserve(amount: U256, reserve: U256) -> Option<U256> {
    (amount > reserve).then_some(amount - reserve)
}

fn render_public_account_identicon(address: &Address) -> gpui::Div {
    let pattern = public_account_identicon_pattern(address);
    let foreground = public_account_identicon_color(address);
    let mut icon = div()
        .size(PUBLIC_ACCOUNT_IDENTICON_SIZE)
        .flex_none()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_0();
    for row in pattern.chunks_exact(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE) {
        let mut row_div = div().flex().gap_0();
        for active in row {
            let cell = div().size(PUBLIC_ACCOUNT_IDENTICON_CELL_SIZE);
            row_div = row_div.child(if *active {
                cell.bg(rgb(foreground))
            } else {
                cell
            });
        }
        icon = icon.child(row_div);
    }
    icon
}

fn public_account_identicon_pattern(
    address: &Address,
) -> [bool; PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT] {
    let mut pattern = [false; PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT];
    let mut has_foreground = false;
    for (row_index, row) in pattern
        .chunks_exact_mut(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE)
        .enumerate()
    {
        for column in 0..PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS {
            let bit_index = row_index * PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS + column;
            let active = public_account_identicon_bit(address, bit_index);
            has_foreground |= active;
            row[column] = active;
            row[PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE - column - 1] = active;
        }
    }
    if !has_foreground {
        pattern[PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT / 2] = true;
    }
    pattern
}

fn public_account_identicon_bit(address: &Address, bit_index: usize) -> bool {
    let bytes = address.as_slice();
    let byte = bytes[(bit_index * 7) % bytes.len()];
    let shift = (bit_index * 5) % u8::BITS as usize;
    ((byte >> shift) & 1) == 1
}

fn public_account_identicon_color(address: &Address) -> u32 {
    let bytes = address.as_slice();
    let color_index = usize::from(bytes[3] ^ bytes[7] ^ bytes[11] ^ bytes[15] ^ bytes[19])
        % PUBLIC_ACCOUNT_IDENTICON_COLORS.len();
    PUBLIC_ACCOUNT_IDENTICON_COLORS[color_index]
}

fn secondary_dialog_content_width(dialog_width: Pixels) -> Pixels {
    (dialog_width - DIALOG_CONTENT_HORIZONTAL_INSET).max(px(0.0))
}

fn render_public_address_qr_dialog_content(
    label: Option<SharedString>,
    address: SharedString,
    chain_label: &str,
    copy_id: SharedString,
    content_width: Pixels,
) -> gpui::Div {
    let receive_warning = SharedString::from(format!(
        "Send only public {chain_label} assets to this address."
    ));
    let address_copy_value = address.clone();
    let copy_row_id = SharedString::from(format!("{}-row", copy_id.as_ref()));
    div()
        .w(content_width)
        .flex()
        .flex_col()
        .items_center()
        .gap_4()
        .child(
            div()
                .w_full()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER))
                .bg(rgb_with_alpha(theme::PRIMARY, 0.08))
                .p(px(10.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .text_size(APP_TEXT_SIZE)
                .line_height(px(18.0))
                .child(receive_warning),
        )
        .children(label.map(|label| {
            div()
                .text_color(rgb(theme::TEXT))
                .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(label)
        }))
        .child(render_public_address_qr_code(address.as_ref()))
        .child(
            div()
                .id(copy_row_id)
                .w_full()
                .flex()
                .items_center()
                .gap_2()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER))
                .bg(rgb(theme::SURFACE_ELEVATED))
                .px(px(10.0))
                .py(px(8.0))
                .cursor_pointer()
                .hover(|this| {
                    this.bg(rgb(theme::SURFACE_HOVER_SUBTLE))
                        .border_color(rgb(theme::BORDER_STRONG))
                })
                .tooltip(|window, cx| Tooltip::new("Copy address").build(window, cx))
                .on_click(move |_event, window, cx| {
                    copy_to_clipboard_with_toast(address_copy_value.clone(), window, cx);
                })
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_color(rgb(theme::TEXT))
                        .text_size(px(12.0))
                        .font_family(APP_MONO_FONT_FAMILY)
                        .line_height(px(17.0))
                        .child(address.clone()),
                )
                .child(clipboard_with_toast(copy_id, address)),
        )
}

fn render_public_address_qr_code(payload: &str) -> gpui::Div {
    let Ok(qr) = QrCode::encode_text(payload, QrCodeEcc::Medium) else {
        return div()
            .p(px(14.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::DANGER))
            .bg(rgb(theme::SURFACE_ELEVATED))
            .text_color(rgb(theme::DANGER))
            .child("QR code unavailable");
    };
    let mut grid = div()
        .flex()
        .flex_col()
        .flex_none()
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .bg(rgb(PUBLIC_ADDRESS_QR_BACKGROUND))
        .p(px(6.0));
    let module_range = public_address_qr_module_range(qr.size());
    for y in module_range.clone() {
        let mut row = div().flex().flex_none();
        for x in module_range.clone() {
            let active = x >= 0 && y >= 0 && x < qr.size() && y < qr.size() && qr.get_module(x, y);
            row = row.child(
                div()
                    .size(PUBLIC_ADDRESS_QR_MODULE_SIZE)
                    .flex_none()
                    .bg(rgb(if active {
                        PUBLIC_ADDRESS_QR_FOREGROUND
                    } else {
                        PUBLIC_ADDRESS_QR_BACKGROUND
                    })),
            );
        }
        grid = grid.child(row);
    }
    grid
}

fn vault_dialog_body(subtitle: impl Into<SharedString>) -> gpui::Div {
    let subtitle = subtitle.into();
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_3()
        .child(app_muted_text(subtitle).line_height(px(18.0)))
}

fn loading_summary(progress: Option<SyncProgressUpdate>) -> String {
    progress.map_or_else(
        || "Preparing wallet sync...".to_string(),
        |progress| format!("{} · {}%", progress.stage.label(), progress.percent()),
    )
}

fn sync_status_bar(progress: Option<SyncProgressUpdate>) -> gpui::Div {
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

fn progress_detail(progress: SyncProgressUpdate) -> String {
    let current = progress
        .current_block
        .max(progress.start_block)
        .min(progress.target_block);
    format!("Block {current} of {}", progress.target_block)
}

fn chain_label_row(chain_id: u64) -> impl IntoElement {
    let label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned);
    let mut row = div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE);
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(px(16.0)).flex_none());
    }
    row.child(SharedString::from(label))
}

fn wallet_label_row(label: SharedString) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE)
        .child(img(icons::wallet_icon_path()).size(px(16.0)).flex_none())
        .child(label)
}

fn header_divider() -> impl IntoElement {
    Divider::vertical()
        .h(px(18.0))
        .mx(px(2.0))
        .color(rgb(theme::BORDER))
}

fn token_label_row(
    label: SharedString,
    icon_path: Option<PathBuf>,
    icon_size: Pixels,
) -> gpui::Div {
    let mut row = div().flex().items_center().gap_1();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(icon_size).rounded_full().flex_none());
    }
    row.child(label)
}

fn private_asset_label_row(label: SharedString, icon_path: Option<PathBuf>) -> gpui::Div {
    let mut row = div().flex().items_center().gap_2();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(px(32.0)).rounded_full().flex_none());
    }
    row.child(label)
}

fn private_action_title_row(
    action: &'static str,
    label: &str,
    icon_path: Option<PathBuf>,
) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(action)
        .child(token_label_row(
            SharedString::from(label.to_owned()),
            icon_path,
            px(20.0),
        ))
}

#[derive(Clone)]
struct FormattedTokenTotal {
    chain_id: u64,
    token: Option<Address>,
    label: String,
    amount: String,
    pending_poi_amount: String,
    total: Option<U256>,
    poi_verified_total: Option<U256>,
    pending_poi_total: Option<U256>,
    decimals: Option<u8>,
    icon_path: Option<PathBuf>,
}

fn format_private_asset_rows(chain_id: u64, totals: &[TokenTotal]) -> Vec<FormattedTokenTotal> {
    totals
        .iter()
        .map(|total| format_total_parts(chain_id, total))
        .collect()
}

#[cfg(test)]
fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let formatted = format_total_parts(chain_id, total);
    format!("{} {}", formatted.label, formatted.amount)
}

fn format_total_parts(chain_id: u64, total: &TokenTotal) -> FormattedTokenTotal {
    let total_raw = U256::from_str_radix(&total.total, 10).ok();
    let poi_verified_total_raw = U256::from_str_radix(&total.poi_verified_total, 10).ok();
    let pending_poi_total = pending_poi_total(total_raw, poi_verified_total_raw);
    let Some(address) = parse_address(&total.token) else {
        return FormattedTokenTotal {
            chain_id,
            token: None,
            label: total.token.clone(),
            amount: total.total.clone(),
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            decimals: None,
            icon_path: None,
        };
    };
    let Some(token) = lookup_token(chain_id, &address) else {
        return FormattedTokenTotal {
            chain_id,
            token: Some(address),
            label: short_address(&address),
            amount: total.total.clone(),
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            decimals: None,
            icon_path: None,
        };
    };
    let amount = total_raw.map_or_else(
        || total.total.clone(),
        |value| format_token_amount(value, token.decimals),
    );
    FormattedTokenTotal {
        chain_id,
        token: Some(address),
        label: token.symbol.to_owned(),
        amount,
        pending_poi_amount: format_pending_poi_amount(pending_poi_total, Some(token.decimals)),
        total: total_raw,
        poi_verified_total: poi_verified_total_raw,
        pending_poi_total,
        decimals: Some(token.decimals),
        icon_path: token_icon_path(chain_id, &address),
    }
}

fn pending_poi_total(total: Option<U256>, poi_verified_total: Option<U256>) -> Option<U256> {
    total
        .zip(poi_verified_total)
        .map(|(total, poi_verified_total)| total.saturating_sub(poi_verified_total))
}

fn format_pending_poi_amount(pending_poi_total: Option<U256>, decimals: Option<u8>) -> String {
    pending_poi_total.as_ref().map_or_else(
        || "0".to_string(),
        |value| {
            if let Some(decimals) = decimals {
                format_token_amount(*value, decimals)
            } else {
                value.to_string()
            }
        },
    )
}

fn should_show_pending_poi_amount(pending_poi_total: Option<U256>) -> bool {
    pending_poi_total.is_some_and(|amount| !amount.is_zero())
}

fn build_unshield_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_unshield_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

fn build_send_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_send_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

fn refresh_form_asset_from_snapshot(
    snapshot: &ListUtxosOutput,
    current: &UnshieldAsset,
    send: bool,
) -> UnshieldAsset {
    let formatted = format_private_asset_rows(snapshot.chain_id, &snapshot.totals)
        .into_iter()
        .find(|asset| asset.token == Some(current.token));
    let total = formatted
        .as_ref()
        .and_then(|asset| asset.total)
        .unwrap_or_default();
    let poi_verified_total = formatted
        .as_ref()
        .and_then(|asset| asset.poi_verified_total)
        .unwrap_or_default();
    let max_batched = if send {
        max_send_amount_from_snapshot(snapshot, current.token)
    } else {
        max_unshield_amount_from_snapshot(snapshot, current.token)
    };

    UnshieldAsset {
        chain_id: current.chain_id,
        token: current.token,
        label: formatted
            .as_ref()
            .map_or_else(|| current.label.clone(), |asset| asset.label.clone()),
        decimals: formatted
            .as_ref()
            .and_then(|asset| asset.decimals)
            .or(current.decimals),
        total,
        poi_verified_total,
        max_batched,
        icon_path: formatted
            .as_ref()
            .and_then(|asset| asset.icon_path.clone())
            .or_else(|| current.icon_path.clone()),
    }
}

#[cfg(test)]
fn send_asset_key_from_formatted(asset: &FormattedTokenTotal) -> Option<UnshieldAssetKey> {
    unshield_asset_key_from_formatted(asset)
}

#[cfg(test)]
fn send_key_matches_asset(key: UnshieldAssetKey, asset: &FormattedTokenTotal) -> bool {
    send_asset_key_from_formatted(asset) == Some(key)
}

fn send_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-send-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

#[cfg(test)]
fn unshield_asset_key_from_formatted(asset: &FormattedTokenTotal) -> Option<UnshieldAssetKey> {
    asset
        .token
        .map(|token| UnshieldAssetKey::new(asset.chain_id, token))
}

#[cfg(test)]
fn unshield_key_matches_asset(key: UnshieldAssetKey, asset: &FormattedTokenTotal) -> bool {
    unshield_asset_key_from_formatted(asset) == Some(key)
}

fn unshield_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-unshield-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

fn delivery_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    action: &str,
) -> SharedString {
    match kind {
        DeliveryFormKind::Send => send_element_id(key, action),
        DeliveryFormKind::Unshield => unshield_element_id(key, action),
    }
}

fn selected_broadcaster_label(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
) -> String {
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return "Specific broadcaster".to_string();
    };
    candidates
        .iter()
        .find(|candidate| candidate.railgun_address == *railgun_address)
        .map_or_else(
            || "Specific unavailable".to_string(),
            broadcaster_candidate_label,
        )
}

fn selected_broadcaster_fee_warning(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    allow_suspicious_broadcasters: bool,
) -> Option<String> {
    if allow_suspicious_broadcasters {
        return None;
    }
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return None;
    };
    candidates
        .iter()
        .find(|candidate| candidate.railgun_address == *railgun_address)
        .and_then(broadcaster_candidate_fee_warning)
}

const fn stable_broadcaster_element_suffix(railgun_address: &str) -> &str {
    railgun_address
}

fn broadcaster_candidate_label(candidate: &PublicBroadcasterCandidate) -> String {
    format_broadcaster_address_label(&candidate.railgun_address, candidate.identifier.as_deref())
}

fn broadcaster_candidate_fee_label(candidate: &PublicBroadcasterCandidate) -> String {
    match candidate.fee_policy_status {
        BroadcasterFeePolicyStatus::Normal { premium_bps, .. }
        | BroadcasterFeePolicyStatus::Suspicious {
            premium_bps: Some(premium_bps),
            ..
        } => return format_premium_bps_one_decimal(premium_bps),
        BroadcasterFeePolicyStatus::Suspicious {
            premium_bps: None, ..
        }
        | BroadcasterFeePolicyStatus::UnknownAnchor => {}
    }
    broadcaster_candidate_raw_fee_label(candidate)
}

fn broadcaster_candidate_raw_fee_label(candidate: &PublicBroadcasterCandidate) -> String {
    lookup_token(candidate.chain_id, &candidate.token).map_or_else(
        || candidate.fee.to_string(),
        |info| format_token_amount(candidate.fee, info.decimals),
    )
}

fn broadcaster_candidate_fee_warning(candidate: &PublicBroadcasterCandidate) -> Option<String> {
    let BroadcasterFeePolicyStatus::Suspicious { premium_bps, .. } = candidate.fee_policy_status
    else {
        return None;
    };
    Some(match premium_bps {
        Some(premium_bps) => format!(
            "Fee outside allowed range ({})",
            format_premium_bps_compact(premium_bps)
        ),
        None => "Fee outside allowed range".to_string(),
    })
}

fn format_premium_bps_one_decimal(premium_bps: i128) -> String {
    let sign = if premium_bps >= 0 { "+" } else { "-" };
    let abs_bps = premium_bps.checked_abs().unwrap_or(i128::MAX);
    let tenths = (abs_bps + 5) / 10;
    format!("{sign}{}.{:01}%", tenths / 10, tenths % 10)
}

fn format_premium_bps_compact(premium_bps: i128) -> String {
    let sign = if premium_bps >= 0 { "+" } else { "-" };
    let abs_bps = premium_bps.checked_abs().unwrap_or(i128::MAX);
    let tenths = (abs_bps + 5) / 10;
    if tenths % 10 == 0 {
        format!("{sign}{}%", tenths / 10)
    } else {
        format!("{sign}{}.{:01}%", tenths / 10, tenths % 10)
    }
}

fn broadcaster_reliability_label(reliability: f64) -> String {
    format!("{:.2}", reliability.clamp(0.0, 1.0))
}

const fn broadcaster_reliability_color(reliability: f64) -> u32 {
    if reliability < 0.5 {
        theme::DANGER
    } else if reliability < 0.75 {
        theme::WARNING
    } else {
        theme::SUCCESS
    }
}

fn render_broadcaster_reliability_badge(reliability: f64) -> gpui::Div {
    let color = broadcaster_reliability_color(reliability);
    div()
        .flex_none()
        .w(px(52.0))
        .px(px(8.0))
        .py(px(4.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(color))
        .text_color(rgb(color))
        .text_size(px(12.0))
        .text_align(gpui::TextAlign::Center)
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(broadcaster_reliability_label(reliability))
}

fn format_exact_candidate_token_amount(
    candidate: &PublicBroadcasterCandidate,
    amount: U256,
) -> String {
    lookup_token(candidate.chain_id, &candidate.token).map_or_else(
        || format!("{amount} raw token units"),
        |info| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(info.decimals)),
                info.symbol
            )
        },
    )
}

fn format_exact_asset_amount_for_display(amount: U256, asset: &UnshieldAsset) -> String {
    asset.decimals.map_or_else(
        || format!("{amount} raw token units"),
        |decimals| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(decimals)),
                asset.label
            )
        },
    )
}

fn token_display_label(chain_id: u64, token: Address) -> String {
    lookup_token(chain_id, &token)
        .map_or_else(|| short_address(&token), |info| info.symbol.to_owned())
}

fn format_exact_token_amount_for_display(chain_id: u64, token: Address, amount: U256) -> String {
    lookup_token(chain_id, &token).map_or_else(
        || format!("{} raw token units ({})", amount, short_address(&token)),
        |info| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(info.decimals)),
                info.symbol
            )
        },
    )
}

const fn native_token_display_label(chain_id: u64) -> &'static str {
    match native_wrapped_output_labels(chain_id) {
        Some((native_label, _wrapped_label)) => native_label,
        None => "base token",
    }
}

fn format_native_token_amount_for_display(chain_id: u64, amount: U256) -> String {
    format!(
        "{} {}",
        format_token_amount(amount, 18),
        native_token_display_label(chain_id)
    )
}

fn format_public_broadcaster_fee_margin(
    chain_id: u64,
    fee_token: Address,
    margin: PublicBroadcasterFeeMargin,
) -> String {
    match margin {
        PublicBroadcasterFeeMargin::Zero => {
            format_exact_token_amount_for_display(chain_id, fee_token, U256::ZERO)
        }
        PublicBroadcasterFeeMargin::Positive(amount) => {
            format_exact_token_amount_for_display(chain_id, fee_token, amount)
        }
        PublicBroadcasterFeeMargin::Negative(amount) => {
            format!(
                "-{}",
                format_exact_token_amount_for_display(chain_id, fee_token, amount)
            )
        }
    }
}

const fn broadcaster_candidate_anchor_rate(candidate: &PublicBroadcasterCandidate) -> Option<U256> {
    match candidate.fee_policy_status {
        BroadcasterFeePolicyStatus::Normal { anchor_rate, .. }
        | BroadcasterFeePolicyStatus::Suspicious { anchor_rate, .. } => Some(anchor_rate),
        BroadcasterFeePolicyStatus::UnknownAnchor => None,
    }
}

fn should_show_distinct_amount(entered_amount: U256, amount: U256) -> bool {
    amount != entered_amount
}

fn public_broadcaster_max_entered_amount_for_mode(
    max_receiver_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
) -> U256 {
    match fee_mode {
        PublicBroadcasterFeeMode::DeductFromAmount => max_receiver_amount + fee_amount,
        PublicBroadcasterFeeMode::AddToAmount => max_receiver_amount,
    }
}

fn cost_estimate_max_entered_amount_for_mode(
    estimate: &PublicBroadcasterCostEstimate,
    fee_mode: PublicBroadcasterFeeMode,
) -> U256 {
    let fee_mode =
        effective_public_broadcaster_fee_mode(estimate.action_token, estimate.fee_token, fee_mode);
    public_broadcaster_max_entered_amount_for_mode(
        estimate.max_receiver_amount,
        estimate.fee_amount,
        fee_mode,
    )
}

fn send_form_max_entered_amount(
    form: &SendFormState,
    delivery_mode: DeliveryMode,
    fee_mode: PublicBroadcasterFeeMode,
) -> Option<U256> {
    match delivery_mode {
        DeliveryMode::ManualCalldata => Some(form.asset.max_batched),
        DeliveryMode::PublicBroadcaster => form
            .cost_estimate
            .as_ref()
            .map(|estimate| cost_estimate_max_entered_amount_for_mode(estimate, fee_mode)),
        DeliveryMode::SelfBroadcast => None,
    }
}

fn unshield_form_max_entered_amount(
    form: &UnshieldFormState,
    delivery_mode: DeliveryMode,
    fee_mode: PublicBroadcasterFeeMode,
) -> Option<U256> {
    match delivery_mode {
        DeliveryMode::ManualCalldata => Some(form.asset.max_batched),
        DeliveryMode::PublicBroadcaster => form
            .cost_estimate
            .as_ref()
            .map(|estimate| cost_estimate_max_entered_amount_for_mode(estimate, fee_mode)),
        DeliveryMode::SelfBroadcast => None,
    }
}

fn adjusted_amount_for_max_change(
    current_amount: U256,
    old_max: Option<U256>,
    new_max: U256,
) -> Option<U256> {
    if current_amount > new_max {
        return Some(new_max);
    }
    if let Some(old_max) = old_max
        && current_amount == old_max
        && new_max > old_max
    {
        return Some(new_max);
    }
    None
}

fn amount_adjustment_for_max_change(
    input: &Entity<InputState>,
    asset: &UnshieldAsset,
    old_max: Option<U256>,
    new_max: Option<U256>,
    cx: &Context<'_, WalletRoot>,
) -> Option<String> {
    let new_max = new_max?;
    let current_value = input.read(cx).value().to_string();
    let Ok(current_amount) = parse_send_amount(current_value.as_str(), asset.decimals) else {
        return None;
    };
    let adjusted_amount = adjusted_amount_for_max_change(current_amount, old_max, new_max)?;
    Some(format_send_amount_input(adjusted_amount, asset.decimals))
}

fn format_form_error_for_asset(error: &str, asset: &UnshieldAsset, fee_token: Address) -> String {
    if let Some(max_spendable) = form_error_public_broadcaster_fee_token_max_spendable(error) {
        return format!(
            "Broadcaster fee exceeds available fee-token balance: {}. Choose a fee token with more spendable balance or a lower-fee broadcaster.",
            format_exact_token_amount_for_display(asset.chain_id, fee_token, max_spendable)
        );
    }

    if let Some(max_spendable) = form_error_public_broadcaster_max_entered_amount(error) {
        return format!(
            "Max POI-verified entered amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    if let Some(max_spendable) = form_error_max_immediately_spendable(error) {
        return format!(
            "Amount exceeds max POI-verified amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    match error {
        "entered amount must be greater than the broadcaster fee" => format!(
            "Entered amount must be greater than the broadcaster fee for {}. Choose add fee on top or enter a larger amount.",
            asset.label
        ),
        _ => error.to_string(),
    }
}

fn format_report_chain(error: &eyre::Report) -> String {
    let mut parts = error.chain().map(ToString::to_string);
    let Some(mut message) = parts.next() else {
        return error.to_string();
    };
    for part in parts {
        if message.ends_with(&part) {
            continue;
        }
        message.push_str(": ");
        message.push_str(&part);
    }
    message
}

fn form_error_public_broadcaster_max_entered_amount(error: &str) -> Option<U256> {
    const MARKER: &str = "public broadcaster max entered amount: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_public_broadcaster_fee_token_max_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "public broadcaster fee-token max spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_max_immediately_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "max immediately spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_decimal_after_marker(error: &str, marker: &str) -> Option<U256> {
    let start = error.find(marker)? + marker.len();
    let digits = error[start..]
        .trim_start()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?;
    if digits.is_empty() {
        return None;
    }
    U256::from_str_radix(digits, 10).ok()
}

fn format_gwei(wei: u128) -> String {
    format_token_amount(U256::from(wei), 9)
}

fn public_broadcaster_fee_mode_summary(
    chain_id: u64,
    action_token: Address,
    fee_token: Address,
    fee_mode: PublicBroadcasterFeeMode,
    entered_amount: U256,
    receiver_amount: U256,
    protocol_fee_amount: U256,
    fee_amount: U256,
    broadcaster: &PublicBroadcasterCandidate,
) -> String {
    if action_token != fee_token {
        let fee_text = format_exact_token_amount_for_display(chain_id, fee_token, fee_amount);
        if protocol_fee_amount.is_zero() {
            return format!(
                "Recipient receives the full entered amount; transaction fee is paid separately as {fee_text}."
            );
        }
        return format!(
            "Recipient receives the entered amount minus {} RAILGUN protocol fee; transaction fee is paid separately as {fee_text}.",
            format_exact_token_amount_for_display(chain_id, action_token, protocol_fee_amount)
        );
    }
    match fee_mode {
        PublicBroadcasterFeeMode::AddToAmount => {
            if protocol_fee_amount.is_zero() {
                "Recipient receives the full entered amount; transaction fee is added to spend."
                    .to_string()
            } else {
                format!(
                    "Recipient receives the entered amount minus {} RAILGUN protocol fee; transaction fee is added to spend.",
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            }
        }
        PublicBroadcasterFeeMode::DeductFromAmount => {
            let reduction = entered_amount.saturating_sub(receiver_amount);
            if reduction.is_zero() && protocol_fee_amount.is_zero() {
                "Recipient receives the entered amount because the broadcaster fee is zero."
                    .to_string()
            } else if protocol_fee_amount.is_zero() {
                format!(
                    "Recipient amount is reduced by {} because transaction fee is paid from the entered amount.",
                    format_exact_candidate_token_amount(broadcaster, reduction)
                )
            } else if reduction.is_zero() {
                format!(
                    "Recipient amount is reduced by {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            } else {
                format!(
                    "Recipient amount is reduced by {} transaction fee and {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, reduction),
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            }
        }
    }
}

fn broadcaster_candidate_matches_query(
    candidate: &PublicBroadcasterCandidate,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    candidate
        .railgun_address
        .to_ascii_lowercase()
        .contains(query)
        || candidate.fees_id.to_ascii_lowercase().contains(query)
        || candidate
            .identifier
            .as_deref()
            .is_some_and(|identifier| identifier.to_ascii_lowercase().contains(query))
        || candidate.version.to_ascii_lowercase().contains(query)
        || candidate
            .token
            .to_checksum(None)
            .to_ascii_lowercase()
            .contains(query)
}

fn render_broadcaster_picker_header(
    root: &Entity<WalletRoot>,
    query_input: &Entity<InputState>,
    filtered_count: usize,
    total_count: usize,
    fee_bonus_popover_open: bool,
) -> gpui::Div {
    let broadcaster_header = if filtered_count == total_count {
        format!("Broadcaster ({total_count})")
    } else {
        format!("Broadcaster ({filtered_count} of {total_count})")
    };
    div()
        .flex()
        .items_center()
        .gap_3()
        .px(px(20.0))
        .text_size(px(11.0))
        .text_color(rgb(theme::TEXT_MUTED))
        .child(div().flex_1().min_w(px(0.0)).child(broadcaster_header))
        .child(
            div()
                .w(px(150.0))
                .flex_none()
                .flex()
                .items_center()
                .gap_1()
                .child("Fee")
                .child({
                    let popover_root = root.clone();
                    let focus_query_input = query_input.clone();
                    let tooltip_enabled = !fee_bonus_popover_open;
                    Popover::new("broadcaster-picker-fee-bonus-popover")
                        .open(fee_bonus_popover_open)
                        .on_open_change(move |open, window, cx| {
                            popover_root.update(cx, |root, cx| {
                                root.set_broadcaster_picker_fee_bonus_popover_open(*open, cx);
                            });
                            if !*open {
                                focus_query_input.read(cx).focus_handle(cx).focus(window);
                            }
                        })
                        .trigger(
                            Button::new("broadcaster-picker-fee-bonus-trigger")
                                .text()
                                .xsmall()
                                .compact()
                                .child(render_fee_bonus_info_icon(tooltip_enabled)),
                        )
                        .content(|_state, _window, _cx| render_fee_bonus_popover())
                }),
        )
        .child(div().w(px(120.0)).flex_none().child("Reliability"))
}

fn render_fee_bonus_info_icon(tooltip_enabled: bool) -> impl IntoElement {
    div()
        .id("broadcaster-picker-fee-bonus-info")
        .size(px(14.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::WARNING))
        .text_color(rgb(theme::WARNING))
        .text_size(px(9.0))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
        .child("i")
        .when(tooltip_enabled, |this| {
            this.tooltip(|window, cx| {
                Tooltip::element(|_window, _cx| render_fee_bonus_popover()).build(window, cx)
            })
        })
}

fn render_fee_bonus_popover() -> gpui::Div {
    div()
        .w(px(360.0))
        .p(px(12.0))
        .flex()
        .flex_col()
        .gap_2()
        .text_size(px(12.0))
        .text_color(rgb(theme::TEXT))
        .child(
            div()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Fee bonus"),
        )
        .child(div().child(
            "Fee is the broadcaster's bonus over the estimated gas cost, not their total payout or profit.",
        ))
        .child(div().child(
            "Broadcasters still pay gas and later need to unshield this bonus, which has its own cost.",
        ))
        .child(div().child(
            "Very low or negative bonuses can be suspicious because the broadcaster may not cover their costs, which can lead to more failed submissions.",
        ))
}

fn render_broadcaster_picker_row(row: &BroadcasterPickerRow) -> gpui::Div {
    div()
        .w_full()
        .flex()
        .items_center()
        .gap_3()
        .text_size(APP_TEXT_SIZE)
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_family(APP_MONO_FONT_FAMILY)
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(row.label.clone()),
                ),
        )
        .child(
            div()
                .w(px(150.0))
                .flex_none()
                .flex()
                .flex_col()
                .gap_1()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(row.fee_label.clone())
                .children(row.fee_warning.clone().map(|warning| {
                    div()
                        .text_color(rgb(theme::DANGER))
                        .text_size(px(11.0))
                        .font_weight(gpui::FontWeight::NORMAL)
                        .child(warning)
                })),
        )
        .child(
            div()
                .w(px(120.0))
                .flex_none()
                .child(render_broadcaster_reliability_badge(row.reliability)),
        )
}

fn max_unshield_amount_from_snapshot(snapshot: &ListUtxosOutput, token: Address) -> U256 {
    planner_max_unshield_amount_from_outputs(&snapshot.utxos, token)
}

fn max_send_amount_from_snapshot(snapshot: &ListUtxosOutput, token: Address) -> U256 {
    planner_max_send_amount_from_outputs(&snapshot.utxos, token)
}

fn max_broadcaster_fee_token_amount_from_snapshot(
    snapshot: &ListUtxosOutput,
    token: Address,
) -> U256 {
    planner_max_broadcaster_fee_token_amount_from_outputs(&snapshot.utxos, token)
}

fn public_broadcaster_fee_token_options_from_snapshot(
    snapshot: &ListUtxosOutput,
    fee_rows: &[broadcaster_monitor::FeeRow],
    unwrap: bool,
    policy: BroadcasterFeePolicy,
    mut anchor_rate_for_token: impl FnMut(Address) -> Option<U256>,
) -> Vec<PublicBroadcasterFeeTokenOption> {
    format_private_asset_rows(snapshot.chain_id, &snapshot.totals)
        .into_iter()
        .filter_map(|asset| {
            let token = asset.token?;
            let poi_verified_total = asset.poi_verified_total?;
            if poi_verified_total.is_zero() {
                return None;
            }
            let max_spendable = max_broadcaster_fee_token_amount_from_snapshot(snapshot, token);
            if max_spendable.is_zero() {
                return None;
            }
            let candidates = public_broadcaster_candidates_for_asset(
                fee_rows,
                snapshot.chain_id,
                token,
                unwrap,
                policy,
                anchor_rate_for_token(token),
            )
            .unwrap_or_default();
            let eligible_broadcaster_count =
                fee_policy_eligible_public_broadcasters(&candidates, policy).len();
            Some(PublicBroadcasterFeeTokenOption {
                token,
                label: asset.label,
                decimals: asset.decimals,
                max_spendable,
                eligible_broadcaster_count,
                icon_path: asset.icon_path,
            })
        })
        .collect()
}

fn fee_token_option_has_eligible_broadcaster(
    options: &[PublicBroadcasterFeeTokenOption],
    token: Address,
) -> bool {
    options
        .iter()
        .any(|option| option.token == token && option.eligible_broadcaster_count > 0)
}

fn selected_fee_token_eligible_broadcaster_count(
    options: &[PublicBroadcasterFeeTokenOption],
    token: Address,
) -> Option<usize> {
    options
        .iter()
        .find(|option| option.token == token)
        .map(|option| option.eligible_broadcaster_count)
}

fn public_broadcaster_submit_disabled_for_fee_token_options(
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
) -> bool {
    selected_fee_token_eligible_broadcaster_count(options, selected_fee_token).unwrap_or_default()
        == 0
}

fn resolve_selected_public_broadcaster_fee_token(
    current_fee_token: Address,
    action_token: Address,
    options: &[PublicBroadcasterFeeTokenOption],
) -> Address {
    if fee_token_option_has_eligible_broadcaster(options, current_fee_token) {
        return current_fee_token;
    }
    if fee_token_option_has_eligible_broadcaster(options, action_token) {
        return action_token;
    }
    options
        .iter()
        .find(|option| option.eligible_broadcaster_count > 0)
        .map_or(current_fee_token, |option| option.token)
}

fn broadcaster_choice_supported_by_candidates(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    policy: BroadcasterFeePolicy,
) -> bool {
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return true;
    };
    fee_policy_eligible_public_broadcasters(candidates, policy)
        .iter()
        .any(|candidate| candidate.railgun_address == *railgun_address)
}

fn should_preserve_estimate_after_broadcaster_policy_change(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    policy: BroadcasterFeePolicy,
) -> bool {
    matches!(choice, BroadcasterChoice::Specific { .. })
        && broadcaster_choice_supported_by_candidates(choice, candidates, policy)
}

fn effective_public_broadcaster_fee_mode(
    action_token: Address,
    fee_token: Address,
    fee_mode: PublicBroadcasterFeeMode,
) -> PublicBroadcasterFeeMode {
    if action_token == fee_token {
        fee_mode
    } else {
        PublicBroadcasterFeeMode::AddToAmount
    }
}

fn should_show_broadcaster_fee_mode_toggle(action_token: Address, fee_token: Address) -> bool {
    action_token == fee_token
}

fn format_unshield_amount_input(amount: U256, decimals: Option<u8>) -> String {
    decimals.map_or_else(
        || amount.to_string(),
        |decimals| format_scaled_amount(amount, decimals),
    )
}

fn format_send_amount_input(amount: U256, decimals: Option<u8>) -> String {
    format_unshield_amount_input(amount, decimals)
}

fn private_action_metrics(asset: &UnshieldAsset) -> Vec<PrivateActionMetric> {
    let mut metrics = vec![PrivateActionMetric {
        label: "Total private balance",
        amount: asset.total,
    }];
    if asset.poi_verified_total != asset.total {
        metrics.push(PrivateActionMetric {
            label: "POI-verified balance",
            amount: asset.poi_verified_total,
        });
    }
    if asset.max_batched != asset.total {
        metrics.push(PrivateActionMetric {
            label: "Max batched transaction",
            amount: asset.max_batched,
        });
    }
    metrics
}

fn render_private_action_metrics(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    asset: &UnshieldAsset,
    disabled: bool,
) -> gpui::Div {
    let decimals = asset.decimals;
    div().w_full().flex().flex_wrap().gap_2().children(
        private_action_metrics(asset)
            .into_iter()
            .map(move |metric| {
                render_private_action_metric(
                    root.clone(),
                    key,
                    kind,
                    delivery_element_id(key, kind, private_action_metric_id_suffix(metric.label)),
                    metric,
                    decimals,
                    disabled,
                )
            }),
    )
}

fn render_private_action_metric(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    id: SharedString,
    metric: PrivateActionMetric,
    decimals: Option<u8>,
    disabled: bool,
) -> impl IntoElement {
    let value = format_unshield_amount_input(metric.amount, decimals);
    div()
        .id(id)
        .flex_1()
        .min_w(px(280.0))
        .px(px(12.0))
        .py(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .flex()
        .items_center()
        .justify_between()
        .gap_2()
        .when(!disabled, |this| {
            this.cursor_pointer()
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .on_click(move |_event, window, cx| {
                    let amount = metric.amount;
                    root.update(cx, |root, cx| {
                        root.set_private_action_metric_amount(kind, key, amount, window, cx);
                    });
                })
        })
        .child(app_muted_text(metric.label).whitespace_nowrap().flex_none())
        .child(
            div()
                .flex_none()
                .whitespace_nowrap()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(SharedString::from(value)),
        )
}

fn private_action_metric_id_suffix(label: &'static str) -> &'static str {
    match label {
        "Total private balance" => "metric-total",
        "POI-verified balance" => "metric-poi-verified",
        "Max batched transaction" => "metric-max-batched",
        _ => "metric",
    }
}

fn render_unshield_generating_status(_tick: usize, stage: TransactionGenerationStage) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::INFO))
        .child(
            Spinner::new()
                .icon(IconName::LoaderCircle)
                .color(rgb(theme::INFO).into())
                .with_size(px(18.0)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(stage.label()),
                )
                .child(app_muted_text(stage.detail())),
        )
}

fn render_delivery_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: DeliveryMode,
    generating: bool,
) -> gpui::Div {
    let selector_root = root;
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(app_muted_text("Delivery mode"))
        .child(
            ButtonGroup::new(delivery_element_id(key, kind, "mode-toggle"))
                .w_full()
                .children([
                    private_action_segment_button(
                        delivery_element_id(key, kind, "manual"),
                        "Manual calldata",
                        mode == DeliveryMode::ManualCalldata,
                    )
                    .disabled(generating),
                    private_action_segment_button(
                        delivery_element_id(key, kind, "public"),
                        "Public broadcaster",
                        mode == DeliveryMode::PublicBroadcaster,
                    )
                    .disabled(generating),
                    private_action_segment_button(
                        delivery_element_id(key, kind, "self"),
                        "Self-broadcast",
                        mode == DeliveryMode::SelfBroadcast,
                    )
                    .disabled(true),
                ])
                .on_click(move |selected, window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    let mode = match *index {
                        0 => DeliveryMode::ManualCalldata,
                        1 => DeliveryMode::PublicBroadcaster,
                        _ => return,
                    };
                    selector_root.update(cx, |root, cx| match kind {
                        DeliveryFormKind::Send => {
                            root.set_send_delivery_mode(key, mode, window, cx);
                        }
                        DeliveryFormKind::Unshield => {
                            root.set_unshield_delivery_mode(key, mode, window, cx);
                        }
                    });
                }),
        )
}

fn render_public_broadcaster_settings(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    allow_suspicious_broadcasters: bool,
    action_token: Address,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    choice: &BroadcasterChoice,
    candidates: Vec<PublicBroadcasterCandidate>,
    fee_token_options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    generating: bool,
) -> gpui::Div {
    let fee_token_root = root.clone();
    let fee_mode_root = root.clone();
    let random_root = root.clone();
    let modal_root = root.clone();
    let policy_label_root = root.clone();
    let policy_switch_root = root;
    let sorted = sort_specific_public_broadcasters(candidates);
    let specific_label = selected_broadcaster_label(choice, &sorted);
    let random_selected = matches!(choice, BroadcasterChoice::Random);
    let specific_selected = matches!(choice, BroadcasterChoice::Specific { .. });
    let selector_disabled = generating || sorted.is_empty();
    let random_button = app_button(
        delivery_element_id(key, kind, "random"),
        "Random broadcaster",
    )
    .flex_1()
    .min_w(px(0.0))
    .selected(random_selected)
    .disabled(selector_disabled);
    let random_button = if random_selected {
        random_button.primary()
    } else {
        random_button
    };
    let specific_button = app_button(
        delivery_element_id(key, kind, "choose-specific"),
        specific_label,
    )
    .flex_1()
    .min_w(px(0.0))
    .selected(specific_selected)
    .disabled(selector_disabled);
    let specific_button = if specific_selected {
        specific_button.primary()
    } else {
        specific_button
    };

    let settings = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(10.0))
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_muted_text("Allow suspicious broadcasters"))
                        .child(cost_estimate_detail_text(
                            "Suspicious broadcasters advertise fees outside the anchor range.",
                        ))
                        .when(!generating, |this| {
                            this.on_mouse_down(MouseButton::Left, move |_, _window, cx| {
                                cx.stop_propagation();
                                policy_label_root.update(cx, |root, cx| {
                                    root.set_allow_suspicious_broadcasters(
                                        kind,
                                        key,
                                        !allow_suspicious_broadcasters,
                                        cx,
                                    );
                                });
                            })
                        }),
                )
                .child(render_danger_switch(
                    delivery_element_id(key, kind, "allow-suspicious-broadcasters"),
                    allow_suspicious_broadcasters,
                    generating,
                    move |checked, _window, cx| {
                        policy_switch_root.update(cx, |root, cx| {
                            root.set_allow_suspicious_broadcasters(kind, key, checked, cx);
                        });
                    },
                )),
        )
        .child(render_fee_token_selector(
            fee_token_root,
            key,
            kind,
            fee_token_options,
            selected_fee_token,
            generating,
        ))
        .child(
            ButtonGroup::new(delivery_element_id(key, kind, "broadcaster-choice-toggle"))
                .w_full()
                .disabled(selector_disabled)
                .child(random_button)
                .child(specific_button)
                .on_click(move |selected, window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    if *index == 0 {
                        random_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => {
                                root.set_send_broadcaster_choice(
                                    key,
                                    BroadcasterChoice::Random,
                                    cx,
                                );
                            }
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_broadcaster_choice(
                                    key,
                                    BroadcasterChoice::Random,
                                    cx,
                                );
                            }
                        });
                    } else {
                        modal_root.update(cx, |root, cx| {
                            root.open_broadcaster_picker(kind, key, window, cx);
                        });
                    }
                }),
        )
        .when(
            should_show_broadcaster_fee_mode_toggle(action_token, selected_fee_token),
            |settings| {
                settings.child(render_broadcaster_fee_mode_toggle(
                    fee_mode_root,
                    key,
                    kind,
                    broadcaster_fee_mode,
                    generating,
                ))
            },
        );

    if sorted.is_empty() {
        return settings.child(app_muted_text(
            "No eligible broadcaster currently advertises this token.",
        ));
    }
    settings
}

fn render_danger_switch(
    id: SharedString,
    checked: bool,
    disabled: bool,
    on_toggle: impl Fn(bool, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let track_width = px(36.0);
    let track_height = px(20.0);
    let thumb_size = px(16.0);
    let inset = px(2.0);
    let max_x = track_width - thumb_size - inset * 2.0;
    let thumb_x = if checked { max_x } else { px(0.0) };
    let track_color = if checked {
        theme::DANGER
    } else {
        theme::SURFACE_HOVER
    };
    let thumb_color = if checked {
        theme::SURFACE
    } else {
        theme::TEXT_MUTED
    };

    div()
        .id(id)
        .w(track_width)
        .h(track_height)
        .flex()
        .items_center()
        .p(inset)
        .rounded_full()
        .bg(rgb(track_color))
        .opacity(if disabled { 0.5 } else { 1.0 })
        .when(!disabled, |this| {
            this.on_mouse_down(MouseButton::Left, move |_, window, cx| {
                cx.stop_propagation();
                on_toggle(!checked, window, cx);
            })
        })
        .child(
            div()
                .size(thumb_size)
                .rounded_full()
                .bg(rgb(thumb_color))
                .left(thumb_x)
                .with_animation(
                    ElementId::NamedInteger("danger-switch-thumb".into(), u64::from(checked)),
                    Animation::new(Duration::from_secs_f64(0.15)),
                    move |this, delta| {
                        let x = if checked {
                            max_x * delta
                        } else {
                            max_x - max_x * delta
                        };
                        this.left(x)
                    },
                ),
        )
}

fn render_unshield_output_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    chain_id: u64,
    unwrap: bool,
    generating: bool,
) -> gpui::Div {
    let Some((native_label, wrapped_label)) = native_wrapped_output_labels(chain_id) else {
        return div();
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(app_muted_text("Output"))
        .child(
            ButtonGroup::new(unshield_element_id(key, "output-toggle"))
                .outline()
                .disabled(generating)
                .child(
                    app_button(unshield_element_id(key, "output-native"), native_label)
                        .selected(unwrap)
                        .disabled(generating),
                )
                .child(
                    app_button(unshield_element_id(key, "output-wrapped"), wrapped_label)
                        .selected(!unwrap)
                        .disabled(generating),
                )
                .on_click(move |selected, _window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    let unwrap = *index == 0;
                    root.update(cx, |root, cx| {
                        root.set_unshield_unwrap(key, unwrap, cx);
                    });
                }),
        )
}

const fn native_wrapped_output_labels(chain_id: u64) -> Option<(&'static str, &'static str)> {
    match chain_id {
        1 | 42161 => Some(("ETH", "WETH")),
        56 => Some(("BNB", "WBNB")),
        137 => Some(("MATIC", "WMATIC")),
        _ => None,
    }
}

fn render_fee_token_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    generating: bool,
) -> gpui::Div {
    let selected_option = options
        .iter()
        .find(|option| option.token == selected_fee_token)
        .cloned();
    let options = options.to_vec();
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            div()
                .min_w(px(0.0))
                .child(app_muted_text("Broadcaster fee token")),
        )
        .child(
            Popover::new(delivery_element_id(key, kind, "fee-token-selector"))
                .trigger(
                    Button::new(delivery_element_id(key, kind, "fee-token-selector-trigger"))
                        .outline()
                        .child(fee_token_selector_trigger_row(
                            selected_option.as_ref(),
                            selected_fee_token,
                        ))
                        .dropdown_caret(true)
                        .disabled(generating || options.is_empty()),
                )
                .content(move |_state, window, cx| {
                    let popover = cx.entity();
                    render_fee_token_selector_menu(
                        &root,
                        &popover,
                        key,
                        kind,
                        &options,
                        selected_fee_token,
                        window,
                    )
                }),
        )
}

fn render_fee_token_selector_menu(
    root: &Entity<WalletRoot>,
    popover: &Entity<gpui_component::popover::PopoverState>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    _window: &mut Window,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .w(px(260.0))
        .children(options.iter().map(|option| {
            let selector_root = root.clone();
            let popover = popover.clone();
            let token = option.token;
            let selected = token == selected_fee_token;
            let disabled = option.eligible_broadcaster_count == 0;
            div()
                .id(fee_token_element_id(key, kind, token))
                .w_full()
                .p(px(8.0))
                .rounded_sm()
                .text_color(rgb(if selected {
                    theme::PRIMARY_FOREGROUND
                } else {
                    theme::TEXT
                }))
                .opacity(if disabled { 0.5 } else { 1.0 })
                .when(selected, |this| this.bg(rgb(theme::PRIMARY)))
                .when(!disabled && !selected, |this| {
                    this.cursor_pointer()
                        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                })
                .when(!disabled, |this| {
                    this.on_mouse_down(MouseButton::Left, move |_, window, cx| {
                        cx.stop_propagation();
                        popover.update(cx, |state, cx| state.dismiss(window, cx));
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => root.set_send_fee_token(key, token, cx),
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_fee_token(key, token, cx);
                            }
                        });
                    })
                })
                .child(fee_token_option_label_row(option, px(18.0)))
        }))
}

fn fee_token_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    token: Address,
) -> SharedString {
    let action = format!("fee-token-{}", token.to_checksum(None));
    delivery_element_id(key, kind, &action)
}

fn fee_token_option_button_label(option: &PublicBroadcasterFeeTokenOption) -> String {
    format!(
        "{} · {}",
        option.label,
        broadcaster_count_label(option.eligible_broadcaster_count)
    )
}

fn fee_token_selector_trigger_row(
    option: Option<&PublicBroadcasterFeeTokenOption>,
    selected_fee_token: Address,
) -> gpui::Div {
    option.map_or_else(
        || {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(SharedString::from(short_address(&selected_fee_token)))
        },
        |option| fee_token_option_label_row(option, px(16.0)),
    )
}

fn fee_token_option_label_row(
    option: &PublicBroadcasterFeeTokenOption,
    icon_size: Pixels,
) -> gpui::Div {
    token_label_row(
        SharedString::from(fee_token_option_button_label(option)),
        option.icon_path.clone(),
        icon_size,
    )
}

fn broadcaster_count_label(count: usize) -> String {
    match count {
        0 => "no broadcasters".to_string(),
        1 => "1 broadcaster".to_string(),
        count => format!("{count} broadcasters"),
    }
}

fn render_broadcaster_fee_mode_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: PublicBroadcasterFeeMode,
    generating: bool,
) -> gpui::Div {
    let selector_root = root;
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(div().min_w(px(0.0)).child(app_muted_text("Broadcaster fee")))
        .child(
            div().flex_none().child(
                ButtonGroup::new(delivery_element_id(key, kind, "fee-mode-toggle"))
                    .outline()
                    .compact()
                    .disabled(generating)
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-deduct"),
                        delivery_element_id(key, kind, "fee-mode-deduct-info"),
                        "Deduct fee from amount",
                        "Recipient receives the entered amount minus the broadcaster fee.",
                        mode == PublicBroadcasterFeeMode::DeductFromAmount,
                    ))
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-add"),
                        delivery_element_id(key, kind, "fee-mode-add-info"),
                        "Add fee on top",
                        "Recipient receives the full entered amount; broadcaster fee is added to spend.",
                        mode == PublicBroadcasterFeeMode::AddToAmount,
                    ))
                    .on_click(move |selected, window, cx| {
                        let Some(index) = selected.first() else {
                            return;
                        };
                        let mode = if *index == 0 {
                            PublicBroadcasterFeeMode::DeductFromAmount
                        } else {
                            PublicBroadcasterFeeMode::AddToAmount
                        };
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => {
                                root.set_send_broadcaster_fee_mode(key, mode, window, cx);
                            }
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_broadcaster_fee_mode(key, mode, window, cx);
                            }
                        });
                    }),
            ),
        )
}

fn fee_mode_segment_button(
    id: SharedString,
    info_id: SharedString,
    label: &'static str,
    tooltip: &'static str,
    selected: bool,
) -> Button {
    Button::new(id).selected(selected).child(
        div()
            .flex()
            .items_center()
            .justify_center()
            .gap_1()
            .text_size(APP_TEXT_SIZE)
            .child(label)
            .child(render_fee_mode_info_icon(info_id, tooltip)),
    )
}

fn render_fee_mode_info_icon(id: SharedString, tooltip: &'static str) -> Button {
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::Info)
        .text_color(rgb(theme::TEXT_MUTED))
        .tooltip(tooltip)
}

fn private_action_segment_button(id: SharedString, label: &'static str, selected: bool) -> Button {
    let button = app_button(id, label)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected);
    if selected { button.primary() } else { button }
}

fn render_send_result(key: UnshieldAssetKey, result: &PreparedSendCall) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared send calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            send_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            send_element_id(key, "copy-data"),
        ))
}

struct PublicBroadcasterCostDisplay<'a> {
    broadcaster: &'a PublicBroadcasterCandidate,
    chain_id: u64,
    action_token: Address,
    fee_token: Address,
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: U256,
    fee_mode: PublicBroadcasterFeeMode,
    gas_limit: u64,
    min_gas_price: u128,
    fee_anchor_rate: Option<U256>,
}

impl<'a> PublicBroadcasterCostDisplay<'a> {
    const fn from_result(
        result: &'a PublicBroadcasterSubmissionResult,
        fee_anchor_rate: Option<U256>,
    ) -> Self {
        Self {
            broadcaster: &result.broadcaster,
            chain_id: result.broadcaster.chain_id,
            action_token: result.action_token,
            fee_token: result.fee_token,
            entered_amount: result.entered_amount,
            receiver_amount: result.receiver_amount,
            recipient_amount: result.recipient_amount,
            total_private_spend: result.total_private_spend,
            fee_amount: result.fee_amount,
            protocol_fee_amount: result.protocol_fee_amount,
            protocol_fee_bps: result.protocol_fee_bps,
            fee_mode: result.fee_mode,
            gas_limit: result.gas_limit,
            min_gas_price: result.min_gas_price,
            fee_anchor_rate,
        }
    }

    const fn from_estimate(
        asset: &UnshieldAsset,
        estimate: &'a PublicBroadcasterCostEstimate,
        fee_anchor_rate: Option<U256>,
    ) -> Self {
        Self {
            broadcaster: &estimate.broadcaster,
            chain_id: asset.chain_id,
            action_token: estimate.action_token,
            fee_token: estimate.fee_token,
            entered_amount: estimate.entered_amount,
            receiver_amount: estimate.receiver_amount,
            recipient_amount: estimate.recipient_amount,
            total_private_spend: estimate.total_private_spend,
            fee_amount: estimate.fee_amount,
            protocol_fee_amount: estimate.protocol_fee_amount,
            protocol_fee_bps: estimate.protocol_fee_bps,
            fee_mode: estimate.fee_mode,
            gas_limit: estimate.gas_limit,
            min_gas_price: estimate.min_gas_price,
            fee_anchor_rate,
        }
    }

    fn private_spend_label(&self) -> &'static str {
        if self.action_token == self.fee_token {
            "Total private spend"
        } else {
            "Action-token private spend"
        }
    }

    fn action_amount(&self, amount: U256) -> String {
        format_exact_token_amount_for_display(self.chain_id, self.action_token, amount)
    }

    fn fee_amount(&self) -> String {
        format_exact_token_amount_for_display(self.chain_id, self.fee_token, self.fee_amount)
    }

    fn fee_breakdown(&self) -> PublicBroadcasterFeeBreakdown {
        public_broadcaster_fee_breakdown(
            self.fee_amount,
            self.gas_limit,
            self.min_gas_price,
            self.fee_token_anchor_rate(),
        )
    }

    fn fee_token_anchor_rate(&self) -> Option<U256> {
        self.fee_anchor_rate
            .or_else(|| broadcaster_candidate_anchor_rate(self.broadcaster))
            .or_else(|| fixed_token_anchor_rate(self.chain_id, self.fee_token))
    }

    fn native_gas_cost_value(&self, breakdown: &PublicBroadcasterFeeBreakdown) -> String {
        format_native_token_amount_for_display(self.chain_id, breakdown.native_gas_cost)
    }

    fn broadcaster_fee_value(&self, breakdown: &PublicBroadcasterFeeBreakdown) -> String {
        breakdown.broadcaster_fee.map_or_else(
            || "unavailable (no anchor)".to_string(),
            |margin| format_public_broadcaster_fee_margin(self.chain_id, self.fee_token, margin),
        )
    }

    fn protocol_fee_value(&self) -> String {
        format!(
            "{} ({} bps)",
            self.action_amount(self.protocol_fee_amount),
            self.protocol_fee_bps
        )
    }

    fn gas_value(&self) -> String {
        format!(
            "~{} gas @ {} gwei",
            self.gas_limit,
            format_gwei(public_broadcaster_service_gas_price(self.min_gas_price))
        )
    }

    fn fee_mode_summary(&self) -> String {
        public_broadcaster_fee_mode_summary(
            self.chain_id,
            self.action_token,
            self.fee_token,
            self.fee_mode,
            self.entered_amount,
            self.receiver_amount,
            self.protocol_fee_amount,
            self.fee_amount,
            self.broadcaster,
        )
    }
}

#[derive(Clone, Copy)]
enum PrivateSpendRowMode {
    Always,
    WhenDistinct,
}

struct PublicBroadcasterCostRowsOptions {
    show_broadcaster: bool,
    show_entered_amount: bool,
    private_spend: PrivateSpendRowMode,
}

fn append_public_broadcaster_cost_rows(
    mut card: gpui::Div,
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    display: &PublicBroadcasterCostDisplay<'_>,
    options: &PublicBroadcasterCostRowsOptions,
    transaction_fee_breakdown_open: bool,
) -> gpui::Div {
    if options.show_broadcaster {
        card = card.child(cost_estimate_row(
            "Broadcaster",
            broadcaster_candidate_label(display.broadcaster),
        ));
    }
    if options.show_entered_amount {
        card = card.child(cost_estimate_row(
            "Entered amount",
            display.action_amount(display.entered_amount),
        ));
    }
    card = card
        .child(cost_estimate_row(
            "Recipient receives",
            display.action_amount(display.recipient_amount),
        ))
        .when(
            matches!(options.private_spend, PrivateSpendRowMode::Always)
                || should_show_distinct_amount(display.entered_amount, display.total_private_spend),
            |card| {
                card.child(cost_estimate_row(
                    display.private_spend_label(),
                    display.action_amount(display.total_private_spend),
                ))
            },
        )
        .when(!display.protocol_fee_bps.is_zero(), |card| {
            card.child(cost_estimate_row(
                "RAILGUN protocol fee",
                display.protocol_fee_value(),
            ))
        })
        .child(render_transaction_fee_breakdown(
            root,
            key,
            kind,
            display,
            transaction_fee_breakdown_open,
        ));
    card
}

fn render_transaction_fee_breakdown(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    display: &PublicBroadcasterCostDisplay<'_>,
    open: bool,
) -> impl IntoElement {
    let breakdown = display.fee_breakdown();
    let fee_amount = display.fee_amount();
    Collapsible::new()
        .open(open)
        .w_full()
        .rounded_md()
        .overflow_hidden()
        // .border_1()
        // .border_color(rgb(theme::BORDER))
        // .bg(rgb(theme::SURFACE))
        .child(
            div()
                .id(delivery_element_id(key, kind, "transaction-fee-breakdown"))
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                // .px(px(10.0))
                .py(px(5.0))
                .cursor_pointer()
                // .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    root.update(cx, |root, cx| {
                        root.set_transaction_fee_breakdown_open(kind, key, !open, cx);
                    });
                })
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_color(rgb(theme::TEXT))
                        .child("Transaction fee"),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_end()
                        .gap_2()
                        .text_color(rgb(theme::TEXT))
                        .child(fee_amount)
                        .child(
                            Icon::new(if open {
                                IconName::ChevronUp
                            } else {
                                IconName::ChevronDown
                            })
                            .xsmall()
                            .text_color(rgb(theme::TEXT_MUTED)),
                        ),
                ),
        )
        .content(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .px(px(10.0))
                .py(px(8.0))
                .border_t_1()
                .border_color(rgb(theme::BORDER))
                .child(transaction_fee_breakdown_row(
                    "Gas cost",
                    display.native_gas_cost_value(&breakdown),
                ))
                .child(transaction_fee_breakdown_row(
                    "Broadcaster's fee",
                    display.broadcaster_fee_value(&breakdown),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(network_gas_breakdown_text("Network gas"))
                        .child(network_gas_breakdown_text(display.gas_value())),
                ),
        )
}

fn render_public_broadcaster_result(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    result: &PublicBroadcasterSubmissionResult,
    fee_anchor_rate: Option<U256>,
    transaction_fee_breakdown_open: bool,
) -> gpui::Div {
    let (title, detail, border, tx_hash) = match &result.result {
        PublicBroadcasterResultKind::Submitted { tx_hash } => (
            "Submitted via public broadcaster",
            format!(
                "{} accepted the transaction.",
                broadcaster_candidate_label(&result.broadcaster)
            ),
            theme::SUCCESS,
            Some(tx_hash.clone()),
        ),
        PublicBroadcasterResultKind::Failed { error } => (
            "Public broadcaster failed",
            error.clone(),
            theme::DANGER,
            None,
        ),
        PublicBroadcasterResultKind::TimedOut => (
            "Public broadcaster timed out",
            "No decryptable broadcaster response arrived before the timeout.".to_string(),
            theme::WARNING,
            None,
        ),
    };
    let display = PublicBroadcasterCostDisplay::from_result(result, fee_anchor_rate);
    let card = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(border))
        .child(app_strong_text(title))
        .child(app_muted_text(detail));
    let mut card = append_public_broadcaster_cost_rows(
        card,
        root,
        key,
        kind,
        &display,
        &PublicBroadcasterCostRowsOptions {
            show_broadcaster: false,
            show_entered_amount: true,
            private_spend: PrivateSpendRowMode::Always,
        },
        transaction_fee_breakdown_open,
    )
    .child(app_muted_text(display.fee_mode_summary()));
    if let Some(tx_hash) = tx_hash {
        card = card.child(render_public_broadcaster_tx_hash_row(
            tx_hash,
            delivery_element_id(key, kind, "copy-public-tx"),
        ));
    }
    card
}

fn render_public_broadcaster_tx_hash_row(tx_hash: String, button_id: SharedString) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("Tx hash"),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .text_color(rgb(theme::TEXT))
                .child(SharedString::from(tx_hash.clone())),
        )
        .child(clipboard_with_toast(button_id, tx_hash))
}

fn render_public_broadcaster_cost_estimate(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    asset: &UnshieldAsset,
    estimate: &PublicBroadcasterCostEstimate,
    fee_anchor_rate: Option<U256>,
    transaction_fee_breakdown_open: bool,
    refreshing: bool,
) -> gpui::Div {
    let refresh_root = root.clone();
    let display = PublicBroadcasterCostDisplay::from_estimate(asset, estimate, fee_anchor_rate);
    let card = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .child(
            div()
                .flex()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_strong_text("Estimated outcome"))
                        .child(cost_estimate_detail_text(
                            "Proof is not generated yet; the final fee may move slightly before publish.",
                        )),
                )
                .child(render_public_broadcaster_estimate_refresh_button(
                    refresh_root,
                    key,
                    kind,
                    refreshing,
                )),
        );
    append_public_broadcaster_cost_rows(
        card,
        root,
        key,
        kind,
        &display,
        &PublicBroadcasterCostRowsOptions {
            show_broadcaster: true,
            show_entered_amount: false,
            private_spend: PrivateSpendRowMode::WhenDistinct,
        },
        transaction_fee_breakdown_open,
    )
    .child(cost_estimate_detail_text(format!(
        "Shape: {} proofs · {} inputs · {} private outputs · {} public outputs",
        estimate.transaction_count,
        estimate.input_count,
        estimate.private_output_count,
        estimate.public_output_count
    )))
    .child(cost_estimate_detail_text(display.fee_mode_summary()))
}

fn render_public_broadcaster_estimate_refresh_button(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    refreshing: bool,
) -> impl IntoElement {
    div()
        .id(delivery_element_id(key, kind, "refresh-estimate"))
        .size(px(18.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .when(refreshing, |this| {
            this.child(
                Spinner::new()
                    .icon(IconName::LoaderCircle)
                    .color(rgb(theme::TEXT_MUTED).into())
                    .with_size(px(13.0)),
            )
        })
        .when(!refreshing, |this| {
            this.cursor_pointer()
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .tooltip(|window, cx| Tooltip::new("Refresh estimate").build(window, cx))
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    root.update(cx, |root, cx| {
                        root.schedule_public_broadcaster_cost_estimate(kind, key, cx);
                    });
                })
                .child(
                    img(icons::refresh_ccw_icon_path())
                        .size(px(13.0))
                        .flex_none(),
                )
        })
}

const fn public_broadcaster_cost_status(
    pending: bool,
    estimating: bool,
) -> Option<CostEstimateStatus> {
    if pending {
        None
    } else if estimating {
        Some(CostEstimateStatus::Estimating)
    } else {
        None
    }
}

const fn public_broadcaster_cost_status_text(
    status: CostEstimateStatus,
) -> (&'static str, &'static str) {
    match status {
        CostEstimateStatus::Estimating => (
            "Estimating public broadcaster cost...",
            "Using current gas price, broadcaster fee rate, and selected private note shape.",
        ),
    }
}

fn render_public_broadcaster_cost_status(_tick: usize, status: CostEstimateStatus) -> gpui::Div {
    let (title, detail) = public_broadcaster_cost_status_text(status);
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            Spinner::new()
                .icon(IconName::LoaderCircle)
                .color(rgb(theme::INFO).into())
                .with_size(px(18.0)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(app_strong_text(title))
                .child(app_muted_text(detail)),
        )
}

fn cost_estimate_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label))
        .child(app_strong_text(value))
}

fn cost_estimate_detail_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn transaction_fee_breakdown_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}
fn network_gas_breakdown_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT_MUTED))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn transaction_fee_breakdown_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(transaction_fee_breakdown_text(label))
        .child(transaction_fee_breakdown_text(value))
}

fn render_unshield_result(key: UnshieldAssetKey, result: &PreparedUnshieldCall) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            unshield_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            unshield_element_id(key, "copy-data"),
        ))
}

fn render_unshield_copy_field(
    label: &'static str,
    value: String,
    button_id: SharedString,
) -> gpui::Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .p(px(8.0))
                .rounded_sm()
                .bg(rgb(theme::BACKGROUND))
                .border_1()
                .border_color(rgb(theme::BORDER))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(value.clone())),
        )
        .child(clipboard_with_toast(button_id, value))
}

fn display_rows_from_output(
    output: &ListUtxosOutput,
    tx_query: &str,
    show_spent_utxos: bool,
) -> Vec<UtxoDisplayRow> {
    let tx_query = tx_query.trim().to_ascii_lowercase();
    let mut rows: Vec<_> = output
        .utxos
        .iter()
        .filter(|row| matches_utxo_filters(row, &tx_query, show_spent_utxos))
        .map(|row| display_row_from_utxo(output.chain_id, row))
        .collect();
    rows.reverse();
    rows
}

fn matches_utxo_filters(row: &UtxoOutput, tx_query: &str, show_spent_utxos: bool) -> bool {
    if tx_query.is_empty() {
        return show_spent_utxos || !row.is_spent;
    }

    row.source_tx_hash.to_ascii_lowercase().contains(tx_query)
        || row
            .spent_tx_hash
            .as_deref()
            .is_some_and(|hash| hash.to_ascii_lowercase().contains(tx_query))
}

fn display_row_from_utxo(chain_id: u64, row: &UtxoOutput) -> UtxoDisplayRow {
    let Some(address) = parse_address(&row.token) else {
        return UtxoDisplayRow {
            tree_position: format_tree_position(row.tree, row.position),
            token: row.token.clone(),
            token_icon_path: None,
            amount: row.value.clone(),
            poi_status: format_poi_status(row),
            poi_spendable: row.poi_spendable,
            source_tx_hash: row.source_tx_hash.clone(),
            source_block_timestamp: row.source_block_timestamp,
            spent_tx_hash: row.spent_tx_hash.clone(),
            token_address: row.token.clone(),
            is_spent: row.is_spent,
        };
    };

    let (token, amount, token_icon_path) = if let Some(token) = lookup_token(chain_id, &address) {
        let amount = U256::from_str_radix(&row.value, 10).map_or_else(
            |_| row.value.clone(),
            |value| format_token_amount(value, token.decimals),
        );
        (
            token.symbol.to_owned(),
            amount,
            token_icon_path(chain_id, &address),
        )
    } else {
        (short_address(&address), row.value.clone(), None)
    };

    UtxoDisplayRow {
        tree_position: format_tree_position(row.tree, row.position),
        token,
        token_icon_path,
        amount,
        poi_status: format_poi_status(row),
        poi_spendable: row.poi_spendable,
        source_tx_hash: row.source_tx_hash.clone(),
        source_block_timestamp: row.source_block_timestamp,
        spent_tx_hash: row.spent_tx_hash.clone(),
        token_address: address.to_checksum(None),
        is_spent: row.is_spent,
    }
}

fn format_poi_status(row: &UtxoOutput) -> String {
    if row.poi_statuses.is_empty() {
        return "Unknown".to_string();
    }
    let mut statuses: Vec<_> = row.poi_statuses.values().cloned().collect();
    statuses.sort();
    statuses.dedup();
    if statuses.len() == 1 {
        statuses.remove(0)
    } else {
        statuses.join(", ")
    }
}

fn format_tree_position(tree: u32, position: u64) -> String {
    format!("{tree}/{position}")
}

fn generated_age_label(timestamp: u64) -> String {
    let age_secs = now_epoch_secs().saturating_sub(timestamp);
    format!("{} ago", format_compact_age(age_secs))
}

fn format_compact_age(age_secs: u64) -> String {
    if age_secs < SECONDS_PER_MINUTE {
        return format!("{age_secs}s");
    }

    if age_secs < SECONDS_PER_HOUR {
        return format!("{}m", age_secs / SECONDS_PER_MINUTE);
    }

    if age_secs < 3 * SECONDS_PER_HOUR {
        return format_age_parts(
            age_secs / SECONDS_PER_HOUR,
            "h",
            (age_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE,
            "m",
        );
    }

    if age_secs < SECONDS_PER_DAY {
        return format!("{}h", age_secs / SECONDS_PER_HOUR);
    }

    if age_secs < 3 * SECONDS_PER_DAY {
        return format_age_parts(
            age_secs / SECONDS_PER_DAY,
            "d",
            (age_secs % SECONDS_PER_DAY) / SECONDS_PER_HOUR,
            "h",
        );
    }

    if age_secs < 30 * SECONDS_PER_DAY {
        return format!("{}d", age_secs / SECONDS_PER_DAY);
    }

    if age_secs < 3 * SECONDS_PER_MONTH {
        return format_age_parts(
            age_secs / SECONDS_PER_MONTH,
            "mo",
            (age_secs % SECONDS_PER_MONTH) / SECONDS_PER_DAY,
            "d",
        );
    }

    if age_secs < SECONDS_PER_YEAR {
        return format!("{}mo", age_secs / SECONDS_PER_MONTH);
    }

    if age_secs < 3 * SECONDS_PER_YEAR {
        return format_age_parts(
            age_secs / SECONDS_PER_YEAR,
            "y",
            (age_secs % SECONDS_PER_YEAR) / SECONDS_PER_MONTH,
            "mo",
        );
    }

    format!("{}y", age_secs / SECONDS_PER_YEAR)
}

fn format_age_parts(
    primary: u64,
    primary_unit: &str,
    secondary: u64,
    secondary_unit: &str,
) -> String {
    if secondary == 0 {
        format!("{primary}{primary_unit}")
    } else {
        format!("{primary}{primary_unit} {secondary}{secondary_unit}")
    }
}

fn local_datetime_label(timestamp: u64) -> String {
    let Ok(seconds) = i64::try_from(timestamp) else {
        return format!("Unix timestamp {timestamp}");
    };
    let Some(utc) = DateTime::<Utc>::from_timestamp(seconds, 0) else {
        return format!("Unix timestamp {timestamp}");
    };
    utc.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn short_hash(hash: &str) -> String {
    if hash.len() <= 14 {
        return hash.to_string();
    }
    format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
}

fn public_account_icon_button(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> Button {
    Button::new(id)
        .icon(icon)
        .ghost()
        .xsmall()
        .compact()
        .tooltip(tooltip)
}

fn public_account_metadata_badge(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> impl IntoElement {
    let tooltip = tooltip.into();
    div()
        .id(id)
        .flex()
        .size(px(18.0))
        .items_center()
        .justify_center()
        .rounded_sm()
        .bg(rgb(theme::SURFACE))
        .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
        .child(Icon::new(icon).xsmall().text_color(rgb(theme::TEXT_MUTED)))
}

fn public_account_matches_search(account: &PublicAccountMetadata, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }
    account
        .label
        .as_deref()
        .is_some_and(|label| label.to_ascii_lowercase().contains(&query))
        || format!("{:#x}", account.address).contains(&query)
}

fn public_account_display_label(account: &PublicAccountMetadata) -> Option<String> {
    account
        .label
        .as_ref()
        .filter(|label| !label.trim().is_empty())
        .cloned()
}

fn public_address_qr_payload(address: Address) -> String {
    format!("{address:#x}")
}

const fn public_address_qr_module_range(qr_size: i32) -> std::ops::Range<i32> {
    -PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES..qr_size + PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES
}

fn next_public_account_label_number(account_count: usize) -> u32 {
    u32::try_from(account_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .unwrap_or(u32::MAX)
}

const fn public_account_source_label(source: PublicAccountSource) -> &'static str {
    match source {
        PublicAccountSource::Derived => "Derived",
        PublicAccountSource::Imported => "Imported",
    }
}

const fn public_account_source_icon(source: PublicAccountSource) -> RailgunPublicAccountIcon {
    match source {
        PublicAccountSource::Derived => RailgunPublicAccountIcon::Derived,
        PublicAccountSource::Imported => RailgunPublicAccountIcon::Imported,
    }
}

fn public_asset_label(chain_id: u64, asset: PublicAssetId) -> String {
    match asset {
        PublicAssetId::Native => chain_name(chain_id).map_or_else(
            || "Native".to_string(),
            |name| match chain_id {
                56 => "BNB".to_string(),
                137 => "MATIC".to_string(),
                _ => format!("{name} native"),
            },
        ),
        PublicAssetId::Erc20(token) => lookup_token(chain_id, &token)
            .map_or_else(|| short_address(&token), |info| info.symbol.to_string()),
    }
}

fn public_action_asset_label(chain_id: u64, asset: PublicAssetId) -> String {
    match asset {
        PublicAssetId::Native => native_token_display_label(chain_id).to_string(),
        PublicAssetId::Erc20(_) => public_asset_label(chain_id, asset),
    }
}

fn public_asset_decimals(chain_id: u64, asset: PublicAssetId) -> Option<u8> {
    match asset {
        PublicAssetId::Native => Some(18),
        PublicAssetId::Erc20(token) => lookup_token(chain_id, &token).map(|info| info.decimals),
    }
}

fn public_asset_icon_path(chain_id: u64, asset: PublicAssetId) -> Option<PathBuf> {
    match asset {
        PublicAssetId::Native => chain_icon_path(chain_id),
        PublicAssetId::Erc20(token) => token_icon_path(chain_id, &token),
    }
}

const fn public_account_status_id(status: PublicAccountStatus) -> &'static str {
    match status {
        PublicAccountStatus::Active => "active",
        PublicAccountStatus::Inactive => "inactive",
    }
}

fn merge_public_balance_snapshot(
    current: Option<&PublicBalanceSnapshot>,
    refreshed: PublicBalanceSnapshot,
    refreshed_status: PublicAccountStatus,
) -> PublicBalanceSnapshot {
    let Some(current) = current.filter(|current| current.chain_id == refreshed.chain_id) else {
        return refreshed;
    };
    let refreshed_ids = refreshed
        .accounts
        .iter()
        .map(|account| account.account.public_account_uuid.clone())
        .collect::<BTreeSet<_>>();
    let mut accounts = current
        .accounts
        .iter()
        .filter(|account| {
            account.account.status != refreshed_status
                && !refreshed_ids.contains(account.account.public_account_uuid.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    accounts.extend(refreshed.accounts);
    PublicBalanceSnapshot {
        chain_id: refreshed.chain_id,
        refreshed_at: refreshed.refreshed_at,
        accounts,
    }
}

fn public_balance_amount_label(amount: &PublicBalanceAmount, decimals: u8) -> String {
    match amount {
        PublicBalanceAmount::Available(amount) => format_token_amount(*amount, decimals),
        PublicBalanceAmount::Unavailable => "unavailable".to_string(),
    }
}

fn public_balance_entry_for_chain(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
    asset: PublicAssetId,
    status: PublicAccountStatus,
) -> Option<PublicBalanceEntry> {
    let snapshot = snapshot.filter(|snapshot| snapshot.chain_id == chain_id)?;
    snapshot
        .accounts
        .iter()
        .find(|account| {
            account.account.public_account_uuid.as_str() == public_account_uuid
                && account.account.status == status
        })?
        .balances
        .iter()
        .find(|entry| entry.asset.id == asset)
        .cloned()
}

fn public_account_visible_balances_for_chain(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
    status: PublicAccountStatus,
) -> Vec<PublicBalanceEntry> {
    let Some(snapshot) = snapshot.filter(|snapshot| snapshot.chain_id == chain_id) else {
        return Vec::new();
    };
    snapshot
        .accounts
        .iter()
        .find(|account| {
            account.account.public_account_uuid.as_str() == public_account_uuid
                && account.account.status == status
        })
        .map_or_else(Vec::new, |account| {
            account
                .balances
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.amount,
                        PublicBalanceAmount::Available(amount) if !amount.is_zero()
                    )
                })
                .cloned()
                .collect()
        })
}

fn render_public_action_stepper(
    root: &Entity<WalletRoot>,
    steps: &[PublicActionStepState],
    expanded_error_steps: &BTreeSet<PublicActionProgressStep>,
    asset_label: &str,
) -> gpui::Div {
    let mut stepper = div()
        .flex()
        .flex_col()
        .gap_0()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_HOVER_SUBTLE))
        .border_1()
        .border_color(rgb(theme::BORDER_SUBTLE));
    let last_index = steps.len().saturating_sub(1);
    for (index, step) in steps.iter().enumerate() {
        stepper = stepper.child(render_public_action_step(
            root,
            step,
            index == last_index,
            expanded_error_steps.contains(&step.step),
            asset_label,
        ));
    }
    stepper
}

fn render_public_action_step(
    root: &Entity<WalletRoot>,
    step: &PublicActionStepState,
    is_last: bool,
    error_details_open: bool,
    asset_label: &str,
) -> gpui::Div {
    let color = public_action_step_color(step.status);
    let title = public_action_step_label(step.step);
    let detail = public_action_step_detail(step.step, step.status);
    let mut body = div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap_1()
        .pb(if is_last { px(0.0) } else { px(12.0) })
        .child(
            app_strong_text(title)
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    if step.status == PublicActionStepStatus::Error {
        body = body.child(render_public_action_step_error(
            root.clone(),
            step,
            asset_label,
            error_details_open,
        ));
    } else {
        body = body.child(
            app_muted_text(detail)
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    }
    body = body.children(
        step.tx_hash
            .as_ref()
            .map(|tx_hash| render_public_action_step_hash(step.step, tx_hash.as_ref())),
    );

    div()
        .flex()
        .items_start()
        .gap_3()
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .child(render_public_action_step_marker(step.status, color))
                .children((!is_last).then(|| {
                    div()
                        .w(px(2.0))
                        .flex_1()
                        .min_h(px(32.0))
                        .my(px(3.0))
                        .rounded_full()
                        .bg(rgb(color))
                })),
        )
        .child(body)
}

fn render_public_action_step_error(
    root: Entity<WalletRoot>,
    step: &PublicActionStepState,
    asset_label: &str,
    details_open: bool,
) -> gpui::Div {
    let summary = public_action_error_summary(step.step, step.message.as_deref(), asset_label);
    let details = public_action_error_details(&summary, step.message.as_deref());
    let copy_value =
        public_action_error_copy_value(step.step, asset_label, &summary, details.as_deref());
    let copy_id = SharedString::from(format!(
        "wallet-public-action-{}-error-copy",
        public_action_step_id(step.step),
    ));
    let mut error = div().flex().flex_col().gap_1().child(
        div()
            .flex()
            .items_start()
            .gap_1()
            .min_w(px(0.0))
            .child(
                app_muted_text(summary)
                    .flex_1()
                    .min_w(px(0.0))
                    .whitespace_normal()
                    .text_color(rgb(theme::DANGER))
                    .line_height(gpui::relative(1.0)),
            )
            .child(clipboard_with_toast(copy_id, copy_value)),
    );

    if let Some(details) = details {
        let step_kind = step.step;
        let toggle_root = root;
        let toggle_id = SharedString::from(format!(
            "wallet-public-action-{}-error-details-toggle",
            public_action_step_id(step_kind),
        ));
        error = error.child(
            Collapsible::new()
                .open(details_open)
                .child(
                    div()
                        .id(toggle_id)
                        .flex()
                        .items_center()
                        .gap_1()
                        .cursor_pointer()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .on_click(move |_event, _window, cx| {
                            toggle_root.update(cx, |root, cx| {
                                root.set_public_action_error_details_open(
                                    step_kind,
                                    !details_open,
                                    cx,
                                );
                            });
                        })
                        .child(app_muted_text(if details_open {
                            "Hide details"
                        } else {
                            "Details"
                        }))
                        .child(
                            Icon::new(if details_open {
                                IconName::ChevronUp
                            } else {
                                IconName::ChevronDown
                            })
                            .xsmall()
                            .text_color(rgb(theme::TEXT_MUTED)),
                        ),
                )
                .content(
                    div().pt(px(2.0)).min_w(px(0.0)).child(
                        app_muted_text(details)
                            .font_family(APP_MONO_FONT_FAMILY)
                            .text_size(px(12.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .whitespace_normal(),
                    ),
                ),
        );
    }
    error
}

fn render_public_action_step_marker(status: PublicActionStepStatus, color: u32) -> gpui::Div {
    div()
        .size(px(26.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .border_1()
        .border_color(rgb(color))
        .bg(rgb(theme::SURFACE))
        .text_color(rgb(color))
        .child(match status {
            PublicActionStepStatus::NotStarted => div()
                .size(px(7.0))
                .rounded_full()
                .bg(rgb(color))
                .into_any_element(),
            PublicActionStepStatus::Pending => Spinner::new()
                .icon(IconName::LoaderCircle)
                .color(rgb(color).into())
                .with_size(px(14.0))
                .into_any_element(),
            PublicActionStepStatus::Done => {
                Icon::new(IconName::CircleCheck).small().into_any_element()
            }
            PublicActionStepStatus::Error => Icon::new(IconName::TriangleAlert)
                .small()
                .into_any_element(),
        })
}

fn render_public_action_step_hash(step: PublicActionProgressStep, tx_hash: &str) -> gpui::Div {
    let button_id = SharedString::from(format!(
        "wallet-public-action-{}-tx-copy",
        public_action_step_id(step)
    ));
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(
            app_muted_text(short_hash(tx_hash))
                .font_family(APP_MONO_FONT_FAMILY)
                .line_height(gpui::relative(1.0)),
        )
        .child(clipboard_with_toast(button_id, tx_hash.to_string()))
}

const fn public_action_step_color(status: PublicActionStepStatus) -> u32 {
    match status {
        PublicActionStepStatus::NotStarted => theme::TEXT,
        PublicActionStepStatus::Pending => theme::WARNING,
        PublicActionStepStatus::Done => theme::SUCCESS,
        PublicActionStepStatus::Error => theme::DANGER,
    }
}

const fn public_action_step_label(step: PublicActionProgressStep) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "Send",
        PublicActionProgressStep::Wrap => "Wrap",
        PublicActionProgressStep::Approve => "Approve",
        PublicActionProgressStep::Shield => "Shield",
    }
}

const fn public_action_step_detail(
    step: PublicActionProgressStep,
    status: PublicActionStepStatus,
) -> &'static str {
    match status {
        PublicActionStepStatus::NotStarted => match step {
            PublicActionProgressStep::Send => "Waiting to broadcast the transfer.",
            PublicActionProgressStep::Wrap => "Waiting to wrap the native token.",
            PublicActionProgressStep::Approve => "Waiting to approve the shield contract.",
            PublicActionProgressStep::Shield => "Waiting to shield into the Private wallet.",
        },
        PublicActionStepStatus::Pending => "Broadcasting and waiting for confirmation.",
        PublicActionStepStatus::Done => "Confirmed on-chain.",
        PublicActionStepStatus::Error => "Failed.",
    }
}

fn public_action_error_summary(
    step: PublicActionProgressStep,
    details: Option<&str>,
    asset_label: &str,
) -> String {
    let details = details.unwrap_or_default().to_ascii_lowercase();
    if details.contains("estimate gas") {
        return match step {
            PublicActionProgressStep::Send => {
                "Could not estimate gas. Check amount, recipient, and gas balance.".to_string()
            }
            PublicActionProgressStep::Wrap => format!(
                "Could not estimate gas to wrap {asset_label}. Check amount and gas balance."
            ),
            PublicActionProgressStep::Approve => {
                "Could not estimate gas for approval. Check token balance and try again."
                    .to_string()
            }
            PublicActionProgressStep::Shield => {
                "Could not estimate gas for shielding. Try again or check the RPC/network."
                    .to_string()
            }
        };
    }
    if details.contains("revert") {
        return match step {
            PublicActionProgressStep::Send => "Transfer reverted on-chain.".to_string(),
            PublicActionProgressStep::Wrap => format!("Wrapping {asset_label} reverted on-chain."),
            PublicActionProgressStep::Approve => "Approval reverted on-chain.".to_string(),
            PublicActionProgressStep::Shield => "Shielding reverted on-chain.".to_string(),
        };
    }
    match step {
        PublicActionProgressStep::Send => {
            "Could not send publicly. Check amount, recipient, and gas balance.".to_string()
        }
        PublicActionProgressStep::Wrap => {
            format!("Could not wrap {asset_label}. Check amount and gas balance.")
        }
        PublicActionProgressStep::Approve => {
            "Could not approve the shield contract. Check token balance and try again.".to_string()
        }
        PublicActionProgressStep::Shield => {
            "Could not shield into the Private wallet. Try again or check the RPC/network."
                .to_string()
        }
    }
}

fn public_action_error_details(summary: &str, details: Option<&str>) -> Option<String> {
    let details = details?.trim();
    if details.is_empty() || details == summary {
        None
    } else {
        Some(details.to_string())
    }
}

fn public_action_error_copy_value(
    step: PublicActionProgressStep,
    asset_label: &str,
    summary: &str,
    details: Option<&str>,
) -> String {
    let mut value = format!(
        "Step: {}\nAsset: {asset_label}\nSummary: {summary}",
        public_action_step_label(step),
    );
    if let Some(details) = details {
        value.push_str("\nDetails: ");
        value.push_str(details);
    }
    value
}

const fn public_action_step_id(step: PublicActionProgressStep) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "send",
        PublicActionProgressStep::Wrap => "wrap",
        PublicActionProgressStep::Approve => "approve",
        PublicActionProgressStep::Shield => "shield",
    }
}

fn public_action_progress_steps(
    mode: PublicActionMode,
    asset: PublicAssetId,
) -> Vec<PublicActionProgressStep> {
    match mode {
        PublicActionMode::Send => vec![PublicActionProgressStep::Send],
        PublicActionMode::Shield if asset == PublicAssetId::Native => vec![
            PublicActionProgressStep::Wrap,
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
        PublicActionMode::Shield => vec![
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
    }
}

fn parse_address(raw: &str) -> Option<Address> {
    raw.parse().ok()
}

fn parse_repair_cache_block(raw: &str) -> Result<Option<u64>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let block = trimmed
        .parse::<u64>()
        .map_err(|_| "Enter a block number, or 0 for deployment block.")?;
    Ok(Some(block))
}

const fn repair_cache_help_text(has_start_block_hint: bool) -> &'static str {
    if has_start_block_hint {
        "Rewind and rescan this chain's wallet cache. Use 0 for deployment block, or use the wallet start block below."
    } else {
        "Rewind and rescan this chain's wallet cache. Use 0 for deployment block."
    }
}

const fn vault_error_kind(error: &VaultError) -> &'static str {
    match error {
        VaultError::Random => "random",
        VaultError::InvalidKdfParams => "invalid_kdf_params",
        VaultError::Kdf => "kdf",
        VaultError::KeySeparation => "key_separation",
        VaultError::Encrypt => "encrypt",
        VaultError::Decrypt => "decrypt",
        VaultError::Encode(_) => "encode",
        VaultError::Decode(_) => "decode",
        VaultError::Db(_) => "db",
        VaultError::Io(_) => "io",
        VaultError::Key(_) => "key",
        VaultError::UnsupportedVersion(_) => "unsupported_version",
        VaultError::VaultAlreadyExists => "vault_already_exists",
        VaultError::VaultNotFound => "vault_not_found",
        VaultError::UnlockFailed => "unlock_failed",
        VaultError::InvalidSpendGrant => "invalid_spend_grant",
        VaultError::WalletNotFound => "wallet_not_found",
        VaultError::InvalidWalletLabel => "invalid_wallet_label",
        VaultError::DuplicateWalletLabel => "duplicate_wallet_label",
        VaultError::InvalidWalletOrder => "invalid_wallet_order",
        VaultError::LastActiveWallet => "last_active_wallet",
        VaultError::WalletDisplayOrderOverflow => "wallet_display_order_overflow",
        VaultError::PublicAccountNotFound => "public_account_not_found",
        VaultError::DuplicatePublicAccountAddress => "duplicate_public_account_address",
        VaultError::InvalidPublicAccountOperation => "invalid_public_account_operation",
        VaultError::PublicAccountDisplayOrderOverflow => "public_account_display_order_overflow",
        VaultError::InvalidPublicEvmPrivateKey => "invalid_public_evm_private_key",
        VaultError::PublicEvmKeyDerivation => "public_evm_key_derivation",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use alloy::primitives::{Address, U256};
    use alloy::uint;
    use broadcaster_monitor::FeeRow;
    use gpui_component::select::SelectItem;
    use wallet_ops::{
        BroadcasterFeePolicy, ListUtxosOutput, PublicAccountBalance, PublicActionProgressStep,
        PublicAssetId, PublicBalanceAmount, PublicBalanceAsset, PublicBalanceEntry,
        PublicBalanceSnapshot, PublicBroadcasterFeeMargin, PublicBroadcasterFeeMode,
        SyncProgressStage, SyncProgressUpdate, TransactionGenerationStage, UtxoOutput,
        vault::{
            PublicAccountMetadata, PublicAccountScope, PublicAccountSource, PublicAccountStatus,
            WalletMetadataBundle, WalletSource, WalletStatus,
        },
    };

    use super::{
        Activity, BroadcasterChoice, ChainUtxoState, CostEstimateStatus,
        PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT, PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE,
        PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES, PrivateActionMetric, PublicActionMode,
        PublicBroadcasterFeeTokenOption, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
        SECONDS_PER_MONTH, SECONDS_PER_YEAR, UnshieldAsset, UnshieldAssetKey, WalletSelectItem,
        WalletTab, adjusted_amount_for_max_change, broadcaster_choice_supported_by_candidates,
        build_send_asset, build_unshield_asset, display_rows_from_output,
        effective_public_broadcaster_fee_mode, fee_token_option_has_eligible_broadcaster,
        format_compact_age, format_exact_asset_amount_for_display, format_form_error_for_asset,
        format_native_token_amount_for_display, format_private_asset_rows,
        format_public_broadcaster_fee_margin, format_report_chain, format_send_amount_input,
        format_total, format_unshield_amount_input, loading_summary, max_send_amount_from_snapshot,
        max_unshield_amount_from_snapshot, merge_public_balance_snapshot,
        native_token_display_label, native_wrapped_output_labels, next_public_account_label_number,
        parse_repair_cache_block, private_action_metrics, progress_detail,
        public_account_identicon_color, public_account_identicon_pattern,
        public_account_matches_search, public_account_visible_balances_for_chain,
        public_action_asset_label, public_action_error_copy_value, public_action_error_details,
        public_action_error_summary, public_action_max_amount_after_reserve,
        public_action_max_label, public_action_progress_steps, public_address_qr_module_range,
        public_address_qr_payload, public_balance_entry_for_chain,
        public_broadcaster_candidates_for_asset, public_broadcaster_cost_status,
        public_broadcaster_cost_status_text, public_broadcaster_fee_token_options_from_snapshot,
        public_broadcaster_submit_disabled_for_fee_token_options, refresh_form_asset_from_snapshot,
        repair_cache_help_text, resolve_selected_public_broadcaster_fee_token,
        send_asset_key_from_formatted, send_element_id, send_key_matches_asset,
        should_focus_utxo_table, should_preserve_estimate_after_broadcaster_policy_change,
        should_show_broadcaster_fee_mode_toggle, should_show_distinct_amount,
        should_show_pending_poi_amount, unshield_asset_key_from_formatted, unshield_element_id,
        unshield_key_matches_asset, wallet_generation_matches, wallet_options_from_metadata,
    };

    fn utxo_output(token: &str, value: &str, is_spent: bool) -> UtxoOutput {
        const SOURCE_TX_HASH: &str =
            "0x1111111111111111111111111111111111111111111111111111111111111111";
        const SPENT_TX_HASH: &str =
            "0x2222222222222222222222222222222222222222222222222222222222222222";

        utxo_output_with_hashes(
            token,
            value,
            is_spent,
            SOURCE_TX_HASH,
            is_spent.then_some(SPENT_TX_HASH),
        )
    }

    fn utxo_output_with_hashes(
        token: &str,
        value: &str,
        is_spent: bool,
        source_tx_hash: &str,
        spent_tx_hash: Option<&str>,
    ) -> UtxoOutput {
        UtxoOutput {
            tree: 0,
            position: 7,
            token: token.to_string(),
            value: value.to_string(),
            commitment_kind: "Transact".to_string(),
            commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            blinded_commitment:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            poi_statuses: BTreeMap::from([(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                if is_spent { "Unknown" } else { "Valid" }.to_string(),
            )]),
            poi_spendable: !is_spent,
            source_tx_hash: source_tx_hash.to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent,
            spent_tx_hash: spent_tx_hash.map(str::to_string),
            spent_block_number: spent_tx_hash.map(|_| 21),
        }
    }

    fn unshield_utxo_output(token: Address, value: u64, tree: u32, position: u64) -> UtxoOutput {
        UtxoOutput {
            tree,
            position,
            token: token.to_checksum(None),
            value: value.to_string(),
            commitment_kind: "Transact".to_string(),
            commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            blinded_commitment:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            poi_statuses: BTreeMap::from([(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                "Valid".to_string(),
            )]),
            poi_spendable: true,
            source_tx_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent: false,
            spent_tx_hash: None,
            spent_block_number: None,
        }
    }

    fn fee_row(chain_id: u64, token: Address, fees_id: &str) -> FeeRow {
        const RAILGUN_ADDRESS: &str = "0zk1qy4v02p5zkq0zfpaxhz79j5tslrv8c44d80d8jr2fuecrtxlp8lemrv7j6fe3z53ll0jm7u592n0hr8elesd0xzv6y9jpdvsyln80m95jcxhvnmagfqg5p6e9mp";

        FeeRow {
            chain_id,
            railgun_address: Arc::from(RAILGUN_ADDRESS),
            token_address: token,
            fee: uint!(10_U256),
            signature_valid: true,
            fees_id: Arc::from(fees_id),
            fee_expiration: SystemTime::now() + Duration::from_secs(60),
            available_wallets: 1,
            version: Arc::from("8.2.3"),
            relay_adapt: Address::ZERO,
            relay_adapt_7702: None,
            required_poi_list_keys: Vec::new(),
            identifier: Some(Arc::from(fees_id)),
            last_seen: SystemTime::now(),
            reliability: 0.9,
        }
    }

    fn wallet_metadata(
        wallet_uuid: &str,
        label: &str,
        source: WalletSource,
        status: WalletStatus,
        display_order: u32,
    ) -> WalletMetadataBundle {
        WalletMetadataBundle {
            wallet_uuid: wallet_uuid.to_string(),
            label: label.to_string(),
            derivation_index: 0,
            source,
            status,
            display_order,
        }
    }

    #[test]
    fn wallet_options_hide_inactive_and_sort_active_metadata() {
        let options = wallet_options_from_metadata(vec![
            wallet_metadata(
                "wallet-b",
                "Beta",
                WalletSource::Imported,
                WalletStatus::Active,
                2,
            ),
            wallet_metadata(
                "wallet-hidden",
                "Hidden",
                WalletSource::Imported,
                WalletStatus::Inactive,
                0,
            ),
            wallet_metadata(
                "wallet-a",
                "Alpha",
                WalletSource::Generated,
                WalletStatus::Active,
                1,
            ),
        ]);

        assert_eq!(options.len(), 2);
        assert_eq!(options[0].wallet_id.as_ref(), "wallet-a");
        assert_eq!(options[0].label.as_ref(), "Alpha");
        assert_eq!(options[0].source, WalletSource::Generated);
        assert_eq!(options[1].wallet_id.as_ref(), "wallet-b");
    }

    #[test]
    fn wallet_select_item_matches_label_and_wallet_id() {
        let wallet = WalletSelectItem {
            wallet_id: "wallet-a".into(),
            label: "Alpha".into(),
        };

        assert!(wallet.matches("alpha"));
        assert!(wallet.matches("wallet-a"));
        assert!(!wallet.matches("add"));
    }

    #[test]
    fn wallet_generation_guard_rejects_stale_async_results() {
        assert!(wallet_generation_matches(
            Some("wallet-a"),
            2,
            "wallet-a",
            2
        ));
        assert!(!wallet_generation_matches(
            Some("wallet-b"),
            2,
            "wallet-a",
            2
        ));
        assert!(!wallet_generation_matches(
            Some("wallet-a"),
            3,
            "wallet-a",
            2
        ));
        assert!(!wallet_generation_matches(None, 2, "wallet-a", 2));
    }

    #[test]
    fn display_rows_use_known_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![utxo_output(
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "1234567",
                false,
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows[0].token, "USDC");
        assert_eq!(rows[0].amount, "1.23");
        assert_eq!(rows[0].tree_position, "0/7");
        assert_eq!(rows[0].poi_status, "Valid");
        assert!(rows[0].poi_spendable);
        assert_eq!(rows[0].source_block_timestamp, 1_700_000_011);
        assert!(rows[0].token_icon_path.is_some());
        assert!(!rows[0].is_spent);
    }

    #[test]
    fn compact_age_uses_expected_thresholds() {
        const M: u64 = SECONDS_PER_MINUTE;
        const H: u64 = SECONDS_PER_HOUR;
        const D: u64 = SECONDS_PER_DAY;
        const MO: u64 = SECONDS_PER_MONTH;
        const Y: u64 = SECONDS_PER_YEAR;

        assert_eq!(format_compact_age(0), "0s");
        assert_eq!(format_compact_age(59), "59s");
        assert_eq!(format_compact_age(M), "1m");
        assert_eq!(format_compact_age(59 * M + 59), "59m");
        assert_eq!(format_compact_age(H), "1h");
        assert_eq!(format_compact_age(2 * H + 14 * M), "2h 14m");
        assert_eq!(format_compact_age(3 * H), "3h");
        assert_eq!(format_compact_age(23 * H + 59 * M), "23h");
        assert_eq!(format_compact_age(D), "1d");
        assert_eq!(format_compact_age(2 * D + 3 * H), "2d 3h");
        assert_eq!(format_compact_age(3 * D), "3d");
        assert_eq!(format_compact_age(29 * D), "29d");
        assert_eq!(format_compact_age(30 * D), "1mo");
        assert_eq!(format_compact_age(2 * MO + 4 * D), "2mo 4d");
        assert_eq!(format_compact_age(3 * MO), "3mo");
        assert_eq!(format_compact_age(11 * MO), "11mo");
        assert_eq!(format_compact_age(Y), "1y");
        assert_eq!(format_compact_age(2 * Y + 3 * MO), "2y 3mo");
        assert_eq!(format_compact_age(3 * Y), "3y");
    }

    #[test]
    fn display_rows_fall_back_for_unknown_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![utxo_output(
                "0x1111111111111111111111111111111111111111",
                "42",
                false,
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows[0].amount, "42");
        assert_eq!(
            rows[0].token_address,
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(rows[0].token_icon_path, None);
    }

    #[test]
    fn totals_format_known_token_amount() {
        let total = wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        };

        assert_eq!(format_total(1, &total), "USDC 1.23");
    }

    #[test]
    fn form_error_formats_broadcaster_max_in_token_units() {
        let asset = UnshieldAsset {
            chain_id: 1,
            token: Address::ZERO,
            label: "USDC".to_string(),
            decimals: Some(6),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };

        let formatted = format_form_error_for_asset(
            "build public broadcaster send proof: public broadcaster max entered amount: 388585770",
            &asset,
            asset.token,
        );

        assert_eq!(
            formatted,
            "Max POI-verified entered amount for public broadcaster: 388.58577 USDC. Try a smaller amount or switch fee mode."
        );
    }

    #[test]
    fn report_chain_preserves_wrapped_public_broadcaster_error() {
        let asset = UnshieldAsset {
            chain_id: 1,
            token: Address::ZERO,
            label: "USDC".to_string(),
            decimals: Some(6),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };
        let error = eyre::eyre!("public broadcaster max entered amount: 388585770")
            .wrap_err("build public broadcaster send proof");

        let chain = format_report_chain(&error);

        assert_eq!(
            chain,
            "build public broadcaster send proof: public broadcaster max entered amount: 388585770"
        );
        assert_eq!(
            format_form_error_for_asset(chain.as_str(), &asset, asset.token),
            "Max POI-verified entered amount for public broadcaster: 388.58577 USDC. Try a smaller amount or switch fee mode."
        );
    }

    #[test]
    fn form_error_formats_fee_token_balance_in_selected_fee_token_units() {
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            .parse::<Address>()
            .expect("weth address");
        let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse::<Address>()
            .expect("usdc address");
        let asset = UnshieldAsset {
            chain_id: 1,
            token: weth,
            label: "WETH".to_string(),
            decimals: Some(18),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };

        let formatted = format_form_error_for_asset(
            "build public broadcaster unshield proof: public broadcaster fee-token max spendable: 388585770",
            &asset,
            usdc,
        );

        assert_eq!(
            formatted,
            "Broadcaster fee exceeds available fee-token balance: 388.58577 USDC. Choose a fee token with more spendable balance or a lower-fee broadcaster."
        );
    }

    #[test]
    fn public_broadcaster_amount_display_is_exact() {
        let asset = UnshieldAsset {
            chain_id: 1,
            token: Address::ZERO,
            label: "USDC".to_string(),
            decimals: Some(6),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };

        assert_eq!(
            format_exact_asset_amount_for_display(uint!(388_429_885_U256), &asset),
            "388.429885 USDC"
        );
        assert_eq!(
            format_exact_asset_amount_for_display(uint!(14_390_115_U256), &asset),
            "14.390115 USDC"
        );
    }

    #[test]
    fn public_broadcaster_estimate_hides_duplicate_amount_rows() {
        let entered = uint!(388_429_885_U256);

        assert!(!should_show_distinct_amount(entered, entered));
        assert!(should_show_distinct_amount(
            entered,
            entered + uint!(1_U256)
        ));
    }

    #[test]
    fn public_broadcaster_cost_status_separates_pending_from_estimating() {
        assert_eq!(public_broadcaster_cost_status(true, false), None);
        assert_eq!(
            public_broadcaster_cost_status(false, true),
            Some(CostEstimateStatus::Estimating)
        );
        assert_eq!(public_broadcaster_cost_status(true, true), None);
        assert_eq!(public_broadcaster_cost_status(false, false), None);
        assert_eq!(
            public_broadcaster_cost_status_text(CostEstimateStatus::Estimating).0,
            "Estimating public broadcaster cost..."
        );
    }

    #[test]
    fn fee_token_options_use_poi_spendable_balances_and_broadcaster_counts() {
        let token_a = Address::from([0x11; 20]);
        let token_b = Address::from([0x22; 20]);
        let token_c = Address::from([0x33; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token_a, 5, 0, 1),
                unshield_utxo_output(token_b, 7, 0, 2),
            ],
            totals: vec![
                wallet_ops::TokenTotal {
                    token: token_a.to_checksum(None),
                    total: "5".to_string(),
                    poi_verified_total: "5".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: token_b.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: token_c.to_checksum(None),
                    total: "9".to_string(),
                    poi_verified_total: "0".to_string(),
                },
            ],
        };
        let fee_rows = vec![fee_row(1, token_a, "token-a")];

        let options = public_broadcaster_fee_token_options_from_snapshot(
            &snapshot,
            &fee_rows,
            false,
            BroadcasterFeePolicy::default(),
            |_| None,
        );

        assert_eq!(options.len(), 2);
        let option_a = options
            .iter()
            .find(|option| option.token == token_a)
            .expect("token a option");
        assert_eq!(option_a.max_spendable, uint!(5_U256));
        assert_eq!(option_a.eligible_broadcaster_count, 1);
        let option_b = options
            .iter()
            .find(|option| option.token == token_b)
            .expect("token b option");
        assert_eq!(option_b.max_spendable, uint!(7_U256));
        assert_eq!(option_b.eligible_broadcaster_count, 0);
        assert!(!options.iter().any(|option| option.token == token_c));
    }

    #[test]
    fn fee_token_options_use_fee_only_transaction_spend_limit() {
        let token = Address::from([0x34; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 20,
            unspent_count: 20,
            spent_count: 0,
            utxos: (0..20)
                .map(|position| unshield_utxo_output(token, 1, 0, position))
                .collect(),
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "20".to_string(),
                poi_verified_total: "20".to_string(),
            }],
        };
        let fee_rows = vec![fee_row(1, token, "token")];

        let options = public_broadcaster_fee_token_options_from_snapshot(
            &snapshot,
            &fee_rows,
            false,
            BroadcasterFeePolicy::default(),
            |_| None,
        );

        assert_eq!(options.len(), 1);
        assert_eq!(options[0].max_spendable, uint!(13_U256));
    }

    #[test]
    fn fee_token_options_include_known_token_icons() {
        let token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse::<Address>()
            .expect("usdc address");
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![unshield_utxo_output(token, 1, 0, 1)],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "1".to_string(),
                poi_verified_total: "1".to_string(),
            }],
        };
        let fee_rows = vec![fee_row(1, token, "usdc")];

        let options = public_broadcaster_fee_token_options_from_snapshot(
            &snapshot,
            &fee_rows,
            false,
            BroadcasterFeePolicy::default(),
            |_| None,
        );

        assert_eq!(options.len(), 1);
        assert!(options[0].icon_path.is_some());
    }

    #[test]
    fn fee_token_resolution_prefers_current_then_action_then_first_eligible() {
        let action = Address::from([0x44; 20]);
        let current = Address::from([0x45; 20]);
        let fallback = Address::from([0x46; 20]);
        let option = |token, count| PublicBroadcasterFeeTokenOption {
            token,
            label: format!("token-{count}"),
            decimals: None,
            max_spendable: U256::from(1),
            eligible_broadcaster_count: count,
            icon_path: None,
        };

        assert_eq!(
            resolve_selected_public_broadcaster_fee_token(
                current,
                action,
                &[option(current, 1), option(action, 1)],
            ),
            current
        );
        assert_eq!(
            resolve_selected_public_broadcaster_fee_token(
                current,
                action,
                &[option(current, 0), option(action, 1), option(fallback, 1)],
            ),
            action
        );
        assert_eq!(
            resolve_selected_public_broadcaster_fee_token(
                current,
                action,
                &[option(current, 0), option(action, 0), option(fallback, 1)],
            ),
            fallback
        );
    }

    #[test]
    fn fee_token_submit_state_requires_selected_token_broadcaster_count() {
        let selected = Address::from([0x51; 20]);
        let other = Address::from([0x52; 20]);
        let options = vec![
            PublicBroadcasterFeeTokenOption {
                token: selected,
                label: "selected".to_string(),
                decimals: None,
                max_spendable: U256::from(1),
                eligible_broadcaster_count: 0,
                icon_path: None,
            },
            PublicBroadcasterFeeTokenOption {
                token: other,
                label: "other".to_string(),
                decimals: None,
                max_spendable: U256::from(1),
                eligible_broadcaster_count: 1,
                icon_path: None,
            },
        ];

        assert!(!fee_token_option_has_eligible_broadcaster(
            &options, selected
        ));
        assert!(fee_token_option_has_eligible_broadcaster(&options, other));
        assert!(public_broadcaster_submit_disabled_for_fee_token_options(
            &options, selected
        ));
        assert!(!public_broadcaster_submit_disabled_for_fee_token_options(
            &options, other
        ));
    }

    #[test]
    fn unsupported_specific_broadcaster_is_detected_for_fee_token_change() {
        let token = Address::from([0x61; 20]);
        let other = Address::from([0x62; 20]);
        let policy = BroadcasterFeePolicy::default();
        let row = fee_row(1, token, "supported");
        let candidates =
            public_broadcaster_candidates_for_asset(&[row], 1, token, false, policy, None)
                .expect("candidates");
        let choice = BroadcasterChoice::Specific {
            railgun_address: candidates[0].railgun_address.clone(),
        };
        let unsupported =
            public_broadcaster_candidates_for_asset(&[], 1, other, false, policy, None)
                .expect("empty candidates");

        assert!(broadcaster_choice_supported_by_candidates(
            &choice,
            &candidates,
            policy
        ));
        assert!(!broadcaster_choice_supported_by_candidates(
            &choice,
            &unsupported,
            policy
        ));
        assert!(should_preserve_estimate_after_broadcaster_policy_change(
            &choice,
            &candidates,
            policy
        ));
        assert!(!should_preserve_estimate_after_broadcaster_policy_change(
            &BroadcasterChoice::Random,
            &candidates,
            policy
        ));
        assert!(!should_preserve_estimate_after_broadcaster_policy_change(
            &choice,
            &unsupported,
            policy
        ));
    }

    #[test]
    fn different_fee_token_forces_add_mode_and_hides_toggle() {
        let action = Address::from([0x71; 20]);
        let fee = Address::from([0x72; 20]);

        assert_eq!(
            effective_public_broadcaster_fee_mode(
                action,
                fee,
                PublicBroadcasterFeeMode::DeductFromAmount,
            ),
            PublicBroadcasterFeeMode::AddToAmount
        );
        assert_eq!(
            effective_public_broadcaster_fee_mode(
                action,
                action,
                PublicBroadcasterFeeMode::DeductFromAmount,
            ),
            PublicBroadcasterFeeMode::DeductFromAmount
        );
        assert!(!should_show_broadcaster_fee_mode_toggle(action, fee));
        assert!(should_show_broadcaster_fee_mode_toggle(action, action));
    }

    #[test]
    fn amount_adjustment_clamps_or_raises_only_at_mode_max() {
        assert_eq!(
            adjusted_amount_for_max_change(uint!(120_U256), Some(uint!(120_U256)), uint!(100_U256),),
            Some(uint!(100_U256))
        );
        assert_eq!(
            adjusted_amount_for_max_change(uint!(100_U256), Some(uint!(100_U256)), uint!(120_U256),),
            Some(uint!(120_U256))
        );
        assert_eq!(
            adjusted_amount_for_max_change(uint!(90_U256), Some(uint!(100_U256)), uint!(120_U256),),
            None
        );
    }

    #[test]
    fn private_tab_is_default_wallet_tab() {
        assert_eq!(WalletTab::default(), WalletTab::Private);
    }

    #[test]
    fn utxo_table_focus_is_activity_scoped() {
        let state = ChainUtxoState::Loading { progress: None };

        assert!(!should_focus_utxo_table(
            Activity::Wallet,
            WalletTab::Private,
            Some(&state)
        ));
        assert!(!should_focus_utxo_table(
            Activity::Broadcaster,
            WalletTab::Activity,
            Some(&state)
        ));
        assert!(should_focus_utxo_table(
            Activity::Wallet,
            WalletTab::Activity,
            Some(&state)
        ));
    }

    #[test]
    fn private_asset_rows_use_totals_formatting() {
        let totals = [wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1000000".to_string(),
        }];

        let rows = format_private_asset_rows(1, &totals);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "USDC");
        assert_eq!(rows[0].amount, "1.23");
        assert_eq!(rows[0].pending_poi_amount, "0.23457");
        assert_eq!(rows[0].pending_poi_total, Some(uint!(234_567_U256)));
        assert!(should_show_pending_poi_amount(rows[0].pending_poi_total));
        assert!(rows[0].icon_path.is_some());
    }

    #[test]
    fn private_asset_rows_hide_zero_pending_poi() {
        let totals = [wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        }];

        let rows = format_private_asset_rows(1, &totals);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pending_poi_amount, "0");
        assert_eq!(rows[0].pending_poi_total, Some(U256::ZERO));
        assert!(!should_show_pending_poi_amount(rows[0].pending_poi_total));
    }

    #[test]
    fn unshield_amount_input_formats_exact_token_units() {
        assert_eq!(
            format_unshield_amount_input(uint!(1_230_000_U256), Some(6)),
            "1.23"
        );
        assert_eq!(
            format_unshield_amount_input(uint!(1_000_000_U256), Some(6)),
            "1"
        );
        assert_eq!(format_unshield_amount_input(uint!(42_U256), None), "42");
    }

    #[test]
    fn send_amount_input_formats_exact_token_units() {
        assert_eq!(
            format_send_amount_input(uint!(1_230_000_U256), Some(6)),
            "1.23"
        );
        assert_eq!(
            format_send_amount_input(uint!(1_000_000_U256), Some(6)),
            "1"
        );
        assert_eq!(format_send_amount_input(uint!(42_U256), None), "42");
    }

    #[test]
    fn transaction_generation_stage_text_is_specific() {
        assert_eq!(
            TransactionGenerationStage::SelectingPrivateNotes.label(),
            "Selecting private notes"
        );
        assert_eq!(
            TransactionGenerationStage::ProvingTransaction.detail(),
            "Generating the zero-knowledge proof. This is usually the slowest step."
        );
        assert_eq!(
            TransactionGenerationStage::PublishingToBroadcaster.label(),
            "Publishing to broadcaster"
        );
        assert_eq!(
            TransactionGenerationStage::WaitingForBroadcasterResponse.detail(),
            "Waiting for the selected broadcaster to respond."
        );
    }

    #[test]
    fn private_action_metrics_hide_values_matching_total() {
        let token = Address::from([0x11; 20]);
        let mut asset = UnshieldAsset {
            chain_id: 1,
            token,
            label: "WETH".to_string(),
            decimals: Some(18),
            total: uint!(10_U256),
            poi_verified_total: uint!(10_U256),
            max_batched: uint!(10_U256),
            icon_path: None,
        };

        assert_eq!(
            private_action_metrics(&asset),
            vec![PrivateActionMetric {
                label: "Total private balance",
                amount: uint!(10_U256),
            }]
        );

        asset.poi_verified_total = uint!(7_U256);
        assert_eq!(
            private_action_metrics(&asset),
            vec![
                PrivateActionMetric {
                    label: "Total private balance",
                    amount: uint!(10_U256),
                },
                PrivateActionMetric {
                    label: "POI-verified balance",
                    amount: uint!(7_U256),
                },
            ]
        );

        asset.poi_verified_total = asset.total;
        asset.max_batched = uint!(8_U256);
        assert_eq!(
            private_action_metrics(&asset),
            vec![
                PrivateActionMetric {
                    label: "Total private balance",
                    amount: uint!(10_U256),
                },
                PrivateActionMetric {
                    label: "Max batched transaction",
                    amount: uint!(8_U256),
                },
            ]
        );
    }

    #[test]
    fn native_wrapped_output_labels_are_chain_specific() {
        assert_eq!(native_wrapped_output_labels(1), Some(("ETH", "WETH")));
        assert_eq!(native_wrapped_output_labels(56), Some(("BNB", "WBNB")));
        assert_eq!(native_wrapped_output_labels(137), Some(("MATIC", "WMATIC")));
        assert_eq!(native_wrapped_output_labels(42161), Some(("ETH", "WETH")));
        assert_eq!(native_wrapped_output_labels(999_999), None);
    }

    #[test]
    fn native_gas_cost_display_uses_base_token_label() {
        assert_eq!(native_token_display_label(1), "ETH");
        assert_eq!(native_token_display_label(999_999), "base token");
        assert_eq!(
            format_native_token_amount_for_display(1, uint!(1_500_000_000_000_000_U256)),
            "0.0015 ETH"
        );
    }

    #[test]
    fn public_account_default_label_number_uses_account_count() {
        assert_eq!(next_public_account_label_number(0), 1);
        assert_eq!(next_public_account_label_number(2), 3);
        assert_eq!(next_public_account_label_number(usize::MAX), u32::MAX);
    }

    #[test]
    fn public_broadcaster_fee_margin_display_is_signed_fee_token_amount() {
        let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse::<Address>()
            .expect("usdc address");

        assert_eq!(
            format_public_broadcaster_fee_margin(
                1,
                usdc,
                PublicBroadcasterFeeMargin::Positive(uint!(123_456_U256))
            ),
            "0.123456 USDC"
        );
        assert_eq!(
            format_public_broadcaster_fee_margin(
                1,
                usdc,
                PublicBroadcasterFeeMargin::Negative(uint!(42_U256))
            ),
            "-0.000042 USDC"
        );
        assert_eq!(
            format_public_broadcaster_fee_margin(1, usdc, PublicBroadcasterFeeMargin::Zero),
            "0 USDC"
        );
    }

    #[test]
    fn max_unshield_amount_from_snapshot_uses_batched_top_chunks() {
        let token = Address::from([0x11; 20]);
        let other = Address::from([0x22; 20]);
        let mut utxos = (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
        utxos.push(unshield_utxo_output(other, 100, 1, 99));
        let mut unknown = unshield_utxo_output(token, 100, 2, 1);
        unknown.poi_statuses.clear();
        unknown.poi_spendable = false;
        utxos.push(unknown);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: utxos.len(),
            unspent_count: utxos.len(),
            spent_count: 0,
            utxos,
            totals: Vec::new(),
        };

        assert_eq!(
            max_unshield_amount_from_snapshot(&snapshot, token),
            uint!(35_U256)
        );
    }

    #[test]
    fn refreshed_form_asset_tracks_new_utxos() {
        let token = Address::from([0x11; 20]);
        let original_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![unshield_utxo_output(token, 5, 0, 1)],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "5".to_string(),
                poi_verified_total: "5".to_string(),
            }],
        };
        let original_row = format_private_asset_rows(1, &original_snapshot.totals)
            .pop()
            .expect("formatted row");
        let original_asset =
            build_unshield_asset(&original_snapshot, &original_row).expect("original asset");
        let updated_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 3, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "8".to_string(),
                poi_verified_total: "8".to_string(),
            }],
        };

        let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false);

        assert_eq!(updated.total, uint!(8_U256));
        assert_eq!(updated.poi_verified_total, uint!(8_U256));
        assert_eq!(updated.max_batched, uint!(8_U256));
    }

    #[test]
    fn refreshed_form_asset_tracks_spent_out_token() {
        let token = Address::from([0x11; 20]);
        let original_asset = UnshieldAsset {
            chain_id: 1,
            token,
            label: "WETH".to_string(),
            decimals: Some(18),
            total: uint!(5_U256),
            poi_verified_total: uint!(5_U256),
            max_batched: uint!(5_U256),
            icon_path: None,
        };
        let mut spent = unshield_utxo_output(token, 5, 0, 1);
        spent.is_spent = true;
        spent.poi_spendable = false;
        spent.spent_tx_hash =
            Some("0x2222222222222222222222222222222222222222222222222222222222222222".to_string());
        spent.spent_block_number = Some(21);
        let updated_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 0,
            spent_count: 1,
            utxos: vec![spent],
            totals: Vec::new(),
        };

        let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false);

        assert_eq!(updated.label, "WETH");
        assert_eq!(updated.decimals, Some(18));
        assert_eq!(updated.total, U256::ZERO);
        assert_eq!(updated.poi_verified_total, U256::ZERO);
        assert_eq!(updated.max_batched, U256::ZERO);
    }

    #[test]
    fn max_send_amount_from_snapshot_uses_batched_top_chunks() {
        let token = Address::from([0x12; 20]);
        let other = Address::from([0x22; 20]);
        let mut utxos = (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
        utxos.push(unshield_utxo_output(other, 100, 1, 99));
        let mut unknown = unshield_utxo_output(token, 100, 2, 1);
        unknown.poi_statuses.clear();
        unknown.poi_spendable = false;
        utxos.push(unknown);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: utxos.len(),
            unspent_count: utxos.len(),
            spent_count: 0,
            utxos,
            totals: Vec::new(),
        };

        assert_eq!(
            max_send_amount_from_snapshot(&snapshot, token),
            uint!(35_U256)
        );
    }

    #[test]
    fn build_unshield_asset_includes_max_batched_transaction() {
        let token = Address::from([0x33; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 7, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "12".to_string(),
                poi_verified_total: "12".to_string(),
            }],
        };
        let row = format_private_asset_rows(1, &snapshot.totals)
            .into_iter()
            .next()
            .expect("asset row");

        let asset = build_unshield_asset(&snapshot, &row).expect("unshield asset");

        assert_eq!(asset.total, uint!(12_U256));
        assert_eq!(asset.max_batched, uint!(12_U256));
    }

    #[test]
    fn build_send_asset_includes_max_batched_transaction() {
        let token = Address::from([0x34; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 7, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "12".to_string(),
                poi_verified_total: "12".to_string(),
            }],
        };
        let row = format_private_asset_rows(1, &snapshot.totals)
            .into_iter()
            .next()
            .expect("asset row");

        let asset = build_send_asset(&snapshot, &row).expect("send asset");

        assert_eq!(asset.total, uint!(12_U256));
        assert_eq!(asset.max_batched, uint!(12_U256));
    }

    #[test]
    fn unshield_key_matches_only_selected_asset() {
        let token = Address::from([0x44; 20]);
        let other = Address::from([0x45; 20]);
        let rows = format_private_asset_rows(
            1,
            &[
                wallet_ops::TokenTotal {
                    token: token.to_checksum(None),
                    total: "5".to_string(),
                    poi_verified_total: "5".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: other.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
            ],
        );
        let key = UnshieldAssetKey::new(1, token);

        assert_eq!(unshield_asset_key_from_formatted(&rows[0]), Some(key));
        assert!(unshield_key_matches_asset(key, &rows[0]));
        assert!(!unshield_key_matches_asset(key, &rows[1]));
    }

    #[test]
    fn send_key_matches_only_selected_asset() {
        let token = Address::from([0x46; 20]);
        let other = Address::from([0x47; 20]);
        let rows = format_private_asset_rows(
            1,
            &[
                wallet_ops::TokenTotal {
                    token: token.to_checksum(None),
                    total: "5".to_string(),
                    poi_verified_total: "5".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: other.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
            ],
        );
        let key = UnshieldAssetKey::new(1, token);

        assert_eq!(send_asset_key_from_formatted(&rows[0]), Some(key));
        assert!(send_key_matches_asset(key, &rows[0]));
        assert!(!send_key_matches_asset(key, &rows[1]));
    }

    #[test]
    fn unshield_element_ids_are_asset_scoped() {
        let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
        let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

        assert_ne!(
            unshield_element_id(first, "cancel").as_ref(),
            unshield_element_id(second, "cancel").as_ref()
        );
        assert_ne!(
            unshield_element_id(first, "copy-to").as_ref(),
            unshield_element_id(first, "copy-data").as_ref()
        );
    }

    fn public_account_for_search(label: Option<&str>, address: Address) -> PublicAccountMetadata {
        PublicAccountMetadata {
            public_account_uuid: "public-account".to_string(),
            address,
            label: label.map(str::to_string),
            source: PublicAccountSource::Imported,
            scope: PublicAccountScope::Global,
            derivation_index: None,
            status: PublicAccountStatus::Active,
            display_order: 0,
        }
    }

    #[test]
    fn public_account_search_matches_empty_query() {
        let account = public_account_for_search(Some("Main account"), Address::from([0x11; 20]));

        assert!(public_account_matches_search(&account, ""));
        assert!(public_account_matches_search(&account, "   "));
    }

    #[test]
    fn public_account_search_matches_label_partial_case_insensitive() {
        let account =
            public_account_for_search(Some("Primary Spending"), Address::from([0x22; 20]));

        assert!(public_account_matches_search(&account, "spend"));
        assert!(public_account_matches_search(&account, "PRIMARY"));
    }

    #[test]
    fn public_account_search_matches_address_partial_case_insensitive() {
        let account = public_account_for_search(None, Address::from([0xab; 20]));

        assert!(public_account_matches_search(&account, "0xabab"));
        assert!(public_account_matches_search(&account, "ABABAB"));
    }

    #[test]
    fn public_account_search_rejects_non_matches() {
        let account = public_account_for_search(Some("Primary"), Address::from([0xcd; 20]));

        assert!(!public_account_matches_search(&account, "savings"));
    }

    #[test]
    fn public_address_qr_payload_is_plain_address() {
        let address = Address::from([0xab; 20]);
        let payload = public_address_qr_payload(address);

        assert_eq!(payload, format!("{address:#x}"));
        assert!(!payload.starts_with("ethereum:"));
    }

    #[test]
    fn public_address_qr_payload_fits_qr_with_quiet_zone() {
        let address = Address::from([0x42; 20]);
        let payload = public_address_qr_payload(address);
        let qr = qrcodegen::QrCode::encode_text(&payload, qrcodegen::QrCodeEcc::Medium)
            .expect("public address should fit in QR code");
        let module_range = public_address_qr_module_range(qr.size());

        assert!(qr.size() > 0);
        assert_eq!(PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES, 4);
        assert_eq!(
            module_range.clone().count(),
            usize::try_from(qr.size() + 8).unwrap()
        );
        assert!(module_range.contains(&-PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES));
        assert!(module_range.contains(&qr.size()));
    }

    #[test]
    fn public_account_identicon_pattern_is_deterministic_and_symmetric() {
        let address = Address::from([0x42; 20]);
        let pattern = public_account_identicon_pattern(&address);

        assert_eq!(pattern, public_account_identicon_pattern(&address));
        assert!(pattern.iter().any(|active| *active));
        for row in pattern.chunks_exact(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE) {
            assert_eq!(row[0], row[4]);
            assert_eq!(row[1], row[3]);
        }
    }

    #[test]
    fn public_account_identicon_differs_for_different_addresses() {
        let first = Address::from([0x11; 20]);
        let second = Address::from([0x22; 20]);

        assert_ne!(
            public_account_identicon_pattern(&first),
            public_account_identicon_pattern(&second),
        );
        assert_ne!(
            public_account_identicon_color(&first),
            public_account_identicon_color(&second),
        );
    }

    #[test]
    fn public_account_identicon_zero_address_is_not_blank() {
        let pattern = public_account_identicon_pattern(&Address::from([0; 20]));
        let active_count = pattern.iter().filter(|active| **active).count();

        assert_eq!(active_count, 1);
        assert!(pattern[PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT / 2]);
    }

    fn public_balance_snapshot_for_test(chain_id: u64) -> PublicBalanceSnapshot {
        let account = public_account_for_search(Some("Main account"), Address::from([0x11; 20]));
        PublicBalanceSnapshot {
            chain_id,
            refreshed_at: SystemTime::UNIX_EPOCH,
            accounts: vec![PublicAccountBalance {
                account,
                balances: vec![PublicBalanceEntry {
                    asset: PublicBalanceAsset {
                        id: PublicAssetId::Native,
                        symbol: "ETH",
                        decimals: 18,
                    },
                    amount: PublicBalanceAmount::Available(U256::from(5_u64)),
                }],
            }],
        }
    }

    #[test]
    fn public_balance_helpers_ignore_stale_chain_snapshot() {
        let snapshot = public_balance_snapshot_for_test(1);

        assert_eq!(
            public_account_visible_balances_for_chain(
                Some(&snapshot),
                1,
                "public-account",
                PublicAccountStatus::Active,
            )
            .len(),
            1,
        );
        assert!(
            public_balance_entry_for_chain(
                Some(&snapshot),
                1,
                "public-account",
                PublicAssetId::Native,
                PublicAccountStatus::Active,
            )
            .is_some(),
        );
        assert!(
            public_account_visible_balances_for_chain(
                Some(&snapshot),
                56,
                "public-account",
                PublicAccountStatus::Active,
            )
            .is_empty(),
        );
        assert!(
            public_balance_entry_for_chain(
                Some(&snapshot),
                56,
                "public-account",
                PublicAssetId::Native,
                PublicAccountStatus::Active,
            )
            .is_none(),
        );
        assert!(
            public_account_visible_balances_for_chain(
                Some(&snapshot),
                1,
                "public-account",
                PublicAccountStatus::Inactive,
            )
            .is_empty(),
        );
    }

    #[test]
    fn public_balance_merge_preserves_other_account_status_group() {
        let active = public_balance_snapshot_for_test(1);
        let mut inactive = public_balance_snapshot_for_test(1);
        inactive.accounts[0].account.public_account_uuid = "inactive-account".to_string();
        inactive.accounts[0].account.status = PublicAccountStatus::Inactive;

        let merged =
            merge_public_balance_snapshot(Some(&active), inactive, PublicAccountStatus::Inactive);

        assert!(merged.accounts.iter().any(|account| {
            account.account.public_account_uuid == "public-account"
                && account.account.status == PublicAccountStatus::Active
        }));
        assert!(merged.accounts.iter().any(|account| {
            account.account.public_account_uuid == "inactive-account"
                && account.account.status == PublicAccountStatus::Inactive
        }));
    }

    #[test]
    fn public_action_native_max_subtracts_estimated_gas_reserve() {
        assert_eq!(
            public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(40_u64)),
            Some(U256::from(60_u64)),
        );
        assert_eq!(
            public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(100_u64)),
            None,
        );
        assert_eq!(
            public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(101_u64)),
            None,
        );
    }

    #[test]
    fn public_action_max_label_notes_native_gas_estimate() {
        let native = PublicBalanceEntry {
            asset: PublicBalanceAsset {
                id: PublicAssetId::Native,
                symbol: "ETH",
                decimals: 18,
            },
            amount: PublicBalanceAmount::Available(U256::from(1_000_000_000_000_000_000_u128)),
        };
        let token = PublicBalanceEntry {
            asset: PublicBalanceAsset {
                id: PublicAssetId::Erc20(Address::from([0x22; 20])),
                symbol: "USDC",
                decimals: 6,
            },
            amount: PublicBalanceAmount::Available(U256::from(1_500_000_u64)),
        };

        assert_eq!(
            public_action_max_label(&native),
            Some("ETH after est. gas".to_string()),
        );
        assert_eq!(
            public_action_max_label(&token),
            Some("1.5 USDC".to_string()),
        );
    }

    #[test]
    fn public_action_progress_steps_use_single_send_step() {
        assert_eq!(
            public_action_progress_steps(PublicActionMode::Send, PublicAssetId::Native),
            vec![PublicActionProgressStep::Send],
        );
    }

    #[test]
    fn public_action_progress_steps_include_wrap_for_native_shield() {
        assert_eq!(
            public_action_progress_steps(PublicActionMode::Shield, PublicAssetId::Native),
            vec![
                PublicActionProgressStep::Wrap,
                PublicActionProgressStep::Approve,
                PublicActionProgressStep::Shield,
            ],
        );
    }

    #[test]
    fn public_action_progress_steps_skip_wrap_for_erc20_shield() {
        assert_eq!(
            public_action_progress_steps(
                PublicActionMode::Shield,
                PublicAssetId::Erc20(Address::from([0xef; 20])),
            ),
            vec![
                PublicActionProgressStep::Approve,
                PublicActionProgressStep::Shield,
            ],
        );
    }

    #[test]
    fn public_action_error_summary_explains_wrap_gas_estimate() {
        assert_eq!(
            public_action_error_summary(
                PublicActionProgressStep::Wrap,
                Some("public-shield-wrap: estimate gas"),
                "ETH",
            ),
            "Could not estimate gas to wrap ETH. Check amount and gas balance.",
        );
    }

    #[test]
    fn public_action_asset_label_uses_native_symbol() {
        assert_eq!(public_action_asset_label(1, PublicAssetId::Native), "ETH");
    }

    #[test]
    fn public_action_error_details_hide_duplicate_summary() {
        let summary = "Could not send publicly.";

        assert_eq!(public_action_error_details(summary, Some(summary)), None);
        assert_eq!(
            public_action_error_details(summary, Some("public-send: estimate gas")),
            Some("public-send: estimate gas".to_string()),
        );
    }

    #[test]
    fn public_action_error_copy_value_includes_context_and_details() {
        assert_eq!(
            public_action_error_copy_value(
                PublicActionProgressStep::Wrap,
                "ETH",
                "Could not estimate gas to wrap ETH.",
                Some("public-shield-wrap: estimate gas: insufficient funds"),
            ),
            "Step: Wrap\nAsset: ETH\nSummary: Could not estimate gas to wrap ETH.\nDetails: public-shield-wrap: estimate gas: insufficient funds",
        );
    }

    #[test]
    fn send_element_ids_are_asset_scoped() {
        let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
        let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

        assert_ne!(
            send_element_id(first, "cancel").as_ref(),
            send_element_id(second, "cancel").as_ref()
        );
        assert_ne!(
            send_element_id(first, "copy-to").as_ref(),
            send_element_id(first, "copy-data").as_ref()
        );
    }

    #[test]
    fn display_rows_reverse_utxo_order() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 3,
            unspent_count: 3,
            spent_count: 0,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "1", false),
                utxo_output("0x2222222222222222222222222222222222222222", "2", false),
                utxo_output("0x3333333333333333333333333333333333333333", "3", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        let amounts: Vec<_> = rows.iter().map(|row| row.amount.as_str()).collect();
        assert_eq!(amounts, ["3", "2", "1"]);
    }

    #[test]
    fn display_rows_include_spent_utxos() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "42", true),
                utxo_output("0x2222222222222222222222222222222222222222", "7", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].amount, "7");
        assert!(!rows[0].is_spent);
        assert_eq!(rows[0].spent_tx_hash, None);
        assert_eq!(rows[1].amount, "42");
        assert!(rows[1].is_spent);
        assert_eq!(
            rows[1].spent_tx_hash.as_deref(),
            Some("0x2222222222222222222222222222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn display_rows_hide_spent_utxos_when_toggle_off() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "42", true),
                utxo_output("0x2222222222222222222222222222222222222222", "7", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "7");
        assert!(!rows[0].is_spent);
    }

    #[test]
    fn display_rows_search_matches_source_tx_hash() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                utxo_output_with_hashes(
                    "0x1111111111111111111111111111111111111111",
                    "42",
                    false,
                    "0xaAaA000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
                utxo_output_with_hashes(
                    "0x2222222222222222222222222222222222222222",
                    "7",
                    false,
                    "0xbbbb000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "aaaa", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "42");
    }

    #[test]
    fn display_rows_search_matches_spent_tx_hash() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output_with_hashes(
                    "0x1111111111111111111111111111111111111111",
                    "42",
                    true,
                    "0x3333000000000000000000000000000000000000000000000000000000000000",
                    Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
                ),
                utxo_output_with_hashes(
                    "0x2222222222222222222222222222222222222222",
                    "7",
                    false,
                    "0x4444000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "dead", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "42");
        assert!(rows[0].is_spent);
    }

    #[test]
    fn display_rows_search_ignores_spent_visibility_toggle() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 0,
            spent_count: 1,
            utxos: vec![utxo_output_with_hashes(
                "0x1111111111111111111111111111111111111111",
                "42",
                true,
                "0x3333000000000000000000000000000000000000000000000000000000000000",
                Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "dead", false);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_spent);
    }

    #[test]
    fn chain_load_uses_default_sync_options() {
        let overrides = super::chain_load_overrides();

        assert_eq!(overrides.init_block_number, None);
        assert_eq!(overrides.sync_to_block, None);
        assert!(overrides.use_indexed_wallet_catch_up);
        assert!(!overrides.rewind_wallet_cache);
    }

    #[test]
    fn repair_cache_block_parses_zero_as_deployment() {
        assert_eq!(parse_repair_cache_block("0"), Ok(None));
        assert_eq!(parse_repair_cache_block(""), Ok(None));
        assert_eq!(parse_repair_cache_block(" 24936249 "), Ok(Some(24936249)));
        assert!(parse_repair_cache_block("nope").is_err());
    }

    #[test]
    fn repair_cache_help_text_only_mentions_hint_when_available() {
        assert!(repair_cache_help_text(true).contains("wallet start block below"));
        assert!(!repair_cache_help_text(false).contains("wallet start block below"));
        assert!(repair_cache_help_text(false).contains("deployment block"));
    }

    #[test]
    fn chain_error_state_preserves_start_block_hint() {
        let state = ChainUtxoState::Error {
            message: Arc::from("sync failed"),
            start_block: Some(24936250),
        };

        assert_eq!(state.start_block(), Some(24936250));
        assert!(!state.renders_table());
    }

    #[test]
    fn loading_summary_uses_sync_stage_and_percent() {
        let commitments =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);
        let indexing = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 150, 300);

        assert_eq!(
            loading_summary(Some(commitments)),
            "Synchronizing commitments · 25%"
        );
        assert_eq!(loading_summary(Some(indexing)), "Indexing UTXOs · 25%");
        assert_eq!(loading_summary(None), "Preparing wallet sync...");
    }

    #[test]
    fn loading_chain_state_keeps_utxo_table_available() {
        let state = ChainUtxoState::Loading { progress: None };

        assert!(state.renders_table());
        assert!(state.is_syncing());
        assert!(!matches!(state, ChainUtxoState::Ready { .. }));
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn progress_detail_clamps_current_block() {
        let progress = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(progress_detail(progress), "Block 300 of 300");
    }
}
