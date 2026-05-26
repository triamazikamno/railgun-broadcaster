use std::path::PathBuf;

use broadcaster_monitor::{EventRx, EventTx, Shared};
use gpui::ObjectFit;
use gpui::{
    App, AppContext, Bounds, Context, Entity, Focusable, IntoElement, ParentElement, Point, Render,
    SharedString, Styled, StyledImage as _, Window, WindowBounds, WindowOptions, div, img,
    prelude::FluentBuilder as _, px, rgb, size,
};
use gpui_component::{
    IconName, Root, Sizable, TitleBar,
    button::ButtonVariants,
    resizable::{resizable_panel, v_resizable},
    tab::{Tab, TabBar},
};
use tokio::runtime::Handle;
use ui::controls::{app_button, app_button_base};
use ui::icons;
use ui::logs::LogStore;
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};

use crate::assets::{HEMATITE_HERO_PATH, HERO_WORDMARK_PATH, LOGO_ICON_PATH, WARM_GLOW_PATH};

use super::actions::register_wallet_shortcut_root;
use super::chain_load::sync_status_bar;
use super::utxo::should_focus_utxo_table;
use super::{
    Activity, ChainUtxoState, HERO_CARD_MAX_WIDTH, HERO_MEDIUM_BREAKPOINT, HERO_STAGE_MAX_WIDTH,
    HERO_WIDE_BREAKPOINT, LOGS_DRAWER_HEIGHT, LOGS_DRAWER_MAX_HEIGHT, LOGS_DRAWER_MIN_HEIGHT,
    SIDEBAR_AUTO_COLLAPSE_WIDTH, VaultState, WalletRoot, WalletStartupRoot, chain_load_overrides,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum WalletTab {
    #[default]
    Private,
    Public,
    Activity,
}

impl WalletTab {
    pub(super) const ALL: [Self; 3] = [Self::Private, Self::Public, Self::Activity];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::Public => "Public",
            Self::Activity => "Activity",
        }
    }

    pub(super) const fn icon_path(self) -> &'static str {
        match self {
            Self::Private => icons::shield_check_icon_path(),
            Self::Public => icons::globe_icon_path(),
            Self::Activity => icons::activity_icon_path(),
        }
    }

    pub(super) const fn shows_utxos(self) -> bool {
        matches!(self, Self::Activity)
    }
}

#[derive(Clone)]
pub(crate) struct WalletAppOptions {
    pub(super) db_path: PathBuf,
}

impl TryFrom<crate::cli::Options> for WalletAppOptions {
    type Error = eyre::Report;

    fn try_from(value: crate::cli::Options) -> Result<Self, Self::Error> {
        Ok(Self {
            db_path: value.db_path.unwrap_or_else(crate::cli::default_db_path),
        })
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
        register_wallet_shortcut_root(window, &root, cx);
        cx.new(|cx| Root::new(root, window, cx))
    }) {
        tracing::error!(%error, "failed to open wallet window");
    }
}

impl WalletRoot {
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

    pub(super) fn focus_public_account_search_if_requested(
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
}

impl Render for WalletRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.apply_public_broadcaster_error_amount_adjustments(window, cx);
        self.ensure_prover_cache_build_monitor(cx);
        self.focus_vault_input_if_requested(window, cx);
        self.focus_utxo_table_if_requested(window, cx);
        self.focus_public_account_search_if_requested(window, cx);

        let root = cx.entity();
        if !matches!(self.vault_state, VaultState::ViewUnlocked) {
            return self.render_locked_vault_screen(root, window);
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
    }
}

fn wallet_titlebar_options() -> gpui::TitlebarOptions {
    let mut options = TitleBar::title_bar_options();
    options.title = Some(SharedString::from("RailOxide"));
    options
}

pub(super) fn render_wallet_window_frame(
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

pub(super) fn render_wallet_hero_screen(window: &Window, card: gpui::AnyElement) -> gpui::Div {
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

impl WalletRoot {
    pub(super) fn render_workspace(&self, root: Entity<Self>, window: &Window) -> impl IntoElement {
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
            Activity::Settings => self.render_settings_view().into_any_element(),
        }
    }

    fn render_settings_view(&self) -> impl IntoElement {
        let content = if let Some(editor) = self.settings_editor.as_ref() {
            div().size_full().child(editor.clone()).into_any_element()
        } else {
            div()
                .p(px(24.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(SharedString::from(
                    self.settings_error.as_ref().map_or_else(
                        || "Settings are unavailable".to_string(),
                        ToString::to_string,
                    ),
                ))
                .into_any_element()
        };
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .bg(rgb(theme::SURFACE))
            .p(px(16.0))
            .child(content)
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
                    .prefix(img(tab.icon_path()).size(px(18.0)).flex_none())
            }))
    }

    fn render_wallet_content(&self, root: &Entity<Self>, window: &Window) -> gpui::AnyElement {
        match self.active_wallet_tab {
            WalletTab::Private => self.render_private_assets_body(root),
            WalletTab::Public => self.render_public_wallet_body(root),
            WalletTab::Activity => self.render_utxo_body(root, window).into_any_element(),
        }
    }

    pub(super) fn render_chain_error_body(&self, root: &Entity<Self>, message: &str) -> gpui::Div {
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
}
