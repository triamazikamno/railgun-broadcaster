use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::{Address, U256};
use broadcaster_monitor::{EventRx, Shared};
use gpui::{
    App, AppContext, Bounds, Context, Entity, Focusable, InteractiveElement, IntoElement,
    KeyBinding, MouseButton, ParentElement, Pixels, Point, Render, SharedString,
    StatefulInteractiveElement, Styled, Window, WindowBounds, WindowOptions, div, img,
    prelude::FluentBuilder as _, px, relative, rgb, size,
};
use gpui_component::{
    Disableable, Root, Sizable,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
    popover::Popover,
    resizable::{ResizableState, resizable_panel, v_resizable},
    scroll::ScrollableElement,
    table::{Column, Table, TableDelegate, TableState},
    tooltip::Tooltip,
    v_flex,
};
use railgun_ui::{
    DEFAULT_CHAINS, chain_icon_path, chain_name, format_token_amount, lookup_token, short_address,
};
use reqwest::Url;
use tokio::runtime::Handle;
use tokio::sync::OnceCell;
use ui::clipboard::copy_with_toast;
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::style::{APP_FONT_FAMILY, APP_TEXT_COLOR, APP_TEXT_SIZE};
use wallet_ops::{
    HttpContext, ListUtxosOutput, SyncProgressUpdate, TokenTotal, UtxoOutput,
    WalletChainSessionRequest, WalletSessionStore,
};

const ACTIVITY_RAIL_WIDTH: Pixels = px(48.0);
const LOGS_DRAWER_HEIGHT: Pixels = px(260.0);
const LOGS_DRAWER_MIN_HEIGHT: Pixels = px(160.0);
const LOGS_DRAWER_MAX_HEIGHT: Pixels = px(600.0);
const FILTER_POPOVER_MAX_HEIGHT: Pixels = px(450.0);
const TABLE_KEY_CONTEXT: &str = "Table";

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
    mnemonic: Arc<str>,
    initial_chain_id: u64,
    db_path: PathBuf,
    init_block_number: Option<u64>,
    rpc_url: Option<Url>,
}

impl From<crate::cli::Options> for WalletAppOptions {
    fn from(value: crate::cli::Options) -> Self {
        Self {
            mnemonic: Arc::from(value.mnemonic),
            initial_chain_id: value.chain_id,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
            rpc_url: value.rpc_url,
        }
    }
}

pub(crate) fn open_wallet_window(
    app: &mut App,
    options: WalletAppOptions,
    http: HttpContext,
    runtime: Handle,
    monitor: Shared,
    event_rx: EventRx,
    chain_ids: Vec<u64>,
    logs: LogStore,
) {
    let window_options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: Point::default(),
            size: size(px(1_360.0), px(860.0)),
        })),
        titlebar: Some(gpui::TitlebarOptions {
            title: Some(SharedString::from("Wallet")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        ..Default::default()
    };

    if let Err(error) = app.open_window(window_options, |window, cx| {
        let monitor = cx.new(|cx| {
            broadcaster_monitor_gpui::BroadcasterMonitorPane::new(
                monitor, event_rx, chain_ids, window, cx,
            )
        });
        let logs = cx.new(|cx| LogsPane::new(logs, window, cx));
        let root = cx.new(|cx| WalletRoot::new(options, http, runtime, monitor, logs, window, cx));
        cx.new(|cx| Root::new(root, window, cx))
    }) {
        tracing::error!(%error, "failed to open wallet window");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Activity {
    Wallet,
    Broadcaster,
}

enum ChainUtxoState {
    Idle,
    Loading {
        progress: Option<SyncProgressUpdate>,
    },
    Ready {
        snapshot: Arc<ListUtxosOutput>,
        _session: Arc<wallet_ops::WalletSession>,
    },
    Error(Arc<str>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainLoadSource {
    Initial,
    Selection,
}

#[derive(Clone, Copy)]
enum UtxoNavigation {
    PageUp,
    PageDown,
    Home,
    End,
}

struct ChainLoadOverrides {
    init_block_number: Option<u64>,
    rpc_url: Option<Url>,
}

fn chain_load_overrides(
    options: &WalletAppOptions,
    chain_id: u64,
    source: ChainLoadSource,
) -> ChainLoadOverrides {
    if source == ChainLoadSource::Initial && chain_id == options.initial_chain_id {
        return ChainLoadOverrides {
            init_block_number: options.init_block_number,
            rpc_url: options.rpc_url.clone(),
        };
    }

    ChainLoadOverrides {
        init_block_number: None,
        rpc_url: None,
    }
}

pub(crate) struct WalletRoot {
    options: WalletAppOptions,
    http: HttpContext,
    runtime: Handle,
    monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
    logs: Entity<LogsPane>,
    active_activity: Activity,
    selected_chain: u64,
    chain_ids: Vec<u64>,
    chain_states: BTreeMap<u64, ChainUtxoState>,
    session_store: Arc<OnceCell<Arc<WalletSessionStore>>>,
    tx_search_input: Entity<InputState>,
    tx_search_query: Arc<str>,
    show_spent_utxos: bool,
    utxo_table: Entity<TableState<UtxoDelegate>>,
    focus_utxo_table_on_render: bool,
    logs_open: bool,
    drawer_split: Entity<ResizableState>,
}

impl WalletRoot {
    fn new(
        options: WalletAppOptions,
        http: HttpContext,
        runtime: Handle,
        monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
        logs: Entity<LogsPane>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let chain_ids = DEFAULT_CHAINS.to_vec();
        let mut chain_states = BTreeMap::new();
        for chain_id in &chain_ids {
            chain_states.insert(*chain_id, ChainUtxoState::Idle);
        }
        let tx_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search tx hash"));
        let utxo_table =
            cx.new(|cx| TableState::new(UtxoDelegate::new(tx_search_input.clone()), window, cx));

        let mut root = Self {
            selected_chain: options.initial_chain_id,
            options,
            http,
            runtime,
            monitor,
            logs,
            active_activity: Activity::Wallet,
            chain_ids,
            chain_states,
            session_store: Arc::new(OnceCell::new()),
            tx_search_input: tx_search_input.clone(),
            tx_search_query: Arc::from(""),
            show_spent_utxos: true,
            utxo_table,
            focus_utxo_table_on_render: false,
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
        root.ensure_chain_load(root.selected_chain, ChainLoadSource::Initial, cx);
        root
    }

    fn ensure_chain_load(
        &mut self,
        chain_id: u64,
        source: ChainLoadSource,
        cx: &mut Context<'_, Self>,
    ) {
        if matches!(
            self.chain_states.get(&chain_id),
            Some(ChainUtxoState::Loading { .. } | ChainUtxoState::Ready { .. })
        ) {
            return;
        }

        self.chain_states
            .insert(chain_id, ChainUtxoState::Loading { progress: None });
        self.sync_utxo_table(cx);

        let overrides = chain_load_overrides(&self.options, chain_id, source);
        let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(None);
        let request = WalletChainSessionRequest {
            mnemonic: self.options.mnemonic.to_string(),
            chain_id,
            init_block_number: overrides.init_block_number,
            progress_tx: Some(progress_tx),
        };
        let rpc_url = overrides.rpc_url;
        let db_path = self.options.db_path.clone();
        let http = self.http.clone();
        let session_store = Arc::clone(&self.session_store);
        let join = self.runtime.spawn(async move {
            let store = session_store
                .get_or_try_init(|| {
                    let db_path = db_path.clone();
                    async move { WalletSessionStore::open(db_path).map(Arc::new) }
                })
                .await?
                .clone();
            store.start_wallet_session(request, rpc_url, &http).await
        });

        cx.spawn(async move |this, cx| {
            loop {
                if progress_rx.changed().await.is_err() {
                    break;
                }
                let progress = *progress_rx.borrow();
                let should_continue = this.update(cx, |root, cx| {
                    let Some(ChainUtxoState::Loading { progress: state }) =
                        root.chain_states.get_mut(&chain_id)
                    else {
                        return false;
                    };
                    *state = progress;
                    cx.notify();
                    true
                });
                if !matches!(should_continue, Ok(true)) {
                    break;
                }
            }
        })
        .detach();

        cx.spawn(async move |this, cx| {
            let session = match join.await {
                Ok(Ok(session)) => Arc::new(session),
                Ok(Err(error)) => {
                    let _ = this.update(cx, |root, cx| {
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error(Arc::from(error.to_string())),
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
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error(Arc::from(format!(
                                "wallet UTXO task failed: {error}"
                            ))),
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
            let initial_snapshot = snapshots_rx.borrow().clone();

            let _ = this.update(cx, |root, cx| {
                root.chain_states.insert(
                    chain_id,
                    ChainUtxoState::Ready {
                        snapshot: initial_snapshot,
                        _session: session.clone(),
                    },
                );
                if root.selected_chain == chain_id {
                    root.sync_utxo_table(cx);
                    root.focus_utxo_table_on_render = true;
                }
                cx.notify();
            });

            loop {
                if snapshots_rx.changed().await.is_err() {
                    break;
                }
                let snapshot = snapshots_rx.borrow().clone();
                if this
                    .update(cx, |root, cx| {
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Ready {
                                snapshot,
                                _session: session.clone(),
                            },
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
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

    fn sync_utxo_table(&self, cx: &mut Context<'_, Self>) {
        let rows = match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Ready { snapshot, .. }) => display_rows_from_output(
                snapshot,
                self.tx_search_query.as_ref(),
                self.show_spent_utxos,
            ),
            _ => Vec::new(),
        };
        self.utxo_table.update(cx, |state, cx| {
            state.delegate_mut().set_rows(rows);
            state.refresh(cx);
        });
    }

    fn select_chain(&mut self, chain_id: u64, cx: &mut Context<'_, Self>) {
        if self.selected_chain == chain_id {
            return;
        }
        self.selected_chain = chain_id;
        self.sync_utxo_table(cx);
        if matches!(
            self.chain_states.get(&chain_id),
            Some(ChainUtxoState::Ready { .. })
        ) {
            self.focus_utxo_table_on_render = true;
        }
        self.ensure_chain_load(chain_id, ChainLoadSource::Selection, cx);
        cx.notify();
    }

    fn toggle_spent_visibility(&mut self, cx: &mut Context<'_, Self>) {
        self.show_spent_utxos = !self.show_spent_utxos;
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn focus_utxo_table_if_requested(&mut self, window: &mut Window, cx: &Context<'_, Self>) {
        if !self.focus_utxo_table_on_render || self.active_activity != Activity::Wallet {
            return;
        }
        if !matches!(
            self.chain_states.get(&self.selected_chain),
            Some(ChainUtxoState::Ready { .. })
        ) {
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

    fn render_activity_rail(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .w(ACTIVITY_RAIL_WIDTH)
            .h_full()
            .flex_none()
            .flex()
            .flex_col()
            .items_center()
            .bg(rgb(0x181825))
            .border_r_1()
            .border_color(rgb(0x313244))
            .child(Self::render_activity_button(
                "activity-wallet",
                icons::wallet_icon_path(),
                "Wallet",
                self.active_activity == Activity::Wallet,
                false,
                {
                    let root = root.clone();
                    move |_event, _window, cx| {
                        root.update(cx, |root, cx| {
                            root.active_activity = Activity::Wallet;
                            root.focus_utxo_table_on_render = true;
                            cx.notify();
                        });
                    }
                },
            ))
            .child(Self::render_activity_button(
                "activity-broadcaster",
                icons::robot_icon_path(),
                "Broadcaster monitor",
                self.active_activity == Activity::Broadcaster,
                false,
                {
                    let root = root.clone();
                    move |_event, _window, cx| {
                        root.update(cx, |root, cx| {
                            root.active_activity = Activity::Broadcaster;
                            cx.notify();
                        });
                    }
                },
            ))
            .child(div().flex_1())
            .child(Self::render_activity_button(
                "activity-logs",
                icons::logs_icon_path(),
                if self.logs_open {
                    "Hide logs"
                } else {
                    "Show logs"
                },
                self.logs_open,
                true,
                move |_event, _window, cx| {
                    root.update(cx, |root, cx| {
                        root.logs_open = !root.logs_open;
                        cx.notify();
                    });
                },
            ))
    }

    fn render_activity_button(
        id: &'static str,
        icon: PathBuf,
        tooltip: &'static str,
        active: bool,
        align_bottom: bool,
        on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
    ) -> impl IntoElement {
        div()
            .id(id)
            .when(!align_bottom, |this| this.mt(px(10.0)))
            .when(align_bottom, |this| this.mb(px(10.0)))
            .size(px(36.0))
            .flex()
            .items_center()
            .justify_center()
            .rounded_md()
            .cursor_pointer()
            .when(active, |this| this.bg(rgb(0x3b82f6)))
            .when(!active, |this| {
                this.bg(rgb(0x181825)).hover(|this| this.bg(rgb(0x313244)))
            })
            .tooltip(move |window, cx| Tooltip::new(tooltip).build(window, cx))
            .on_click(on_click)
            .child(img(icon).size(px(18.0)).flex_none())
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
            .bg(rgb(0x1e1e2e))
            .child(self.render_wallet_header(root.clone()))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .p(px(12.0))
                    .child(self.render_utxo_body(root, window)),
            )
    }

    fn render_wallet_header(&self, root: Entity<Self>) -> impl IntoElement {
        let summary = match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                let totals = totals_label(self.selected_chain, &snapshot.totals);
                let counts = if snapshot.spent_count == 0 {
                    format!("{} unspent UTXOs", snapshot.unspent_count)
                } else {
                    format!(
                        "{} unspent · {} spent",
                        snapshot.unspent_count, snapshot.spent_count
                    )
                };
                if totals.is_empty() {
                    counts
                } else {
                    format!("{counts} · Totals: {totals}")
                }
            }
            Some(ChainUtxoState::Loading { progress }) => loading_summary(*progress),
            Some(ChainUtxoState::Error(_)) => "Failed to load UTXOs".to_string(),
            _ => "Ready to load UTXOs".to_string(),
        };

        div()
            .h(px(52.0))
            .flex_none()
            .flex()
            .items_center()
            .gap_3()
            .px(px(14.0))
            .bg(rgb(0x181825))
            .border_b_1()
            .border_color(rgb(0x313244))
            .child(self.render_chain_selector(root))
            .child(
                div()
                    .text_color(rgb(0xcdd6f4))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Wallet UTXOs"),
            )
            .child(
                div()
                    .text_color(rgb(0xa6adc8))
                    .text_size(px(12.0))
                    .child(SharedString::from(summary)),
            )
    }

    fn render_chain_selector(&self, root: Entity<Self>) -> impl IntoElement {
        let selected_chain = self.selected_chain;
        let chain_ids = self.chain_ids.clone();

        Popover::new("wallet-chain-selector")
            .trigger(
                Button::new("wallet-chain-selector-trigger")
                    .ghost()
                    .small()
                    .justify_start()
                    .child(chain_label_row(selected_chain)),
            )
            .content(move |_state, window, cx| {
                let popover = cx.entity();
                let max_height =
                    (window.viewport_size().height * 0.7).min(FILTER_POPOVER_MAX_HEIGHT);
                let root = root.clone();
                v_flex()
                    .gap_1()
                    .min_w(px(180.0))
                    .max_h(max_height)
                    .overflow_y_scrollbar()
                    .children(chain_ids.clone().into_iter().map(move |chain_id| {
                        let root = root.clone();
                        let popover = popover.clone();
                        Button::new(SharedString::from(format!("wallet-chain-{chain_id}")))
                            .ghost()
                            .small()
                            .w_full()
                            .justify_start()
                            .child(chain_label_row(chain_id))
                            .on_click(move |_event, window, cx| {
                                root.update(cx, |root, cx| {
                                    root.select_chain(chain_id, cx);
                                });
                                popover.update(cx, |state, cx| state.dismiss(window, cx));
                            })
                    }))
            })
    }

    fn render_utxo_body(&self, root: &Entity<Self>, window: &Window) -> impl IntoElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Loading { progress }) => loading_progress(*progress),
            Some(ChainUtxoState::Error(error)) => error_message(error.as_ref()),
            Some(ChainUtxoState::Ready { snapshot, .. }) if snapshot.utxo_count == 0 => {
                centered_message("No UTXOs found")
            }
            Some(ChainUtxoState::Ready { .. }) => div()
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
        let search_input = Input::new(&self.tx_search_input)
            .xsmall()
            .px(px(8.0))
            .py(px(13.0))
            .when(search_active, |input| {
                input.suffix(
                    div()
                        .id("wallet-search-clear")
                        .size(px(18.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded_sm()
                        .cursor_pointer()
                        .hover(|this| this.bg(rgb(0x313244)))
                        .tooltip(|window, cx| Tooltip::new("Clear search").build(window, cx))
                        .on_click(move |_event, window, cx| {
                            clear_search_input.update(cx, |input, cx| {
                                input.set_value("", window, cx);
                            });
                            clear_search_table.update(cx, |table, cx| {
                                table.focus_handle(cx).focus(window);
                            });
                        })
                        .child(img(icons::close_icon_path()).size(px(12.0)).flex_none()),
                )
            });
        let spent_toggle_label = if self.show_spent_utxos {
            "Hide spent"
        } else {
            "Show spent"
        };
        let spent_toggle = Button::new("wallet-toggle-spent-utxos")
            .xsmall()
            .outline()
            .p(px(12.0))
            .disabled(search_active)
            .opacity(if search_active { 0.45 } else { 1.0 })
            .child(spent_toggle_label)
            .on_click(move |_event, _window, cx| {
                root.update(cx, |root, cx| {
                    root.toggle_spent_visibility(cx);
                });
            });
        let spent_toggle = if self.show_spent_utxos || search_active {
            spent_toggle.ghost()
        } else {
            spent_toggle.primary()
        };

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
            .bg(rgb(0x1e1e2e))
            .border_t_1()
            .border_color(rgb(0x313244))
            .child(
                div()
                    .h(px(34.0))
                    .flex()
                    .items_center()
                    .px(px(12.0))
                    .bg(rgb(0x181825))
                    .border_b_1()
                    .border_color(rgb(0x313244))
                    .child(img(icons::logs_icon_path()).size(px(16.0)).flex_none())
                    .child(
                        div()
                            .ml(px(8.0))
                            .text_color(rgb(0xcdd6f4))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Logs"),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .id("close-wallet-logs-drawer")
                            .size(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_color(rgb(0xa6adc8))
                            .hover(|this| this.bg(rgb(0x313244)).text_color(rgb(0xcdd6f4)))
                            .tooltip(|window, cx| Tooltip::new("Hide logs").build(window, cx))
                            .on_click(move |_event, _window, cx| {
                                root.update(cx, |root, cx| {
                                    root.logs_open = false;
                                    cx.notify();
                                });
                            })
                            .child(img(icons::close_icon_path()).size(px(14.0)).flex_none()),
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

impl Render for WalletRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.focus_utxo_table_if_requested(window, cx);

        let root = cx.entity();
        div()
            .relative()
            .size_full()
            .flex()
            .bg(rgb(0x1e1e2e))
            .text_color(rgb(APP_TEXT_COLOR))
            .font_family(APP_FONT_FAMILY)
            .text_size(APP_TEXT_SIZE)
            .child(self.render_activity_rail(root.clone()))
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.render_workspace(root, window)),
            )
            .children(Root::render_notification_layer(window, cx))
    }
}

#[derive(Clone)]
struct UtxoDisplayRow {
    tree: u32,
    position: u64,
    token: String,
    amount: String,
    source_tx_hash: String,
    spent_tx_hash: Option<String>,
    token_address: String,
    is_spent: bool,
}

struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 6],
    tx_search_input: Entity<InputState>,
}

impl UtxoDelegate {
    fn new(tx_search_input: Entity<InputState>) -> Self {
        Self {
            rows: Arc::from(Vec::<UtxoDisplayRow>::new()),
            columns: [
                Column::new("tree", "tree").width(px(70.0)).movable(false),
                Column::new("position", "position")
                    .width(px(110.0))
                    .movable(false),
                Column::new("token", "token")
                    .width(px(150.0))
                    .movable(false),
                Column::new("amount", "amount")
                    .width(px(160.0))
                    .movable(false),
                Column::new("source_tx", "source tx")
                    .width(px(170.0))
                    .movable(false),
                Column::new("spent_tx", "spent tx")
                    .width(px(170.0))
                    .movable(false),
            ],
            tx_search_input,
        }
    }

    fn set_rows(&mut self, rows: Vec<UtxoDisplayRow>) {
        self.rows = Arc::from(rows);
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

    fn render_tr(
        &mut self,
        row_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> gpui::Stateful<gpui::Div> {
        let row = div().id(("row", row_ix));
        if self.rows.get(row_ix).is_some_and(|row| row.is_spent) {
            return row.bg(rgb(0x3a1f2a));
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
                .text_color(utxo_cell_text_color(row, rgb(0xa6adc8)))
                .child(SharedString::from(row.tree.to_string()))
                .into_any_element(),
            1 => div()
                .text_color(utxo_cell_text_color(row, rgb(0xa6adc8)))
                .child(SharedString::from(row.position.to_string()))
                .into_any_element(),
            2 => {
                let address = row.token_address.clone();
                div()
                    .id(SharedString::from(format!("wallet-token-cell-{row_ix}")))
                    .cursor_pointer()
                    .text_color(utxo_cell_text_color(row, rgb(0xcdd6f4)))
                    .child(SharedString::from(row.token.clone()))
                    .on_click(move |_event, window, cx| {
                        copy_with_toast(address.clone(), window, cx);
                    })
                    .into_any_element()
            }
            3 => div()
                .text_color(utxo_cell_text_color(row, rgb(0xf9e2af)))
                .child(SharedString::from(row.amount.clone()))
                .into_any_element(),
            4 => tx_hash_cell(
                row,
                row_ix,
                "source",
                &row.source_tx_hash,
                rgb(0x94e2d5),
                self.tx_search_input.clone(),
            ),
            _ => match row.spent_tx_hash.as_deref() {
                Some(tx_hash) => tx_hash_cell(
                    row,
                    row_ix,
                    "spent",
                    tx_hash,
                    rgb(0xf38ba8),
                    self.tx_search_input.clone(),
                ),
                None => div()
                    .text_color(rgb(0x6c7086))
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
    let copy_hash = tx_hash.to_string();
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
                .cursor_pointer()
                .text_color(utxo_cell_text_color(row, color))
                .child(SharedString::from(display_hash))
                .on_click(move |_event, window, cx| {
                    copy_with_toast(copy_hash.clone(), window, cx);
                }),
        )
        .child(
            div()
                .id(SharedString::from(format!(
                    "wallet-{kind}-tx-search-{row_ix}"
                )))
                .size(px(16.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded_sm()
                .cursor_pointer()
                .opacity(0.0)
                .group_hover(group, |this| this.opacity(1.0))
                .hover(|this| this.bg(rgb(0x313244)))
                .tooltip(|window, cx| Tooltip::new("Filter by this transaction").build(window, cx))
                .on_click(move |_event, window, cx| {
                    tx_search_input.update(cx, |input, cx| {
                        input.set_value(search_hash.clone(), window, cx);
                    });
                })
                .child(img(icons::search_icon_path()).size(px(10.0)).flex_none()),
        )
        .into_any_element()
}

fn utxo_cell_text_color(row: &UtxoDisplayRow, color: gpui::Rgba) -> gpui::Rgba {
    if row.is_spent { rgb(0xd8a0ae) } else { color }
}

fn centered_message(message: &'static str) -> gpui::Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(0x6c7086))
        .child(message)
}

fn loading_summary(progress: Option<SyncProgressUpdate>) -> String {
    progress.map_or_else(
        || "Preparing wallet sync...".to_string(),
        |progress| format!("{} · {}%", progress.stage.label(), progress.percent()),
    )
}

fn loading_progress(progress: Option<SyncProgressUpdate>) -> gpui::Div {
    let title = progress.map_or("Preparing wallet sync", |progress| progress.stage.label());
    let percent = progress.map_or(0, SyncProgressUpdate::percent);
    let detail = progress.map_or_else(
        || "Waiting for indexed sync progress...".to_string(),
        progress_detail,
    );
    let fill_width = relative(f32::from(percent) / 100.0);

    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .w(px(460.0))
                .flex()
                .flex_col()
                .gap_3()
                .p(px(18.0))
                .rounded_md()
                .bg(rgb(0x181825))
                .border_1()
                .border_color(rgb(0x313244))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .text_color(rgb(0xcdd6f4))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(title),
                        )
                        .child(div().flex_1())
                        .child(
                            div()
                                .text_color(rgb(0x89dceb))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(SharedString::from(format!("{percent}%"))),
                        ),
                )
                .child(
                    div()
                        .h(px(9.0))
                        .w_full()
                        .rounded_md()
                        .overflow_hidden()
                        .bg(rgb(0x313244))
                        .child(div().h_full().w(fill_width).rounded_md().bg(rgb(0x89dceb))),
                )
                .child(
                    div()
                        .text_color(rgb(0xa6adc8))
                        .text_size(px(12.0))
                        .child(SharedString::from(detail)),
                ),
        )
}

fn progress_detail(progress: SyncProgressUpdate) -> String {
    let current = progress
        .current_block
        .max(progress.start_block)
        .min(progress.target_block);
    format!("Block {current} of {}", progress.target_block)
}

fn error_message(message: &str) -> gpui::Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(0xf38ba8))
        .child(SharedString::from(message.to_owned()))
}

fn chain_label_row(chain_id: u64) -> impl IntoElement {
    let label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned);
    let mut row = div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(0xcdd6f4));
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(px(16.0)).flex_none());
    }
    row.child(SharedString::from(label))
}

fn totals_label(chain_id: u64, totals: &[TokenTotal]) -> String {
    totals
        .iter()
        .map(|total| format_total(chain_id, total))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let Some(address) = parse_address(&total.token) else {
        return format!("{} {}", total.token, total.total);
    };
    let Some(token) = lookup_token(chain_id, &address) else {
        return format!("{} {}", short_address(&address), total.total);
    };
    let amount = U256::from_str_radix(&total.total, 10).map_or_else(
        |_| total.total.clone(),
        |value| format_token_amount(value, token.decimals),
    );
    format!("{} {amount}", token.symbol)
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
            tree: row.tree,
            position: row.position,
            token: row.token.clone(),
            amount: row.value.clone(),
            source_tx_hash: row.source_tx_hash.clone(),
            spent_tx_hash: row.spent_tx_hash.clone(),
            token_address: row.token.clone(),
            is_spent: row.is_spent,
        };
    };

    let (token, amount) = if let Some(token) = lookup_token(chain_id, &address) {
        let amount = U256::from_str_radix(&row.value, 10).map_or_else(
            |_| row.value.clone(),
            |value| format_token_amount(value, token.decimals),
        );
        (token.symbol.to_owned(), amount)
    } else {
        (short_address(&address), row.value.clone())
    };

    UtxoDisplayRow {
        tree: row.tree,
        position: row.position,
        token,
        amount,
        source_tx_hash: row.source_tx_hash.clone(),
        spent_tx_hash: row.spent_tx_hash.clone(),
        token_address: address.to_checksum(None),
        is_spent: row.is_spent,
    }
}

fn short_hash(hash: &str) -> String {
    if hash.len() <= 14 {
        return hash.to_string();
    }
    format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
}

fn parse_address(raw: &str) -> Option<Address> {
    raw.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use wallet_ops::{ListUtxosOutput, SyncProgressStage, SyncProgressUpdate, UtxoOutput};

    use super::{
        ChainLoadSource, WalletAppOptions, chain_load_overrides, display_rows_from_output,
        format_total, loading_summary, progress_detail,
    };

    fn wallet_options_with_overrides() -> WalletAppOptions {
        WalletAppOptions {
            mnemonic: Arc::from("test mnemonic"),
            initial_chain_id: 1,
            db_path: PathBuf::from("db"),
            init_block_number: Some(123),
            rpc_url: Some(reqwest::Url::parse("https://example.invalid/rpc").unwrap()),
        }
    }

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
            source_tx_hash: source_tx_hash.to_string(),
            source_block_number: 11,
            is_spent,
            spent_tx_hash: spent_tx_hash.map(str::to_string),
            spent_block_number: spent_tx_hash.map(|_| 21),
        }
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
        assert!(!rows[0].is_spent);
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
    }

    #[test]
    fn totals_format_known_token_amount() {
        let total = wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
        };

        assert_eq!(format_total(1, &total), "USDC 1.23");
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
    fn initial_chain_load_uses_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 1, ChainLoadSource::Initial);

        assert_eq!(overrides.init_block_number, Some(123));
        assert_eq!(overrides.rpc_url, options.rpc_url);
    }

    #[test]
    fn selected_chain_load_ignores_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 56, ChainLoadSource::Selection);

        assert_eq!(overrides.init_block_number, None);
        assert_eq!(overrides.rpc_url, None);
    }

    #[test]
    fn selected_initial_chain_reload_ignores_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 1, ChainLoadSource::Selection);

        assert_eq!(overrides.init_block_number, None);
        assert_eq!(overrides.rpc_url, None);
    }

    #[test]
    fn loading_summary_uses_sync_stage_and_percent() {
        let progress =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);

        assert_eq!(
            loading_summary(Some(progress)),
            "Synchronizing commitments · 25%"
        );
    }

    #[test]
    fn progress_detail_clamps_current_block() {
        let progress = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(progress_detail(progress), "Block 300 of 300");
    }
}
