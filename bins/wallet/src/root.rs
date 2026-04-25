use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::{Address, U256};
use broadcaster_monitor::{EventRx, Shared};
use gpui::{
    App, AppContext, Bounds, Context, Entity, InteractiveElement, IntoElement, ParentElement,
    Pixels, Point, Render, SharedString, StatefulInteractiveElement, Styled, Window, WindowBounds,
    WindowOptions, div, img, prelude::FluentBuilder as _, px, rgb, size,
};
use gpui_component::{
    Root, Sizable,
    button::{Button, ButtonVariants},
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
use ui::clipboard::copy_with_toast;
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::style::{APP_FONT_FAMILY, APP_TEXT_COLOR, APP_TEXT_SIZE};
use wallet_ops::{HttpContext, ListUtxosOutput, TokenTotal, UtxoOutput, WalletSessionRequest};

const ACTIVITY_RAIL_WIDTH: Pixels = px(48.0);
const LOGS_DRAWER_HEIGHT: Pixels = px(260.0);
const LOGS_DRAWER_MIN_HEIGHT: Pixels = px(160.0);
const LOGS_DRAWER_MAX_HEIGHT: Pixels = px(600.0);
const FILTER_POPOVER_MAX_HEIGHT: Pixels = px(450.0);

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
    Loading,
    Ready {
        snapshot: Arc<ListUtxosOutput>,
        _session: Arc<wallet_ops::WalletSession>,
    },
    Error(Arc<str>),
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
    utxo_table: Entity<TableState<UtxoDelegate>>,
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
        let utxo_table = cx.new(|cx| TableState::new(UtxoDelegate::new(), window, cx));

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
            utxo_table,
            logs_open: false,
            drawer_split: cx.new(|_| ResizableState::default()),
        };
        root.ensure_chain_load(root.selected_chain, cx);
        root
    }

    fn ensure_chain_load(&mut self, chain_id: u64, cx: &mut Context<'_, Self>) {
        if matches!(
            self.chain_states.get(&chain_id),
            Some(ChainUtxoState::Loading | ChainUtxoState::Ready { .. })
        ) {
            return;
        }

        self.chain_states.insert(chain_id, ChainUtxoState::Loading);
        self.sync_utxo_table(cx);

        let request = WalletSessionRequest {
            mnemonic: self.options.mnemonic.to_string(),
            chain_id,
            db_path: self.options.db_path.clone(),
            init_block_number: if chain_id == self.options.initial_chain_id {
                self.options.init_block_number
            } else {
                None
            },
        };
        let rpc_url = if chain_id == self.options.initial_chain_id {
            self.options.rpc_url.clone()
        } else {
            None
        };
        let http = self.http.clone();
        let join = self
            .runtime
            .spawn(async move { wallet_ops::start_wallet_session(request, rpc_url, &http).await });

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
            Some(ChainUtxoState::Ready { snapshot, .. }) => display_rows_from_output(snapshot),
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
        self.ensure_chain_load(chain_id, cx);
        cx.notify();
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

    fn render_workspace(&self, root: Entity<Self>) -> impl IntoElement {
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
                                .child(self.render_active_content(root.clone())),
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
                .child(self.render_active_content(root))
        }
    }

    fn render_active_content(&self, root: Entity<Self>) -> gpui::AnyElement {
        match self.active_activity {
            Activity::Wallet => self.render_wallet_view(root).into_any_element(),
            Activity::Broadcaster => self.monitor.clone().into_any_element(),
        }
    }

    fn render_wallet_view(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .bg(rgb(0x1e1e2e))
            .child(self.render_wallet_header(root))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .p(px(12.0))
                    .child(self.render_utxo_body()),
            )
    }

    fn render_wallet_header(&self, root: Entity<Self>) -> impl IntoElement {
        let summary = match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                let totals = totals_label(self.selected_chain, &snapshot.totals);
                if totals.is_empty() {
                    format!("{} UTXOs", snapshot.utxo_count)
                } else {
                    format!("{} UTXOs · Totals: {totals}", snapshot.utxo_count)
                }
            }
            Some(ChainUtxoState::Loading) => "Synchronizing wallet events...".to_string(),
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

    fn render_utxo_body(&self) -> impl IntoElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Loading) => centered_message("Synchronizing wallet events..."),
            Some(ChainUtxoState::Error(error)) => error_message(error.as_ref()),
            Some(ChainUtxoState::Ready { snapshot, .. }) if snapshot.utxos.is_empty() => {
                centered_message("No UTXOs found")
            }
            Some(ChainUtxoState::Ready { .. }) => div()
                .size_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .child(Table::new(&self.utxo_table)),
            _ => centered_message("Select a chain to load UTXOs"),
        }
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
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
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
                    .child(self.render_workspace(root)),
            )
    }
}

#[derive(Clone)]
struct UtxoDisplayRow {
    chain_id: u64,
    tree: u32,
    position: u64,
    token: String,
    amount: String,
    token_address: String,
}

struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 6],
}

impl UtxoDelegate {
    fn new() -> Self {
        Self {
            rows: Arc::from(Vec::<UtxoDisplayRow>::new()),
            columns: [
                Column::new("chain", "chain")
                    .width(px(120.0))
                    .movable(false),
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
                Column::new("token_address", "token address")
                    .width(px(420.0))
                    .movable(false),
            ],
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

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row_ix];
        match col_ix {
            0 => chain_label_row(row.chain_id).into_any_element(),
            1 => div()
                .text_color(rgb(0xa6adc8))
                .child(SharedString::from(row.tree.to_string()))
                .into_any_element(),
            2 => div()
                .text_color(rgb(0xa6adc8))
                .child(SharedString::from(row.position.to_string()))
                .into_any_element(),
            3 => div()
                .text_color(rgb(0xcdd6f4))
                .child(SharedString::from(row.token.clone()))
                .into_any_element(),
            4 => div()
                .text_color(rgb(0xf9e2af))
                .child(SharedString::from(row.amount.clone()))
                .into_any_element(),
            _ => {
                let address = row.token_address.clone();
                div()
                    .id(SharedString::from(format!("wallet-token-address-{row_ix}")))
                    .cursor_pointer()
                    .text_color(rgb(0x89dceb))
                    .child(SharedString::from(address.clone()))
                    .on_click(move |_event, window, cx| {
                        copy_with_toast(address.clone(), window, cx);
                    })
                    .into_any_element()
            }
        }
    }
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

fn display_rows_from_output(output: &ListUtxosOutput) -> Vec<UtxoDisplayRow> {
    output
        .utxos
        .iter()
        .map(|row| display_row_from_utxo(output.chain_id, row))
        .collect()
}

fn display_row_from_utxo(chain_id: u64, row: &UtxoOutput) -> UtxoDisplayRow {
    let Some(address) = parse_address(&row.token) else {
        return UtxoDisplayRow {
            chain_id,
            tree: row.tree,
            position: row.position,
            token: row.token.clone(),
            amount: row.value.clone(),
            token_address: row.token.clone(),
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
        chain_id,
        tree: row.tree,
        position: row.position,
        token,
        amount,
        token_address: address.to_checksum(None),
    }
}

fn parse_address(raw: &str) -> Option<Address> {
    raw.parse().ok()
}

#[cfg(test)]
mod tests {
    use wallet_ops::{ListUtxosOutput, UtxoOutput};

    use super::{display_rows_from_output, format_total};

    #[test]
    fn display_rows_use_known_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            utxos: vec![UtxoOutput {
                tree: 0,
                position: 7,
                token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
                value: "1234567".to_string(),
            }],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output);
        assert_eq!(rows[0].token, "USDC");
        assert_eq!(rows[0].amount, "1.23");
    }

    #[test]
    fn display_rows_fall_back_for_unknown_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            utxos: vec![UtxoOutput {
                tree: 1,
                position: 2,
                token: "0x1111111111111111111111111111111111111111".to_string(),
                value: "42".to_string(),
            }],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output);
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
}
