use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use chrono::{DateTime, Local, Utc};
use gpui::{
    App, Context, Entity, Focusable, InteractiveElement, IntoElement, MouseButton, ParentElement,
    Pixels, SharedString, StatefulInteractiveElement, Styled, Window, div, img,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, IconName, Sizable, StyledExt,
    button::ButtonVariants,
    checkbox::Checkbox,
    input::InputState,
    spinner::Spinner,
    table::{Column, Table, TableDelegate, TableState},
    tag::Tag,
    tooltip::Tooltip,
};
use railgun_ui::{format_token_amount, lookup_token, short_address, token_icon_asset_path};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_button_base, app_input, app_muted_text};
use ui::icons;
use ui::theme::{self, APP_MONO_FONT_FAMILY};
use wallet_ops::{ListUtxosOutput, UtxoOutput};

use super::actions::{UtxoEnd, UtxoHome, UtxoPageDown, UtxoPageUp};
use super::chain_load::ChainUtxoState;
use super::shell::WalletTab;
use super::sidebar::Activity;
use super::tokens::parse_address;
use super::{
    SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, SECONDS_PER_MONTH, SECONDS_PER_YEAR,
    WalletRoot, centered_message, rgb_with_alpha, token_label_row,
};

use crate::assets::WalletIconSource;

#[derive(Clone, Copy)]
enum UtxoNavigation {
    PageUp,
    PageDown,
    Home,
    End,
}

impl WalletRoot {
    pub(super) fn sync_utxo_table(&self, cx: &mut Context<'_, Self>) {
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

    fn set_spent_visibility(&mut self, show_spent: bool, cx: &mut Context<'_, Self>) {
        if self.show_spent_utxos == show_spent {
            return;
        }
        self.show_spent_utxos = show_spent;
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn begin_clear_local_pending_spent_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.local_pending_spent_clear_confirming = true;
        cx.notify();
    }

    fn cancel_clear_local_pending_spent_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.local_pending_spent_clear_confirming = false;
        cx.notify();
    }

    fn clear_local_pending_spent_locks(&mut self, cx: &mut Context<'_, Self>) {
        let Some(session) = self.selected_chain_session() else {
            self.local_pending_spent_clear_confirming = false;
            cx.notify();
            return;
        };
        self.local_pending_spent_clear_confirming = false;
        let clear = self
            .runtime
            .spawn(async move { session.clear_local_pending_spent().await });
        cx.spawn(async move |this, cx| {
            let changed = clear.await.unwrap_or(false);
            let _ = this.update(cx, |root, cx| {
                if changed {
                    root.sync_utxo_table(cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn selected_chain_session(&self) -> Option<Arc<wallet_ops::WalletSession>> {
        self.chain_states
            .get(&self.selected_chain)
            .and_then(ChainUtxoState::poi_refresh_session)
    }

    pub(super) fn focus_utxo_table_if_requested(
        &mut self,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
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

    pub(super) fn render_utxo_body(
        &self,
        root: &Entity<Self>,
        window: &Window,
    ) -> impl IntoElement {
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
                .child(self.render_utxo_controls(root))
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

    fn render_utxo_controls(&self, root: &Entity<Self>) -> impl IntoElement {
        let search_active = !self.tx_search_query.is_empty();
        let local_pending_spent_count = self
            .chain_states
            .get(&self.selected_chain)
            .and_then(ChainUtxoState::snapshot)
            .map_or(0, |snapshot| snapshot.local_pending_spent_count);
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
        let spent_toggle_root = root.clone();
        let spent_toggle = Checkbox::new("wallet-toggle-spent-utxos")
            .label("Show spent")
            .checked(self.show_spent_utxos)
            .xsmall()
            .disabled(search_active)
            .opacity(if search_active { 0.45 } else { 1.0 })
            .on_click(move |checked, _window, cx| {
                let checked = *checked;
                spent_toggle_root.update(cx, |root, cx| {
                    root.set_spent_visibility(checked, cx);
                });
            });

        div()
            .flex_none()
            .flex()
            .flex_col()
            .gap_2()
            .when(local_pending_spent_count > 0, |this| {
                this.child(
                    self.render_local_pending_spent_summary(
                        root.clone(),
                        local_pending_spent_count,
                    ),
                )
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_start()
                    .gap_2()
                    .child(div().w(px(280.0)).child(search_input))
                    .child(spent_toggle),
            )
    }

    fn render_local_pending_spent_summary(
        &self,
        root: Entity<Self>,
        count: usize,
    ) -> impl IntoElement {
        let confirming = self.local_pending_spent_clear_confirming;
        let begin_root = root.clone();
        let cancel_root = root.clone();
        let clear_root = root;
        let noun = if count == 1 { "UTXO" } else { "UTXOs" };

        div()
            .w_full()
            .flex()
            .flex_col()
            .gap_2()
            .rounded_md()
            .border_1()
            .border_color(rgb(if confirming {
                theme::DANGER
            } else {
                theme::BORDER
            }))
            .bg(if confirming {
                rgb_with_alpha(theme::DANGER, 0.08)
            } else {
                rgb(theme::SURFACE)
            })
            .p(px(10.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        app_muted_text(format!(
                            "Locally locked pending submission: {count} {noun}"
                        ))
                        .line_height(px(18.0)),
                    )
                    .child(div().flex_1())
                    .when(!confirming, |this| {
                        this.child(
                            app_button("wallet-clear-local-pending-spent", "Clear local locks")
                                .outline()
                                .small()
                                .danger()
                                .on_click(move |_event, _window, cx| {
                                    begin_root.update(cx, |root, cx| {
                                        root.begin_clear_local_pending_spent_confirmation(cx);
                                    });
                                }),
                        )
                    }),
            )
            .when(confirming, |this| {
                this.child(
                    div()
                        .text_size(px(12.0))
                        .line_height(px(17.0))
                        .text_color(rgb(theme::DANGER))
                        .child("This only clears local submitted-transaction locks. If the original transaction later confirms, these UTXOs may fail simulation or become spent again."),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            app_button("wallet-cancel-clear-local-pending-spent", "Cancel")
                                .outline()
                                .small()
                                .on_click(move |_event, _window, cx| {
                                    cancel_root.update(cx, |root, cx| {
                                        root.cancel_clear_local_pending_spent_confirmation(cx);
                                    });
                                }),
                        )
                        .child(
                            app_button(
                                "wallet-confirm-clear-local-pending-spent",
                                "Clear local locks",
                            )
                            .small()
                            .danger()
                            .on_click(move |_event, _window, cx| {
                                clear_root.update(cx, |root, cx| {
                                    root.clear_local_pending_spent_locks(cx);
                                });
                            }),
                        ),
                )
            })
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
}

#[derive(Clone)]
pub(super) struct UtxoDisplayRow {
    pub(super) tree_position: String,
    pub(super) token: String,
    pub(super) token_icon_path: Option<WalletIconSource>,
    pub(super) amount: String,
    pub(super) poi_status: String,
    pub(super) poi_spendable: bool,
    pub(super) source_tx_hash: String,
    pub(super) source_block_timestamp: u64,
    pub(super) spent_tx_hash: Option<String>,
    pub(super) token_address: String,
    pub(super) is_spent: bool,
    pub(super) pending_new: bool,
    pub(super) pending_spent: bool,
    pub(super) local_pending_spent: bool,
}

pub(super) struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 7],
    tx_search_input: Entity<InputState>,
    poi_refresh_session: Option<Arc<wallet_ops::WalletSession>>,
    poi_refreshing: bool,
}

impl UtxoDelegate {
    pub(super) fn new(tx_search_input: Entity<InputState>) -> Self {
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

    pub(super) fn set_rows(&mut self, rows: Vec<UtxoDisplayRow>) {
        self.rows = Arc::from(rows);
    }

    pub(super) fn set_column_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(super) fn set_poi_refresh_state(
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
        if self
            .rows
            .get(row_ix)
            .is_some_and(|row| row.pending_new || row.pending_spent || row.local_pending_spent)
        {
            return row.bg(rgb(theme::WARNING_BG));
        }
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
    } else if row.pending_new || row.pending_spent || row.local_pending_spent {
        rgb(theme::WARNING)
    } else {
        color
    }
}

pub(super) fn should_focus_utxo_table(
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    state: Option<&ChainUtxoState>,
) -> bool {
    active_activity == Activity::Wallet
        && active_wallet_tab.shows_utxos()
        && state.is_some_and(ChainUtxoState::renders_table)
}

pub(super) fn display_rows_from_output(
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
        return show_spent_utxos || !row.is_spent || row.pending_spent || row.local_pending_spent;
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
            pending_new: row.pending_new,
            pending_spent: row.pending_spent,
            local_pending_spent: row.local_pending_spent,
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
            token_icon_asset_path(chain_id, &address).map(WalletIconSource::embedded),
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
        pending_new: row.pending_new,
        pending_spent: row.pending_spent,
        local_pending_spent: row.local_pending_spent,
    }
}

fn format_poi_status(row: &UtxoOutput) -> String {
    if row.pending_spent {
        return "Pending spend".to_string();
    }
    if row.local_pending_spent {
        return "Locally locked".to_string();
    }
    if row.pending_new {
        return "Pending receive".to_string();
    }
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

pub(super) fn format_compact_age(age_secs: u64) -> String {
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

pub(super) fn short_hash(hash: &str) -> String {
    if hash.len() <= 14 {
        return hash.to_string();
    }
    format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
}
