use alloy::primitives::Address;
use gpui::{
    App, Context, Entity, InteractiveElement, IntoElement, ParentElement, Pixels, SharedString,
    StatefulInteractiveElement, Styled, Window, div, img, px, rgb,
};
use gpui_component::{
    Sizable, Size,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
    popover::Popover,
    scroll::ScrollableElement,
    table::{Column, ColumnSort, TableDelegate, TableState},
    v_flex,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::state::FeeRow;
use crate::ui::clipboard::copy_with_toast;
use crate::ui::tokens::{
    chain_icon_path, chain_name, format_token_amount, lookup_token, short_address,
};

/// A single-select filter: either "All" (no filter) or a specific value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeesFilter<T: Copy + PartialEq> {
    All,
    One(T),
}

/// `TableDelegate` backing the fees pane. Owns the full sorted row snapshot
/// (`all_rows`) plus the post-filter visible subset (`rows`) that
/// `rows_count` / `render_td` see. Header cells for the first three columns
/// are overridden in `render_th` to host per-column filter widgets.
pub(crate) struct FeesDelegate {
    all_rows: Arc<[FeeRow]>,
    rows: Arc<[FeeRow]>,
    columns: [Column; 8],
    /// Static option set for the chain dropdown — resolved once from
    /// `cli::Options::effective_chain_ids()` and never changes at runtime.
    chain_ids: Vec<u64>,
    chain_filter: FeesFilter<u64>,
    /// Lower-cased substring query for the broadcaster filter (empty = no filter).
    broadcaster_query: Arc<str>,
    /// Owned by the delegate so `render_th(col=1)` can render the live `Input`.
    broadcaster_input: Entity<InputState>,
    token_filter: FeesFilter<(u64, Address)>,
    /// Active sort state for the fee column. `Default` preserves the natural
    /// (chain, broadcaster, token) order set by `set_rows`.
    fee_sort: ColumnSort,
}

impl FeesDelegate {
    pub(crate) fn new(chain_ids: Vec<u64>, broadcaster_input: Entity<InputState>) -> Self {
        Self {
            all_rows: Arc::from(Vec::<FeeRow>::new()),
            rows: Arc::from(Vec::<FeeRow>::new()),
            columns: [
                Column::new("chain", "chain").width(px(60.0)).movable(false),
                Column::new("broadcaster", "broadcaster")
                    .width(px(240.0))
                    .movable(false),
                Column::new("token", "token")
                    .width(px(120.0))
                    .movable(false),
                // Sorting is driven by our own cell-wide click handler in
                // `render_th` — not `.sortable()`. The built-in sort icon
                // hitbox was too small (a ~14px square on the right edge);
                // our replacement makes the entire header area clickable.
                Column::new("fee", "fee").width(px(100.0)).movable(false),
                Column::new("sig", "sig").width(px(40.0)).movable(false),
                Column::new("reliability", "rel")
                    .width(px(50.0))
                    .movable(false),
                Column::new("last_seen", "last seen")
                    .width(px(120.0))
                    .movable(false),
                Column::new("expires", "expires in")
                    .width(px(120.0))
                    .movable(false),
            ],
            chain_ids,
            chain_filter: FeesFilter::One(1),
            broadcaster_query: Arc::from(""),
            broadcaster_input,
            token_filter: FeesFilter::All,
            fee_sort: ColumnSort::Default,
        }
    }

    pub(crate) fn set_rows(&mut self, rows: Vec<FeeRow>) {
        let mut sorted = rows;
        sorted.sort_by(|a, b| {
            a.chain_id
                .cmp(&b.chain_id)
                .then_with(|| a.railgun_address.cmp(&b.railgun_address))
                .then_with(|| a.token_address.cmp(&b.token_address))
        });
        self.all_rows = Arc::from(sorted);
        self.rebuild_visible();
    }

    pub(crate) fn set_chain_filter(&mut self, filter: FeesFilter<u64>) {
        self.chain_filter = filter;
        // Cascade: if a chain-scoped token is selected and the chain filter
        // no longer matches, drop the token filter back to All. The
        // broadcaster query is a substring — it self-corrects when rows
        // stop matching, no reset needed.
        self.token_filter = cascade_reset_token(filter, self.token_filter);
        self.rebuild_visible();
    }

    pub(crate) fn set_broadcaster_query(&mut self, query: Arc<str>) {
        self.broadcaster_query = query;
        self.rebuild_visible();
    }

    pub(crate) fn set_token_filter(&mut self, filter: FeesFilter<(u64, Address)>) {
        self.token_filter = filter;
        self.rebuild_visible();
    }

    /// Advance fee sort through Default → Descending → Ascending → Default,
    /// matching the cycle `gpui_component::Table` uses for its built-in
    /// sort icon.
    pub(crate) fn toggle_fee_sort(&mut self) {
        self.fee_sort = match self.fee_sort {
            ColumnSort::Default => ColumnSort::Descending,
            ColumnSort::Descending => ColumnSort::Ascending,
            ColumnSort::Ascending => ColumnSort::Default,
        };
        self.rebuild_visible();
    }

    fn rebuild_visible(&mut self) {
        let chain_filter = self.chain_filter;
        let token_filter = self.token_filter;
        let query = self.broadcaster_query.clone();

        let mut rows: Vec<FeeRow> = self
            .all_rows
            .iter()
            .filter(|row| matches_chain(row, chain_filter))
            .filter(|row| matches_token(row, token_filter))
            .filter(|row| matches_broadcaster(row, &query))
            .cloned()
            .collect();
        // Sort by raw fee amount when requested. Raw comparison is stable
        // within a single (chain, token) group; cross-token ordering is
        // meaningful only in wei — callers comparing human-scale magnitudes
        // across tokens should filter by token first.
        match self.fee_sort {
            ColumnSort::Default => {}
            ColumnSort::Ascending => rows.sort_by_key(|row| row.fee),
            ColumnSort::Descending => rows.sort_by_key(|row| std::cmp::Reverse(row.fee)),
        }
        self.rows = Arc::from(rows);
    }

    /// Unique token options across `all_rows`, scoped by the current chain
    /// filter. Sorted by (`chain_id`, symbol-or-address) for stable menu order.
    fn token_options(&self) -> Vec<(u64, Address)> {
        let mut seen: Vec<(u64, Address)> = Vec::new();
        for row in self.all_rows.iter() {
            if !matches_chain(row, self.chain_filter) {
                continue;
            }
            let key = (row.chain_id, row.token_address);
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        seen.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| token_label(a.0, &a.1).cmp(&token_label(b.0, &b.1)))
        });
        seen
    }
}

const fn matches_chain(row: &FeeRow, filter: FeesFilter<u64>) -> bool {
    match filter {
        FeesFilter::All => true,
        FeesFilter::One(id) => row.chain_id == id,
    }
}

fn matches_token(row: &FeeRow, filter: FeesFilter<(u64, Address)>) -> bool {
    match filter {
        FeesFilter::All => true,
        FeesFilter::One((chain_id, addr)) => row.chain_id == chain_id && row.token_address == addr,
    }
}

fn matches_broadcaster(row: &FeeRow, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let addr_hit = row.railgun_address.to_ascii_lowercase().contains(query);
    let id_hit = row
        .identifier
        .as_deref()
        .is_some_and(|i| i.to_ascii_lowercase().contains(query));
    addr_hit || id_hit
}

/// Downgrade an existing token filter to `All` when a new chain filter
/// rules out its chain. Returns the original filter otherwise.
const fn cascade_reset_token(
    chain: FeesFilter<u64>,
    token: FeesFilter<(u64, Address)>,
) -> FeesFilter<(u64, Address)> {
    match (chain, token) {
        (FeesFilter::One(c), FeesFilter::One((tc, _))) if tc != c => FeesFilter::All,
        _ => token,
    }
}

/// Display label for a chain id in filter UI — falls back to the numeric id
/// for CLI-set chains outside the default broadcaster set.
fn chain_label(chain_id: u64) -> String {
    chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned)
}

/// Display label for a token in filter UI — symbol when known, short-hash fallback.
fn token_label(chain_id: u64, addr: &Address) -> String {
    lookup_token(chain_id, addr).map_or_else(|| short_address(addr), |info| info.symbol.to_owned())
}

/// Token label for the filter menu, optionally prefixed with the chain name.
/// The prefix is added when the chain filter is `All`, so items from different
/// chains (`Ethereum: USDC` vs. `BSC: USDC`) can be told apart. When a single
/// chain is pinned the prefix is redundant and omitted.
fn token_menu_label(chain_id: u64, addr: &Address, show_chain: bool) -> String {
    if show_chain {
        format!("{}: {}", chain_label(chain_id), token_label(chain_id, addr))
    } else {
        token_label(chain_id, addr)
    }
}

fn icon_label_row(chain_id: u64, label: SharedString, icon_size: Pixels) -> impl IntoElement {
    let mut row = div().flex().items_center().gap_1();
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(icon_size).flex_none());
    }
    row.child(label)
}

fn trigger_content(
    chain_id: Option<u64>,
    label: SharedString,
    icon_size: Pixels,
) -> impl IntoElement {
    let mut row = div().w_full().flex().items_center().gap_1().text_left();
    if let Some(chain_id) = chain_id {
        row = row.child(icon_label_row(chain_id, label, icon_size));
    } else {
        row = row.child(label);
    }
    row
}

const FILTER_POPOVER_MAX_HEIGHT: Pixels = px(850.0);

fn filter_popover_max_height(window: &Window) -> Pixels {
    (window.viewport_size().height * 0.7).min(FILTER_POPOVER_MAX_HEIGHT)
}

impl TableDelegate for FeesDelegate {
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
        cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        let table = cx.entity();
        match col_ix {
            0 => render_chain_header(&self.chain_ids, self.chain_filter, table).into_any_element(),
            1 => Input::new(&self.broadcaster_input)
                .with_size(Size::XSmall)
                .into_any_element(),
            2 => {
                let options = self.token_options();
                render_token_header(options, self.chain_filter, self.token_filter, table)
                    .into_any_element()
            }
            3 => render_fee_header(self.fee_sort, table).into_any_element(),
            _ => div()
                .size_full()
                .child(self.columns[col_ix].name.clone())
                .into_any_element(),
        }
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
            0 => {
                if matches!(self.chain_filter, FeesFilter::All) {
                    div()
                        .text_color(rgb(0xcba6f7))
                        .child(icon_label_row(
                            row.chain_id,
                            SharedString::from(""),
                            px(16.0),
                        ))
                        .into_any_element()
                } else {
                    div().into_any_element()
                }
            }
            1 => {
                // 0zk addresses are ASCII base32; byte-slice on the last 4 is safe.
                let addr = row.railgun_address.as_ref();
                let last4 = &addr[addr.len().saturating_sub(4)..];
                let label = match row.identifier.as_deref() {
                    Some(id) if !id.is_empty() => format!("0zk...{last4} ({id})"),
                    _ => format!("0zk...{last4}"),
                };
                let addr = addr.to_string();
                div()
                    .id(SharedString::from(format!(
                        "broadcaster-addr-cell-{row_ix}"
                    )))
                    .cursor_pointer()
                    .text_color(rgb(0xcdd6f4))
                    .child(SharedString::from(label))
                    .on_click(move |_event, window, cx| {
                        copy_with_toast(addr.clone(), window, cx);
                    })
                    .into_any_element()
            }
            2 => {
                let label = lookup_token(row.chain_id, &row.token_address).map_or_else(
                    || short_address(&row.token_address),
                    |info| info.symbol.to_owned(),
                );
                // EIP-55 checksummed form for clipboard — the form downstream
                // tooling expects. Captured by the click closure per row.
                let addr_for_clipboard = row.token_address.to_string();
                div()
                    .id(SharedString::from(format!("token-cell-{row_ix}")))
                    .cursor_pointer()
                    .text_color(rgb(0xcdd6f4))
                    .child(SharedString::from(label))
                    .on_click(move |_event, window, cx| {
                        copy_with_toast(addr_for_clipboard.clone(), window, cx);
                    })
                    .into_any_element()
            }
            3 => {
                let label = lookup_token(row.chain_id, &row.token_address).map_or_else(
                    || row.fee.to_string(),
                    |info| format_token_amount(row.fee, info.decimals),
                );
                div()
                    .text_color(rgb(0xf9e2af))
                    .child(SharedString::from(label))
                    .into_any_element()
            }
            4 => {
                let (label, color) = if row.signature_valid {
                    ("OK", rgb(0xa6e3a1))
                } else {
                    ("BAD", rgb(0xf38ba8))
                };
                div()
                    .text_color(color)
                    .child(SharedString::from(label))
                    .into_any_element()
            }
            5 => {
                let color = if row.reliability >= 0.9 {
                    rgb(0xa6e3a1)
                } else {
                    rgb(0xddbb44)
                };
                div()
                    .text_color(color)
                    .child(SharedString::from(format!("{:.2}", row.reliability)))
                    .into_any_element()
            }
            6 => {
                let age = humantime::Duration::from(Duration::from_secs(
                    SystemTime::now()
                        .duration_since(row.last_seen)
                        .unwrap_or_default()
                        .as_secs(),
                ));
                div()
                    .text_color(rgb(0xa6adc8))
                    .child(SharedString::from(format!("{age} ago")))
                    .into_any_element()
            }
            _ => {
                let now = SystemTime::now();
                if let Ok(d) = row.fee_expiration.duration_since(now) {
                    let expires = humantime::Duration::from(Duration::from_secs(d.as_secs()));
                    div()
                        .text_color(rgb(0xa6adc8))
                        .child(SharedString::from(expires.to_string()))
                        .into_any_element()
                } else {
                    let age = humantime::Duration::from(Duration::from_secs(
                        now.duration_since(row.fee_expiration)
                            .unwrap_or_default()
                            .as_secs(),
                    ));
                    div()
                        .text_color(rgb(0xf38ba8))
                        .child(SharedString::from(format!("expired {age} ago")))
                        .into_any_element()
                }
            }
        }
    }
}

fn render_chain_header(
    chain_ids: &[u64],
    current: FeesFilter<u64>,
    table: Entity<TableState<FeesDelegate>>,
) -> impl IntoElement {
    let (trigger_chain, trigger_label) = match current {
        FeesFilter::All => (None, SharedString::from("All ▼")),
        FeesFilter::One(id) => (Some(id), SharedString::from(" ▼")),
    };
    let ids: Vec<u64> = chain_ids.to_vec();

    Popover::new("fees-chain-filter")
        .trigger(
            Button::new("fees-chain-filter-trigger")
                .ghost()
                .xsmall()
                .justify_start()
                .child(trigger_content(trigger_chain, trigger_label, px(16.0))),
        )
        .content(move |_state, window, cx| {
            let table = table.clone();
            let ids = ids.clone();
            let popover = cx.entity();
            let max_height = filter_popover_max_height(window);
            v_flex()
                .gap_1()
                .min_w(px(160.0))
                .max_h(max_height)
                .overflow_y_scrollbar()
                .child({
                    let table = table.clone();
                    let popover = popover.clone();
                    Button::new("fees-chain-filter-all")
                        .ghost()
                        .xsmall()
                        .w_full()
                        .justify_start()
                        .child(trigger_content(None, SharedString::from("All"), px(16.0)))
                        .on_click(move |_event, window, cx| {
                            table.update(cx, |state, cx| {
                                state.delegate_mut().set_chain_filter(FeesFilter::All);
                                cx.notify();
                            });
                            popover.update(cx, |state, cx| state.dismiss(window, cx));
                        })
                })
                .children(ids.into_iter().map(move |id| {
                    let table = table.clone();
                    let popover = popover.clone();
                    Button::new(SharedString::from(format!("fees-chain-filter-{id}")))
                        .ghost()
                        .xsmall()
                        .w_full()
                        .justify_start()
                        .child(trigger_content(
                            Some(id),
                            SharedString::from(chain_label(id)),
                            px(16.0),
                        ))
                        .on_click(move |_event, window, cx| {
                            table.update(cx, |state, cx| {
                                state.delegate_mut().set_chain_filter(FeesFilter::One(id));
                                cx.notify();
                            });
                            popover.update(cx, |state, cx| state.dismiss(window, cx));
                        })
                }))
        })
}

fn render_token_header(
    options: Vec<(u64, Address)>,
    chain: FeesFilter<u64>,
    current: FeesFilter<(u64, Address)>,
    table: Entity<TableState<FeesDelegate>>,
) -> impl IntoElement {
    // When the chain filter is `All`, a cross-chain menu needs the chain
    // prefix to disambiguate same-symbol tokens (`Ethereum: USDC` vs.
    // `BSC: USDC`). The trigger label uses the same rule so a pinned
    // cross-chain token is self-describing.
    let show_chain = matches!(chain, FeesFilter::All);
    let (trigger_chain, trigger_label) = match current {
        FeesFilter::All => (None, SharedString::from("token: All")),
        FeesFilter::One((chain_id, addr)) => (
            show_chain.then_some(chain_id),
            SharedString::from(format!(
                "token: {}",
                token_menu_label(chain_id, &addr, show_chain)
            )),
        ),
    };

    Popover::new("fees-token-filter")
        .trigger(
            Button::new("fees-token-filter-trigger")
                .ghost()
                .xsmall()
                .justify_start()
                .child(trigger_content(trigger_chain, trigger_label, px(16.0))),
        )
        .content(move |_state, window, cx| {
            let table = table.clone();
            let options = options.clone();
            let popover = cx.entity();
            let max_height = filter_popover_max_height(window);
            v_flex()
                .gap_1()
                .min_w(px(200.0))
                .max_h(max_height)
                .overflow_y_scrollbar()
                .child({
                    let table = table.clone();
                    let popover = popover.clone();
                    Button::new("fees-token-filter-all")
                        .ghost()
                        .xsmall()
                        .w_full()
                        .justify_start()
                        .child(trigger_content(None, SharedString::from("All"), px(16.0)))
                        .on_click(move |_event, window, cx| {
                            table.update(cx, |state, cx| {
                                state.delegate_mut().set_token_filter(FeesFilter::All);
                                cx.notify();
                            });
                            popover.update(cx, |state, cx| state.dismiss(window, cx));
                        })
                })
                .children(options.into_iter().map(move |(chain_id, addr)| {
                    let table = table.clone();
                    let popover = popover.clone();
                    let id = format!("fees-token-filter-{chain_id}-{addr:#x}");
                    Button::new(SharedString::from(id))
                        .ghost()
                        .xsmall()
                        .w_full()
                        .justify_start()
                        .child(trigger_content(
                            show_chain.then_some(chain_id),
                            SharedString::from(token_menu_label(chain_id, &addr, false)),
                            px(16.0),
                        ))
                        .on_click(move |_event, window, cx| {
                            table.update(cx, |state, cx| {
                                state
                                    .delegate_mut()
                                    .set_token_filter(FeesFilter::One((chain_id, addr)));
                                cx.notify();
                            });
                            popover.update(cx, |state, cx| state.dismiss(window, cx));
                        })
                }))
        })
}

fn render_fee_header(
    sort: ColumnSort,
    table: Entity<TableState<FeesDelegate>>,
) -> impl IntoElement {
    // `⇅` when no sort is active (affordance only); up/down triangles
    // otherwise. Using inline text arrows keeps this independent of the
    // lib's built-in sort icon, which has a cell-right-corner hitbox
    // that's ~14px tall and hard to target.
    let arrow = match sort {
        ColumnSort::Default => "⇅",
        ColumnSort::Ascending => "▲",
        ColumnSort::Descending => "▼",
    };
    div()
        .id("fees-fee-header")
        .size_full()
        .cursor_pointer()
        .child(SharedString::from(format!("fee {arrow}")))
        .on_click(move |_event, _window, cx| {
            cx.stop_propagation();
            table.update(cx, |state, cx| {
                state.delegate_mut().toggle_fee_sort();
                cx.notify();
            });
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use ruint::aliases::U256;
    use std::time::SystemTime;

    fn row(chain_id: u64, broadcaster: &str, token: Address, identifier: Option<&str>) -> FeeRow {
        FeeRow {
            chain_id,
            railgun_address: Arc::from(broadcaster),
            token_address: token,
            fee: U256::from(0u64),
            signature_valid: true,
            fees_id: Arc::from("fid"),
            fee_expiration: SystemTime::now(),
            identifier: identifier.map(Arc::from),
            last_seen: SystemTime::now(),
            reliability: 1.0,
        }
    }

    #[test]
    fn chain_filter_one_narrows_rows_to_that_chain() {
        let t = address!("0x0000000000000000000000000000000000000001");
        let r1 = row(1, "0zkaaa", t, None);
        let r137 = row(137, "0zkbbb", t, None);
        assert!(matches_chain(&r1, FeesFilter::One(1)));
        assert!(!matches_chain(&r137, FeesFilter::One(1)));
        assert!(matches_chain(&r1, FeesFilter::All));
        assert!(matches_chain(&r137, FeesFilter::All));
    }

    #[test]
    fn broadcaster_query_matches_identifier_and_address_case_insensitive() {
        let t = address!("0x0000000000000000000000000000000000000001");
        let r = row(1, "0zkABCdef", t, Some("Alice"));
        // Empty query always matches.
        assert!(matches_broadcaster(&r, ""));
        // The caller is expected to pre-lowercase the query (that's what the
        // subscription in root.rs does); predicate does per-row lowercasing.
        assert!(matches_broadcaster(&r, "abcdef"));
        assert!(matches_broadcaster(&r, "ali"));
        assert!(!matches_broadcaster(&r, "zzz"));
        // A broadcaster without an identifier still matches by address.
        let r_no_id = row(1, "0zkABCdef", t, None);
        assert!(matches_broadcaster(&r_no_id, "abcdef"));
        assert!(!matches_broadcaster(&r_no_id, "ali"));
    }

    #[test]
    fn cascade_reset_drops_token_filter_when_chain_changes() {
        let t = address!("0x0000000000000000000000000000000000000001");
        let token_on_chain_1 = FeesFilter::One((1u64, t));

        // Switching to a different chain drops the token filter.
        assert_eq!(
            cascade_reset_token(FeesFilter::One(137), token_on_chain_1),
            FeesFilter::All
        );
        // Staying on the same chain preserves it.
        assert_eq!(
            cascade_reset_token(FeesFilter::One(1), token_on_chain_1),
            token_on_chain_1
        );
        // Removing the chain filter preserves the token filter.
        assert_eq!(
            cascade_reset_token(FeesFilter::All, token_on_chain_1),
            token_on_chain_1
        );
        // When no token filter is set, any chain change is a no-op.
        assert_eq!(
            cascade_reset_token(FeesFilter::One(137), FeesFilter::All),
            FeesFilter::All
        );
    }
}
