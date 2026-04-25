use std::collections::VecDeque;
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpui::{
    App, AppContext, Context, Entity, IntoElement, ParentElement, Pixels, Render, ScrollStrategy,
    SharedString, Styled, Window, canvas, div, px, rgb,
};
use gpui_component::table::{Column, Table, TableDelegate, TableEvent, TableState};
use parking_lot::RwLock;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context as LayerContext, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::table::ColumnWidthSync;

/// Maximum number of retained log lines kept in the bounded in-memory ring.
pub const DEFAULT_LOG_CAPACITY: usize = 100;

const LOG_PANE_REFRESH_INTERVAL: Duration = Duration::from_millis(250);

/// Single retained log line from the app's in-memory tracing layer.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub seq: u64,
    pub unix_ms: u64,
    pub level: Level,
    pub target: Arc<str>,
    pub message: Arc<str>,
}

struct LogState {
    logs: VecDeque<LogEntry>,
    capacity: usize,
    seq: AtomicU64,
    rev: AtomicU64,
}

impl LogState {
    fn new(capacity: usize) -> Self {
        Self {
            logs: VecDeque::with_capacity(capacity),
            capacity,
            seq: AtomicU64::new(0),
            rev: AtomicU64::new(0),
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn push(&mut self, entry: LogEntry) {
        if self.logs.len() == self.capacity {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
        self.rev.fetch_add(1, Ordering::Release);
    }
}

/// Shared app-wide log store suitable for a hidden diagnostics drawer or tab.
#[derive(Clone)]
pub struct LogStore {
    inner: Arc<RwLock<LogState>>,
}

impl LogStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(LogState::new(capacity))),
        }
    }

    #[must_use]
    pub fn rev(&self) -> u64 {
        self.inner.read().rev.load(Ordering::Acquire)
    }

    pub fn push(&self, mut entry: LogEntry) {
        let mut state = self.inner.write();
        entry.seq = state.next_seq();
        state.push(entry);
    }

    #[must_use]
    pub fn logs(&self) -> Vec<LogEntry> {
        self.inner.read().logs.iter().cloned().collect()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.read().capacity
    }
}

/// Bounded in-memory tracing layer that mirrors app logs into [`LogStore`].
pub struct UiLogLayer {
    logs: LogStore,
}

impl UiLogLayer {
    #[must_use]
    pub const fn new(logs: LogStore) -> Self {
        Self { logs }
    }
}

impl<S> Layer<S> for UiLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        self.logs.push(LogEntry {
            seq: 0,
            unix_ms: now_unix_ms(),
            level: *metadata.level(),
            target: Arc::from(metadata.target()),
            message: Arc::from(visitor.into_message()),
        });
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    extras: String,
}

impl MessageVisitor {
    fn into_message(mut self) -> String {
        if !self.extras.is_empty() {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&self.extras);
        }
        self.message
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(&mut self.message, "{value:?}");
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value}", field.name());
        }
    }
}

#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `TableDelegate` backing a generic app log pane.
pub struct LogsDelegate {
    rows: Arc<[LogEntry]>,
    columns: [Column; 4],
}

impl LogsDelegate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: Arc::from(Vec::<LogEntry>::new()),
            columns: [
                Column::new("time", "time").width(px(90.0)).movable(false),
                Column::new("level", "level").width(px(60.0)).movable(false),
                Column::new("target", "target")
                    .width(px(200.0))
                    .movable(false),
                Column::new("message", "message")
                    .width(px(900.0))
                    .movable(false),
            ],
        }
    }

    pub fn set_rows(&mut self, rows: Vec<LogEntry>) {
        self.rows = Arc::from(rows);
    }

    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn set_message_width(&mut self, width: Pixels) {
        const MIN_MESSAGE_WIDTH: Pixels = px(120.0);
        self.columns[3].width = width.max(MIN_MESSAGE_WIDTH);
    }

    #[must_use]
    pub const fn message_width(&self) -> Pixels {
        self.columns[3].width
    }
}

impl Default for LogsDelegate {
    fn default() -> Self {
        Self::new()
    }
}

impl ColumnWidthSync for LogsDelegate {
    fn columns_mut(&mut self) -> &mut [Column] {
        &mut self.columns
    }
}

impl TableDelegate for LogsDelegate {
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
        let entry = &self.rows[row_ix];
        match col_ix {
            0 => div()
                .text_color(rgb(0x6c7086))
                .child(SharedString::from(format_time(entry.unix_ms))),
            1 => {
                let (label, color) = match entry.level {
                    Level::ERROR => ("ERR", rgb(0xf38ba8)),
                    Level::WARN => ("WRN", rgb(0xf9e2af)),
                    Level::INFO => ("INF", rgb(0xa6e3a1)),
                    Level::DEBUG => ("DBG", rgb(0x89dceb)),
                    Level::TRACE => ("TRC", rgb(0xa6adc8)),
                };
                div().text_color(color).child(SharedString::from(label))
            }
            2 => div()
                .text_color(rgb(0xcba6f7))
                .child(SharedString::from(entry.target.as_ref().to_owned())),
            _ => div()
                .text_color(rgb(0xcdd6f4))
                .child(SharedString::from(entry.message.as_ref().to_owned())),
        }
    }

    fn render_empty(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .text_color(rgb(0x6c7086))
            .child("No log entries yet")
    }
}

fn format_time(unix_ms: u64) -> String {
    let secs = unix_ms / 1_000;
    let ms = unix_ms % 1_000;
    let hh = (secs / 3_600) % 24;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02}.{ms:03}")
}

/// Reusable app-wide logs pane. Hosts a table and mirrors [`LogStore`] changes
/// into the delegate without tying logs to any specific feature pane.
pub struct LogsPane {
    logs: LogStore,
    table: Entity<TableState<LogsDelegate>>,
    last_width: Option<Pixels>,
    follow_tail: bool,
}

impl LogsPane {
    pub fn new(logs: LogStore, window: &mut Window, cx: &mut Context<'_, Self>) -> Self {
        let table = cx.new(|cx| {
            let mut delegate = LogsDelegate::new();
            let rows = logs.logs();
            let row_count = rows.len();
            delegate.set_rows(rows);
            let state = TableState::new(delegate, window, cx);
            if row_count > 0 {
                state
                    .vertical_scroll_handle
                    .scroll_to_item(row_count - 1, ScrollStrategy::Bottom);
            }
            state
        });

        cx.subscribe(&table, |_this, state, event: &TableEvent, cx| {
            if let TableEvent::ColumnWidthsChanged(widths) = event {
                state.update(cx, |s, _| {
                    s.delegate_mut().apply_column_widths(widths);
                });
            }
        })
        .detach();

        let refresh_logs = logs.clone();
        cx.spawn(async move |this, cx| {
            let mut last_rev = refresh_logs.rev();
            loop {
                cx.background_executor()
                    .timer(LOG_PANE_REFRESH_INTERVAL)
                    .await;
                let current_rev = refresh_logs.rev();
                if current_rev == last_rev {
                    continue;
                }
                last_rev = current_rev;
                let rows = refresh_logs.logs();
                let row_count = rows.len();

                if this
                    .update(cx, |pane, cx| {
                        let mut follow_tail = pane.follow_tail;
                        pane.table.update(cx, |state, cx| {
                            follow_tail = should_follow_tail(
                                follow_tail,
                                state.delegate().row_count(),
                                state.visible_range().rows(),
                            );
                            state.delegate_mut().set_rows(rows);
                            if follow_tail && row_count > 0 {
                                state
                                    .vertical_scroll_handle
                                    .scroll_to_item(row_count - 1, ScrollStrategy::Bottom);
                            }
                            cx.notify();
                        });
                        pane.follow_tail = follow_tail;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        Self {
            logs,
            table,
            last_width: None,
            follow_tail: true,
        }
    }

    fn sync_table_width(&mut self, width: Pixels, cx: &mut Context<'_, Self>) {
        if self.last_width == Some(width) {
            return;
        }

        self.last_width = Some(width);
        self.table.update(cx, |state, cx| {
            state.delegate_mut().set_message_width(width - px(410.0));
            state.refresh(cx);
        });
    }

    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.logs.logs().len()
    }
}

fn should_follow_tail(
    current_follow_tail: bool,
    old_row_count: usize,
    visible_rows: &Range<usize>,
) -> bool {
    if old_row_count == 0 {
        return true;
    }

    if visible_rows.is_empty() {
        return current_follow_tail;
    }

    visible_rows.end >= old_row_count
}

impl Render for LogsPane {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let entity = cx.entity();

        div()
            .relative()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .child(Table::new(&self.table))
            .child(
                canvas(
                    move |bounds, _, cx| {
                        entity.update(cx, |this, cx| {
                            this.sync_table_width(bounds.size.width, cx);
                        });
                    },
                    |_, (), _, _| {},
                )
                .absolute()
                .size_full(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn default_log_capacity_is_100() {
        assert_eq!(DEFAULT_LOG_CAPACITY, 100);
    }

    #[test]
    fn bounded_retention_drops_oldest() {
        let logs = LogStore::new(4);
        let layer = UiLogLayer::new(logs.clone());
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for i in 0..10 {
                tracing::info!(iter = i, "log-line");
            }
        });
        let entries = logs.logs();
        assert_eq!(entries.len(), 4, "only the newest 4 entries should remain");
        assert!(entries.last().unwrap().message.contains("log-line"));
    }

    #[test]
    fn follow_tail_stays_enabled_at_bottom() {
        assert!(should_follow_tail(true, 100, &(90..100)));
    }

    #[test]
    fn follow_tail_pauses_when_scrolled_up() {
        assert!(!should_follow_tail(true, 100, &(20..60)));
    }

    #[test]
    fn follow_tail_resumes_when_scrolled_back_to_bottom() {
        assert!(should_follow_tail(false, 100, &(80..100)));
    }

    #[test]
    fn follow_tail_preserves_state_without_visible_range() {
        assert!(should_follow_tail(true, 100, &(0..0)));
        assert!(!should_follow_tail(false, 100, &(0..0)));
    }

    #[test]
    fn follow_tail_starts_enabled_for_empty_table() {
        assert!(should_follow_tail(false, 0, &(0..0)));
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let logs = LogStore::new(16);
        let layer = UiLogLayer::new(logs.clone());
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..5 {
                tracing::info!("tick");
            }
        });
        let seqs: Vec<u64> = logs.logs().iter().map(|l| l.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }
}
