use std::sync::Arc;

use gpui::{
    App, Context, IntoElement, ParentElement, Pixels, SharedString, Styled, Window, div, px, rgb,
};
use gpui_component::table::{Column, TableDelegate, TableState};
use tracing::Level;

use crate::state::LogEntry;
use crate::ui::table_columns::ColumnWidthSync;

/// `TableDelegate` backing the log pane. Columns mirror the v1 fixed-cell
/// layout (time, level, target, message); `message` is given a generous
/// initial width because the `Table` widget uses fixed column widths with a
/// horizontal scroll fallback instead of a flex column.
pub(crate) struct LogsDelegate {
    rows: Arc<[LogEntry]>,
    columns: [Column; 4],
}

impl LogsDelegate {
    pub(crate) fn new() -> Self {
        Self {
            rows: Arc::from(Vec::<LogEntry>::new()),
            columns: [
                Column::new("time", "time").width(px(90.0)).movable(false),
                Column::new("level", "level").width(px(60.0)).movable(false),
                Column::new("target", "target")
                    .width(px(200.0))
                    .movable(false),
                // Initial fallback width only. `ViewerRoot::render` re-sizes
                // the message column on every window-width change via
                // [`set_message_width`] so it fills the remaining space.
                Column::new("message", "message")
                    .width(px(900.0))
                    .movable(false),
            ],
        }
    }

    pub(crate) fn set_rows(&mut self, rows: Vec<LogEntry>) {
        self.rows = Arc::from(rows);
    }

    /// Update the message column's width. Clamped to a small minimum so the
    /// column is never hidden on very narrow windows.
    pub(crate) fn set_message_width(&mut self, width: Pixels) {
        const MIN_MESSAGE_WIDTH: Pixels = px(120.0);
        self.columns[3].width = width.max(MIN_MESSAGE_WIDTH);
    }

    /// Returns the message column's currently-configured width. Used by the
    /// caller to decide whether a `TableState::refresh` is actually needed.
    pub(crate) const fn message_width(&self) -> Pixels {
        self.columns[3].width
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
}

fn format_time(unix_ms: u64) -> String {
    let secs = unix_ms / 1_000;
    let ms = unix_ms % 1_000;
    let hh = (secs / 3_600) % 24;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02}.{ms:03}")
}
