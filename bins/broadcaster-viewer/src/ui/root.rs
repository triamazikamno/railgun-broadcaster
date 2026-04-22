use std::sync::Arc;
use std::time::Duration;

use gpui::{
    App, AppContext, Bounds, Context, Entity, IntoElement, ParentElement, Pixels, Point, Render,
    SharedString, Styled, Window, WindowBounds, WindowOptions, div, px, rgb, size,
};
use gpui_component::{
    Root,
    input::{InputEvent, InputState},
    resizable::{ResizableState, h_resizable, resizable_panel, v_resizable},
    table::{Table, TableDelegate, TableEvent, TableState},
};

use crate::state::{EventRx, Shared};
use crate::ui::fees_view::FeesDelegate;
use crate::ui::log_view::LogsDelegate;
use crate::ui::peers_view::{self, PeersDelegate};
use crate::ui::table_columns::ColumnWidthSync;

/// Lower bound between UI re-renders when events are arriving. Events are
/// coalesced inside this window so high-rate producers (logs, peer polls)
/// cannot drive the UI past this rate.
const UI_REFRESH_THROTTLE: Duration = Duration::from_millis(100);

/// Periodic wakeup that checks whether the shared state revision advanced
/// since the last render. If it did not, the tick is a no-op — no `notify()`
/// means no gpui layout / paint / Metal present, so the window sleeps.
const LOG_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) fn open_main_window(
    app: &mut App,
    shared: Shared,
    event_rx: EventRx,
    chain_ids: Vec<u64>,
) {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: Point::default(),
            size: size(px(1_280.0), px(800.0)),
        })),
        titlebar: Some(gpui::TitlebarOptions {
            title: Some(SharedString::from("Broadcaster Viewer")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        ..Default::default()
    };

    // Wrap `ViewerRoot` in `gpui_component::Root` so the window owns a
    // `NotificationList` — that's what lets `Window::push_notification` work
    // from click handlers (the "Copied!" toast on the token column).
    if let Err(error) = app.open_window(options, |window, cx| {
        let viewer = cx.new(|cx| ViewerRoot::new(shared, event_rx, chain_ids, window, cx));
        cx.new(|cx| Root::new(viewer, window, cx))
    }) {
        tracing::error!(%error, "failed to open viewer window");
    }
}

/// Fixed width (px) consumed by the log table's non-message columns plus an
/// allowance for the table's internal border and vertical scrollbar. The
/// message column gets `viewport_width - LOG_MESSAGE_CHROME`.
const LOG_MESSAGE_CHROME: Pixels = px(90.0 + 60.0 + 200.0 + 40.0);

pub(crate) struct ViewerRoot {
    shared: Shared,
    outer_split: Entity<ResizableState>,
    top_split: Entity<ResizableState>,
    fees_table: Entity<TableState<FeesDelegate>>,
    peers_table: Entity<TableState<PeersDelegate>>,
    logs_table: Entity<TableState<LogsDelegate>>,
    /// Last viewport width seen in `render`. Used to avoid calling
    /// `TableState::refresh` on every paint; we only refresh when the window
    /// actually got wider or narrower.
    last_viewport_width: Option<Pixels>,
}

impl ViewerRoot {
    fn new(
        shared: Shared,
        mut event_rx: EventRx,
        chain_ids: Vec<u64>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let outer_split = cx.new(|_| ResizableState::default());
        let top_split = cx.new(|_| ResizableState::default());
        // The broadcaster free-text filter input. Owned by the fees delegate
        // (so `render_th` can render it) AND subscribed to here, so the
        // `InputEvent::Change` stream forwards into the delegate's query
        // state. Mirrors the widths-mirror subscription pattern below.
        let broadcaster_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search broadcaster"));
        let fees_table = cx.new(|cx| {
            TableState::new(
                FeesDelegate::new(chain_ids, broadcaster_input.clone()),
                window,
                cx,
            )
        });
        let peers_table = cx.new(|cx| TableState::new(PeersDelegate::new(), window, cx));
        let logs_table = cx.new(|cx| TableState::new(LogsDelegate::new(), window, cx));

        cx.subscribe(&broadcaster_input, |this, input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                let query: Arc<str> = Arc::from(input.read(cx).value().to_ascii_lowercase());
                this.fees_table.update(cx, |state, cx| {
                    state.delegate_mut().set_broadcaster_query(query);
                    cx.notify();
                });
            }
        })
        .detach();

        Self::subscribe_column_width_sync(cx, &logs_table);
        Self::subscribe_column_width_sync(cx, &peers_table);

        // The peers table only occupies the right side of `top_split`, so its
        // fill column must track that panel's width rather than the whole
        // window. Observing the split catches both outer window resizes and
        // user drags on the top splitter.
        cx.observe(&top_split, |this, _, cx| {
            this.sync_peers_addr_width(None, cx);
        })
        .detach();

        // Two refresh sources, merged:
        //   1. Fee / peer `ViewerEvent`s on the mpsc — these are rare and
        //      directly user-visible; notify immediately (throttled).
        //   2. `LOG_REFRESH_INTERVAL` tick — picks up new log lines and
        //      updates relative "last seen" timestamps without riding the
        //      high-rate log event stream.
        // When idle this future is blocked on the timer / recv and consumes
        // ~0 CPU; the log_sink layer keeps filling the ring independently.
        cx.spawn(async move |this, cx| {
            let mut last_rev: u64 = 0;
            loop {
                let log_tick = cx.background_executor().timer(LOG_REFRESH_INTERVAL);
                tokio::select! {
                    evt = event_rx.recv() => {
                        if evt.is_none() {
                            break;
                        }
                        while event_rx.try_recv().is_ok() {}
                    }
                    () = log_tick => {}
                }
                // Gate `cx.notify()` on an actual state change, AND push the
                // fresh row snapshots into each table delegate so the
                // virtualized `Table` widgets see the latest data on the
                // next paint. Without this gate, idle ticks would trigger
                // full `Window::draw` + `MetalLayer::nextDrawable` cycles
                // for no visible effect.
                let notified = this.update(cx, |root, cx| {
                    let state = root.shared.read();
                    let current = state.rev();
                    if current == last_rev {
                        return false;
                    }
                    last_rev = current;
                    let fees = state.fee_rows();
                    let peers = state.peer_rows();
                    let logs = state.logs();
                    drop(state);

                    root.fees_table.update(cx, |s, cx| {
                        s.delegate_mut().set_rows(fees);
                        cx.notify();
                    });
                    root.peers_table.update(cx, |s, cx| {
                        s.delegate_mut().set_rows(peers);
                        cx.notify();
                    });
                    root.logs_table.update(cx, |s, cx| {
                        s.delegate_mut().set_rows(logs);
                        cx.notify();
                    });
                    cx.notify();
                    true
                });
                match notified {
                    Err(_) => break,
                    Ok(false) => {}
                    Ok(true) => {
                        cx.background_executor().timer(UI_REFRESH_THROTTLE).await;
                    }
                }
            }
        })
        .detach();

        Self {
            shared,
            outer_split,
            top_split,
            fees_table,
            peers_table,
            logs_table,
            last_viewport_width: None,
        }
    }

    fn sync_peers_addr_width(&self, viewport_width: Option<Pixels>, cx: &mut Context<'_, Self>) {
        let top_split = self.top_split.read(cx);
        let Some(current_peers_width) = top_split.sizes().get(1).copied() else {
            return;
        };

        let peers_pane_width = if let Some(viewport_width) = viewport_width {
            let total_width = top_split
                .sizes()
                .iter()
                .copied()
                .fold(px(0.0), |sum, width| sum + width);
            if total_width == px(0.0) {
                current_peers_width
            } else {
                viewport_width * (current_peers_width / total_width)
            }
        } else {
            current_peers_width
        };

        self.peers_table.update(cx, |s, cx| {
            let target = peers_pane_width - s.delegate().addr_chrome();
            if s.delegate().addr_width() != target.max(px(120.0)) {
                s.delegate_mut().set_addr_width(target);
                s.refresh(cx);
            }
        });
    }

    /// Mirror user-dragged column widths back into the delegate so any later
    /// `TableState::refresh` keeps the latest runtime widths as source of
    /// truth.
    fn subscribe_column_width_sync<D>(cx: &mut Context<'_, Self>, table: &Entity<TableState<D>>)
    where
        D: TableDelegate + ColumnWidthSync,
    {
        cx.subscribe(table, |_this, state, event: &TableEvent, cx| {
            if let TableEvent::ColumnWidthsChanged(widths) = event {
                state.update(cx, |s, _| {
                    s.delegate_mut().apply_column_widths(widths);
                });
            }
        })
        .detach();
    }
}

impl Render for ViewerRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        // The log pane spans the full window width (it sits under the
        // `v_resizable`), so viewport width is a direct proxy for the log
        // table's available width. Size the message column to fill whatever
        // remains after the other columns + table chrome. Only refresh when
        // the width actually changed so we don't thrash col_groups on every
        // paint.
        let viewport_width = window.viewport_size().width;
        if self.last_viewport_width != Some(viewport_width) {
            self.last_viewport_width = Some(viewport_width);
            let target = viewport_width - LOG_MESSAGE_CHROME;
            self.logs_table.update(cx, |s, cx| {
                if s.delegate().message_width() != target.max(px(120.0)) {
                    s.delegate_mut().set_message_width(target);
                    s.refresh(cx);
                }
            });
            self.sync_peers_addr_width(Some(viewport_width), cx);
        }

        let peer_summary = self.shared.read().peer_summary();

        // `gpui_component::Root` (our window wrapper) owns the
        // `NotificationList` but does NOT include it in its own render tree.
        // We have to embed it ourselves via `render_notification_layer`,
        // which returns a pre-positioned absolute overlay anchored top-right.
        let notification_layer = Root::render_notification_layer(window, cx);

        div()
            .relative()
            .size_full()
            .bg(rgb(0x1e1e2e))
            .text_color(rgb(0xcdd6f4))
            .font_family("Menlo")
            .text_size(px(12.0))
            .child(
                v_resizable("viewer-outer")
                    .with_state(&self.outer_split)
                    .child(
                        resizable_panel().child(
                            h_resizable("viewer-top")
                                .with_state(&self.top_split)
                                .child(
                                    resizable_panel()
                                        .size(px(640.0))
                                        .child(Table::new(&self.fees_table)),
                                )
                                .child(resizable_panel().child(peers_view::render_pane(
                                    &peer_summary,
                                    &self.peers_table,
                                ))),
                        ),
                    )
                    .child(
                        resizable_panel()
                            .size(px(150.0))
                            .child(Table::new(&self.logs_table)),
                    ),
            )
            .children(notification_layer)
    }
}
