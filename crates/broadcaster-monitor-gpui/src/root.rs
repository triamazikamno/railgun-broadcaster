use std::sync::Arc;
use std::time::Duration;

use broadcaster_monitor::{EventRx, Shared};
use gpui::{
    App, AppContext, Bounds, Context, Entity, IntoElement, ParentElement, Pixels, Point, Render,
    SharedString, Styled, Window, WindowBounds, WindowOptions, div, px, rgb, size,
};
use gpui_component::{
    Root,
    input::{InputEvent, InputState},
    resizable::{ResizableState, h_resizable, resizable_panel},
    table::{Table, TableDelegate, TableEvent, TableState},
};
use ui::table::ColumnWidthSync;

use crate::fees_view::FeesDelegate;
use crate::peers_view::{self, PeersDelegate};

/// Lower bound between UI re-renders when events are arriving.
const UI_REFRESH_THROTTLE: Duration = Duration::from_millis(100);

/// Periodic wakeup that updates relative timestamp cells at a bounded rate.
const UI_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

pub fn open_monitor_window(app: &mut App, shared: Shared, event_rx: EventRx, chain_ids: Vec<u64>) {
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

    if let Err(error) = app.open_window(options, |window, cx| {
        let pane =
            cx.new(|cx| BroadcasterMonitorPane::new(shared, event_rx, chain_ids, window, cx));
        let root = cx.new(|cx| StandaloneMonitorRoot::new(pane, cx));
        cx.new(|cx| Root::new(root, window, cx))
    }) {
        tracing::error!(%error, "failed to open broadcaster monitor window");
    }
}

struct StandaloneMonitorRoot {
    pane: Entity<BroadcasterMonitorPane>,
}

impl StandaloneMonitorRoot {
    const fn new(pane: Entity<BroadcasterMonitorPane>, _cx: &mut Context<'_, Self>) -> Self {
        Self { pane }
    }
}

impl Render for StandaloneMonitorRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        div()
            .relative()
            .size_full()
            .child(self.pane.clone())
            .children(Root::render_notification_layer(window, cx))
    }
}

pub struct BroadcasterMonitorPane {
    shared: Shared,
    top_split: Entity<ResizableState>,
    fees_table: Entity<TableState<FeesDelegate>>,
    peers_table: Entity<TableState<PeersDelegate>>,
    /// Last viewport width seen in `render`; used to avoid refreshing the table on every paint.
    last_viewport_width: Option<Pixels>,
}

impl BroadcasterMonitorPane {
    pub fn new(
        shared: Shared,
        mut event_rx: EventRx,
        chain_ids: Vec<u64>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let top_split = cx.new(|_| ResizableState::default());
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

        Self::subscribe_column_width_sync(cx, &peers_table);

        // The peers table only occupies the right side of `top_split`, so its
        // fill column must track that panel's width rather than the whole window.
        cx.observe(&top_split, |this, _, cx| {
            this.sync_peers_addr_width(None, cx);
        })
        .detach();

        cx.spawn(async move |this, cx| {
            let mut last_rev: u64 = 0;
            loop {
                let tick = cx.background_executor().timer(UI_REFRESH_INTERVAL);
                tokio::select! {
                    evt = event_rx.recv() => {
                        if evt.is_none() {
                            break;
                        }
                        while event_rx.try_recv().is_ok() {}
                    }
                    () = tick => {}
                }

                let notified = this.update(cx, |root, cx| {
                    let state = root.shared.read();
                    let current = state.rev();
                    if current == last_rev {
                        return false;
                    }
                    last_rev = current;
                    let fees = state.fee_rows();
                    let peers = state.peer_rows();
                    drop(state);

                    root.fees_table.update(cx, |s, cx| {
                        s.delegate_mut().set_rows(fees);
                        cx.notify();
                    });
                    root.peers_table.update(cx, |s, cx| {
                        s.delegate_mut().set_rows(peers);
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
            top_split,
            fees_table,
            peers_table,
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
    /// `TableState::refresh` keeps the latest runtime widths as source of truth.
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

impl Render for BroadcasterMonitorPane {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let viewport_width = window.viewport_size().width;
        if self.last_viewport_width != Some(viewport_width) {
            self.last_viewport_width = Some(viewport_width);
            self.sync_peers_addr_width(Some(viewport_width), cx);
        }

        let peer_summary = self.shared.read().peer_summary();

        div()
            .size_full()
            .bg(rgb(0x1e1e2e))
            .text_color(rgb(0xcdd6f4))
            .font_family("Menlo")
            .text_size(px(12.0))
            .child(
                h_resizable("broadcaster-monitor-top")
                    .with_state(&self.top_split)
                    .child(
                        resizable_panel()
                            .size(px(640.0))
                            .child(Table::new(&self.fees_table)),
                    )
                    .child(
                        resizable_panel()
                            .child(peers_view::render_pane(&peer_summary, &self.peers_table)),
                    ),
            )
    }
}
