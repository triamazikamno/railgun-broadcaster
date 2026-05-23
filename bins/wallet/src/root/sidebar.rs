use gpui::{
    Entity, InteractiveElement, IntoElement, MouseButton, ParentElement, SharedString,
    StatefulInteractiveElement, Styled, div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Icon, IconName, Sizable,
    button::{Button, ButtonVariants},
    popover::Popover,
    progress::Progress as UiProgress,
    sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
    spinner::Spinner,
};
use ui::theme;
use wallet_ops::ProverCacheBuildProgress;

use crate::assets::{
    LOGO_ICON_PATH, RailgunNetworkStatusIcon, RailgunSidebarIcon, SIDEBAR_WORDMARK_PATH,
};

use super::network::{network_health_color, render_network_status_popover_content};
use super::{SIDEBAR_WIDTH, WalletRoot, WalletTab, rgb_with_alpha, should_focus_utxo_table};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Activity {
    Wallet,
    Broadcaster,
    Settings,
}

#[cfg(test)]
pub(super) const fn sidebar_primary_activity_order() -> [Activity; 3] {
    [Activity::Wallet, Activity::Broadcaster, Activity::Settings]
}

impl WalletRoot {
    pub(super) fn render_sidebar(
        &self,
        root: Entity<Self>,
        collapsed: bool,
        sidebar_is_narrow: bool,
    ) -> impl IntoElement {
        let wallet_root = root.clone();
        let broadcaster_root = root.clone();
        let settings_root = root.clone();
        let logs_root = root.clone();
        let network_root = root.clone();
        let cache_root = root.clone();
        let public_broadcaster_count = self.sidebar_public_broadcaster_count;
        let public_broadcaster_color =
            Self::public_broadcaster_status_color(public_broadcaster_count);

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
                        SidebarMenuItem::new("Broadcasters")
                            .icon(
                                Icon::new(RailgunSidebarIcon::Broadcaster)
                                    .size_4()
                                    .text_color(rgb(public_broadcaster_color)),
                            )
                            .active(self.active_activity == Activity::Broadcaster)
                            .when(public_broadcaster_count > 0, |item| {
                                item.suffix(Self::render_public_broadcaster_count_badge(
                                    public_broadcaster_count,
                                ))
                            })
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
                    )
                    .child(
                        SidebarMenuItem::new("Settings")
                            .icon(Icon::new(IconName::Settings).size_4())
                            .active(self.active_activity == Activity::Settings)
                            .on_click(move |_event, _window, cx| {
                                settings_root.update(cx, |root, cx| {
                                    root.active_activity = Activity::Settings;
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
                    .when_some(
                        self.prover_cache_build_progress.clone(),
                        |this, progress| {
                            this.child(self.render_prover_cache_build_pill(
                                &cache_root,
                                collapsed,
                                progress,
                            ))
                        },
                    )
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

    const fn public_broadcaster_status_color(count: usize) -> u32 {
        if count > 0 {
            theme::SUCCESS
        } else {
            theme::WARNING
        }
    }

    fn render_public_broadcaster_count_badge(count: usize) -> impl IntoElement {
        let color = theme::SUCCESS;
        div()
            .px(px(6.0))
            .py(px(1.0))
            .rounded_full()
            .border_1()
            .border_color(rgb(color))
            .bg(rgb_with_alpha(color, 0.10))
            .text_color(rgb(color))
            .text_size(px(11.0))
            .font_weight(gpui::FontWeight::SEMIBOLD)
            .line_height(gpui::relative(1.0))
            .child(count.to_string())
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

    fn render_prover_cache_build_pill(
        &self,
        root: &Entity<Self>,
        collapsed: bool,
        progress: ProverCacheBuildProgress,
    ) -> impl IntoElement {
        let popover_root = root.clone();
        let content_progress = progress;
        let trigger = Button::new("wallet-prover-cache-build-pill-trigger")
            .text()
            .tab_stop(false)
            .tooltip("Building prover cache")
            .child(Self::render_prover_cache_build_chip(collapsed));

        Popover::new("wallet-prover-cache-build-popover")
            .open(self.prover_cache_build_popover_open)
            .on_open_change(move |open, _window, cx| {
                popover_root.update(cx, |root, cx| {
                    root.set_prover_cache_build_popover_open(*open, cx);
                });
            })
            .trigger(trigger)
            .content(move |_state, _window, _cx| {
                Self::render_prover_cache_build_popover_content(&content_progress)
            })
    }

    fn render_prover_cache_build_chip(collapsed: bool) -> gpui::AnyElement {
        let color = theme::INFO;
        let spinner = Spinner::new()
            .icon(IconName::LoaderCircle)
            .color(rgb(color).into())
            .with_size(px(14.0));

        if collapsed {
            return div()
                .id("wallet-prover-cache-build-pill-collapsed")
                .h(px(32.0))
                .px_2()
                .flex()
                .items_center()
                .justify_center()
                .rounded_lg()
                .border_1()
                .border_color(rgb(color))
                .bg(rgb_with_alpha(color, 0.08))
                .cursor_pointer()
                .hover(|this| this.bg(rgb_with_alpha(color, 0.14)))
                .child(spinner)
                .into_any_element();
        }

        div()
            .id("wallet-prover-cache-build-pill")
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
            .child(spinner)
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_size(px(13.0))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .line_height(gpui::relative(1.0))
                    .text_color(rgb(color))
                    .child("Building prover cache"),
            )
            .into_any_element()
    }

    fn render_prover_cache_build_popover_content(progress: &ProverCacheBuildProgress) -> gpui::Div {
        let percent = progress.percent();
        let variant = progress
            .current_variant
            .as_deref()
            .unwrap_or("Preparing variants");
        let variant_kind = match progress.current_variant_is_poi {
            Some(true) => "POI",
            Some(false) => "Railgun",
            None => "Variant",
        };
        let count_text = if progress.total_variants == 0 {
            "Preparing variant list...".to_string()
        } else {
            format!(
                "{} of {} variants complete",
                progress.completed_variants, progress.total_variants
            )
        };

        div()
            .w(px(320.0))
            .flex()
            .flex_col()
            .gap_3()
            .text_size(px(13.0))
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
                        Spinner::new()
                            .icon(IconName::LoaderCircle)
                            .color(rgb(theme::INFO).into())
                            .with_size(px(16.0)),
                    )
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(rgb(theme::INFO))
                            .child(progress.stage.label()),
                    ),
            )
            .child(
                div()
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
                            .text_color(rgb(theme::INFO))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(format!("{percent}%"))),
                    ),
            )
            .child(
                div()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .line_height(px(18.0))
                    .child(SharedString::from(count_text)),
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
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(variant_kind),
                    )
                    .child(
                        div()
                            .font_family(theme::APP_MONO_FONT_FAMILY)
                            .text_size(px(12.0))
                            .line_height(px(17.0))
                            .text_color(rgb(theme::TEXT))
                            .child(SharedString::from(variant.to_string())),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .text_size(px(12.0))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(SharedString::from(format!(
                        "Succeeded: {}",
                        progress.succeeded_variants
                    )))
                    .child(SharedString::from(format!(
                        "Failed: {}",
                        progress.failed_variants
                    ))),
            )
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
}
