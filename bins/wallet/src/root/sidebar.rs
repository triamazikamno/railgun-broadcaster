use gpui::{
    Entity, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement, Styled,
    div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Icon, IconName, Sizable,
    button::{Button, ButtonVariants},
    popover::Popover,
    sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
};

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
                        SidebarMenuItem::new("Public broadcasters")
                            .icon(Icon::new(RailgunSidebarIcon::Broadcaster).size_4())
                            .active(self.active_activity == Activity::Broadcaster)
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
