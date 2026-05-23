use std::net::IpAddr;
use std::sync::Arc;

use eyre::WrapErr;
use gpui::{
    Context, Entity, InteractiveElement, IntoElement, MouseButton, ParentElement, Styled, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{Disableable, Icon, Sizable, button::ButtonVariants};
use tokio::runtime::Handle;
use tokio::sync::watch;
use ui::controls::{app_button, app_strong_text};
use ui::theme::{self, APP_TEXT_SIZE};
use wallet_ops::{
    HttpContext, WalletNetworkHealth, WalletNetworkHealthState, WalletNetworkMode,
    request_tor_state_reset,
};

use crate::assets::RailgunNetworkStatusIcon;

use super::{
    NETWORK_HEALTH_REFRESH_INTERVAL, TOR_EXIT_IP_QUERY_TIMEOUT, TOR_EXIT_IP_QUERY_URL,
    TOR_HEALTH_RETRY_TIMEOUT, WalletRoot, format_report_chain, rgb_with_alpha,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum TorExitIpQueryState {
    #[default]
    Idle,
    Querying,
    Success(IpAddr),
    Error(Arc<str>),
}

pub(super) const fn network_health_color(health: &WalletNetworkHealth) -> u32 {
    match (health.mode, health.state) {
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Ready) => theme::SUCCESS,
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Reconnecting) => theme::WARNING,
        (WalletNetworkMode::Tor, WalletNetworkHealthState::Degraded) => theme::DANGER,
        (WalletNetworkMode::Proxy, _) => theme::PRIMARY,
        (WalletNetworkMode::Direct, _) => theme::TEXT_MUTED,
    }
}

impl WalletRoot {
    pub(super) fn spawn_network_health_monitor(&self, cx: &Context<'_, Self>) {
        if self.http.network_mode() != WalletNetworkMode::Tor {
            return;
        }

        let http = self.http.clone();
        let runtime = self.runtime.clone();
        let mut shutdown = self.waku_worker_shutdown.subscribe();
        cx.spawn(async move |this, cx| {
            loop {
                tokio::select! {
                    () = cx.background_executor().timer(NETWORK_HEALTH_REFRESH_INTERVAL) => {}
                    should_shutdown = wallet_root_shutdown_requested(&mut shutdown) => {
                        if should_shutdown {
                            break;
                        }
                        continue;
                    }
                }
                let health = http.network_health();
                let Ok(should_retry) = this.update(cx, |root, cx| {
                    let should_retry = health.state != WalletNetworkHealthState::Ready;
                    root.set_network_health(health, cx);
                    should_retry
                }) else {
                    break;
                };

                if should_retry {
                    tokio::select! {
                        () = retry_tor_bootstrap(&http, &runtime) => {}
                        should_shutdown = wallet_root_shutdown_requested(&mut shutdown) => {
                            if should_shutdown {
                                break;
                            }
                            continue;
                        }
                    }
                    let health = http.network_health();
                    if this
                        .update(cx, |root, cx| root.set_network_health(health, cx))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        })
        .detach();
    }

    fn set_network_health(&mut self, health: WalletNetworkHealth, cx: &mut Context<'_, Self>) {
        if self.network_health != health {
            self.network_health = health;
            cx.notify();
        }
    }

    pub(super) fn set_network_status_popover_open(
        &mut self,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        if !open {
            self.network_status_error = None;
            self.tor_exit_ip_query = TorExitIpQueryState::Idle;
            self.tor_state_reset_confirming = false;
        }
        if self.network_status_popover_open != open {
            self.network_status_popover_open = open;
            cx.notify();
        } else if !open {
            cx.notify();
        }
    }

    fn start_new_tor_session(&mut self, cx: &mut Context<'_, Self>) {
        match self.http.start_new_tor_session() {
            Ok(generation) => {
                let waku_refreshed = self.waku.refresh_network_session();
                tracing::info!(
                    tor_session_generation = generation,
                    waku_refreshed,
                    "started new Tor session"
                );
                self.network_status_error = None;
                self.tor_exit_ip_query = TorExitIpQueryState::Idle;
                self.network_health = self.http.network_health();
            }
            Err(error) => {
                tracing::warn!(%error, "failed to start new Tor session");
                self.network_status_error = Some(Arc::from(format_report_chain(&error)));
            }
        }
        cx.notify();
    }

    fn query_tor_exit_ip(&mut self, cx: &mut Context<'_, Self>) {
        if self.http.network_mode() != WalletNetworkMode::Tor
            || matches!(self.tor_exit_ip_query, TorExitIpQueryState::Querying)
        {
            return;
        }

        self.network_status_error = None;
        self.tor_exit_ip_query = TorExitIpQueryState::Querying;
        cx.notify();

        let Some(proxy_url) = self.http.proxy_url.clone() else {
            self.tor_exit_ip_query = TorExitIpQueryState::Error(Arc::from(
                "Exit IP query requires the built-in Tor SOCKS bridge",
            ));
            cx.notify();
            return;
        };
        let query = self
            .runtime
            .spawn(async move { query_exit_ip_through_tor(proxy_url).await });
        cx.spawn(async move |this, cx| {
            let state = match query.await {
                Ok(Ok(ip)) => TorExitIpQueryState::Success(ip),
                Ok(Err(error)) => {
                    TorExitIpQueryState::Error(Arc::from(format_report_chain(&error)))
                }
                Err(error) => TorExitIpQueryState::Error(Arc::from(format!(
                    "Exit IP query task failed: {error}"
                ))),
            };
            let _ = this.update(cx, |root, cx| {
                root.tor_exit_ip_query = state;
                cx.notify();
            });
        })
        .detach();
    }

    fn begin_tor_state_reset_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.network_status_error = None;
        self.tor_exit_ip_query = TorExitIpQueryState::Idle;
        self.tor_state_reset_confirming = true;
        cx.notify();
    }

    fn cancel_tor_state_reset_confirmation(&mut self, cx: &mut Context<'_, Self>) {
        self.tor_state_reset_confirming = false;
        cx.notify();
    }

    fn quit_and_reset_tor_state(&mut self, cx: &mut Context<'_, Self>) {
        match request_tor_state_reset(&self.options.db_path) {
            Ok(marker_path) => {
                tracing::warn!(
                    marker_path = %marker_path.display(),
                    "requested Tor state reset on next wallet startup; quitting wallet"
                );
                cx.quit();
            }
            Err(error) => {
                tracing::warn!(%error, "failed to request Tor state reset");
                self.network_status_error = Some(Arc::from(format_report_chain(&error)));
                self.tor_state_reset_confirming = false;
                cx.notify();
            }
        }
    }
}

pub(super) fn render_network_status_popover_content(
    root: Entity<WalletRoot>,
    health: &WalletNetworkHealth,
    color: u32,
    error: Option<Arc<str>>,
    exit_ip_query: TorExitIpQueryState,
    reset_confirming: bool,
) -> gpui::Div {
    let session_root = root.clone();
    let query_root = root.clone();
    let reset_root = root.clone();
    let cancel_reset_root = root.clone();
    let confirm_reset_root = root;
    let exit_ip_querying = matches!(exit_ip_query, TorExitIpQueryState::Querying);
    div()
        .w(px(300.0))
        .flex()
        .flex_col()
        .gap_3()
        .text_size(APP_TEXT_SIZE)
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
                    Icon::new(RailgunNetworkStatusIcon::Tor)
                        .small()
                        .text_color(rgb(color)),
                )
                .child(
                    app_strong_text(health.label())
                        .text_size(px(14.0))
                        .text_color(rgb(color)),
                ),
        )
        .child(
            div()
                .text_size(px(12.0))
                .line_height(px(18.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .child(health.detail.to_string()),
        )
        .when_some(error, |this, error| {
            this.child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::DANGER))
                    .bg(rgb_with_alpha(theme::DANGER, 0.08))
                    .p(px(10.0))
                    .text_size(px(12.0))
                    .line_height(px(17.0))
                    .text_color(rgb(theme::DANGER))
                    .child(error.to_string()),
            )
        })
        .when(health.mode == WalletNetworkMode::Tor, |this| {
            this.child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::SURFACE))
                    .p(px(10.0))
                    .text_size(px(12.0))
                    .line_height(px(17.0))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(
                        "Future wallet HTTP/RPC requests use the active Tor session. Waku peers reconnect and rediscover using the new Tor session.",
                    ),
            )
            .child(
                app_button("wallet-network-new-tor-session", "New Tor session")
                    .outline()
                    .small()
                    .on_click(move |_event, _window, cx| {
                        cx.stop_propagation();
                        session_root.update(cx, |root, cx| {
                            root.start_new_tor_session(cx);
                        });
                    }),
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
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.0))
                            .line_height(px(17.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(
                                "Contacts https://ifconfig.me/ip through Tor.",
                            ),
                    )
                    .child(
                        app_button(
                            "wallet-network-query-exit-ip",
                            if exit_ip_querying {
                                "Querying..."
                            } else {
                                "Query exit IP"
                            },
                        )
                        .outline()
                        .small()
                        .loading(exit_ip_querying)
                        .disabled(exit_ip_querying)
                        .on_click(move |_event, _window, cx| {
                            cx.stop_propagation();
                            query_root.update(cx, |root, cx| {
                                root.query_tor_exit_ip(cx);
                            });
                        }),
                    )
                    .when(!matches!(exit_ip_query, TorExitIpQueryState::Idle), |this| {
                        this.child(match exit_ip_query {
                            TorExitIpQueryState::Idle => div().into_any_element(),
                            TorExitIpQueryState::Querying => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child("Querying exit IP through Tor...")
                                .into_any_element(),
                            TorExitIpQueryState::Success(ip) => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::SUCCESS))
                                .child(format!("Exit IP: {ip}"))
                                .into_any_element(),
                            TorExitIpQueryState::Error(error) => div()
                                .text_size(px(12.0))
                                .line_height(px(17.0))
                                .text_color(rgb(theme::DANGER))
                                .child(error.to_string())
                                .into_any_element(),
                        })
                    }),
            )
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(if reset_confirming {
                        theme::DANGER
                    } else {
                        theme::BORDER
                    }))
                    .bg(if reset_confirming {
                        rgb_with_alpha(theme::DANGER, 0.08)
                    } else {
                        rgb(theme::SURFACE)
                    })
                    .p(px(10.0))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.0))
                            .line_height(px(17.0))
                            .text_color(rgb(if reset_confirming {
                                theme::DANGER
                            } else {
                                theme::TEXT_MUTED
                            }))
                            .child(if reset_confirming {
                                "Clears Tor cache and guard state only. Wallet data is not deleted. The wallet will quit, and Tor state will be reset on next startup."
                            } else {
                                "If Tor hidden-service connectivity gets stuck, reset only Tor cache and guard state on next startup. Wallet data is not deleted."
                            }),
                    )
                    .when(!reset_confirming, |this| {
                        this.child(
                            app_button("wallet-network-reset-tor-state", "Reset Tor state")
                                .outline()
                                .small()
                                .danger()
                                .on_click(move |_event, _window, cx| {
                                    cx.stop_propagation();
                                    reset_root.update(cx, |root, cx| {
                                        root.begin_tor_state_reset_confirmation(cx);
                                    });
                                }),
                        )
                    })
                    .when(reset_confirming, |this| {
                        this.child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    app_button("wallet-network-cancel-tor-reset", "Cancel")
                                        .outline()
                                        .small()
                                        .on_click(move |_event, _window, cx| {
                                            cx.stop_propagation();
                                            cancel_reset_root.update(cx, |root, cx| {
                                                root.cancel_tor_state_reset_confirmation(cx);
                                            });
                                        }),
                                )
                                .child(
                                    app_button("wallet-network-confirm-tor-reset", "Quit and reset")
                                        .small()
                                        .danger()
                                        .on_click(move |_event, _window, cx| {
                                            cx.stop_propagation();
                                            confirm_reset_root.update(cx, |root, cx| {
                                                root.quit_and_reset_tor_state(cx);
                                            });
                                        }),
                                ),
                        )
                    }),
            )
        })
}

async fn wallet_root_shutdown_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    shutdown.changed().await.is_err() || *shutdown.borrow()
}

pub(super) async fn query_exit_ip_through_tor(proxy_url: reqwest::Url) -> eyre::Result<IpAddr> {
    let proxy = reqwest::Proxy::all(proxy_url.as_str())
        .wrap_err_with(|| format!("invalid Tor proxy URL {proxy_url}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .pool_max_idle_per_host(0)
        .build()
        .wrap_err("build one-shot Tor exit IP query client")?;
    let response = client
        .get(TOR_EXIT_IP_QUERY_URL)
        .timeout(TOR_EXIT_IP_QUERY_TIMEOUT)
        .send()
        .await
        .wrap_err("query Tor exit IP")?
        .error_for_status()
        .wrap_err("ifconfig.me returned an error status")?;
    let body = response
        .text()
        .await
        .wrap_err("read Tor exit IP response")?;
    let value = body.trim();
    value
        .parse::<IpAddr>()
        .wrap_err_with(|| format!("ifconfig.me returned a non-IP response: {value:?}"))
}

pub(super) async fn retry_tor_bootstrap(http: &HttpContext, runtime: &Handle) {
    let Some(arti_client) = http.arti_client() else {
        return;
    };

    let retry = runtime.spawn(async move {
        tokio::time::timeout(TOR_HEALTH_RETRY_TIMEOUT, arti_client.bootstrap()).await
    });
    match retry.await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::debug!(%error, "Tor bootstrap retry failed during health check");
        }
        Ok(Err(_elapsed)) => {
            tracing::debug!(
                timeout_secs = TOR_HEALTH_RETRY_TIMEOUT.as_secs(),
                "Tor bootstrap retry still pending during health check"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "Tor bootstrap retry task failed during health check");
        }
    }
}
