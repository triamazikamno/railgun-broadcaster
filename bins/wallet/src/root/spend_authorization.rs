use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{
    AnyElement, AppContext, Axis, Context, Entity, Focusable, InteractiveElement, IntoElement,
    ParentElement, SharedString, StatefulInteractiveElement, Styled, Window, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Selectable, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    description_list::{DescriptionItem, DescriptionList},
    input::{InputEvent, InputState},
    tooltip::Tooltip,
};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_input, app_muted_text, app_strong_text, app_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY};
use wallet_ops::BlockedShieldRescueUtxoId;
use zeroize::Zeroizing;

use crate::assets::WalletIconSource;

use super::private_action::UnshieldAssetKey;
use super::{WalletRoot, new_masked_input, secondary_dialog_content_width, token_label_row};

const SPEND_AUTHORIZATION_DIALOG_WIDTH: gpui::Pixels = px(560.0);
const SPEND_AUTHORIZATION_SESSION_WARNING: &str = "This will allow on-chain spending from this vault without re-entering the password until you lock the vault or close the app. Only use this on a trusted device.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpendAuthorizationLifetime {
    Once,
    FiveMinutes,
    FifteenMinutes,
    UntilVaultLock,
}

impl SpendAuthorizationLifetime {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Once => "Just this spend",
            Self::FiveMinutes => "5 minutes",
            Self::FifteenMinutes => "15 minutes",
            Self::UntilVaultLock => "Until vault locks/app closes",
        }
    }

    const fn duration(self) -> Option<Duration> {
        match self {
            Self::Once | Self::UntilVaultLock => None,
            Self::FiveMinutes => Some(Duration::from_secs(5 * 60)),
            Self::FifteenMinutes => Some(Duration::from_secs(15 * 60)),
        }
    }
}

pub(super) struct SpendAuthorizationCache {
    password: Zeroizing<String>,
    expires_at: Option<Instant>,
}

impl SpendAuthorizationCache {
    fn new(
        password: Zeroizing<String>,
        lifetime: SpendAuthorizationLifetime,
        now: Instant,
    ) -> Option<Self> {
        match lifetime {
            SpendAuthorizationLifetime::Once => None,
            SpendAuthorizationLifetime::UntilVaultLock => Some(Self {
                password,
                expires_at: None,
            }),
            SpendAuthorizationLifetime::FiveMinutes
            | SpendAuthorizationLifetime::FifteenMinutes => {
                lifetime.duration().map(|duration| Self {
                    password,
                    expires_at: Some(now + duration),
                })
            }
        }
    }

    fn is_valid_at(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpendAuthorizationIntent {
    PrivateSend(UnshieldAssetKey),
    PrivateUnshield(UnshieldAssetKey),
    BlockedShieldRefund(BlockedShieldRescueUtxoId),
    PublicSend,
    PublicShield,
}

#[derive(Clone)]
pub(super) struct SpendAuthorizationSummary {
    title: Arc<str>,
    detail: Arc<str>,
    rows: Vec<SpendAuthorizationSummaryRow>,
}

impl SpendAuthorizationSummary {
    pub(super) fn new(
        title: impl Into<Arc<str>>,
        detail: impl Into<Arc<str>>,
        rows: Vec<SpendAuthorizationSummaryRow>,
    ) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
            rows,
        }
    }
}

#[derive(Clone)]
pub(super) struct SpendAuthorizationSummaryRow {
    label: Arc<str>,
    value: Arc<str>,
    icon_path: Option<WalletIconSource>,
}

impl SpendAuthorizationSummaryRow {
    pub(super) fn new(label: impl Into<Arc<str>>, value: impl Into<Arc<str>>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            icon_path: None,
        }
    }

    pub(super) fn with_icon(mut self, icon_path: Option<WalletIconSource>) -> Self {
        self.icon_path = icon_path;
        self
    }
}

struct SpendAuthorizationDialogContent {
    root: Entity<WalletRoot>,
    intent: SpendAuthorizationIntent,
    summary: SpendAuthorizationSummary,
    password_input: Entity<InputState>,
    lifetime: SpendAuthorizationLifetime,
    error: Option<Arc<str>>,
}

impl SpendAuthorizationDialogContent {
    fn new(
        root: Entity<WalletRoot>,
        intent: SpendAuthorizationIntent,
        summary: SpendAuthorizationSummary,
        initial_lifetime: SpendAuthorizationLifetime,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let password_input = new_masked_input(window, cx, "vault password");
        cx.subscribe_in(
            &password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| match event {
                InputEvent::PressEnter { .. } => this.submit(window, cx),
                InputEvent::Change => {
                    this.error = None;
                    cx.notify();
                }
                _ => {}
            },
        )
        .detach();
        Self {
            root,
            intent,
            summary,
            password_input,
            lifetime: initial_lifetime,
            error: None,
        }
    }

    fn focus_password(&self, window: &mut Window, cx: &Context<'_, Self>) {
        self.password_input.read(cx).focus_handle(cx).focus(window);
    }

    fn submit(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let password = Zeroizing::new(self.password_input.read(cx).value().to_string());
        self.password_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        if password.trim().is_empty() {
            self.error = Some(Arc::from(
                "Enter the vault password to authorize this spend",
            ));
            cx.notify();
            return;
        }

        let intent = self.intent;
        let lifetime = self.lifetime;
        let root = self.root.clone();
        root.update(cx, |root, cx| {
            root.finish_spend_authorization(intent, password, lifetime, window, cx);
        });
    }

    fn set_lifetime(&mut self, lifetime: SpendAuthorizationLifetime, cx: &mut Context<'_, Self>) {
        if self.lifetime != lifetime {
            self.lifetime = lifetime;
            cx.notify();
        }
    }
}

impl gpui::Render for SpendAuthorizationDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let dialog = cx.entity();
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(app_strong_text(self.summary.title.to_string()))
            .child(app_muted_text(self.summary.detail.to_string()).whitespace_normal())
            .child(render_spend_authorization_summary(&self.summary))
            .child(app_input(&self.password_input))
            .child(app_muted_text("Remember authorization"))
            .child(render_spend_authorization_lifetime_buttons(
                dialog.clone(),
                self.lifetime,
            ))
            .when(
                self.lifetime == SpendAuthorizationLifetime::UntilVaultLock,
                |this| {
                    this.child(
                        Alert::warning(
                            "wallet-spend-auth-session-warning",
                            SPEND_AUTHORIZATION_SESSION_WARNING,
                        )
                        .small(),
                    )
                },
            )
            .when_some(self.error.as_ref(), |this, error| {
                this.child(app_muted_text(error.to_string()).text_color(rgb(theme::DANGER)))
            })
            .child(
                div()
                    .w_full()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .child(
                        app_button("wallet-spend-auth-cancel", "Cancel")
                            .flex_none()
                            .on_click(move |_event, window, cx| {
                                window.close_dialog(cx);
                            }),
                    )
                    .child(
                        app_button("wallet-spend-auth-submit", "Authorize and continue")
                            .primary()
                            .flex_none()
                            .on_click(move |_event, window, cx| {
                                dialog.update(cx, |dialog, cx| dialog.submit(window, cx));
                            }),
                    ),
            )
    }
}

fn render_spend_authorization_summary(summary: &SpendAuthorizationSummary) -> DescriptionList {
    DescriptionList::vertical()
        .large()
        .bordered(false)
        .columns(1)
        .children(summary.rows.iter().map(spend_authorization_summary_item))
}

fn spend_authorization_summary_item(row: &SpendAuthorizationSummaryRow) -> DescriptionItem {
    DescriptionItem::new(row.label.to_string()).value(spend_authorization_summary_value(row))
}

fn spend_authorization_summary_value(row: &SpendAuthorizationSummaryRow) -> AnyElement {
    if let Some(icon_path) = row.icon_path.clone() {
        return token_label_row(
            SharedString::from(row.value.to_string()),
            Some(icon_path),
            px(20.0),
        )
        .w_full()
        .min_w(px(0.0))
        .py(px(2.0))
        .text_color(rgb(theme::TEXT))
        .into_any_element();
    }

    if row.label.as_ref() == "Recipient" {
        let copyable = row.value.as_ref() != "Selected private wallet";
        return div()
            .w_full()
            .flex()
            .items_start()
            .gap_2()
            .py(px(2.0))
            .child(
                app_text(row.value.to_string())
                    .flex_1()
                    .min_w(px(0.0))
                    .line_height(px(17.0))
                    .text_color(rgb(theme::TEXT))
                    .font_family(APP_MONO_FONT_FAMILY)
                    .whitespace_normal(),
            )
            .when(copyable, |this| {
                this.child(
                    div()
                        .id("wallet-spend-auth-recipient-copy-action")
                        .flex_none()
                        .tooltip(|window, cx| Tooltip::new("Copy recipient").build(window, cx))
                        .child(clipboard_with_toast(
                            "wallet-spend-auth-recipient-copy",
                            row.value.to_string(),
                        )),
                )
            })
            .into_any_element();
    }

    app_text(row.value.to_string())
        .w_full()
        .min_w(px(0.0))
        .py(px(2.0))
        .text_color(rgb(theme::TEXT))
        .whitespace_normal()
        .into_any_element()
}

fn render_spend_authorization_lifetime_buttons(
    dialog: Entity<SpendAuthorizationDialogContent>,
    selected: SpendAuthorizationLifetime,
) -> ButtonGroup {
    ButtonGroup::new("wallet-spend-auth-lifetime")
        .w_full()
        .outline()
        .warning()
        .small()
        .layout(Axis::Vertical)
        .child(spend_authorization_lifetime_button(
            SpendAuthorizationLifetime::Once,
            selected,
            "wallet-spend-auth-once",
        ))
        .child(spend_authorization_lifetime_button(
            SpendAuthorizationLifetime::FiveMinutes,
            selected,
            "wallet-spend-auth-five-minutes",
        ))
        .child(spend_authorization_lifetime_button(
            SpendAuthorizationLifetime::FifteenMinutes,
            selected,
            "wallet-spend-auth-fifteen-minutes",
        ))
        .child(spend_authorization_lifetime_button(
            SpendAuthorizationLifetime::UntilVaultLock,
            selected,
            "wallet-spend-auth-until-lock",
        ))
        .on_click(move |selected, _window, cx| {
            let Some(index) = selected.first() else {
                return;
            };
            let lifetime = match *index {
                0 => SpendAuthorizationLifetime::Once,
                1 => SpendAuthorizationLifetime::FiveMinutes,
                2 => SpendAuthorizationLifetime::FifteenMinutes,
                3 => SpendAuthorizationLifetime::UntilVaultLock,
                _ => return,
            };
            dialog.update(cx, |dialog, cx| dialog.set_lifetime(lifetime, cx));
        })
}

fn spend_authorization_lifetime_button(
    lifetime: SpendAuthorizationLifetime,
    selected: SpendAuthorizationLifetime,
    id: &'static str,
) -> Button {
    app_button(id, lifetime.label())
        .selected(lifetime == selected)
        .w_full()
}

impl WalletRoot {
    pub(super) fn request_spend_authorization(
        &mut self,
        intent: SpendAuthorizationIntent,
        summary: SpendAuthorizationSummary,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(password) = self.valid_spend_authorization_password(cx) {
            self.continue_authorized_spend(intent, password, window, cx);
            return;
        }

        self.open_spend_authorization_dialog(intent, summary, window, cx);
    }

    fn open_spend_authorization_dialog(
        &self,
        intent: SpendAuthorizationIntent,
        summary: SpendAuthorizationSummary,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        let initial_lifetime = self.spend_authorization_lifetime;
        let content = cx.new(|cx| {
            SpendAuthorizationDialogContent::new(
                root,
                intent,
                summary,
                initial_lifetime,
                window,
                cx,
            )
        });
        let focus_content = content.clone();
        let dialog_width =
            (window.viewport_size().width * 0.92).min(SPEND_AUTHORIZATION_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Authorize spend"))
                .child(div().w(content_width).child(content.clone()))
        });
        cx.defer_in(window, move |_root, window, cx| {
            focus_content.update(cx, |content, cx| content.focus_password(window, cx));
        });
    }

    fn valid_spend_authorization_password(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        let now = Instant::now();
        if self
            .spend_authorization_cache
            .as_ref()
            .is_some_and(|authorization| authorization.is_valid_at(now))
        {
            return self
                .spend_authorization_cache
                .as_ref()
                .map(|authorization| authorization.password.clone());
        }
        if self.spend_authorization_cache.take().is_some() {
            cx.notify();
        }
        None
    }

    pub(super) fn finish_spend_authorization(
        &mut self,
        intent: SpendAuthorizationIntent,
        password: Zeroizing<String>,
        lifetime: SpendAuthorizationLifetime,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.spend_authorization_lifetime = lifetime;
        self.spend_authorization_cache =
            SpendAuthorizationCache::new(password.clone(), lifetime, Instant::now());
        window.close_dialog(cx);
        self.continue_authorized_spend(intent, password, window, cx);
    }

    pub(super) fn clear_spend_authorization(&mut self, cx: &mut Context<'_, Self>) {
        if self.spend_authorization_cache.take().is_some() {
            cx.notify();
        }
    }

    fn continue_authorized_spend(
        &mut self,
        intent: SpendAuthorizationIntent,
        password: Zeroizing<String>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        match intent {
            SpendAuthorizationIntent::PrivateSend(key) => {
                self.generate_send_calldata_authorized(key, password, window, cx);
            }
            SpendAuthorizationIntent::PrivateUnshield(key) => {
                self.generate_unshield_calldata_authorized(key, password, window, cx);
            }
            SpendAuthorizationIntent::BlockedShieldRefund(utxo_id) => {
                self.submit_blocked_shield_refund_authorized(utxo_id, password, window, cx);
            }
            SpendAuthorizationIntent::PublicSend => {
                self.submit_public_send_authorized(password, window, cx);
            }
            SpendAuthorizationIntent::PublicShield => {
                self.submit_public_shield_authorized(password, window, cx);
            }
        }
    }
}

pub(super) fn is_spend_authorization_failure_error(error: &str) -> bool {
    error.contains("authorize ") && error.ends_with("unlock failed")
}

#[cfg(test)]
pub(super) fn remembered_spend_authorization_valid_for_test(
    lifetime: SpendAuthorizationLifetime,
    elapsed: Duration,
) -> bool {
    let now = Instant::now();
    let Some(cache) =
        SpendAuthorizationCache::new(Zeroizing::new("password".to_string()), lifetime, now)
    else {
        return false;
    };
    cache.is_valid_at(now + elapsed)
}
