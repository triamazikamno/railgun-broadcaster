use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{
    AnyElement, AppContext, Axis, Context, Entity, Focusable, InteractiveElement, IntoElement,
    ParentElement, SharedString, StatefulInteractiveElement, Styled, Window, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Selectable, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    description_list::{DescriptionItem, DescriptionList},
    dialog::DialogButtonProps,
    input::{InputEvent, InputState},
    spinner::Spinner,
    tooltip::Tooltip,
};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_input, app_muted_text, app_strong_text, app_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY};
use wallet_ops::hardware::{HardwareDerivationDescriptor, HardwareDeviceKind};
#[cfg(feature = "hardware")]
use wallet_ops::hardware::{
    HardwareDerivationError,
    ledger::LedgerHardwareDerivationClient,
    synthetic_entropy_from_hardware_output,
    trezor::{TrezorHardwareDerivationClient, TrezorPinMatrixProvider},
};
#[cfg(feature = "hardware")]
use wallet_ops::vault::{
    DesktopVaultStore, DesktopViewSession, HardwareProfileSession, VaultError,
};
use wallet_ops::{BlockedShieldRescueUtxoId, DesktopPrivateSpendAuthorization};
use zeroize::Zeroizing;

use crate::assets::WalletIconSource;

use super::private_action::UnshieldAssetKey;
use super::{
    WalletRoot, dialog_content_max_height, dialog_max_height, new_masked_input,
    scrollable_dialog_content, secondary_dialog_content_width, token_label_row,
};

const SPEND_AUTHORIZATION_DIALOG_WIDTH: gpui::Pixels = px(560.0);
const SPEND_AUTHORIZATION_SESSION_WARNING: &str = "This will allow on-chain spending from this vault without re-entering the password until you lock the vault or close the app. Only use this on a trusted device.";
const SUMMARY_RECIPIENT_PREFIX_CHARS: usize = 8;
const SUMMARY_RECIPIENT_SUFFIX_CHARS: usize = 8;
const SUMMARY_RECIPIENT_SHORTEN_THRESHOLD_CHARS: usize = 28;

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
            Self::FiveMinutes => Some(Duration::from_mins(5)),
            Self::FifteenMinutes => Some(Duration::from_mins(15)),
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
    PrivateSendSelfBroadcastGasPassword(UnshieldAssetKey),
    PrivateUnshield(UnshieldAssetKey),
    PrivateUnshieldSelfBroadcastGasPassword(UnshieldAssetKey),
    BlockedShieldRefund(BlockedShieldRescueUtxoId),
    BlockedShieldRefundGasPassword(BlockedShieldRescueUtxoId),
    PublicSend,
    PublicShield,
}

impl SpendAuthorizationIntent {
    const fn uses_private_wallet(self) -> bool {
        matches!(
            self,
            Self::PrivateSend(_) | Self::PrivateUnshield(_) | Self::BlockedShieldRefund(_)
        )
    }
}

#[derive(Clone)]
#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
pub(super) enum HardwareSpendAuthorizationCompletion {
    Continue(SpendAuthorizationIntent),
    PrivateSendSelfBroadcast {
        key: UnshieldAssetKey,
        vault_password: Zeroizing<String>,
    },
    PrivateUnshieldSelfBroadcast {
        key: UnshieldAssetKey,
        vault_password: Zeroizing<String>,
    },
    BlockedShieldRefund {
        utxo_id: BlockedShieldRescueUtxoId,
        vault_password: Zeroizing<String>,
    },
}

#[cfg(feature = "hardware")]
enum HardwareSpendAuthorizationError {
    Hardware(HardwareDerivationError),
    Vault(VaultError),
}

#[cfg(feature = "hardware")]
type HardwareSpendAuthorizationTaskOutput = Result<
    (DesktopPrivateSpendAuthorization, HardwareProfileSession),
    HardwareSpendAuthorizationError,
>;

#[cfg(feature = "hardware")]
impl From<HardwareDerivationError> for HardwareSpendAuthorizationError {
    fn from(error: HardwareDerivationError) -> Self {
        Self::Hardware(error)
    }
}

#[cfg(feature = "hardware")]
impl From<VaultError> for HardwareSpendAuthorizationError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
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

#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
struct HardwareSpendAuthorizationDialogContent {
    root: Entity<WalletRoot>,
    completion: HardwareSpendAuthorizationCompletion,
    summary: SpendAuthorizationSummary,
    device_label: &'static str,
    pending: bool,
    cancelled: bool,
    error: Option<Arc<str>>,
}

impl HardwareSpendAuthorizationDialogContent {
    #[allow(clippy::missing_const_for_fn)]
    fn new(
        root: Entity<WalletRoot>,
        completion: HardwareSpendAuthorizationCompletion,
        summary: SpendAuthorizationSummary,
        device_label: &'static str,
    ) -> Self {
        Self {
            root,
            completion,
            summary,
            device_label,
            pending: false,
            cancelled: false,
            error: None,
        }
    }

    fn cancel(&mut self, cx: &mut Context<'_, Self>) {
        self.cancelled = true;
        cx.notify();
    }

    fn start(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.pending {
            return;
        }
        self.pending = true;
        self.cancelled = false;
        self.error = None;
        cx.notify();

        #[cfg(not(feature = "hardware"))]
        {
            let _ = window;
            self.pending = false;
            self.error = Some(Arc::from(
                "Hardware wallet support is not enabled in this build. Rebuild the wallet with the hardware feature to authorize hardware-derived spends.",
            ));
            cx.notify();
        }

        #[cfg(feature = "hardware")]
        {
            let root = self.root.clone();
            let completion = self.completion.clone();
            let task = root.update(cx, |root, cx| {
                root.start_hardware_spend_authorization_task(window, cx)
            });
            match task {
                Ok(join) => {
                    cx.spawn_in(window, async move |this, cx| {
                        let result = join.await;
                        let _ = this.update_in(cx, |dialog, window, cx| {
                            if dialog.cancelled {
                                return;
                            }
                            dialog.pending = false;
                            match result {
                                Ok(Ok((authorization, hardware_session))) => {
                                    let root = dialog.root.clone();
                                    window.close_dialog(cx);
                                    root.update(cx, |root, cx| {
                                        root.refresh_active_hardware_profile_session(
                                            hardware_session,
                                            cx,
                                        );
                                        match completion {
                                            HardwareSpendAuthorizationCompletion::Continue(intent) => {
                                                root.continue_authorized_spend(
                                                    intent,
                                                    authorization,
                                                    window,
                                                    cx,
                                                );
                                            }
                                            HardwareSpendAuthorizationCompletion::PrivateSendSelfBroadcast {
                                                key,
                                                vault_password,
                                            } => {
                                                root.generate_send_calldata_authorized_with_gas_password(
                                                    key,
                                                    authorization,
                                                    Some(vault_password),
                                                    window,
                                                    cx,
                                                );
                                            }
                                            HardwareSpendAuthorizationCompletion::PrivateUnshieldSelfBroadcast {
                                                key,
                                                vault_password,
                                            } => {
                                                root.generate_unshield_calldata_authorized_with_gas_password(
                                                    key,
                                                    authorization,
                                                    Some(vault_password),
                                                    window,
                                                    cx,
                                                );
                                            }
                                            HardwareSpendAuthorizationCompletion::BlockedShieldRefund {
                                                utxo_id,
                                                vault_password,
                                            } => {
                                                root.submit_blocked_shield_refund_authorized(
                                                    utxo_id,
                                                    authorization,
                                                    Some(vault_password),
                                                    window,
                                                    cx,
                                                );
                                            }
                                        }
                                    });
                                }
                                Ok(Err(error)) => {
                                    let message = hardware_spend_authorization_error_message(&error);
                                    let root = dialog.root.clone();
                                    root.update(cx, |root, cx| {
                                        root.discard_active_trezor_session_if_stale(&message, cx);
                                    });
                                    dialog.error = Some(Arc::from(message));
                                    cx.notify();
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "desktop hardware spend authorization task failed");
                                    dialog.error = Some(Arc::from(
                                        "Hardware spend authorization failed. See logs for non-sensitive diagnostics.",
                                    ));
                                    cx.notify();
                                }
                            }
                        });
                    })
                    .detach();
                }
                Err(message) => {
                    self.pending = false;
                    self.error = Some(message);
                    cx.notify();
                }
            }
        }
    }
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

impl gpui::Render for HardwareSpendAuthorizationDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let dialog = cx.entity();
        let pending = self.pending;
        let submit_label = if pending {
            "Waiting for device..."
        } else if self.error.is_some() {
            "Try again"
        } else {
            "Approve on device"
        };
        let show_trezor_app_passphrase = self
            .root
            .read(cx)
            .current_session_needs_trezor_app_passphrase();
        #[cfg(feature = "hardware")]
        let trezor_app_passphrase_input = self.root.read(cx).trezor_app_passphrase_input.clone();
        #[cfg(feature = "hardware")]
        let trezor_pin_matrix_prompt = {
            let root = self.root.read(cx);
            root.hardware_profile_unlock
                .trezor_pin_matrix_prompt
                .as_ref()
                .map(|prompt| {
                    super::vault_ui::render_trezor_pin_matrix_prompt(&self.root, prompt)
                        .into_any_element()
                })
        };
        #[cfg(not(feature = "hardware"))]
        let trezor_pin_matrix_prompt: Option<AnyElement> = None;

        div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(app_strong_text(self.summary.title.to_string()))
            .child(app_muted_text(hardware_spend_authorization_detail()).whitespace_normal())
            .child(render_spend_authorization_summary(&self.summary))
            .child(Alert::warning(
                "wallet-hardware-spend-custody-warning",
                "This is hardware-derived software custody, not true hardware signing. The device derives a temporary seed, and the desktop app signs this Railgun spend in memory.",
            ).small())
            .child(
                app_muted_text(hardware_spend_authorization_instruction(self.device_label))
                    .whitespace_normal(),
            )
            .when(show_trezor_app_passphrase, |this| {
                #[cfg(feature = "hardware")]
                {
                    this.child(
                        div()
                            .w_full()
                            .p(px(12.0))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(theme::BORDER))
                            .bg(rgb(theme::SURFACE))
                            .child(app_strong_text("Trezor app passphrase"))
                            .child(
                                app_muted_text(
                                    "If the Trezor session expired, enter the app passphrase for this request.",
                                )
                                .whitespace_normal(),
                            )
                            .child(app_input(&trezor_app_passphrase_input).disabled(pending)),
                    )
                }
                #[cfg(not(feature = "hardware"))]
                {
                    this
                }
            })
            .children(trezor_pin_matrix_prompt)
            .when(pending, |this| {
                this.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(Spinner::new().small())
                        .child(app_muted_text("Waiting for device approval...")),
                )
            })
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
                        app_button("wallet-hardware-spend-auth-cancel", "Cancel")
                            .flex_none()
                            .disabled(pending)
                            .on_click(move |_event, window, cx| {
                                window.close_dialog(cx);
                            }),
                    )
                    .child(
                        app_button("wallet-hardware-spend-auth-submit", submit_label)
                            .primary()
                            .flex_none()
                            .disabled(pending)
                            .on_click(move |_event, window, cx| {
                                dialog.update(cx, |dialog, cx| dialog.start(window, cx));
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
        let display_value = if copyable {
            spend_authorization_recipient_display(row.value.as_ref())
        } else {
            row.value.to_string()
        };
        return div()
            .w_full()
            .flex()
            .items_start()
            .gap_2()
            .py(px(2.0))
            .child(
                app_text(display_value)
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

pub(in crate::root) fn spend_authorization_recipient_display(value: &str) -> String {
    if value.chars().count() <= SUMMARY_RECIPIENT_SHORTEN_THRESHOLD_CHARS {
        return value.to_string();
    }
    let prefix: String = value.chars().take(SUMMARY_RECIPIENT_PREFIX_CHARS).collect();
    let suffix_chars: Vec<char> = value
        .chars()
        .rev()
        .take(SUMMARY_RECIPIENT_SUFFIX_CHARS)
        .collect();
    let suffix: String = suffix_chars.into_iter().rev().collect();
    format!("{prefix}...{suffix}")
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
        if intent.uses_private_wallet() && self.selected_wallet_source().is_hardware_derived() {
            self.clear_spend_authorization(cx);
            self.open_hardware_spend_authorization_dialog(
                HardwareSpendAuthorizationCompletion::Continue(intent),
                summary,
                window,
                cx,
            );
            return;
        }
        if let Some(password) = self.valid_spend_authorization_password(cx) {
            self.continue_authorized_spend(
                intent,
                DesktopPrivateSpendAuthorization::VaultPassword(password),
                window,
                cx,
            );
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
        let dialog_max_height = dialog_max_height(window);
        let content_max_height = dialog_content_max_height(window);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text("Authorize spend"))
                .child(scrollable_dialog_content(
                    content_max_height,
                    div().w(content_width).child(content.clone()),
                ))
        });
        cx.defer_in(window, move |_root, window, cx| {
            focus_content.update(cx, |content, cx| content.focus_password(window, cx));
        });
    }

    pub(super) fn open_hardware_public_action_authorization_dialog(
        intent: SpendAuthorizationIntent,
        summary: SpendAuthorizationSummary,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        let dialog_width =
            (window.viewport_size().width * 0.92).min(SPEND_AUTHORIZATION_DIALOG_WIDTH);
        let dialog_max_height = dialog_max_height(window);
        let content_max_height = dialog_content_max_height(window);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let submit_root = root.clone();
            let show_trezor_app_passphrase = root
                .read(cx)
                .current_session_needs_trezor_app_passphrase();
            #[cfg(feature = "hardware")]
            let trezor_app_passphrase_input = root.read(cx).trezor_app_passphrase_input.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text("Authorize hardware public action"))
                .button_props(DialogButtonProps::default().ok_text("Approve on device"))
                .footer(|ok, cancel, window, cx| vec![cancel(window, cx), ok(window, cx)])
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.clear_trezor_app_passphrase_input(window, cx);
                    });
                })
                .on_ok(move |_event, window, cx| {
                    submit_root.update(cx, |root, cx| {
                        root.continue_authorized_spend(
                            intent,
                            DesktopPrivateSpendAuthorization::VaultPassword(Zeroizing::new(
                                String::new(),
                            )),
                            window,
                            cx,
                        );
                    });
                    true
                })
                .child(scrollable_dialog_content(
                    content_max_height,
                    div()
                        .w(content_width)
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(app_strong_text(summary.title.to_string()))
                        .child(app_muted_text(summary.detail.to_string()).whitespace_normal())
                        .child(render_spend_authorization_summary(&summary))
                        .when(show_trezor_app_passphrase, |this| {
                            #[cfg(feature = "hardware")]
                            {
                                this.child(
                                    div()
                                        .w_full()
                                        .p(px(12.0))
                                        .flex()
                                        .flex_col()
                                        .gap_2()
                                        .rounded_md()
                                        .border_1()
                                        .border_color(rgb(theme::BORDER))
                                        .bg(rgb(theme::SURFACE))
                                        .child(app_strong_text("Trezor app passphrase"))
                                        .child(
                                            app_muted_text(
                                                "If the Trezor session expired, enter the app passphrase for this public account request.",
                                            )
                                            .whitespace_normal(),
                                        )
                                        .child(app_input(&trezor_app_passphrase_input)),
                                )
                            }
                            #[cfg(not(feature = "hardware"))]
                            {
                                this
                            }
                        })
                        .child(
                            app_muted_text("The app will verify the stored public account address against the connected device before signing.")
                                .whitespace_normal(),
                        ),
                ))
        });
    }

    pub(super) fn open_hardware_spend_authorization_dialog(
        &mut self,
        completion: HardwareSpendAuthorizationCompletion,
        summary: SpendAuthorizationSummary,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(descriptor) = self.selected_hardware_descriptor() else {
            self.set_vault_error(
                "Selected wallet is missing its hardware derivation descriptor",
                cx,
            );
            return;
        };
        let root = cx.entity();
        let device_label = hardware_device_label(descriptor.device_kind);
        let dialog_width =
            (window.viewport_size().width * 0.92).min(SPEND_AUTHORIZATION_DIALOG_WIDTH);
        let dialog_max_height = dialog_max_height(window);
        let content_max_height = dialog_content_max_height(window);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|_cx| {
            HardwareSpendAuthorizationDialogContent::new(
                root.clone(),
                completion,
                summary,
                device_label,
            )
        });
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_content = content.clone();
            let close_root = root.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text("Authorize hardware spend"))
                .on_close(move |_event, window, cx| {
                    close_content.update(cx, HardwareSpendAuthorizationDialogContent::cancel);
                    close_root.update(cx, |root, cx| {
                        root.clear_trezor_app_passphrase_input(window, cx);
                        root.clear_trezor_pin_matrix_prompt(cx);
                    });
                })
                .child(scrollable_dialog_content(
                    content_max_height,
                    div().w(content_width).child(content.clone()),
                ))
        });
    }

    fn selected_hardware_descriptor(&self) -> Option<HardwareDerivationDescriptor> {
        let selected_wallet_id = self.selected_wallet_id.as_ref()?;
        self.wallet_metadata
            .iter()
            .find(|metadata| metadata.wallet_uuid == selected_wallet_id.as_ref())
            .and_then(|metadata| metadata.hardware_derivation_descriptor().cloned())
    }

    #[cfg(feature = "hardware")]
    fn start_hardware_spend_authorization_task(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Result<tokio::task::JoinHandle<HardwareSpendAuthorizationTaskOutput>, Arc<str>> {
        let Some(descriptor) = self.selected_hardware_descriptor() else {
            return Err(Arc::from(
                "Selected wallet is missing its hardware derivation descriptor",
            ));
        };
        let Some(store) = self.vault_store.clone() else {
            return Err(Arc::from("Wallet vault storage is unavailable"));
        };
        let Some(view_session) = self.view_session.clone() else {
            return Err(Arc::from(
                "Unlock the wallet vault before authorizing a spend",
            ));
        };
        let Some(hardware_session) = view_session.hardware_profile_session().cloned() else {
            return Err(Arc::from(
                "Unlock the matching hardware profile before authorizing a spend",
            ));
        };
        let trezor_app_passphrase =
            self.read_trezor_app_passphrase_for_hardware_session(&hardware_session, window, cx);
        let trezor_pin_matrix_provider =
            if hardware_session.device_kind == HardwareDeviceKind::Trezor {
                Some(self.trezor_pin_matrix_provider_for_operation(window, cx))
            } else {
                None
            };
        Ok(self.runtime.spawn(derive_hardware_spend_authorization(
            store,
            view_session,
            hardware_session,
            descriptor,
            trezor_app_passphrase,
            trezor_pin_matrix_provider,
        )))
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
        self.continue_authorized_spend(
            intent,
            DesktopPrivateSpendAuthorization::VaultPassword(password),
            window,
            cx,
        );
    }

    pub(super) fn clear_spend_authorization(&mut self, cx: &mut Context<'_, Self>) {
        if self.spend_authorization_cache.take().is_some() {
            cx.notify();
        }
    }

    fn continue_authorized_spend(
        &mut self,
        intent: SpendAuthorizationIntent,
        authorization: DesktopPrivateSpendAuthorization,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        match intent {
            SpendAuthorizationIntent::PrivateSend(key) => {
                self.generate_send_calldata_authorized(key, authorization, window, cx);
            }
            SpendAuthorizationIntent::PrivateSendSelfBroadcastGasPassword(key) => {
                let DesktopPrivateSpendAuthorization::VaultPassword(password) = authorization
                else {
                    self.set_vault_error(
                        "Self-broadcast software gas-payer authorization requires the vault password",
                        cx,
                    );
                    return;
                };
                self.request_private_send_hardware_authorization_with_gas_password(
                    key, password, window, cx,
                );
            }
            SpendAuthorizationIntent::PrivateUnshield(key) => {
                self.generate_unshield_calldata_authorized(key, authorization, window, cx);
            }
            SpendAuthorizationIntent::PrivateUnshieldSelfBroadcastGasPassword(key) => {
                let DesktopPrivateSpendAuthorization::VaultPassword(password) = authorization
                else {
                    self.set_vault_error(
                        "Self-broadcast software gas-payer authorization requires the vault password",
                        cx,
                    );
                    return;
                };
                self.request_private_unshield_hardware_authorization_with_gas_password(
                    key, password, window, cx,
                );
            }
            SpendAuthorizationIntent::BlockedShieldRefund(utxo_id) => {
                self.submit_blocked_shield_refund_authorized(
                    utxo_id,
                    authorization,
                    None,
                    window,
                    cx,
                );
            }
            SpendAuthorizationIntent::BlockedShieldRefundGasPassword(utxo_id) => {
                let DesktopPrivateSpendAuthorization::VaultPassword(password) = authorization
                else {
                    self.set_vault_error(
                        "Blocked Shield refund gas-payer authorization requires the vault password",
                        cx,
                    );
                    return;
                };
                self.request_blocked_shield_refund_hardware_authorization(
                    utxo_id, password, window, cx,
                );
            }
            SpendAuthorizationIntent::PublicSend => {
                let DesktopPrivateSpendAuthorization::VaultPassword(password) = authorization
                else {
                    self.set_vault_error(
                        "Public account spend authorization requires the vault password",
                        cx,
                    );
                    return;
                };
                self.submit_public_send_authorized(password, window, cx);
            }
            SpendAuthorizationIntent::PublicShield => {
                let DesktopPrivateSpendAuthorization::VaultPassword(password) = authorization
                else {
                    self.set_vault_error(
                        "Public account spend authorization requires the vault password",
                        cx,
                    );
                    return;
                };
                self.submit_public_shield_authorized(password, window, cx);
            }
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn refresh_active_hardware_profile_session(
        &mut self,
        hardware_session: HardwareProfileSession,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(view_session) = self.view_session.as_ref() else {
            return;
        };
        if view_session.hardware_profile_session().is_none() {
            return;
        }
        self.view_session = Some(Arc::new(
            view_session.clone_with_hardware_profile_session(hardware_session),
        ));
        cx.notify();
    }

    fn request_private_send_hardware_authorization_with_gas_password(
        &mut self,
        key: UnshieldAssetKey,
        vault_password: Zeroizing<String>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.send_spend_draft(key, cx) else {
            return;
        };
        self.open_hardware_spend_authorization_dialog(
            HardwareSpendAuthorizationCompletion::PrivateSendSelfBroadcast {
                key,
                vault_password,
            },
            super::private_action::private_send_authorization_summary(&draft),
            window,
            cx,
        );
    }

    fn request_private_unshield_hardware_authorization_with_gas_password(
        &mut self,
        key: UnshieldAssetKey,
        vault_password: Zeroizing<String>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.unshield_spend_draft(key, cx) else {
            return;
        };
        self.open_hardware_spend_authorization_dialog(
            HardwareSpendAuthorizationCompletion::PrivateUnshieldSelfBroadcast {
                key,
                vault_password,
            },
            super::private_action::private_unshield_authorization_summary(&draft),
            window,
            cx,
        );
    }
}

const fn hardware_device_label(device_kind: HardwareDeviceKind) -> &'static str {
    match device_kind {
        HardwareDeviceKind::Ledger => "Ledger",
        HardwareDeviceKind::Trezor => "Trezor",
    }
}

pub(in crate::root) fn hardware_spend_authorization_instruction(device_label: &str) -> String {
    format!(
        "Use the intended {device_label} passphrase wallet, then approve the Railgun derivation request."
    )
}

pub(in crate::root) const fn hardware_spend_authorization_detail() -> &'static str {
    "Approve the Railgun derivation request on your hardware wallet to authorize this private spend."
}

#[cfg(feature = "hardware")]
fn hardware_spend_authorization_error_message(error: &HardwareSpendAuthorizationError) -> String {
    match error {
        HardwareSpendAuthorizationError::Hardware(error) => {
            format!("Hardware spend authorization failed: {error}")
        }
        HardwareSpendAuthorizationError::Vault(error) => format!("Vault error: {error}"),
    }
}

#[cfg(feature = "hardware")]
async fn derive_hardware_spend_authorization(
    store: Arc<DesktopVaultStore>,
    view_session: Arc<DesktopViewSession>,
    mut hardware_session: HardwareProfileSession,
    descriptor: HardwareDerivationDescriptor,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    trezor_pin_matrix_provider: Option<TrezorPinMatrixProvider>,
) -> Result<
    (DesktopPrivateSpendAuthorization, HardwareProfileSession),
    HardwareSpendAuthorizationError,
> {
    hardware_session.verify_descriptor(&descriptor)?;
    let entropy = match descriptor.device_kind {
        HardwareDeviceKind::Ledger => {
            let client = LedgerHardwareDerivationClient::connect().await?;
            let active = client.active_profile_session(&descriptor.path).await?;
            active.verify_descriptor(&descriptor)?;
            let output = client.eip1024_shared_secret(&descriptor.path, true).await?;
            synthetic_entropy_from_hardware_output(&descriptor, output)?
        }
        HardwareDeviceKind::Trezor => {
            let mut client = TrezorHardwareDerivationClient::connect_with_session(
                hardware_session.trezor_session_id.clone(),
            )?;
            client.set_passphrase_mode(hardware_session.trezor_passphrase_mode());
            if let Some(passphrase) = trezor_app_passphrase {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            if let Some(provider) = trezor_pin_matrix_provider {
                client.set_pin_matrix_provider(provider);
            }
            let active = client.active_profile_session(&descriptor.path)?;
            active.verify_descriptor(&descriptor)?;
            hardware_session
                .trezor_session_id
                .clone_from(&active.trezor_session_id);
            hardware_session.set_trezor_passphrase_mode(active.trezor_passphrase_mode());
            let output = client.cipher_key_value(&descriptor)?;
            synthetic_entropy_from_hardware_output(&descriptor, output)?
        }
    };
    let signer = store.hardware_railgun_spend_signer_from_entropy(
        view_session.as_ref(),
        &descriptor,
        entropy.expose_secret(),
    )?;
    Ok((
        DesktopPrivateSpendAuthorization::PreauthorizedSigner(signer),
        hardware_session,
    ))
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
