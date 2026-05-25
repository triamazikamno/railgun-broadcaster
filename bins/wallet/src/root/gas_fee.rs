use std::sync::Arc;

use gpui::{
    App, AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled, Window, div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, Selectable, Sizable, Size, StyleSized,
    button::{Button, ButtonGroup, ButtonVariants},
    input::{InputEvent, InputState},
    spinner::Spinner,
    tooltip::Tooltip,
};
use ui::controls::{app_input, app_muted_text};
use ui::icons;
use ui::theme;
use wallet_ops::{SelfBroadcastGasFeeQuote, SelfBroadcastGasFeeSelection};

use crate::assets::RailgunActionIcon;

use super::{
    DeliveryFormKind, UnshieldAssetKey, WalletRoot, labeled_field,
    private_action::private_action_input, public_action::PublicActionMode,
};

const GWEI_WEI: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Eip1559GasFeeMode {
    Auto,
    Custom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Eip1559GasFeeEditTarget {
    MaxFee,
    MaxTip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Eip1559GasFeeTarget {
    Private {
        key: UnshieldAssetKey,
        kind: DeliveryFormKind,
    },
    Public {
        mode: PublicActionMode,
    },
}

pub(super) struct Eip1559GasFeeEditorState {
    pub(super) mode: Eip1559GasFeeMode,
    pub(super) max_fee_input: Entity<InputState>,
    pub(super) max_priority_fee_input: Entity<InputState>,
    pub(super) quote: Option<SelfBroadcastGasFeeQuote>,
    pub(super) refreshing: bool,
    pub(super) refresh_id: u64,
    pub(super) error: Option<Arc<str>>,
}

#[derive(Clone)]
pub(super) struct GasRetryInputs {
    pub(super) max_fee_input: Entity<InputState>,
    pub(super) max_tip_input: Entity<InputState>,
}

impl GasRetryInputs {
    pub(super) fn new<T>(
        initial_max_fee_per_gas: u128,
        initial_max_priority_fee_per_gas: u128,
        window: &mut Window,
        cx: &mut Context<'_, T>,
    ) -> Self {
        let max_fee_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("max fee gwei");
            input.set_value(format_gwei(initial_max_fee_per_gas), window, cx);
            input
        });
        let max_tip_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("max tip gwei");
            input.set_value(format_gwei(initial_max_priority_fee_per_gas), window, cx);
            input
        });
        Self {
            max_fee_input,
            max_tip_input,
        }
    }

    pub(super) fn subscribe_clear_error<T: 'static>(
        &self,
        cx: &mut Context<'_, T>,
        clear: impl Fn(&mut T, &mut Context<'_, T>) + Clone + 'static,
    ) {
        let clear_max_fee = clear.clone();
        cx.subscribe(
            &self.max_fee_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    clear_max_fee(this, cx);
                }
            },
        )
        .detach();

        cx.subscribe(
            &self.max_tip_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    clear(this, cx);
                }
            },
        )
        .detach();
    }

    pub(super) fn render_fields(&self) -> gpui::Div {
        div()
            .w_full()
            .flex()
            .flex_wrap()
            .gap_3()
            .child(
                labeled_field("Max fee (gwei)", app_input(&self.max_fee_input).w_full())
                    .flex_1()
                    .min_w(px(150.0)),
            )
            .child(
                labeled_field("Max tip (gwei)", app_input(&self.max_tip_input).w_full())
                    .flex_1()
                    .min_w(px(150.0)),
            )
    }

    pub(super) fn parse(&self, cx: &App) -> Result<(u128, u128), String> {
        let max_fee = parse_gwei_to_wei(self.max_fee_input.read(cx).value().as_ref())?;
        let max_tip = parse_gwei_to_wei(self.max_tip_input.read(cx).value().as_ref())?;
        validate_custom_gas_fee(max_fee, max_tip)?;
        Ok((max_fee, max_tip))
    }
}

impl Eip1559GasFeeEditorState {
    pub(super) fn new(window: &mut Window, cx: &mut Context<'_, WalletRoot>) -> Self {
        Self {
            mode: Eip1559GasFeeMode::Auto,
            max_fee_input: cx.new(|cx| InputState::new(window, cx).placeholder("max fee gwei")),
            max_priority_fee_input: cx
                .new(|cx| InputState::new(window, cx).placeholder("max tip gwei")),
            quote: None,
            refreshing: false,
            refresh_id: 0,
            error: None,
        }
    }

    pub(super) fn selection(
        &self,
        cx: &Context<'_, WalletRoot>,
    ) -> Result<SelfBroadcastGasFeeSelection, String> {
        match self.mode {
            Eip1559GasFeeMode::Auto => Ok(SelfBroadcastGasFeeSelection::Auto),
            Eip1559GasFeeMode::Custom => {
                let max_fee_per_gas =
                    parse_gwei_to_wei(self.max_fee_input.read(cx).value().as_ref())?;
                let max_priority_fee_per_gas =
                    parse_gwei_to_wei(self.max_priority_fee_input.read(cx).value().as_ref())?;
                validate_custom_gas_fee(max_fee_per_gas, max_priority_fee_per_gas)?;
                Ok(SelfBroadcastGasFeeSelection::Custom {
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                })
            }
        }
    }

    pub(super) fn seed_custom_from_auto_if_empty(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, WalletRoot>,
    ) {
        let Some(quote) = self.quote else {
            return;
        };
        let max_fee_empty = self.max_fee_input.read(cx).value().trim().is_empty();
        let max_priority_fee_empty = self
            .max_priority_fee_input
            .read(cx)
            .value()
            .trim()
            .is_empty();
        if !max_fee_empty || !max_priority_fee_empty {
            return;
        }

        let max_fee = format_gwei(quote.suggested_max_fee_per_gas);
        let max_priority_fee = format_gwei(quote.suggested_max_priority_fee_per_gas);
        self.max_fee_input
            .update(cx, |input, cx| input.set_value(max_fee, window, cx));
        self.max_priority_fee_input.update(cx, |input, cx| {
            input.set_value(max_priority_fee, window, cx);
        });
    }

    pub(super) fn overwrite_custom_from_auto(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, WalletRoot>,
    ) -> bool {
        let Some(quote) = self.quote else {
            return false;
        };
        let max_fee = format_gwei(quote.suggested_max_fee_per_gas);
        let max_priority_fee = format_gwei(quote.suggested_max_priority_fee_per_gas);
        self.max_fee_input
            .update(cx, |input, cx| input.set_value(max_fee, window, cx));
        self.max_priority_fee_input.update(cx, |input, cx| {
            input.set_value(max_priority_fee, window, cx);
        });
        true
    }
}

impl WalletRoot {
    pub(super) fn set_eip1559_gas_fee_mode(
        &mut self,
        target: Eip1559GasFeeTarget,
        mode: Eip1559GasFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        match target {
            Eip1559GasFeeTarget::Private { key, kind } => {
                self.set_self_broadcast_gas_fee_mode(kind, key, mode, window, cx);
            }
            Eip1559GasFeeTarget::Public { mode: action_mode } => {
                self.set_public_action_gas_fee_mode(action_mode, mode, window, cx);
            }
        }
    }

    pub(super) fn refresh_eip1559_gas_fee_quote(
        &mut self,
        target: Eip1559GasFeeTarget,
        cx: &mut Context<'_, Self>,
    ) {
        match target {
            Eip1559GasFeeTarget::Private { key, kind } => {
                self.refresh_self_broadcast_gas_fee_quote(kind, key, cx);
            }
            Eip1559GasFeeTarget::Public { mode } => {
                self.refresh_public_action_gas_fee_quote(mode, cx);
            }
        }
    }

    pub(super) fn customize_eip1559_gas_fee_from_auto(
        &mut self,
        target: Eip1559GasFeeTarget,
        edit_target: Eip1559GasFeeEditTarget,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        match target {
            Eip1559GasFeeTarget::Private { key, kind } => {
                self.customize_self_broadcast_gas_fee_from_auto(kind, key, edit_target, window, cx);
            }
            Eip1559GasFeeTarget::Public { mode } => {
                self.customize_public_action_gas_fee_from_auto(mode, edit_target, window, cx);
            }
        }
    }
}

pub(super) fn render_eip1559_gas_fee_editor(
    root: Entity<WalletRoot>,
    target: Eip1559GasFeeTarget,
    state: &Eip1559GasFeeEditorState,
    disabled: bool,
) -> gpui::Div {
    let mode_root = root.clone();
    let refresh_root = root.clone();
    let auto_selected = state.mode == Eip1559GasFeeMode::Auto;
    let custom_selected = state.mode == Eip1559GasFeeMode::Custom;
    let target_id = gas_fee_target_id(target);

    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(div().min_w(px(0.0)).child(app_muted_text("Gas fee")))
                .child(
                    div().flex_none().child(
                        ButtonGroup::new(SharedString::from(format!(
                            "wallet-eip1559-gas-mode-{target_id}"
                        )))
                        .outline()
                        .compact()
                        .disabled(disabled)
                        .child(gas_fee_mode_segment_button(
                            SharedString::from(format!("wallet-eip1559-gas-auto-{target_id}")),
                            "Auto",
                            auto_selected,
                            Some(render_auto_refresh_button(
                                refresh_root,
                                SharedString::from(format!(
                                    "wallet-eip1559-gas-refresh-{target_id}"
                                )),
                                target,
                                auto_selected && state.refreshing,
                                auto_selected && !disabled && !state.refreshing,
                            )),
                        ))
                        .child(gas_fee_mode_segment_button(
                            SharedString::from(format!("wallet-eip1559-gas-custom-{target_id}")),
                            "Custom",
                            custom_selected,
                            None,
                        ))
                        .on_click(move |selected, window, cx| {
                            let Some(index) = selected.first() else {
                                return;
                            };
                            let mode = if *index == 0 {
                                Eip1559GasFeeMode::Auto
                            } else {
                                Eip1559GasFeeMode::Custom
                            };
                            mode_root.update(cx, |root, cx| {
                                root.set_eip1559_gas_fee_mode(target, mode, window, cx);
                            });
                        }),
                    ),
                ),
        )
        .child(render_gas_fee_inputs(root, target, state, disabled))
        .when_some(state.error.as_ref(), |this, error| {
            this.child(app_muted_text(error.to_string()).text_color(rgb(theme::DANGER)))
        })
}

fn gas_fee_mode_segment_button(
    id: SharedString,
    label: &'static str,
    selected: bool,
    accessory: Option<gpui::AnyElement>,
) -> Button {
    Button::new(id).selected(selected).child(
        div()
            .flex()
            .items_center()
            .justify_center()
            .gap_1()
            .text_size(theme::APP_TEXT_SIZE)
            .child(label)
            .children(accessory),
    )
}

fn render_auto_refresh_button(
    root: Entity<WalletRoot>,
    id: SharedString,
    target: Eip1559GasFeeTarget,
    refreshing: bool,
    enabled: bool,
) -> gpui::AnyElement {
    div()
        .id(id)
        .size(px(18.0))
        .flex_none()
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .when(refreshing, |this| {
            this.child(
                Spinner::new()
                    .icon(IconName::LoaderCircle)
                    .color(rgb(theme::TEXT_MUTED).into())
                    .with_size(px(13.0)),
            )
        })
        .when(!refreshing, |this| {
            this.opacity(if enabled { 1.0 } else { 0.45 })
                .when(enabled, |this| {
                    this.cursor_pointer()
                        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                        .tooltip(|window, cx| {
                            Tooltip::new("Refresh gas price hint").build(window, cx)
                        })
                        .on_click(move |_event, _window, cx| {
                            cx.stop_propagation();
                            root.update(cx, |root, cx| {
                                root.refresh_eip1559_gas_fee_quote(target, cx);
                            });
                        })
                })
                .child(
                    img(icons::refresh_ccw_icon_path())
                        .size(px(13.0))
                        .flex_none(),
                )
        })
        .into_any_element()
}

fn render_gas_fee_inputs(
    root: Entity<WalletRoot>,
    target: Eip1559GasFeeTarget,
    state: &Eip1559GasFeeEditorState,
    disabled: bool,
) -> gpui::Div {
    let auto_selected = state.mode == Eip1559GasFeeMode::Auto;
    let edit_enabled = !disabled && state.quote.is_some();
    let auto_max_fee = state.quote.map_or_else(
        || SharedString::from("unavailable"),
        |quote| SharedString::from(format_gwei(quote.suggested_max_fee_per_gas)),
    );
    let auto_max_tip = state.quote.map_or_else(
        || SharedString::from("unavailable"),
        |quote| SharedString::from(format_gwei(quote.suggested_max_priority_fee_per_gas)),
    );
    let target_id = gas_fee_target_id(target);
    div()
        .flex()
        .items_end()
        .gap_3()
        .child(render_gas_fee_input_slot(
            "Max fee (gwei)",
            if auto_selected {
                render_auto_gas_fee_value(
                    auto_max_fee,
                    Some(render_auto_gas_fee_edit_button(
                        root.clone(),
                        SharedString::from(format!("wallet-eip1559-gas-edit-max-fee-{target_id}")),
                        target,
                        Eip1559GasFeeEditTarget::MaxFee,
                        edit_enabled,
                    )),
                )
                .into_any_element()
            } else {
                private_action_input(&state.max_fee_input)
                    .disabled(disabled)
                    .into_any_element()
            },
        ))
        .child(render_gas_fee_input_slot(
            "Max tip (gwei)",
            if auto_selected {
                render_auto_gas_fee_value(
                    auto_max_tip,
                    Some(render_auto_gas_fee_edit_button(
                        root,
                        SharedString::from(format!("wallet-eip1559-gas-edit-max-tip-{target_id}")),
                        target,
                        Eip1559GasFeeEditTarget::MaxTip,
                        edit_enabled,
                    )),
                )
                .into_any_element()
            } else {
                private_action_input(&state.max_priority_fee_input)
                    .disabled(disabled)
                    .into_any_element()
            },
        ))
}

fn render_gas_fee_input_slot(label: &'static str, input: gpui::AnyElement) -> gpui::Div {
    labeled_field(label, input).flex_1().min_w(px(0.0))
}

fn render_auto_gas_fee_value(
    value: impl Into<SharedString>,
    accessory: Option<gpui::AnyElement>,
) -> gpui::Div {
    div()
        .w_full()
        .input_h(Size::Medium)
        .px(px(12.0))
        .py(px(8.0))
        .flex()
        .items_center()
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .bg(rgb(theme::SURFACE))
        .text_size(theme::APP_TEXT_SIZE)
        .text_color(rgb(theme::TEXT_MUTED))
        .child(value.into())
        .child(div().flex_1())
        .children(accessory)
}

fn render_auto_gas_fee_edit_button(
    root: Entity<WalletRoot>,
    id: SharedString,
    gas_target: Eip1559GasFeeTarget,
    edit_target: Eip1559GasFeeEditTarget,
    enabled: bool,
) -> gpui::AnyElement {
    Button::new(id)
        .icon(Icon::new(RailgunActionIcon::Pencil))
        .ghost()
        .xsmall()
        .compact()
        .tooltip("Customize gas fee")
        .disabled(!enabled)
        .on_click(move |_event, window, cx| {
            cx.stop_propagation();
            root.update(cx, |root, cx| {
                root.customize_eip1559_gas_fee_from_auto(gas_target, edit_target, window, cx);
            });
        })
        .into_any_element()
}

fn gas_fee_target_id(target: Eip1559GasFeeTarget) -> String {
    match target {
        Eip1559GasFeeTarget::Private { key, kind } => {
            format!(
                "private-{}-{}-{}",
                key.chain_id,
                key.token,
                gas_fee_kind_id(kind)
            )
        }
        Eip1559GasFeeTarget::Public { mode } => {
            format!("public-{}", public_action_mode_id(mode))
        }
    }
}

const fn gas_fee_kind_id(kind: DeliveryFormKind) -> &'static str {
    match kind {
        DeliveryFormKind::Send => "send",
        DeliveryFormKind::Unshield => "unshield",
    }
}

const fn public_action_mode_id(mode: PublicActionMode) -> &'static str {
    match mode {
        PublicActionMode::Shield => "shield",
        PublicActionMode::Send => "send",
    }
}

pub(super) fn parse_gwei_to_wei(input: &str) -> Result<u128, String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("Enter a gas fee in gwei".to_string());
    }
    if value.starts_with('-') {
        return Err("Gas fee cannot be negative".to_string());
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some() || whole.is_empty() && fractional.is_none() {
        return Err("Enter a valid decimal gwei amount".to_string());
    }
    let whole_wei = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| "Enter a valid decimal gwei amount".to_string())?
            .checked_mul(GWEI_WEI)
            .ok_or_else(|| "Gas fee is too large".to_string())?
    };
    let fractional_wei = if let Some(fractional) = fractional {
        if fractional.len() > 9 || !fractional.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("Enter no more than 9 decimal places for gwei".to_string());
        }
        let mut padded = fractional.to_string();
        while padded.len() < 9 {
            padded.push('0');
        }
        padded
            .parse::<u128>()
            .map_err(|_| "Enter a valid decimal gwei amount".to_string())?
    } else {
        0
    };
    whole_wei
        .checked_add(fractional_wei)
        .ok_or_else(|| "Gas fee is too large".to_string())
}

pub(super) fn validate_custom_gas_fee(
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<(), String> {
    if max_fee_per_gas == 0 {
        return Err("Max fee must be greater than 0 gwei".to_string());
    }
    if max_priority_fee_per_gas > max_fee_per_gas {
        return Err("Max tip cannot exceed max fee".to_string());
    }
    Ok(())
}

pub(super) fn format_gwei(wei: u128) -> String {
    let whole = wei / GWEI_WEI;
    let fractional = wei % GWEI_WEI;
    if fractional == 0 {
        return whole.to_string();
    }
    let mut fractional = format!("{fractional:09}");
    while fractional.ends_with('0') {
        fractional.pop();
    }
    format!("{whole}.{fractional}")
}
