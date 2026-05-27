use super::*;

pub(in crate::root) fn private_action_asset_title_select(
    asset_select: &Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>,
    disabled: bool,
) -> gpui::Div {
    div().w(px(170.0)).h(px(32.0)).child(
        Select::new(asset_select)
            .w_full()
            .h(px(32.0))
            .placeholder("Select asset")
            .menu_width(px(220.0))
            .disabled(disabled),
    )
}

pub(in crate::root) fn private_action_asset_select_row(
    label: &str,
    icon_path: Option<WalletIconSource>,
) -> gpui::Div {
    div().flex().items_center().gap_2().child(token_label_row(
        SharedString::from(label.to_owned()),
        icon_path,
        px(16.0),
    ))
}

pub(in crate::root) fn render_fee_token_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    generating: bool,
) -> gpui::Div {
    let selected_option = options
        .iter()
        .find(|option| option.token == selected_fee_token)
        .cloned();
    let options = options.to_vec();
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            div()
                .min_w(px(0.0))
                .child(app_muted_text("Transaction fee token")),
        )
        .child(
            Popover::new(delivery_element_id(key, kind, "fee-token-selector"))
                .trigger(
                    Button::new(delivery_element_id(key, kind, "fee-token-selector-trigger"))
                        .outline()
                        .child(fee_token_selector_trigger_row(
                            selected_option.as_ref(),
                            selected_fee_token,
                        ))
                        .dropdown_caret(true)
                        .disabled(generating || options.is_empty()),
                )
                .content(move |_state, window, cx| {
                    let popover = cx.entity();
                    render_fee_token_selector_menu(
                        &root,
                        &popover,
                        key,
                        kind,
                        &options,
                        selected_fee_token,
                        window,
                    )
                }),
        )
}

pub(in crate::root) fn render_fee_token_selector_menu(
    root: &Entity<WalletRoot>,
    popover: &Entity<gpui_component::popover::PopoverState>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    _window: &mut Window,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .w(px(260.0))
        .children(options.iter().map(|option| {
            let selector_root = root.clone();
            let popover = popover.clone();
            let token = option.token;
            let selected = token == selected_fee_token;
            let disabled = option.eligible_broadcaster_count == 0;
            div()
                .id(fee_token_element_id(key, kind, token))
                .w_full()
                .p(px(8.0))
                .rounded_sm()
                .text_color(rgb(if selected {
                    theme::PRIMARY_FOREGROUND
                } else {
                    theme::TEXT
                }))
                .opacity(if disabled { 0.5 } else { 1.0 })
                .when(selected, |this| this.bg(rgb(theme::PRIMARY)))
                .when(!disabled && !selected, |this| {
                    this.cursor_pointer()
                        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                })
                .when(!disabled, |this| {
                    this.on_mouse_down(MouseButton::Left, move |_, window, cx| {
                        cx.stop_propagation();
                        popover.update(cx, |state, cx| state.dismiss(window, cx));
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => root.set_send_fee_token(key, token, cx),
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_fee_token(key, token, cx);
                            }
                        });
                    })
                })
                .child(fee_token_option_label_row(option, px(18.0)))
        }))
}

pub(in crate::root) fn fee_token_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    token: Address,
) -> SharedString {
    let action = format!("fee-token-{}", token.to_checksum(None));
    delivery_element_id(key, kind, &action)
}

pub(in crate::root) fn fee_token_option_button_label(
    option: &PublicBroadcasterFeeTokenOption,
) -> String {
    format!(
        "{} · {}",
        option.label,
        broadcaster_count_label(option.eligible_broadcaster_count)
    )
}

pub(in crate::root) fn fee_token_selector_trigger_row(
    option: Option<&PublicBroadcasterFeeTokenOption>,
    selected_fee_token: Address,
) -> gpui::Div {
    option.map_or_else(
        || {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(SharedString::from(short_address(&selected_fee_token)))
        },
        |option| fee_token_option_label_row(option, px(16.0)),
    )
}

pub(in crate::root) fn fee_token_option_label_row(
    option: &PublicBroadcasterFeeTokenOption,
    icon_size: Pixels,
) -> gpui::Div {
    token_label_row(
        SharedString::from(fee_token_option_button_label(option)),
        option.icon_path.clone(),
        icon_size,
    )
}

pub(in crate::root) fn broadcaster_count_label(count: usize) -> String {
    match count {
        0 => "no broadcasters".to_string(),
        1 => "1 broadcaster".to_string(),
        count => format!("{count} broadcasters"),
    }
}

pub(in crate::root) fn render_broadcaster_fee_mode_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: PublicBroadcasterFeeMode,
    generating: bool,
) -> gpui::Div {
    let selector_root = root;
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(div().min_w(px(0.0)).child(app_muted_text("Transaction fee")))
        .child(
            div().flex_none().child(
                ButtonGroup::new(delivery_element_id(key, kind, "fee-mode-toggle"))
                    .outline()
                    .compact()
                    .disabled(generating)
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-deduct"),
                        delivery_element_id(key, kind, "fee-mode-deduct-info"),
                        "Deduct fee from amount",
                        "Recipient receives the entered amount minus the transaction fee.",
                        mode == PublicBroadcasterFeeMode::DeductFromAmount,
                    ))
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-add"),
                        delivery_element_id(key, kind, "fee-mode-add-info"),
                        "Add fee on top",
                        "Recipient receives the full entered amount; transaction fee is added to spend.",
                        mode == PublicBroadcasterFeeMode::AddToAmount,
                    ))
                    .on_click(move |selected, window, cx| {
                        let Some(index) = selected.first() else {
                            return;
                        };
                        let mode = if *index == 0 {
                            PublicBroadcasterFeeMode::DeductFromAmount
                        } else {
                            PublicBroadcasterFeeMode::AddToAmount
                        };
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => {
                                root.set_send_broadcaster_fee_mode(key, mode, window, cx);
                            }
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_broadcaster_fee_mode(key, mode, window, cx);
                            }
                        });
                    }),
            ),
        )
}

pub(in crate::root) fn fee_mode_segment_button(
    id: SharedString,
    info_id: SharedString,
    label: &'static str,
    tooltip: &'static str,
    selected: bool,
) -> Button {
    Button::new(id).selected(selected).child(
        div()
            .flex()
            .items_center()
            .justify_center()
            .gap_1()
            .text_size(APP_TEXT_SIZE)
            .child(label)
            .child(render_fee_mode_info_icon(info_id, tooltip)),
    )
}

pub(in crate::root) fn render_fee_mode_info_icon(
    id: SharedString,
    tooltip: &'static str,
) -> Button {
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::Info)
        .text_color(rgb(theme::TEXT_MUTED))
        .tooltip(tooltip)
}

pub(in crate::root) fn private_action_segment_button(
    id: SharedString,
    label: &'static str,
    selected: bool,
) -> Button {
    private_action_segment_button_with_accessory(id, label, selected, None)
}

pub(in crate::root) fn private_action_segment_button_with_accessory(
    id: SharedString,
    label: &'static str,
    selected: bool,
    accessory: Option<gpui::AnyElement>,
) -> Button {
    let button = app_button_base(id)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_1()
                .child(app_button_label(label))
                .children(accessory),
        );
    if selected { button.primary() } else { button }
}

pub(in crate::root) fn render_self_broadcast_privacy_icon(
    id: SharedString,
    selected: bool,
) -> gpui::AnyElement {
    let color = if selected {
        theme::PRIMARY_FOREGROUND
    } else {
        theme::WARNING
    };
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::TriangleAlert)
        .text_color(rgb(color))
        .tooltip(SELF_BROADCAST_PRIVACY_WARNING)
        .into_any_element()
}

pub(in crate::root) fn render_self_broadcast_gas_payer_warning_icon(
    id: SharedString,
) -> gpui::AnyElement {
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::TriangleAlert)
        .text_color(rgb(theme::DANGER))
        .tooltip(SELF_BROADCAST_ZERO_GAS_PAYER_WARNING)
        .into_any_element()
}

pub(in crate::root) fn render_send_result(
    key: UnshieldAssetKey,
    result: &PreparedSendCall,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared send calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            send_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            send_element_id(key, "copy-data"),
        ))
}

pub(in crate::root) fn render_unshield_result(
    key: UnshieldAssetKey,
    result: &PreparedUnshieldCall,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            unshield_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            unshield_element_id(key, "copy-data"),
        ))
}

pub(in crate::root) fn render_unshield_copy_field(
    label: &'static str,
    value: String,
    button_id: SharedString,
) -> gpui::Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .p(px(8.0))
                .rounded_sm()
                .bg(rgb(theme::BACKGROUND))
                .border_1()
                .border_color(rgb(theme::BORDER))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(value.clone())),
        )
        .child(clipboard_with_toast(button_id, value))
}
