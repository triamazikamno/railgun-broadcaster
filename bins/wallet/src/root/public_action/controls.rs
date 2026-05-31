use super::*;

pub(in crate::root) fn render_public_action_amount_input(
    root: Entity<WalletRoot>,
    mode: PublicActionMode,
    input: &Entity<InputState>,
    label: String,
    max_label: Option<String>,
    disabled: bool,
) -> gpui::Div {
    let max_root = root;
    let max_id = match mode {
        PublicActionMode::Shield => "wallet-public-shield-max",
        PublicActionMode::Send => "wallet-public-send-max",
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(app_muted_text(label))
                .children(max_label.map(|label| {
                    app_button(max_id, format!("Max: {label}"))
                        .link()
                        .xsmall()
                        .compact()
                        .disabled(disabled)
                        .on_click(move |_event, window, cx| {
                            max_root.update(cx, |root, cx| {
                                root.set_public_action_amount_to_max(mode, window, cx);
                            });
                        })
                })),
        )
        .child(app_input(input).disabled(disabled))
}

pub(in crate::root) fn public_action_segment_button(
    id: SharedString,
    label: &'static str,
    icon: impl Into<Icon>,
    selected: bool,
) -> Button {
    let button = Button::new(id)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_1()
                .text_size(APP_TEXT_SIZE)
                .child(icon.into().small())
                .child(label),
        );
    if selected { button.primary() } else { button }
}

pub(in crate::root) fn public_action_title_row(
    label: String,
    icon_path: Option<WalletIconSource>,
) -> gpui::Div {
    div().flex().items_center().gap_1().child(token_label_row(
        SharedString::from(label),
        icon_path,
        px(20.0),
    ))
}

pub(in crate::root) fn public_action_context_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label))
        .child(
            app_strong_text(value)
                .text_size(px(13.0))
                .font_family(APP_MONO_FONT_FAMILY),
        )
}

pub(in crate::root) fn render_public_action_active_status_notice(
    root: Entity<WalletRoot>,
    mode: PublicActionMode,
    step: &PublicActionStepState,
    requires_device_approval: bool,
    command_available: bool,
) -> gpui::Div {
    let step_kind = step.step;
    let discard_available = public_action_discard_attempt_available(command_available, step);
    let view_root = root.clone();
    let discard_root = root;
    let title = match (mode, step.status) {
        (PublicActionMode::Shield, PublicActionStepStatus::Error) => {
            "Public shield needs attention"
        }
        (PublicActionMode::Send, PublicActionStepStatus::Error) => "Public send needs attention",
        (PublicActionMode::Shield, _) => "Public shield in progress",
        (PublicActionMode::Send, _) => "Public send in progress",
    };
    let detail = format!(
        "{}: {}",
        public_action_step_label(step.step),
        public_action_step_detail_for_context(
            step.step,
            step.status,
            requires_device_approval,
            step.tx_hash.is_some(),
        )
    );
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::INFO))
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(app_strong_text(title))
                .child(app_muted_text(detail).whitespace_normal()),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .justify_end()
                .gap_2()
                .child(
                    app_button(
                        SharedString::from(format!(
                            "wallet-public-action-{}-view-progress",
                            public_action_step_id(step_kind)
                        )),
                        "View status",
                    )
                    .outline()
                    .small()
                    .on_click(move |_event, window, cx| {
                        view_root.update(cx, |root, cx| {
                            root.show_public_action_progress_dialog(window, cx);
                        });
                    }),
                )
                .when(discard_available, |this| {
                    this.child(
                        app_button(
                            SharedString::from(format!(
                                "wallet-public-action-{}-discard-attempt",
                                public_action_step_id(step_kind)
                            )),
                            "Discard attempt",
                        )
                        .danger()
                        .small()
                        .on_click(move |_event, _window, cx| {
                            discard_root.update(cx, |root, cx| {
                                root.discard_public_action_attempt(cx);
                            });
                        }),
                    )
                }),
        )
}

pub(in crate::root) fn render_public_action_progress_footer(
    root: Entity<WalletRoot>,
    action: ProgressFooterAction,
) -> gpui::Div {
    let button_root = root;
    let (id, label) = match action {
        ProgressFooterAction::Stop => ("wallet-public-action-stop", "Stop"),
        ProgressFooterAction::Close => ("wallet-public-action-close", "Close"),
    };
    let button = app_button(id, label).small().flex_none();
    let button = match action {
        ProgressFooterAction::Stop => button.danger().icon(Icon::new(RailgunActionIcon::Square)),
        ProgressFooterAction::Close => button.outline(),
    };
    div()
        .w_full()
        .flex()
        .justify_end()
        .pt(px(2.0))
        .child(button.on_click(move |_event, window, cx| {
            button_root.update(cx, |root, cx| match action {
                ProgressFooterAction::Stop => root.stop_public_action_progress(cx),
                ProgressFooterAction::Close => root.close_public_action_progress_dialog(window, cx),
            });
        }))
}

pub(in crate::root) fn public_action_closed_active_step(
    steps: &[PublicActionStepState],
) -> Option<&PublicActionStepState> {
    steps
        .iter()
        .find(|step| step.status == PublicActionStepStatus::Pending)
        .or_else(|| {
            steps
                .iter()
                .find(|step| step.status == PublicActionStepStatus::Error)
        })
}

pub(in crate::root) const fn public_action_mode_verb(mode: PublicActionMode) -> &'static str {
    match mode {
        PublicActionMode::Shield => "Shield",
        PublicActionMode::Send => "Send",
    }
}

pub(in crate::root) fn public_action_max_label(entry: &PublicBalanceEntry) -> Option<String> {
    if entry.asset.id == PublicAssetId::Native {
        return entry
            .amount
            .amount()
            .map(|_| format!("{} after est. gas", entry.asset.symbol));
    }
    entry.amount.amount().map(|_| {
        format!(
            "{} {}",
            public_balance_amount_label(&entry.amount, entry.asset.decimals),
            entry.asset.symbol,
        )
    })
}

pub(in crate::root) fn public_action_max_amount_after_reserve(
    amount: U256,
    reserve: U256,
) -> Option<U256> {
    (amount > reserve).then_some(amount - reserve)
}

pub(in crate::root) fn public_action_asset_label(
    chain_id: u64,
    asset: PublicAssetId,
    registry: Option<&wallet_ops::settings::EffectiveTokenRegistry>,
) -> String {
    match asset {
        PublicAssetId::Native => native_token_display_label(chain_id).to_string(),
        PublicAssetId::Erc20(_) => public_asset_label(chain_id, asset, registry),
    }
}
