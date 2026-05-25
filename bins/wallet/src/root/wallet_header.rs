use std::sync::Arc;

use gpui::{
    App, Context, Entity, InteractiveElement, IntoElement, ParentElement, Pixels, SharedString,
    StatefulInteractiveElement, Styled, Window, div, img, px, rgb,
};
use gpui_component::{
    IconName, Sizable, WindowExt,
    dialog::DialogButtonProps,
    divider::Divider,
    menu::{DropdownMenu, PopupMenuItem},
    select::{Select, SelectItem},
    tooltip::Tooltip,
};
use railgun_ui::{chain_icon_path, chain_name};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button_base, app_input, app_muted_text, app_strong_text};
use ui::{icons, theme};
use wallet_ops::vault::WalletSource;

use super::utxo::short_hash;
use super::{
    APP_TEXT_SIZE, ChainUtxoState, WalletRoot, chain_load_overrides, secondary_dialog_content_width,
};

#[derive(Clone)]
pub(super) struct WalletSelectItem {
    pub(super) wallet_id: Arc<str>,
    pub(super) label: Arc<str>,
}

impl SelectItem for WalletSelectItem {
    type Value = Arc<str>;

    fn title(&self) -> SharedString {
        SharedString::from(self.label.to_string())
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(wallet_label_row(SharedString::from(self.label.to_string())).into_any_element())
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        wallet_label_row(SharedString::from(self.label.to_string()))
    }

    fn value(&self) -> &Self::Value {
        &self.wallet_id
    }

    fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        self.label.to_lowercase().contains(&query) || self.wallet_id.to_lowercase().contains(&query)
    }
}

#[derive(Clone, Copy)]
pub(super) struct ChainSelectItem {
    pub(super) chain_id: u64,
}

impl SelectItem for ChainSelectItem {
    type Value = u64;

    fn title(&self) -> SharedString {
        SharedString::from(
            chain_name(self.chain_id).map_or_else(|| self.chain_id.to_string(), str::to_owned),
        )
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(chain_label_row(self.chain_id).into_any_element())
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        chain_label_row(self.chain_id)
    }

    fn value(&self) -> &Self::Value {
        &self.chain_id
    }
}

impl WalletRoot {
    pub(super) fn repair_wallet_cache_from_input(&mut self, cx: &mut Context<'_, Self>) -> bool {
        if self
            .chain_states
            .get(&self.selected_chain)
            .is_some_and(ChainUtxoState::is_syncing)
        {
            self.repair_cache_error = Some(Arc::from(
                "Wait for wallet sync to finish before repairing the cache",
            ));
            cx.notify();
            return false;
        }

        let raw_block = self.repair_cache_block_input.read(cx).value();
        let rewind_from = match parse_repair_cache_block(raw_block.as_ref()) {
            Ok(rewind_from) => rewind_from,
            Err(message) => {
                self.repair_cache_error = Some(Arc::from(message));
                cx.notify();
                return false;
            }
        };

        let mut overrides = chain_load_overrides();
        overrides.init_block_number = rewind_from;
        overrides.sync_to_block = None;
        overrides.rewind_wallet_cache = true;
        self.repair_cache_error = None;
        self.start_chain_load(self.selected_chain, &overrides, true, cx);
        cx.notify();
        true
    }

    fn open_repair_cache_dialog(window: &mut Window, cx: &mut Context<'_, Self>) {
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(px(420.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let submit_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text("Repair wallet cache"))
                .button_props(DialogButtonProps::default().ok_text("Repair"))
                .footer(|ok, _, window, cx| vec![ok(window, cx)])
                .on_ok(move |_event, _window, cx| {
                    submit_root.update(cx, Self::repair_wallet_cache_from_input)
                })
                .child(
                    content_root
                        .read(cx)
                        .render_repair_cache_dialog_content(content_width),
                )
        });
    }

    pub(super) fn render_wallet_header(&self, root: &Entity<Self>) -> impl IntoElement {
        let lock_root = root.clone();
        let receive_address = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok());

        div()
            .h(px(52.0))
            .flex_none()
            .flex()
            .items_center()
            .gap_3()
            .px(px(14.0))
            .bg(rgb(theme::SURFACE))
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(self.render_wallet_selector())
                    .child(self.render_wallet_actions_menu(root.clone())),
            )
            .child(self.render_chain_selector())
            .child(div().flex_1())
            .children(receive_address.clone().map(|address| {
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .text_color(rgb(theme::TEAL))
                    .child(SharedString::from(short_hash(&address)))
                    .child(clipboard_with_toast("wallet-receive-address-copy", address))
            }))
            .children(receive_address.map(|_| header_divider()))
            .child(
                app_button_base("wallet-lock-vault")
                    .outline()
                    .xsmall()
                    .px(px(10.0))
                    .py(px(15.0))
                    .tooltip("Lock vault")
                    .child(img(icons::lock_icon_path()).size(px(12.0)).flex_none())
                    .on_click(move |_event, window, cx| {
                        lock_root.update(cx, |root, cx| {
                            root.lock_vault(window, cx);
                        });
                    }),
            )
    }

    fn render_wallet_actions_menu(&self, root: Entity<Self>) -> impl IntoElement {
        let disabled = matches!(
            self.chain_states.get(&self.selected_chain),
            Some(state) if state.is_syncing()
        );
        let add_root = root.clone();
        let manage_root = root.clone();
        let repair_root = root;

        app_button_base("wallet-actions-menu-trigger")
            .outline()
            .xsmall()
            .h(px(24.0))
            .w(px(28.0))
            .tooltip("Wallet actions")
            .icon(IconName::Ellipsis)
            .dropdown_menu(move |menu, _window, _cx| {
                let add_root = add_root.clone();
                let manage_root = manage_root.clone();
                let repair_root = repair_root.clone();
                menu.min_w(px(190.0))
                    .item(
                        PopupMenuItem::new("Add wallet")
                            .icon(IconName::Plus)
                            .on_click(move |_event, window, cx| {
                                add_root.update(cx, |root, cx| {
                                    root.open_add_wallet_dialog(window, cx);
                                });
                            }),
                    )
                    .item(PopupMenuItem::new("Manage wallets").on_click(
                        move |_event, window, cx| {
                            manage_root.update(cx, |root, cx| {
                                root.open_manage_wallets_dialog(window, cx);
                            });
                        },
                    ))
                    .item(
                        PopupMenuItem::new("Repair wallet cache")
                            .disabled(disabled)
                            .on_click(move |_event, window, cx| {
                                repair_root.update(cx, |_root, cx| {
                                    Self::open_repair_cache_dialog(window, cx);
                                });
                            }),
                    )
            })
    }

    pub(super) fn render_repair_cache_dialog_content(&self, content_width: Pixels) -> gpui::Div {
        let input = self.repair_cache_block_input.clone();
        let error = self.repair_cache_error.clone();
        let start_block = self.selected_chain_wallet_start_block();
        let help_text = repair_cache_help_text(start_block.is_some());
        let start_block_hint = start_block.map(|start_block| {
            let hint_input = input.clone();
            let value = start_block.to_string();
            let label = match self.selected_wallet_source() {
                WalletSource::Generated => "generated wallet start block",
                WalletSource::Imported => "wallet init block",
            };

            div()
                .id("wallet-repair-current-start-block")
                .w_full()
                .px(px(8.0))
                .py(px(6.0))
                .rounded_sm()
                .cursor_pointer()
                .text_size(APP_TEXT_SIZE)
                .text_color(rgb(theme::PRIMARY))
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                .tooltip(|window, cx| {
                    Tooltip::new("Fill repair block with this start block").build(window, cx)
                })
                .on_click(move |_event, window, cx| {
                    hint_input.update(cx, |input, cx| {
                        input.set_value(&value, window, cx);
                    });
                })
                .child(SharedString::from(format!("Use {label}: {start_block}")))
        });

        div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .child(app_muted_text(help_text))
            .children(start_block_hint)
            .child(app_input(&input))
            .children(error.as_ref().map(|message| {
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::DANGER))
                    .child(SharedString::from(message.to_string()))
            }))
    }

    fn render_wallet_selector(&self) -> impl IntoElement {
        div().h(px(24.0)).w(px(180.0)).flex().items_center().child(
            Select::new(&self.wallet_select)
                .appearance(false)
                .small()
                .w(px(180.0))
                .h(px(24.0))
                .menu_width(px(220.0))
                .search_placeholder("Search wallets"),
        )
    }

    fn render_chain_selector(&self) -> impl IntoElement {
        div().h(px(24.0)).w(px(130.0)).flex().items_center().child(
            Select::new(&self.chain_select)
                .appearance(false)
                .small()
                .w(px(130.0))
                .h(px(24.0))
                .menu_width(px(150.0)),
        )
    }
}

fn chain_label_row(chain_id: u64) -> impl IntoElement {
    let label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned);
    let mut row = div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE);
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(px(16.0)).flex_none());
    }
    row.child(SharedString::from(label))
}

fn wallet_label_row(label: SharedString) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE)
        .child(img(icons::wallet_icon_path()).size(px(16.0)).flex_none())
        .child(label)
}

fn header_divider() -> impl IntoElement {
    Divider::vertical()
        .h(px(18.0))
        .mx(px(2.0))
        .color(rgb(theme::BORDER))
}

pub(super) fn parse_repair_cache_block(raw: &str) -> Result<Option<u64>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let block = trimmed
        .parse::<u64>()
        .map_err(|_| "Enter a block number, or 0 for deployment block.")?;
    Ok(Some(block))
}

pub(super) const fn repair_cache_help_text(has_start_block_hint: bool) -> &'static str {
    if has_start_block_hint {
        "Rewind and rescan this chain's wallet cache. Use 0 for deployment block, or use the wallet start block below."
    } else {
        "Rewind and rescan this chain's wallet cache. Use 0 for deployment block."
    }
}
