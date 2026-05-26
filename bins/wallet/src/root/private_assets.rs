use std::collections::BTreeMap;

use alloy::primitives::{Address, U256};
use gpui::{
    Context, Entity, InteractiveElement, IntoElement, ParentElement, SharedString, Styled, Window,
    div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{Disableable, Icon, IconName, Sizable, WindowExt, scroll::ScrollableElement};
use railgun_ui::{format_token_amount, format_usd_micro_value, short_address};
use ui::controls::{app_button, app_muted_text, app_strong_text};
use ui::theme::{self};
use wallet_ops::{
    ListUtxosOutput, TokenAnchorRateCache, TokenTotal,
    max_send_amount_from_outputs as planner_max_send_amount_from_outputs,
    max_unshield_amount_from_outputs as planner_max_unshield_amount_from_outputs,
    settings::EffectiveTokenRegistry,
};

use crate::assets::{RailgunActionIcon, WalletIconSource};

use super::chain_load::loading_summary;
use super::public_account::render_public_address_qr_dialog_content;
use super::{
    ChainUtxoState, PUBLIC_ADDRESS_QR_DIALOG_WIDTH, UnshieldAsset, WalletRoot, centered_message,
    parse_address, secondary_dialog_content_width, token_display_metadata,
};

#[cfg(test)]
use super::UnshieldAssetKey;

#[derive(Clone)]
pub(super) struct FormattedTokenTotal {
    pub(super) chain_id: u64,
    pub(super) token: Option<Address>,
    pub(super) label: String,
    pub(super) amount: String,
    pub(super) usd_micro_amount: Option<U256>,
    pub(super) usd_amount: Option<String>,
    pub(super) pending_poi_amount: String,
    pub(super) pending_incoming_amount: String,
    pub(super) pending_outgoing_amount: String,
    pub(super) total: Option<U256>,
    pub(super) poi_verified_total: Option<U256>,
    pub(super) pending_poi_total: Option<U256>,
    pub(super) pending_incoming_total: Option<U256>,
    pub(super) pending_outgoing_total: Option<U256>,
    pub(super) decimals: Option<u8>,
    pub(super) icon_path: Option<WalletIconSource>,
}

pub(super) fn max_unshield_amount_from_snapshot(
    snapshot: &ListUtxosOutput,
    token: Address,
) -> U256 {
    planner_max_unshield_amount_from_outputs(&snapshot.utxos, token)
}

pub(super) fn max_send_amount_from_snapshot(snapshot: &ListUtxosOutput, token: Address) -> U256 {
    planner_max_send_amount_from_outputs(&snapshot.utxos, token)
}

pub(super) fn format_private_asset_rows_from_snapshot(
    snapshot: &ListUtxosOutput,
    registry: Option<&EffectiveTokenRegistry>,
    anchor_cache: Option<&TokenAnchorRateCache>,
) -> Vec<FormattedTokenTotal> {
    let mut rows =
        format_private_asset_rows(snapshot.chain_id, &snapshot.totals, registry, anchor_cache);
    apply_pending_asset_amounts(snapshot, registry, anchor_cache, &mut rows);
    rows.sort_by_key(|b| std::cmp::Reverse(b.usd_micro_amount));
    rows
}

pub(super) fn format_private_asset_rows(
    chain_id: u64,
    totals: &[TokenTotal],
    registry: Option<&EffectiveTokenRegistry>,
    anchor_cache: Option<&TokenAnchorRateCache>,
) -> Vec<FormattedTokenTotal> {
    totals
        .iter()
        .map(|total| format_total_parts(chain_id, total, registry, anchor_cache))
        .collect()
}

pub(super) fn private_asset_display_amounts(
    asset: &FormattedTokenTotal,
) -> (String, Option<String>) {
    match asset.usd_amount.as_ref() {
        Some(usd_amount) => (
            usd_amount.clone(),
            Some(format!("{} {}", asset.amount, asset.label)),
        ),
        None => (asset.amount.clone(), None),
    }
}

pub(super) fn total_private_balance_usd_amount(rows: &[FormattedTokenTotal]) -> Option<String> {
    let mut total: Option<U256> = None;
    for amount in rows.iter().filter_map(|row| row.usd_micro_amount) {
        total = Some(match total {
            Some(total) => total.checked_add(amount)?,
            None => amount,
        });
    }
    total.map(format_usd_micro_value)
}

#[cfg(test)]
pub(super) fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let formatted = format_total_parts(chain_id, total, None, None);
    format!("{} {}", formatted.label, formatted.amount)
}

fn format_total_parts(
    chain_id: u64,
    total: &TokenTotal,
    registry: Option<&EffectiveTokenRegistry>,
    anchor_cache: Option<&TokenAnchorRateCache>,
) -> FormattedTokenTotal {
    let total_raw = U256::from_str_radix(&total.total, 10).ok();
    let poi_verified_total_raw = U256::from_str_radix(&total.poi_verified_total, 10).ok();
    let pending_poi_total = pending_poi_total(total_raw, poi_verified_total_raw);
    let Some(address) = parse_address(&total.token) else {
        return FormattedTokenTotal {
            chain_id,
            token: None,
            label: total.token.clone(),
            amount: total.total.clone(),
            usd_micro_amount: None,
            usd_amount: None,
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            pending_incoming_amount: "0".to_string(),
            pending_outgoing_amount: "0".to_string(),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            pending_incoming_total: Some(U256::ZERO),
            pending_outgoing_total: Some(U256::ZERO),
            decimals: None,
            icon_path: None,
        };
    };
    let Some(token) = token_display_metadata(registry, chain_id, &address) else {
        return FormattedTokenTotal {
            chain_id,
            token: Some(address),
            label: short_address(&address),
            amount: total.total.clone(),
            usd_micro_amount: None,
            usd_amount: None,
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            pending_incoming_amount: "0".to_string(),
            pending_outgoing_amount: "0".to_string(),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            pending_incoming_total: Some(U256::ZERO),
            pending_outgoing_total: Some(U256::ZERO),
            decimals: None,
            icon_path: None,
        };
    };
    let amount = total_raw.map_or_else(
        || total.total.clone(),
        |value| format_token_amount(value, token.decimals),
    );
    let usd_micro_amount = total_raw
        .and_then(|value| private_asset_usd_micro_amount(chain_id, address, value, anchor_cache));
    let usd_amount = usd_micro_amount.map(format_usd_micro_value);
    FormattedTokenTotal {
        chain_id,
        token: Some(address),
        label: token.symbol,
        amount,
        usd_micro_amount,
        usd_amount,
        pending_poi_amount: format_pending_poi_amount(pending_poi_total, Some(token.decimals)),
        pending_incoming_amount: "0".to_string(),
        pending_outgoing_amount: "0".to_string(),
        total: total_raw,
        poi_verified_total: poi_verified_total_raw,
        pending_poi_total,
        pending_incoming_total: Some(U256::ZERO),
        pending_outgoing_total: Some(U256::ZERO),
        decimals: Some(token.decimals),
        icon_path: token.icon_path,
    }
}

fn apply_pending_asset_amounts(
    snapshot: &ListUtxosOutput,
    registry: Option<&EffectiveTokenRegistry>,
    anchor_cache: Option<&TokenAnchorRateCache>,
    rows: &mut Vec<FormattedTokenTotal>,
) {
    let mut pending: BTreeMap<Address, (U256, U256)> = BTreeMap::new();
    for row in &snapshot.utxos {
        if !row.pending_new && !row.pending_spent && !row.local_pending_spent {
            continue;
        }
        let Some(token) = parse_address(&row.token) else {
            continue;
        };
        let Ok(value) = U256::from_str_radix(&row.value, 10) else {
            continue;
        };
        let entry = pending.entry(token).or_default();
        if row.pending_new {
            entry.0 += value;
        }
        if row.pending_spent || row.local_pending_spent {
            entry.1 += value;
        }
    }

    for (token, (incoming, outgoing)) in pending {
        let index = rows.iter().position(|row| row.token == Some(token));
        let row = if let Some(index) = index {
            &mut rows[index]
        } else {
            rows.push(format_total_parts(
                snapshot.chain_id,
                &TokenTotal {
                    token: token.to_checksum(None),
                    total: "0".to_string(),
                    poi_verified_total: "0".to_string(),
                },
                registry,
                anchor_cache,
            ));
            rows.last_mut().expect("pending row inserted")
        };
        row.pending_incoming_total = Some(incoming);
        row.pending_outgoing_total = Some(outgoing);
        row.pending_incoming_amount = format_pending_amount(incoming, row.decimals);
        row.pending_outgoing_amount = format_pending_amount(outgoing, row.decimals);
    }
}

fn private_asset_usd_micro_amount(
    chain_id: u64,
    token: Address,
    total: U256,
    anchor_cache: Option<&TokenAnchorRateCache>,
) -> Option<U256> {
    anchor_cache.and_then(|cache| cache.cached_token_usd_micro_value(chain_id, token, total))
}

fn pending_poi_total(total: Option<U256>, poi_verified_total: Option<U256>) -> Option<U256> {
    total
        .zip(poi_verified_total)
        .map(|(total, poi_verified_total)| total.saturating_sub(poi_verified_total))
}

fn format_pending_poi_amount(pending_poi_total: Option<U256>, decimals: Option<u8>) -> String {
    pending_poi_total.as_ref().map_or_else(
        || "0".to_string(),
        |value| {
            if let Some(decimals) = decimals {
                format_token_amount(*value, decimals)
            } else {
                value.to_string()
            }
        },
    )
}

fn format_pending_amount(value: U256, decimals: Option<u8>) -> String {
    decimals.map_or_else(
        || value.to_string(),
        |decimals| format_token_amount(value, decimals),
    )
}

pub(super) fn should_show_pending_poi_amount(pending_poi_total: Option<U256>) -> bool {
    pending_poi_total.is_some_and(|amount| !amount.is_zero())
}

pub(super) fn should_show_pending_amount(pending_total: Option<U256>) -> bool {
    pending_total.is_some_and(|amount| !amount.is_zero())
}

pub(super) fn build_unshield_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_unshield_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

pub(super) fn build_send_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_send_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

impl WalletRoot {
    fn open_private_receive_address_dialog(&self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let Some(address) = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok())
        else {
            return;
        };
        window.close_all_dialogs(cx);
        let dialog_width =
            (window.viewport_size().width * 0.92).min(PUBLIC_ADDRESS_QR_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let address_text = SharedString::from(address);
        let copy_id = SharedString::from("wallet-private-receive-address-copy");
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Private receive address"))
                .child(render_public_address_qr_dialog_content(
                    None,
                    address_text.clone(),
                    None,
                    copy_id.clone(),
                    content_width,
                ))
        });
    }

    pub(super) fn render_private_assets_body(&self, root: &Entity<Self>) -> gpui::AnyElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Error { message, .. }) => self
                .render_chain_error_body(root, message.as_ref())
                .into_any_element(),
            Some(ChainUtxoState::Loading { progress }) => {
                centered_message(loading_summary(*progress)).into_any_element()
            }
            Some(ChainUtxoState::Syncing {
                snapshot, progress, ..
            }) => self.render_private_asset_snapshot(root, snapshot, false, true, *progress),
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                self.render_private_asset_snapshot(root, snapshot, true, false, None)
            }
            Some(ChainUtxoState::Idle) | None => {
                centered_message("Select a chain to load private balances").into_any_element()
            }
        }
    }

    fn render_private_asset_snapshot(
        &self,
        root: &Entity<Self>,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
        syncing: bool,
        progress: Option<wallet_ops::SyncProgressUpdate>,
    ) -> gpui::AnyElement {
        let assets = format_private_asset_rows_from_snapshot(
            snapshot,
            Some(&self.effective_token_registry),
            Some(&self.public_broadcaster_anchor_cache),
        );
        let total_balance = total_private_balance_usd_amount(&assets);
        let receive_available = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok())
            .is_some();
        let send_asset = assets
            .iter()
            .find_map(|asset| build_send_asset(snapshot, asset));
        let unshield_asset = assets
            .iter()
            .find_map(|asset| build_unshield_asset(snapshot, asset));
        if assets.is_empty() {
            let message = if syncing {
                loading_summary(progress)
            } else {
                "No private assets found".to_string()
            };
            if receive_available {
                return Self::render_private_empty_state(root.clone(), message, receive_available)
                    .into_any_element();
            }
            return centered_message(message).into_any_element();
        }
        let has_total_balance = total_balance.is_some();

        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_y_scrollbar()
            .child(
                div()
                    .w(super::PRIVATE_ASSET_LIST_WIDTH)
                    .max_w_full()
                    .mx_auto()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .py(px(16.0))
                    .when_some(total_balance, |column, total_balance| {
                        column.child(Self::render_private_balance_hero(
                            root.clone(),
                            total_balance,
                            receive_available,
                            send_asset,
                            unshield_asset,
                            chain_ready,
                        ))
                    })
                    .when(!has_total_balance && receive_available, |column| {
                        column.child(Self::render_private_receive_action(
                            root.clone(),
                            receive_available,
                        ))
                    })
                    .children(assets.into_iter().enumerate().map(|(ix, asset)| {
                        Self::render_private_asset_row(
                            root.clone(),
                            ix,
                            asset,
                            snapshot,
                            chain_ready,
                        )
                        .into_any_element()
                    })),
            )
            .into_any_element()
    }

    fn render_private_empty_state(
        root: Entity<Self>,
        message: String,
        receive_available: bool,
    ) -> gpui::Div {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_3()
                    .child(app_muted_text(message))
                    .child(Self::render_private_receive_button(
                        root,
                        "wallet-private-empty-receive",
                        receive_available,
                    )),
            )
    }

    fn render_private_receive_action(root: Entity<Self>, receive_available: bool) -> gpui::Div {
        div()
            .w_full()
            .flex()
            .justify_center()
            .child(Self::render_private_receive_button(
                root,
                "wallet-private-standalone-receive",
                receive_available,
            ))
    }

    fn render_private_receive_button(
        root: Entity<Self>,
        id: &'static str,
        receive_available: bool,
    ) -> impl IntoElement {
        app_button(id, "Receive")
            .child(Icon::new(RailgunActionIcon::QrCode).small())
            .outline()
            .disabled(!receive_available)
            .tooltip("Show private receive address")
            .on_click(move |_event, window, cx| {
                root.update(cx, |root, cx| {
                    root.open_private_receive_address_dialog(window, cx);
                });
            })
    }

    fn render_private_balance_hero(
        root: Entity<Self>,
        total_balance: String,
        receive_available: bool,
        send_asset: Option<UnshieldAsset>,
        unshield_asset: Option<UnshieldAsset>,
        chain_ready: bool,
    ) -> gpui::Div {
        let receive_root = root.clone();
        let send_root = root.clone();
        let unshield_root = root;
        let can_send = chain_ready && send_asset.is_some();
        let can_unshield = chain_ready && unshield_asset.is_some();

        div()
            .w_full()
            .min_h(px(210.0))
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_4()
            .px(px(24.0))
            .py(px(34.0))
            .child(
                div()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .text_size(theme::ASSET_SYMBOL_TEXT_SIZE)
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Total private balance"),
            )
            .child(
                div()
                    .text_color(rgb(theme::WARNING))
                    .text_size(px(44.0))
                    .line_height(px(48.0))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(SharedString::from(total_balance)),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_center()
                    .gap_2()
                    .child(Self::render_private_receive_button(
                        receive_root,
                        "wallet-private-hero-receive",
                        receive_available,
                    ))
                    .child(
                        app_button("wallet-private-hero-send", "Send")
                            .child(Icon::new(RailgunActionIcon::Send).small())
                            .outline()
                            .disabled(!can_send)
                            .tooltip(if can_send {
                                "Prepare private send calldata"
                            } else if chain_ready {
                                "No sendable private asset available"
                            } else {
                                "Available after wallet sync finishes"
                            })
                            .on_click(move |_event, window, cx| {
                                let Some(asset) = send_asset.clone() else {
                                    return;
                                };
                                send_root.update(cx, |root, cx| {
                                    root.open_send_form(asset, window, cx);
                                });
                            }),
                    )
                    .child(
                        app_button("wallet-private-hero-unshield", "Unshield")
                            .child(Icon::new(IconName::Globe).small())
                            .outline()
                            .disabled(!can_unshield)
                            .tooltip(if can_unshield {
                                "Prepare unshield calldata"
                            } else if chain_ready {
                                "No unshieldable private asset available"
                            } else {
                                "Available after wallet sync finishes"
                            })
                            .on_click(move |_event, window, cx| {
                                let Some(asset) = unshield_asset.clone() else {
                                    return;
                                };
                                unshield_root.update(cx, |root, cx| {
                                    root.open_unshield_form(asset, window, cx);
                                });
                            }),
                    ),
            )
    }

    fn render_private_asset_row(
        root: Entity<Self>,
        ix: usize,
        asset: FormattedTokenTotal,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
    ) -> gpui::Div {
        let send_asset = build_send_asset(snapshot, &asset);
        let can_send = chain_ready && send_asset.is_some();
        let unshield_asset = build_unshield_asset(snapshot, &asset);
        let can_unshield = chain_ready && unshield_asset.is_some();
        let send_tooltip = if can_send {
            "Prepare private send calldata"
        } else if chain_ready {
            "Token cannot be sent from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let unshield_tooltip = if can_unshield {
            "Prepare unshield calldata"
        } else if chain_ready {
            "Token cannot be unshielded from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let send_opacity = if can_send { 1.0 } else { 0.5 };
        let unshield_opacity = if can_unshield { 1.0 } else { 0.5 };
        let show_pending_poi = should_show_pending_poi_amount(asset.pending_poi_total);
        let pending_poi_amount = asset.pending_poi_amount.clone();
        let show_pending_incoming = should_show_pending_amount(asset.pending_incoming_total);
        let show_pending_outgoing = should_show_pending_amount(asset.pending_outgoing_total);
        let pending_incoming_amount = asset.pending_incoming_amount.clone();
        let pending_outgoing_amount = asset.pending_outgoing_amount.clone();
        let (primary_amount, secondary_amount) = private_asset_display_amounts(&asset);
        let row_group = SharedString::from(format!("wallet-private-asset-row-{ix}"));
        let send_root = root.clone();
        let unshield_root = root;

        div()
            .group(row_group.clone())
            .w_full()
            .flex()
            .items_center()
            .gap_4()
            .p(px(16.0))
            .rounded_lg()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .items_center()
                    .text_size(theme::ASSET_SYMBOL_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(private_asset_label_row(
                        SharedString::from(asset.label.clone()),
                        asset.icon_path,
                    )),
            )
            .child(
                div()
                    .group(row_group.clone())
                    .flex()
                    .items_center()
                    .gap_2()
                    .opacity(0.0)
                    .group_hover(row_group, |this| this.opacity(1.0))
                    .hover(|this| this.opacity(1.0))
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-send-{ix}")),
                            "Send",
                        )
                        .child(Icon::new(RailgunActionIcon::Send).small())
                        .outline()
                        .disabled(!can_send)
                        .opacity(send_opacity)
                        .tooltip(send_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = send_asset.clone() else {
                                return;
                            };
                            send_root.update(cx, |root, cx| {
                                root.open_send_form(asset, window, cx);
                            });
                        }),
                    )
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-unshield-{ix}")),
                            "Unshield",
                        )
                        .child(Icon::new(IconName::Globe).small())
                        .outline()
                        .disabled(!can_unshield)
                        .opacity(unshield_opacity)
                        .tooltip(unshield_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = unshield_asset.clone() else {
                                return;
                            };
                            unshield_root.update(cx, |root, cx| {
                                root.open_unshield_form(asset, window, cx);
                            });
                        }),
                    ),
            )
            .child(
                div()
                    .min_w(px(150.0))
                    .flex()
                    .flex_col()
                    .items_end()
                    .child(
                        div()
                            .text_color(rgb(theme::WARNING))
                            .text_size(theme::BALANCE_TEXT_SIZE)
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(primary_amount)),
                    )
                    .when_some(secondary_amount, |column, secondary_amount| {
                        column.child(
                            app_muted_text(secondary_amount)
                                .whitespace_nowrap()
                                .text_align(gpui::TextAlign::Right),
                        )
                    })
                    .when(show_pending_poi, |column| {
                        column.child(private_asset_pending_label(format!(
                            "Pending POI: {pending_poi_amount}"
                        )))
                    })
                    .when(show_pending_incoming, |column| {
                        column.child(private_asset_pending_label(format!(
                            "Pending: +{pending_incoming_amount}"
                        )))
                    })
                    .when(show_pending_outgoing, |column| {
                        column.child(private_asset_pending_label(format!(
                            "Pending: -{pending_outgoing_amount}"
                        )))
                    }),
            )
    }
}

fn private_asset_label_row(label: SharedString, icon_path: Option<WalletIconSource>) -> gpui::Div {
    let mut row = div().flex().items_center().gap_2();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(px(32.0)).rounded_full().flex_none());
    }
    row.child(label)
}

fn private_asset_pending_label(label: impl Into<SharedString>) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_end()
        .gap_1()
        .text_color(rgb(theme::TEXT_MUTED))
        .text_size(px(12.0))
        .child(Icon::new(RailgunActionIcon::Clock).xsmall())
        .child(
            app_muted_text(label)
                .text_size(px(12.0))
                .whitespace_nowrap()
                .text_align(gpui::TextAlign::Right),
        )
}

pub(super) fn refresh_form_asset_from_snapshot(
    snapshot: &ListUtxosOutput,
    current: &UnshieldAsset,
    send: bool,
    registry: Option<&EffectiveTokenRegistry>,
) -> UnshieldAsset {
    let formatted = format_private_asset_rows(snapshot.chain_id, &snapshot.totals, registry, None)
        .into_iter()
        .find(|asset| asset.token == Some(current.token));
    let total = formatted
        .as_ref()
        .and_then(|asset| asset.total)
        .unwrap_or_default();
    let poi_verified_total = formatted
        .as_ref()
        .and_then(|asset| asset.poi_verified_total)
        .unwrap_or_default();
    let max_batched = if send {
        max_send_amount_from_snapshot(snapshot, current.token)
    } else {
        max_unshield_amount_from_snapshot(snapshot, current.token)
    };

    UnshieldAsset {
        chain_id: current.chain_id,
        token: current.token,
        label: formatted
            .as_ref()
            .map_or_else(|| current.label.clone(), |asset| asset.label.clone()),
        decimals: formatted
            .as_ref()
            .and_then(|asset| asset.decimals)
            .or(current.decimals),
        total,
        poi_verified_total,
        max_batched,
        icon_path: formatted
            .as_ref()
            .and_then(|asset| asset.icon_path.clone())
            .or_else(|| current.icon_path.clone()),
    }
}

#[cfg(test)]
pub(super) fn send_asset_key_from_formatted(
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAssetKey> {
    unshield_asset_key_from_formatted(asset)
}

#[cfg(test)]
pub(super) fn send_key_matches_asset(key: UnshieldAssetKey, asset: &FormattedTokenTotal) -> bool {
    send_asset_key_from_formatted(asset) == Some(key)
}

#[cfg(test)]
pub(super) fn unshield_asset_key_from_formatted(
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAssetKey> {
    asset
        .token
        .map(|token| UnshieldAssetKey::new(asset.chain_id, token))
}

#[cfg(test)]
pub(super) fn unshield_key_matches_asset(
    key: UnshieldAssetKey,
    asset: &FormattedTokenTotal,
) -> bool {
    unshield_asset_key_from_formatted(asset) == Some(key)
}
