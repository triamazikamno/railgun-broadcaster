use std::collections::BTreeMap;

use alloy::primitives::{Address, U256};
use gpui::{
    Entity, IntoElement, ParentElement, SharedString, Styled, div, img,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{Disableable, Icon, IconName, Sizable, scroll::ScrollableElement};
use railgun_ui::{format_token_amount, short_address};
use ui::controls::{app_button, app_muted_text};
use ui::theme::{self};
use wallet_ops::{
    ListUtxosOutput, TokenTotal,
    max_send_amount_from_outputs as planner_max_send_amount_from_outputs,
    max_unshield_amount_from_outputs as planner_max_unshield_amount_from_outputs,
    settings::EffectiveTokenRegistry,
};

use crate::assets::{RailgunActionIcon, WalletIconSource};

use super::chain_load::loading_summary;
use super::{
    ChainUtxoState, UnshieldAsset, WalletRoot, centered_message, parse_address,
    token_display_metadata,
};

#[cfg(test)]
use super::UnshieldAssetKey;

#[derive(Clone)]
pub(super) struct FormattedTokenTotal {
    pub(super) chain_id: u64,
    pub(super) token: Option<Address>,
    pub(super) label: String,
    pub(super) amount: String,
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
) -> Vec<FormattedTokenTotal> {
    let mut rows = format_private_asset_rows(snapshot.chain_id, &snapshot.totals, registry);
    apply_pending_asset_amounts(snapshot, registry, &mut rows);
    rows
}

pub(super) fn format_private_asset_rows(
    chain_id: u64,
    totals: &[TokenTotal],
    registry: Option<&EffectiveTokenRegistry>,
) -> Vec<FormattedTokenTotal> {
    totals
        .iter()
        .map(|total| format_total_parts(chain_id, total, registry))
        .collect()
}

#[cfg(test)]
pub(super) fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let formatted = format_total_parts(chain_id, total, None);
    format!("{} {}", formatted.label, formatted.amount)
}

fn format_total_parts(
    chain_id: u64,
    total: &TokenTotal,
    registry: Option<&EffectiveTokenRegistry>,
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
    FormattedTokenTotal {
        chain_id,
        token: Some(address),
        label: token.symbol,
        amount,
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
            ));
            rows.last_mut().expect("pending row inserted")
        };
        row.pending_incoming_total = Some(incoming);
        row.pending_outgoing_total = Some(outgoing);
        row.pending_incoming_amount = format_pending_amount(incoming, row.decimals);
        row.pending_outgoing_amount = format_pending_amount(outgoing, row.decimals);
    }
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
        let assets =
            format_private_asset_rows_from_snapshot(snapshot, Some(&self.effective_token_registry));
        if assets.is_empty() {
            return centered_message(if syncing {
                loading_summary(progress)
            } else {
                "No private assets found".to_string()
            })
            .into_any_element();
        }

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
        let send_root = root.clone();
        let unshield_root = root;

        div()
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
                    .min_w(px(150.0))
                    .flex()
                    .flex_col()
                    .items_end()
                    .child(
                        div()
                            .text_color(rgb(theme::WARNING))
                            .text_size(theme::BALANCE_TEXT_SIZE)
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(asset.amount)),
                    )
                    .when(show_pending_poi, |column| {
                        column.child(
                            app_muted_text(format!("*Pending POI: {pending_poi_amount}"))
                                .whitespace_nowrap()
                                .text_align(gpui::TextAlign::Right),
                        )
                    })
                    .when(show_pending_incoming, |column| {
                        column.child(
                            app_muted_text(format!("Pending: +{pending_incoming_amount}"))
                                .whitespace_nowrap()
                                .text_align(gpui::TextAlign::Right),
                        )
                    })
                    .when(show_pending_outgoing, |column| {
                        column.child(
                            app_muted_text(format!("Pending: -{pending_outgoing_amount}"))
                                .whitespace_nowrap()
                                .text_align(gpui::TextAlign::Right),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
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
    }
}

fn private_asset_label_row(label: SharedString, icon_path: Option<WalletIconSource>) -> gpui::Div {
    let mut row = div().flex().items_center().gap_2();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(px(32.0)).rounded_full().flex_none());
    }
    row.child(label)
}

pub(super) fn refresh_form_asset_from_snapshot(
    snapshot: &ListUtxosOutput,
    current: &UnshieldAsset,
    send: bool,
    registry: Option<&EffectiveTokenRegistry>,
) -> UnshieldAsset {
    let formatted = format_private_asset_rows(snapshot.chain_id, &snapshot.totals, registry)
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
