use std::time::{Duration, Instant};

use gpui::{
    App, AppContext, Context, Entity, Focusable, InteractiveElement, IntoElement, ParentElement,
    Pixels, SharedString, StatefulInteractiveElement, Styled, WeakEntity, Window, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    IndexPath, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    input::{InputEvent, InputState},
    list::{ListDelegate, ListItem, ListState},
    popover::Popover,
    tooltip::Tooltip,
};
use railgun_ui::{chain_name, format_broadcaster_address_label, format_token_amount};
use ui::controls::{app_muted_text, app_strong_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    BroadcasterFeePolicy, BroadcasterFeePolicyStatus, PublicBroadcasterCandidate,
    PublicBroadcasterCostEstimate, PublicBroadcasterSelection,
    fee_policy_eligible_public_broadcasters, settings::EffectiveTokenRegistry,
    sort_specific_public_broadcasters,
};

use super::{
    BROADCASTER_PICKER_MAX_HEIGHT, DeliveryFormKind, PRIVATE_ASSET_LIST_WIDTH, UnshieldAssetKey,
    WalletRoot, dialogs::render_broadcaster_picker_dialog_content, token_display_label,
    token_display_metadata,
};

const BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const BROADCASTER_PICKER_DIALOG_CHROME_HEIGHT: Pixels = px(210.0);
pub(super) const BROADCASTER_PICKER_ROW_HEIGHT: Pixels = px(64.0);
pub(super) const BROADCASTER_PICKER_LIST_PADDING_HEIGHT: Pixels = px(16.0);
const BROADCASTER_PICKER_MIN_LIST_HEIGHT: Pixels = px(120.0);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum BroadcasterChoice {
    #[default]
    Random,
    Specific {
        railgun_address: String,
    },
}

pub(super) struct BroadcasterPickerState {
    pub(super) kind: DeliveryFormKind,
    pub(super) key: UnshieldAssetKey,
    pub(super) query_input: Entity<InputState>,
    pub(super) list: Entity<ListState<BroadcasterPickerDelegate>>,
    pub(super) fee_bonus_popover_open: bool,
}

#[derive(Clone, PartialEq)]
pub(super) struct BroadcasterPickerRow {
    pub(super) railgun_address: String,
    pub(super) label: String,
    pub(super) fee_label: String,
    pub(super) fee_warning: Option<String>,
    pub(super) reliability: f64,
    pub(super) selected: bool,
}

#[derive(Clone, PartialEq)]
pub(super) struct BroadcasterPickerContent {
    pub(super) rows: Vec<BroadcasterPickerRow>,
    pub(super) empty_message: SharedString,
    pub(super) generating: bool,
    pub(super) query: String,
}

pub(super) struct BroadcasterPickerDialogSnapshot {
    pub(super) query_input: Entity<InputState>,
    pub(super) list: Entity<ListState<BroadcasterPickerDelegate>>,
    pub(super) rows: Vec<BroadcasterPickerRow>,
    pub(super) empty_message: SharedString,
    pub(super) generating: bool,
    pub(super) query: String,
    pub(super) filtered_count: usize,
    pub(super) total_count: usize,
    pub(super) list_height: Pixels,
    pub(super) show_all_broadcasters: bool,
    pub(super) fee_bonus_popover_open: bool,
    pub(super) kind: DeliveryFormKind,
    pub(super) key: UnshieldAssetKey,
}

pub(super) struct BroadcasterPickerDelegate {
    root: WeakEntity<WalletRoot>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generating: bool,
    rows: Vec<BroadcasterPickerRow>,
    empty_message: SharedString,
    query: String,
    pending_content: Option<BroadcasterPickerContent>,
    last_live_update: Option<Instant>,
    live_update_scheduled: bool,
}

impl BroadcasterPickerDelegate {
    pub(super) fn new(
        root: WeakEntity<WalletRoot>,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
    ) -> Self {
        Self {
            root,
            kind,
            key,
            generating: false,
            rows: Vec::new(),
            empty_message: SharedString::from("No broadcasters match this search."),
            query: String::new(),
            pending_content: None,
            last_live_update: None,
            live_update_scheduled: false,
        }
    }

    pub(super) fn set_content(
        &mut self,
        content: BroadcasterPickerContent,
        cx: &Context<'_, ListState<Self>>,
    ) -> bool {
        if self.current_content_matches(&content) {
            return false;
        }

        if self.should_apply_immediately(&content) {
            self.pending_content = None;
            self.apply_content(content);
            self.last_live_update = Some(Instant::now());
            return true;
        }

        if self.last_live_update.is_some_and(|last_update| {
            last_update.elapsed() >= BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL
        }) {
            self.pending_content = None;
            self.apply_content(content);
            self.last_live_update = Some(Instant::now());
            return true;
        }

        if self.pending_content.as_ref() == Some(&content) {
            return false;
        }

        self.pending_content = Some(content);
        if !self.live_update_scheduled {
            self.live_update_scheduled = true;
            let remaining = self.last_live_update.map_or(
                BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL,
                |last_update| {
                    BROADCASTER_PICKER_LIVE_UPDATE_INTERVAL.saturating_sub(last_update.elapsed())
                },
            );
            cx.spawn(async move |this, cx| {
                cx.background_executor().timer(remaining).await;
                let _ = this.update(cx, |list, cx| {
                    let delegate = list.delegate_mut();
                    delegate.live_update_scheduled = false;
                    let Some(content) = delegate.pending_content.take() else {
                        return;
                    };
                    if !delegate.current_content_matches(&content) {
                        delegate.apply_content(content);
                        delegate.last_live_update = Some(Instant::now());
                        cx.notify();
                    }
                });
            })
            .detach();
        }
        false
    }

    fn current_content_matches(&self, content: &BroadcasterPickerContent) -> bool {
        self.rows == content.rows
            && self.empty_message == content.empty_message
            && self.generating == content.generating
            && self.query == content.query
    }

    fn should_apply_immediately(&self, content: &BroadcasterPickerContent) -> bool {
        self.last_live_update.is_none()
            || self.query != content.query
            || self.generating != content.generating
            || selected_broadcaster_address(&self.rows)
                != selected_broadcaster_address(&content.rows)
    }

    fn apply_content(&mut self, content: BroadcasterPickerContent) {
        self.rows = content.rows;
        self.empty_message = content.empty_message;
        self.generating = content.generating;
        self.query = content.query;
    }
}

fn selected_broadcaster_address(rows: &[BroadcasterPickerRow]) -> Option<&str> {
    rows.iter()
        .find(|row| row.selected)
        .map(|row| row.railgun_address.as_str())
}

impl WalletRoot {
    pub(super) fn public_broadcaster_selection(
        choice: &BroadcasterChoice,
    ) -> PublicBroadcasterSelection {
        match choice {
            BroadcasterChoice::Random => PublicBroadcasterSelection::Random,
            BroadcasterChoice::Specific { railgun_address } => {
                PublicBroadcasterSelection::Specific {
                    railgun_address: railgun_address.clone(),
                }
            }
        }
    }

    pub(super) fn public_broadcaster_submission_selection(
        choice: &BroadcasterChoice,
        cost_estimate: Option<&PublicBroadcasterCostEstimate>,
    ) -> PublicBroadcasterSelection {
        match choice {
            BroadcasterChoice::Random => {
                cost_estimate.map_or(PublicBroadcasterSelection::Random, |estimate| {
                    PublicBroadcasterSelection::Specific {
                        railgun_address: estimate.broadcaster.railgun_address.clone(),
                    }
                })
            }
            BroadcasterChoice::Specific { .. } => Self::public_broadcaster_selection(choice),
        }
    }

    pub(super) fn set_broadcaster_picker_fee_bonus_popover_open(
        &mut self,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(picker) = self.broadcaster_picker.as_mut() else {
            return;
        };
        if picker.fee_bonus_popover_open == open {
            return;
        }
        picker.fee_bonus_popover_open = open;
        cx.notify();
    }

    pub(super) fn open_broadcaster_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.broadcaster_picker.is_some() {
            return;
        }
        let Some((asset_label, chain_id, fee_token)) = (match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).map(|form| {
                (
                    form.asset.label.clone(),
                    form.asset.chain_id,
                    form.selected_fee_token,
                )
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.label.clone(),
                    form.asset.chain_id,
                    form.selected_fee_token,
                )
            }),
        }) else {
            return;
        };

        let query_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search broadcasters"));
        let focus_query_input = query_input.clone();
        cx.subscribe(&query_input, |_this, _input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        })
        .detach();
        let root = cx.weak_entity();
        let list = cx.new(|cx| {
            ListState::new(BroadcasterPickerDelegate::new(root, kind, key), window, cx)
                .selectable(false)
        });
        self.broadcaster_picker = Some(BroadcasterPickerState {
            kind,
            key,
            query_input,
            list,
            fee_bonus_popover_open: false,
        });
        self.refresh_public_broadcaster_anchor(kind, key, cx);
        Self::open_broadcaster_picker_dialog(
            format!(
                "{asset_label} · fee token {}",
                token_display_label(chain_id, fee_token, Some(&self.effective_token_registry))
            ),
            chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned),
            window,
            cx,
        );
        cx.defer_in(window, move |_this, window, cx| {
            focus_query_input.read(cx).focus_handle(cx).focus(window);
        });
        cx.notify();
    }

    fn open_broadcaster_picker_dialog(
        asset_label: String,
        chain_label: String,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            let dialog_width = (window.viewport_size().width * 0.92).min(PRIVATE_ASSET_LIST_WIDTH);
            let max_height = broadcaster_picker_dialog_height(window);
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .h(max_height)
                .title(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_strong_text("Choose public broadcaster"))
                        .child(app_muted_text(format!("{asset_label} on {chain_label}"))),
                )
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.close_broadcaster_picker(cx);
                    });
                })
                .child(render_broadcaster_picker_dialog_content(
                    &content_root,
                    window,
                    cx,
                ))
        });
    }

    pub(super) fn close_broadcaster_picker(&mut self, cx: &mut Context<'_, Self>) {
        self.broadcaster_picker = None;
        cx.notify();
    }

    pub(super) fn choose_broadcaster_from_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        railgun_address: String,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let choice = BroadcasterChoice::Specific { railgun_address };
        match kind {
            DeliveryFormKind::Send => self.set_send_broadcaster_choice(key, choice, cx),
            DeliveryFormKind::Unshield => self.set_unshield_broadcaster_choice(key, choice, cx),
        }
        self.broadcaster_picker = None;
        cx.notify();
        window.close_dialog(cx);
    }

    pub(super) fn broadcaster_picker_dialog_snapshot(
        &self,
        window: &Window,
        cx: &App,
    ) -> Option<BroadcasterPickerDialogSnapshot> {
        let picker = self.broadcaster_picker.as_ref()?;
        let (
            chain_id,
            token,
            unwrap,
            current_choice,
            generating,
            show_all_broadcasters,
            favorites_only,
        ) = (match picker.kind {
            DeliveryFormKind::Send => self.send_forms.get(&picker.key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    false,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                    form.favorites_only_broadcasters,
                )
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&picker.key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    form.unwrap,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                    form.favorites_only_broadcasters,
                )
            }),
        })?;
        let query = picker
            .query_input
            .read(cx)
            .value()
            .trim()
            .to_ascii_lowercase();
        let policy = self.public_broadcaster_fee_policy(show_all_broadcasters);
        let candidates = self.current_public_broadcaster_candidates(
            chain_id,
            token,
            unwrap,
            favorites_only,
            policy,
        );
        let candidates = if show_all_broadcasters {
            candidates
        } else {
            fee_policy_eligible_public_broadcasters(&candidates, policy)
        };
        let candidates = sort_specific_public_broadcasters(candidates);
        let total_count = candidates.len();
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| broadcaster_candidate_matches_query(candidate, &query))
            .collect();
        let filtered_count = candidates.len();
        let empty_message = SharedString::from(if total_count == 0 {
            "No eligible broadcaster currently advertises this token."
        } else {
            "No broadcasters match this search."
        });
        let rows = candidates
            .iter()
            .map(|candidate| BroadcasterPickerRow {
                railgun_address: candidate.railgun_address.clone(),
                label: broadcaster_candidate_label(candidate),
                fee_label: broadcaster_candidate_fee_label(
                    candidate,
                    Some(&self.effective_token_registry),
                ),
                fee_warning: broadcaster_candidate_fee_warning(candidate),
                reliability: candidate.reliability,
                selected: matches!(
                    current_choice,
                    BroadcasterChoice::Specific { railgun_address: ref selected } if selected == &candidate.railgun_address
                ),
            })
            .collect::<Vec<_>>();
        let list_height =
            broadcaster_picker_list_height(rows.len(), broadcaster_picker_dialog_height(window));
        Some(BroadcasterPickerDialogSnapshot {
            query_input: picker.query_input.clone(),
            list: picker.list.clone(),
            rows,
            empty_message,
            generating,
            query,
            filtered_count,
            total_count,
            list_height,
            show_all_broadcasters,
            fee_bonus_popover_open: picker.fee_bonus_popover_open,
            kind: picker.kind,
            key: picker.key,
        })
    }
}

fn broadcaster_picker_dialog_height(window: &Window) -> Pixels {
    (window.viewport_size().height * 0.82).min(BROADCASTER_PICKER_MAX_HEIGHT)
}

fn broadcaster_picker_list_height(row_count: usize, dialog_height: Pixels) -> Pixels {
    let target_height = (dialog_height - BROADCASTER_PICKER_DIALOG_CHROME_HEIGHT).max(px(0.0));
    broadcaster_picker_list_content_height(row_count)
        .max(BROADCASTER_PICKER_MIN_LIST_HEIGHT)
        .min(target_height)
}

fn broadcaster_picker_list_content_height(row_count: usize) -> Pixels {
    (0..row_count).fold(BROADCASTER_PICKER_LIST_PADDING_HEIGHT, |height, _row| {
        height + BROADCASTER_PICKER_ROW_HEIGHT
    })
}

impl ListDelegate for BroadcasterPickerDelegate {
    type Item = ListItem;

    fn items_count(&self, _section: usize, _cx: &App) -> usize {
        self.rows.len()
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn render_item(
        &mut self,
        ix: IndexPath,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) -> Option<Self::Item> {
        let row = self.rows.get(ix.row)?.clone();
        let root = self.root.clone();
        let kind = self.kind;
        let key = self.key;
        let selected = row.selected;
        let railgun_address = row.railgun_address.clone();
        Some(
            ListItem::new(SharedString::from(format!(
                "broadcaster-picker-list-row-{}",
                stable_broadcaster_element_suffix(&row.railgun_address)
            )))
            .h(BROADCASTER_PICKER_ROW_HEIGHT)
            .px(px(12.0))
            .py(px(0.0))
            .rounded_md()
            .border_1()
            .border_color(if selected {
                rgb(theme::SUCCESS)
            } else {
                rgb(theme::SURFACE)
            })
            .disabled(self.generating)
            .on_click(move |_event, window, cx| {
                cx.stop_propagation();
                let railgun_address = railgun_address.clone();
                let _ = root.update(cx, |root, cx| {
                    root.choose_broadcaster_from_picker(kind, key, railgun_address, window, cx);
                });
            })
            .child(render_broadcaster_picker_row(&row)),
        )
    }

    fn render_empty(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) -> impl IntoElement {
        div()
            .p(px(16.0))
            .rounded_md()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER))
            .child(app_muted_text(self.empty_message.clone()))
    }

    fn set_selected_index(
        &mut self,
        _ix: Option<IndexPath>,
        _window: &mut Window,
        _cx: &mut Context<'_, ListState<Self>>,
    ) {
    }

    fn is_eof(&self, _cx: &App) -> bool {
        false
    }
}

pub(super) fn selected_broadcaster_label(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
) -> String {
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return "Specific broadcaster".to_string();
    };
    candidates
        .iter()
        .find(|candidate| candidate.railgun_address == *railgun_address)
        .map_or_else(
            || "Specific unavailable".to_string(),
            broadcaster_candidate_label,
        )
}

pub(super) fn selected_broadcaster_fee_warning(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    allow_suspicious_broadcasters: bool,
) -> Option<String> {
    if allow_suspicious_broadcasters {
        return None;
    }
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return None;
    };
    candidates
        .iter()
        .find(|candidate| candidate.railgun_address == *railgun_address)
        .and_then(broadcaster_candidate_fee_warning)
}

const fn stable_broadcaster_element_suffix(railgun_address: &str) -> &str {
    railgun_address
}

pub(super) fn broadcaster_candidate_label(candidate: &PublicBroadcasterCandidate) -> String {
    format_broadcaster_address_label(&candidate.railgun_address, candidate.identifier.as_deref())
}

pub(super) fn broadcaster_candidate_fee_label(
    candidate: &PublicBroadcasterCandidate,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    match candidate.fee_policy_status {
        BroadcasterFeePolicyStatus::Normal { premium_bps, .. }
        | BroadcasterFeePolicyStatus::Suspicious {
            premium_bps: Some(premium_bps),
            ..
        } => return format_premium_bps_one_decimal(premium_bps),
        BroadcasterFeePolicyStatus::Suspicious {
            premium_bps: None, ..
        }
        | BroadcasterFeePolicyStatus::UnknownAnchor => {}
    }
    broadcaster_candidate_raw_fee_label(candidate, registry)
}

fn broadcaster_candidate_raw_fee_label(
    candidate: &PublicBroadcasterCandidate,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    token_display_metadata(registry, candidate.chain_id, &candidate.token).map_or_else(
        || candidate.fee.to_string(),
        |info| format_token_amount(candidate.fee, info.decimals),
    )
}

pub(super) fn broadcaster_candidate_fee_warning(
    candidate: &PublicBroadcasterCandidate,
) -> Option<String> {
    let BroadcasterFeePolicyStatus::Suspicious { premium_bps, .. } = candidate.fee_policy_status
    else {
        return None;
    };
    Some(match premium_bps {
        Some(premium_bps) => format!(
            "Fee outside allowed range ({})",
            format_premium_bps_compact(premium_bps)
        ),
        None => "Fee outside allowed range".to_string(),
    })
}

fn format_premium_bps_one_decimal(premium_bps: i128) -> String {
    let sign = if premium_bps >= 0 { "+" } else { "-" };
    let abs_bps = premium_bps.checked_abs().unwrap_or(i128::MAX);
    let tenths = (abs_bps + 5) / 10;
    format!("{sign}{}.{:01}%", tenths / 10, tenths % 10)
}

fn format_premium_bps_compact(premium_bps: i128) -> String {
    let sign = if premium_bps >= 0 { "+" } else { "-" };
    let abs_bps = premium_bps.checked_abs().unwrap_or(i128::MAX);
    let tenths = (abs_bps + 5) / 10;
    if tenths % 10 == 0 {
        format!("{sign}{}%", tenths / 10)
    } else {
        format!("{sign}{}.{:01}%", tenths / 10, tenths % 10)
    }
}

fn broadcaster_reliability_label(reliability: f64) -> String {
    format!("{:.2}", reliability.clamp(0.0, 1.0))
}

const fn broadcaster_reliability_color(reliability: f64) -> u32 {
    if reliability < 0.5 {
        theme::DANGER
    } else if reliability < 0.75 {
        theme::WARNING
    } else {
        theme::SUCCESS
    }
}

fn render_broadcaster_reliability_badge(reliability: f64) -> gpui::Div {
    let color = broadcaster_reliability_color(reliability);
    div()
        .flex_none()
        .w(px(52.0))
        .px(px(8.0))
        .py(px(4.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(color))
        .text_color(rgb(color))
        .text_size(px(12.0))
        .text_align(gpui::TextAlign::Center)
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(broadcaster_reliability_label(reliability))
}

pub(super) fn broadcaster_candidate_matches_query(
    candidate: &PublicBroadcasterCandidate,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    candidate
        .railgun_address
        .to_ascii_lowercase()
        .contains(query)
        || candidate.fees_id.to_ascii_lowercase().contains(query)
        || candidate
            .identifier
            .as_deref()
            .is_some_and(|identifier| identifier.to_ascii_lowercase().contains(query))
        || candidate.version.to_ascii_lowercase().contains(query)
        || candidate
            .token
            .to_checksum(None)
            .to_ascii_lowercase()
            .contains(query)
}

pub(super) fn render_broadcaster_picker_header(
    root: &Entity<WalletRoot>,
    query_input: &Entity<InputState>,
    filtered_count: usize,
    total_count: usize,
    fee_bonus_popover_open: bool,
) -> gpui::Div {
    let broadcaster_header = if filtered_count == total_count {
        format!("Broadcaster ({total_count})")
    } else {
        format!("Broadcaster ({filtered_count} of {total_count})")
    };
    div()
        .flex()
        .items_center()
        .gap_3()
        .px(px(20.0))
        .text_size(px(11.0))
        .text_color(rgb(theme::TEXT_MUTED))
        .child(div().flex_1().min_w(px(0.0)).child(broadcaster_header))
        .child(
            div()
                .w(px(150.0))
                .flex_none()
                .flex()
                .items_center()
                .gap_1()
                .child("Fee")
                .child({
                    let popover_root = root.clone();
                    let focus_query_input = query_input.clone();
                    let tooltip_enabled = !fee_bonus_popover_open;
                    Popover::new("broadcaster-picker-fee-bonus-popover")
                        .open(fee_bonus_popover_open)
                        .on_open_change(move |open, window, cx| {
                            popover_root.update(cx, |root, cx| {
                                root.set_broadcaster_picker_fee_bonus_popover_open(*open, cx);
                            });
                            if !*open {
                                focus_query_input.read(cx).focus_handle(cx).focus(window);
                            }
                        })
                        .trigger(
                            Button::new("broadcaster-picker-fee-bonus-trigger")
                                .text()
                                .xsmall()
                                .compact()
                                .child(render_fee_bonus_info_icon(tooltip_enabled)),
                        )
                        .content(|_state, _window, _cx| render_fee_bonus_popover())
                }),
        )
        .child(div().w(px(120.0)).flex_none().child("Reliability"))
}

fn render_fee_bonus_info_icon(tooltip_enabled: bool) -> impl IntoElement {
    div()
        .id("broadcaster-picker-fee-bonus-info")
        .size(px(14.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::WARNING))
        .text_color(rgb(theme::WARNING))
        .text_size(px(9.0))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
        .child("i")
        .when(tooltip_enabled, |this| {
            this.tooltip(|window, cx| {
                Tooltip::element(|_window, _cx| render_fee_bonus_popover()).build(window, cx)
            })
        })
}

fn render_fee_bonus_popover() -> gpui::Div {
    div()
        .w(px(360.0))
        .p(px(12.0))
        .flex()
        .flex_col()
        .gap_2()
        .text_size(px(12.0))
        .text_color(rgb(theme::TEXT))
        .child(
            div()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Fee bonus"),
        )
        .child(div().child(
            "Fee is the broadcaster's bonus over the estimated gas cost, not their total payout or profit.",
        ))
        .child(div().child(
            "Broadcasters still pay gas and later need to unshield this bonus, which has its own cost.",
        ))
        .child(div().child(
            "Very low or negative bonuses can be suspicious because the broadcaster may not cover their costs, which can lead to more failed submissions.",
        ))
}

fn render_broadcaster_picker_row(row: &BroadcasterPickerRow) -> gpui::Div {
    div()
        .w_full()
        .flex()
        .items_center()
        .gap_3()
        .text_size(APP_TEXT_SIZE)
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_family(APP_MONO_FONT_FAMILY)
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(row.label.clone()),
                ),
        )
        .child(
            div()
                .w(px(150.0))
                .flex_none()
                .flex()
                .flex_col()
                .gap_1()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(row.fee_label.clone())
                .children(row.fee_warning.clone().map(|warning| {
                    div()
                        .text_color(rgb(theme::DANGER))
                        .text_size(px(11.0))
                        .font_weight(gpui::FontWeight::NORMAL)
                        .child(warning)
                })),
        )
        .child(
            div()
                .w(px(120.0))
                .flex_none()
                .child(render_broadcaster_reliability_badge(row.reliability)),
        )
}

pub(super) fn broadcaster_choice_supported_by_candidates(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    policy: BroadcasterFeePolicy,
) -> bool {
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return true;
    };
    fee_policy_eligible_public_broadcasters(candidates, policy)
        .iter()
        .any(|candidate| candidate.railgun_address == *railgun_address)
}

pub(super) fn should_preserve_estimate_after_broadcaster_policy_change(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
    policy: BroadcasterFeePolicy,
) -> bool {
    matches!(choice, BroadcasterChoice::Specific { .. })
        && broadcaster_choice_supported_by_candidates(choice, candidates, policy)
}
