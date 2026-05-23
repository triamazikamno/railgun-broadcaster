use gpui::{Context, Entity, IntoElement, ParentElement, Render, Styled, Window, div, px, rgb};
use gpui_component::{Disableable, Sizable, checkbox::Checkbox, list::List};
use ui::controls::app_input;
use ui::theme;

use super::broadcaster_picker::{
    BroadcasterPickerContent, BroadcasterPickerDialogSnapshot, render_broadcaster_picker_header,
};
use super::private_action::delivery_element_id;
use super::{DeliveryFormKind, UnshieldAssetKey, WalletRoot};

pub(super) struct PrivateActionDialogContent {
    root: Entity<WalletRoot>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
}

#[derive(Clone, Copy)]
pub(super) enum PublicAccountDialogKind {
    Derive,
    Import,
    EditLabel,
}

impl PublicAccountDialogKind {
    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Derive => "Derive from private",
            Self::Import => "Import private key",
            Self::EditLabel => "Edit account label",
        }
    }
}

pub(super) struct PublicAccountDialogContent {
    root: Entity<WalletRoot>,
    kind: PublicAccountDialogKind,
    content_width: gpui::Pixels,
}

pub(super) struct PublicActionDialogContent {
    root: Entity<WalletRoot>,
    content_width: gpui::Pixels,
}

pub(super) struct PrivateBroadcasterProgressDialogContent {
    root: Entity<WalletRoot>,
    content_width: gpui::Pixels,
}

impl PrivateActionDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self { root, kind, key }
    }
}

impl Render for PrivateActionDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        match self.kind {
            DeliveryFormKind::Send => self
                .root
                .read(cx)
                .render_send_form(self.root.clone(), self.key),
            DeliveryFormKind::Unshield => self
                .root
                .read(cx)
                .render_unshield_form(self.root.clone(), self.key),
        }
    }
}

impl PublicAccountDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        kind: PublicAccountDialogKind,
        content_width: gpui::Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            kind,
            content_width,
        }
    }
}

impl Render for PublicAccountDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root.read(cx).render_public_account_dialog_content(
            self.root.clone(),
            self.kind,
            self.content_width,
        )
    }
}

impl PublicActionDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        content_width: gpui::Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for PublicActionDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_public_action_dialog_content(self.root.clone(), self.content_width)
    }
}

impl PrivateBroadcasterProgressDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        content_width: gpui::Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for PrivateBroadcasterProgressDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_private_broadcaster_progress_dialog_content(self.content_width)
    }
}

pub(super) struct BroadcasterPickerDialogContent {
    root: Entity<WalletRoot>,
}

impl BroadcasterPickerDialogContent {
    pub(super) fn new(root: Entity<WalletRoot>, cx: &mut Context<'_, Self>) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self { root }
    }
}

impl Render for BroadcasterPickerDialogContent {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let Some(snapshot) = self
            .root
            .read(cx)
            .broadcaster_picker_dialog_snapshot(window, cx)
        else {
            return div();
        };
        let BroadcasterPickerDialogSnapshot {
            query_input,
            list,
            rows,
            empty_message,
            generating,
            query,
            filtered_count,
            total_count,
            list_height,
            show_all_broadcasters,
            fee_bonus_popover_open,
            kind,
            key,
        } = snapshot;
        list.update(cx, |list, cx| {
            let content = BroadcasterPickerContent {
                rows,
                empty_message,
                generating,
                query,
            };
            if list.delegate_mut().set_content(content, cx) {
                cx.notify();
            }
        });

        let toggle_root = self.root.clone();
        div()
            .w_full()
            .h_full()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_input(&query_input).small().disabled(generating)),
                    )
                    .child(
                        Checkbox::new(delivery_element_id(key, kind, "show-all-broadcasters"))
                            .label("Show all broadcasters")
                            .checked(show_all_broadcasters)
                            .xsmall()
                            .disabled(generating)
                            .on_click(move |checked, _window, cx| {
                                let checked = *checked;
                                toggle_root.update(cx, |root, cx| {
                                    root.set_allow_suspicious_broadcasters(kind, key, checked, cx);
                                });
                            }),
                    ),
            )
            .child(render_broadcaster_picker_header(
                &self.root,
                &query_input,
                filtered_count,
                total_count,
                fee_bonus_popover_open,
            ))
            .child(
                List::new(&list)
                    .p(px(8.0))
                    .h(list_height)
                    .min_h(px(0.0))
                    .w_full()
                    .bg(rgb(theme::SURFACE)),
            )
    }
}

pub(super) struct RepairCacheDialogContent {
    root: Entity<WalletRoot>,
    content_width: gpui::Pixels,
}

impl RepairCacheDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        content_width: gpui::Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for RepairCacheDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_repair_cache_dialog_content(self.content_width)
    }
}

pub(super) struct AddWalletDialogContent {
    root: Entity<WalletRoot>,
    content_width: gpui::Pixels,
}

impl AddWalletDialogContent {
    pub(super) fn new(
        root: Entity<WalletRoot>,
        content_width: gpui::Pixels,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        Self {
            root,
            content_width,
        }
    }
}

impl Render for AddWalletDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.root
            .read(cx)
            .render_add_wallet_dialog_content(self.root.clone(), self.content_width)
    }
}
