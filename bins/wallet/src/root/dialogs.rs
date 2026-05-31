use gpui::{App, Entity, ParentElement, Styled, Window, div, px, rgb};
use gpui_component::{Disableable, Icon, Sizable, checkbox::Checkbox, list::List};
use ui::controls::app_input;
use ui::theme;

use crate::assets::CHEVRONS_DOWN_ICON_PATH;

use super::WalletRoot;
use super::broadcaster_picker::{
    BROADCASTER_PICKER_LIST_PADDING_HEIGHT, BROADCASTER_PICKER_ROW_HEIGHT,
    BroadcasterPickerContent, BroadcasterPickerDialogSnapshot, render_broadcaster_picker_header,
};
use super::private_action::delivery_element_id;

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

pub(super) fn render_broadcaster_picker_dialog_content(
    root: &Entity<WalletRoot>,
    window: &Window,
    cx: &mut App,
) -> gpui::Div {
    let Some(snapshot) = root.read(cx).broadcaster_picker_dialog_snapshot(window, cx) else {
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
    let hidden_row_count = hidden_broadcaster_picker_row_count(rows.len(), list_height);
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

    let toggle_root = root.clone();
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
            root,
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
        .children(render_broadcaster_picker_scroll_hint(hidden_row_count))
}

fn hidden_broadcaster_picker_row_count(row_count: usize, list_height: gpui::Pixels) -> usize {
    let visible_row_count = visible_broadcaster_picker_row_count(list_height);
    row_count.saturating_sub(visible_row_count)
}

fn visible_broadcaster_picker_row_count(list_height: gpui::Pixels) -> usize {
    let mut visible_row_count = 0;
    let mut content_height = BROADCASTER_PICKER_LIST_PADDING_HEIGHT;

    loop {
        let next_height = content_height + BROADCASTER_PICKER_ROW_HEIGHT;
        if next_height > list_height {
            break visible_row_count;
        }
        visible_row_count += 1;
        content_height = next_height;
    }
}

fn render_broadcaster_picker_scroll_hint(hidden_row_count: usize) -> Option<gpui::Div> {
    if hidden_row_count == 0 {
        return None;
    }

    Some(
        div()
            .w_full()
            .flex()
            .items_center()
            .gap_1()
            .px(px(8.0))
            .pt(px(3.0))
            .text_size(px(11.0))
            .text_color(rgb(theme::TEXT_MUTED))
            .child(Icon::empty().path(CHEVRONS_DOWN_ICON_PATH).size(px(15.0)))
            .child("Scroll for more"),
    )
}
