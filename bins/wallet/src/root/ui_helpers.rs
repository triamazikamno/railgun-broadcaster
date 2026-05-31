use gpui::{IntoElement, ParentElement, Pixels, SharedString, Styled, Window, div, img, px, rgb};
use gpui_component::scroll::ScrollableElement;
use ui::controls::app_muted_text;
use ui::theme;

use crate::assets::WalletIconSource;

const DIALOG_CONTENT_HORIZONTAL_INSET: Pixels = px(56.0);

pub(super) fn rgb_with_alpha(hex: u32, alpha: f32) -> gpui::Rgba {
    let mut color = rgb(hex);
    color.a = alpha;
    color
}

pub(super) fn centered_message(message: impl Into<SharedString>) -> gpui::Div {
    let message = message.into();
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .child(message)
}

pub(super) fn secondary_dialog_content_width(dialog_width: Pixels) -> Pixels {
    (dialog_width - DIALOG_CONTENT_HORIZONTAL_INSET).max(px(0.0))
}

pub(super) fn dialog_max_height(window: &Window) -> Pixels {
    window.viewport_size().height * 0.84
}

pub(super) fn dialog_content_max_height(window: &Window) -> Pixels {
    window.viewport_size().height * 0.74
}

pub(super) fn scrollable_dialog_content(
    max_height: Pixels,
    content: impl IntoElement,
) -> impl IntoElement {
    div()
        .max_h(max_height)
        .min_h(px(0.0))
        .overflow_y_scrollbar()
        .child(content)
}

pub(super) fn labeled_field(
    label: impl Into<SharedString>,
    content: impl IntoElement,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(app_muted_text(label))
        .child(content)
}

pub(super) fn token_label_row(
    label: SharedString,
    icon_path: Option<WalletIconSource>,
    icon_size: Pixels,
) -> gpui::Div {
    let mut row = div().flex().items_center().gap_1();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(icon_size).rounded_full().flex_none());
    }
    row.child(label)
}
