use std::path::PathBuf;

use gpui::{ParentElement, Pixels, SharedString, Styled, div, img, px, rgb};
use ui::theme;

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

pub(super) fn token_label_row(
    label: SharedString,
    icon_path: Option<PathBuf>,
    icon_size: Pixels,
) -> gpui::Div {
    let mut row = div().flex().items_center().gap_1();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(icon_size).rounded_full().flex_none());
    }
    row.child(label)
}
