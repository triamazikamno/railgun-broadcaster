use gpui::{
    Div, ElementId, Entity, FontWeight, ParentElement, SharedString, Styled, div, px, relative, rgb,
};
use gpui_component::Sizable;
use gpui_component::button::Button;
use gpui_component::input::{Input, InputState};

use crate::theme::{self, APP_TEXT_SIZE};

#[must_use]
pub fn app_input(state: &Entity<InputState>) -> Input {
    Input::new(state).xsmall().px(px(8.0)).py(px(13.0))
}

#[must_use]
pub fn app_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    app_button_base(id).child(app_button_label(label))
}

#[must_use]
pub fn app_button_base(id: impl Into<ElementId>) -> Button {
    Button::new(id)
}

#[must_use]
pub fn app_button_label(label: impl Into<SharedString>) -> Div {
    app_text(label).flex_none()
}

#[must_use]
pub fn app_text(label: impl Into<SharedString>) -> Div {
    div()
        .text_size(APP_TEXT_SIZE)
        .line_height(relative(1.0))
        .child(label.into())
}

#[must_use]
pub fn app_muted_text(label: impl Into<SharedString>) -> Div {
    app_text(label).text_color(rgb(theme::TEXT_MUTED))
}

#[must_use]
pub fn app_strong_text(label: impl Into<SharedString>) -> Div {
    app_text(label)
        .text_color(rgb(theme::TEXT))
        .font_weight(FontWeight::SEMIBOLD)
}
