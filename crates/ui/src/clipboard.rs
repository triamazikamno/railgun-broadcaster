//! Shared copy affordance for the viewer UI.

use gpui::{App, ClipboardItem, ElementId, SharedString, Window};
use gpui_component::{WindowExt, clipboard::Clipboard, notification::Notification};

const COPIED_MESSAGE: &str = "Copied to clipboard!";

/// Render a copy button that writes to the clipboard and shows a confirmation toast.
pub fn clipboard_with_toast(id: impl Into<ElementId>, value: impl Into<SharedString>) -> Clipboard {
    Clipboard::new(id)
        .value(value)
        .on_copied(|_value, window, cx| {
            push_copied_toast(window, cx);
        })
}

/// Copy text to the clipboard and show the same confirmation toast as [`clipboard_with_toast`].
pub fn copy_to_clipboard_with_toast(
    value: impl Into<SharedString>,
    window: &mut Window,
    cx: &mut App,
) {
    let value = value.into();
    cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
    push_copied_toast(window, cx);
}

fn push_copied_toast(window: &mut Window, cx: &mut App) {
    window.push_notification(Notification::success(COPIED_MESSAGE), cx);
}
