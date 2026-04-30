//! Shared copy affordance for the viewer UI.

use gpui::{ElementId, SharedString};
use gpui_component::{WindowExt, clipboard::Clipboard, notification::Notification};

const COPIED_MESSAGE: &str = "Copied to clipboard!";

/// Render a copy button that writes to the clipboard and shows a confirmation toast.
pub fn clipboard_with_toast(id: impl Into<ElementId>, value: impl Into<SharedString>) -> Clipboard {
    Clipboard::new(id)
        .value(value)
        .on_copied(|_value, window, cx| {
            window.push_notification(Notification::success(COPIED_MESSAGE), cx);
        })
}
