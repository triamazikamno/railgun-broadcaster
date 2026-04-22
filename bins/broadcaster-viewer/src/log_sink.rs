use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::state::{LogEntry, Shared, now_unix_ms};

/// Bounded in-memory tracing layer: formats events into a [`LogEntry`] and
/// pushes them into the [`Shared`] ring buffer. It intentionally does NOT
/// notify the UI on every event — log churn would dominate the render loop.
/// The UI is woken by a periodic tick in `ui::root` that picks up new
/// entries at a bounded rate.
pub(crate) struct ViewerLogLayer {
    shared: Shared,
}

impl ViewerLogLayer {
    #[must_use]
    pub(crate) const fn new(shared: Shared) -> Self {
        Self { shared }
    }
}

impl<S> Layer<S> for ViewerLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let mut state = self.shared.write();
        let seq = state.next_log_seq();
        state.push_log(LogEntry {
            seq,
            unix_ms: now_unix_ms(),
            level: *metadata.level(),
            target: std::sync::Arc::from(metadata.target()),
            message: std::sync::Arc::from(visitor.into_message()),
        });
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    extras: String,
}

impl MessageVisitor {
    fn into_message(mut self) -> String {
        if !self.extras.is_empty() {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&self.extras);
        }
        self.message
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(&mut self.message, "{value:?}");
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::shared;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn bounded_retention_drops_oldest() {
        let shared = shared(4);
        let layer = ViewerLogLayer::new(shared.clone());
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for i in 0..10 {
                tracing::info!(iter = i, "log-line");
            }
        });
        let logs = shared.read().logs();
        assert_eq!(logs.len(), 4, "only the newest 4 entries should remain");
        assert!(logs.last().unwrap().message.contains("log-line"));
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let shared = shared(16);
        let layer = ViewerLogLayer::new(shared.clone());
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..5 {
                tracing::info!("tick");
            }
        });
        let logs = shared.read().logs();
        let seqs: Vec<u64> = logs.iter().map(|l| l.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }
}
