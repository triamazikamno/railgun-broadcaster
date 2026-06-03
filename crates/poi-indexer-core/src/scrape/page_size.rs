const UPSTREAM_MAX_PAGE_SIZE: usize = 500;
const GROW_AFTER_SUCCESSES: usize = 2;

#[derive(Debug, Clone)]
pub struct PageSizeAdapter {
    current_size: usize,
    max_size: usize,
    min_size: usize,
    consecutive_successes: usize,
    consecutive_failures: usize,
}

impl PageSizeAdapter {
    #[must_use]
    pub fn new(current_size: usize, max_size: usize, min_size: usize) -> Self {
        let max_size = max_size.clamp(1, UPSTREAM_MAX_PAGE_SIZE);
        let min_size = min_size.clamp(1, max_size);
        let current_size = current_size.clamp(min_size, max_size);

        Self {
            current_size,
            max_size,
            min_size,
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }

    #[must_use]
    pub const fn current_size(&self) -> usize {
        self.current_size
    }

    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    #[must_use]
    pub const fn min_size(&self) -> usize {
        self.min_size
    }

    #[must_use]
    pub const fn consecutive_successes(&self) -> usize {
        self.consecutive_successes
    }

    #[must_use]
    pub const fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    pub fn on_success(&mut self) {
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;

        if self.consecutive_successes < GROW_AFTER_SUCCESSES || self.current_size == self.max_size {
            return;
        }

        self.current_size = self.current_size.saturating_mul(2).min(self.max_size);
        self.consecutive_successes = 0;
    }

    pub fn on_failure(&mut self) {
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.current_size = (self.current_size / 2).max(self.min_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_shrinks_on_failures_and_floors_at_min() {
        let mut adapter = PageSizeAdapter::new(500, 500, 25);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 250);
        assert_eq!(adapter.consecutive_failures(), 1);
        assert_eq!(adapter.consecutive_successes(), 0);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 125);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 62);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 31);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 25);

        adapter.on_failure();
        assert_eq!(adapter.current_size(), 25);
    }

    #[test]
    fn page_size_grows_after_successes_and_caps_at_max() {
        let mut adapter = PageSizeAdapter::new(25, 100, 25);

        adapter.on_success();
        assert_eq!(adapter.current_size(), 25);
        assert_eq!(adapter.consecutive_successes(), 1);

        adapter.on_success();
        assert_eq!(adapter.current_size(), 50);
        assert_eq!(adapter.consecutive_successes(), 0);

        adapter.on_success();
        adapter.on_success();
        assert_eq!(adapter.current_size(), 100);

        adapter.on_success();
        adapter.on_success();
        assert_eq!(adapter.current_size(), 100);
    }
}
