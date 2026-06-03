use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    budget: usize,
    base_delay: Duration,
    max_delay: Duration,
}

impl RetryPolicy {
    #[must_use]
    pub const fn new(budget: usize, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            budget,
            base_delay,
            max_delay,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> usize {
        self.budget
    }

    #[must_use]
    pub const fn base_delay(&self) -> Duration {
        self.base_delay
    }

    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.max_delay
    }

    #[must_use]
    pub fn backoff_delay(&self, attempt: usize) -> Duration {
        let mut delay = self.base_delay;
        for _ in 0..attempt {
            delay = delay.saturating_mul(2);
            if delay >= self.max_delay {
                return self.max_delay;
            }
        }
        delay.min(self.max_delay)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetryError<E> {
    NoAttemptsConfigured,
    BudgetExhausted { attempts: usize, source: E },
}

pub async fn retry_with_backoff<F, Fut, T, E>(
    policy: &RetryPolicy,
    mut op: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    if policy.budget == 0 {
        return Err(RetryError::NoAttemptsConfigured);
    }

    let mut attempts = 0;
    loop {
        attempts += 1;
        match op().await {
            Ok(value) => return Ok(value),
            Err(source) if attempts >= policy.budget => {
                return Err(RetryError::BudgetExhausted { attempts, source });
            }
            Err(_) => tokio::time::sleep(policy.backoff_delay(attempts - 1)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retry_policy_honors_budget() {
        let policy = RetryPolicy::new(3, Duration::ZERO, Duration::ZERO);
        let mut attempts = 0;

        let result = retry_with_backoff(&policy, || {
            attempts += 1;
            async { Err::<(), _>("upstream unavailable") }
        })
        .await;

        assert_eq!(attempts, 3);
        assert_eq!(
            result,
            Err(RetryError::BudgetExhausted {
                attempts: 3,
                source: "upstream unavailable",
            })
        );
    }

    #[test]
    fn retry_policy_backoff_never_exceeds_max_delay() {
        let policy = RetryPolicy::new(5, Duration::from_secs(2), Duration::from_secs(30));

        assert_eq!(policy.backoff_delay(0), Duration::from_secs(2));
        assert_eq!(policy.backoff_delay(1), Duration::from_secs(4));
        assert_eq!(policy.backoff_delay(4), Duration::from_secs(30));
        assert_eq!(policy.backoff_delay(100), Duration::from_secs(30));
    }
}
