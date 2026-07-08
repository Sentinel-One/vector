use std::time::Duration;

// `tokio-retry` crate
// MIT License
// Copyright (c) 2017 Sam Rijs
//
/// A retry strategy driven by exponential back-off.
///
/// The power corresponds to the number of past attempts.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    current: u64,
    base: u64,
    factor: u64,
    max_delay: Option<Duration>,
}

impl ExponentialBackoff {
    /// Constructs a new exponential back-off strategy,
    /// given a base duration in milliseconds.
    ///
    /// The resulting duration is calculated by taking the base to the `n`-th power,
    /// where `n` denotes the number of past attempts.
    pub const fn from_millis(base: u64) -> ExponentialBackoff {
        ExponentialBackoff {
            current: base,
            base,
            factor: 1u64,
            max_delay: None,
        }
    }

    /// A multiplicative factor that will be applied to the retry delay.
    ///
    /// For example, using a factor of `1000` will make each delay in units of seconds.
    ///
    /// Default factor is `1`.
    pub const fn factor(mut self, factor: u64) -> ExponentialBackoff {
        self.factor = factor;
        self
    }

    /// Apply a maximum delay. No retry delay will be longer than this `Duration`.
    pub const fn max_delay(mut self, duration: Duration) -> ExponentialBackoff {
        self.max_delay = Some(duration);
        self
    }

    /// Resets the exponential back-off strategy to its initial state.
    pub fn reset(&mut self) {
        self.current = self.base;
    }
}

impl Iterator for ExponentialBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        let duration = if let Some(duration) = self.current.checked_mul(self.factor) {
            Duration::from_millis(duration)
        } else {
            Duration::from_millis(u64::MAX)
        };

        // check if we reached max delay
        if let Some(ref max_delay) = self.max_delay {
            if duration > *max_delay {
                return Some(*max_delay);
            }
        }

        if let Some(next) = self.current.checked_mul(self.base) {
            self.current = next;
        } else {
            self.current = u64::MAX;
        }

        Some(duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff_initial_delay() {
        let mut backoff = ExponentialBackoff::from_millis(2).factor(250);
        let first_delay = backoff.next().expect("backoff should produce a delay");

        assert_eq!(first_delay, Duration::from_millis(500));
        assert!(
            first_delay >= Duration::from_millis(100),
            "delay should be reasonable for network errors"
        );
    }

    #[test]
    fn test_exponential_backoff_doubles_each_retry() {
        let mut backoff = ExponentialBackoff::from_millis(2).factor(250);

        let delays: Vec<Duration> = (0..7).map(|_| backoff.next().unwrap()).collect();

        for i in 1..delays.len() {
            let ratio = delays[i].as_millis() as f64 / delays[i - 1].as_millis() as f64;
            assert!(
                (1.9..=2.1).contains(&ratio),
                "delay[{}] ({:?}) should be ~2x delay[{}] ({:?}), got ratio {}",
                i,
                delays[i],
                i - 1,
                delays[i - 1],
                ratio
            );
        }
    }

    #[test]
    fn test_exponential_backoff_max_delay_cap() {
        let mut backoff = ExponentialBackoff::from_millis(2)
            .factor(250)
            .max_delay(Duration::from_secs(60));

        for _ in 0..20 {
            backoff.next();
        }

        for i in 0..5 {
            let delay = backoff.next().expect("backoff should always produce delays");
            assert_eq!(
                delay,
                Duration::from_secs(60),
                "delay {} after cap should be 60s, got {:?}",
                i,
                delay
            );
        }
    }

    #[test]
    fn test_exponential_backoff_reset() {
        let mut backoff = ExponentialBackoff::from_millis(2).factor(250);

        for _ in 0..5 {
            backoff.next();
        }
        let high_delay = backoff.next().unwrap();
        assert!(
            high_delay > Duration::from_secs(1),
            "should have advanced beyond initial delay"
        );

        backoff.reset();
        let reset_delay = backoff.next().unwrap();
        assert_eq!(
            reset_delay,
            Duration::from_millis(500),
            "reset should return to initial 500ms delay"
        );
    }

    #[test]
    fn test_exponential_backoff_progression_prevents_tight_loops() {
        let mut backoff = ExponentialBackoff::from_millis(2).factor(250);

        let mut total_wait_time = Duration::ZERO;
        for _ in 0..10 {
            total_wait_time += backoff.next().unwrap();
        }

        assert!(
            total_wait_time >= Duration::from_secs(30),
            "10 retries should accumulate significant wait time, got {:?}",
            total_wait_time
        );
    }

    #[test]
    fn test_exponential_backoff_instances_are_independent() {
        let mut backoff1 = ExponentialBackoff::from_millis(2).factor(250);
        let mut backoff2 = ExponentialBackoff::from_millis(2).factor(250);

        backoff1.next();
        backoff1.next();
        let delay1 = backoff1.next().unwrap();

        let delay2 = backoff2.next().unwrap();

        assert_eq!(
            delay2,
            Duration::from_millis(500),
            "new backoff should start at 500ms"
        );
        assert!(delay1 > delay2, "advanced backoff should have higher delay");
    }

    #[test]
    fn test_exponential_backoff_with_custom_base() {
        let mut backoff = ExponentialBackoff::from_millis(10).factor(100);

        assert_eq!(backoff.next(), Some(Duration::from_millis(1000)));
        assert_eq!(backoff.next(), Some(Duration::from_millis(10000)));
        assert_eq!(backoff.next(), Some(Duration::from_millis(100000)));
    }

    #[test]
    fn test_exponential_backoff_without_max_delay() {
        let mut backoff = ExponentialBackoff::from_millis(2).factor(1000);

        assert_eq!(backoff.next(), Some(Duration::from_millis(2000)));
        assert_eq!(backoff.next(), Some(Duration::from_millis(4000)));
        assert_eq!(backoff.next(), Some(Duration::from_millis(8000)));
    }
}
