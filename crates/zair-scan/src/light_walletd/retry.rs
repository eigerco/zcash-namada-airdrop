//! Utility functions for Light Wallet Daemon (light-walletd).
//! Utility functions include retry logic with exponential backoff for handling transient errors.

use std::time::Duration;

use crate::light_walletd::config::ValidatedLightWalletdConfig;
use crate::light_walletd::error::LightWalletdError;

/// Calculates the delay for exponential backoff.
///
/// delay = `base_delay` × (`backoff_factor` ^ `attempt`)
fn calculate_backoff_delay(
    attempt: u32,
    base_delay: Duration,
    max_delay: Duration,
    backoff_factor: u32,
) -> Duration {
    let delay = base_delay
        .checked_mul(backoff_factor.saturating_pow(attempt))
        .unwrap_or(max_delay);

    delay.min(max_delay)
}

/// Retries an async operation with exponential backoff.
///
/// On transient errors (as determined by [`LightWalletdError::is_retryable`]), the operation is
/// retried.
///
/// # Type Parameters
///
/// * `F` - A closure that produces the future to retry. Called once per attempt.
/// * `Fut` - The future type returned by `F`.
/// * `T` - The success type.
/// * `E` - The error type, must be convertible to [`LightWalletdError`].
#[allow(
    clippy::arithmetic_side_effects,
    reason = "`attempt` can not overflow because it should always be less than `MAX_RETRIES`, which is far from the limits."
)]
pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &ValidatedLightWalletdConfig,
    mut operation: F,
) -> Result<T, LightWalletdError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Into<LightWalletdError>,
{
    let mut attempt = 0;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error = e.into();
                if attempt < config.max_retry_attempts && error.is_retryable() {
                    let delay = calculate_backoff_delay(
                        attempt,
                        config.initial_retry_delay,
                        config.max_retry_delay,
                        config.backoff_factor,
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                } else {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "Tests")]

    use tonic::Status;

    use super::*;
    use crate::light_walletd::LightWalletdConfig;

    pub fn test_config() -> ValidatedLightWalletdConfig {
        LightWalletdConfig {
            max_retry_attempts: 3,
            initial_retry_delay: Duration::from_millis(1),
            max_retry_delay: Duration::from_millis(10),
            backoff_factor: 2,
            ..Default::default()
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn validate_backoff_delay() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_secs(10);
        let backoff_factor = 2;

        // Exponential growth: 100, 200, 400, 800
        for i in 0..4 {
            let expected = initial.saturating_mul(2_u32.saturating_pow(i));
            assert_eq!(
                calculate_backoff_delay(i, initial, max, backoff_factor),
                expected
            );
        }

        // Capped at max
        assert_eq!(
            calculate_backoff_delay(10, Duration::from_millis(100), max, backoff_factor),
            max
        );

        // Max less than initial - still capped
        let max = Duration::from_secs(1);
        assert_eq!(
            calculate_backoff_delay(0, Duration::from_secs(10), max, 2),
            max
        );
    }

    #[test]
    fn backoff_edge_cases() {
        let max = Duration::from_secs(10);

        // Zero initial delay
        assert_eq!(
            calculate_backoff_delay(5, Duration::ZERO, max, 2),
            Duration::ZERO
        );

        // Saturates instead of overflow
        assert_eq!(
            calculate_backoff_delay(
                u32::MAX,
                Duration::from_secs(1000),
                Duration::from_secs(10),
                2
            ),
            Duration::from_secs(10)
        );
    }

    #[tokio::test]
    async fn succeeds_on_first_try() {
        let config = test_config();
        let mut call_count = 0_u32;

        let result = retry_with_backoff(&config, || {
            call_count += 1;
            async { Ok::<u32, LightWalletdError>(42) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn gives_up_after_max_retries() {
        let config = test_config();
        let mut call_count = 0_u32;

        let result: Result<u32, LightWalletdError> = retry_with_backoff(&config, || {
            call_count += 1;
            async { Err(LightWalletdError::Grpc(Status::unavailable("down"))) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 4); // 1 initial + 3 retries
    }

    #[tokio::test]
    async fn no_retry_for_non_transient() {
        let config = test_config();
        let mut call_count = 0_u32;

        let result: Result<u32, LightWalletdError> = retry_with_backoff(&config, || {
            call_count += 1;
            async { Err(LightWalletdError::Grpc(Status::not_found("missing"))) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn succeeds_on_last_retry() {
        let config = test_config();
        let mut call_count = 0_u32;

        let result: Result<u32, LightWalletdError> = retry_with_backoff(&config, || {
            let count = call_count;
            call_count += 1;
            async move {
                if count < 3 {
                    Err(LightWalletdError::Grpc(Status::unavailable("down")))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 4);
    }

    #[tokio::test]
    async fn stops_on_non_transient_after_transient() {
        let config = LightWalletdConfig {
            max_retry_attempts: 5,
            initial_retry_delay: Duration::from_millis(1),
            max_retry_delay: Duration::from_millis(10),
            backoff_factor: 2,
            ..Default::default()
        }
        .validate()
        .unwrap();

        let mut call_count = 0_u32;

        let result: Result<u32, LightWalletdError> = retry_with_backoff(&config, || {
            let count = call_count;
            call_count += 1;
            async move {
                if count == 0 {
                    Err(LightWalletdError::Grpc(Status::unavailable("down")))
                } else {
                    Err(LightWalletdError::Grpc(Status::not_found("missing")))
                }
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 2);
    }
}
