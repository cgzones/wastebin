pub mod delete;
pub mod download;
pub mod extract;
pub mod health;
pub mod html;
pub mod insert;
pub mod raw;
pub mod robots;
pub mod theme;

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum_extra::extract::cookie::{Cookie, SameSite};
use ratelimit::Ratelimiter;

use crate::Error;
use crate::handlers::extract::serialize_uids;

static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Minimum number of seconds between two rate-limiting log messages.
const RATELIMIT_LOG_INTERVAL: u64 = 60;

/// Build a cookie with secure defaults: `HttpOnly`, `SameSite=Strict`, `Path=/`.
pub(crate) fn cookie(name: &str, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_owned(), value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie
}

/// Build the signed `uid` cookie carrying the client's uid list.
pub(crate) fn uid_cookie(uids: &[i64]) -> Cookie<'static> {
    let mut cookie = cookie("uid", serialize_uids(uids));
    cookie.set_secure(true);
    cookie
}

/// Take a token from `limiter`, logging `what` at most once per minute.
///
/// `logged` holds the next second (since `START`) at which logging is allowed again.
pub(crate) fn check_ratelimit(
    limiter: Option<&Ratelimiter>,
    logged: &AtomicU64,
    what: &str,
) -> Result<(), Error> {
    let Some(limiter) = limiter else {
        return Ok(());
    };

    if limiter.try_wait().is_err() {
        let now = START.elapsed().as_secs();
        let deadline = logged.load(Ordering::Relaxed);
        if now >= deadline
            && logged
                .compare_exchange(
                    deadline,
                    now.saturating_add(RATELIMIT_LOG_INTERVAL),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            tracing::info!("Rate limiting {what}");
        }

        return Err(Error::RateLimit);
    }

    Ok(())
}
