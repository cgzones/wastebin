pub mod delete;
pub mod download;
pub mod extract;
pub mod html;
pub mod insert;
pub mod raw;
pub mod robots;
pub mod theme;

use std::sync::LazyLock;
use std::time::Instant;

use axum_extra::extract::cookie::{Cookie, SameSite};

pub(crate) static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Minimum number of seconds between two rate-limiting log messages.
pub(crate) const RATELIMIT_LOG_INTERVAL: u64 = 60;

/// Build a cookie with secure defaults: `HttpOnly`, `SameSite=Strict`, `Path=/`.
pub(crate) fn cookie(name: &str, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_owned(), value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie
}
