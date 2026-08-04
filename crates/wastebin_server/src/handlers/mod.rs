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

use std::sync::Arc;

use axum::extract::FromRef;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, SameSite};
use ratelimit::Ratelimiter;
use wastebin_core::db::read::{Data, Entry};
use wastebin_core::db::{self, Database};

use crate::cache::Key;
use crate::handlers::extract::{Accepts, Password, serialize_uids};
use crate::handlers::html::Chrome;
use crate::{AppState, Error};

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
///
/// `SameSite=Lax` rather than the `Strict` of the others: an `?owner=` handoff is a link someone
/// opens, and `Strict` withholds the cookie on exactly that navigation — so the server saw no
/// identity, minted a fresh one, and set it over the visitor's real one, costing them the right to
/// delete everything they had already made. `Lax` still withholds it from cross-site POSTs and
/// subresource loads, which is where deletion could otherwise be driven from.
pub(crate) fn uid_cookie(uids: &[i64]) -> Cookie<'static> {
    let mut cookie = cookie("uid", serialize_uids(uids));
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(true);
    cookie
}

/// The limiter guarding password attempts, for the read handlers that do not take the whole state.
#[derive(Clone)]
pub(crate) struct PasswordRatelimit(Option<Arc<Ratelimiter>>);

impl FromRef<AppState> for PasswordRatelimit {
    fn from_ref(state: &AppState) -> Self {
        Self(state.ratelimit_password.clone())
    }
}

impl PasswordRatelimit {
    /// Spend a token for one password attempt.
    ///
    /// Every attempt derives a key with argon2 — 64 MiB and ten passes over four lanes — before
    /// the ciphertext is looked at, so a wrong password costs exactly what a right one does and an
    /// attacker needs only one encrypted paste's id to keep every core busy and that memory
    /// resident. Call this only where a password was actually supplied: a read without one costs
    /// nothing and must not spend from the same bucket.
    pub(crate) fn check(&self) -> Result<(), Error> {
        static RL_LOGGED: AtomicU64 = AtomicU64::new(0);

        check_ratelimit(self.0.as_deref(), &RL_LOGGED, "password attempts")
    }
}

/// Serve a paste's bytes for a route that answers with content rather than a page.
///
/// `/raw` and `/dl` differ only in how they wrap the entry, so the burn refusal, the password rate
/// limit and the HTML-prompt fallback live here rather than in each: a further bytes route gets
/// all three by calling this instead of restating them, and cannot quietly drop one.
pub(crate) async fn serve_bytes(
    db: &Database,
    ratelimit: &PasswordRatelimit,
    chrome: &Chrome,
    id: String,
    password: Option<Password>,
    respond: impl FnOnce(&Key, Data) -> Response,
) -> Result<Response, Error> {
    let password = password.map(|Password(password)| password);
    let key: Key = id.parse()?;

    let metadata = db.get_metadata(key.id).await?;

    // These routes are GETs that return bytes, so there is nowhere to confirm the destruction and
    // nothing stopping anything that merely follows a URL from triggering it. The content stays
    // reachable through the paste page, which does ask first.
    if metadata.must_be_deleted {
        return Err(Error::BurnNotConfirmed);
    }

    // Only an attempt that reaches argon2 is worth a token. The bucket is a single process-wide
    // one with no refund, so letting a password for a missing or unencrypted paste spend one let
    // anyone lock every user out of every encrypted paste for free.
    if password.is_some() && metadata.is_encrypted {
        ratelimit.check()?;
    }

    match db.get(key.id, password).await {
        Ok(Entry::Regular(data) | Entry::Burned(data)) => Ok(respond(&key, data)),
        // A browser is sent the prompt to fill in; a client that asked for JSON cannot act on an
        // HTML form and would only see a 200 where it expected the paste.
        Err(db::Error::NoPassword) if chrome.accepts == Accepts::Html => {
            Ok(chrome.password_input(key.id.to_string()))
        }
        Err(err) => Err(err.into()),
    }
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
