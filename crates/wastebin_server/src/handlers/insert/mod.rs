use std::sync::atomic::AtomicBool;

use wastebin_core::{db::write, id::Id};

use crate::AppState;
use crate::Error;
use crate::Error::{RateLimit, TooLongExpires};

pub mod api;
pub mod form;

async fn common_insert(
    appstate: &AppState,
    entry: write::Entry,
) -> Result<(Id, write::Entry), Error> {
    if let Some(max_expiration) = appstate.page.max_expiration {
        if entry.expires.is_none_or(|exp| exp > max_expiration) {
            Err(TooLongExpires)?;
        }
    }

    if let Some(ref ratelimiter) = appstate.ratelimit_insert {
        static RL_LOGGED: AtomicBool = AtomicBool::new(false);

        if ratelimiter.try_wait().is_err() {
            if !RL_LOGGED.fetch_or(true, std::sync::atomic::Ordering::Acquire) {
                tracing::info!("Rate limiting paste insertions");
            }

            Err(RateLimit)?;
        }

        RL_LOGGED.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    let res = appstate.db.insert(entry).await?;

    Ok(res)
}
