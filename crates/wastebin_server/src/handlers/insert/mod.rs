use std::sync::atomic::{AtomicU64, Ordering};

use wastebin_core::{db::write, id::Id};

use crate::AppState;
use crate::Error;
use crate::Error::RateLimit;
use crate::handlers::{RATELIMIT_LOG_INTERVAL, START};

pub mod api;
pub mod form;

async fn common_insert(
    appstate: &AppState,
    entry: write::Entry,
) -> Result<(Id, write::Entry), Error> {
    if let Some(ref ratelimiter) = appstate.ratelimit_insert {
        /// Next second since `START` at which logging is allowed again.
        static RL_LOGGED: AtomicU64 = AtomicU64::new(0);

        if ratelimiter.try_wait().is_err() {
            let now = START.elapsed().as_secs();
            let deadline = RL_LOGGED.load(Ordering::Relaxed);
            if now >= deadline
                && RL_LOGGED
                    .compare_exchange(
                        deadline,
                        now.saturating_add(RATELIMIT_LOG_INTERVAL),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                tracing::info!("Rate limiting paste insertions");
            }

            Err(RateLimit)?;
        }
    }

    let res = appstate.db.insert(entry).await?;

    Ok(res)
}
