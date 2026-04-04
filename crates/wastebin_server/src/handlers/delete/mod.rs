use std::sync::atomic::{AtomicU64, Ordering};

use wastebin_core::db;
use wastebin_core::id::Id;

use crate::AppState;
use crate::Error;
use crate::Error::RateLimit;
use crate::handlers::{RATELIMIT_LOG_INTERVAL, START};

pub mod api;
pub mod form;

async fn common_delete(appstate: &AppState, id: Id, uids: &[i64]) -> Result<(), Error> {
    // Cheap ownership pre-check so bogus ids cannot drain the rate limiter before the
    // authoritative, atomic check in `delete_for` below.
    let metadata = match appstate.db.get_metadata(id).await {
        Ok(metadata) => metadata,
        Err(db::Error::NotFound) => return Err(db::Error::Delete.into()),
        Err(err) => return Err(err.into()),
    };

    if !metadata.uid.is_some_and(|uid| uids.contains(&uid)) {
        return Err(db::Error::Delete.into());
    }

    if let Some(ref ratelimiter) = appstate.ratelimit_delete {
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
                tracing::info!("Rate limiting paste deletions");
            }

            Err(RateLimit)?;
        }
    }

    appstate.db.delete_for(id, uids).await?;

    Ok(())
}
