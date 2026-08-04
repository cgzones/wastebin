use std::sync::atomic::AtomicU64;

use wastebin_core::db;
use wastebin_core::id::Id;

use crate::AppState;
use crate::Error;
use crate::handlers::check_ratelimit;

pub mod api;
pub mod form;

async fn common_delete(appstate: &AppState, id: Id, uids: &[i64]) -> Result<(), Error> {
    static RL_LOGGED: AtomicU64 = AtomicU64::new(0);

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

    check_ratelimit(
        appstate.ratelimit_delete.as_deref(),
        &RL_LOGGED,
        "paste deletions",
    )?;

    appstate.db.delete_for(id, uids).await?;

    Ok(())
}
