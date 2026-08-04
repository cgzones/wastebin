use std::sync::atomic::AtomicU64;

use wastebin_core::{db::write, id::Id};

use crate::AppState;
use crate::Error;
use crate::Error::TooLongExpires;
use crate::handlers::check_ratelimit;

pub mod api;
pub mod form;

async fn common_insert(
    appstate: &AppState,
    entry: write::Entry,
) -> Result<(Id, write::Entry), Error> {
    static RL_LOGGED: AtomicU64 = AtomicU64::new(0);

    if let Some(max_expiration) = appstate.page.max_expiration
        && entry.expires.is_none_or(|exp| exp > max_expiration)
    {
        return Err(TooLongExpires);
    }

    check_ratelimit(
        appstate.ratelimit_insert.as_deref(),
        &RL_LOGGED,
        "paste insertions",
    )?;

    let res = appstate.db.insert(entry).await?;

    Ok(res)
}
