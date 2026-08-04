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

    // The extension is never stored: it only shapes the URL this insert redirects to, and comes
    // back as a path segment on every later request. Accepting an arbitrary string put whatever
    // the client sent into a `Location` header — a CRLF made the header unbuildable and answered
    // a successfully inserted paste with a 500, and a `../` walked the redirect off the paste
    // entirely. Only the extensions the form itself offers get through.
    if let Some(ext) = &entry.extension
        && !appstate.highlighter.has_extension(ext)
    {
        return Err(Error::InvalidExtension);
    }

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
