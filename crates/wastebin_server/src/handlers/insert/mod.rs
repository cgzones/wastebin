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

    // The form marks the textarea `required`, but that only binds a browser: both endpoints took
    // an empty body and answered with a paste URL that renders nothing.
    if entry.text.trim().is_empty() {
        return Err(Error::EmptyPaste);
    }

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

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

    /// The textarea is marked `required`, which binds a browser and nothing else — both endpoints
    /// used to mint a URL for a paste that renders nothing.
    #[tokio::test]
    async fn empty_paste_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for text in ["", "   \n\t "] {
            let data = crate::handlers::insert::form::Entry {
                text: String::from(text),
                ..Default::default()
            };
            let res = client.post_form().form(&data).send().await?;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "form text {text:?}");

            let data = crate::handlers::insert::api::Entry {
                text: String::from(text),
                ..Default::default()
            };
            let res = client.post_json().json(&data).send().await?;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "json text {text:?}");
        }

        Ok(())
    }

    /// Only the emptiness check trims; content that merely has padding is stored as it was sent.
    #[tokio::test]
    async fn padded_paste_is_kept_verbatim() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let data = crate::handlers::insert::form::Entry {
            text: String::from("  hi  "),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let text = client
            .get(&format!("/raw{location}"))
            .send()
            .await?
            .text()
            .await?;
        assert_eq!(text, "  hi  ");

        Ok(())
    }
}
