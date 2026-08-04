use std::sync::atomic::AtomicU64;

use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
use wastebin_core::{db::write, id::Id};

use crate::AppState;
use crate::Error;
use crate::Error::TooLongExpires;
use crate::handlers::check_ratelimit;

pub mod api;
pub mod form;

/// Longest title kept, in characters.
///
/// The title is shown back on the paste page and handed to the browser as the download filename,
/// so its length lands in a response header. Nothing bounded it: a 900k-character title built a
/// 1.8 MB `content-disposition`, which clients with a header cap answer by dropping the whole
/// header block — the security headers with it — and which reverse proxies reject outright.
const MAX_TITLE_CHARS: usize = 80;

/// Return `title` with everything unfit for a filename removed, or `None` if nothing is left.
///
/// A title is read by whoever opens the paste and reused as a filename, so the characters that
/// hide or reorder what follows them do not belong in it: an override can make `report<RLO>gnp.exe`
/// read as `report exe.png`. Dropping rather than rejecting keeps a paste whose title merely picked
/// up a stray character from failing outright.
fn sanitize_title(title: &str) -> Option<String> {
    // Neither bound can be exceeded: the result drops characters and never adds any, and it stops
    // at `MAX_TITLE_CHARS` of at most four bytes each.
    let mut sanitized = String::with_capacity(title.len().min(MAX_TITLE_CHARS * 4));
    sanitized.extend(
        title
            .chars()
            .filter(|&c| {
                !matches!(
                    c.general_category(),
                    // Control and format characters: bidi overrides and isolates, zero-width joiners,
                    // interlinear annotation, the deprecated format characters.
                    GeneralCategory::Control
                    | GeneralCategory::Format
                    // Nothing renders these, and their meaning is per-installation.
                    | GeneralCategory::PrivateUse
                    // Unassigned covers the noncharacters too.
                    | GeneralCategory::Unassigned
                    // A title is one line.
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
                )
            })
            .take(MAX_TITLE_CHARS),
    );

    // Trimmed in place rather than by copying the trimmed slice back out: the padding sits at the
    // ends, so the buffer just built already holds the answer.
    sanitized.truncate(sanitized.trim_end().len());
    let leading = sanitized.len() - sanitized.trim_start().len();
    sanitized.drain(..leading);

    (!sanitized.is_empty()).then_some(sanitized)
}

/// Store `entry`, filed under `owner`.
///
/// `owner` is the identity the client already holds, from its cookie or a signed `owner` token;
/// `None` mints a fresh one — but only once the entry is known to be acceptable.
async fn common_insert(
    appstate: &AppState,
    mut entry: write::Entry,
    owner: Option<i64>,
) -> Result<(Id, write::Entry, i64), Error> {
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

    // Both routes funnel through here, so neither can be the one that forgets.
    entry.title = entry.title.as_deref().and_then(sanitize_title);

    check_ratelimit(
        appstate.ratelimit_insert.as_deref(),
        &RL_LOGGED,
        "paste insertions",
    )?;

    // Last, so a request that was never going to be stored does not write a row through the
    // single-threaded actor first: minting ran ahead of every check above, and ahead of the
    // limiter, so rejected inserts moved the counter with nothing accounting for them.
    let uid = match owner {
        Some(uid) => uid,
        None => appstate.db.next_uid().await?,
    };
    entry.uid = Some(uid);

    let (id, entry) = appstate.db.insert(entry).await?;

    Ok((id, entry, uid))
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

    /// Minting ran before the entry was looked at, so every rejected insert still wrote a row
    /// through the single-threaded actor and moved the counter on — work no rate limit could ever
    /// account for, since the limiter is checked later still.
    #[tokio::test]
    async fn a_rejected_insert_mints_no_uid() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        // The signed token carries `owner:<uid>` as its plaintext payload.
        let uid_of = |token: &str| -> i64 {
            let payload = token.split("owner:").nth(1).expect("token payload");
            payload.parse().expect("uid")
        };

        let first = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: String::from("hi"),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        for _ in 0..5 {
            let res = client
                .post_json()
                .json(&crate::handlers::insert::api::Entry {
                    text: String::new(),
                    ..Default::default()
                })
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        }

        let second = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: String::from("hi"),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        assert_eq!(
            uid_of(&second.owner),
            uid_of(&first.owner) + 1,
            "rejected inserts consumed uids"
        );

        Ok(())
    }

    /// The title doubles as the download filename, and nothing bounded it: a 900k-character one
    /// produced a 1.8 MB `content-disposition`, past the header cap of every client that has one —
    /// which then dropped the whole header block, security headers included.
    #[tokio::test]
    async fn an_overlong_title_is_cut_to_the_limit() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let data = crate::handlers::insert::api::Entry {
            text: String::from("hi"),
            title: Some("a".repeat(500)),
            ..Default::default()
        };
        let payload = client
            .post_json()
            .json(&data)
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let res = client.get(&format!("/dl{}", payload.path)).send().await?;
        let disposition = res
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()?
            .to_owned();

        assert!(
            disposition.contains(&format!("filename=\"{}\"", "a".repeat(80))),
            "got: {disposition}"
        );
        assert!(!disposition.contains(&"a".repeat(81)), "got: {disposition}");

        Ok(())
    }

    /// A title is shown back to whoever opens the paste and handed to the browser as a filename,
    /// so the characters that reorder or hide what follows them do not belong in it.
    #[tokio::test]
    async fn unsafe_characters_are_dropped_from_a_title() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;

        // Bidi override, zero-width space, a control character, an interlinear annotation, a
        // paragraph separator, a private-use code point and a noncharacter.
        let title = "a\u{202E}b\u{200B}c\u{0007}d\u{FFF9}e\u{2029}f\u{E000}g\u{FDD0}h";

        for (route, path) in [("json", "/dl"), ("form", "/dl")] {
            let payload = if route == "json" {
                client
                    .post_json()
                    .json(&crate::handlers::insert::api::Entry {
                        text: String::from("hi"),
                        title: Some(title.to_owned()),
                        ..Default::default()
                    })
                    .send()
                    .await?
                    .json::<crate::handlers::insert::api::RedirectResponse>()
                    .await?
                    .path
            } else {
                let res = client
                    .post_form()
                    .form(&crate::handlers::insert::form::Entry {
                        text: String::from("hi"),
                        title: title.to_owned(),
                        ..Default::default()
                    })
                    .send()
                    .await?;
                res.headers().get("location").unwrap().to_str()?.to_owned()
            };

            let res = client.get(&format!("{path}{payload}")).send().await?;
            let disposition = res
                .headers()
                .get("content-disposition")
                .unwrap()
                .to_str()?
                .to_owned();

            assert!(
                disposition.contains("filename=\"abcdefgh\""),
                "{route}: got {disposition}"
            );
        }

        Ok(())
    }

    /// The filter is about what hides or reorders text, not about what alphabet it is in — an
    /// ordinary title in any script has to survive it intact.
    #[tokio::test]
    async fn an_international_title_survives() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let title = "café 日本語 Ελληνικά 🎉";

        let res = client
            .post_form()
            .form(&crate::handlers::insert::form::Entry {
                text: String::from("hi"),
                title: title.to_owned(),
                ..Default::default()
            })
            .send()
            .await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        let body = client.get(&location).send().await?.text().await?;
        assert!(body.contains(title), "title was mangled");

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
