use std::fmt::Write;

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::HeaderValue;

use crate::Page;
use crate::cache::Key;
use crate::handlers::PasswordRatelimit;
use crate::handlers::extract::{Accepts, Password, Theme};
use crate::handlers::html::{ErrorResponse, make_error, password_input};
use crate::i18n::Lang;
use wastebin_core::db::read::{Data, Entry};
use wastebin_core::db::{self, Database};

/// GET handler for raw content of a paste.
#[expect(clippy::too_many_arguments)]
pub async fn get(
    Path(id): Path<String>,
    State(db): State<Database>,
    State(page): State<Page>,
    State(ratelimit): State<PasswordRatelimit>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
    password: Option<Password>,
) -> Result<Response, ErrorResponse> {
    async {
        let key: Key = id.parse()?;
        let password = password.map(|Password(password)| password);

        let metadata = db.get_metadata(key.id).await?;

        // A download is a GET with no way to confirm the destruction; see `raw::get`.
        if metadata.must_be_deleted {
            return Err(crate::Error::BurnNotConfirmed);
        }

        // Only an attempt that reaches argon2 is worth a token; see `raw::get`.
        if password.is_some() && metadata.is_encrypted {
            ratelimit.check()?;
        }

        match db.get(key.id, password).await {
            Ok(Entry::Regular(data) | Entry::Burned(data)) => {
                Ok(get_download(&key, data).into_response())
            }
            // A browser is sent the prompt to fill in; a client that asked for JSON cannot act on
            // an HTML form and would only see a 200 where it expected the paste.
            Err(db::Error::NoPassword) if accepts == Accepts::Html => {
                Ok(password_input(&page, theme, lang, key.id.to_string()))
            }
            Err(err) => Err(err.into()),
        }
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
}

/// Return `true` if `c` reorders the text around it rather than showing a glyph of its own.
///
/// Percent-encoding carries these through `filename*` intact, and the client decodes them back
/// before showing the name, so `evil<U+202E>gnp.exe` is offered as `evil.exe.png` — the extension
/// the user reads is not the one the file has. The quoted fallback already loses them.
fn reorders_text(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Build the `Content-Disposition` for `filename`.
///
/// RFC 6266 wants both spellings: a quoted `filename` that any parser understands, and the
/// extended `filename*` after it, which the parsers that support it prefer. Emitting only the
/// latter left clients that ignore it falling back to the last path segment of the URL.
#[must_use]
fn make_content_disposition(filename: &str) -> HeaderValue {
    const PREFIX: &str = "attachment; filename=\"";
    const SEPARATOR: &str = "\"; filename*=UTF-8''";

    // The title is attacker-controlled and both spellings below are built from it, so the
    // characters that would misrepresent the name are replaced before either is written. Applied
    // as the two passes read it rather than materialised in between, which built a whole second
    // copy of the title for the sake of two loops that each walk it once anyway.
    let sanitized = || {
        filename.chars().map(|c| {
            if c.is_control() || reorders_text(c) {
                '_'
            } else {
                c
            }
        })
    };

    // The quoted spelling emits one byte a character and the extended one at most three bytes a
    // byte, so this covers both without ever growing.
    let mut value =
        String::with_capacity(PREFIX.len() + SEPARATOR.len() + filename.len() + filename.len() * 3);
    value.push_str(PREFIX);

    for c in sanitized() {
        // A quote or backslash would end the quoted string early and let the rest of the title be
        // read as further parameters; anything outside printable ASCII cannot be spelled here.
        if (c.is_ascii_graphic() && c != '"' && c != '\\') || c == ' ' {
            value.push(c);
        } else {
            value.push('_');
        }
    }

    value.push_str(SEPARATOR);

    let mut encoded = [0u8; 4];
    for c in sanitized() {
        for &b in c.encode_utf8(&mut encoded).as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b'+') {
                value.push(b as char);
            } else {
                write!(value, "%{b:02X}").expect("writing to String");
            }
        }
    }

    HeaderValue::try_from(value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

#[must_use]
fn get_download(key: &Key, data: Data) -> impl IntoResponse {
    let filename = data.metadata.title.unwrap_or_else(|| key.to_string());

    let content_type = "text/plain; charset=utf-8";
    let content_disposition = make_content_disposition(&filename);

    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CONTENT_DISPOSITION, content_disposition),
        ],
        data.text,
    )
}

#[cfg(test)]
mod tests {
    use super::make_content_disposition;
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use http::header;
    use reqwest::StatusCode;

    #[tokio::test]
    async fn download() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("FooBarBaz"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;
        let filename = &location[1..];
        let res = client.get(&format!("/dl/{filename}.cpp")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let content_disposition = res.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert_eq!(
            content_disposition.to_str()?,
            format!("attachment; filename=\"{filename}.cpp\"; filename*=UTF-8''{filename}.cpp"),
        );

        let content = res.text().await?;
        assert_eq!(content, "FooBarBaz");

        let res = client.get(&format!("/dl{location}")).send().await?;
        let content_disposition = res.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert_eq!(
            content_disposition.to_str()?,
            format!("attachment; filename=\"{filename}\"; filename*=UTF-8''{filename}"),
        );

        Ok(())
    }

    #[tokio::test]
    async fn download_title_with_quotes() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("content"),
            title: String::from(r#"file"name.txt"#),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let res = client.get(&format!("/dl{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let content_disposition = res.headers().get(header::CONTENT_DISPOSITION).unwrap();
        // The quote must not survive into the fallback, or it would close the quoted string and
        // let the rest of the title be read as further parameters.
        assert_eq!(
            content_disposition.to_str()?,
            "attachment; filename=\"file_name.txt\"; filename*=UTF-8''file%22name.txt",
        );

        Ok(())
    }

    /// Percent-encoding is transport, not sanitisation: the client decodes `filename*` back before
    /// showing the name, so a right-to-left override used to survive into it and offer
    /// `evil<U+202E>gnp.exe` as `evil.exe.png`.
    ///
    /// Inserting now drops such a character outright, so it never reaches a stored title. The
    /// replacement in `make_content_disposition` stays as the backstop for rows stored before
    /// that, which is what `a_stored_reordering_title_is_still_neutralised` covers.
    #[tokio::test]
    async fn download_title_reordering_the_extension() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("content"),
            title: String::from("evil\u{202e}gnp.exe"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let res = client.get(&format!("/dl{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let content_disposition = res.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert_eq!(
            content_disposition.to_str()?,
            "attachment; filename=\"evilgnp.exe\"; filename*=UTF-8''evilgnp.exe",
        );

        Ok(())
    }

    /// A title stored before inserting sanitized them still reaches this code, so the replacement
    /// here has to keep standing on its own.
    #[test]
    fn a_stored_reordering_title_is_still_neutralised() {
        let disposition = make_content_disposition("evil\u{202e}gnp.exe");

        assert_eq!(
            disposition.to_str().unwrap(),
            "attachment; filename=\"evil_gnp.exe\"; filename*=UTF-8''evil_gnp.exe",
        );
    }

    #[tokio::test]
    async fn download_title_with_non_ascii() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("content"),
            title: String::from("café.txt"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let res = client.get(&format!("/dl{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let content_disposition = res.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert_eq!(
            content_disposition.to_str()?,
            "attachment; filename=\"caf_.txt\"; filename*=UTF-8''caf%C3%A9.txt",
        );

        Ok(())
    }
}
