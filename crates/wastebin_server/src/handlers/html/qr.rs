use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use qrcodegen::QrCode;
use url::Url;

use crate::cache::Key;
use crate::handlers::extract::{Theme, Uids, can_delete};
use crate::handlers::html::{Chrome, ErrorResponse};
use crate::i18n::Lang;
use crate::{Error, Highlighter, Page};
use wastebin_core::db::Database;
use wastebin_core::expiration::Expiration;

/// GET handler for a QR page.
pub async fn get(
    Path(id): Path<String>,
    State(db): State<Database>,
    State(highlighter): State<Highlighter>,
    uids: Option<Uids>,
    chrome: Chrome,
) -> Result<Qr, ErrorResponse> {
    async {
        let key: Key = id.parse()?;

        // Establish the paste exists before encoding anything, as `/burn/` does: the encode is
        // CPU-bound and this route has no rate limiter, so a bogus id would otherwise buy a full
        // one for free.
        let metadata = db.get_metadata(key.id).await?;
        let code = code_for(&chrome.page.base_url, &key)?;

        // This view never asks for a password, so it may only render the public parts.
        let metadata = metadata.into_public_parts();

        Ok(Qr {
            page: chrome.page.clone(),
            theme: chrome.theme,
            lang: chrome.lang,
            can_delete: can_delete(uids.as_ref(), metadata.uid),
            is_markdown: highlighter.is_markdown(key.ext.as_deref()),
            key,
            is_available: true,
            code,
            title: metadata.title,
            expiration: metadata.expiration,
        })
    }
    .await
    .map_err(|err| chrome.error(err))
}

/// Paste view showing the formatted paste as well as a bunch of links.
#[derive(Template, WebTemplate)]
#[template(path = "qr.html")]
pub(crate) struct Qr {
    page: Page,
    theme: Theme,
    lang: Lang,
    key: Key,
    can_delete: bool,
    is_available: bool,
    is_markdown: bool,
    code: qrcodegen::QrCode,
    title: Option<String>,
    expiration: Option<Expiration>,
}

impl Qr {
    fn dark_modules(&self) -> impl Iterator<Item = (i32, i32)> + '_ {
        dark_modules(&self.code)
    }
}

/// Build the absolute URL of `key` under `base`.
///
/// Joining the path onto the base parses it as a relative reference, and one whose first segment
/// holds a colon is an absolute URI instead — the extension is caller-supplied and unvalidated, so
/// `{id}.x://evil.example.com` replaced the authority outright and the code on a trusted page
/// pointed wherever the caller chose. Pushing a segment can only ever extend the base's path.
fn paste_url(base: &Url, key: &Key) -> Result<Url, Error> {
    let mut url = base.clone();

    url.path_segments_mut()
        .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
        .push(&key.to_string());

    Ok(url)
}

/// Encode the QR code for `key`.
///
/// Run inline rather than through [`Renderer`], unlike highlighting. The pool exists so that an
/// abandoned *expensive* render drops out of the queue instead of occupying a blocking thread, and
/// it only pays for itself when the work is worth the hand-off. An encode is not: it measures
/// 69–84 µs for the URLs this builds, which a `spawn_blocking` round trip is a sizeable fraction
/// of, and taking a permit for it put a QR request behind whatever multi-millisecond highlight
/// happened to hold one. The input is a paste id and this crate's own base URL, so the cost has no
/// caller-controlled upper end for the pool to bound in the first place.
///
/// Takes the base URL rather than the whole [`Page`], because that is all it reads — which also
/// lets the pinning test below call it without building one.
pub fn code_for(base: &Url, key: &Key) -> Result<QrCode, Error> {
    let url = paste_url(base, key)?;

    Ok(QrCode::encode_text(
        url.as_str(),
        qrcodegen::QrCodeEcc::High,
    )?)
}

/// Yield the module coordinates that are dark.
///
/// Borrowed rather than collected: the template walks these once to write the path, and a code of
/// any size holds thousands of them.
pub fn dark_modules(code: &QrCode) -> impl Iterator<Item = (i32, i32)> + '_ {
    let size = code.size();
    (0..size)
        .flat_map(move |x| (0..size).map(move |y| (x, y)))
        .filter(move |(x, y)| code.get_module(*x, *y))
}

#[cfg(test)]
mod tests {
    use super::{code_for, paste_url};
    use crate::cache::Key;
    use crate::handlers::insert::api::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;
    use sha2::{Digest, Sha256};

    /// Hex digest of every module, row by row.
    fn grid_digest(code: &qrcodegen::QrCode) -> String {
        let mut hasher = Sha256::new();
        for y in 0..code.size() {
            for x in 0..code.size() {
                hasher.update([u8::from(code.get_module(x, y))]);
            }
        }
        hex::encode(hasher.finalize())
            .get(0..16)
            .expect("at least 16 characters")
            .to_string()
    }

    /// The exact symbol served for a given paste, pinned.
    ///
    /// `qrcodegen` ships no tests of its own — the whole of its repository's test suite is one C
    /// program, and the Rust port has none — so nothing but this says that upgrading it still
    /// produces the code this site has been handing out. The version, the mask and every module
    /// are covered, which between them pin the encoder's three decisions: how much data it packs
    /// (version), which of the eight patterns it scores best (mask), and what it draws.
    ///
    /// A failure here is not necessarily a bug. Mask choice is a quality heuristic, and upstream
    /// is free to improve it; a changed digest means "look at what the upgrade did and decide",
    /// not "revert". What it rules out is that happening unnoticed.
    ///
    /// The base URL is fixed rather than taken from a running server so the expectation does not
    /// move with the test harness's port.
    #[test]
    fn the_encoded_symbol_is_pinned() {
        let base = url::Url::parse("https://paste.example.com/").unwrap();

        // id, symbol size, chosen mask, digest of the module grid.
        for (id, size, mask, digest) in [
            ("bJZCna", 33, 2, "f8131e519f0e0665"),
            ("sIiFec.rs", 37, 6, "fc633a7fe8bc6fd9"),
            ("wxWCRiLU6wc", 37, 6, "afb36e25cda561f4"),
            ("wxWCRiLU6wc.rs", 37, 4, "51c480d8b499905d"),
            ("wxWCRiLU6wc.markdown", 41, 6, "c71f46168eac277b"),
        ] {
            let key: Key = id.parse().expect("valid key");
            let code = code_for(&base, &key).expect("encodable");

            assert_eq!(code.size(), size, "{id}: symbol size changed");
            assert_eq!(code.mask().value(), mask, "{id}: chosen mask changed");
            assert_eq!(grid_digest(&code), digest, "{id}: module grid changed");
        }
    }

    /// The QR was built by joining the raw path onto the base URL, and a relative reference whose
    /// first segment holds a colon parses as an absolute URI — `{id}.x://evil.example.com` became
    /// exactly that. The code shown on a trusted page then pointed wherever the caller chose, and
    /// `/burn/` reaches this without a paste existing at all.
    #[test]
    fn a_scheme_in_the_extension_cannot_steer_the_code() {
        let base = url::Url::parse("https://paste.example.com/").unwrap();

        for ext in [
            "x://evil.example.com",
            "x:evil",
            "./../../evil",
            "a/b",
            "%2e%2e%2fevil",
        ] {
            let key = Key {
                id: wastebin_core::id::Id::from(104_651_828_u32),
                ext: Some(ext.to_string()),
            };

            let url = paste_url(&base, &key).unwrap();

            assert_eq!(url.host_str(), Some("paste.example.com"), "ext {ext:?}");
            assert_eq!(url.scheme(), "https", "ext {ext:?}");
            assert!(
                url.as_str().starts_with("https://paste.example.com/"),
                "ext {ext:?} produced {url}"
            );
        }
    }

    /// An extension too long for a QR code is the caller's doing, so it is a bad request rather
    /// than an internal error — and it must not read as the server having broken.
    #[tokio::test]
    async fn an_unencodable_extension_is_a_bad_request() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        // The page checks the paste exists before encoding anything, so this needs a real one to
        // reach the encoder at all.
        let id = client
            .seed(wastebin_core::db::write::Entry {
                text: String::from("FooBarBaz"),
                ..Default::default()
            })
            .await?;

        let res = client
            .get(&format!("/burn/{id}.{}", "a".repeat(4096)))
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn title_is_escaped() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let entry = Entry {
            text: "FooBarBaz".to_string(),
            title: Some("<img src=x onerror=alert(1)>".to_string()),
            ..Default::default()
        };

        let payload = client
            .post_json()
            .json(&entry)
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let body = client
            .get(&format!("/qr{}", payload.path))
            .send()
            .await?
            .text()
            .await?;

        assert!(!body.contains("<img src=x"), "raw markup leaked: {body}");
        assert!(body.contains("&#60;img src=x"), "body: {body}");

        Ok(())
    }

    /// Only the content is encrypted; the title is a plain column. This view reads metadata and
    /// never asks for a password, so it handed the title to anyone holding the id — while `/{id}`
    /// withholds it. People put in titles what they think the password covers.
    #[tokio::test]
    async fn an_encrypted_paste_keeps_its_title_back() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let entry = Entry {
            text: "FooBarBaz".to_string(),
            title: Some("Q1-layoff-list".to_string()),
            password: Some("hunter2".to_string()),
            ..Default::default()
        };

        let payload = client
            .post_json()
            .json(&entry)
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let body = client
            .get(&format!("/qr{}", payload.path))
            .send()
            .await?
            .text()
            .await?;

        assert!(!body.contains("Q1-layoff-list"), "title leaked: {body}");

        Ok(())
    }

    /// An unencrypted paste has nothing to hide, so its title still shows.
    #[tokio::test]
    async fn a_plain_paste_still_shows_its_title() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let entry = Entry {
            text: "FooBarBaz".to_string(),
            title: Some("release-notes".to_string()),
            ..Default::default()
        };

        let payload = client
            .post_json()
            .json(&entry)
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let body = client
            .get(&format!("/qr{}", payload.path))
            .send()
            .await?
            .text()
            .await?;

        assert!(body.contains("release-notes"), "title missing: {body}");

        Ok(())
    }
}
