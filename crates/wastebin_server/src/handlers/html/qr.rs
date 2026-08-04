use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use qrcodegen::QrCode;
use url::Url;

use crate::cache::Key;
use crate::handlers::extract::{Accepts, Theme, Uids, can_delete};
use crate::handlers::html::{ErrorResponse, make_error};
use crate::i18n::Lang;
use crate::{Error, Highlighter, Page};
use wastebin_core::db::Database;
use wastebin_core::db::read::Metadata;
use wastebin_core::expiration::Expiration;

/// GET handler for a QR page.
#[expect(clippy::too_many_arguments)]
pub async fn get(
    Path(id): Path<String>,
    State(page): State<Page>,
    State(db): State<Database>,
    State(highlighter): State<Highlighter>,
    uids: Option<Uids>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
) -> Result<Qr, ErrorResponse> {
    async {
        let key: Key = id.parse()?;
        let code = code_for(&page, &key).await?;

        let Metadata {
            uid: owner_uid,
            title,
            expiration,
            is_encrypted,
            ..
        } = db.get_metadata(key.id).await?;

        // Only the content is encrypted; the title is a plain column, and this view never asks for
        // a password. `/{id}` withholds it, so showing it here handed anyone with the id the one
        // thing the password was assumed to cover.
        let title = (!is_encrypted).then_some(title).flatten();

        Ok(Qr {
            page: page.clone(),
            theme,
            lang,
            can_delete: can_delete(uids.as_ref(), owner_uid),
            is_markdown: highlighter.is_markdown(key.ext.as_deref()),
            key,
            is_available: true,
            code,
            title,
            expiration,
        })
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
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
    fn dark_modules(&self) -> Vec<(i32, i32)> {
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

pub fn code_from(url: &Url, key: &Key) -> Result<QrCode, Error> {
    Ok(QrCode::encode_text(
        paste_url(url, key)?.as_str(),
        qrcodegen::QrCodeEcc::High,
    )?)
}

/// Encode the QR code for `key` off the async runtime.
pub async fn code_for(page: &Page, key: &Key) -> Result<QrCode, Error> {
    let page = page.clone();
    let key = key.clone();

    tokio::task::spawn_blocking(move || code_from(&page.base_url, &key))
        .await
        .map_err(Error::from)?
}

/// Return module coordinates that are dark.
pub fn dark_modules(code: &QrCode) -> Vec<(i32, i32)> {
    let size = code.size();
    (0..size)
        .flat_map(|x| (0..size).map(move |y| (x, y)))
        .filter(|(x, y)| code.get_module(*x, *y))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::paste_url;
    use crate::cache::Key;
    use crate::handlers::insert::api::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

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
