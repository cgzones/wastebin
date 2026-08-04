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
        let code = code_for(&page, id).await?;

        let Metadata {
            uid: owner_uid,
            title,
            expiration,
            ..
        } = db.get_metadata(key.id).await?;

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

pub fn code_from(url: &Url, id: &str) -> Result<QrCode, Error> {
    Ok(QrCode::encode_text(
        url.join(id)?.as_str(),
        qrcodegen::QrCodeEcc::High,
    )?)
}

/// Encode the QR code for `id` off the async runtime.
pub async fn code_for(page: &Page, id: String) -> Result<QrCode, Error> {
    let page = page.clone();

    tokio::task::spawn_blocking(move || code_from(&page.base_url, &id))
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
    use crate::handlers::insert::api::Entry;
    use crate::test_helpers::{Client, StoreCookies};

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
}
