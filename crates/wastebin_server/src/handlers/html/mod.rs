pub mod burn;
pub mod index;
pub mod paste;
pub mod qr;
pub mod rendered;

use askama::Template;
use askama_web::WebTemplate;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::Page;
use crate::handlers::extract::Theme;
use crate::i18n::Lang;

/// Error page showing a message.
#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
pub(crate) struct Error {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub description: &'static str,
}

/// Page showing password input.
#[derive(Template, WebTemplate)]
#[template(path = "encrypted.html")]
pub(crate) struct PasswordInput {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub id: String,
}

/// Interstitial page shown before a burn-after-reading paste is revealed.
#[derive(Template, WebTemplate)]
#[template(path = "burn-confirmation.html")]
pub(crate) struct BurnConfirmation {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub id: String,
    pub title: Option<String>,
}

/// Render the password prompt shown when a paste is encrypted but no password was supplied.
#[must_use]
pub(crate) fn password_input(page: &Page, theme: Theme, lang: Lang, id: String) -> Response {
    PasswordInput {
        page: page.clone(),
        theme,
        lang,
        id,
    }
    .into_response()
}

/// Error response carrying a status code and the page itself.
pub(crate) type ErrorResponse = (StatusCode, Error);

/// Create an error response from `error` consisting of [`StatusCode`] derive from `error` as well
/// as a rendered page with a description.
///
/// The page shows a fixed, translated message for the kind of failure. The error's own
/// `Display` — which may quote sqlite, syntect or a panic payload — is only logged.
#[must_use]
pub fn make_error(error: crate::Error, page: Page, theme: Theme, lang: Lang) -> ErrorResponse {
    error.log();

    let description = lang.t(error.message_key());

    (
        error.into(),
        Error {
            page,
            theme,
            lang,
            description,
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    /// The rendered page must describe the failure to the visitor, not quote the internals that
    /// produced it — `Display` on these variants can carry sqlite or syntect wording.
    #[tokio::test]
    async fn error_page_hides_internal_detail() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/aaaaaa").send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let body = res.text().await?;
        assert!(!body.contains("database error"), "body: {body}");
        assert!(!body.contains("entry not found"), "body: {body}");
        assert!(body.contains("does not exist"), "body: {body}");

        Ok(())
    }

    /// The JSON API shares the sanitised wording; only the log keeps the detail.
    #[tokio::test]
    async fn json_error_hides_internal_detail() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.delete("/aaaaaa").send().await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let body = res.text().await?;
        assert!(!body.contains("uid cookie"), "body: {body}");
        assert!(body.contains("not allowed"), "body: {body}");

        Ok(())
    }

    /// A generic title leaves every error tab indistinguishable from a working page.
    #[tokio::test]
    async fn error_page_is_titled() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let body = client
            .get("/aaaaaa")
            .header(header::ACCEPT, "text/html")
            .send()
            .await?
            .text()
            .await?;

        assert!(body.contains("<title>test: Error"), "body: {body}");

        Ok(())
    }

    /// The message is picked per request language, like the rest of the page.
    #[tokio::test]
    async fn error_message_is_translated() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let body = client
            .get("/aaaaaa")
            .header(header::ACCEPT_LANGUAGE, "de")
            .send()
            .await?
            .text()
            .await?;

        assert!(body.contains("existiert nicht"), "body: {body}");

        Ok(())
    }
}
