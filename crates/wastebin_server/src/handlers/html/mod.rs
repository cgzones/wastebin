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
use crate::errors::JsonErrorResponse;
use crate::handlers::extract::{Accepts, Theme};
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
    /// Where the confirmation posts back to; the view that destroys the paste owns it.
    pub action: String,
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

/// Error response in whichever representation the client asked for.
pub(crate) enum ErrorResponse {
    Html(StatusCode, Box<Error>),
    Json(JsonErrorResponse),
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        match self {
            ErrorResponse::Html(status, page) => (status, *page).into_response(),
            ErrorResponse::Json(json) => json.into_response(),
        }
    }
}

/// Create an error response from `error`, carrying a [`StatusCode`] derived from `error` and a
/// description of it.
///
/// The description is a fixed, translated message for the kind of failure. The error's own
/// `Display` — which may quote sqlite, syntect or a panic payload — is only logged.
///
/// A client that asked for JSON gets the same envelope the API uses, rather than a rendered page
/// it has no way to read.
#[must_use]
pub fn make_error(
    error: crate::Error,
    page: Page,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
) -> ErrorResponse {
    if accepts == Accepts::Json {
        return ErrorResponse::Json(error.into());
    }

    error.log();

    let description = lang.t(error.message_key());
    let status = StatusCode::from(&error);

    ErrorResponse::Html(
        status,
        Box::new(Error {
            page,
            theme,
            lang,
            description,
        }),
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

    /// A client that asked for JSON got a full HTML error page it had no way to read.
    #[tokio::test]
    async fn json_clients_get_json_errors() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for path in [
            "/aaaaaa",
            "/md/aaaaaa",
            "/raw/aaaaaa",
            "/dl/aaaaaa",
            "/qr/aaaaaa",
        ] {
            let res = client
                .get(path)
                .header(header::ACCEPT, "application/json")
                .send()
                .await?;

            assert_eq!(res.status(), StatusCode::NOT_FOUND, "path {path}");
            assert_eq!(
                res.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "path {path}"
            );

            let body = res.text().await?;
            assert!(
                body.starts_with("{\"message\":"),
                "path {path} body: {body}"
            );
        }

        Ok(())
    }

    /// A browser must keep getting the rendered page, and a client stating no preference too.
    #[tokio::test]
    async fn html_clients_still_get_pages() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for accept in ["text/html,application/xhtml+xml,*/*;q=0.8", "*/*"] {
            let res = client
                .get("/aaaaaa")
                .header(header::ACCEPT, accept)
                .send()
                .await?;

            assert_eq!(
                res.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8",
                "accept {accept}"
            );
        }

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
