pub mod burn;
pub mod index;
pub mod paste;
pub mod qr;
pub mod rendered;

use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::cache::{Cache, Key, Mode};
use crate::errors::JsonErrorResponse;
use crate::handlers::extract::{Accepts, RequestOrigin, Theme};
use crate::handlers::html::paste::PasteForm;
use crate::handlers::{NoStore, PasswordRatelimit};
use crate::i18n::Lang;
use crate::render::Renderer;
use crate::{Highlighter, Page};
use wastebin_core::crypto::Password;
use wastebin_core::db;
use wastebin_core::db::Database;
use wastebin_core::db::read::{Data, Entry, Metadata};
use wastebin_highlight::Html;

/// The page context every rendered response is built from: the site's [`Page`] metadata plus the
/// three per-request preferences.
///
/// These four always travel together — no error page, prompt or interstitial can be built without
/// all of them — so they are extracted once rather than threaded through every handler signature.
/// Adding a fifth piece of page-wide context is a change to this struct, not to a dozen argument
/// lists.
#[derive(Clone)]
pub(crate) struct Chrome {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub accepts: Accepts,
}

impl<S> FromRequestParts<S> for Chrome
where
    Page: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            page: Page::from_ref(state),
            theme: Theme::from_request_parts(parts, state).await?,
            lang: Lang::from_request_parts(parts, state).await?,
            accepts: Accepts::from_request_parts(parts, state).await?,
        })
    }
}

impl Chrome {
    /// Turn `error` into a response in whichever representation the client asked for.
    ///
    /// The description is a fixed, translated message for the kind of failure. The error's own
    /// `Display` — which may quote sqlite, syntect or a panic payload — is only logged.
    ///
    /// A client that asked for JSON gets the same envelope the API uses, rather than a rendered
    /// page it has no way to read.
    #[must_use]
    pub(crate) fn error(&self, error: crate::Error) -> ErrorResponse {
        if self.accepts == Accepts::Json {
            return ErrorResponse::Json(error.into());
        }

        error.log();

        let description = self.lang.t(error.message_key());
        let status = StatusCode::from(&error);

        ErrorResponse::Html(
            status,
            Box::new(Error {
                page: self.page.clone(),
                theme: self.theme,
                lang: self.lang,
                description,
            }),
        )
    }

    /// Render the password prompt shown when a paste is encrypted but no password was supplied.
    ///
    /// The prompt is marked `no-store`, like everything else served for an encrypted paste.
    #[must_use]
    pub(crate) fn password_input(&self, action: FormAction) -> Response {
        PasswordInput {
            page: self.page.clone(),
            theme: self.theme,
            lang: self.lang,
            action,
        }
        .into_response()
        .no_store()
    }
}

/// Target of an interstitial's submit form, i.e. the view the paste was requested from.
#[derive(Clone, Debug)]
pub(crate) struct FormAction(String);

impl FormAction {
    /// Post back to the source view at `/{key}`.
    pub(crate) fn source(key: &Key) -> Self {
        Self(format!("/{key}"))
    }

    /// Post back to the rendered Markdown view at `/md/{key}`.
    pub(crate) fn rendered(key: &Key) -> Self {
        Self(format!("/md/{key}"))
    }
}

impl fmt::Display for FormAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error page showing a message.
#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
pub(crate) struct Error {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub description: &'static str,
}

/// Page showing password input. Its form posts back to `action`, the view the user came from.
#[derive(Template, WebTemplate)]
#[template(path = "encrypted.html")]
pub(crate) struct PasswordInput {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub action: FormAction,
}

/// Interstitial page shown before a burn-after-reading paste is revealed. Its form posts back to
/// `action`, the view the user came from.
#[derive(Template, WebTemplate)]
#[template(path = "burn-confirmation.html")]
pub(crate) struct BurnConfirmation {
    pub page: Page,
    pub theme: Theme,
    pub lang: Lang,
    pub title: Option<String>,
    /// Where the confirmation posts back to; the view that destroys the paste owns it.
    pub action: FormAction,
}

/// A paste read for one of the two HTML views, ready to be wrapped in that view's template.
pub(crate) struct PasteView {
    pub html: Arc<String>,
    pub is_available: bool,
    pub metadata: Metadata,
}

/// Everything `/{id}` and `/md/{id}` do identically around reading a paste.
///
/// The two views differ only in how they turn the stored text into HTML and in what they render
/// around the result. The burn interstitial, the password prompt, the attempt limiter and the
/// render cache are common to both — and were written out twice, which is how their check order
/// came to disagree — so they live here and each view supplies only its own two pieces.
pub(crate) struct PasteReader<'a> {
    pub db: &'a Database,
    pub cache: &'a Cache,
    pub renderer: &'a Renderer,
    pub ratelimit: &'a PasswordRatelimit,
    pub chrome: &'a Chrome,
    pub highlighter: &'a Highlighter,
    pub mode: Mode,
}

impl PasteReader<'_> {
    /// Read the paste at `key`, rendering its text with `render` off the async runtime and
    /// wrapping the result with `page`.
    ///
    /// The answer may instead be the burn interstitial or the password prompt. `action` is where
    /// those post back to; the view that destroys the paste owns it.
    pub(crate) async fn read(
        self,
        key: &Key,
        form: Option<PasteForm>,
        action: FormAction,
        render: impl FnOnce(
            String,
            Option<String>,
            Highlighter,
        ) -> Result<Html, wastebin_highlight::Error>
        + Send
        + 'static,
        page: impl FnOnce(PasteView) -> Response,
    ) -> Result<Response, crate::Error> {
        let password = form
            .as_ref()
            .and_then(|form| form.password.as_ref())
            // An empty field is no password at all: it derives nothing, yet it cost a token and
            // pushed the request off the cache on both the read and the write side.
            .filter(|password| !password.is_empty())
            .map(|password| Password::from(password.as_bytes().to_vec()));
        let confirmed = form.as_ref().and_then(|form| form.confirm_burn.as_deref()) == Some("1");
        let no_password = password.is_none();

        let metadata = self.db.get_metadata(key.id).await?;

        // Both views destroy the paste, so both have to ask first — otherwise anything that
        // follows the URL, including an image in someone else's rendered paste, destroys it on the
        // reader's behalf. This sits ahead of the limiter because the interstitial never reaches
        // `db.get`, and so never derives a key: it is not an attempt worth a token.
        if metadata.must_be_deleted && !confirmed {
            return Ok(BurnConfirmation {
                page: self.chrome.page.clone(),
                theme: self.chrome.theme,
                lang: self.chrome.lang,
                action,
                // The interstitial comes before any password is asked for.
                title: metadata.into_public_parts().title,
            }
            .into_response());
        }

        // Only an attempt that reaches argon2 is worth a token; see `raw::get`. The metadata read
        // above already settled whether this paste can derive anything.
        if !no_password && metadata.is_encrypted {
            self.ratelimit.check()?;
        }

        // An entry is only ever cached while it was available and unencrypted, so a hit can be
        // served from metadata alone — no need to read and decompress the body just to drop it.
        if let Some(html) = no_password
            .then(|| self.cache.get(key, self.mode))
            .flatten()
        {
            tracing::trace!(?key, "found cached item");

            return Ok(page(PasteView {
                html,
                is_available: true,
                metadata,
            }));
        }

        let Entry {
            data: Data { text, metadata },
            encrypted,
            burn,
        } = match self.db.get(key.id, password).await {
            Ok(entry) => entry,
            Err(db::Error::NoPassword) => return Ok(self.chrome.password_input(action)),
            Err(err) => return Err(err.into()),
        };
        let is_available = burn.is_none();

        let ext = key.ext.clone();
        let highlighter = self.highlighter.clone();
        let html: Arc<String> = match self
            .renderer
            .run(move || render(text, ext, highlighter))
            .await?
        {
            Ok(html) => html.into_inner(),
            // The general message sends the reader to `/raw` and the download, which refuse a
            // paste that burns.
            Err(wastebin_highlight::Error::TooLarge(_)) if burn.is_some() => {
                return Err(crate::Error::BurnRenderTooLarge);
            }
            Err(err) => return Err(err.into()),
        };

        if is_available && no_password {
            tracing::trace!(?key, "cache item");
            self.cache.put(key, self.mode, Arc::clone(&html));
        }

        let response = page(PasteView {
            html,
            is_available,
            metadata,
        });
        let response = if encrypted {
            response.no_store()
        } else {
            response
        };

        // Burned only once there is a page to show: a render or a template that fails drops the
        // ticket and leaves the paste for another attempt, rather than taking the one read with
        // it. The delete still settles concurrent readers — only the one whose burn removed the
        // row gets its page out.
        if let Some(burn) = burn
            && response.status().is_success()
        {
            self.db.burn(burn).await?;
        }

        Ok(response)
    }
}

/// A request a state-changing route may act on, i.e. one not driven from another site.
///
/// Extracting this *is* the check, so a route opts in by naming the type rather than by
/// remembering to call [`RequestOrigin::is_cross_site`] — the failure mode being a new POST route
/// that is unprotected by default and where nothing fails to say so.
pub(crate) struct SameSite;

impl<S> FromRequestParts<S> for SameSite
where
    Page: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let origin = RequestOrigin::from_request_parts(parts, state).await?;

        if origin.is_cross_site(&Page::from_ref(state).base_url) {
            let chrome = Chrome::from_request_parts(parts, state).await?;
            return Err(chrome.error(crate::Error::CrossSite));
        }

        Ok(Self)
    }
}

/// Error response in whichever representation the client asked for.
pub(crate) enum ErrorResponse {
    Html(StatusCode, Box<Error>),
    Json(JsonErrorResponse),
}

impl From<Infallible> for ErrorResponse {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        match self {
            ErrorResponse::Html(status, page) => (status, *page).into_response(),
            ErrorResponse::Json(json) => json.into_response(),
        }
    }
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

    /// A browser must keep getting the rendered page, and so must a client stating no preference
    /// or refusing JSON outright.
    #[tokio::test]
    async fn html_clients_still_get_pages() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for accept in [
            "text/html,application/xhtml+xml,*/*;q=0.8",
            "*/*",
            "application/json;q=0, */*;q=1",
        ] {
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
