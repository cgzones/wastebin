pub mod burn;
pub mod index;
pub mod paste;
pub mod qr;
pub mod rendered;

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::cache::{Cache, Key, Mode};
use crate::errors::JsonErrorResponse;
use crate::handlers::PasswordRatelimit;
use crate::handlers::extract::{Accepts, RequestOrigin, Theme};
use crate::handlers::html::paste::PasteForm;
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
    #[must_use]
    pub(crate) fn password_input(&self, id: String) -> Response {
        PasswordInput {
            page: self.page.clone(),
            theme: self.theme,
            lang: self.lang,
            id,
        }
        .into_response()
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

/// Render `template` into a buffer sized for the `body_len` bytes of paste it wraps.
///
/// The derived [`WebTemplate`] response goes through askama's own `render`, which reserves
/// `SIZE_HINT` — the template's static text, a few kilobytes — and then doubles its way up to the
/// whole document. That is the same growth the emitter avoids by reserving, paid a second time on
/// a body whose size is already known here: measured at 2.7 ms against 0.45 ms for a full-size
/// render. Only the two paste views carry a body worth sizing for; every other page is small
/// enough that `SIZE_HINT` already covers it.
pub(crate) fn render_sized<T: Template>(template: &T, body_len: usize) -> Response {
    let mut buf = String::with_capacity(T::SIZE_HINT.saturating_add(body_len));

    if let Err(err) = template.render_into(&mut buf) {
        tracing::error!("failed to render template: {err}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        buf,
    )
        .into_response()
}

/// A paste read for one of the two HTML views, ready to be wrapped in that view's template.
pub(crate) struct PasteView {
    pub html: Arc<String>,
    pub is_available: bool,
    pub metadata: Metadata,
}

/// What reading a paste produced.
pub(crate) enum Read {
    /// The paste itself.
    Paste(PasteView),
    /// An answer that is not the paste: the burn interstitial or the password prompt.
    Other(Response),
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
    /// Read the paste at `key`, rendering its text with `render` off the async runtime.
    ///
    /// `action` is where the burn interstitial posts back to; the view that destroys the paste
    /// owns it. `id` is the path as given, used only to address the password prompt.
    pub(crate) async fn read(
        self,
        id: String,
        key: &Key,
        form: Option<PasteForm>,
        action: String,
        render: impl FnOnce(
            String,
            Option<String>,
            Highlighter,
        ) -> Result<Html, wastebin_highlight::Error>
        + Send
        + 'static,
    ) -> Result<Read, crate::Error> {
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
            return Ok(Read::Other(
                BurnConfirmation {
                    page: self.chrome.page.clone(),
                    theme: self.chrome.theme,
                    lang: self.chrome.lang,
                    action,
                    // The interstitial comes before any password is asked for.
                    title: metadata.into_public_parts().title,
                }
                .into_response(),
            ));
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

            return Ok(Read::Paste(PasteView {
                html,
                is_available: true,
                metadata,
            }));
        }

        let (data, is_available) = match self.db.get(key.id, password).await {
            Ok(Entry::Regular(data)) => (data, true),
            Ok(Entry::Burned(data)) => (data, false),
            Err(db::Error::NoPassword) => return Ok(Read::Other(self.chrome.password_input(id))),
            Err(err) => return Err(err.into()),
        };

        let Data { text, metadata } = data;
        let ext = key.ext.clone();
        let highlighter = self.highlighter.clone();
        let html: Arc<String> = self
            .renderer
            .run(move || render(text, ext, highlighter))
            .await??
            .into_inner();

        if is_available && no_password {
            tracing::trace!(?key, "cache item");
            self.cache.put(key, self.mode, Arc::clone(&html));
        }

        Ok(Read::Paste(PasteView {
            html,
            is_available,
            metadata,
        }))
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
