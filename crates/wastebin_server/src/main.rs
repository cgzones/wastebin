mod assets;
mod cache;
mod env;
mod errors;
mod handlers;
mod i18n;
mod page;
mod render;
#[cfg(test)]
mod test_helpers;

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRef, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{Router, get, post};
use axum_extra::extract::cookie::Key;
use http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, SERVER, VARY,
    WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, X_XSS_PROTECTION,
};
use ratelimit::Ratelimiter;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{MakeSpan, TraceLayer};

use crate::cache::Cache;
use crate::errors::Error;
use crate::handlers::html::Chrome;
use crate::handlers::{delete, download, health, html, insert, raw, robots, theme};
use crate::render::Renderer;
use wastebin_core::db::Database;
use wastebin_core::env as core_env;

/// Reference counted [`page::Page`] wrapper.
pub(crate) type Page = Arc<page::Page>;

/// Reference counted [`highlight::Highlighter`] wrapper.
pub(crate) type Highlighter = Arc<wastebin_highlight::Highlighter>;

#[derive(Clone, FromRef)]
pub(crate) struct AppState {
    db: Database,
    cache: Cache,
    key: Key,
    page: Page,
    highlighter: Highlighter,
    renderer: Renderer,
    // Skipped: all three share a type, so deriving would emit conflicting impls. The password
    // limiter is reached through the `PasswordRatelimit` newtype instead.
    #[from_ref(skip)]
    ratelimit_insert: Option<Arc<Ratelimiter>>,
    #[from_ref(skip)]
    ratelimit_delete: Option<Arc<Ratelimiter>>,
    #[from_ref(skip)]
    ratelimit_password: Option<Arc<Ratelimiter>>,
}

/// Request span that records the path but not the query string.
///
/// A paste URL carries its `?owner=` deletion token in the query, and the id itself is the only
/// thing guarding the content, so neither belongs in a log line that outlives the request.
#[derive(Clone, Copy)]
struct PathOnlyMakeSpan;

impl<B> MakeSpan<B> for PathOnlyMakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        tracing::debug_span!(
            "request",
            method = %request.method(),
            path = %request.uri().path(),
            version = ?request.version(),
        )
    }
}

async fn security_headers_layer(req: Request, next: Next) -> impl IntoResponse {
    // Rendered Markdown may embed remote images via `![](…)`; relax img-src for that route only,
    // and only to TLS origins so a paste cannot force a plaintext request.
    const CSP_STRICT: HeaderValue = HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; img-src 'self' data: ; style-src 'self' data: ; font-src 'self' data: ; object-src 'none' ; base-uri 'none' ; frame-ancestors 'none' ; form-action 'self' ; require-trusted-types-for 'script' ; trusted-types 'none' ;",
    );
    const CSP_RENDERED: HeaderValue = HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; img-src 'self' https: data: ; style-src 'self' data: ; font-src 'self' data: ; object-src 'none' ; base-uri 'none' ; frame-ancestors 'none' ; form-action 'self' ; require-trusted-types-for 'script' ; trusted-types 'none' ;",
    );

    // Every feature wastebin never uses. `clipboard-write` is deliberately absent: the copy
    // buttons need it and its default allowlist is already `self`.
    const PERMISSIONS_POLICY: HeaderValue = HeaderValue::from_static(
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
    );

    let csp = if req.uri().path().starts_with("/md/") {
        CSP_RENDERED
    } else {
        CSP_STRICT
    };

    let headers: [(HeaderName, HeaderValue); 10] = [
        // Every page already carries the exact version in its `generator` meta tag, so withholding
        // it here bought nothing and only left the two disagreeing.
        (
            SERVER,
            HeaderValue::from_static(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            )),
        ),
        // Severs `window.opener` and blocks other origins from pulling responses in as no-cors
        // subresources. Non-browser clients (curl, the API) are unaffected.
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ),
        (CONTENT_SECURITY_POLICY, csp),
        (REFERRER_POLICY, HeaderValue::from_static("same-origin")),
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (
            HeaderName::from_static("x-permitted-cross-domain-policies"),
            HeaderValue::from_static("none"),
        ),
        // Explicitly off: the auditor this enabled was removed from every current browser after
        // proving to be an XSS vector of its own, and `1; mode=block` still reaches the ones that
        // kept it. The CSP above is what actually defends these pages.
        (X_XSS_PROTECTION, HeaderValue::from_static("0")),
    ];

    let mut response = next.run(req).await;

    // A paste URL is the only thing guarding its content, and the rendered page varies with the
    // caller's cookies, so nothing dynamic may be retained by a shared cache. Assets are served
    // from content-hashed routes and set their own long-lived policy, which is left alone.
    response
        .headers_mut()
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));

    // A rendered page depends on the `pref` and `uid` cookies and on the negotiated language, so
    // its URL alone does not identify it. Assets do not vary that way and are left out, so they
    // stay shareable between visitors. Appended rather than set, because the compression layer
    // sits outside this one and adds `accept-encoding` of its own.
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .is_some_and(|content_type| content_type.starts_with("text/html"))
    {
        response
            .headers_mut()
            .append(VARY, HeaderValue::from_static("accept-language, cookie"));
    }

    // A 401 must name a challenge, and the only credential here is the paste password — carried
    // either by the prompt's form or by the `wastebin-password` header. The scheme is named after
    // it rather than reusing `Basic`, whose dialog browsers would raise over the prompt.
    if response.status() == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .entry(WWW_AUTHENTICATE)
            .or_insert(HeaderValue::from_static(
                "wastebin-password realm=\"paste\"",
            ));
    }

    (headers, response)
}

async fn handle_service_errors(chrome: Chrome, req: Request, next: Next) -> Response {
    // `answer_options` answers OPTIONS out of the same 405, so rendering a page here would only
    // build one for it to throw away. The status is what it matches on, and that survives either
    // way — this just skips the wasted render.
    let asked_options = req.method() == http::Method::OPTIONS;
    let response = next.run(req).await;

    // An extractor answers a request it could not parse itself, in plain text, quoting the parser
    // — the field names of the handler's own type and where in the input it gave up. Every error
    // this crate raises is rendered instead, so a `text/plain` body at one of these statuses is
    // one of those rejections rather than an answer a handler built.
    let is_rejection = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .is_some_and(|content_type| content_type.starts_with("text/plain"));

    let status = response.status();

    // A 405 is the router's answer, not an extractor's, so it is recognised by status alone.
    let error = if status == StatusCode::METHOD_NOT_ALLOWED {
        if asked_options {
            return response;
        }

        Error::MethodNotAllowed
    } else {
        // 413 and 415 describe the request whatever produced them, so they are rewritten on
        // sight; 422 and 400 are only ours to reinterpret when a rejection is what produced them.
        let ours = is_rejection
            || matches!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNSUPPORTED_MEDIA_TYPE
            );

        let Some(error) = ours.then(|| errors::rejection_error(status)).flatten() else {
            return response;
        };

        error
    };

    // The `Allow` a 405 is required to carry is not on `response` yet: axum attaches it as the
    // inner router completes, after this layer has already run, so the rendered page inherits it
    // without anything being carried over by hand.
    chrome.error(error).into_response()
}

/// Answer `OPTIONS` from the `Allow` list the router already computes.
///
/// The routes only register the methods they serve, so axum rejects `OPTIONS` with a 405 that
/// nonetheless names every method allowed there. Turning that into the 204 the method is defined
/// to return costs nothing and keeps the list in one place.
async fn answer_options(req: Request, next: Next) -> Response {
    let asked = req.method() == http::Method::OPTIONS;
    let mut response = next.run(req).await;

    if response.status() != StatusCode::METHOD_NOT_ALLOWED {
        return response;
    }

    let Some(allowed) = response.headers().get(ALLOW).and_then(|v| v.to_str().ok()) else {
        return response;
    };

    // The router never lists OPTIONS, since it does not route it — but this handler serves it.
    let Ok(allow) = HeaderValue::try_from(format!("{allowed},OPTIONS")) else {
        return response;
    };

    // `Allow` names what the resource supports, so it cannot depend on which method asked. Naming
    // OPTIONS only in the answer to OPTIONS left a 405 telling the same client, about the same
    // resource, that a method it had just been served did not exist.
    response.headers_mut().insert(ALLOW, allow);

    if !asked {
        return response;
    }

    *response.status_mut() = StatusCode::NO_CONTENT;
    *response.body_mut() = axum::body::Body::empty();

    // A 204 carries no representation, so neither header may describe one.
    let headers = response.headers_mut();
    headers.remove(CONTENT_TYPE);
    headers.remove(http::header::CONTENT_LENGTH);

    response
}

/// Fallback for a path no route matched.
///
/// Without one, axum answers a bare 404 with an empty body, which is the only failure on the site
/// that does not look like the rest of it.
async fn handle_not_found(chrome: Chrome) -> Response {
    chrome.error(Error::RouteNotFound).into_response()
}

/// Build a rate limiter refilling `per_second` tokens every second.
fn make_ratelimiter(per_second: std::num::NonZeroU32) -> Arc<Ratelimiter> {
    let value = per_second.get().into();

    Arc::new(
        Ratelimiter::builder(value)
            .max_tokens(value)
            .initial_available(value)
            .build()
            .expect("valid rate limiter values"),
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("received signal, exiting ...");
}

fn make_app(state: AppState, timeout: Duration, max_body_size: usize) -> Router {
    let mut router = Router::new();

    // Register every embedded asset under its content-hashed route, so adding an asset in
    // `page.rs` cannot silently miss its route here.
    for asset in state.page.assets.iter() {
        let route = asset.route().to_owned();
        let asset = asset.clone();

        router = router.route(&route, get(move || std::future::ready(asset.response())));
    }

    let app = router
        .route("/", get(html::index::get).post(insert::api::post))
        .route("/robots.txt", get(robots::get))
        .route("/health", get(health::get))
        .route("/theme", post(theme::post))
        .route("/new", post(insert::form::post))
        .route("/qr/{id}", get(html::qr::get))
        .route(
            "/md/{id}",
            get(html::rendered::get).post(html::rendered::get),
        )
        .route("/burn/{id}", get(html::burn::get))
        .route(
            "/{id}",
            get(html::paste::get)
                .post(html::paste::get)
                .delete(delete::api::delete),
        )
        .route("/dl/{id}", get(download::get))
        .route("/raw/{id}", get(raw::get))
        .route("/delete/{id}", post(delete::form::delete))
        .fallback(handle_not_found)
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(max_body_size))
                .layer(TraceLayer::new_for_http().make_span_with(PathOnlyMakeSpan))
                .layer(CompressionLayer::new())
                // Outside `handle_service_errors`, which answers by building a fresh page rather
                // than by amending the one it was handed: inside, every header added here was
                // dropped again for exactly the statuses that layer renders.
                .layer(from_fn(security_headers_layer))
                // Inside the header layer: this one synthesises its response rather than amending
                // one, so from outside its 408 left with no CSP, no `nosniff` and no
                // `Cache-Control` — on a response whose URL names a paste.
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    timeout,
                ))
                .layer(from_fn_with_state(state.clone(), handle_service_errors)),
        )
        .with_state(state);

    // Wrapping the finished router, rather than layering onto it, is what lets `answer_options`
    // read the `Allow` header: axum attaches that as the inner router's response completes, after
    // any middleware layered onto the routes themselves has already run.
    Router::new()
        .fallback_service(app)
        .layer(from_fn(answer_options))
}

/// Access mode for a Unix socket this process creates.
///
/// Connecting to a Unix socket needs write permission on it, so the mode is what decides who may
/// reach the server. Left to the umask it is whatever the service manager happened to set — `0777`
/// under a umask of zero. Owner and group, so a reverse proxy is let in by sharing the group
/// rather than by the socket standing open to every local account.
const SOCKET_MODE: u32 = 0o660;

/// Bind the Unix socket at `path`, clearing a socket left behind by an earlier run.
///
/// Neither a graceful shutdown nor a crash can be relied on to unlink the socket file, and
/// `bind` refuses a path that still exists: without this the *second* start of the same service
/// fails with `EADDRINUSE`, so a restart never comes back. Only a socket nothing answers on is
/// removed — one with a live listener means another instance owns the path, and anything that is
/// not a socket is the operator's file rather than ours.
async fn bind_unix_socket(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).await.is_ok() {
                return Err(std::io::Error::other(format!(
                    "{} is already served by a running instance",
                    path.display()
                )));
            }

            tracing::info!("removing stale socket {}", path.display());
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;

    Ok(listener)
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cache_size = env::cache_size()?;
    let cache_max_bytes = env::cache_max_bytes()?;
    let method = env::database_method()?;
    let key = env::signing_key()?;
    let socket_type = env::socket_type()?;
    let max_body_size = env::max_body_size()?;
    let base_url = env::base_url()?;
    let timeout = env::http_timeout()?;
    let expirations = env::expiration_set()?;
    let theme = env::theme()?;
    let title = env::title()?;
    let ratelimit_insert = env::ratelimit_insert()?;
    let ratelimit_delete = env::ratelimit_delete()?;
    let ratelimit_password = env::ratelimit_password()?;
    let max_expiration = env::max_expiration()?;
    env::validate_expirations(&expirations, max_expiration)?;

    let highlighter = Arc::new(wastebin_highlight::Highlighter::default());
    let cache = Cache::new(cache_size, cache_max_bytes, Arc::clone(&highlighter))?;
    let (db, db_handler) = Database::new(method, core_env::password_hash_salt()?)?;

    tracing::debug!("serving on {socket_type}");
    if let Some(size) = cache_size {
        tracing::debug!("caching {size} paste highlights")
    } else {
        tracing::debug!("caching disabled")
    }
    tracing::debug!("restricting maximum body size to {max_body_size} bytes");
    tracing::debug!("enforcing a http timeout of {timeout:#?}");
    tracing::debug!("enforcing a maximum expiry of {max_expiration:?}");
    tracing::debug!("ratelimiting insert amount to {ratelimit_insert:?} per second");
    tracing::debug!("ratelimiting delete attempts to {ratelimit_delete:?} per second");
    tracing::debug!("ratelimiting password attempts to {ratelimit_password:?} per second");

    let page = Arc::new(page::Page::new(
        title,
        base_url,
        theme,
        expirations,
        max_body_size,
        max_expiration,
        &highlighter,
    ));
    let ratelimit_insert = ratelimit_insert.map(make_ratelimiter);
    let ratelimit_delete = ratelimit_delete.map(make_ratelimiter);
    let ratelimit_password = ratelimit_password.map(make_ratelimiter);
    let state = AppState {
        db,
        cache,
        key,
        page,
        highlighter,
        renderer: Renderer::with_available_parallelism(),
        ratelimit_insert,
        ratelimit_delete,
        ratelimit_password,
    };

    let app = make_app(state, timeout, max_body_size);

    let serve = async {
        match socket_type {
            env::SocketType::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal())
                    .await?;
            }
            env::SocketType::Unix(path) => {
                let listener = bind_unix_socket(&path).await?;
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal())
                    .await?;

                if let Err(err) = std::fs::remove_file(&path) {
                    tracing::warn!("could not remove socket {}: {err}", path.display());
                }
            }
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    tokio::try_join!(serve, async { db_handler.await.map_err(Into::into) })?;

    Ok(())
}

/// Upper bound on threads for blocking work, per CPU.
///
/// Everything dispatched to the blocking pool is CPU- or memory-bound: key derivation, syntax
/// highlighting, Markdown rendering, compression and the database. None of it benefits from
/// running hundreds deep, and tokio's default of 512 threads is a ceiling high enough that a
/// backlog turns into memory exhaustion before it turns into queueing. A small multiple of the
/// CPU count leaves headroom for the database handler, which occupies a thread permanently.
const BLOCKING_THREADS_PER_CPU: usize = 4;

fn main() -> ExitCode {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(cpus * BLOCKING_THREADS_PER_CPU)
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("Error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(start()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use http::header::{VARY, X_FRAME_OPTIONS};

    /// Collect every `Vary` value, lowercased, across however many header lines carry them.
    async fn vary_of(client: &Client, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let res = client.get(path).send().await?;

        Ok(res
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
            .to_lowercase())
    }

    /// The same URL renders differently per `pref`/`uid` cookie and per `Accept-Language`, so a
    /// shared cache told only about `accept-encoding` would hand one visitor another's page.
    #[tokio::test]
    async fn html_varies_on_cookies_and_language() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for path in ["/", "/aaaaaa"] {
            let vary = vary_of(&client, path).await?;

            assert!(vary.contains("cookie"), "path {path} vary: {vary}");
            assert!(vary.contains("accept-language"), "path {path} vary: {vary}");
        }

        Ok(())
    }

    /// `TimeoutLayer` synthesises its response itself, so sitting outside the header layer meant a
    /// 408 left with no CSP, no `nosniff`, no `X-Frame-Options` and no `Cache-Control` — on a
    /// response whose URL names a paste.
    #[tokio::test]
    async fn a_timed_out_response_keeps_its_security_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new_timing_out(StoreCookies(false)).await;

        // A route whose work goes to a blocking thread, so the request is certain to yield and
        // the already-elapsed timer is certain to win; a handler that never awaits can outrun it.
        // Seeded rather than posted, because an insert through this client would time out too.
        let id = client
            .seed(wastebin_core::db::write::Entry {
                text: String::from("FooBarBaz"),
                ..Default::default()
            })
            .await?;

        let res = client.get(&format!("/burn/{id}.txt")).send().await?;
        assert_eq!(res.status(), http::StatusCode::REQUEST_TIMEOUT);

        for header in [
            http::header::CONTENT_SECURITY_POLICY,
            http::header::X_CONTENT_TYPE_OPTIONS,
            X_FRAME_OPTIONS,
            http::header::CACHE_CONTROL,
        ] {
            assert!(
                res.headers().contains_key(&header),
                "408 is missing {header}",
            );
        }

        Ok(())
    }

    /// An extractor answers a body it cannot parse itself, in plain text, quoting the parser: the
    /// field names of the internal type and where in the input it gave up. That is exactly the
    /// detail `Error::message_key` exists to keep out of a response, and it went out unlocalised
    /// and outside the JSON envelope besides.
    #[tokio::test]
    async fn an_extractor_rejection_is_answered_like_any_other_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client
            .post_json()
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json")
            .body(r#"{"text":"AAA","text":"BBB"}"#)
            .send()
            .await?;

        assert_eq!(res.status(), http::StatusCode::UNPROCESSABLE_ENTITY);

        let body = res.text().await?;
        assert!(
            !body.contains("Failed to deserialize") && !body.contains("duplicate field"),
            "parser detail reached the client: {body}"
        );
        assert!(
            body.starts_with(r#"{"message":"#),
            "not the JSON envelope: {body}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn rewritten_errors_keep_their_security_headers() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;

        // 413 from the body limit, 415 from the content type, 405 from the method.
        let too_large = client
            .post_json()
            .header(http::header::CONTENT_TYPE, "application/json")
            .body("x".repeat(2 * 1024 * 1024))
            .send()
            .await?;
        assert_eq!(too_large.status(), http::StatusCode::PAYLOAD_TOO_LARGE);

        let wrong_type = client
            .post_json()
            .header(http::header::CONTENT_TYPE, "application/xml")
            .body("<x/>")
            .send()
            .await?;
        assert_eq!(
            wrong_type.status(),
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let wrong_method = client.get("/theme").send().await?;
        assert_eq!(wrong_method.status(), http::StatusCode::METHOD_NOT_ALLOWED);

        for (name, res) in [
            ("413", too_large),
            ("415", wrong_type),
            ("405", wrong_method),
        ] {
            let headers = res.headers();

            for header in [
                http::header::CONTENT_SECURITY_POLICY,
                http::header::X_CONTENT_TYPE_OPTIONS,
                X_FRAME_OPTIONS,
                http::header::CACHE_CONTROL,
            ] {
                assert!(
                    headers.contains_key(&header),
                    "{name} is missing {header}: {headers:?}"
                );
            }
        }

        Ok(())
    }

    /// The `<link rel="icon">` points at the PNG, but `/favicon.ico` is probed blindly by link
    /// unfurlers and feed readers — and `/{id}` would otherwise answer them with an error page.
    #[tokio::test]
    async fn the_icon_is_served_under_both_paths() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let png = client.get("/favicon.png").send().await?;
        assert_eq!(png.status(), http::StatusCode::OK);
        assert_eq!(
            png.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        let png = png.bytes().await?;

        let ico = client.get("/favicon.ico").send().await?;
        assert_eq!(ico.status(), http::StatusCode::OK);
        assert_eq!(ico.bytes().await?, png);

        // The page itself references the honestly-named one.
        let body = client.get("/").send().await?.text().await?;
        assert!(body.contains(r#"href="/favicon.png""#), "body: {body}");

        Ok(())
    }

    /// `OPTIONS` is defined to report what a resource accepts, not to be refused by it.
    #[tokio::test]
    async fn options_reports_the_allowed_methods() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for (path, expected) in [("/", "GET,HEAD,POST"), ("/robots.txt", "GET,HEAD")] {
            let res = client
                .request(reqwest::Method::OPTIONS, path)
                .send()
                .await?;

            assert_eq!(res.status(), http::StatusCode::NO_CONTENT, "path {path}");

            let allow = res
                .headers()
                .get(http::header::ALLOW)
                .expect("allow header")
                .to_str()?;

            assert_eq!(allow, format!("{expected},OPTIONS"), "path {path}");
            assert!(res.text().await?.is_empty(), "path {path}");
        }

        Ok(())
    }

    /// Only `OPTIONS` is answered this way — a genuinely wrong method is still refused.
    #[tokio::test]
    async fn other_methods_are_still_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client
            .request(reqwest::Method::PUT, "/robots.txt")
            .send()
            .await?;

        assert_eq!(res.status(), http::StatusCode::METHOD_NOT_ALLOWED);

        Ok(())
    }

    /// An unmatched path used to answer with an empty-bodied 404, the one failure on the site
    /// that did not look like the rest of it.
    #[tokio::test]
    async fn unknown_route_renders_the_error_page() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/no/such/path").send().await?;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );

        let body = res.text().await?;
        assert!(body.contains("<!DOCTYPE html>"), "body: {body}");
        assert!(body.contains("does not exist"), "body: {body}");

        Ok(())
    }

    /// A wrong method used to answer with an empty body and no content type, so bookmarking a
    /// form action showed a blank page. It still has to name what it would have allowed.
    #[tokio::test]
    async fn wrong_method_renders_the_error_page() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/new").send().await?;
        assert_eq!(res.status(), http::StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers().get(http::header::ALLOW).unwrap(),
            "POST,OPTIONS"
        );
        assert_eq!(
            res.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );

        let body = res.text().await?;
        assert!(body.contains("<!DOCTYPE html>"), "body: {body}");
        assert!(body.contains("not allowed"), "body: {body}");

        Ok(())
    }

    /// `answer_options` builds its 204 out of the very 405 the page above now replaces, and the
    /// `Allow` it needs is attached only after that replacement happens. Both still have to hold.
    #[tokio::test]
    async fn options_still_answers_with_no_content() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.request(http::Method::OPTIONS, "/new").send().await?;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        assert_eq!(
            res.headers().get(http::header::ALLOW).unwrap(),
            "POST,OPTIONS"
        );

        Ok(())
    }

    /// `Allow` describes the target resource, not the request that happened to reach it, so the
    /// 405 and the 204 have to name the same set. OPTIONS used to be appended only on the way out
    /// of an OPTIONS request, leaving the 405 disowning a method the very next request was served.
    #[tokio::test]
    async fn allow_agrees_between_405_and_options() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for path in ["/", "/new", "/theme", "/robots.txt", "/aaaaaaaaaaa"] {
            let rejected = client.request(http::Method::PUT, path).send().await?;
            assert_eq!(
                rejected.status(),
                http::StatusCode::METHOD_NOT_ALLOWED,
                "path {path}"
            );

            let offered = client.request(http::Method::OPTIONS, path).send().await?;
            assert_eq!(
                offered.status(),
                http::StatusCode::NO_CONTENT,
                "path {path}"
            );

            let from_405 = rejected.headers().get(http::header::ALLOW);
            let from_options = offered.headers().get(http::header::ALLOW);

            assert_eq!(from_405, from_options, "path {path}");
            assert!(
                from_405
                    .expect("allow header")
                    .to_str()?
                    .contains("OPTIONS"),
                "path {path} does not name the method it just served"
            );
        }

        Ok(())
    }

    /// A 401 is required to name a challenge, and the layer answers for every one of them rather
    /// than each handler remembering to. Both credential failures have to carry it.
    #[tokio::test]
    async fn every_401_carries_a_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let paste = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: "FooBarBaz".to_string(),
                password: Some("hunter2".to_string()),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;
        let raw = format!("/raw{}", paste.path);

        for password in [None, Some("wrong")] {
            let mut request = client
                .get(&raw)
                .header(http::header::ACCEPT, "application/json");

            if let Some(password) = password {
                request = request.header("wastebin-password", password);
            }

            let res = request.send().await?;
            assert_eq!(
                res.status(),
                http::StatusCode::UNAUTHORIZED,
                "password {password:?}"
            );
            assert_eq!(
                res.headers().get(http::header::WWW_AUTHENTICATE).unwrap(),
                "wastebin-password realm=\"paste\"",
                "password {password:?}"
            );
            assert!(!res.text().await?.contains("FooBarBaz"));
        }

        Ok(())
    }

    /// The fallback negotiates like every other failure.
    #[tokio::test]
    async fn unknown_route_answers_json_clients() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client
            .get("/no/such/path")
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await?;

        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        Ok(())
    }

    /// The `generator` meta tag in every page already names the version, so the header agrees
    /// with it rather than reporting a bare product name.
    #[tokio::test]
    async fn server_header_carries_the_version() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let res = client.get("/").send().await?;

        assert_eq!(
            res.headers().get(http::header::SERVER).unwrap(),
            concat!("wastebin/", env!("CARGO_PKG_VERSION"))
        );

        Ok(())
    }

    /// The XSS auditor was removed from current browsers after becoming a vulnerability itself,
    /// so the header must switch it off rather than ask for it.
    #[tokio::test]
    async fn xss_auditor_is_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let res = client.get("/").send().await?;

        assert_eq!(
            res.headers().get(http::header::X_XSS_PROTECTION).unwrap(),
            "0"
        );

        Ok(())
    }

    /// Assets are identical for every visitor; varying them on cookies would defeat sharing.
    #[tokio::test]
    async fn assets_do_not_vary_on_cookies() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let body = client.get("/").send().await?.text().await?;
        let route = body
            .split("href=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a stylesheet route");

        let vary = vary_of(&client, route).await?;
        assert!(!vary.contains("cookie"), "route {route} vary: {vary}");

        Ok(())
    }

    #[tokio::test]
    async fn frame_options_matches_csp_frame_ancestors() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let res = client.get("/").send().await?;

        // The CSP says `frame-ancestors 'none'`; the legacy header must not advertise a weaker
        // policy to consumers that only understand it.
        assert_eq!(res.headers().get(X_FRAME_OPTIONS).unwrap(), "DENY");

        Ok(())
    }

    #[tokio::test]
    async fn permissions_policy_disables_unused_features() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;
        let res = client.get("/").send().await?;

        let policy = res
            .headers()
            .get("permissions-policy")
            .expect("permissions-policy header")
            .to_str()?
            .to_owned();

        for feature in ["camera", "microphone", "geolocation", "payment", "usb"] {
            assert!(policy.contains(&format!("{feature}=()")), "got: {policy}");
        }

        // The copy buttons call `navigator.clipboard.writeText`, whose default allowlist is
        // already `self` — denying it here would break them.
        assert!(!policy.contains("clipboard"), "got: {policy}");

        Ok(())
    }

    #[tokio::test]
    async fn csp_requires_trusted_types() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        // Both the strict and the Markdown-relaxed policy must carry it.
        for path in ["/", "/md/"] {
            let res = client.get(path).send().await?;
            let csp = res
                .headers()
                .get(http::header::CONTENT_SECURITY_POLICY)
                .expect("csp header")
                .to_str()?
                .to_owned();

            assert!(
                csp.contains("require-trusted-types-for 'script'"),
                "path {path}, csp: {csp}"
            );
            assert!(
                csp.contains("trusted-types 'none'"),
                "path {path}, csp: {csp}"
            );
        }

        Ok(())
    }

    /// Every page used to reach the browser with no heading at all: the visible titles were
    /// `<div class="dialog-header">`, and the pages without one had nothing to offer instead.
    #[tokio::test]
    async fn every_page_carries_a_heading() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let insert = async |text: &str, extension: Option<&str>, burn: bool| {
            let data = crate::handlers::insert::form::Entry {
                text: text.to_owned(),
                extension: extension.map(ToOwned::to_owned),
                burn_after_reading: burn.then(|| String::from("on")),
                ..Default::default()
            };
            let res = client.post_form().form(&data).send().await.unwrap();
            let location = res.headers().get("location").unwrap().to_str().unwrap();
            location.rsplit('/').next().unwrap().to_owned()
        };

        let plain = insert("hello", None, false).await;
        let markdown = insert("# Doc", Some("md"), false).await;
        let burning = insert("secret", None, true).await;

        let paths = [
            String::from("/"),
            format!("/{plain}"),
            format!("/md/{markdown}"),
            format!("/qr/{plain}"),
            format!("/burn/{burning}"),
            format!("/{burning}"),
            String::from("/nope"),
        ];

        for path in paths {
            let body = client.get(&path).send().await?.text().await?;
            assert!(
                body.contains("<h1"),
                "{path} rendered without a heading: {body}"
            );
        }

        Ok(())
    }

    /// Every template that ships a `<button>`, so a new one cannot quietly default to `submit`.
    const TEMPLATES: [(&str, &str); 7] = [
        ("index.html", include_str!("../templates/index.html")),
        ("paste.html", include_str!("../templates/paste.html")),
        (
            "encrypted.html",
            include_str!("../templates/encrypted.html"),
        ),
        (
            "burn-confirmation.html",
            include_str!("../templates/burn-confirmation.html"),
        ),
        ("burn.html", include_str!("../templates/burn.html")),
        ("error.html", include_str!("../templates/error.html")),
        (
            "theme-switcher.html",
            include_str!("../templates/theme-switcher.html"),
        ),
    ];

    /// A `<button>` with no `type` submits the form it sits in. The copy button was the one that
    /// left it out; it happens to sit outside the delete form it shares a nav group with, so the
    /// omission cost nothing until someone moved either of them.
    #[test]
    fn shipped_buttons_declare_their_type() {
        for (name, source) in TEMPLATES {
            for (offset, _) in source.match_indices("<button") {
                let tag = &source[offset..];
                let end = tag.find('>').expect("a closed button tag");

                assert!(
                    tag[..end].contains("type=\""),
                    "{name} has a button without a type: {}",
                    &tag[..end]
                );
            }
        }
    }

    #[test]
    fn shipped_scripts_use_no_trusted_types_sinks() {
        const SCRIPTS: [(&str, &str); 4] = [
            ("index.js", include_str!("javascript/index.js")),
            ("paste.js", include_str!("javascript/paste.js")),
            ("burn.js", include_str!("javascript/burn.js")),
            (
                "password-toggle.js",
                include_str!("javascript/password-toggle.js"),
            ),
        ];

        // `trusted-types 'none'` forbids creating a policy, so any of these would throw at
        // runtime rather than fail closed.
        for (name, source) in SCRIPTS {
            for sink in [
                "innerHTML",
                "outerHTML",
                "insertAdjacentHTML",
                "document.write",
            ] {
                assert!(!source.contains(sink), "{name} uses {sink}");
            }
        }
    }

    /// Sanitising keeps `class` so highlighted code blocks survive, so a paste may name any of the
    /// site's own chrome classes — and `.toast` is `position: fixed` at `z-index: 1000`, enough to
    /// float a fake "session expired" prompt over the page. The stylesheet is what keeps rendered
    /// paste markup inside the article; there is no JS runtime here to assert it against a DOM.
    #[test]
    fn rendered_markdown_cannot_leave_the_article_flow() {
        let css = include_str!("style.css");

        let (_, containment) = css
            .split_once(".markdown-body [class] {")
            .expect("rendered markdown must neutralise positioning on classed descendants");
        let (containment, _) = containment.split_once('}').expect("unterminated rule");

        assert!(
            containment.contains("position: static"),
            "borrowed chrome could still be lifted out of the flow: {containment}"
        );
        assert!(
            containment.contains("z-index: auto"),
            "borrowed chrome could still be stacked over the page: {containment}"
        );
    }

    #[tokio::test]
    async fn cross_origin_isolation_headers() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for path in ["/", "/robots.txt"] {
            let res = client.get(path).send().await?;
            let headers = res.headers();

            assert_eq!(
                headers.get("cross-origin-opener-policy").unwrap(),
                "same-origin",
                "path {path}"
            );
            assert_eq!(
                headers.get("cross-origin-resource-policy").unwrap(),
                "same-origin",
                "path {path}"
            );
        }

        Ok(())
    }
}
