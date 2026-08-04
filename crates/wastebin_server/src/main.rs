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

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRef, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{Router, get, post};
use axum_extra::extract::cookie::Key;
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, SERVER, VARY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, X_XSS_PROTECTION,
};
use ratelimit::Ratelimiter;
use tokio::net::{TcpListener, UnixListener};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{MakeSpan, TraceLayer};

use crate::cache::Cache;
use crate::errors::Error;
use crate::handlers::extract::{Accepts, Theme};
use crate::handlers::{delete, download, html, insert, raw, robots, theme};
use crate::i18n::Lang;
use crate::render::Renderer;
use wastebin_core::db::Database;
use wastebin_core::env as core_env;

/// Reference counted [`page::Page`] wrapper.
pub(crate) type Page = Arc<page::Page>;

/// Reference counted [`highlight::Highlighter`] wrapper.
pub(crate) type Highlighter = Arc<wastebin_highlight::Highlighter>;

#[derive(Clone)]
pub(crate) struct AppState {
    db: Database,
    cache: Cache,
    key: Key,
    page: Page,
    highlighter: Highlighter,
    renderer: Renderer,
    ratelimit_insert: Option<Arc<Ratelimiter>>,
    ratelimit_delete: Option<Arc<Ratelimiter>>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

impl FromRef<AppState> for Highlighter {
    fn from_ref(state: &AppState) -> Self {
        state.highlighter.clone()
    }
}

impl FromRef<AppState> for Page {
    fn from_ref(state: &AppState) -> Self {
        state.page.clone()
    }
}

impl FromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for Cache {
    fn from_ref(state: &AppState) -> Self {
        state.cache.clone()
    }
}

impl FromRef<AppState> for Renderer {
    fn from_ref(state: &AppState) -> Self {
        state.renderer.clone()
    }
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

    (headers, response)
}

async fn handle_service_errors(
    State(page): State<Page>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;

    let error = match response.status() {
        StatusCode::PAYLOAD_TOO_LARGE => Error::PayloadTooLarge,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => Error::UnsupportedMediaType,
        _ => return response,
    };

    html::make_error(error, page, theme, lang, accepts).into_response()
}

/// Fallback for a path no route matched.
///
/// Without one, axum answers a bare 404 with an empty body, which is the only failure on the site
/// that does not look like the rest of it.
async fn handle_not_found(
    State(page): State<Page>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
) -> Response {
    html::make_error(Error::RouteNotFound, page, theme, lang, accepts).into_response()
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

    router
        .route("/", get(html::index::get).post(insert::api::post))
        .route("/robots.txt", get(robots::get))
        .route("/theme", get(theme::get))
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
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    timeout,
                ))
                .layer(CompressionLayer::new())
                .layer(from_fn_with_state(state.clone(), handle_service_errors))
                .layer(from_fn(security_headers_layer)),
        )
        .with_state(state)
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

    let page = Arc::new(page::Page::new(
        title,
        base_url,
        theme,
        expirations,
        max_body_size,
        max_expiration,
    ));
    let ratelimit_insert = ratelimit_insert.map(make_ratelimiter);
    let ratelimit_delete = ratelimit_delete.map(make_ratelimiter);
    let state = AppState {
        db,
        cache,
        key,
        page,
        highlighter,
        renderer: Renderer::with_available_parallelism(),
        ratelimit_insert,
        ratelimit_delete,
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
                let listener = UnixListener::bind(path)?;
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal())
                    .await?;
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
