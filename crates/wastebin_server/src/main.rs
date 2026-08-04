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
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, SERVER, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS, X_XSS_PROTECTION,
};
use ratelimit::Ratelimiter;
use tokio::net::{TcpListener, UnixListener};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{MakeSpan, TraceLayer};

use crate::cache::Cache;
use crate::errors::Error;
use crate::handlers::extract::Theme;
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
    // Rendered Markdown may embed remote images via `![](…)`; relax img-src for that route only.
    const CSP_STRICT: HeaderValue = HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; img-src 'self' data: ; style-src 'self' data: ; font-src 'self' data: ; object-src 'none' ; base-uri 'none' ; frame-ancestors 'none' ; form-action 'self' ;",
    );
    const CSP_RENDERED: HeaderValue = HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; img-src * data: ; style-src 'self' data: ; font-src 'self' data: ; object-src 'none' ; base-uri 'none' ; frame-ancestors 'none' ; form-action 'self' ;",
    );

    let csp = if req.uri().path().starts_with("/md/") {
        CSP_RENDERED
    } else {
        CSP_STRICT
    };

    let headers: [(HeaderName, HeaderValue); 7] = [
        (SERVER, HeaderValue::from_static(env!("CARGO_PKG_NAME"))),
        (CONTENT_SECURITY_POLICY, csp),
        (REFERRER_POLICY, HeaderValue::from_static("same-origin")),
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN")),
        (
            HeaderName::from_static("x-permitted-cross-domain-policies"),
            HeaderValue::from_static("none"),
        ),
        (X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block")),
    ];

    let mut response = next.run(req).await;

    // A paste URL is the only thing guarding its content, and the rendered page varies with the
    // caller's cookies, so nothing dynamic may be retained by a shared cache. Assets are served
    // from content-hashed routes and set their own long-lived policy, which is left alone.
    response
        .headers_mut()
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));

    (headers, response)
}

async fn handle_service_errors(
    State(page): State<Page>,
    theme: Theme,
    lang: Lang,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;

    let error = match response.status() {
        StatusCode::PAYLOAD_TOO_LARGE => Error::PayloadTooLarge,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => Error::UnsupportedMediaType,
        _ => return response,
    };

    html::make_error(error, page, theme, lang).into_response()
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

    let cache = Cache::new(cache_size)?;
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
    let highlighter = Arc::new(wastebin_highlight::Highlighter::default());
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

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}
