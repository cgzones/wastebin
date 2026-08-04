use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use axum_extra::extract::cookie::Key;
use reqwest::RequestBuilder;
use tokio::net::TcpListener;

use crate::cache::Cache;
use crate::{Ratelimiter, page};

use wastebin_core::db::{self, Database};
use wastebin_core::expiration::ExpirationSet;
use wastebin_highlight::{Highlighter, Theme};

pub(crate) struct Client {
    client: reqwest::Client,
    addr: SocketAddr,
}

/// Determine if the client should store cookies.
pub(crate) struct StoreCookies(pub bool);

impl Client {
    pub(crate) async fn new(store_cookies: StoreCookies) -> Self {
        Self::new_with_ratelimits(store_cookies, None, None).await
    }

    /// Like [`Self::new`] but with a configurable delete rate limiter, for tests that need to
    /// exercise the delete limiter itself.
    pub(crate) async fn new_with_ratelimit_delete(
        store_cookies: StoreCookies,
        ratelimit_delete: Option<Arc<Ratelimiter>>,
    ) -> Self {
        Self::new_with_ratelimits(store_cookies, ratelimit_delete, None).await
    }

    /// Like [`Self::new`] but with a configurable password-attempt limiter.
    pub(crate) async fn new_with_ratelimit_password(
        store_cookies: StoreCookies,
        ratelimit_password: Option<Arc<Ratelimiter>>,
    ) -> Self {
        Self::new_with_ratelimits(store_cookies, None, ratelimit_password).await
    }

    async fn new_with_ratelimits(
        store_cookies: StoreCookies,
        ratelimit_delete: Option<Arc<Ratelimiter>>,
        ratelimit_password: Option<Arc<Ratelimiter>>,
    ) -> Self {
        let (db, handler) =
            Database::new(db::Open::Memory, "testsalt".to_string().try_into().unwrap())
                .expect("open memory database");
        let highlighter = Arc::new(Highlighter::default());
        let cache = Cache::new(
            NonZeroUsize::new(128),
            64 * 1024 * 1024,
            Arc::clone(&highlighter),
        )
        .unwrap();
        let key = Key::generate();
        let expirations = "0".parse::<ExpirationSet>().unwrap();
        let page = Arc::new(page::Page::new(
            String::from("test"),
            url::Url::parse("https://localhost:8888").unwrap(),
            Theme::Ayu,
            expirations,
            1024 * 1024,
            None,
        ));
        let state = crate::AppState {
            db,
            cache,
            key,
            page,
            highlighter,
            renderer: crate::render::Renderer::with_available_parallelism(),
            ratelimit_insert: Some(Arc::new(
                Ratelimiter::builder(60)
                    .max_tokens(60)
                    .initial_available(60)
                    .build()
                    .unwrap(),
            )),
            ratelimit_delete,
            ratelimit_password,
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Could not bind ephemeral socket");

        let addr = listener.local_addr().unwrap();

        tokio::spawn(handler);

        tokio::spawn(async move {
            let app = crate::make_app(state, Duration::from_secs(30), 1024 * 1024);

            axum::serve(listener, app)
                .with_graceful_shutdown(crate::shutdown_signal())
                .await
                .unwrap();
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(store_cookies.0)
            .build()
            .unwrap();

        Self { client, addr }
    }

    /// The origin this client actually talks to, for `Origin` headers in same-site tests.
    pub(crate) fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(format!("http://{}{}", self.addr, url))
    }

    pub(crate) fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(format!("http://{}{}", self.addr, url))
    }

    pub(crate) fn post_form(&self) -> RequestBuilder {
        self.client.post(format!("http://{}/new", self.addr))
    }

    pub(crate) fn post_json(&self) -> RequestBuilder {
        self.client.post(format!("http://{}/", self.addr))
    }

    pub(crate) fn delete(&self, url: &str) -> RequestBuilder {
        self.client.delete(format!("http://{}{}", self.addr, url))
    }

    pub(crate) fn request(&self, method: reqwest::Method, url: &str) -> RequestBuilder {
        self.client
            .request(method, format!("http://{}{}", self.addr, url))
    }
}

/// A form entry carrying placeholder content, for the tests whose subject is not the body.
///
/// `Entry::default()` leaves `text` empty, which inserting rejects, so it cannot stand in for
/// "some paste".
pub(crate) fn some_entry() -> crate::handlers::insert::form::Entry {
    crate::handlers::insert::form::Entry {
        text: String::from("FooBarBaz"),
        ..Default::default()
    }
}
