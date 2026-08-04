use std::time::Duration;

use axum::response::IntoResponse;
use axum_extra::TypedHeader;
use axum_extra::headers;

/// Return robots.txt content.
///
/// The body is a compile-time constant, so the `no-store` every dynamic response defaults to only
/// bought a refetch per crawl. It shares the short window the unhashed assets use rather than the
/// pinned one, since this route outlives any particular build of its bytes.
pub async fn get() -> impl IntoResponse {
    let cache_control = headers::CacheControl::new().with_max_age(Duration::from_hours(1));

    (
        TypedHeader(cache_control),
        r"User-agent: *
Disallow: /",
    )
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    /// The body is fixed at compile time, so it must not inherit the `no-store` that every
    /// dynamic response defaults to.
    #[tokio::test]
    async fn robots_is_cacheable() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/robots.txt").send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CACHE_CONTROL).unwrap(),
            "max-age=3600"
        );

        assert!(res.text().await?.contains("Disallow: /"));

        Ok(())
    }
}
