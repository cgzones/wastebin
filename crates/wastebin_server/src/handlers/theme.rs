use axum::extract::Query;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;

use crate::handlers::cookie;
use crate::handlers::extract::{Preference, SafeReferer};

/// POST handler to switch theme by setting the pref cookie and redirecting back to the referer.
///
/// Storing the preference changes state, so it is not reachable by following a link — a
/// prefetcher must not be able to retheme the site for a visitor.
#[must_use]
pub async fn post(
    SafeReferer(redirect): SafeReferer,
    jar: CookieJar,
    Query(pref): Query<Preference>,
) -> impl IntoResponse {
    let cookie = cookie("pref", pref.pref.to_string());
    (jar.add(cookie), redirect)
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use http::header::REFERER;

    #[tokio::test]
    async fn external_referer_redirects_to_path_only() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let response = client
            .post("/theme")
            .header(REFERER, "https://evil.example.com/phish?bait=1")
            .query(&[("pref", "dark")])
            .send()
            .await?;

        assert!(response.status().is_redirection());
        let location = response.headers().get("location").unwrap().to_str()?;
        assert_eq!(location, "/phish?bait=1");

        Ok(())
    }

    #[tokio::test]
    async fn off_origin_referers_fall_back_to_root() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        for referer in [
            r"/\evil.example.com/phish",
            "https://evil.example.com//attacker.example.com/p",
            r"https://evil.example.com/\attacker.example.com",
        ] {
            let response = client
                .post("/theme")
                .header(REFERER, referer)
                .query(&[("pref", "dark")])
                .send()
                .await?;

            let location = response.headers().get("location").unwrap().to_str()?;
            assert_eq!(location, "/", "referer {referer} redirected to {location}");
        }

        Ok(())
    }

    #[tokio::test]
    async fn protocol_relative_referer_falls_back_to_root() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(true)).await;

        let response = client
            .post("/theme")
            .header(REFERER, "//evil.example.com/phish")
            .query(&[("pref", "dark")])
            .send()
            .await?;

        assert!(response.status().is_redirection());
        let location = response.headers().get("location").unwrap().to_str()?;
        assert_eq!(location, "/");

        Ok(())
    }

    /// Storing the preference is a state change, so following a link must not perform it — a
    /// prefetcher or a link-walking extension would otherwise retheme the site for the visitor.
    #[tokio::test]
    async fn get_does_not_switch_the_theme() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let response = client
            .get("/theme")
            .header(REFERER, "/")
            .query(&[("pref", "dark")])
            .send()
            .await?;

        assert_eq!(response.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.cookies().all(|cookie| cookie.name() != "pref"));

        Ok(())
    }

    /// The switcher has to submit, so it must render as a form rather than as links.
    #[tokio::test]
    async fn switcher_renders_as_forms() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let body = client.get("/").send().await?.text().await?;

        assert!(
            body.contains(r#"<form method="post" action="/theme?pref=dark""#),
            "body: {body}"
        );
        assert!(!body.contains(r#"href="/theme"#), "body: {body}");

        Ok(())
    }

    #[tokio::test]
    async fn redirect_with_cookie() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let response = client
            .post("/theme")
            .header(REFERER, "/foo")
            .query(&[("pref", "dark")])
            .send()
            .await?;

        assert!(response.status().is_redirection());

        let location = response.headers().get("location").unwrap().to_str()?;
        assert_eq!(location, "/foo");

        let cookie = response
            .cookies()
            .find(|cookie| cookie.name() == "pref")
            .unwrap();

        assert_eq!(cookie.value(), "dark");
        assert_eq!(cookie.path().unwrap(), "/");
        assert!(cookie.http_only());
        assert!(cookie.same_site_strict());

        Ok(())
    }
}
