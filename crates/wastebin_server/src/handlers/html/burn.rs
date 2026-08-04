use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::cache::Key;
use crate::handlers::extract::Theme;
use crate::handlers::html::qr::{code_for, dark_modules};
use crate::handlers::html::{Chrome, ErrorResponse};
use crate::i18n::Lang;
use crate::render::Renderer;
use crate::{Database, Page};

/// GET handler for the burn page.
pub async fn get(
    Path(id): Path<String>,
    State(db): State<Database>,
    State(renderer): State<Renderer>,
    chrome: Chrome,
) -> Result<Burn, ErrorResponse> {
    async {
        let key: Key = id.parse()?;

        // This page only shares a paste — a link and a QR code pointing at it — so it has nothing
        // to show once there is no paste. It answered 200 for every well-formed id, handing out a
        // scannable code for an entry that was never there or had already been read. Metadata is
        // enough to tell, and reading it never burns anything.
        db.get_metadata(key.id).await?;

        let code = code_for(&renderer, &chrome.page, &key).await?;

        Ok(Burn {
            page: chrome.page.clone(),
            key,
            code,
            theme: chrome.theme,
            lang: chrome.lang,
        })
    }
    .await
    .map_err(|err| chrome.error(err))
}

/// Burn page shown if "burn-after-reading" was selected during insertion.
#[derive(Template, WebTemplate)]
#[template(path = "burn.html")]
pub(crate) struct Burn {
    page: Page,
    key: Key,
    code: qrcodegen::QrCode,
    theme: Theme,
    lang: Lang,
}

impl Burn {
    fn dark_modules(&self) -> Vec<(i32, i32)> {
        dark_modules(&self.code)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::Client;
    use crate::{handlers::insert::form::Entry, test_helpers::StoreCookies};

    use reqwest::{StatusCode, header};

    /// The page has to exist for this to prove anything: once a missing paste answers with the
    /// error page, an id that was never inserted would pass simply by rendering nothing.
    #[tokio::test]
    async fn extension_is_escaped() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("FooBarBaz"),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let id = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()?
            .replace("/burn/", "");

        let res = client
            .get(&format!("/burn/{id}.%22%3E%3Cimg%20src=x%3E"))
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        let body = res.text().await?;
        assert!(!body.contains("<img src=x"), "raw markup leaked: {body}");

        Ok(())
    }

    /// The page exists only to share a paste, so it has nothing to show once there is no paste.
    /// It used to answer 200 for any well-formed id, handing out a scannable code for an entry
    /// that was never there — or, after the reveal, for one that had just been destroyed.
    #[tokio::test]
    async fn a_paste_that_is_gone_has_no_burn_page() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/burn/aaaaaaaaaaa").send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "id never inserted");

        let data = Entry {
            text: String::from("secret-body-xyz"),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let id = location.replace("/burn/", "");

        // While the paste is still there the page is served as before.
        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        // Reading it burns it, and the share page goes with it.
        let res = client
            .post(&format!("/{id}"))
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "paste was burned");

        Ok(())
    }

    #[tokio::test]
    async fn burn() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("secret-body-xyz"),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;

        // Location is the `/burn/foo` page not the paste itself, so remove the prefix.
        let location = location.replace("burn/", "");

        // First GET shows the confirmation interstitial without revealing content.
        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        let body = res.text().await?;
        assert!(body.contains("confirm_burn"));
        assert!(body.contains(">reveal<"));
        assert!(!body.contains("secret-body-xyz"));

        // Second GET must still show the confirmation — the paste is not yet burned.
        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains(">reveal<"));

        // Confirming reveals the paste and burns it.
        let res = client
            .post(&location)
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("secret-body-xyz"));

        // Subsequent GETs 404 — the paste was burned.
        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn burn_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let password = "asd";
        let data = Entry {
            text: String::from("secret-body-xyz"),
            password: password.to_string(),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;

        // Location is the `/burn/foo` page not the paste itself, so remove the prefix.
        let location = location.replace("burn/", "");

        // First GET shows the burn confirmation interstitial.
        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains(">reveal<"));

        // Confirming an encrypted burn paste yields the password form, not the content.
        let res = client
            .post(&location)
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        let body = res.text().await?;
        assert!(body.contains("password"));
        assert!(!body.contains("secret-body-xyz"));

        // Submitting the password (with the hidden confirm_burn from encrypted.html)
        // reveals the paste and burns it.
        let res = client
            .post(&location)
            .form(&[("password", password), ("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("secret-body-xyz"));

        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    /// Only the paste page ever asked for a confirmation, so `/raw`, `/dl` and `/md` destroyed a
    /// burn paste on a plain GET. Since `/md` runs the relaxed CSP that permits same-origin
    /// images, a paste holding `![](/raw/OTHER_ID)` made every viewer's browser destroy someone
    /// else's paste; a link unfurler did the same to any of them.
    #[tokio::test]
    async fn a_get_on_another_route_does_not_burn() -> Result<(), Box<dyn std::error::Error>> {
        for route in ["raw", "dl", "md"] {
            let client = Client::new(StoreCookies(false)).await;
            let data = Entry {
                text: String::from("secret-body-xyz"),
                extension: Some(String::from("md")),
                burn_after_reading: Some(String::from("on")),
                ..Default::default()
            };

            let res = client.post_form().form(&data).send().await?;
            assert_eq!(res.status(), StatusCode::SEE_OTHER);

            let location = res
                .headers()
                .get("location")
                .unwrap()
                .to_str()?
                .replace("burn/", "");
            let id = location.trim_start_matches('/').to_owned();

            let res = client
                .get(&format!("/{route}/{id}"))
                .header(header::ACCEPT, "text/html; charset=utf-8")
                .send()
                .await?;
            let status = res.status();
            let body = res.text().await?;
            assert!(
                !body.contains("secret-body-xyz"),
                "/{route} revealed the content: {status}"
            );

            // Whatever it answered, the paste is still there to be confirmed.
            let res = client
                .get(&location)
                .header(header::ACCEPT, "text/html; charset=utf-8")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::OK, "/{route} burned the paste");
            assert!(res.text().await?.contains(">reveal<"));
        }

        Ok(())
    }

    /// The rendered view still destroys the paste — it just asks first, and its interstitial has
    /// to post back to itself rather than to the source view.
    #[tokio::test]
    async fn a_confirmed_burn_still_works_on_the_rendered_view()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# secret-body-xyz"),
            extension: Some(String::from("md")),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()?
            .replace("burn/", "");
        let id = location.trim_start_matches('/').to_owned();

        let body = client
            .get(&format!("/md/{id}"))
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?
            .text()
            .await?;
        assert!(
            body.contains(&format!("action=\"/md/{id}\"")),
            "interstitial must post back to the rendered view: {body}"
        );

        let res = client
            .post(&format!("/md/{id}"))
            .form(&[("password", ""), ("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("secret-body-xyz"));

        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "should be burned");

        Ok(())
    }

    /// The confirmation is a form field, and `Form` reads the query string on GET — so a link
    /// carrying `?confirm_burn=1` skipped the interstitial and destroyed the paste. Anything that
    /// merely follows a URL (an `<img>`, a prefetch, a link unfurler) could burn it.
    #[tokio::test]
    async fn burn_is_not_confirmed_from_the_query_string() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("secret-body-xyz"),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()?
            .replace("burn/", "");

        let res = client
            .get(&location)
            .query(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        let body = res.text().await?;
        assert!(!body.contains("secret-body-xyz"), "content was revealed");
        assert!(body.contains(">reveal<"), "expected the interstitial");

        // And the paste survived: the interstitial is still there to be confirmed.
        let res = client
            .get(&location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn burn_confirmation_does_not_delete() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("FooBarBaz"),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()?
            .replace("burn/", "");

        // Hit the URL a handful of times — none of these should burn the paste.
        for _ in 0..5 {
            let res = client
                .get(&location)
                .header(header::ACCEPT, "text/html; charset=utf-8")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::OK);
            assert!(res.text().await?.contains(">reveal<"));
        }

        Ok(())
    }
}
