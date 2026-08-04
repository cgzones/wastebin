use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::Page;
use crate::cache::Key;
use crate::handlers::extract::{Accepts, Theme};
use crate::handlers::html::qr::{code_for, dark_modules};
use crate::handlers::html::{ErrorResponse, make_error};
use crate::i18n::Lang;

/// GET handler for the burn page.
pub async fn get(
    Path(id): Path<String>,
    State(page): State<Page>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
) -> Result<Burn, ErrorResponse> {
    async {
        let key: Key = id.parse()?;
        let code = code_for(&page, id).await?;

        Ok(Burn {
            page: page.clone(),
            key,
            code,
            theme,
            lang,
        })
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
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

    #[tokio::test]
    async fn extension_is_escaped() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let body = client
            .get("/burn/aaaaaaaaaaa.%22%3E%3Cimg%20src=x%3E")
            .send()
            .await?
            .text()
            .await?;

        assert!(!body.contains("<img src=x"), "raw markup leaked: {body}");

        Ok(())
    }
    use reqwest::{StatusCode, header};

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
