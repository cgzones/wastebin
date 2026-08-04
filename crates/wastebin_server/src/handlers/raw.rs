use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use crate::cache::Key;
use crate::handlers::PasswordRatelimit;
use crate::handlers::extract::{Accepts, Password, Theme};
use crate::handlers::html::{ErrorResponse, make_error, password_input};
use crate::i18n::Lang;
use crate::{Database, Page};
use wastebin_core::db;
use wastebin_core::db::read::Entry;

/// GET handler for raw content of a paste.
#[expect(clippy::too_many_arguments)]
pub async fn get(
    Path(id): Path<String>,
    State(db): State<Database>,
    State(page): State<Page>,
    State(ratelimit): State<PasswordRatelimit>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
    password: Option<Password>,
) -> Result<Response, ErrorResponse> {
    async {
        let password = password.map(|Password(password)| password);
        let key: Key = id.parse()?;

        // Only an attempt that reaches argon2 is worth a token. The bucket is a single
        // process-wide one with no refund, so letting a password for a missing or unencrypted
        // paste spend one let anyone lock every user out of every encrypted paste for free.
        if password.is_some() && db.get_metadata(key.id).await?.is_encrypted {
            ratelimit.check()?;
        }

        match db.get(key.id, password).await {
            Ok(Entry::Regular(data) | Entry::Burned(data)) => Ok(data.text.into_response()),
            // A browser is sent the prompt to fill in; a client that asked for JSON cannot act on
            // an HTML form and would only see a 200 where it expected the paste.
            Err(db::Error::NoPassword) if accepts == Accepts::Html => {
                Ok(password_input(&page, theme, lang, key.id.to_string()))
            }
            Err(err) => Err(err.into()),
        }
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    /// Every password attempt runs a full argon2 derivation before the ciphertext is looked at, so
    /// a wrong password costs a right one's 64 MiB and four busy lanes. Nothing bounded how many
    /// an anonymous caller could ask for.
    #[tokio::test]
    async fn password_attempts_are_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = std::sync::Arc::new(
            ratelimit::Ratelimiter::builder(1)
                .max_tokens(1)
                .initial_available(1)
                .build()?,
        );
        let client = Client::new_with_ratelimit_password(StoreCookies(false), Some(limiter)).await;

        let paste = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: "SECRETPAYLOAD".to_string(),
                password: Some("hunter2".to_string()),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;
        let raw = format!("/raw{}", paste.path);

        // The single token buys one attempt; the next is refused before argon2 is entered.
        let first = client
            .get(&raw)
            .header("wastebin-password", "wrong")
            .send()
            .await?;
        assert_eq!(first.status(), StatusCode::FORBIDDEN);

        let second = client
            .get(&raw)
            .header("wastebin-password", "wrong")
            .send()
            .await?;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        // A read carrying no password never touches the bucket.
        let none = client.get(&raw).send().await?;
        assert_eq!(none.status(), StatusCode::OK, "prompt should still render");

        Ok(())
    }

    /// The bucket is a single process-wide one, so a token spent on a request that never derives
    /// a key is a token taken from every other user. A password sent for a paste that does not
    /// exist — or one that is not encrypted — costs the server nothing and must cost no token,
    /// or anyone can lock the whole instance out of every encrypted paste for free.
    #[tokio::test]
    async fn a_password_for_no_derivation_keeps_its_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let limiter = std::sync::Arc::new(
            ratelimit::Ratelimiter::builder(1)
                .max_tokens(1)
                .initial_available(1)
                .build()?,
        );
        let client = Client::new_with_ratelimit_password(StoreCookies(false), Some(limiter)).await;

        let secret = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: "SECRETPAYLOAD".to_string(),
                password: Some("hunter2".to_string()),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let plain = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: "public".to_string(),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        // Neither of these can reach argon2, so neither may spend the only token.
        for _ in 0..5 {
            let res = client
                .get("/raw/aaaaaa")
                .header("wastebin-password", "wrong")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown id");

            let res = client
                .get(&format!("/raw{}", plain.path))
                .header("wastebin-password", "wrong")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::OK, "unencrypted paste");
        }

        // The token is still there for the one attempt that does derive a key.
        let res = client
            .get(&format!("/raw{}", secret.path))
            .header("wastebin-password", "hunter2")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.text().await?, "SECRETPAYLOAD");

        Ok(())
    }

    /// Without a password the browser gets a prompt, which is a 200 carrying a form. A client
    /// asking for JSON cannot fill that in and must be told the paste needs a password instead.
    #[tokio::test]
    async fn json_client_is_not_handed_the_password_form() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;

        let entry = crate::handlers::insert::api::Entry {
            text: "FooBarBaz".to_string(),
            password: Some("SuperSecretPassword".to_string()),
            ..Default::default()
        };
        let payload = client
            .post_json()
            .json(&entry)
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;

        let res = client
            .get(&format!("/raw{}", payload.path))
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let body = res.text().await?;
        assert!(!body.contains("type=\"password\""), "body: {body}");
        assert!(!body.contains("FooBarBaz"), "body: {body}");

        // The browser path is unchanged: still the prompt, still a 200.
        let res = client
            .get(&format!("/raw{}", payload.path))
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("type=\"password\""));

        Ok(())
    }
}
