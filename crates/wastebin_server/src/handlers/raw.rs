use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use crate::cache::Key;
use crate::handlers::NoStore;
use crate::handlers::PasswordRatelimit;
use crate::handlers::extract::{Accepts, Password, Theme};
use crate::handlers::html::{ErrorResponse, FormAction, make_error, password_input};
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

        let metadata = db.get_metadata(key.id).await?;

        // This route is a GET that returns bytes, so there is nowhere to confirm the destruction
        // and nothing stopping anything that merely follows a URL from triggering it. The content
        // stays reachable through the paste page, which does ask first.
        if metadata.must_be_deleted {
            return Err(crate::Error::BurnNotConfirmed);
        }

        // Only an attempt that reaches argon2 is worth a token. The bucket is a single
        // process-wide one with no refund, so letting a password for a missing or unencrypted
        // paste spend one let anyone lock every user out of every encrypted paste for free.
        if password.is_some() && metadata.is_encrypted {
            ratelimit.check()?;
        }

        let Entry {
            data,
            encrypted,
            burn,
        } = match db.get(key.id, password).await {
            Ok(entry) => entry,
            // A browser is sent the prompt to fill in; a client that asked for JSON cannot act on
            // an HTML form and would only see a 200 where it expected the paste.
            Err(db::Error::NoPassword) if accepts == Accepts::Html => {
                return Ok(password_input(&page, theme, lang, FormAction::source(&key)));
            }
            Err(err) => return Err(err.into()),
        };

        // Unreachable behind the refusal above, but whatever serves the content is what burns
        // it: relaxing that check must not turn these routes into a way past the single read.
        if let Some(burn) = burn {
            db.burn(burn).await?;
        }

        let response = data.text.into_response();
        Ok(if encrypted {
            response.no_store()
        } else {
            response
        })
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
}

#[cfg(test)]
mod tests {
    use crate::handlers::extract::PASSWORD_HEADER_NAME;
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    /// Every password attempt runs a full argon2 derivation before the ciphertext is looked at, so
    /// a wrong password costs a right one's 64 MiB and four busy lanes. Nothing bounded how many
    /// an anonymous caller could ask for.
    #[tokio::test]
    async fn password_attempts_are_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
        // The token comes back once an hour rather than once a second: an argon2 attempt in a
        // loaded parallel run can take longer than a second, and a token refilled meanwhile let
        // through the attempt the test expects to be refused.
        let limiter = std::sync::Arc::new(
            ratelimit::Ratelimiter::builder(1)
                .period(std::time::Duration::from_secs(3600))
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
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);

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
                .period(std::time::Duration::from_secs(3600))
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

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "wastebin-password realm=\"paste\"",
        );

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

    #[tokio::test]
    async fn encrypted_raw_is_not_stored() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let password = "hunter2";
        let data = Entry {
            text: String::from("secret-body-xyz"),
            password: password.to_string(),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        // Password prompt for the encrypted paste must not be cached either.
        let res = client.get(&format!("/raw{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        // Decrypted content must not be stored.
        let res = client
            .get(&format!("/raw{location}"))
            .header(PASSWORD_HEADER_NAME, password)
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let cache_control = res.headers().get(header::CACHE_CONTROL).cloned();
        assert_eq!(res.text().await?, "secret-body-xyz");
        assert_eq!(cache_control.unwrap(), "no-store");

        Ok(())
    }
}
