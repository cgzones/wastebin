use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use crate::Database;
use crate::handlers::extract::Password;
use crate::handlers::html::{Chrome, ErrorResponse, FormAction};
use crate::handlers::{PasswordRatelimit, serve_bytes};

/// GET and POST handler for raw content of a paste; the password prompt posts back here.
pub async fn get(
    Path(id): Path<String>,
    State(db): State<Database>,
    State(ratelimit): State<PasswordRatelimit>,
    chrome: Chrome,
    password: Option<Password>,
) -> Result<Response, ErrorResponse> {
    serve_bytes(
        &db,
        &ratelimit,
        &chrome,
        id,
        password,
        FormAction::raw,
        |_, data| data.text.into_response(),
    )
    .await
    .map_err(|err| chrome.error(err))
}

#[cfg(test)]
mod tests {
    use crate::handlers::extract::PASSWORD_HEADER_NAME;
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies, one_token_limiter};
    use reqwest::{StatusCode, header};

    /// Every password attempt runs a full argon2 derivation before the ciphertext is looked at, so
    /// a wrong password costs a right one's 64 MiB and four busy lanes. Nothing bounded how many
    /// an anonymous caller could ask for.
    #[tokio::test]
    async fn password_attempts_are_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = one_token_limiter();
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
        let limiter = one_token_limiter();
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

    /// The prompt a browser is given here posted to the source view, so entering the password
    /// rendered the highlighted page rather than the bytes — and asking for them again prompted
    /// again, forever.
    #[tokio::test]
    async fn the_prompt_unlocks_the_raw_view() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("secret-body-xyz"),
            password: String::from("hunter2"),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let raw = format!("/raw{location}");

        let prompt = client
            .get(&raw)
            .header(header::ACCEPT, "text/html")
            .send()
            .await?
            .text()
            .await?;
        assert!(prompt.contains(&format!("action=\"{raw}\"")), "{prompt}");

        // Exactly what the prompt submits.
        let res = client
            .post(&raw)
            .form(&[("confirm_burn", "1"), ("password", "hunter2")])
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let cache_control = res.headers().get(header::CACHE_CONTROL).cloned();
        assert_eq!(res.text().await?, "secret-body-xyz");
        assert_eq!(cache_control.unwrap(), "no-store");

        // Submitting the prompt empty asks again rather than failing as a wrong password.
        let res = client
            .post(&raw)
            .form(&[("confirm_burn", "1"), ("password", "")])
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("type=\"password\""));

        Ok(())
    }

    /// A password posted to the prompt is an attempt like one sent in the header, so it spends a
    /// token the same way.
    #[tokio::test]
    async fn posted_password_attempts_are_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = one_token_limiter();
        let client = Client::new_with_ratelimit_password(StoreCookies(false), Some(limiter)).await;
        let data = Entry {
            text: String::from("SECRETPAYLOAD"),
            password: String::from("hunter2"),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let raw = format!("/raw{location}");

        let first = client
            .post(&raw)
            .form(&[("password", "wrong")])
            .send()
            .await?;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);

        let second = client
            .post(&raw)
            .form(&[("password", "wrong")])
            .send()
            .await?;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    /// The prompt posts here now, so a body over the limit has to be told it is too large rather
    /// than read as no password and prompted for again.
    #[tokio::test]
    async fn an_oversized_password_form_is_too_large() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("secret-body-xyz"),
            password: String::from("hunter2"),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        // `make_app` is given a 1 MiB limit by the test harness.
        let res = client
            .post(&format!("/raw{location}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("x".repeat(2 * 1024 * 1024))
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);

        Ok(())
    }
}
