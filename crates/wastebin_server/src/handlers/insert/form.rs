use std::num::NonZeroU32;

use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::cache::Key;
use crate::errors;
use crate::handlers::extract::Uids;
use crate::handlers::html::{Chrome, SameSite};
use crate::handlers::uid_cookie;
use wastebin_core::db::write;

use super::common_insert;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub text: String,
    pub extension: Option<String>,
    pub expires: Option<String>,
    // The browser form always submits these, empty or not, but a scripted client has no reason to
    // send a field it is not using — and an absent one is exactly the empty string's meaning.
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub title: String,
    #[serde(rename = "burn-after-reading")]
    pub burn_after_reading: Option<String>,
}

impl TryFrom<Entry> for write::Entry {
    type Error = crate::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let burn_after_reading = entry.burn_after_reading.map(|s| s == "on");
        let password = (!entry.password.is_empty()).then_some(entry.password);
        let title = (!entry.title.is_empty()).then_some(entry.title);
        // `0` is how the form spells "never expires". Anything else that is not a number is a
        // malformed request, not another way to ask for a paste that is kept forever.
        let expires = entry
            .expires
            .map(|expires| {
                expires
                    .parse::<u32>()
                    .map(NonZeroU32::new)
                    .map_err(|_| crate::Error::MalformedForm)
            })
            .transpose()?
            .flatten();

        Ok(Self {
            text: entry.text,
            extension: entry.extension.filter(|e| !e.is_empty()),
            expires,
            burn_after_reading,
            uid: None,
            password,
            title,
        })
    }
}

pub async fn post(
    State(appstate): State<AppState>,
    _: SameSite,
    jar: SignedCookieJar,
    uids: Option<Uids>,
    chrome: Chrome,
    entry: Result<Form<Entry>, FormRejection>,
) -> Result<(SignedCookieJar, Redirect), impl IntoResponse> {
    let entry = match entry {
        Ok(Form(entry)) => entry,
        // This route consumes its own rejection, so it never reaches `handle_service_errors` —
        // hence the shared table, rather than a second one that drifts. Folding the body limit
        // into "malformed" told someone whose upload was simply too big that their form was
        // broken, and answered differently than the JSON endpoint does for the same body.
        Err(rejection) => {
            let error =
                errors::rejection_error(rejection.status()).unwrap_or(crate::Error::MalformedForm);

            return Err(chrome.error(error));
        }
    };

    async {
        // Pick the existing primary uid (first in the cookie list) or mint a new one.
        // Re-set the cookie with the full list unchanged so claimed uids survive.
        //
        // Only the first entry is ever used to tag a new paste. Uids claimed through the
        // `?owner=` handoff are appended behind it, so they grant deletion rights over the
        // pastes they came with but never capture what this client creates afterwards.
        let mut uids = uids.map(|Uids(uids)| uids).unwrap_or_default();
        let owner = uids.first().copied();

        let entry: write::Entry = entry.try_into()?;

        let (id, entry, primary) = common_insert(&appstate, entry, owner).await?;

        if uids.is_empty() {
            uids.push(primary);
        }

        let url = {
            let burn_after_reading = entry.burn_after_reading.unwrap_or(false);
            let url_path = Key {
                id,
                ext: entry.extension,
            };

            if burn_after_reading {
                format!("/burn/{url_path}")
            } else {
                format!("/{url_path}")
            }
        };

        Ok((jar.add(uid_cookie(&uids)), Redirect::to(&url)))
    }
    .await
    .map_err(|err| chrome.error(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{Client, StoreCookies, some_entry};
    use reqwest::{StatusCode, header};
    use std::collections::HashMap;

    /// This route consumes its own `FormRejection`, so `handle_service_errors` never sees it. With
    /// a table of its own it answered an unsupported content type as a malformed form — a 422
    /// describing the fields, where the same body on the JSON endpoint correctly gets a 415.
    #[tokio::test]
    async fn an_unsupported_content_type_is_not_a_malformed_form()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client
            .post_form()
            .header(header::CONTENT_TYPE, "application/xml")
            .body("<x/>")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        Ok(())
    }

    #[tokio::test]
    async fn cross_site_insert_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;
        let data = Entry {
            text: String::from("FooBarBaz"),
            ..Default::default()
        };

        let res = client
            .post_form()
            .header(header::ORIGIN, "https://evil.example.com")
            .form(&data)
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // The site's own form still works.
        let res = client
            .post_form()
            .header(header::ORIGIN, client.origin())
            .form(&data)
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        Ok(())
    }

    #[tokio::test]
    async fn unparsable_expiration_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let data = Entry {
            text: String::from("FooBarBaz"),
            expires: Some(String::from("garbage")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        Ok(())
    }

    /// An oversized body used to fold into the "malformed form" rejection, so the web UI called a
    /// too-large upload broken while the JSON endpoint called the same body too large.
    #[tokio::test]
    async fn oversized_form_is_too_large_not_malformed() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        // `make_app` is given a 1 MiB limit by the test harness.
        let res = client
            .post_form()
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("x".repeat(2 * 1024 * 1024))
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // A body that is merely unparsable is still a different answer.
        let data = Entry {
            text: String::from("FooBarBaz"),
            expires: Some(String::from("garbage")),
            ..Default::default()
        };
        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        Ok(())
    }

    /// The extension is interpolated into the `Location` this insert answers with, so anything
    /// that is not a plain extension either breaks the header outright or walks the redirect off
    /// the paste. Both used to be accepted: a CRLF answered an inserted paste with a 500, and a
    /// `../` pointed the client at an unrelated path.
    #[tokio::test]
    async fn unknown_extension_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for extension in [
            "zzzznope",
            "../../admin",
            "a/b",
            "?x=1",
            "a\r\nX-Injected: yes",
        ] {
            let data = Entry {
                text: String::from("FooBarBaz"),
                extension: Some(String::from(extension)),
                ..Default::default()
            };

            let res = client.post_form().form(&data).send().await?;
            assert_eq!(
                res.status(),
                StatusCode::BAD_REQUEST,
                "extension {extension:?} was not rejected"
            );
        }

        Ok(())
    }

    /// Every value the language picker offers must survive the check above — `txt` in particular,
    /// which names the plain-text syntax and so must not be taken for an extension naming none.
    #[tokio::test]
    async fn offered_extensions_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        for extension in ["rs", "txt", "md", "CMakeLists.txt", ".env"] {
            let data = Entry {
                text: String::from("FooBarBaz"),
                extension: Some(String::from(extension)),
                ..Default::default()
            };

            let res = client.post_form().form(&data).send().await?;
            assert_eq!(
                res.status(),
                StatusCode::SEE_OTHER,
                "extension {extension:?} was rejected"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn zero_expiration_still_means_never() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let data = Entry {
            text: String::from("FooBarBaz"),
            expires: Some(String::from("0")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        Ok(())
    }

    #[tokio::test]
    async fn insert() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("FooBarBaz"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;

        let res = client
            .get(location)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);

        let header = res.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(header.to_str().unwrap().contains("text/html"));

        let content = res.text().await?;
        assert!(content.contains("FooBarBaz"));

        let res = client
            .get(&format!("/raw{location}"))
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);

        let header = res.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(header.to_str().unwrap().contains("text/plain"));

        let content = res.text().await?;
        assert_eq!(content, "FooBarBaz");

        Ok(())
    }

    /// Omitting an optional field is not a malformed request: the browser form always sends
    /// `password` and `title`, but a scripted client posting only `text` was rejected as
    /// unprocessable with nothing naming the missing field.
    #[tokio::test]
    async fn omitted_optional_fields_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client
            .post_form()
            .body("text=FooBarBaz")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let res = client.get(&format!("/raw{location}")).send().await?;
        assert_eq!(res.text().await?, "FooBarBaz");

        Ok(())
    }

    #[tokio::test]
    async fn insert_fail() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let mut data = HashMap::new();
        data.insert("Hello", "World");

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        Ok(())
    }

    #[tokio::test]
    async fn insert_sets_uid_cookie() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;
        let res = client.post_form().form(&some_entry()).send().await?;
        let cookie = res.cookies().find(|cookie| cookie.name() == "uid").unwrap();
        assert_eq!(cookie.name(), "uid");
        assert!(cookie.value().len() > 40);
        assert_eq!(cookie.path().unwrap(), "/");
        assert!(cookie.http_only());
        // Lax, not Strict: a handoff link is a cross-site navigation, and Strict withheld the
        // cookie on exactly that request — so the claim overwrote the identity instead of joining
        // it. Cross-site POSTs and subresource loads still do not carry it.
        assert!(cookie.same_site_lax());
        assert!(cookie.domain().is_none());
        assert!(cookie.expires().is_none());
        assert!(cookie.max_age().is_none());
        assert!(cookie.secure());

        Ok(())
    }
}
