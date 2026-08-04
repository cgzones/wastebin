use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::response::{IntoResponse, Response};

use crate::cache::{Key, Mode};
use crate::handlers::NoStore;
use crate::handlers::extract::{Accepts, Theme, Uids, can_delete};
use crate::handlers::html::paste::PasteForm;
use crate::handlers::html::{
    BurnConfirmation, ErrorResponse, FormAction, make_error, password_input,
};
use crate::i18n::Lang;
use crate::{Cache, Database, Highlighter, Page};
use wastebin_core::crypto::Password;
use wastebin_core::db;
use wastebin_core::db::read::{Data, Entry, Metadata};
use wastebin_core::expiration::Expiration;
use wastebin_highlight::markdown;

/// Page showing a Markdown paste rendered as HTML.
#[derive(Template, WebTemplate)]
#[template(path = "rendered.html")]
pub(crate) struct Rendered {
    page: Page,
    key: Key,
    theme: Theme,
    lang: Lang,
    can_delete: bool,
    is_available: bool,
    /// Always `true` for this view; needed by the inherited paste template.
    is_markdown: bool,
    expiration: Option<Expiration>,
    html: Arc<String>,
    title: Option<String>,
}

#[expect(clippy::too_many_arguments)]
pub async fn get(
    State(cache): State<Cache>,
    State(page): State<Page>,
    State(db): State<Database>,
    State(highlighter): State<Highlighter>,
    State(render_pool): State<crate::render::Renderer>,
    Path(id): Path<String>,
    uids: Option<Uids>,
    theme: Theme,
    lang: Lang,
    accepts: Accepts,
    method: http::Method,
    form: Result<Form<PasteForm>, FormRejection>,
) -> Result<Response, ErrorResponse> {
    async {
        let form = form.ok().map(|Form(form)| form);
        // Same reason as the source view: `Form` reads the query string on GET and HEAD, and a
        // password does not belong in a URL.
        let password = form
            .as_ref()
            .filter(|_| !matches!(method, http::Method::GET | http::Method::HEAD))
            .and_then(|form| form.password.as_ref())
            .filter(|password| !password.is_empty())
            .map(|password| Password::from(password.as_bytes().to_vec()));
        let confirmed = form.as_ref().and_then(|form| form.confirm_burn.as_deref()) == Some("1");
        let no_password = password.is_none();
        let key: Key = id.parse()?;
        let metadata = db.get_metadata(key.id).await?;

        if metadata.must_be_deleted && !confirmed {
            return Ok(BurnConfirmation {
                page: page.clone(),
                theme,
                lang,
                title: metadata.title.clone(),
                action: FormAction::rendered(&key),
            }
            .into_response());
        }

        // A cached render implies the paste was available and unencrypted when stored, so its
        // metadata is all that is still needed — reading the body back would only waste a
        // decompression of bytes we immediately drop.
        let cached = no_password
            .then(|| cache.get(&key, Mode::Rendered))
            .flatten();

        let (html, is_available, encrypted, metadata, burn) = if let Some(cached) = cached {
            tracing::trace!(?key, "found cached rendered markdown");
            (cached, true, false, metadata, None)
        } else {
            let Entry {
                data: Data { text, metadata },
                encrypted,
                burn,
            } = match db.get(key.id, password).await {
                Ok(entry) => entry,
                Err(db::Error::NoPassword) => {
                    return Ok(password_input(
                        &page,
                        theme,
                        lang,
                        FormAction::rendered(&key),
                    ));
                }
                Err(err) => return Err(err.into()),
            };
            let is_available = burn.is_none();

            let highlighter = highlighter.clone();
            let rendered: Arc<String> = render_pool
                .run(move || markdown::render(&text, &highlighter))
                .await??
                .into_inner();

            if is_available && no_password {
                tracing::trace!(?key, "cache rendered markdown");
                cache.put(&key, Mode::Rendered, Arc::clone(&rendered));
            }

            (rendered, is_available, encrypted, metadata, burn)
        };

        let Metadata {
            uid: owner_uid,
            title,
            expiration,
            ..
        } = metadata;

        let rendered = Rendered {
            page: page.clone(),
            can_delete: can_delete(uids.as_ref(), owner_uid),
            key,
            theme,
            lang,
            is_available,
            is_markdown: true,
            expiration,
            html,
            title,
        };

        let response = rendered.into_response();
        let response = if encrypted {
            response.no_store()
        } else {
            response
        };

        // Burned only once there is a page to show: a render or a template that fails drops the
        // ticket and leaves the paste for another attempt, rather than taking the one read with
        // it. The delete still settles concurrent readers — only the one whose burn removed the
        // row gets its page out.
        if let Some(burn) = burn
            && response.status().is_success()
        {
            db.burn(burn).await?;
        }

        Ok(response)
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
}

#[cfg(test)]
mod tests {
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    #[tokio::test]
    async fn renders_markdown_as_html() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# Hello\n\n| a | b |\n|---|---|\n| 1 | 2 |\n"),
            extension: Some(String::from("md")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        let res = client
            .get(&format!("/md{location}"))
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);

        let body = res.text().await?;
        assert!(body.contains("markdown-body"), "body: {body}");
        assert!(body.contains("<h1>Hello</h1>"), "body: {body}");
        assert!(body.contains("<th>a</th>"), "body: {body}");

        Ok(())
    }

    /// The rendered view reads its password through the same query-string-capable `Form`, so it
    /// needs the same guard as the source view.
    #[tokio::test]
    async fn password_is_not_taken_from_the_query_string() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = Client::new(StoreCookies(false)).await;

        let paste = client
            .post_json()
            .json(&crate::handlers::insert::api::Entry {
                text: "SECRETPAYLOAD".to_string(),
                extension: Some(String::from("md")),
                password: Some("hunter2".to_string()),
                ..Default::default()
            })
            .send()
            .await?
            .json::<crate::handlers::insert::api::RedirectResponse>()
            .await?;
        let rendered = format!("/md{}", paste.path);

        let body = client
            .get(&rendered)
            .query(&[("password", "hunter2")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?
            .text()
            .await?;
        assert!(!body.contains("SECRETPAYLOAD"), "body: {body}");

        let body = client
            .post(&rendered)
            .form(&[("password", "hunter2")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?
            .text()
            .await?;
        assert!(body.contains("SECRETPAYLOAD"), "body: {body}");

        Ok(())
    }

    #[tokio::test]
    async fn burn_requires_confirmation() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# secret\n"),
            extension: Some(String::from("md")),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        // Location is the `/burn/foo` page not the paste itself, so remove the prefix.
        let location = res
            .headers()
            .get("location")
            .unwrap()
            .to_str()?
            .replace("burn/", "");
        let rendered = format!("/md{location}");

        // First GET of the rendered view shows the confirmation interstitial without revealing
        // content, and confirms against the rendered route.
        let res = client
            .get(&rendered)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.text().await?;
        assert!(body.contains("confirm_burn"), "body: {body}");
        assert!(
            body.contains(&format!("action=\"{rendered}\"")),
            "body: {body}"
        );
        assert!(!body.contains("<h1>secret</h1>"), "body: {body}");

        // Second GET must still show the confirmation — the paste is not yet burned.
        let res = client
            .get(&rendered)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains(">reveal<"));

        // Confirming reveals the rendered paste and burns it.
        let res = client
            .post(&rendered)
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("<h1>secret</h1>"));

        // Subsequent GETs 404 — the paste was burned.
        let res = client
            .get(&rendered)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    /// Markdown nested past the parser's limit fails to render on every attempt, and the reveal
    /// burnt the paste before rendering it: the one read went to an error page and the paste was
    /// gone. The source view can still show it, so the failed attempt has to leave it there.
    #[tokio::test]
    async fn a_failed_render_leaves_a_burn_paste_for_another_view()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: "<div>".repeat(300),
            extension: Some(String::from("md")),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let id = location.replace("/burn/", "");

        for attempt in 0..2 {
            let res = client
                .post(&format!("/md/{id}"))
                .form(&[("confirm_burn", "1")])
                .header(header::ACCEPT, "text/html")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "attempt {attempt}");
        }

        let res = client
            .post(&format!("/{id}"))
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.text().await?.contains("confirm_burn"), "not revealed");

        let res = client
            .post(&format!("/{id}"))
            .form(&[("confirm_burn", "1")])
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "revealed twice");

        Ok(())
    }

    #[tokio::test]
    async fn missing_paste_is_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/md/aaaaaa").send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn rendered_response_relaxes_img_src() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# picture\n\n![cat](https://example.com/cat.png)\n"),
            extension: Some(String::from("md")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        let rendered = client.get(&format!("/md{location}")).send().await?;
        let csp = rendered
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()?
            .to_owned();
        // Remote images stay possible, but only over TLS: a plaintext image URL would leak the
        // fact and timing of the view to a network observer.
        assert!(csp.contains("img-src 'self' https: data:"), "csp: {csp}");
        assert!(!csp.contains("img-src *"), "csp: {csp}");

        let source = client.get(&location).send().await?;
        let csp = source
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()?;
        assert!(csp.contains("img-src 'self' data:"), "csp: {csp}");

        Ok(())
    }

    #[tokio::test]
    async fn encrypted_rendered_is_not_stored() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let password = "hunter2";
        let data = Entry {
            text: String::from("# secret\n"),
            extension: Some(String::from("md")),
            password: password.to_string(),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        // The password prompt is not cacheable.
        let res = client.get(&format!("/md{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        // The decrypted Markdown is not cacheable either.
        let res = client
            .post(&format!("/md{location}"))
            .form(&[("password", password)])
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let cache_control = res.headers().get(header::CACHE_CONTROL).cloned();
        let body = res.text().await?;
        assert!(body.contains("<h1>secret</h1>"), "body: {body}");
        assert_eq!(cache_control.unwrap(), "no-store");

        Ok(())
    }

    /// The rendered view caches under its own mode, so it must also decide availability from the
    /// database rather than from a cache hit.
    #[tokio::test]
    async fn deleted_paste_is_not_served_from_cache() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;
        let data = Entry {
            text: String::from("# cache-me-then-delete"),
            extension: Some(String::from("md")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let rendered = format!("/md{location}");

        // The first render fills the cache, the second is served from it.
        for _ in 0..2 {
            let res = client
                .get(&rendered)
                .header(header::ACCEPT, "text/html; charset=utf-8")
                .send()
                .await?;
            assert_eq!(res.status(), StatusCode::OK);
            assert!(res.text().await?.contains("cache-me-then-delete"));
        }

        // Deletion goes through the bare id, without the extension the URL carries.
        let id = location.trim_start_matches('/');
        let id = id.split('.').next().unwrap();

        let res = client.delete(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = client
            .get(&rendered)
            .header(header::ACCEPT, "text/html; charset=utf-8")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
