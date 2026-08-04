use std::sync::Arc;

use askama::Template;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::response::Response;

use crate::cache::{Key, Mode};
use crate::handlers::extract::{Theme, Uids, can_delete};
use crate::handlers::html::paste::PasteForm;
use crate::handlers::html::{Chrome, ErrorResponse, PasteReader, PasteView, Read, render_sized};
use crate::i18n::Lang;
use crate::{Cache, Database, Highlighter, Page};
use wastebin_core::db::read::Metadata;
use wastebin_core::expiration::Expiration;
use wastebin_highlight::markdown;

/// Page showing a Markdown paste rendered as HTML.
///
/// Responds through [`render_sized`] rather than deriving `WebTemplate`, so the page is built in
/// a buffer sized for the document it carries.
#[derive(Template)]
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
    State(db): State<Database>,
    State(highlighter): State<Highlighter>,
    State(render_pool): State<crate::render::Renderer>,
    State(ratelimit): State<crate::handlers::PasswordRatelimit>,
    Path(id): Path<String>,
    uids: Option<Uids>,
    chrome: Chrome,
    method: http::Method,
    form: Result<Form<PasteForm>, FormRejection>,
) -> Result<Response, ErrorResponse> {
    async {
        // Same reason as the source view: `Form` reads the query string on GET and HEAD, so
        // neither a password nor a burn confirmation may be taken from one there.
        let form = form
            .ok()
            .filter(|_| !matches!(method, http::Method::GET | http::Method::HEAD));
        let key: Key = id.parse()?;

        let read = PasteReader {
            db: &db,
            cache: &cache,
            renderer: &render_pool,
            ratelimit: &ratelimit,
            chrome: &chrome,
            highlighter: &highlighter,
            mode: Mode::Rendered,
        }
        .read(
            id,
            &key,
            form.map(|Form(form)| form),
            format!("/md/{key}"),
            |text, highlighter| markdown::render(&text, &highlighter),
        )
        .await?;

        let PasteView {
            html,
            is_available,
            metadata,
        } = match read {
            Read::Paste(view) => view,
            Read::Other(response) => return Ok(response),
        };

        let Metadata {
            uid: owner_uid,
            title,
            expiration,
            ..
        } = metadata;

        let rendered = Rendered {
            page: chrome.page.clone(),
            can_delete: can_delete(uids.as_ref(), owner_uid),
            key,
            theme: chrome.theme,
            lang: chrome.lang,
            is_available,
            is_markdown: true,
            expiration,
            html,
            title,
        };

        Ok(render_sized(&rendered, rendered.html.len()))
    }
    .await
    .map_err(|err| chrome.error(err))
}

#[cfg(test)]
mod tests {
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::{StatusCode, header};

    /// An empty field is not an attempt. Taking it for one ran a derivation that could only fail,
    /// answering "wrong password" to someone who supplied none — and the source view already
    /// treats it as absent.
    #[tokio::test]
    async fn an_empty_password_is_no_attempt() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# Hello"),
            extension: Some(String::from("md")),
            password: String::from("hunter2"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let id = location.trim_start_matches('/');

        let res = client
            .post(&format!("/md/{id}"))
            .form(&[("password", "")])
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.text().await?.contains("type=\"password\""),
            "expected the prompt, not a failed attempt"
        );

        Ok(())
    }

    /// The interstitial submits `confirm_burn` alone, so a form type demanding a `password` field
    /// rejected exactly the request its own template sends — the reveal button re-rendered the
    /// confirmation forever and the rendered view of a burn paste could never be reached.
    #[tokio::test]
    async fn burn_confirmation_reveals_the_render() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("# BurnedHeading"),
            extension: Some(String::from("md")),
            burn_after_reading: Some(String::from("on")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let id = location.replace("/burn/", "");

        // The confirmation comes first and reveals nothing.
        let res = client
            .get(&format!("/md/{id}"))
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.text().await?.contains("BurnedHeading"));

        // Confirming with exactly what the template posts renders the paste and burns it.
        let res = client
            .post(&format!("/md/{id}"))
            .form(&[("confirm_burn", "1")])
            .header(header::ACCEPT, "text/html")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("BurnedHeading"));

        let res = client.get(&format!("/md/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    /// The rendered view is read to judge a paste just as the source view is, so it reveals the
    /// same characters — and the paste itself stays untouched, so `/raw` still answers with the
    /// bytes that were stored.
    #[tokio::test]
    async fn a_reordering_character_is_shown_but_not_altered()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let text = "Some \u{202e}reordered prose.\n\n```rs\nlet admin = \u{202e}false;\n```\n";

        let res = client
            .post_form()
            .form(&Entry {
                text: text.to_string(),
                extension: Some(String::from("md")),
                ..Default::default()
            })
            .send()
            .await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();
        let id = location.trim_start_matches('/').trim_end_matches(".md");

        let page = client
            .get(&format!("/md/{id}"))
            .send()
            .await?
            .text()
            .await?;
        assert_eq!(
            page.matches(r#"data-cp="U+202E""#).count(),
            2,
            "prose and code block should both be marked: {page}"
        );

        let raw = client
            .get(&format!("/raw/{id}"))
            .send()
            .await?
            .text()
            .await?;
        assert_eq!(raw, text, "/raw altered the paste");

        Ok(())
    }

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
