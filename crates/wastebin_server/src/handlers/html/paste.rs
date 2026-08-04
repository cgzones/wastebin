use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::SignedCookieJar;
use axum_extra::extract::cookie::Key as CookieKey;
use serde::Deserialize;

use crate::cache::{Key, Mode};
use crate::handlers::extract::{Theme, Uids, can_delete, verify_owner_token};
use crate::handlers::html::{BurnConfirmation, ErrorResponse, make_error, password_input};
use crate::handlers::uid_cookie;
use crate::i18n::Lang;
use crate::{AppState, Page};
use wastebin_core::crypto::Password;
use wastebin_core::db;
use wastebin_core::db::read::{Data, Entry, Metadata};
use wastebin_core::expiration::Expiration;

/// Magic-link handoff: when a paste was created via the JSON API, the response contains a signed
/// `owner` token. Opening `/<id>?owner=<token>` lets the browser claim ownership of the paste, the
/// server validates the token, appends the uid to the user's signed `uid` cookie, and redirects to
/// the clean paste URL so the token never leaks via Referer.
#[derive(Deserialize, Debug)]
pub(crate) struct OwnerHandoff {
    pub(crate) owner: Option<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PasswordForm {
    pub(crate) password: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PasteForm {
    #[serde(default)]
    pub(crate) password: Option<String>,
    #[serde(default)]
    pub(crate) confirm_burn: Option<String>,
}

/// Paste view showing the formatted paste.
#[derive(Template, WebTemplate)]
#[template(path = "formatted.html")]
pub(crate) struct Paste {
    page: Page,
    key: Key,
    theme: Theme,
    lang: Lang,
    can_delete: bool,
    /// If the paste still in the database and can be fetched with another request.
    is_available: bool,
    /// Expiration in case it was set.
    expiration: Option<Expiration>,
    html: Arc<str>,
    title: Option<String>,
    /// Whether the paste's extension identifies it as Markdown, enabling the rendered-view toggle.
    is_markdown: bool,
}

#[expect(clippy::too_many_arguments)]
pub async fn get(
    State(appstate): State<AppState>,
    State(cookie_key): State<CookieKey>,
    Path(id): Path<String>,
    Query(handoff): Query<OwnerHandoff>,
    jar: SignedCookieJar,
    uids: Option<Uids>,
    theme: Theme,
    lang: Lang,
    form: Result<Form<PasteForm>, FormRejection>,
) -> Result<Response, ErrorResponse> {
    let cache = &appstate.cache;
    let page = &appstate.page;
    let db = &appstate.db;
    let highlighter = &appstate.highlighter;

    if let Some(token) = handoff.owner.as_deref()
        && let Some(claimed_uid) = verify_owner_token(&cookie_key, token)
    {
        let mut new_uids = uids
            .as_ref()
            .map(|Uids(list)| list.clone())
            .unwrap_or_default();
        if !new_uids.contains(&claimed_uid) {
            new_uids.push(claimed_uid);
        }
        // Redirect to the parsed key rather than the raw path, which is otherwise free to
        // steer the `Location` header off-site.
        let key: Key = id
            .parse()
            .map_err(|err| make_error(err, page.clone(), theme, lang))?;
        let cookie = uid_cookie(&new_uids);
        return Ok((jar.add(cookie), Redirect::to(&format!("/{key}"))).into_response());
    }

    async {
        let form = form.ok().map(|Form(form)| form);
        let password = form
            .as_ref()
            .and_then(|form| form.password.as_ref())
            .filter(|password| !password.is_empty())
            .map(|password| Password::from(password.as_bytes().to_vec()));
        let confirmed = form.as_ref().and_then(|form| form.confirm_burn.as_deref()) == Some("1");
        let no_password = password.is_none();
        let key: Key = id.parse()?;

        let metadata = match db.get_metadata(key.id).await {
            Ok(metadata) => metadata,
            Err(err) => return Err(err.into()),
        };

        if metadata.must_be_deleted && !confirmed {
            return Ok(BurnConfirmation {
                page: page.clone(),
                theme,
                lang,
                id,
                title: metadata.title.clone(),
            }
            .into_response());
        }

        // An entry is only ever cached while it was available and unencrypted, so a hit can be
        // served from metadata alone — no need to read and decompress the body just to drop it.
        let cached = no_password.then(|| cache.get(&key, Mode::Source)).flatten();

        let (html, is_available, metadata) = if let Some(html) = cached {
            tracing::trace!(?key, "found cached item");
            (html, true, metadata)
        } else {
            let (data, is_available) = match db.get(key.id, password).await {
                Ok(Entry::Regular(data)) => (data, true),
                Ok(Entry::Burned(data)) => (data, false),
                Err(db::Error::NoPassword) => return Ok(password_input(page, theme, lang, id)),
                Err(err) => return Err(err.into()),
            };

            let Data { text, metadata } = data;
            let ext = key.ext.clone();
            let highlighter = highlighter.clone();
            let html: Arc<str> =
                tokio::task::spawn_blocking(move || highlighter.highlight(text, ext))
                    .await??
                    .into_inner();

            if is_available && no_password {
                tracing::trace!(?key, "cache item");
                cache.put(&key, Mode::Source, Arc::clone(&html));
            }

            (html, is_available, metadata)
        };

        let Metadata {
            uid: owner_uid,
            title,
            expiration,
            ..
        } = metadata;

        let paste = Paste {
            page: page.clone(),
            can_delete: can_delete(uids.as_ref(), owner_uid),
            is_markdown: highlighter.is_markdown(key.ext.as_deref()),
            key,
            theme,
            lang,
            is_available,
            expiration,
            html,
            title,
        };

        Ok(paste.into_response())
    }
    .await
    .map_err(|err| make_error(err, appstate.page, theme, lang))
}

#[cfg(test)]
mod tests {
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

    #[tokio::test]
    async fn unknown_paste() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/000000").send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn owner_handoff_does_not_redirect_off_site() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let entry = crate::handlers::insert::api::Entry {
            text: "FooBarBaz".to_string(),
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
            .get(&format!("/%2F%2Fevil.example.com?owner={}", payload.owner))
            .send()
            .await?;

        // The id does not parse, so this must not turn into a redirect at all.
        assert_ne!(res.status(), StatusCode::SEE_OTHER);
        assert!(res.headers().get("location").is_none());

        Ok(())
    }

    /// The first view populates the render cache; once the paste expires the cached render must
    /// not be served in its place.
    #[tokio::test]
    async fn expired_paste_is_not_served_from_cache() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let data = Entry {
            text: String::from("cache-me-then-expire"),
            expires: Some(String::from("1")),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.contains("cache-me-then-expire"));

        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    /// Deleting a paste leaves its render in the cache, so the view must decide availability from
    /// the database rather than from a cache hit.
    #[tokio::test]
    async fn deleted_paste_is_not_served_from_cache() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;
        let data = Entry {
            text: String::from("cache-me-then-delete"),
            ..Default::default()
        };

        let res = client.post_form().form(&data).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?.to_owned();

        // The first view fills the cache, the second is served from it.
        for _ in 0..2 {
            let res = client.get(&location).send().await?;
            assert_eq!(res.status(), StatusCode::OK);
            assert!(res.text().await?.contains("cache-me-then-delete"));
        }

        let res = client.delete(&location).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = client.get(&location).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // The raw view never consults the cache, but must agree.
        let res = client.get(&format!("/raw{location}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
