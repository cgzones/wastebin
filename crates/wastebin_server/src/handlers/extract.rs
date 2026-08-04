use std::convert::Infallible;

use axum::extract::{
    Form, FromRef, FromRequest, FromRequestParts, OptionalFromRequest, OptionalFromRequestParts,
    Request,
};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum_extra::extract::cookie::Key;
use axum_extra::extract::{CookieJar, SignedCookieJar};
use cookie::Cookie;
use serde::Deserialize;

use wastebin_core::crypto;

use crate::i18n::Lang;

/// A safe redirect back to the referer.
///
/// Extracts the `Referer` header and strips it down to just the path (and query string),
/// preventing open redirects via external referer values. Falls back to `"/"`.
pub(crate) struct SafeReferer(pub Redirect);

/// Theme extractor, extracted from the `pref` cookie. An absent or unparsable cookie yields
/// [`Theme::System`].
#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub(crate) enum Theme {
    #[serde(rename = "dark")]
    Dark,
    #[serde(rename = "light")]
    Light,
    #[default]
    #[serde(rename = "system")]
    System,
}

/// Theme preference for use in shared [`axum::extract::Query`]'s.
#[derive(Debug, Deserialize)]
pub(crate) struct Preference {
    pub pref: Theme,
}

/// Password extractor.
pub(crate) struct Password(pub crypto::Password);

/// The `Origin` a request declared, together with the `Host` it was addressed to.
///
/// Browsers attach `Origin` to form submissions and page script cannot forge it, so a mismatch
/// identifies a cross-site submission. Requests without one — curl, the JSON API, anything not a
/// browser — are deliberately left alone: this backs up `SameSite=Strict` on the cookies rather
/// than replacing it.
pub(crate) struct RequestOrigin {
    origin: Option<String>,
    host: Option<String>,
}

/// Uid cookie value extractor, extracted from the `uid` cookie.
///
/// The cookie holds a comma-separated list of i64 values: index 0 is the client's
/// primary identity (used by the form route when tagging new pastes), subsequent
/// entries are uids claimed via the magic-link `?owner=` handoff. An empty list
/// is valid (e.g. cookie was just signed-but-empty).
pub(crate) struct Uids(pub Vec<i64>);

/// Password header to encrypt a paste.
pub(crate) const PASSWORD_HEADER_NAME: http::HeaderName =
    http::HeaderName::from_static("wastebin-password");

impl std::fmt::Display for Theme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Theme::Dark => f.write_str("dark"),
            Theme::Light => f.write_str("light"),
            Theme::System => f.write_str("system"),
        }
    }
}

impl std::str::FromStr for Theme {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dark" => Ok(Theme::Dark),
            "light" => Ok(Theme::Light),
            "system" => Ok(Theme::System),
            _ => Err(()),
        }
    }
}

impl<S> FromRequestParts<S> for Theme
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await;

        jar.map(|jar| {
            jar.get("pref")
                .and_then(|cookie| cookie.value_trimmed().parse::<Theme>().ok())
                .unwrap_or_default()
        })
    }
}

/// Parse the comma-separated `uid` cookie value into a list of i64s.
/// Non-numeric tokens are skipped silently — a tampered cookie that survives
/// HMAC verification but contains junk should not 500 the request.
pub(crate) fn parse_uids(value: &str) -> Vec<i64> {
    value
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect()
}

/// Return `true` if the client's uid list claims ownership of `owner_uid`, i.e. whether this
/// client is allowed to delete the paste.
pub(crate) fn can_delete(uids: Option<&Uids>, owner_uid: Option<i64>) -> bool {
    matches!((uids, owner_uid), (Some(Uids(uids)), Some(owner_uid)) if uids.contains(&owner_uid))
}

/// Serialize a uid list back into the cookie wire format.
pub(crate) fn serialize_uids(uids: &[i64]) -> String {
    uids.iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Sign a single uid using the same key as the `uid` cookie. The returned
/// string is meant to be carried in the `?owner=` query of a paste URL so the
/// server can promote it to a proper signed cookie on first GET.
pub(crate) fn sign_owner_token(key: &Key, uid: i64) -> String {
    let mut jar = cookie::CookieJar::new();
    jar.signed_mut(key).add(Cookie::new("uid", uid.to_string()));
    jar.get("uid")
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default()
}

/// Verify a token produced by [`sign_owner_token`] and recover the uid.
pub(crate) fn verify_owner_token(key: &Key, token: &str) -> Option<i64> {
    let mut jar = cookie::CookieJar::new();
    jar.add(Cookie::new("uid", token.to_owned()));
    jar.signed(key)
        .get("uid")
        .and_then(|cookie| cookie.value().parse::<i64>().ok())
}

impl<S> FromRequestParts<S> for Uids
where
    S: Send + Sync,
    Key: FromRef<S>,
{
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = SignedCookieJar::<crate::Key>::from_request_parts(parts, state)
            .await
            .map_err(|_| ())?;

        let uids = jar
            .get("uid")
            .map(|cookie| parse_uids(cookie.value_trimmed()))
            .ok_or(())?;

        Ok(Uids(uids))
    }
}

impl<S> OptionalFromRequestParts<S> for Uids
where
    S: Send + Sync,
    Key: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(
            <Uids as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
                .ok(),
        )
    }
}

/// Strip a trailing `:port` from an authority, leaving an IPv6 literal's brackets intact.
fn host_of(authority: &str) -> &str {
    match authority.rfind(']') {
        Some(end) => &authority[..=end],
        None => authority.split(':').next().unwrap_or(authority),
    }
}

impl RequestOrigin {
    /// Whether a browser marked this request as coming from another site.
    ///
    /// The declared origin is accepted when it names either the host the request was addressed
    /// to or the configured base URL. Both are needed: a reverse proxy may rewrite `Host` to an
    /// internal name, while `WASTEBIN_BASE_URL` may be left at its hostname-derived guess. Only
    /// hosts are compared — a port mismatch is not a cross-site signal worth breaking
    /// deployments over.
    pub(crate) fn is_cross_site(&self, base_url: &url::Url) -> bool {
        let Some(origin) = self.origin.as_deref() else {
            return false;
        };

        // A sandboxed or privacy-shielded context sends `null`, which matches nothing.
        let Some(origin_host) = url::Url::parse(origin)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
        else {
            return true;
        };

        let addressed = self.host.as_deref().map(host_of);
        let configured = base_url.host_str();

        addressed != Some(origin_host.as_str()) && configured != Some(origin_host.as_str())
    }
}

impl<S> FromRequestParts<S> for RequestOrigin
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let header = |name: http::HeaderName| {
            parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };

        std::future::ready(Ok(Self {
            origin: header(http::header::ORIGIN),
            host: header(http::header::HOST),
        }))
    }
}

/// Whether `value` stays on this origin: exactly one leading slash, and no second slash or
/// backslash after it. Browsers resolve both `//host` and `/\host` as an authority, so either
/// would leave the origin.
fn is_same_origin_path(value: &str) -> bool {
    value
        .strip_prefix('/')
        .is_some_and(|rest| !rest.starts_with('/') && !rest.starts_with('\\'))
}

/// Reduce a `Referer` header value to a same-origin redirect target.
fn referer_redirect(referer: Option<&str>) -> Redirect {
    let Some(referer) = referer else {
        return Redirect::to("/");
    };

    if is_same_origin_path(referer) {
        return Redirect::to(referer);
    }

    let Ok(url) = referer.parse::<url::Url>() else {
        return Redirect::to("/");
    };

    // The path of an absolute URL can itself start with a slash run, so it needs the same check.
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };

    if is_same_origin_path(&target) {
        Redirect::to(&target)
    } else {
        Redirect::to("/")
    }
}

impl<S> FromRequestParts<S> for SafeReferer
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let referer = parts
            .headers
            .get(http::header::REFERER)
            .and_then(|referer| referer.to_str().ok());

        std::future::ready(Ok(SafeReferer(referer_redirect(referer))))
    }
}

impl<S> OptionalFromRequest<S> for Password
where
    S: Send + Sync,
{
    type Rejection = ();

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        #[derive(Deserialize, Debug)]
        struct Data {
            password: String,
        }

        let password = req
            .headers()
            .get(PASSWORD_HEADER_NAME)
            .and_then(|header| header.to_str().ok())
            .map(|value| Password(value.as_bytes().to_vec().into()));

        if password.is_some() {
            return Ok(password);
        }

        // `Form` reads the query string on GET and HEAD, which would put the password in the URL
        // and from there into browser history and every proxy log on the way. Only accept it from
        // a request body; the header above is the way to send one with a GET.
        if matches!(req.method(), &http::Method::GET | &http::Method::HEAD) {
            return Ok(None);
        }

        Ok(Form::<Data>::from_request(req, state)
            .await
            .ok()
            .map(|data| Password(data.password.as_bytes().to_vec().into())))
    }
}

/// Map a single language tag (e.g. `en`, `de-AT`) to a supported [`Lang`].
fn lang_from_tag(tag: &str) -> Option<Lang> {
    const TAGS: [(&str, Lang); 3] = [("en", Lang::En), ("de", Lang::De), ("zh", Lang::Zh)];

    let primary = tag.split('-').next()?.trim();

    TAGS.into_iter()
        .find(|(tag, _)| primary.eq_ignore_ascii_case(tag))
        .map(|(_, lang)| lang)
}

/// Pick the best supported language from an `Accept-Language` header value,
/// honoring `q=` weights. Falls back to the default language if nothing
/// matches.
fn lang_from_accept_language(header: &str) -> Lang {
    header
        .split(',')
        .enumerate()
        .filter_map(|(idx, entry)| {
            let mut parts = entry.split(';');
            let tag = parts.next().map(str::trim).filter(|t| !t.is_empty())?;
            let lang = lang_from_tag(tag)?;

            let q = parts
                .find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                })
                .and_then(|s| s.parse::<f32>().ok())
                .unwrap_or(1.0);

            // Use position as a tie-breaker so the first listed entry wins
            // when weights are equal.
            #[expect(clippy::cast_precision_loss)]
            let weighted = q - (idx as f32) * 1e-6;
            Some((weighted, lang))
        })
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map_or(Lang::default(), |(_, l)| l)
}

impl<S> FromRequestParts<S> for Lang
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(Ok(parts
            .headers
            .get(http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map_or_else(Lang::default, lang_from_accept_language)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(origin: Option<&str>, host: Option<&str>) -> RequestOrigin {
        RequestOrigin {
            origin: origin.map(str::to_owned),
            host: host.map(str::to_owned),
        }
    }

    fn base_url() -> url::Url {
        url::Url::parse("https://paste.example.com").unwrap()
    }

    #[test]
    fn a_request_without_an_origin_is_allowed() {
        // curl and the JSON API never send one.
        assert!(!request(None, Some("paste.example.com")).is_cross_site(&base_url()));
    }

    #[test]
    fn the_addressed_host_is_accepted() {
        // Matches Host but not the configured base URL, as on a LAN deployment.
        assert!(
            !request(Some("http://192.168.1.5:8088"), Some("192.168.1.5:8088"))
                .is_cross_site(&base_url())
        );
    }

    #[test]
    fn the_configured_base_url_is_accepted() {
        // Matches base_url but not Host, as behind a proxy that rewrites Host.
        assert!(
            !request(Some("https://paste.example.com"), Some("127.0.0.1:8088"))
                .is_cross_site(&base_url())
        );
    }

    #[test]
    fn ipv6_literals_keep_their_brackets() {
        assert!(!request(Some("http://[::1]:8088"), Some("[::1]:8088")).is_cross_site(&base_url()));
    }

    #[test]
    fn another_site_is_rejected() {
        for origin in [
            "https://evil.example.com",
            // A prefix/suffix of the real host must not pass.
            "https://paste.example.com.evil.test",
            "https://evilpaste.example.com",
            // Sandboxed contexts send this; it can never be same-site.
            "null",
        ] {
            assert!(
                request(Some(origin), Some("paste.example.com")).is_cross_site(&base_url()),
                "origin {origin} was accepted"
            );
        }
    }

    #[test]
    fn picks_highest_q() {
        assert_eq!(lang_from_accept_language("en;q=0.5,de;q=0.9"), Lang::De);
    }

    #[test]
    fn defaults_to_english_when_unsupported() {
        assert_eq!(lang_from_accept_language("ja,fr;q=0.7"), Lang::En);
    }

    #[test]
    fn handles_region_subtags() {
        assert_eq!(lang_from_accept_language("de-AT"), Lang::De);
    }

    #[test]
    fn first_listed_wins_on_tie() {
        // Both implicit q=1.0; first listed should win.
        assert_eq!(lang_from_accept_language("de,en"), Lang::De);
        assert_eq!(lang_from_accept_language("en,de"), Lang::En);
    }
}
