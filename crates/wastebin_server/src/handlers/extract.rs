use std::convert::Infallible;
use std::str::FromStr;

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

/// Which representation the client wants back when a request fails.
///
/// Only an explicit preference for `application/json` switches away from HTML, so a browser, a
/// bare `curl` and anything sending `*/*` keep getting the rendered page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Accepts {
    #[default]
    Html,
    Json,
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

/// Marks a signed payload as an owner token rather than a `uid` cookie's uid list.
///
/// The signature covers the value alone — not the name it is stored under — so a bare uid signed
/// for the token was byte-for-byte a valid single-entry `uid` cookie. The token travels in a URL,
/// where it reaches browser history, bookmarks and anything logging full URLs, so whoever picked
/// one out could paste it straight into a `Cookie:` header instead of going through the handoff.
///
/// Marking the payload does not stop it verifying under another name — nothing can, given what is
/// signed — but `parse_uids` drops the marked form as junk, so a replayed token now names no
/// identity at all. A uid list never carries the marker, so it does not verify as a token either.
const OWNER_TOKEN_PREFIX: &str = "owner:";

/// Sign a single uid using the same key as the `uid` cookie. The returned
/// string is meant to be carried in the `?owner=` query of a paste URL so the
/// server can promote it to a proper signed cookie on first GET.
///
/// The token names an identity, not a paste, and identities are reused across every paste a
/// client creates — so whoever holds one can delete all of them, those made after the token was
/// issued included. That is what makes the handoff a grouping mechanism; treat the token as the
/// long-lived credential it is.
pub(crate) fn sign_owner_token(key: &Key, uid: i64) -> String {
    let mut jar = cookie::CookieJar::new();
    jar.signed_mut(key)
        .add(Cookie::new("owner", format!("{OWNER_TOKEN_PREFIX}{uid}")));
    jar.get("owner")
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default()
}

/// Verify a token produced by [`sign_owner_token`] and recover the uid.
pub(crate) fn verify_owner_token(key: &Key, token: &str) -> Option<i64> {
    let mut jar = cookie::CookieJar::new();
    jar.add(Cookie::new("owner", token.to_owned()));
    jar.signed(key)
        .get("owner")
        .and_then(|cookie| {
            cookie
                .value()
                .strip_prefix(OWNER_TOKEN_PREFIX)
                .map(str::to_owned)
        })
        .and_then(|uid| uid.parse::<i64>().ok())
}

/// Only the optional form exists: a request without the cookie is ordinary, not a failure, and
/// every consumer takes `Option<Uids>`. A mandatory impl would carry a rejection no response path
/// ever renders.
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
        let Ok(jar) = SignedCookieJar::<crate::Key>::from_request_parts(parts, state).await;

        Ok(jar
            .get("uid")
            .map(|cookie| Uids(parse_uids(cookie.value_trimmed()))))
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

        // `Authority` drops the port and keeps an IPv6 literal's brackets, which is the spelling
        // `Url::host_str` produces on the other side of the comparison. A `Host` it cannot parse
        // names nothing, so only the configured base URL can still match.
        let addressed = self
            .host
            .as_deref()
            .and_then(|host| http::uri::Authority::from_str(host).ok());
        let configured = base_url.host_str();

        addressed.as_ref().map(http::uri::Authority::host) != Some(origin_host.as_str())
            && configured != Some(origin_host.as_str())
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

/// Read the `q=` weight of an `Accept`-style entry's parameters, defaulting to `1.0`.
fn quality(parts: std::str::Split<'_, char>) -> f32 {
    parts
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("q=").or_else(|| part.strip_prefix("Q="))
        })
        .find_map(|value| value.parse::<f32>().ok())
        .unwrap_or(1.0)
}

/// Pick the highest weighted entry of an `Accept`-style header, honoring `q=` weights.
///
/// `pick` maps one entry's media range or language tag to a value; entries it rejects are
/// ignored. Position breaks ties so the first listed entry wins at equal weight.
fn negotiate<T>(header: &str, pick: impl Fn(&str) -> Option<T>) -> Option<T> {
    header
        .split(',')
        .enumerate()
        .filter_map(|(idx, entry)| {
            let mut parts = entry.split(';');
            let value = pick(parts.next().map(str::trim)?)?;

            #[expect(clippy::cast_precision_loss)]
            let weighted = quality(parts) - (idx as f32) * 1e-6;

            Some((weighted, value))
        })
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(_, value)| value)
}

/// Pick the representation an `Accept` header asks for, honoring `q=` weights.
///
/// Media ranges other than the two concrete types are ignored, so `*/*` — what a bare `curl`
/// and many libraries send — leaves the HTML default in place rather than being read as a
/// preference either way.
fn accepts_from_header(header: &str) -> Accepts {
    negotiate(header, |media| {
        if media.eq_ignore_ascii_case("application/json") {
            Some(Accepts::Json)
        } else if media.eq_ignore_ascii_case("text/html") {
            Some(Accepts::Html)
        } else {
            None
        }
    })
    .unwrap_or_default()
}

impl<S> FromRequestParts<S> for Accepts
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
            .get(http::header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map_or_else(Accepts::default, accepts_from_header)))
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
    negotiate(header, lang_from_tag).unwrap_or_default()
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

    /// The signature covers the cookie's name, so signing the token under `uid` made it byte-for-
    /// byte a valid single-entry `uid` cookie. Since the token rides in a URL — browser history,
    /// bookmarks, any proxy logging one — a leak could be replayed as a cookie directly, skipping
    /// the handoff the design routes claims through.
    #[test]
    fn an_owner_token_is_not_also_a_uid_cookie() {
        let key = Key::generate();
        let token = sign_owner_token(&key, 42);

        // The signature covers the value alone, so the token still verifies when presented under
        // another name. What has to hold is that its payload names no identity.
        let mut jar = cookie::CookieJar::new();
        jar.add(Cookie::new("uid", token.clone()));
        let claimed = jar
            .signed(&key)
            .get("uid")
            .map(|cookie| parse_uids(cookie.value_trimmed()))
            .unwrap_or_default();
        assert!(
            claimed.is_empty(),
            "an owner token conferred {claimed:?} when replayed as a uid cookie"
        );

        // The reverse, too: a cookie value must not stand in for a token.
        let mut jar = cookie::CookieJar::new();
        jar.signed_mut(&key).add(Cookie::new("uid", "42"));
        let cookie_value = jar.get("uid").expect("signed cookie").value().to_owned();
        assert_eq!(
            verify_owner_token(&key, &cookie_value),
            None,
            "a uid cookie verified as an owner token"
        );

        // And the token still round-trips.
        assert_eq!(verify_owner_token(&key, &token), Some(42));
    }

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
    fn accept_header_selects_the_representation() {
        assert_eq!(accepts_from_header("application/json"), Accepts::Json);
        assert_eq!(accepts_from_header("text/html"), Accepts::Html);

        // A browser listing both prefers HTML by weight.
        assert_eq!(
            accepts_from_header("text/html,application/xhtml+xml,application/json;q=0.9"),
            Accepts::Html
        );
        assert_eq!(
            accepts_from_header("text/html;q=0.2,application/json;q=0.9"),
            Accepts::Json
        );
    }

    /// `*/*` states no preference, so it must not be read as one.
    #[test]
    fn wildcard_accept_keeps_the_html_default() {
        assert_eq!(accepts_from_header("*/*"), Accepts::Html);
        assert_eq!(accepts_from_header("text/plain"), Accepts::Html);
        assert_eq!(accepts_from_header(""), Accepts::Html);
    }

    #[test]
    fn first_listed_wins_on_tie() {
        // Both implicit q=1.0; first listed should win.
        assert_eq!(lang_from_accept_language("de,en"), Lang::De);
        assert_eq!(lang_from_accept_language("en,de"), Lang::En);
    }
}
