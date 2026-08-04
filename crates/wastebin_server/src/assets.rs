use std::time::Duration;

use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum_extra::{TypedHeader, headers};
use sha2::{Digest, Sha256};

use wastebin_highlight::Theme;

/// An asset associated with a MIME type.
#[derive(Clone)]
pub(crate) struct Asset {
    /// Route that this will be served under.
    route: String,
    /// MIME type of this asset determined for the `ContentType` response header.
    mime: mime::Mime,
    /// Actual asset content.
    content: Bytes,
    /// Whether `route` carries a content hash. Only then can the bytes behind it never change,
    /// which is what makes an indefinite, unvalidated cache entry safe.
    hashed: bool,
}

/// Asset kind.
#[derive(Copy, Clone)]
pub(crate) enum Kind {
    Css,
    Js,
}

impl IntoResponse for Asset {
    fn into_response(self) -> Response {
        self.response()
    }
}

impl Asset {
    /// Construct new asset under the given `name`, `mime` type and `content`.
    #[must_use]
    pub fn new(name: &str, mime: mime::Mime, content: Vec<u8>) -> Self {
        Self {
            route: format!("/{name}"),
            mime,
            content: content.into(),
            hashed: false,
        }
    }

    /// Construct new hashed asset under the given `name`, `kind` and `content`.
    #[must_use]
    pub fn new_hashed(name: &str, kind: Kind, content: Vec<u8>) -> Self {
        let (mime, ext) = match kind {
            Kind::Css => (mime::TEXT_CSS, "css"),
            Kind::Js => (mime::TEXT_JAVASCRIPT, "js"),
        };

        let route = format!(
            "/{name}.{}.{ext}",
            hex::encode(Sha256::digest(&content))
                .get(0..16)
                .expect("at least 16 characters")
        );

        Self {
            route,
            mime,
            content: content.into(),
            hashed: true,
        }
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Serve this asset without copying its content.
    #[must_use]
    pub fn response(&self) -> Response {
        // Only a hashed route is safe to pin: its URL changes with its content, so a client can
        // never be stuck on a stale copy. An unhashed route outlives its bytes, so it gets a
        // short window instead of being frozen for a month.
        let cache_control = if self.hashed {
            headers::CacheControl::new()
                .with_max_age(Duration::from_hours(24 * 365))
                .with_immutable()
        } else {
            headers::CacheControl::new().with_max_age(Duration::from_hours(1))
        };

        let headers = (
            TypedHeader(headers::ContentType::from(self.mime.clone())),
            TypedHeader(cache_control),
        );

        (headers, self.content.clone()).into_response()
    }
}

/// Collection of light and dark CSS and main UI style CSS derived from them.
pub(crate) struct Css {
    /// Main UI CSS stylesheet.
    pub style: Asset,
    /// Light theme colors.
    pub light: Asset,
    /// Dark theme colors.
    pub dark: Asset,
    /// Overrides applied when JavaScript is disabled.
    pub no_js: Asset,
}

impl Css {
    /// Create CSS assets for `theme`.
    #[must_use]
    pub fn new(theme: Theme) -> Self {
        let style = Asset::new_hashed("style", Kind::Css, include_str!("style.css").into());
        let light = Asset::new_hashed("light", Kind::Css, theme.light_css());
        let dark = Asset::new_hashed("dark", Kind::Css, theme.dark_css());
        let no_js = Asset::new_hashed("no-js", Kind::Css, include_str!("no-js.css").into());

        Self {
            style,
            light,
            dark,
            no_js,
        }
    }

    /// Iterate over all CSS assets.
    pub fn iter(&self) -> impl Iterator<Item = &Asset> {
        [&self.style, &self.light, &self.dark, &self.no_js].into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_asset() {
        let asset = Asset::new_hashed("style", Kind::Css, String::from("body {}").into_bytes());
        assert_eq!(asset.route(), "/style.62368a1a29259b30.css");

        let asset = Asset::new_hashed("main", Kind::Js, String::from("1 + 1").into_bytes());
        assert_eq!(asset.route(), "/main.72fce59447a01f48.js");
    }

    #[test]
    fn asset_response() {
        let asset = Asset::new(
            "foo.css",
            mime::TEXT_CSS,
            String::from("body {}").into_bytes(),
        );

        let response = asset.into_response();
        let headers = response.headers();

        assert_eq!(headers.get(http::header::CONTENT_TYPE).unwrap(), "text/css");
    }

    /// A content-hashed route can never serve different bytes, so it may be pinned forever.
    #[test]
    fn hashed_assets_are_cached_indefinitely() {
        let asset = Asset::new_hashed("style", Kind::Css, String::from("body {}").into_bytes());
        let response = asset.into_response();

        assert_eq!(
            response.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "immutable, max-age=31536000"
        );
    }

    /// An unhashed route keeps serving the same URL after its content changes, so pinning it
    /// would strand the stale copy in every client that fetched it.
    #[test]
    fn unhashed_assets_are_revalidated() {
        let asset = Asset::new("favicon.png", mime::IMAGE_PNG, vec![0]);
        let response = asset.into_response();

        let cache_control = response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        assert!(
            !cache_control.contains("immutable"),
            "got: {cache_control}"
        );
        assert_eq!(cache_control, "max-age=3600");
    }
}
