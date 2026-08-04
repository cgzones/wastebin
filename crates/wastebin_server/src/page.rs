use std::num::NonZeroU32;

use url::Url;

use crate::assets::{Asset, Css, Kind};
use wastebin_core::expiration::{Expiration, ExpirationSet};
use wastebin_highlight::Theme;

/// Static page assets.
pub(crate) struct Assets {
    pub favicon: Asset,
    /// The same icon under the well-known path. Browsers follow the `<link rel="icon">` to
    /// `favicon.png`, but link unfurlers and feed readers still probe `/favicon.ico` blindly, and
    /// an error page is a poor answer for them.
    pub favicon_ico: Asset,
    pub css: Css,
    pub index_js: Asset,
    pub paste_js: Asset,
    pub burn_js: Asset,
    pub password_toggle_js: Asset,
}

/// One selectable expiration in the index form, and whether it is preselected.
pub(crate) struct ExpirationChoice {
    pub duration: std::time::Duration,
    pub default: bool,
}

impl std::fmt::Display for ExpirationChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Expiration {
            duration: self.duration,
        }
        .fmt(f)
    }
}

pub(crate) struct Page {
    pub version: &'static str,
    pub title: String,
    pub assets: Assets,
    pub base_url: Url,
    pub expirations: Vec<ExpirationChoice>,
    pub max_body_size: usize,
    pub max_expiration: Option<NonZeroU32>,
}

impl Page {
    /// Create new page meta data from generated  `assets`, `title` and optional `base_url`.
    #[must_use]
    pub fn new(
        title: String,
        base_url: Url,
        theme: Theme,
        expirations: ExpirationSet,
        max_body_size: usize,
        max_expiration: Option<NonZeroU32>,
    ) -> Self {
        let assets = Assets::new(theme);
        let (values, default) = expirations.into_parts();
        let expirations = values
            .into_iter()
            .map(|expiration| ExpirationChoice {
                duration: expiration.duration,
                default: default == Some(expiration),
            })
            .collect();

        Self {
            version: env!("CARGO_PKG_VERSION"),
            title,
            assets,
            base_url,
            expirations,
            max_body_size,
            max_expiration,
        }
    }
}

impl Assets {
    /// Create page [`Assets`] for the given `theme`.
    #[must_use]
    fn new(theme: Theme) -> Self {
        let favicon = Asset::new(
            "favicon.png",
            mime::IMAGE_PNG,
            include_bytes!("../../../assets/favicon.png").to_vec(),
        );

        Self {
            // Both routes serve the same bytes; `Asset` holds them in `Bytes`, so this shares
            // rather than copies them.
            favicon_ico: favicon.aliased("favicon.ico"),
            favicon,
            css: Css::new(theme),
            index_js: Asset::new_hashed(
                "index",
                Kind::Js,
                include_bytes!("javascript/index.js").to_vec(),
            ),
            paste_js: Asset::new_hashed(
                "paste",
                Kind::Js,
                include_bytes!("javascript/paste.js").to_vec(),
            ),
            burn_js: Asset::new_hashed(
                "burn",
                Kind::Js,
                include_bytes!("javascript/burn.js").to_vec(),
            ),
            password_toggle_js: Asset::new_hashed(
                "password-toggle",
                Kind::Js,
                include_bytes!("javascript/password-toggle.js").to_vec(),
            ),
        }
    }

    /// Iterate over every asset, so routing them does not have to enumerate the fields by hand.
    pub fn iter(&self) -> impl Iterator<Item = &Asset> {
        [
            &self.favicon,
            &self.favicon_ico,
            &self.index_js,
            &self.paste_js,
            &self.burn_js,
            &self.password_toggle_js,
        ]
        .into_iter()
        .chain(self.css.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(expirations: &str) -> Page {
        Page::new(
            String::from("test"),
            Url::parse("https://localhost:8888").unwrap(),
            Theme::Ayu,
            expirations.parse::<ExpirationSet>().unwrap(),
            1024,
            None,
        )
    }

    #[test]
    fn preselects_the_default_expiration() {
        let page = page("10m,1h=d,1d");

        let checked = page
            .expirations
            .iter()
            .filter(|choice| choice.default)
            .collect::<Vec<_>>();

        assert_eq!(checked.len(), 1);
        assert_eq!(checked[0].duration, std::time::Duration::from_hours(1));
    }

    #[test]
    fn preselects_nothing_without_a_default() {
        let page = page("10m,1h,1d");
        assert!(page.expirations.iter().all(|choice| !choice.default));
    }
}
