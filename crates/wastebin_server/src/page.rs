use std::num::NonZeroU32;

use url::Url;

use crate::assets::{Asset, Css, Kind};
use crate::highlight::Theme;
use wastebin_core::expiration::{Expiration, ExpirationSet};

/// Static page assets.
pub(crate) struct Assets {
    pub favicon: Asset,
    pub css: Css,
    pub index_js: Asset,
    pub paste_js: Asset,
    pub burn_js: Asset,
}

pub(crate) struct Page {
    pub version: &'static str,
    pub title: String,
    pub assets: Assets,
    pub base_url: Url,
    pub expirations: Vec<Expiration>,
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
        max_expiration: Option<NonZeroU32>,
    ) -> Self {
        let assets = Assets::new(theme);
        let expirations = expirations.into_inner();

        Self {
            version: env!("CARGO_PKG_VERSION"),
            title,
            assets,
            base_url,
            expirations,
            max_expiration,
        }
    }
}

impl Assets {
    /// Create page [`Assets`] for the given `theme`.
    #[must_use]
    fn new(theme: Theme) -> Self {
        Self {
            favicon: Asset::new(
                "favicon.ico",
                mime::IMAGE_PNG,
                include_bytes!("../../../assets/favicon.png").to_vec(),
            ),
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
        }
    }
}
