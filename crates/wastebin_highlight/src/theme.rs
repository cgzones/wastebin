use std::io::Cursor;
use std::str::FromStr;
use std::sync::LazyLock;

use syntect::highlighting::{self, ThemeSet};
use syntect::html::{ClassStyle, css_for_theme_with_class_style};
use two_face::theme::{EmbeddedLazyThemeSet, EmbeddedThemeName};

/// Deserializing the embedded theme dump is not cheap, so do it once.
static THEMES: LazyLock<EmbeddedLazyThemeSet> = LazyLock::new(two_face::theme::extra);

/// Supported themes.
#[derive(Copy, Clone)]
pub enum Theme {
    Ayu,
    Base16Ocean,
    Catppuccin,
    Coldark,
    Gruvbox,
    Monokai,
    Onehalf,
    Solarized,
}

/// An error which can be returned when parsing a [`Theme`] from its string representation.
#[derive(thiserror::Error, Debug)]
#[error("failed to parse theme name")]
pub struct ParseThemeNameError;

impl FromStr for Theme {
    type Err = ParseThemeNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|theme| theme.name() == s)
            .ok_or(ParseThemeNameError)
    }
}

impl Theme {
    /// All supported themes.
    pub const ALL: [Self; 8] = [
        Theme::Ayu,
        Theme::Base16Ocean,
        Theme::Catppuccin,
        Theme::Coldark,
        Theme::Gruvbox,
        Theme::Monokai,
        Theme::Onehalf,
        Theme::Solarized,
    ];

    /// Generate combined light CSS for the given Theme.
    #[must_use]
    pub fn light_css(self) -> Vec<u8> {
        combined_css("light", &self.light_theme())
    }

    /// Return light syntect highlighting theme.
    #[must_use]
    pub fn light_theme(self) -> highlighting::Theme {
        self.theme(false)
    }

    /// Generate combined dark CSS for the given Theme.
    #[must_use]
    pub fn dark_css(self) -> Vec<u8> {
        combined_css("dark", &self.dark_theme())
    }

    /// Return dark syntect highlighting theme.
    #[must_use]
    pub fn dark_theme(self) -> highlighting::Theme {
        self.theme(true)
    }

    /// Embedded light and dark variants, or `None` for themes shipped as `.tmTheme` files.
    const fn embedded(self) -> Option<(EmbeddedThemeName, EmbeddedThemeName)> {
        match self {
            Theme::Ayu => None,
            Theme::Base16Ocean => Some((
                EmbeddedThemeName::Base16OceanLight,
                EmbeddedThemeName::Base16OceanDark,
            )),
            Theme::Catppuccin => Some((
                EmbeddedThemeName::CatppuccinLatte,
                EmbeddedThemeName::CatppuccinMocha,
            )),
            Theme::Coldark => Some((
                EmbeddedThemeName::ColdarkCold,
                EmbeddedThemeName::ColdarkDark,
            )),
            Theme::Gruvbox => Some((
                EmbeddedThemeName::GruvboxLight,
                EmbeddedThemeName::GruvboxDark,
            )),
            Theme::Monokai => Some((
                EmbeddedThemeName::MonokaiExtendedLight,
                EmbeddedThemeName::MonokaiExtended,
            )),
            Theme::Onehalf => Some((
                EmbeddedThemeName::OneHalfLight,
                EmbeddedThemeName::OneHalfDark,
            )),
            Theme::Solarized => Some((
                EmbeddedThemeName::SolarizedLight,
                EmbeddedThemeName::SolarizedDark,
            )),
        }
    }

    fn theme(self, dark: bool) -> highlighting::Theme {
        let Some((light_name, dark_name)) = self.embedded() else {
            let theme = if dark {
                include_str!("../themes/ayu-dark.tmTheme")
            } else {
                include_str!("../themes/ayu-light.tmTheme")
            };
            return ThemeSet::load_from_reader(&mut Cursor::new(theme)).expect("loading theme");
        };

        THEMES
            .get(if dark { dark_name } else { light_name })
            .clone()
    }

    /// Return string representation of the theme name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Theme::Ayu => "ayu",
            Theme::Base16Ocean => "base16ocean",
            Theme::Catppuccin => "catppuccin",
            Theme::Coldark => "coldark",
            Theme::Gruvbox => "gruvbox",
            Theme::Monokai => "monokai",
            Theme::Onehalf => "onehalf",
            Theme::Solarized => "solarized",
        }
    }
}

/// Generate the highlighting colors for `theme` and add main foreground and background colors
/// based on the theme.
fn combined_css(color_scheme: &str, theme: &highlighting::Theme) -> Vec<u8> {
    let fg = theme.settings.foreground.expect("existing color");
    let bg = theme.settings.background.expect("existing color");

    format!(
        "{} {}",
        format_args!(
            ":root {{
      color-scheme: {color_scheme};
      --main-bg-color: rgb({}, {}, {}, {});
      --main-fg-color: rgb({}, {}, {}, {});
    }}",
            bg.r, bg.g, bg.b, bg.a, fg.r, fg.g, fg.b, fg.a
        ),
        css_for_theme_with_class_style(theme, ClassStyle::Spaced).expect("generating CSS")
    )
    .into_bytes()
}
