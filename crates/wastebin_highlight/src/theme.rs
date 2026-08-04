use std::io::Cursor;
use std::str::FromStr;
use std::sync::LazyLock;

use syntect::highlighting::{self, ThemeSet};
use syntect::html::{ClassStyle, css_for_theme_with_class_style};
use two_face::theme::{EmbeddedLazyThemeSet, EmbeddedThemeName};

use crate::palette;

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
    RosePine,
    Solarized,
}

/// Where the light and dark variants of a [`Theme`] come from.
enum Variants {
    /// Bundled with `two_face`.
    Embedded(EmbeddedThemeName, EmbeddedThemeName),
    /// Shipped as `.tmTheme` sources with this crate.
    File(&'static str, &'static str),
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
    pub const ALL: [Self; 9] = [
        Theme::Ayu,
        Theme::Base16Ocean,
        Theme::Catppuccin,
        Theme::Coldark,
        Theme::Gruvbox,
        Theme::Monokai,
        Theme::Onehalf,
        Theme::RosePine,
        Theme::Solarized,
    ];

    /// Generate combined light CSS for the given Theme.
    #[must_use]
    pub fn light_css(self) -> Vec<u8> {
        combined_css(palette::Scheme::Light, &self.light_theme())
    }

    /// Return light syntect highlighting theme.
    #[must_use]
    pub fn light_theme(self) -> highlighting::Theme {
        self.theme(false)
    }

    /// Generate combined dark CSS for the given Theme.
    #[must_use]
    pub fn dark_css(self) -> Vec<u8> {
        combined_css(palette::Scheme::Dark, &self.dark_theme())
    }

    /// Return dark syntect highlighting theme.
    #[must_use]
    pub fn dark_theme(self) -> highlighting::Theme {
        self.theme(true)
    }

    /// Light and dark variants.
    const fn variants(self) -> Variants {
        match self {
            Theme::Ayu => Variants::File(
                include_str!("../themes/ayu-light.tmTheme"),
                include_str!("../themes/ayu-dark.tmTheme"),
            ),
            Theme::Base16Ocean => Variants::Embedded(
                EmbeddedThemeName::Base16OceanLight,
                EmbeddedThemeName::Base16OceanDark,
            ),
            Theme::Catppuccin => Variants::Embedded(
                EmbeddedThemeName::CatppuccinLatte,
                EmbeddedThemeName::CatppuccinMocha,
            ),
            Theme::Coldark => Variants::Embedded(
                EmbeddedThemeName::ColdarkCold,
                EmbeddedThemeName::ColdarkDark,
            ),
            Theme::Gruvbox => Variants::Embedded(
                EmbeddedThemeName::GruvboxLight,
                EmbeddedThemeName::GruvboxDark,
            ),
            Theme::Monokai => Variants::Embedded(
                EmbeddedThemeName::MonokaiExtendedLight,
                EmbeddedThemeName::MonokaiExtended,
            ),
            Theme::Onehalf => Variants::Embedded(
                EmbeddedThemeName::OneHalfLight,
                EmbeddedThemeName::OneHalfDark,
            ),
            Theme::RosePine => Variants::File(
                include_str!("../themes/rose-pine-dawn.tmTheme"),
                include_str!("../themes/rose-pine.tmTheme"),
            ),
            Theme::Solarized => Variants::Embedded(
                EmbeddedThemeName::SolarizedLight,
                EmbeddedThemeName::SolarizedDark,
            ),
        }
    }

    fn theme(self, dark: bool) -> highlighting::Theme {
        match self.variants() {
            Variants::Embedded(light, dark_name) => {
                THEMES.get(if dark { dark_name } else { light }).clone()
            }
            Variants::File(light, dark_source) => {
                let theme = if dark { dark_source } else { light };
                ThemeSet::load_from_reader(&mut Cursor::new(theme)).expect("loading theme")
            }
        }
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
            Theme::RosePine => "rosepine",
            Theme::Solarized => "solarized",
        }
    }
}

/// Generate the UI chrome palette for `theme` followed by the syntax highlighting colors.
fn combined_css(scheme: palette::Scheme, theme: &highlighting::Theme) -> Vec<u8> {
    format!(
        "{}{}",
        palette::Palette::new(theme, scheme).css(),
        css_for_theme_with_class_style(theme, ClassStyle::Spaced).expect("generating CSS")
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rose_pine_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let theme: Theme = "rosepine".parse()?;
        assert_eq!(theme.name(), "rosepine");
        Ok(())
    }

    #[test]
    fn rose_pine_bundled_files_load() -> Result<(), Box<dyn std::error::Error>> {
        let theme: Theme = "rosepine".parse()?;

        // The bundled Dawn and main variants carry these background colors, so seeing them in the
        // generated CSS proves the right file ended up on each side.
        let light = String::from_utf8(theme.light_css())?;
        assert!(light.contains("--page-bg: #faf4ed;"));

        let dark = String::from_utf8(theme.dark_css())?;
        assert!(dark.contains("--page-bg: #191724;"));

        Ok(())
    }

    #[test]
    fn foreground_alpha_is_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let theme: Theme = "gruvbox".parse()?;

        // Gruvbox stores its foreground with a non-opaque alpha. The syntax highlighting CSS
        // ignores the alpha, so the chrome palette does too.
        let dark = String::from_utf8(theme.dark_css())?;
        assert!(dark.contains("--fg: #ebdbb2;"), "{dark}");

        Ok(())
    }
}
