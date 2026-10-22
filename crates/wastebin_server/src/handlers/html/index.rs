use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::i18n::Lang;
use crate::{Page, handlers::extract::Theme};

/// GET handler for the index page.
#[must_use]
pub async fn get(State(page): State<Page>, theme: Theme, lang: Lang) -> Index {
    Index { page, theme, lang }
}

/// Index page displaying a form for paste insertion and a selection box for languages.
#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
pub(crate) struct Index {
    page: Page,
    theme: Theme,
    lang: Lang,
}

#[cfg(test)]
mod tests {
    use crate::cache::valid_extension;

    /// Picker extension coverage.
    ///
    /// The template submits `extensions.first()`.
    #[test]
    fn picker_extensions_pass_validation() {
        let highlighter = &crate::test_helpers::HIGHLIGHTER;

        for syntax in highlighter.syntaxes() {
            let Some(extension) = syntax.extensions.first() else {
                continue;
            };

            assert!(
                valid_extension(extension),
                "syntax {:?} submits invalid extension {:?}",
                syntax.name,
                extension
            );
        }
    }
}
