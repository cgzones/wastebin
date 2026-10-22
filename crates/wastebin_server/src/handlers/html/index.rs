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
    use crate::test_helpers::{Client, StoreCookies};

    /// Tab indents in the editor, so a keyboard user could not leave it; Escape hands the next
    /// Tab back to the browser, and the editor has to say so to whoever cannot see the page.
    #[tokio::test]
    async fn the_editor_tells_how_to_leave_it() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let body = client.get("/").send().await?.text().await?;

        let editor = body
            .split('<')
            .find(|tag| tag.starts_with("textarea "))
            .ok_or("no editor")?;
        assert!(
            editor.contains(r#"aria-describedby="editor-hint""#),
            "{editor}"
        );

        let hint = body
            .split('<')
            .find(|tag| tag.contains(r#"id="editor-hint""#))
            .ok_or("no hint")?;
        assert!(hint.contains("Escape"), "{hint}");

        Ok(())
    }

    /// The server can only refuse to encrypt with no password if it learns encryption was asked
    /// for, so the toggle has to be submitted with the form.
    #[tokio::test]
    async fn the_encryption_toggle_is_submitted() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;
        let body = client.get("/").send().await?.text().await?;

        let toggle = body
            .split('<')
            .find(|tag| tag.contains(r#"id="encrypt-toggle""#))
            .ok_or("no encryption toggle")?;
        assert!(toggle.contains(r#"name="encrypt""#), "{toggle}");

        Ok(())
    }

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
