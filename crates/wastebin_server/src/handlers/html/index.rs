use crate::{Highlighter, Page, handlers::extract::Theme};
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

/// GET handler for the index page.
#[must_use]
pub async fn get(
    State(page): State<Page>,
    State(highlighter): State<Highlighter>,
    theme: Option<Theme>,
) -> Index {
    Index {
        page,
        theme,
        highlighter,
    }
}

/// Index page displaying a form for paste insertion and a selection box for languages.
#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
pub(crate) struct Index {
    page: Page,
    theme: Option<Theme>,
    highlighter: Highlighter,
}
