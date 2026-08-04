use axum::extract::{Path, State};
use axum::response::Redirect;

use crate::handlers::extract::{Accepts, RequestOrigin, Theme, Uids};
use crate::handlers::html::{ErrorResponse, make_error};
use crate::i18n::Lang;
use crate::{AppState, Page};

use super::common_delete;

#[expect(clippy::too_many_arguments)]
pub async fn delete(
    Path(id): Path<String>,
    State(appstate): State<AppState>,
    State(page): State<Page>,
    uids: Option<Uids>,
    theme: Theme,
    lang: Lang,
    origin: RequestOrigin,
    accepts: Accepts,
) -> Result<Redirect, ErrorResponse> {
    async {
        if origin.is_cross_site(&page.base_url) {
            return Err(crate::Error::CrossSite);
        }

        let Some(Uids(uids)) = uids else {
            return Err(crate::Error::MissingUid);
        };

        let id = id.parse()?;
        common_delete(&appstate, id, &uids).await?;
        Ok(Redirect::to("/"))
    }
    .await
    .map_err(|err| make_error(err, page, theme, lang, accepts))
}

#[cfg(test)]
mod tests {
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

    #[tokio::test]
    async fn delete_via_link() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        let res = client.post(&format!("/delete/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn delete_without_uid_cookie_is_forbidden() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        let res = client.post(&format!("/delete/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn cross_site_delete_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        // The uid cookie is present and would otherwise authorize this.
        let res = client
            .post(&format!("/delete/{id}"))
            .header(http::header::ORIGIN, "https://evil.example.com")
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK, "paste was deleted anyway");

        // The site's own form still works.
        let res = client
            .post(&format!("/delete/{id}"))
            .header(http::header::ORIGIN, client.origin())
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        Ok(())
    }
}
