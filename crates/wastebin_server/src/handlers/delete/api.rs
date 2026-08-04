use axum::extract::{Path, State};

use crate::AppState;
use crate::errors::{Error, JsonErrorResponse};
use crate::handlers::extract::Uids;

use super::common_delete;

pub async fn delete(
    Path(id): Path<String>,
    State(appstate): State<AppState>,
    uids: Option<Uids>,
) -> Result<(), JsonErrorResponse> {
    let Some(Uids(uids)) = uids else {
        return Err(Error::MissingUid.into());
    };

    let id = id.parse().map_err(Error::Id)?;
    common_delete(&appstate, id, &uids).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::Ratelimiter;
    use crate::handlers::insert::form::Entry;
    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

    #[tokio::test]
    async fn delete() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        let res = client.delete(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn delete_nonexistent_is_forbidden() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(true)).await;

        // Establish a uid cookie so this exercises the ownership check rather than the
        // missing-cookie path.
        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let res = client.delete("/aaaaaa").send().await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    #[tokio::test]
    async fn bogus_deletes_do_not_consume_ratelimit_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let limiter = Arc::new(
            Ratelimiter::builder(1)
                .max_tokens(1)
                .initial_available(1)
                .build()?,
        );
        let client = Client::new_with_ratelimit_delete(StoreCookies(true), Some(limiter)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        // The bucket only holds a single token; if these bogus deletes drained it, the real
        // delete below would be wrongly rejected as rate-limited.
        for _ in 0..5 {
            let res = client.delete("/aaaaaa").send().await?;
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
        }

        let res = client.delete(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn exhausted_ratelimit_prevents_deletion() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = Arc::new(
            Ratelimiter::builder(1)
                .max_tokens(1)
                .initial_available(1)
                .build()?,
        );
        let client = Client::new_with_ratelimit_delete(StoreCookies(true), Some(limiter)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?;
        let first_id = location.replace('/', "");

        let res = client.post_form().form(&Entry::default()).send().await?;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str()?;
        let second_id = location.replace('/', "");

        // Consumes the single available token.
        let res = client.delete(&format!("/{first_id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        let res = client.get(&format!("/{first_id}")).send().await?;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // No sleep here: the bucket must still be empty for this to hit the limiter.
        let res = client.delete(&format!("/{second_id}")).send().await?;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        // The paste must survive: a rate-limited request must not have deleted it anyway.
        let res = client.get(&format!("/{second_id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn delete_without_uid_cookie_is_forbidden() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.post_form().form(&Entry::default()).send().await?;
        let location = res.headers().get("location").unwrap().to_str()?;
        let id = location.replace('/', "");

        let res = client.delete(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // The paste must survive the rejected deletion.
        let res = client.get(&format!("/{id}")).send().await?;
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }
}
