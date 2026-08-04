use axum::extract::State;
use axum::http::StatusCode;

use wastebin_core::db::Database;

/// Answer a liveness probe by round-tripping a query through the database actor.
///
/// The body is empty: a probe reads the status and nothing else, and an unauthenticated route
/// should not volunteer detail about the server. The failure goes to the log instead.
pub async fn get(State(db): State<Database>) -> StatusCode {
    match db.ping().await {
        Ok(()) => StatusCode::OK,
        Err(err) => {
            tracing::error!("health check failed: {err}");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use axum::http::StatusCode as AxumStatus;
    use wastebin_core::db::{self, Database};

    use crate::test_helpers::{Client, StoreCookies};
    use reqwest::StatusCode;

    #[tokio::test]
    async fn health_reports_ok() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(StoreCookies(false)).await;

        let res = client.get("/health").send().await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().await?.is_empty());

        Ok(())
    }

    /// A process whose database actor died answers every paste request with an error forever, so
    /// the probe has to fail rather than keep it in rotation.
    #[tokio::test]
    async fn health_reports_a_gone_backend() {
        let (db, handler) =
            Database::new(db::Open::Memory, "testsalt".to_string().try_into().unwrap()).unwrap();

        // The future owns the handler and therefore the receiver; dropping it closes the channel.
        drop(handler);

        assert_eq!(super::get(State(db)).await, AxumStatus::SERVICE_UNAVAILABLE);
    }
}
