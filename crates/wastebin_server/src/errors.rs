use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;

use crate::i18n::Lang;
use wastebin_core::{db, id};

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("highlighting error: {0}")]
    SyntaxHighlighting(#[from] wastebin_highlight::Error),
    #[error("could not generate QR code: {0}")]
    QrCode(#[from] qrcodegen::DataTooLong),
    #[error("could not parse URL: {0}")]
    UrlParsing(#[from] url::ParseError),
    #[error("database error: {0}")]
    Database(#[from] db::Error),
    #[error("id error: {0}")]
    Id(#[from] id::Error),
    #[error("malformed form data")]
    MalformedForm,
    #[error("extension names no known syntax")]
    InvalidExtension,
    #[error("payload exceeded limit")]
    PayloadTooLarge,
    #[error("unsupported media type")]
    UnsupportedMediaType,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("missing or invalid uid cookie")]
    MissingUid,
    #[error("cross-site request")]
    CrossSite,
    #[error("rate-limit hit")]
    RateLimit,
    #[error("expires too far in the future")]
    TooLongExpires,
    /// The request that asked for this render is gone, so the answer is never sent anywhere.
    #[error("render abandoned by its caller")]
    Abandoned,
    #[error("renderer is gone")]
    RendererGone,
    /// No route matched the request path.
    #[error("no such route")]
    RouteNotFound,
}

impl Error {
    /// Translation key for the message the client is shown.
    ///
    /// A variant's `Display` can carry a sqlite message, a panic payload or a syntect failure —
    /// detail the client never asked for, cannot act on, and that describes the server's
    /// internals. Every variant maps to a fixed key instead; the detail goes to the log.
    pub(crate) fn message_key(&self) -> &'static str {
        match self {
            Error::Database(db::Error::NotFound) | Error::RouteNotFound => "error.not_found",
            Error::Database(db::Error::Delete) | Error::MissingUid => "error.forbidden",
            Error::CrossSite => "error.cross_site",
            Error::Database(db::Error::WrongPassword) => "error.wrong_password",
            Error::Database(db::Error::NoPassword) => "error.no_password",
            Error::Id(_) | Error::UrlParsing(_) => "error.invalid_id",
            Error::InvalidExtension => "error.invalid_extension",
            Error::RateLimit => "error.rate_limit",
            Error::TooLongExpires => "error.too_long_expires",
            Error::MalformedForm => "error.malformed_form",
            Error::PayloadTooLarge => "error.payload_too_large",
            Error::UnsupportedMediaType => "error.unsupported_media_type",
            Error::MethodNotAllowed => "error.method_not_allowed",
            Error::SyntaxHighlighting(wastebin_highlight::Error::TooDeeplyNested(_)) => {
                "error.too_deeply_nested"
            }
            Error::Join(_)
            | Error::QrCode(_)
            | Error::Database(_)
            | Error::Abandoned
            | Error::RendererGone
            | Error::SyntaxHighlighting(_) => "error.internal",
        }
    }

    /// Record the internal detail, which never reaches the client.
    pub(crate) fn log(&self) {
        if StatusCode::from(self).is_server_error() {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::debug!(error = %self, "request rejected");
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonError {
    pub message: String,
}

/// Response carrying a status code and the error message as JSON.
pub(crate) type JsonErrorResponse = (StatusCode, Json<JsonError>);

impl From<Error> for StatusCode {
    fn from(err: Error) -> Self {
        Self::from(&err)
    }
}

impl From<&Error> for StatusCode {
    fn from(err: &Error) -> Self {
        match err {
            Error::Database(db::Error::NotFound) | Error::RouteNotFound => StatusCode::NOT_FOUND,
            Error::Database(db::Error::Delete | db::Error::WrongPassword)
            | Error::MissingUid
            | Error::CrossSite => StatusCode::FORBIDDEN,
            Error::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            Error::Database(db::Error::NoPassword)
            | Error::Id(_)
            | Error::UrlParsing(_)
            | Error::InvalidExtension
            | Error::TooLongExpires
            | Error::SyntaxHighlighting(wastebin_highlight::Error::TooDeeplyNested(_)) => {
                StatusCode::BAD_REQUEST
            }
            Error::MalformedForm => StatusCode::UNPROCESSABLE_ENTITY,
            Error::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Error::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Error::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Error::Join(_)
            | Error::QrCode(_)
            | Error::Database(_)
            | Error::Abandoned
            | Error::RendererGone
            | Error::SyntaxHighlighting(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<Error> for JsonErrorResponse {
    fn from(err: Error) -> Self {
        err.log();

        // The API is not localised, so the client always gets the English wording — but the same
        // fixed set of messages as the rendered page, never the internal detail.
        let payload = Json::from(JsonError {
            message: Lang::En.t(err.message_key()).to_owned(),
        });

        (err.into(), payload)
    }
}
