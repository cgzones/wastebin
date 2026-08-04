use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZero, NonZeroU32, NonZeroU64, NonZeroUsize, ParseIntError, TryFromIntError};
use std::path::PathBuf;
use std::time::Duration;

use axum_extra::extract::cookie::Key;

use wastebin_core::env::var;
use wastebin_core::env::vars::{
    self, ADDRESS_PORT, BASE_URL, CACHE_SIZE, HTTP_TIMEOUT, MAX_BODY_SIZE, PASTE_EXPIRATIONS,
    PASTE_MAX_EXPIRATION, RATELIMIT_DELETE, RATELIMIT_INSERT, SIGNING_KEY,
};
use wastebin_core::{db, expiration, expiration::Expiration};
use wastebin_highlight::{Theme, theme::ParseThemeNameError};

pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("failed to construct cache")]
    CacheConstruction(#[from] cached::BuildError),
    #[error("failed to parse {CACHE_SIZE}, expected number of elements: {0}")]
    CacheSize(ParseIntError),
    #[error(transparent)]
    Env(#[from] wastebin_core::env::Error),
    #[error("failed to parse {MAX_BODY_SIZE}, expected number of bytes: {0}")]
    MaxBodySize(ParseIntError),
    #[error("failed to parse {ADDRESS_PORT}, expected `host:port`")]
    AddressPort,
    #[error("failed to parse {BASE_URL}: {0}")]
    BaseUrl(String),
    #[error("failed to generate key from {SIGNING_KEY}: {0}")]
    SigningKey(String),
    #[error("failed to parse {HTTP_TIMEOUT}: {0}")]
    HttpTimeout(ParseIntError),
    #[error("failed to parse {PASTE_EXPIRATIONS}: {0}")]
    ParsePasteExpiration(#[from] expiration::Error),
    #[error("failed to parse theme name")]
    ParseTheme(#[from] ParseThemeNameError),
    #[error("failed to parse {PASTE_MAX_EXPIRATION}: {0}")]
    ParsePasteMaxExpiration(expiration::Error),
    #[error("failed to parse {PASTE_MAX_EXPIRATION}: {0}")]
    PasteMaxExpirationOverflow(TryFromIntError),
    #[error(
        "{PASTE_EXPIRATIONS} entry `{0}` is incompatible with {PASTE_MAX_EXPIRATION}: entries must be non-zero and at most the maximum"
    )]
    ExpirationExceedsMax(expiration::Expiration),
    #[error("binding to both TCP and Unix socket is not possible")]
    BothListeners,
    #[error("failed to parse {RATELIMIT_INSERT}: {0}")]
    RatelimitInsert(ParseIntError),
    #[error("failed to parse {RATELIMIT_DELETE}: {0}")]
    RatelimitDelete(ParseIntError),
}

pub(crate) enum SocketType {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Display for SocketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketType::Tcp(addr) => {
                write!(f, "{addr}")
            }
            SocketType::Unix(path) => {
                write!(f, "{}", path.display())
            }
        }
    }
}

pub fn title() -> Result<String, Error> {
    Ok(var(vars::TITLE)?.unwrap_or_else(|| "wastebin".to_string()))
}

pub fn theme() -> Result<Theme, Error> {
    var(vars::THEME)?.map_or(Ok(Theme::Ayu), |value| Ok(value.parse()?))
}

pub fn cache_size() -> Result<NonZeroUsize, Error> {
    var(vars::CACHE_SIZE)?.map_or_else(
        || Ok(NonZeroUsize::new(128).expect("128 is non-zero")),
        |value| value.parse::<NonZeroUsize>().map_err(Error::CacheSize),
    )
}

pub fn database_method() -> Result<db::Open, Error> {
    Ok(var(vars::DATABASE_PATH)?
        .map_or(db::Open::Memory, |path| db::Open::Path(PathBuf::from(path))))
}

pub fn signing_key() -> Result<Key, Error> {
    var(vars::SIGNING_KEY)?.map_or_else(
        || Ok(Key::generate()),
        |value| Key::try_from(value.as_bytes()).map_err(|err| Error::SigningKey(err.to_string())),
    )
}

pub fn socket_type() -> Result<SocketType, Error> {
    match (var(vars::ADDRESS_PORT)?, var(vars::SOCKET_PATH)?) {
        (Some(_), Some(_)) => Err(Error::BothListeners),
        (Some(value), None) => {
            let addr: SocketAddr = value.parse().map_err(|_| Error::AddressPort)?;
            Ok(SocketType::Tcp(addr))
        }
        (None, Some(value)) => Ok(SocketType::Unix(value.into())),
        (None, None) => {
            let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8088);
            Ok(SocketType::Tcp(addr))
        }
    }
}

pub fn max_body_size() -> Result<usize, Error> {
    var(vars::MAX_BODY_SIZE)?.map_or(Ok(1024 * 1024), |value| {
        // A zero body limit would reject every paste, so treat it as a misconfiguration.
        value
            .parse::<NonZeroUsize>()
            .map(NonZeroUsize::get)
            .map_err(Error::MaxBodySize)
    })
}

/// Read base URL either from the environment variable or fallback to the hostname.
pub fn base_url() -> Result<url::Url, Error> {
    if let Some(value) = var(vars::BASE_URL)? {
        return url::Url::parse(&value).map_err(|err| Error::BaseUrl(err.to_string()));
    }

    let hostname =
        hostname::get().map_err(|err| Error::BaseUrl(format!("failed to get hostname: {err}")))?;

    url::Url::parse(&format!("https://{}", hostname.to_string_lossy()))
        .map_err(|err| Error::BaseUrl(err.to_string()))
}

pub fn http_timeout() -> Result<Duration, Error> {
    var(vars::HTTP_TIMEOUT)?.map_or(Ok(DEFAULT_HTTP_TIMEOUT), |value| {
        // A zero timeout would answer every request with 408, so treat it as a misconfiguration.
        value
            .parse::<NonZeroU64>()
            .map(|secs| Duration::from_secs(secs.get()))
            .map_err(Error::HttpTimeout)
    })
}

/// Parse [`expiration::ExpirationSet`] from environment or return default.
pub fn expiration_set() -> Result<expiration::ExpirationSet, Error> {
    let value = var(vars::PASTE_EXPIRATIONS)?;

    Ok(value
        .as_deref()
        .unwrap_or("0=d,10m,1h,1d,1w,1M,1y")
        .parse::<expiration::ExpirationSet>()?)
}

pub fn max_expiration() -> Result<Option<NonZeroU32>, Error> {
    var(vars::PASTE_MAX_EXPIRATION)?
        .map(|value| {
            value
                .parse::<Expiration>()
                .map_err(Error::ParsePasteMaxExpiration)
                .and_then(|exp| {
                    u32::try_from(exp.duration.as_secs()).map_err(Error::PasteMaxExpirationOverflow)
                })
        })
        .transpose()
        .map(|op| op.and_then(NonZero::new))
}

/// Ensure the configured expirations are all reachable once a maximum is enforced.
///
/// A zero-duration ("never") entry, or one exceeding `max_expiration`, would be offered by the
/// form yet unconditionally rejected by `insert::common_insert`, so it is treated as a startup
/// misconfiguration rather than silently dropped.
pub(crate) fn validate_expirations(
    expirations: &expiration::ExpirationSet,
    max_expiration: Option<NonZeroU32>,
) -> Result<(), Error> {
    let Some(max_expiration) = max_expiration else {
        return Ok(());
    };

    let max_secs = u64::from(max_expiration.get());

    for expiration in expirations.values() {
        let secs = expiration.duration.as_secs();

        if secs == 0 || secs > max_secs {
            return Err(Error::ExpirationExceedsMax(*expiration));
        }
    }

    Ok(())
}

/// Parse a per-second rate limit from `name`, mapping parse failures through `err`.
///
/// A zero limit is documented as disabling the limiter, hence [`NonZero::new`] rather than an
/// error.
fn ratelimit(
    name: &'static str,
    err: fn(ParseIntError) -> Error,
) -> Result<Option<NonZeroU32>, Error> {
    var(name)?
        .map(|value| value.parse::<u32>().map_err(err))
        .transpose()
        .map(|op| op.and_then(NonZero::new))
}

pub fn ratelimit_insert() -> Result<Option<NonZeroU32>, Error> {
    ratelimit(vars::RATELIMIT_INSERT, Error::RatelimitInsert)
}

pub fn ratelimit_delete() -> Result<Option<NonZeroU32>, Error> {
    ratelimit(vars::RATELIMIT_DELETE, Error::RatelimitDelete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_expirations_rejects_never_with_max() {
        let expirations = "0=d,1h".parse::<expiration::ExpirationSet>().unwrap();
        let max = NonZeroU32::new(3600).unwrap();

        assert!(matches!(
            validate_expirations(&expirations, Some(max)),
            Err(Error::ExpirationExceedsMax(_))
        ));
    }

    #[test]
    fn validate_expirations_rejects_entry_above_max() {
        let expirations = "1h,1d".parse::<expiration::ExpirationSet>().unwrap();
        let max = NonZeroU32::new(3600).unwrap();

        assert!(matches!(
            validate_expirations(&expirations, Some(max)),
            Err(Error::ExpirationExceedsMax(_))
        ));
    }

    #[test]
    fn validate_expirations_accepts_set_within_max() {
        let expirations = "10m,1h=d".parse::<expiration::ExpirationSet>().unwrap();
        let max = NonZeroU32::new(3600).unwrap();

        assert!(validate_expirations(&expirations, Some(max)).is_ok());
    }

    #[test]
    fn validate_expirations_accepts_anything_without_max() {
        let expirations = "0=d,1h,1y".parse::<expiration::ExpirationSet>().unwrap();

        assert!(validate_expirations(&expirations, None).is_ok());
    }
}
