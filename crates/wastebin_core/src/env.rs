use crate::crypto;

/// Names of environment variables.
pub mod vars {
    /// Address and port the server binds to.
    pub const ADDRESS_PORT: &str = "WASTEBIN_ADDRESS_PORT";
    /// Base URL to use for the QR code link.
    pub const BASE_URL: &str = "WASTEBIN_BASE_URL";
    /// Number of cached items.
    pub const CACHE_SIZE: &str = "WASTEBIN_CACHE_SIZE";
    /// Path to the database file.
    pub const DATABASE_PATH: &str = "WASTEBIN_DATABASE_PATH";
    /// Time before a request times out.
    pub const HTTP_TIMEOUT: &str = "WASTEBIN_HTTP_TIMEOUT";
    /// Maximum body size.
    pub const MAX_BODY_SIZE: &str = "WASTEBIN_MAX_BODY_SIZE";
    /// Password salt for encryption.
    pub const PASSWORD_SALT: &str = "WASTEBIN_PASSWORD_SALT";
    /// Expirations list.
    pub const PASTE_EXPIRATIONS: &str = "WASTEBIN_PASTE_EXPIRATIONS";
    /// Maximum expiration time.
    pub const PASTE_MAX_EXPIRATION: &str = "WASTEBIN_PASTE_MAX_EXPIRATION";
    /// Signing key for signed cookie store.
    pub const SIGNING_KEY: &str = "WASTEBIN_SIGNING_KEY";
    /// Theme to use.
    pub const THEME: &str = "WASTEBIN_THEME";
    /// Title.
    pub const TITLE: &str = "WASTEBIN_TITLE";
    /// Unix socket path the server binds to.
    pub const SOCKET_PATH: &str = "WASTEBIN_UNIX_SOCKET_PATH";
    /// Insert rate-limit.
    pub const RATELIMIT_INSERT: &str = "WASTEBIN_RATELIMIT_INSERT";
    /// Delete rate-limit.
    pub const RATELIMIT_DELETE: &str = "WASTEBIN_RATELIMIT_DELETE";
}

/// Read the argon2 salt from the environment, falling back to a fixed default.
///
/// Call once at startup and pass the result to [`crate::db::Database::new`], so the value is
/// fixed for the process rather than read lazily on the first encrypted paste. A salt shorter
/// than [`crypto::MIN_SALT_LEN`] is rejected here, since argon2 would otherwise reject it on
/// every encrypted paste at runtime.
pub fn password_hash_salt() -> Result<crypto::Salt, crypto::Error> {
    std::env::var(vars::PASSWORD_SALT)
        .unwrap_or_else(|_| {
            tracing::info!(
                "Using default salt for encryption. Consider setting `{}`.",
                vars::PASSWORD_SALT
            );

            "somesalt".to_string()
        })
        .try_into()
}
