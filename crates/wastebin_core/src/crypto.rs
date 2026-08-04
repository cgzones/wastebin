use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngExt;
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

static CONFIG: LazyLock<argon2::Config> = LazyLock::new(|| argon2::Config {
    variant: argon2::Variant::Argon2i,
    version: argon2::Version::Version13,
    mem_cost: 65536,
    time_cost: 10,
    lanes: 4,
    thread_mode: argon2::ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 32,
});

/// Shortest salt argon2 accepts. A shorter one makes every key derivation fail, so it is rejected
/// when the [`Salt`] is constructed rather than on the first encrypted paste.
pub const MIN_SALT_LEN: usize = 8;

/// Bounds how many key derivations run at once.
///
/// A derivation costs [`CONFIG`]`.mem_cost` — 64 MiB — for as long as it runs, and reading any
/// password-protected paste starts one before the ciphertext is even looked at, so a wrong
/// password costs the same as a right one. Without a bound, concurrent readers of a single
/// encrypted paste are a memory-exhaustion lever: the blocking pool alone would allow hundreds of
/// derivations, hence tens of gigabytes. The work is CPU- and memory-bound, so the machine's
/// parallelism is as much of it as can usefully proceed at once.
static DERIVATION_LIMIT: LazyLock<usize> = LazyLock::new(|| {
    std::thread::available_parallelism()
        .unwrap_or(NonZeroUsize::MIN)
        .get()
});

static DERIVATIONS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(*DERIVATION_LIMIT)));

/// Encryption or decryption errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to hash with argon2: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("salt is {0} bytes, expected at least {MIN_SALT_LEN}")]
    SaltTooShort(usize),
    #[error("failed to encrypt")]
    ChaCha20Poly1305Encrypt,
    #[error("failed to decrypt")]
    ChaCha20Poly1305Decrypt,
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("key derivation limiter is gone")]
    DerivationLimiterGone,
}

/// Encrypted data item.
pub(crate) struct Encrypted {
    /// Encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: XNonce,
}

pub struct Password(Vec<u8>);

/// Salt mixed into the argon2 key derivation. Configured once and passed in, so key derivation
/// does not depend on process-wide state.
#[derive(Clone)]
pub struct Salt(Arc<str>);

/// Plaintext bytes to be encrypted.
pub(crate) struct Plaintext(Vec<u8>);

impl From<Vec<u8>> for Password {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl TryFrom<String> for Salt {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        if value.len() < MIN_SALT_LEN {
            return Err(Error::SaltTooShort(value.len()));
        }

        Ok(Self(Arc::from(value)))
    }
}

impl From<Vec<u8>> for Plaintext {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

fn cipher_from(password: &[u8], salt: &Salt) -> Result<XChaCha20Poly1305, Error> {
    let key = argon2::hash_raw(password, salt.0.as_bytes(), &CONFIG)?;
    let key = Key::try_from(key.as_slice()).map_err(|_| Error::ChaCha20Poly1305Encrypt)?;
    Ok(XChaCha20Poly1305::new(&key))
}

/// Wait for a key-derivation slot.
///
/// The permit is owned so it can move into the blocking closure and cover the derivation itself:
/// a caller that goes away must not release the slot while its work is still running.
async fn derivation_permit() -> Result<tokio::sync::OwnedSemaphorePermit, Error> {
    Arc::clone(&DERIVATIONS)
        .acquire_owned()
        .await
        .map_err(|_| Error::DerivationLimiterGone)
}

impl Plaintext {
    /// Consume and encrypt plaintext into [`Encrypted`] using `password`.
    pub async fn encrypt(self, password: Password, salt: Salt) -> Result<Encrypted, Error> {
        let permit = derivation_permit().await?;

        spawn_blocking(move || {
            let _permit = permit;
            let cipher = cipher_from(&password.0, &salt)?;
            let nonce = XNonce::from(rand::rng().random::<[u8; 24]>());
            let ciphertext = cipher
                .encrypt(&nonce, self.0.as_ref())
                .map_err(|_| Error::ChaCha20Poly1305Encrypt)?;

            Ok(Encrypted::new(ciphertext, nonce))
        })
        .await?
    }
}

impl Encrypted {
    /// Create new [`Encrypted`] item from `ciphertext` and `nonce`.
    #[must_use]
    pub fn new(ciphertext: Vec<u8>, nonce: XNonce) -> Self {
        Self { ciphertext, nonce }
    }

    /// Decrypt into bytes using `password`.
    pub async fn decrypt(self, password: Password, salt: Salt) -> Result<Vec<u8>, Error> {
        let permit = derivation_permit().await?;

        spawn_blocking(move || {
            let _permit = permit;
            let cipher = cipher_from(&password.0, &salt)?;
            let plaintext = cipher
                .decrypt(&self.nonce, self.ciphertext.as_ref())
                .map_err(|_| Error::ChaCha20Poly1305Decrypt)?;
            Ok(plaintext)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let salt = Salt::try_from("somesalt".to_string()).unwrap();
        let password = "secret".to_string();
        let plaintext = "encrypt me".to_string();
        let encrypted = Plaintext::from(plaintext.as_bytes().to_vec())
            .encrypt(Password::from(password.as_bytes().to_vec()), salt.clone())
            .await
            .unwrap();
        let decrypted = encrypted
            .decrypt(Password::from(password.as_bytes().to_vec()), salt)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn rejects_short_salts() {
        assert!(matches!(
            Salt::try_from("short".to_string()),
            Err(Error::SaltTooShort(5))
        ));

        // The shortest salt argon2 accepts.
        assert!(Salt::try_from("a".repeat(MIN_SALT_LEN)).is_ok());
    }

    /// The limiter is process-wide, so this asserts only invariants that other tests running in
    /// parallel cannot perturb: derivations still complete when more are asked for than the limit
    /// allows, and no path ever hands back more permits than it took.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_derivations_are_bounded() {
        assert!(*DERIVATION_LIMIT >= 1, "limiter must allow progress");

        let salt = Salt::try_from("somesalt".to_string()).unwrap();
        let batch = (0..*DERIVATION_LIMIT * 2)
            .map(|_| {
                let salt = salt.clone();

                tokio::spawn(async move {
                    Plaintext::from(b"encrypt me".to_vec())
                        .encrypt(Password::from(b"secret".to_vec()), salt)
                        .await
                })
            })
            .collect::<Vec<_>>();

        for task in batch {
            // A leaked permit would deadlock this instead of failing it.
            task.await.unwrap().unwrap();
        }

        assert!(
            DERIVATIONS.available_permits() <= *DERIVATION_LIMIT,
            "released more permits than were taken"
        );
    }

    #[tokio::test]
    async fn different_salts_do_not_interoperate() {
        let password = || Password::from("secret".as_bytes().to_vec());
        let encrypted = Plaintext::from("encrypt me".as_bytes().to_vec())
            .encrypt(
                password(),
                Salt::try_from("first-salt".to_string()).unwrap(),
            )
            .await
            .unwrap();

        assert!(
            encrypted
                .decrypt(
                    password(),
                    Salt::try_from("second-salt".to_string()).unwrap()
                )
                .await
                .is_err()
        );
    }
}
