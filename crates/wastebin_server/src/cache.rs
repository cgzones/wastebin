use std::fmt::Display;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use cached::{Cached, LruCache};

use crate::env;
use crate::errors::Error;

use wastebin_core::id::{self, Id};

/// Cache based on identifier and format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub id: Id,
    pub ext: Option<String>,
}

const MAX_EXTENSION_LEN: usize = 32;

/// Extension validity check.
///
/// Accepts ASCII alphanumerics, `.`, `_` and `-` up to [`MAX_EXTENSION_LEN`]
/// bytes. Syntect's syntax set contains dotted extensions such as `.env` and
/// `CMakeLists.txt`.
pub(crate) fn valid_extension(extension: &str) -> bool {
    extension.len() <= MAX_EXTENSION_LEN
        && extension.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
        })
}

/// Which representation of a paste a cached entry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Mode {
    /// Syntax-highlighted source view.
    Source,
    /// Markdown rendered to HTML.
    Rendered,
}

/// Cache slot: a paste identity paired with the representation it holds.
type Slot = (Key, Mode);

/// The LRU behind [`Cache`], absent when caching is disabled.
type Store = Option<Arc<Mutex<LruCache<Slot, Arc<String>>>>>;

/// Stores rendered HTML, shared so that cache hits are a refcount bump rather than a copy of the
/// whole document.
#[derive(Clone)]
pub(crate) struct Cache {
    /// [`None`] when caching is disabled, i.e. `WASTEBIN_CACHE_SIZE=0`.
    inner: Store,
}

impl Cache {
    /// Create a cache holding up to `size` rendered documents; [`None`] disables caching.
    pub fn new(size: Option<NonZeroUsize>) -> Result<Self, env::Error> {
        let Some(size) = size else {
            return Ok(Self { inner: None });
        };

        let cache = LruCache::builder().max_size(size.get()).build()?;

        Ok(Self {
            inner: Some(Arc::new(Mutex::new(cache))),
        })
    }

    pub fn put(&self, key: &Key, mode: Mode, value: Arc<String>) {
        let Some(inner) = &self.inner else {
            return;
        };

        inner
            .lock()
            .expect("getting lock")
            .cache_set((key.clone(), mode), value);
    }

    #[must_use]
    pub fn get(&self, key: &Key, mode: Mode) -> Option<Arc<String>> {
        self.inner
            .as_ref()?
            .lock()
            .expect("getting lock")
            .cache_get(&(key.clone(), mode))
            .map(Arc::clone)
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ext) = &self.ext {
            write!(f, "{}.{}", self.id, ext)
        } else {
            write!(f, "{}", self.id)
        }
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (id, ext) = match value.split_once('.') {
            None => (value.parse()?, None),
            Some((id, ext)) => {
                if !valid_extension(ext) {
                    return Err(Error::Id(id::Error::IllegalCharacters));
                }

                (id.parse().map_err(Error::Id)?, Some(ext.to_string()))
            }
        };

        Ok(Self { id, ext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key() {
        let key = Key::from_str("bJZCna").unwrap();
        assert_eq!(key.id.to_string(), "bJZCna");
        assert_eq!(key.id, Id::from(104_651_828_u32));
        assert_eq!(key.ext, None);

        let key = Key::from_str("sIiFec.rs").unwrap();
        assert_eq!(key.id.to_string(), "sIiFec");
        assert_eq!(key.id, 1_243_750_162_u32.into());
        assert_eq!(key.ext.unwrap(), "rs");

        assert!(Key::from_str("foo").is_err());
        assert!(Key::from_str("bar.rs").is_err());

        assert!(Key::from_str("sIiFec.").is_ok());
        assert!(Key::from_str("sIiFec.a-b_C9").is_ok());
        let key = Key::from_str("sIiFec.CMakeLists.txt").unwrap();
        assert_eq!(key.ext.as_deref(), Some("CMakeLists.txt"));
        assert!(Key::from_str("sIiFec.rs/js").is_err());
        assert!(Key::from_str("sIiFec.\"><img src=x>").is_err());
        assert!(Key::from_str(&format!("sIiFec.{}", "a".repeat(33))).is_err());
    }

    #[test]
    fn extension_validation() {
        assert!(valid_extension(""));
        assert!(valid_extension("rs"));
        assert!(valid_extension("a-b_C9"));
        assert!(valid_extension("rs.js"));
        assert!(valid_extension(".env.development.local"));
        assert!(valid_extension("CMakeLists.txt"));
        assert!(valid_extension(&"a".repeat(MAX_EXTENSION_LEN)));

        assert!(!valid_extension(&"a".repeat(MAX_EXTENSION_LEN + 1)));
        assert!(!valid_extension("\"><img src=x>"));
        assert!(!valid_extension("rs/js"));
        assert!(!valid_extension("r s"));
        assert!(!valid_extension("ü"));
    }

    #[test]
    fn zero_size_disables_caching() {
        let key = Key::from_str("bJZCna").unwrap();

        let cache = Cache::new(NonZeroUsize::new(1)).unwrap();
        cache.put(&key, Mode::Source, Arc::new(String::from("cached")));
        assert_eq!(
            cache.get(&key, Mode::Source).as_deref().map(String::as_str),
            Some("cached")
        );

        let cache = Cache::new(None).unwrap();
        cache.put(&key, Mode::Source, Arc::new(String::from("cached")));
        assert!(cache.get(&key, Mode::Source).is_none());
    }

    #[test]
    fn cache_key_url_path() {
        let key = Key {
            id: Id::from(0xffff_ffff_u32),
            ext: Some("txt".to_string()),
        };
        assert_eq!(key.to_string(), "+++++d.txt");

        let key = Key {
            id: Id::from(0xffff_ffff_u32),
            ext: None,
        };
        assert_eq!(key.to_string(), "+++++d");
    }
}
