use std::fmt::Display;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use cached::{Cached, LruCache};

use crate::env;
use crate::errors::Error;

use wastebin_core::id::Id;

/// Cache based on identifier and format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub id: Id,
    pub ext: Option<String>,
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

/// Stores rendered HTML, shared so that cache hits are a refcount bump rather than a copy of the
/// whole document.
#[derive(Clone)]
pub(crate) struct Cache {
    inner: Arc<Mutex<LruCache<Slot, Arc<str>>>>,
}

impl Cache {
    pub fn new(size: NonZeroUsize) -> Result<Self, env::Error> {
        let cache = LruCache::builder().max_size(size.into()).build()?;
        let inner = Arc::new(Mutex::new(cache));

        Ok(Self { inner })
    }

    pub fn put(&self, key: &Key, mode: Mode, value: Arc<str>) {
        self.inner
            .lock()
            .expect("getting lock")
            .cache_set((key.clone(), mode), value);
    }

    #[must_use]
    pub fn get(&self, key: &Key, mode: Mode) -> Option<Arc<str>> {
        self.inner
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
            Some((id, ext)) => (id.parse().map_err(Error::Id)?, Some(ext.to_string())),
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
