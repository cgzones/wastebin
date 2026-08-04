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

/// Cache slot: a paste, the syntax its source view was rendered with, and the representation held.
///
/// The syntax rather than the extension that named it, since that is what the render actually
/// depended on; [`None`] for a rendered document, which depended on neither.
type Slot = (Id, Option<wastebin_highlight::SyntaxKey>, Mode);

/// The LRU behind [`Cache`], absent when caching is disabled.
type Store = Option<Arc<Mutex<LruCache<Slot, Arc<str>>>>>;

/// Stores rendered HTML, shared so that cache hits are a refcount bump rather than a copy of the
/// whole document.
#[derive(Clone)]
pub(crate) struct Cache {
    /// [`None`] when caching is disabled, i.e. `WASTEBIN_CACHE_SIZE=0`.
    inner: Store,
    /// Ceiling on the bytes held across all entries.
    max_bytes: usize,
    /// Decides which extensions name a syntax of their own; see [`Cache::slot`].
    highlighter: Arc<wastebin_highlight::Highlighter>,
}

impl Cache {
    /// Create a cache holding up to `size` rendered documents totalling at most `max_bytes`;
    /// a `size` of [`None`] disables caching.
    pub fn new(
        size: Option<NonZeroUsize>,
        max_bytes: usize,
        highlighter: Arc<wastebin_highlight::Highlighter>,
    ) -> Result<Self, env::Error> {
        let Some(size) = size else {
            return Ok(Self {
                inner: None,
                max_bytes,
                highlighter,
            });
        };

        let cache = LruCache::builder().max_size(size.get()).build()?;

        Ok(Self {
            inner: Some(Arc::new(Mutex::new(cache))),
            max_bytes,
            highlighter,
        })
    }

    /// Build the slot `key` occupies.
    ///
    /// Keyed on the syntax the extension resolves to, not on the extension itself, because that is
    /// all the source view's output ever depended on. Every spelling of one syntax therefore shares
    /// a slot — `md`, `markdown` and `mdown`, and equally the several hundred extensions that name
    /// no syntax and so all render as plain text. Keeping them apart would let a single paste
    /// occupy the whole cache: the extension is caller-supplied and unbounded in variety, so
    /// `/{id}.a`, `/{id}.b`, … would each be a miss, a fresh render and an eviction.
    ///
    /// A rendered document does not depend on the extension at all — `markdown::render` is never
    /// told one — so it carries no syntax here.
    fn slot(&self, key: &Key, mode: Mode) -> Slot {
        let syntax = match mode {
            Mode::Rendered => None,
            Mode::Source => Some(self.highlighter.syntax_key(key.ext.as_deref())),
        };

        (key.id, syntax, mode)
    }

    pub fn put(&self, key: &Key, mode: Mode, value: Arc<str>) {
        let Some(inner) = &self.inner else {
            return;
        };

        // Resolved before taking the lock: `slot` walks the syntax set, which is far more work
        // than the lookup it feeds and would otherwise stretch a process-wide critical section
        // every source view passes through.
        let slot = self.slot(key, mode);

        let mut cache = inner.lock().expect("getting lock");
        cache.cache_set(slot, value);

        // Entries are bounded by count as well, but a rendered document has no size limit of its
        // own: a paste of newlines expands into tens of megabytes of line markup, and a hundred
        // of those would be gigabytes resident. Drop the least recently used until the total
        // fits — including, if it alone is too large, the entry just inserted.
        //
        // Summed once and then kept in step by subtracting what each eviction gave back: re-summing
        // per round walked every entry again, so a large insert that evicted many of them cost a
        // pass over the cache for each one.
        let mut total = cached_bytes(&cache);

        while total > self.max_bytes {
            let Some(oldest) = cache.key_order().last().copied() else {
                break;
            };

            let freed = cache.cache_remove(&oldest).map_or(0, |html| html.len());
            total = total.saturating_sub(freed);
        }
    }

    #[must_use]
    pub fn get(&self, key: &Key, mode: Mode) -> Option<Arc<str>> {
        let inner = self.inner.as_ref()?;

        // Resolved before the lock, as in `put`: the receiver of `cache_get` — and so `.lock()` —
        // is evaluated before its argument, which would put the syntax walk inside the section.
        let slot = self.slot(key, mode);

        inner
            .lock()
            .expect("getting lock")
            .cache_get(&slot)
            .map(Arc::clone)
    }
}

/// Bytes currently held by the cache.
///
/// Entry counts stay small, so summing beats keeping a running total in step with every insert,
/// eviction and overwrite.
fn cached_bytes(cache: &LruCache<Slot, Arc<str>>) -> usize {
    cache.value_order().iter().map(|html| html.len()).sum()
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

    fn test_cache(size: Option<NonZeroUsize>, max_bytes: usize) -> Cache {
        Cache::new(
            size,
            max_bytes,
            Arc::new(wastebin_highlight::Highlighter::default()),
        )
        .unwrap()
    }

    #[test]
    fn zero_size_disables_caching() {
        let key = Key::from_str("bJZCna").unwrap();

        let cache = test_cache(NonZeroUsize::new(1), 1024);
        cache.put(&key, Mode::Source, Arc::from("cached"));
        assert_eq!(cache.get(&key, Mode::Source).as_deref(), Some("cached"));

        let cache = test_cache(None, 1024);
        cache.put(&key, Mode::Source, Arc::from("cached"));
        assert!(cache.get(&key, Mode::Source).is_none());
    }

    #[test]
    fn total_size_stays_within_the_byte_budget() {
        let cache = test_cache(NonZeroUsize::new(128), 1000);
        let value: Arc<str> = Arc::from("x".repeat(300).as_str());

        // Ten entries of 300 bytes are well within the entry count but far past the budget.
        for n in 0..10u32 {
            let key = Key {
                id: Id::from(n),
                ext: None,
            };
            cache.put(&key, Mode::Source, Arc::clone(&value));
        }

        let held = {
            let inner = cache.inner.as_ref().unwrap().lock().unwrap();
            cached_bytes(&inner)
        };
        assert!(held <= 1000, "cache held {held} bytes");

        // The most recent insert survives; the oldest were dropped.
        let newest = Key {
            id: Id::from(9u32),
            ext: None,
        };
        assert!(cache.get(&newest, Mode::Source).is_some());
        let oldest = Key {
            id: Id::from(0u32),
            ext: None,
        };
        assert!(cache.get(&oldest, Mode::Source).is_none());
    }

    /// Eviction stops as soon as the total fits, so an insert that overshoots the budget by one
    /// entry drops one entry — not the whole cache.
    ///
    /// The budget test above cannot see this: it overshoots repeatedly, so a cache that wipes
    /// itself still ends up holding the newest entry and missing the oldest, which is exactly what
    /// it asserts. Over-eviction is free of any symptom except the hit rate.
    #[test]
    fn eviction_stops_once_the_total_fits() {
        let cache = test_cache(NonZeroUsize::new(128), 1000);
        let value: Arc<str> = Arc::from("x".repeat(300).as_str());

        // Four entries are 1200 bytes against a 1000-byte budget: dropping the oldest leaves 900,
        // and the other three have to survive.
        for n in 0..4u32 {
            let key = Key {
                id: Id::from(n),
                ext: None,
            };
            cache.put(&key, Mode::Source, Arc::clone(&value));
        }

        let held = (1..4u32)
            .filter(|n| {
                let key = Key {
                    id: Id::from(*n),
                    ext: None,
                };
                cache.get(&key, Mode::Source).is_some()
            })
            .count();

        assert_eq!(
            held,
            3,
            "eviction ran past the budget and dropped {} extra",
            3 - held
        );
    }

    #[test]
    fn an_entry_larger_than_the_budget_is_not_kept() {
        let cache = test_cache(NonZeroUsize::new(128), 100);
        let key = Key::from_str("bJZCna").unwrap();

        cache.put(&key, Mode::Source, Arc::from("x".repeat(500).as_str()));
        assert!(cache.get(&key, Mode::Source).is_none());
    }

    #[test]
    fn unknown_extensions_share_one_slot() {
        let cache = test_cache(NonZeroUsize::new(128), 1024);
        let id = Id::from(104_651_828_u32);

        let stored = Key {
            id,
            ext: Some("zzz-not-a-syntax".to_string()),
        };
        cache.put(&stored, Mode::Source, Arc::from("plain"));

        // A different unknown extension, and no extension at all, render identically and so must
        // hit the same entry rather than each taking a slot of their own.
        for ext in [None, Some("also-not-a-syntax".to_string())] {
            let probe = Key { id, ext };
            assert_eq!(cache.get(&probe, Mode::Source).as_deref(), Some("plain"));
        }

        // A real syntax is a different render and keeps its own slot.
        let known = Key {
            id,
            ext: Some("rs".to_string()),
        };
        assert!(cache.get(&known, Mode::Source).is_none());
    }

    /// The source view's output depends on the syntax, not on which of its extensions named it, so
    /// every spelling of one syntax describes the same document. Keying on the extension gave
    /// `md`, `markdown` and `mdown` a slot each, holding byte-identical HTML; 102 of the 213
    /// syntaxes list more than one extension, so this was the common case, not a corner of it.
    #[test]
    fn extensions_naming_one_syntax_share_a_slot() {
        let cache = test_cache(NonZeroUsize::new(128), 1024);
        let id = Id::from(104_651_828_u32);

        let stored = Key {
            id,
            ext: Some("md".to_string()),
        };
        cache.put(&stored, Mode::Source, Arc::from("rendered as markdown"));

        for ext in ["markdown", "mdown"] {
            let probe = Key {
                id,
                ext: Some(ext.to_string()),
            };
            assert_eq!(
                cache.get(&probe, Mode::Source).as_deref(),
                Some("rendered as markdown"),
                "{ext} did not share markdown's slot",
            );
        }

        // A different syntax is a different render and keeps its own slot.
        let other = Key {
            id,
            ext: Some("rs".to_string()),
        };
        assert!(cache.get(&other, Mode::Source).is_none());
    }

    /// A rendered document is Markdown either way — `markdown::render` never sees the extension —
    /// so every known extension took a slot holding byte-identical HTML. With 586 of them against
    /// a 128-entry cache, one paste fetched under varying extensions evicted everything else and
    /// paid for a full render each time.
    #[test]
    fn one_paste_holds_one_rendered_slot() {
        let cache = test_cache(NonZeroUsize::new(128), 1024);
        let id = Id::from(104_651_828_u32);

        let stored = Key {
            id,
            ext: Some("md".to_string()),
        };
        cache.put(&stored, Mode::Rendered, Arc::from("<h1>x</h1>"));

        for ext in [None, Some("rs".to_string()), Some("py".to_string())] {
            let probe = Key { id, ext };
            assert_eq!(
                cache.get(&probe, Mode::Rendered).as_deref(),
                Some("<h1>x</h1>"),
            );
        }

        // The source view does depend on the extension, so it keeps a slot per syntax.
        let known = Key {
            id,
            ext: Some("rs".to_string()),
        };
        assert!(cache.get(&known, Mode::Source).is_none());
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
