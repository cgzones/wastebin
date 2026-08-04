//! Randomized panic hunt over the two attacker-reachable entry points of this crate.
//!
//! `Highlighter::highlight` and `markdown::render` both turn a raw paste body into HTML on every
//! request, and the release profile sets `panic = 'abort'` — so a panic reachable from either is a
//! remote denial of service any visitor can repeat. This test drives both with inputs biased
//! towards the shapes that break HTML emitters (multi-byte characters astride a byte cutoff, bidi
//! and zero-width marks, unterminated markup, deeply nested tags) and reports *every* distinct
//! panic rather than stopping at the first.
//!
//! No dependencies: the generator is a xorshift64* PRNG seeded from a constant, so a failure is
//! reproducible from the seed printed alongside it.
//!
//! The default budget is small enough to sit in the normal test run; a real hunt wants
//! `FUZZ_SECS=600 cargo test -p wastebin_highlight --test fuzz_panics -- --nocapture`. Whatever
//! the budget, the run prints how much of the corpus it actually reached — a truncated pass must
//! not read as a clean sweep.
//!
//! Knobs (environment):
//!   `FUZZ_ITERS`  — random iterations to run (default 5000)
//!   `FUZZ_SECS`   — wall-clock cap on the whole run, both phases (default 3)
//!   `FUZZ_SEED`   — starting seed (default 0x2545_F491_4F6C_DD1D)

use std::borrow::Cow;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use wastebin_highlight::{Highlighter, markdown};

/// Deserializing the syntax set costs tens of milliseconds, and it is immutable.
static HIGHLIGHTER: LazyLock<Highlighter> = LazyLock::new(Highlighter::default);

/// Where the panic hook parks what it saw, read back by [`catch`].
static LAST_PANIC: Mutex<Option<Panic>> = Mutex::new(None);

static EXECUTIONS: AtomicUsize = AtomicUsize::new(0);

/// An info string far longer than any real language name.
static LONG_TOKEN: LazyLock<String> = LazyLock::new(|| "x".repeat(500));

#[derive(Clone, Debug, PartialEq, Eq)]
struct Panic {
    message: String,
    location: String,
}

/// One call into the crate, held so it can be replayed while shrinking.
#[derive(Clone, Debug)]
enum Case {
    Highlight { text: String, ext: Option<String> },
    Markdown { text: String },
}

impl Case {
    fn body(&self) -> &str {
        match self {
            Self::Highlight { text, .. } | Self::Markdown { text } => text,
        }
    }

    fn with_body(&self, text: String) -> Self {
        match self {
            Self::Highlight { ext, .. } => Self::Highlight {
                text,
                ext: ext.clone(),
            },
            Self::Markdown { .. } => Self::Markdown { text },
        }
    }

    fn entry_point(&self) -> &'static str {
        match self {
            Self::Highlight { .. } => "Highlighter::highlight",
            Self::Markdown { .. } => "markdown::render",
        }
    }

    /// Call the crate. Errors are expected outcomes; only a panic is a finding.
    fn exercise(&self) {
        match self {
            Self::Highlight { text, ext } => {
                let _ = HIGHLIGHTER.highlight(text.clone(), ext.clone());
            }
            Self::Markdown { text } => {
                let _ = markdown::render(text, &HIGHLIGHTER);
            }
        }
    }
}

/// Run one case, returning the panic it produced, if any.
fn catch(case: &Case) -> Option<Panic> {
    EXECUTIONS.fetch_add(1, Ordering::Relaxed);
    LAST_PANIC.lock().ok()?.take();

    if panic::catch_unwind(AssertUnwindSafe(|| case.exercise())).is_ok() {
        return None;
    }

    LAST_PANIC.lock().ok()?.take().or_else(|| {
        Some(Panic {
            message: "<hook did not fire>".to_string(),
            location: "<unknown>".to_string(),
        })
    })
}

// ---------------------------------------------------------------------------------------------
// PRNG
// ---------------------------------------------------------------------------------------------

/// xorshift64*, so a seed reproduces a run exactly.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            usize::try_from(self.next_u64() % (n as u64)).unwrap_or(0)
        }
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let index = self.below(items.len());
        &items[index]
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in.max(1)) == 0
    }
}

// ---------------------------------------------------------------------------------------------
// Input generation
// ---------------------------------------------------------------------------------------------

/// ASCII characters that are structural to HTML, Markdown or the escaper.
const STRUCTURAL: &[&str] = &[
    "<", ">", "&", "\"", "'", "/", "\\", "`", "|", "*", "_", "-", "#", "[", "]", "(", ")", "!",
    "~", "=", ":", ";", "{", "}", "$", "%", "^", "+", "?", "@",
];

/// Multi-byte UTF-8 of every width, so they can land astride an ASCII structural character.
const MULTIBYTE: &[&str] = &[
    "é",        // 2 bytes
    "Ω",        // 2 bytes
    "→",        // 3 bytes
    "中",       // 3 bytes
    "ﬃ",        // 3 bytes
    "\u{d7ff}", // 3 bytes, just below the surrogate range
    "𝔘",        // 4 bytes
    "🙈",       // 4 bytes
    "𐍈",        // 4 bytes
    "\u{10ffff}",
];

/// Characters `is_deceptive` marks up, i.e. the special path in `mark_deceptive_characters`.
const DECEPTIVE: &[&str] = &[
    "\u{200b}", "\u{200c}", "\u{200d}", "\u{200e}", "\u{200f}", "\u{202a}", "\u{202b}", "\u{202c}",
    "\u{202d}", "\u{202e}", "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}", "\u{206a}", "\u{206f}",
    "\u{2028}", "\u{2029}", "\u{fff9}", "\u{fffa}", "\u{fffb}", "\u{feff}",
];

/// C0/C1 controls, which `replace_control_characters` rewrites before anything else looks.
const CONTROLS: &[&str] = &[
    "\u{0}", "\u{1}", "\u{7}", "\u{8}", "\u{b}", "\u{c}", "\u{1b}", "\u{7f}", "\u{85}", "\u{9b}",
];

/// Unterminated and malformed markup.
const MALFORMED: &[&str] = &[
    "<",
    "<a href=",
    "<a href=\"",
    "<!--",
    "-->",
    "<![CDATA[",
    "]]>",
    "<?xml",
    "<div",
    "</",
    "</span>",
    "<span>",
    "<div/>",
    "<script>",
    "<input type=password>",
    "<img src=x onerror=alert(1)>",
    "```",
    "```rust",
    "~~~",
    "> [!NOTE]",
    "> [!CAUTION]",
    "[](",
    "](",
    "[x](javascript:alert(1))",
    "![](data:,)",
    "[^1]",
    "&#x",
    "&amp",
    "&#0;",
    "|---|",
    "- [ ] ",
];

const WHITESPACE: &[&str] = &["\n", "\r\n", "\r", "\t", " ", "\n\n", "  ", "\u{a0}"];

const WORDS: &[&str] = &[
    "fn",
    "let",
    "a",
    "the",
    "0x1",
    "123",
    "x",
    "http://x",
    "mailto:a@b",
    "javascript",
    "rust",
    "md",
    "code",
];

/// Extensions the URL may carry.
const EXTENSIONS: &[&str] = &[
    "",
    "md",
    "markdown",
    "mdown",
    "txt",
    "rs",
    "pl",
    "html",
    "c",
    "sh",
    "MD",
    "Rmd",
    "é",
    "🙈",
    "\u{202e}",
    ".",
    "..",
    "../../etc/passwd",
    "a/b",
    "a.b",
    "a\\b",
    "\u{0}",
    " ",
    "tar.gz",
];

fn random_extension(rng: &mut Rng) -> Option<String> {
    match rng.below(12) {
        0 => None,
        1 => Some("x".repeat(1 + rng.below(6000))),
        2 => {
            // A short random extension built from the same nasty palette.
            let mut ext = String::new();
            for _ in 0..rng.below(6) {
                let which = rng.below(5);
                let palette = [STRUCTURAL, MULTIBYTE, DECEPTIVE, CONTROLS, WORDS][which];
                ext.push_str(rng.pick(palette));
            }
            Some(ext)
        }
        _ => Some((*rng.pick(EXTENSIONS)).to_string()),
    }
}

/// Append one fragment drawn from the weighted palette.
fn push_fragment(rng: &mut Rng, out: &mut String) {
    // Weighted: structural ASCII and multi-byte characters dominate so they end up adjacent, which
    // is where a byte offset taken on a char-indexed string goes wrong.
    let palette: &[&str] = match rng.below(100) {
        0..=24 => STRUCTURAL,
        25..=44 => MULTIBYTE,
        45..=57 => DECEPTIVE,
        58..=63 => CONTROLS,
        64..=79 => MALFORMED,
        80..=91 => WHITESPACE,
        _ => WORDS,
    };
    out.push_str(rng.pick(palette));
}

/// Build a line whose byte length lands within a few bytes of `HIGHLIGHT_LINE_LENGTH_CUTOFF`
/// (2048), with a multi-byte character deliberately straddling that offset.
fn cutoff_line(rng: &mut Rng) -> String {
    const CUTOFF: usize = 2048;

    let palette = if rng.chance(2) { MULTIBYTE } else { DECEPTIVE };
    let straddler = *rng.pick(palette);
    let width = straddler.len();
    // Place the character so that offset 2048 falls inside it (or just beside it).
    let inside = rng.below(width + 3);
    let pad = CUTOFF.saturating_sub(inside);

    let filler = *rng.pick(&["a", " ", "<", "`", "*", "\\", "&"]);
    let mut line = filler.repeat(pad);
    line.push_str(straddler);

    // Something structural right after the boundary, so a mis-sliced tail shows up as markup.
    for _ in 0..rng.below(8) {
        push_fragment(rng, &mut line);
    }
    line
}

fn generate(rng: &mut Rng) -> Case {
    let text = match rng.below(100) {
        // Ordinary soup of nasty fragments.
        0..=49 => {
            let count = 1 + rng.below(200);
            let mut out = String::new();
            for _ in 0..count {
                push_fragment(rng, &mut out);
                if rng.chance(12) {
                    out.push('\n');
                }
            }
            if rng.chance(3) {
                out.push('\n');
            }
            out
        }
        // Lines around the 2048-byte highlight cutoff.
        50..=69 => {
            let mut out = String::new();
            for _ in 0..1 + rng.below(3) {
                out.push_str(&cutoff_line(rng));
                if rng.chance(2) {
                    out.push('\n');
                }
            }
            out
        }
        // A single very long line with no newline at all.
        70..=76 => {
            let mut out = String::new();
            while out.len() < 4096 + rng.below(8192) {
                push_fragment(rng, &mut out);
            }
            out.retain(|c| c != '\n' && c != '\r');
            out
        }
        // Deep nesting, of tags or of Markdown constructs.
        77..=85 => {
            let depth = rng.below(600);
            let unit = *rng.pick(&["<div>", "<b>", "<span>", "> ", "- ", "*", "[", "<div/>"]);
            let mut out = unit.repeat(depth);
            if rng.chance(2) {
                out.push_str(&"</div>".repeat(rng.below(depth + 1)));
            }
            out
        }
        // Degenerate: empty, newlines only, a lone CR, no trailing newline.
        86..=91 => (*rng.pick(&[
            "",
            "\n",
            "\r",
            "\r\r\r",
            "\n\n\n\n\n\n\n\n",
            "\u{0}",
            " ",
            "\u{feff}",
        ]))
        .repeat(rng.below(2000)),
        // A fenced code block, which is the only way into `highlight_code_block`.
        _ => {
            let fence = *rng.pick(&["```", "~~~", "````"]);
            let token = *rng.pick(&[
                "rust",
                "pl",
                "html",
                "md",
                "",
                "🙈",
                "<script>",
                "a b",
                LONG_TOKEN.as_str(),
            ]);
            let mut out = format!("{fence}{token}\n");
            for _ in 0..rng.below(60) {
                push_fragment(rng, &mut out);
                if rng.chance(6) {
                    out.push('\n');
                }
            }
            if rng.chance(3) {
                out.push('\n');
                out.push_str(fence);
            }
            out
        }
    };

    if rng.chance(2) {
        Case::Markdown { text }
    } else {
        Case::Highlight {
            text,
            ext: random_extension(rng),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fixed corpus
// ---------------------------------------------------------------------------------------------

/// Hand-picked inputs, so coverage of the known-nasty shapes does not depend on luck.
fn nasty_corpus() -> Vec<String> {
    let mut corpus: Vec<String> = [
        "",
        "\n",
        "\r",
        "\r\n",
        "\n\n\n\n",
        "a",
        "a\n",
        "no trailing newline",
        "<",
        "<a href=",
        "<a href=\"",
        "<!--",
        "<!-- unterminated",
        "<![CDATA[",
        "<![CDATA[x]]>",
        "&",
        "&amp",
        "&#x",
        "\"",
        "'",
        "/",
        "\\",
        "`",
        "```",
        "```rust\n",
        "```rust\nfn main() {}\n```",
        "~~~\n~~~",
        "> [!NOTE]\n> body",
        "> [!CAUTION]",
        "| a | b |\n|---|---|\n| 1 | 2 |",
        "- [ ] task\n- [x] done",
        "[link](javascript:alert(1))",
        "[l](http://example.com)",
        "[l](<>)",
        "![i](data:image/png;base64,AAA)",
        "<script>alert(1)</script>",
        "<div/>",
        "</span>",
        "<span>",
        "<input type=password>",
        "[^1]: note\n[^1]",
        "\u{202e}",
        "\u{200b}",
        "\u{feff}",
        "\u{2066}\u{2067}\u{2068}\u{2069}",
        "\u{2028}\u{2029}",
        "\u{206a}",
        "\u{fff9}\u{fffa}\u{fffb}",
        "\u{200b}<\u{202e}>\u{200f}",
        "<\u{202e}>",
        "a\u{202e}<b>\u{202e}",
        "é→𝔘🙈",
        "é<é>é&é\"é'é/é\\é`é",
        "🙈<🙈>🙈",
        "\u{0}\u{1}\u{7f}\u{1b}",
        "\u{0}<\u{0}",
        "\u{0}\u{202e}\u{0}",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    corpus.push("𝔘".repeat(600));
    corpus.push("<div>".repeat(300));
    corpus.push("<div>".repeat(3000));
    corpus.push("<b>".repeat(257));
    corpus.push("<b>".repeat(255));
    corpus.push("*".repeat(5000));
    corpus.push("\n".repeat(10000));
    corpus.push("a".repeat(20000));

    // Multi-byte characters placed exactly astride the 2048-byte cutoff, from every offset that
    // could split them, in both entry points.
    for straddler in ["é", "→", "𝔘", "🙈", "\u{202e}", "\u{feff}"] {
        for inside in 0..=straddler.len() + 2 {
            let pad = 2048usize.saturating_sub(inside);
            corpus.push(format!("{}{straddler}<b>&\"'\n", "a".repeat(pad)));
            corpus.push(format!(
                "{}{straddler}{}\ntail\n",
                "a".repeat(pad),
                "b".repeat(10)
            ));
            corpus.push(format!("```rust\n{}{straddler}\n```\n", "a".repeat(pad)));
        }
    }

    corpus
}

/// Every string literal appearing in this crate's own `#[cfg(test)]` modules.
///
/// Those inputs were written to probe exactly the paths this test is trying to break, so they are
/// worth far more than random bytes — and scraping them means new ones are picked up for free.
fn scraped_corpus() -> Vec<String> {
    let mut out = Vec::new();
    for source in [
        include_str!("../src/highlight.rs"),
        include_str!("../src/markdown.rs"),
    ] {
        // Only the test module: the rest of the file holds this crate's own markup constants, and
        // a locally patched source would otherwise feed its own strings back in.
        let tail = match source.find("mod tests") {
            Some(at) => &source[at..],
            None => continue,
        };
        out.extend(string_literals(tail));
    }
    out
}

/// Pull Rust string literals — raw (`r#"…"#`) and ordinary — out of `source`.
fn string_literals(source: &str) -> Vec<String> {
    let bytes: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        // Raw string: r, some hashes, a quote.
        if bytes[i] == 'r' {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < bytes.len() && bytes[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == '"' {
                let closing: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let rest: String = bytes[j + 1..].iter().collect();
                if let Some(end) = rest.find(&closing) {
                    out.push(rest[..end].to_string());
                    i = j + 1 + rest[..end].chars().count() + closing.len();
                    continue;
                }
            }
        }

        if bytes[i] == '"' {
            let mut literal = String::new();
            let mut j = i + 1;
            let mut escaped = false;
            while j < bytes.len() {
                let c = bytes[j];
                if escaped {
                    match c {
                        'n' => literal.push('\n'),
                        't' => literal.push('\t'),
                        'r' => literal.push('\r'),
                        '0' => literal.push('\u{0}'),
                        'u' => {
                            // \u{XXXX}
                            let rest: String = bytes[j + 1..].iter().collect();
                            if let Some(close) = rest.find('}')
                                && rest.starts_with('{')
                                && let Ok(cp) = u32::from_str_radix(&rest[1..close], 16)
                                && let Some(c) = char::from_u32(cp)
                            {
                                literal.push(c);
                                j += close + 1;
                            }
                        }
                        other => literal.push(other),
                    }
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    break;
                } else {
                    literal.push(c);
                }
                j += 1;
            }
            if !literal.is_empty() {
                out.push(literal);
            }
            i = j + 1;
            continue;
        }

        i += 1;
    }

    out
}

// ---------------------------------------------------------------------------------------------
// Shrinking and reporting
// ---------------------------------------------------------------------------------------------

/// Shrink `case` while it keeps panicking in the same place.
fn minimize(case: &Case, target: &Panic) -> Case {
    let still_fails =
        |candidate: &Case| catch(candidate).is_some_and(|p| p.location == target.location);

    let mut best = case.clone();

    // Drop the extension, then shorten it, if the panic does not need it.
    if let Case::Highlight { text, ext: Some(_) } = &best {
        let without = Case::Highlight {
            text: text.clone(),
            ext: None,
        };
        if still_fails(&without) {
            best = without;
        }
    }

    // Delete runs of characters, halving the run length each pass.
    let mut chunk = best.body().chars().count().div_ceil(2).max(1);
    while chunk > 0 {
        let mut changed = true;
        while changed {
            changed = false;
            let chars: Vec<char> = best.body().chars().collect();
            let mut at = 0;
            while at < chars.len() {
                let end = (at + chunk).min(chars.len());
                let mut shorter: String = chars[..at].iter().collect();
                shorter.extend(&chars[end..]);
                let candidate = best.with_body(shorter);
                if still_fails(&candidate) {
                    best = candidate;
                    changed = true;
                    break;
                }
                at += chunk;
            }
        }
        if chunk == 1 {
            break;
        }
        chunk /= 2;
    }

    best
}

/// Render `s` as a Rust string literal that pastes straight into a test.
fn rust_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// Cut a report line down so one enormous input cannot bury the others.
fn clipped(s: &str) -> Cow<'_, str> {
    const LIMIT: usize = 400;
    if s.chars().count() <= LIMIT {
        return Cow::Borrowed(s);
    }
    let head: String = s.chars().take(LIMIT).collect();
    Cow::Owned(format!(
        "{head}  /* … {} more characters */",
        s.chars().count() - LIMIT
    ))
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------------------------

#[test]
fn neither_entry_point_panics() {
    let iterations = env_usize("FUZZ_ITERS", 5_000);
    let budget = Duration::from_secs(env_usize("FUZZ_SECS", 3) as u64);
    let seed = env_usize("FUZZ_SEED", 0) as u64;
    let seed = if seed == 0 {
        0x2545_F491_4F6C_DD1D
    } else {
        seed
    };

    // Swallow the default hook's output — a run that finds a hundred panics would otherwise be
    // unreadable — while keeping the message and location.
    panic::set_hook(Box::new(|info| {
        let message = info.payload().downcast_ref::<&str>().map_or_else(
            || {
                info.payload()
                    .downcast_ref::<String>()
                    .cloned()
                    .unwrap_or_else(|| "<non-string payload>".to_string())
            },
            |s| (*s).to_string(),
        );
        let location = info
            .location()
            .map_or_else(|| "<unknown>".to_string(), ToString::to_string);
        if let Ok(mut slot) = LAST_PANIC.lock() {
            *slot = Some(Panic { message, location });
        }
    }));

    // Keyed by panic location, so one bug reports once however often it is hit.
    let mut findings: Vec<(Panic, Case, u64, usize)> = Vec::new();
    let mut record = |found: Panic, case: Case, at_seed: u64, hits: usize| {
        if findings.iter().any(|(p, ..)| p.location == found.location) {
            return;
        }
        findings.push((found, case, at_seed, hits));
    };

    let started = Instant::now();

    // ---- fixed corpus, both entry points ----
    let mut corpus = nasty_corpus();
    let scraped = scraped_corpus();
    let scraped_count = scraped.len();
    corpus.extend(scraped);

    // Cheapest first: cost is roughly linear in length, and a handful of very large inputs would
    // otherwise consume a small budget before most of the distinct *shapes* had been tried at all.
    corpus.sort_by_key(String::len);

    let corpus_extensions: [Option<&str>; 8] = [
        None,
        Some(""),
        Some("md"),
        Some("markdown"),
        Some("txt"),
        Some("rs"),
        Some("pl"),
        Some("html"),
    ];

    let mut corpus_reached = 0;
    for (index, text) in corpus.iter().enumerate() {
        // The budget bounds this phase too. Highlighting one large input through a regex-heavy
        // syntax runs into the tens of milliseconds, so the fixed corpus alone outlasts any
        // budget worth having in the default test run.
        if started.elapsed() > budget {
            break;
        }
        corpus_reached = index + 1;

        let case = Case::Markdown { text: text.clone() };
        if let Some(found) = catch(&case) {
            record(found, case, 0, index);
        }

        // A large input costs the same through every syntax, and the regex-heavy ones cost orders
        // of magnitude more per byte — so only the small inputs are run through the whole matrix.
        let matrix = if text.len() > 4096 {
            &corpus_extensions[..3]
        } else {
            &corpus_extensions[..]
        };

        for ext in matrix {
            let case = Case::Highlight {
                text: text.clone(),
                ext: ext.map(ToString::to_string),
            };
            if let Some(found) = catch(&case) {
                record(found, case, 0, index);
            }
        }
    }

    let after_corpus = EXECUTIONS.load(Ordering::Relaxed);

    // ---- randomized phase ----
    let mut rng = Rng(seed);
    let mut done = 0;
    for iteration in 0..iterations {
        // The seed at the top of this iteration, so a finding replays from exactly here.
        let at_seed = rng.0;
        let case = generate(&mut rng);
        if let Some(found) = catch(&case) {
            record(found, case, at_seed, iteration);
        }
        done = iteration + 1;
        if started.elapsed() > budget {
            break;
        }
    }

    let total = EXECUTIONS.load(Ordering::Relaxed);

    eprintln!("--- fuzz_panics ---");
    eprintln!(
        "corpus: {corpus_reached}/{} inputs ({scraped_count} scraped from the crate's own tests) in {after_corpus} executions{}",
        corpus.len(),
        if corpus_reached < corpus.len() {
            " — TRUNCATED by FUZZ_SECS, raise it to sweep the whole corpus"
        } else {
            ""
        }
    );
    eprintln!("random: {done} iterations from seed {seed:#x}");
    eprintln!(
        "total:  {total} executions in {:.1?}, {} distinct panic site(s)",
        started.elapsed(),
        findings.len()
    );

    for (found, case, at_seed, index) in &findings {
        let minimized = minimize(case, found);
        eprintln!();
        eprintln!("PANIC at {}", found.location);
        eprintln!("  message:     {}", found.message);
        eprintln!("  entry point: {}", minimized.entry_point());
        eprintln!("  seed:        {at_seed:#x} (index {index})");
        if let Case::Highlight { ext, .. } = &minimized {
            eprintln!("  extension:   {:?}", ext.as_deref().map(clipped));
        }
        eprintln!(
            "  minimized:   {}",
            clipped(&rust_literal(minimized.body()))
        );
    }

    // Only now: shrinking replays panicking cases, and the default hook would print each one.
    let _ = panic::take_hook();

    assert!(
        findings.is_empty(),
        "{} entry point(s) panicked; see the report above",
        findings.len()
    );
}
