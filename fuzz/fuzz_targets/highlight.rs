#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use wastebin_highlight::Highlighter;

static H: LazyLock<Highlighter> = LazyLock::new(Highlighter::default);

fuzz_target!(|data: &[u8]| {
    // Paste bodies are always valid UTF-8 in production (they are Rust `String`s), so convert
    // lossily rather than discarding the input: every exec then reaches the target.
    let s = String::from_utf8_lossy(data);
    // Everything before the first NUL is the extension, the rest is the paste body.
    let (ext, text) = match s.split_once('\u{0}') {
        Some((e, t)) => (Some(e.to_string()), t.to_string()),
        None => (None, s.into_owned()),
    };
    let _ = H.highlight(text, ext);
});
