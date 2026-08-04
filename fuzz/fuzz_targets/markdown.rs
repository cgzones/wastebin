#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use wastebin_highlight::{Highlighter, markdown};

static H: LazyLock<Highlighter> = LazyLock::new(Highlighter::default);

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = markdown::render(&s, &H);
});
