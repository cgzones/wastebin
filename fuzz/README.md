# Fuzzing `wastebin_highlight`

`Highlighter::highlight` and `markdown::render` turn a raw paste body into HTML on every request,
with both the body and the file extension attacker-controlled. The release profile sets
`panic = 'abort'`, so a panic reachable from either is not a 500 — it takes the process down, and
any visitor can repeat it by re-fetching the same paste. Neither function is reached through a
sanitizer on the way in, so these two entry points are the crate's whole attack surface.

There are two harnesses, for two different moments.

## In the test run

`crates/wastebin_highlight/tests/fuzz_panics.rs` is dependency-free and runs as an ordinary test,
so it keeps working without nightly or any tooling:

```bash
cargo test -p wastebin_highlight --test fuzz_panics -- --nocapture
```

It drives a fixed corpus of boundary-hostile inputs and then a seeded random phase, and reports
*every* distinct panic site rather than stopping at the first. The default budget is a few seconds
and will not finish the corpus; the run prints how much of it was reached, so a truncated pass is
never mistaken for a clean sweep. For a real hunt raise the budget:

```bash
FUZZ_SECS=600 cargo test -p wastebin_highlight --test fuzz_panics -- --nocapture
```

`FUZZ_ITERS`, `FUZZ_SECS` and `FUZZ_SEED` are documented at the top of that file. A reported
failure prints the seed and a minimized input as a Rust literal, so it replays directly.

## Coverage-guided

This directory is a [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) project — nightly and
libFuzzer, orders of magnitude more effective at reaching new code than the random harness:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run markdown -- -dict=fuzz/dict.txt
cargo +nightly fuzz run highlight -- -dict=fuzz/dict.txt
```

It is a separate workspace on purpose: it needs nightly and builds with sanitizers, neither of
which the main workspace's stable toolchain and lint policy should have to accommodate. Nothing
in CI runs it.

The `highlight` target splits its input at the first NUL — everything before it is the extension,
the rest is the paste body — so one libFuzzer input drives both arguments. Both targets convert
bytes to UTF-8 lossily rather than rejecting invalid input, because a paste body is always a Rust
`String` in production; discarding non-UTF-8 would waste most executions.

Corpora and artifacts are not committed: they reach tens of megabytes and regenerate from a run.

## When adding a harness

Prove it can fail before trusting a green run. Inject a boundary fault into a scratch copy — for
example `&text[2048..]` in `highlight` — and confirm the harness finds and minimizes it. A fuzzer
that cannot see a planted bug reports nothing for the same reason it reports nothing when the code
is clean.
