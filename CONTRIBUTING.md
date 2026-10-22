# Development

Run `cargo build --workspace` to build and `cargo test --workspace --all-targets`
to run the test suite. Before submitting a change, also run
`cargo fmt --all --check` and `cargo clippy --all-targets -- -Dwarnings`.

Development and test builds use line-table debug information to reduce compilation
and linking work while retaining file names and line numbers in backtraces. For
full debugger support, use `CARGO_PROFILE_DEV_DEBUG=2 cargo build` or
`CARGO_PROFILE_TEST_DEBUG=2 cargo test --workspace --all-targets`.

To compare build times, use separate empty `CARGO_TARGET_DIR` directories for the
before and after revisions and run `cargo build --workspace --locked --timings`,
then `cargo test --workspace --all-targets --locked --no-run --timings`. The second
command measures the additional cost of compiling tests after a development
build. Disable any compiler cache (for example, with `RUSTC_WRAPPER=`) for an
uncached comparison. Run measurements sequentially to avoid CPU contention.

Measure test execution separately by repeating `cargo test --workspace
--all-targets --locked` after compilation. The randomized highlighting test has a
three-second default budget; keep its `FUZZ_*` settings the same when comparing
runs.
