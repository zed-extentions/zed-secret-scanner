# Contributing

Report issues and propose changes in this repository. Maintainers review contributions before incorporating them into a release.

## Development

Install Rust and the `wasm32-wasip2` target, then run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --target wasm32-wasip2 --release
```

Keep Tier 2 domain logic (`crates/secret-scanner-core`) pure `std` and independent of `zed_extension_api`, and add unit tests for all behavior changes. Do not include real credentials or secret values in examples, documentation, or tests (assemble synthetic test tokens at runtime where needed).
