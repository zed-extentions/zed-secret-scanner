//! `secret-scanner-core` — Tier 2 pure `std` domain logic for `zed-secret-scanner`.
//!
//! Shared by the Tier 1 Zed extension (`src/lib.rs`, compiled to `wasm32-wasip2`)
//! and the Tier 3 native language server (`crates/secret-scanner-lsp`). Nothing in this
//! crate touches the filesystem, the network, or `zed_extension_api`; every input
//! arrives as a string slice or a plain struct so that the whole crate is unit
//! tested on the host.
//!
//! Token formats are adapted from the default rule set of
//! [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and re-implemented as
//! hand-written matchers (no regex engine).

pub mod allow;
pub mod comment;
pub mod config;
pub mod entropy;
pub mod mask;
pub mod paths;
pub mod position;
pub mod release;
pub mod rules;
pub mod scanner;
