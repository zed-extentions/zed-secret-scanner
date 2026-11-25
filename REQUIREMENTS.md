# Requirements Specification — zed-secret-scanner (Secret Scanner)

- Version: v0.1.0 · Status: **Implemented (G1–G4 Complete, G5 Pending Zed Manual Check)**
- Reference Inspiration: [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (MIT) — independent Rust/WASM implementation with zero upstream runtime dependencies
- Priority notation: MUST (Required for v0.1.0) / SHOULD (Recommended)

## 1. Objectives

Provide real-time inline hardcoded-secret detection, masked diagnostic reporting, one-keypress `Ctrl+.` suppression Quick Fixes, configurable workspace scanning, and a standalone CLI scanner (`secret-scanner-lsp scan`) for Zed via a 3-Tier Rust/WASM (`wasm32-wasip2`) extension and native `secret-scanner-lsp` sidecar.

## 2. Functional Requirements

| ID | Requirement | Priority | Verification |
|---|---|---|---|
| FR-1 | Detect 24 prefixed provider token formats (`aws-access-token`, `github-pat`, `github-fine-grained-pat`, `github-oauth`, `github-app-token`, `github-refresh-token`, `gitlab-pat`, `slack-token`, `slack-webhook-url`, `stripe-access-token`, `gcp-api-key`, `gcp-oauth-client-secret`, `openai-api-key`, `anthropic-api-key`, `huggingface-access-token`, `npm-access-token`, `pypi-upload-token`, `sendgrid-api-token`, `twilio-api-key`, `shopify-token`, `digitalocean-token`, `square-token`, `databricks-api-token`, `age-secret-key`) with exact word boundaries and character classes using hand-written `std` matchers | MUST | G2 (`secret-scanner-core`) |
| FR-2 | Detect 5 structural secret formats (`private-key`, `azure-storage-account-key`, `hashicorp-tf-api-token`, `jwt`, `url-credentials`), reporting only the password segment of URLs and excluding common documentation passwords (`pass`, `password`, `passwd`, `pwd`, `secret`, `xxx`) | MUST | G2 (`secret-scanner-core`) |
| FR-3 | Detect generic secret assignments (`generic-api-key`) matching credential keywords (`api_key`, `secret`, `token`, `password`, etc.) paired with high Shannon entropy values (`>= 3.5` bits/char, length `>= 12`), while skipping metadata key suffixes (`_url`, `_path`, `_hash`, `_id`, etc.), regexes/prose, unquoted code references, and lines longer than 4096 bytes | MUST | G2 (`secret-scanner-core`) |
| FR-4 | Support inline suppression comments (`secret-scanner-lsp:ignore`, `secret-scanner-lsp:ignore-next-line`, and `gitleaks:allow`) and placeholder filtering (`EXAMPLE`, `${...}`, `{{...}}`, `changeme`, repeated characters, env references) | MUST | G2 (`secret-scanner-core`) |
| FR-5 | Publish LSP diagnostics (`textDocument/publishDiagnostics`) with UTF-16 character offsets (`byte_to_utf16_col`), rule ID code, configured severity, and masked secret previews (`mask_secret`, max 4 leading chars and at most 1/4 of length) so raw secrets never leave the scanner | MUST | G2 (`secret-scanner-core`, `secret-scanner-lsp`), G5 |
| FR-6 | Offer `Ctrl+.` (`QuickFix`) code actions (`textDocument/codeAction`) inserting a language-appropriate indented `#` / `//` / `--` / `/* */` / `<!-- -->` `secret-scanner-lsp:ignore-next-line` comment above affected lines, while omitting quick fixes for comment-free formats like JSON | MUST | G2 (`secret-scanner-lsp`), G5 |
| FR-7 | Decode `lsp.secret-scanner-lsp.settings` (`disabledRules`, `severity`, `entropy.enabled`, `entropy.threshold`, `entropy.minLength`, `ignorePaths`, `maxFileSize`, `workspaceScan.enabled`, `workspaceScan.maxFiles`) at initialization and dynamically on `workspace/didChangeConfiguration`, immediately re-diagnosing open documents | MUST | G2 (`secret-scanner-lsp`, protocol E2E), G5 |
| FR-8 | Skip non-source directories (`.git`, `node_modules`, `target`, `dist`, etc.), lockfiles, minified `.min.js`/`.min.css`, binary extensions, files exceeding `maxFileSize`, NUL-containing binary payloads, and user `ignorePaths` globs | MUST | G2 (`secret-scanner-core`, `secret-scanner-lsp`) |
| FR-9 | Resolve `secret-scanner-lsp` binary in deterministic order (`lsp.secret-scanner-lsp.binary.path` -> `worktree.which("secret-scanner-lsp")` -> cached version directory -> exact-version GitHub Release download via `zed::github_release_by_tag_name` & `zed::download_file` with stale cache cleanup and offline fallback) and scope `extension.toml` capabilities strictly to release `download_file` hosts | MUST | G2 (`secret-scanner-core`, `zed_secret_scanner`), G3, G5 |
| FR-10 | Support opt-in background workspace scanning on startup (`workspaceScan.enabled = true`) bounded by `workspaceScan.maxFiles` without overwriting diagnostics for open editor buffers, clearing stale closed-file diagnostics when disabled | MUST | G2 (`secret-scanner-lsp`, protocol E2E), G5 |
| FR-11 | Provide standalone CLI mode `secret-scanner-lsp scan [--json] [--no-entropy] [--max-files N] [PATH...]` emitting masked text or JSON findings with exit code `0` (clean), `1` (findings), or `2` (usage or missing-path error) | MUST | G2 (`secret-scanner-lsp`, protocol E2E) |

## 3. Non-Functional Requirements

| ID | Requirement | Priority | Verification |
|---|---|---|---|
| NFR-1 | Pure `std` Tier 2 crate (`crates/secret-scanner-core`) with zero external dependencies and zero `zed_extension_api` imports | MUST | `Cargo.toml` inspection, `cargo test` |
| NFR-2 | `#![forbid(unsafe_code)]` via `[lints.rust] unsafe_code = "forbid"` in all workspace crates, permissive dependency licenses only (no GPL/SSPL/BUSL/MPL), and committed `Cargo.lock` | MUST | `cargo metadata`, `cargo clippy --workspace --all-targets -- -D warnings` |
| NFR-3 | Explicit `crate::` imports everywhere (no `use super::` or wildcard `::*;` imports), formatted with `cargo fmt`, building cleanly on `wasm32-wasip2` release | MUST | G2, G3 |
| NFR-4 | End-to-end JSON-RPC stdio LSP and CLI subprocess tests verifying real binary handshake, diagnostics, code action edits, live settings reload, and clean shutdown within bounded timeouts | MUST | G2 (`tests/protocol.rs`) |
| NFR-5 | Reproducible filtered public snapshot export pipeline (`scripts/export-public.sh`, `scripts/public-gate.sh`) preventing private strings, fixtures, or credentials from leaking | MUST | `export-public.sh` dry run |

## 4. Traceability Matrix

| Requirement ID | Implementation Module | Test Coverage |
|---|---|---|
| FR-1 | `crates/secret-scanner-core/src/rules.rs` (`RULES`, `find_matches`) | `rules::tests::{rule_ids_are_unique_and_kebab_case, aws_access_key_requires_exact_length_and_boundaries, github_tokens, slack_and_stripe_tokens, cloud_and_ai_provider_keys, sendgrid_twilio_shopify_digitalocean, terraform_and_azure_and_age}` |
| FR-2 | `crates/secret-scanner-core/src/rules.rs` (`find_private_key`, `find_azure_account_key`, `find_terraform_token`, `find_jwt`, `find_url_credentials`) | `rules::tests::{private_key_header_but_not_public_key, jwt_needs_three_segments, url_credentials_report_only_the_password, terraform_and_azure_and_age}` |
| FR-3 | `crates/secret-scanner-core/src/entropy.rs` (`shannon_entropy`, `is_secret_key`, `find_generic_assignments`) | `entropy::tests::{entropy_of_known_strings, secret_key_names, detects_assignments_in_common_syntaxes, ignores_references_placeholders_and_low_entropy, regexes_prose_and_escaped_quotes}` |
| FR-4 | `crates/secret-scanner-core/src/allow.rs` (`ignores_own_line`, `ignores_next_line`, `is_placeholder`) | `allow::tests::{line_markers, placeholders}`, `scanner::tests::{inline_markers_suppress_findings, placeholders_are_not_reported}` |
| FR-5 | `crates/secret-scanner-core/src/{mask.rs, position.rs, scanner.rs}`, `crates/secret-scanner-lsp/src/convert.rs` | `mask::tests::masks_long_and_short_values`, `position::tests::{splits_lf_and_crlf, utf16_columns}`, `scanner::tests::*`, `convert::tests::positions_are_utf16_and_metadata_is_set` |
| FR-6 | `crates/secret-scanner-core/src/comment.rs`, `crates/secret-scanner-lsp/src/actions.rs` | `comment::tests::styles_by_path_and_language`, `actions::tests::{inserts_indented_comment_above_the_line, no_action_for_json}` |
| FR-7 | `crates/secret-scanner-core/src/config.rs`, `crates/secret-scanner-lsp/src/{settings.rs, server.rs}` | `config::tests::*`, `settings::tests::*`, `protocol::initialize_diagnose_quick_fix_and_shutdown` |
| FR-8 | `crates/secret-scanner-core/src/paths.rs`, `crates/secret-scanner-lsp/src/workspace.rs` | `paths::tests::{glob_semantics, default_skips, user_patterns}`, `workspace::tests::*` |
| FR-9 | `crates/secret-scanner-core/src/release.rs`, `src/lib.rs`, `extension.toml` | `release::tests::*`, `zed_secret_scanner::tests::{manifest_follows_registry_rules, capabilities_are_scoped}` |
| FR-10 | `crates/secret-scanner-lsp/src/{server.rs, workspace.rs}` | `workspace::tests::{walks_skipping_default_and_user_patterns, respects_max_files_and_reads_text_only}` |
| FR-11 | `crates/secret-scanner-lsp/src/{cli.rs, main.rs}` | `cli::tests::{parses_flags_and_default_path, renders_masked_text_and_json}`, `protocol::scan_cli_reports_and_sets_exit_code` |
| NFR-1..NFR-4 | Workspace `Cargo.toml`s, `crates/secret-scanner-lsp/tests/protocol.rs` | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo build --target wasm32-wasip2 --release` |
| NFR-5 | `.public-export`, `scripts/export-public.sh`, `scripts/public-gate.sh`, `.github/workflows/publish-public.yml` | Verified via `export-public.sh` snapshot + locked workspace build/test |
