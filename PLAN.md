# PLAN — zed-secret-scanner (v0.1.0 Implementation Plan)

Reference Inspiration: [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (MIT)
Target: Zed extension (`secret-scanner-lsp`), Rust/WASM (`wasm32-wasip2`, `zed_extension_api = "0.7.0"`).

---

## 1. Scope & Milestones

1. **Tier 2 Core Engine (`crates/secret-scanner-core`)** — *[Completed]*
   - Pure `std` secret scanner with zero external crate dependencies and zero regex-engine overhead.
   - 24 prefixed token rules + 5 structural rules + Shannon entropy keyword detector (`generic-api-key`).
   - Inline allow markers (`secret-scanner-lsp:ignore`, `secret-scanner-lsp:ignore-next-line`, `gitleaks:allow`), placeholder filtering, strict masking (`mask_secret`), UTF-16 column conversion, language comment styles, glob path filtering, and release/cache resolution rules.
2. **Tier 3 Native Language Server & CLI (`crates/secret-scanner-lsp`)** — *[Completed]*
   - stdio LSP server (`lsp-server` / `lsp-types`) emitting inline `publishDiagnostics`, `Ctrl+.` `QuickFix` code actions, live `didChangeConfiguration` reloads, and opt-in background workspace scanning (`workspaceScan.enabled`).
   - Standalone CLI `secret-scanner-lsp scan [--json] [--no-entropy] [--max-files N] [PATH...]` for terminal, Zed tasks, and CI pipelines.
   - Real-binary JSON-RPC and CLI end-to-end integration tests (`tests/protocol.rs`) with bounded process exit timeouts.
3. **Tier 1 WASM Extension (`src/lib.rs`, `extension.toml`)** — *[Completed]*
   - Resolves `secret-scanner-lsp` from `lsp.secret-scanner-lsp.binary.path` -> `PATH` -> versioned cache -> exact-version GitHub Releases download (`zed::github_release_by_tag_name` + `zed::download_file`) with stale cache pruning and offline fallback.
   - Forwards `lsp.secret-scanner-lsp.settings` on initialization and workspace configuration updates.
4. **False-Positive Audit Across Sibling Repositories** — *[Completed]*
   - Validated CLI scans across existing extension codebases to refine exclusions (documentation URL passwords like `user:pass@host`, regex definitions, prose/grammar examples, and normalized CLI paths).

---

## 2. Module Structure

```text
zed-secret-scanner/
├── Cargo.toml                  # Workspace root & zed_secret_scanner cdylib (zed_extension_api 0.7.0)
├── Cargo.lock                  # Committed lockfile for reproducible builds
├── extension.toml              # id = "secret-scanner-lsp", scoped download_file capabilities
├── src/lib.rs                  # Tier 1 WASM boundary & manifest compliance tests
├── crates/
│   ├── secret-scanner-core/           # Tier 2 pure std engine (rules, entropy, allow, mask, comment, config, paths, position, release, scanner)
│   └── secret-scanner-lsp/            # Tier 3 native stdio LSP + scan CLI + protocol.rs E2E tests
└── scripts/                    # apply-ruleset.sh, export-public.sh, public-gate.sh, public-gate-allow.txt
```

---

## 3. API Ground Truth & Constraints

- Verified against `zed_extension_api = "0.7.0"` (`wasm32-wasip2`, `[lints.rust] unsafe_code = "forbid"`).
- No custom WebView, no global command registration, and no `process:exec` wildcard capability.
- Static pattern + entropy detection only: `secret-scanner-lsp` does not call cloud provider APIs to verify whether a token is active or revoked.

---

## 4. Verification Gates (G1–G5)

- **G1**: `PLAN.md`, `REQUIREMENTS.md`, and `ARCHITECTURE.md` complete and aligned.
- **G2**: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass (36 `secret-scanner-core` + 11 `secret-scanner-lsp` unit + 4 `protocol` E2E + 2 `zed_secret_scanner` manifest tests = 53 tests).
- **G3**: `cargo build --target wasm32-wasip2 --release` produces `target/wasm32-wasip2/release/zed_secret_scanner.wasm`.
- **G4**: English community/docs files, MIT attribution, `Cargo.lock` committed, and `scripts/export-public.sh` snapshot dry run green.
- **G5**: Manual verification inside Zed following `README.md`.
