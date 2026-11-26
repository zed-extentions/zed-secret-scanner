# zed-secret-scanner — Hardcoded Secret Scanner for Zed (`secret-scanner-lsp`)

A real-time hardcoded-secret scanner and standalone CLI for Zed, built with a zero-VSCode-dependency 3-Tier Rust/WASM (`wasm32-wasip2`) extension and the native `secret-scanner-lsp` language server.
Inspired by [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) — an independent pure-Rust reimplementation containing no upstream source code, binaries, or regex runtime dependency.

> Zed has no built-in credential scanner across source, configuration, and documentation files; `zed-secret-scanner` catches API tokens, private keys, JWTs, URL passwords, and high-entropy secret assignments directly inside the editor buffer with masked diagnostics, masked hover cards, and one-keypress `Ctrl+.` suppressions.

## Demo

Recorded in the real Zed editor (`v1.29.3`) in headless CI; JSON-RPC protocol traces (`protocol.jsonl`) verify the behavior shown in each recording.

These recordings show Zed using synthetic example data. Any token visible in the editor is a dynamically constructed fake test value, and raw secret values never appear in diagnostics, hover payloads, or CLI output.

### Diagnostics

Hardcoded secrets are flagged live as you type and listed in the Project Diagnostics panel (`Ctrl+Shift+M` / `F8`) with masked previews.

![Diagnostics](https://github.com/zed-extentions/zed-secret-scanner/releases/download/v0.1.0/lsp-diagnostics.gif)

### Hover

Hovering a flagged token shows its rule title, rule ID, severity, masked snippet, remediation guidance, and inline suppression instructions.

![Hover](https://github.com/zed-extentions/zed-secret-scanner/releases/download/v0.1.0/lsp-hover.gif)

### Quick Fix

`Ctrl+.` offers inserting `secret-scanner-lsp:ignore-next-line` above the flagged line or appending `secret-scanner-lsp:ignore` inline, clearing the diagnostic immediately.

![Quick Fix](https://github.com/zed-extentions/zed-secret-scanner/releases/download/v0.1.0/lsp-quick-fix.gif)

## Features

### Inline Secret Diagnostics, Hover & Code Actions
- [x] Real-time inline diagnostics (`textDocument/publishDiagnostics`) and Project Diagnostics (`Ctrl+Shift+M` / `F8`)
- [x] **30 built-in rules**: 24 prefixed provider token matchers, 5 structural matchers (`private-key`, `azure-storage-account-key`, `hashicorp-tf-api-token`, `jwt`, `url-credentials`), and keyword + Shannon entropy detection (`generic-api-key`)
- [x] Always-masked diagnostic messages (`prefix…(N chars)`) so raw credentials are never echoed in diagnostics, hover popovers, or CLI output
- [x] **Masked Hover cards** (`textDocument/hover`): Displays rule title, rule ID, configured severity, masked snippet, remediation guidance, and suppression instructions
- [x] Context-aware `Ctrl+.` (`Cmd+.`) Quick Fixes offering both indented `secret-scanner-lsp:ignore-next-line` above the flagged line (preferred) and inline `secret-scanner-lsp:ignore` at end-of-line
- [x] Honors `secret-scanner-lsp:ignore`, `secret-scanner-lsp:ignore-next-line`, and `gitleaks:allow` inline markers plus common placeholder patterns

### Workspace Scanning, CLI & Binary Provisioning
- [x] Opt-in background workspace scanning on startup (`workspaceScan.enabled`) bounded by `workspaceScan.maxFiles`
- [x] Standalone CLI (`secret-scanner-lsp scan [--json] [--no-entropy] [--max-files N] [PATH...]`) for terminals, `.zed/tasks.json`, and CI
- [x] Automatic binary resolution (`lsp.secret-scanner-lsp.binary.path` -> `PATH` -> cached version dir -> exact-version GitHub Release download with offline cache fallback)

### Zed Extension API Boundaries
- [ ] Remote token validity verification or revocation *(Out of scope — static local detection only; secrets never leave your machine)*
- [ ] Custom WebViews or sidebar secret dashboards *(Blocked by Zed Extension API `0.7.0` — surfaced via Project Diagnostics `Ctrl+Shift+M` and Code Action Palette `Ctrl+.`)*

## Prerequisites

For normal editor diagnostics, masked Hover cards, and `Ctrl+.` Quick Fixes, no manual installation is needed once releases are published: `zed-secret-scanner` downloads the matching `secret-scanner-lsp` server binary automatically from GitHub Releases (or uses a copy on `PATH` / `lsp.secret-scanner-lsp.binary.path`).
To run `secret-scanner-lsp scan` from a terminal or `.zed/tasks.json`, install `secret-scanner-lsp` on `PATH` (for example `cargo install --path crates/secret-scanner-lsp`).

### Binary resolution order

`zed-secret-scanner` locates `secret-scanner-lsp` in this order:

1. **`lsp.secret-scanner-lsp.binary.path`** in `.zed/settings.json` (explicit override, with optional `arguments` and `env`)
2. **`secret-scanner-lsp` on `PATH`** (resolved via `worktree.which("secret-scanner-lsp")`)
3. **Version-matched cached binary** in the extension work directory (`secret-scanner-lsp-v<VERSION>/`)
4. **Automatic GitHub Release download** for tag `v<VERSION>` (`zed::github_release_by_tag_name` + `zed::download_file`), falling back to the newest previously cached version when offline
5. **Actionable installation error** if none of the above succeed

```json
{
  "lsp": {
    "secret-scanner-lsp": {
      "binary": {
        "path": "/custom/path/to/secret-scanner-lsp",
        "arguments": ["--stdio"]
      }
    }
  }
}
```

## Usage

### 1. Inline Diagnostics & Project Diagnostics (`Ctrl+Shift+M` / `F8`)

Open, edit, or save any supported source, config, `.env`, or documentation file. Potential secrets are underlined inline and aggregated in the Project Diagnostics panel (`diagnostics: deploy`, `Ctrl+Shift+M`, next diagnostic `F8`).

### 2. Hover & Code Action Palette (`Ctrl+.` / `Cmd+.`)

Hover over any flagged secret (`editor: hover`) to inspect the rule title, rule ID, severity, masked value, remediation guidance, and suppression options without exposing the raw secret.

Place the cursor on a flagged line and press `Ctrl+.` (`editor: toggle code actions`) to choose between inserting an indented `secret-scanner-lsp:ignore-next-line` comment above the line or appending `secret-scanner-lsp:ignore` inline in the file's native comment syntax (`#`, `//`, `--`, `/* ... */`, or `<!-- ... -->`). JSON files do not support comments, so no quick fix is offered there; use `disabledRules` or `ignorePaths` instead.

You can also suppress false positives manually with:
- `secret-scanner-lsp:ignore` (same line)
- `secret-scanner-lsp:ignore-next-line` (previous line)
- `gitleaks:allow` (same line, for existing annotations)

### 3. CLI & Task Palette (`Alt+Shift+T`)

Run a one-shot scan across files or directories from your terminal or CI:

```sh
secret-scanner-lsp scan
secret-scanner-lsp scan --json --no-entropy src/ .env.example
secret-scanner-lsp scan --max-files 1000 .
```

Exit codes: `0` = clean, `1` = findings detected, `2` = usage error.

Optionally bind it in `.zed/tasks.json` (when `secret-scanner-lsp` is on `PATH`):

```json
[
  {
    "label": "secrets: Scan workspace",
    "command": "secret-scanner-lsp",
    "args": ["scan", "$ZED_WORKTREE_ROOT"]
  },
  {
    "label": "secrets: Scan current file",
    "command": "secret-scanner-lsp",
    "args": ["scan", "$ZED_FILE"]
  }
]
```

### 4. Built-in Rules

| Rule ID | Title | Pattern / Scope |
|---|---|---|
| `private-key` | Private key | PEM header `-----BEGIN … PRIVATE KEY-----` |
| `aws-access-token` | AWS access key ID | `AKIA`, `ASIA`, `ABIA`, `ACCA` + 16 `[A-Z0-9]` |
| `azure-storage-account-key` | Azure storage account key | `AccountKey=` + 86–88 Base64 chars |
| `github-pat` | GitHub personal access token | `ghp_` + 36 `[A-Za-z0-9]` |
| `github-fine-grained-pat` | GitHub fine-grained personal access token | `github_pat_` + 82 `[A-Za-z0-9_]` |
| `github-oauth` | GitHub OAuth access token | `gho_` + 36 `[A-Za-z0-9]` |
| `github-app-token` | GitHub App token | `ghu_` / `ghs_` + 36 `[A-Za-z0-9]` |
| `github-refresh-token` | GitHub refresh token | `ghr_` + 36 `[A-Za-z0-9]` |
| `gitlab-pat` | GitLab personal access token | `glpat-` + 20–80 URL-safe chars |
| `slack-token` | Slack token | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` / `xoxe-` |
| `slack-webhook-url` | Slack incoming webhook URL | `https://hooks.slack.com/services/...` |
| `stripe-access-token` | Stripe secret key | `sk_live_` / `sk_test_` / `sk_prod_` / `rk_*` |
| `gcp-api-key` | Google Cloud API key | `AIza` + 35 URL-safe chars |
| `gcp-oauth-client-secret` | Google OAuth client secret | `GOCSPX-` + 28 URL-safe chars |
| `openai-api-key` | OpenAI API key | `sk-proj-` / `sk-svcacct-` / `sk-admin-` |
| `anthropic-api-key` | Anthropic API key | `sk-ant-api03-` / `sk-ant-admin01-` |
| `huggingface-access-token` | Hugging Face access token | `hf_` + 34 letters |
| `npm-access-token` | npm access token | `npm_` + 36 `[A-Za-z0-9]` |
| `pypi-upload-token` | PyPI upload token | `pypi-AgEIcHlwaS5vcmc` + 50–500 chars |
| `sendgrid-api-token` | SendGrid API key | `SG.` + 66 `[A-Za-z0-9_-.=]` |
| `twilio-api-key` | Twilio API key | `SK` + 32 hex chars |
| `shopify-token` | Shopify access token | `shpat_` / `shpca_` / `shppa_` / `shpss_` + 32 hex |
| `digitalocean-token` | DigitalOcean token | `dop_v1_` / `doo_v1_` / `dor_v1_` + 64 lowercase hex |
| `square-token` | Square access token or secret | `sq0atp-` / `sq0csp-` + 22–43 URL-safe chars |
| `databricks-api-token` | Databricks API token | `dapi` + 32 lowercase hex |
| `age-secret-key` | age secret key | `AGE-SECRET-KEY-1` + 58 `[A-Z0-9]` |
| `hashicorp-tf-api-token` | HashiCorp Terraform API token | `14chars.atlasv1.60-70chars` |
| `jwt` | JSON Web Token | Three-segment `eyJ….eyJ….sig` |
| `url-credentials` | Password in URL | `scheme://user:password@host` (common doc passwords excluded) |
| `generic-api-key` | Generic secret assignment | Credential keyword assignment with Shannon entropy `>= 3.5` and length `>= 12` |

### 5. Workspace Configuration (`.zed/settings.json`)

```json
{
  "lsp": {
    "secret-scanner-lsp": {
      "settings": {
        "severity": "warning",
        "disabledRules": [],
        "entropy": {
          "enabled": true,
          "threshold": 3.5,
          "minLength": 12
        },
        "ignorePaths": ["**/fixtures/**", "*.snap"],
        "maxFileSize": 1048576,
        "workspaceScan": {
          "enabled": false,
          "maxFiles": 5000
        }
      }
    }
  }
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `severity` | `"error"` \| `"warning"` \| `"information"` \| `"hint"` | `"warning"` | LSP diagnostic severity for all rules |
| `disabledRules` | `string[]` | `[]` | Rule IDs to suppress globally (e.g. `["jwt", "generic-api-key"]`) |
| `entropy.enabled` | `bool` | `true` | Enables the `generic-api-key` keyword + entropy detector |
| `entropy.threshold` | `number` | `3.5` | Minimum Shannon entropy (bits per char) for generic assignments |
| `entropy.minLength` | `number` | `12` | Minimum value length (bytes) for generic assignments |
| `ignorePaths` | `string[]` | `[]` | Extra glob patterns (relative to workspace root, or filename if no `/`) to skip |
| `maxFileSize` | `number` | `1048576` | Maximum file size in bytes (1 MiB default) |
| `workspaceScan.enabled` | `bool` | `false` | Scans non-ignored workspace files on startup and publishes diagnostics |
| `workspaceScan.maxFiles` | `number` | `5000` | Maximum files visited during a startup workspace scan |

Default skipped paths always include `.git`, `node_modules`, `target`, `dist`, `build`, `vendor`, lockfiles (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, etc.), `.min.js`/`.min.css`, binary extensions, and files containing NUL bytes.

## Constraints

- **Static Local Detection Only**: `secret-scanner-lsp` performs local pattern and Shannon entropy matching; it never transmits file contents or tests tokens against external APIs.
- **No Custom WebView / Global Commands**: `zed_extension_api = "0.7.0"` does not expose custom WebViews or arbitrary command registration; findings and suppressions use standard LSP diagnostics and `Ctrl+.` Code Actions.
- **Language Attachment Scope**: Secrets can be committed in any text format, so `extension.toml` attaches `secret-scanner-lsp` to 51 common source, configuration, IaC, and documentation language names (including both canonical Zed names such as `CSharp`, `Docker`, `ini`, `Vue`, `Bash` and common aliases, following the precedent of Zed's `harper`, `cspell`, and `typos` extensions); Zed ignores languages without an installed grammar.
- **WASI Sandbox (Tier 1/2)**: Extension host logic runs under `wasm32-wasip2` with `#![forbid(unsafe_code)]` and zero external dependencies in `crates/secret-scanner-core`.

## Installation (Dev Extension)

1. Build the local server binary so `secret-scanner-lsp` is available (or place it on `PATH` / configure `lsp.secret-scanner-lsp.binary.path` before the first release tag is published):
   ```sh
   cargo build --manifest-path crates/secret-scanner-lsp/Cargo.toml --release
   ```
2. Open Zed Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) → **`zed: install dev extension`** → select this directory (`zed-secret-scanner`).

## Manual Verification Procedure (G5)

1. **Clean-install auto-download check (post-release)**: Ensure `secret-scanner-lsp` is not on `PATH` and clear Zed's `extensions/work/secret-scanner-lsp` directory, install the exported public commit as a dev extension, and open a supported file. Confirm `secret-scanner-lsp` auto-downloads cleanly under `[[capabilities]]` and `Zed.log` contains zero capability, permission, or WASM panic errors. *(Before the first GitHub Release is published, point `lsp.secret-scanner-lsp.binary.path` at the locally built `secret-scanner-lsp` binary to verify LSP behavior.)*
2. Create a Python or `.env` file containing a synthetic non-real test assignment, for example assembling or pasting a fake `AKIA…` / `sk_test_…` value or a high-entropy `API_KEY=...` assignment, plus a placeholder `AWS_KEY=AKIAIOSFODNN7EXAMPLE` and an inline-suppressed line ending in `# secret-scanner-lsp:ignore`.
3. **Verify Inline Diagnostics (`Ctrl+Shift+M` / `F8`)**: Confirm diagnostics appear only on the unmasked test assignment and never display the raw secret string; confirm the placeholder and ignored line produce no diagnostics.
4. **Verify Hover & Code Action Palette (`Ctrl+.`)**: Hover over a flagged token and confirm the Markdown popover displays the rule ID, severity, masked value, remediation guidance, and suppression instructions without exposing the raw secret. Place the cursor on a flagged line, trigger `editor: toggle code actions`, verify both `Ignore this secret (add secret-scanner-lsp:ignore-next-line above)` and `Ignore this secret inline (append secret-scanner-lsp:ignore)` are offered, apply one, and confirm the comment is inserted and the diagnostic disappears.
5. **Verify Live Settings Reload**: Set `"disabledRules": ["generic-api-key"]` or `"severity": "error"` under `lsp.secret-scanner-lsp.settings` in `.zed/settings.json` and confirm diagnostics update immediately without restarting the server.
6. **Verify CLI**: Run `secret-scanner-lsp scan .` on a test file and confirm exit code `1` with masked output, exit code `0` on a clean file, and exit code `2` on a non-existent path.

## Development

```sh
cargo fmt --all -- --check                      # formatting check
cargo clippy --workspace --all-targets -- -D warnings  # lint check (G2)
cargo test --workspace                          # unit & E2E tests (G2)
cargo build --target wasm32-wasip2 --release    # extension WASM build (G3)
```

- [`src/lib.rs`](src/lib.rs) — Tier 1 WASM boundary (`zed_extension_api::Extension` trait wiring).
- [`crates/secret-scanner-core/`](crates/secret-scanner-core/) — Tier 2 pure `std` secret detection engine and unit tests.
- [`crates/secret-scanner-lsp/`](crates/secret-scanner-lsp/) — Tier 3 native stdio LSP server, `scan` CLI, and JSON-RPC E2E tests.

Architecture: [ARCHITECTURE.md](ARCHITECTURE.md) · Plan: [PLAN.md](PLAN.md) · Requirements: [REQUIREMENTS.md](REQUIREMENTS.md)

## License

MIT. An independent Rust/WASM reimplementation inspired by [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
