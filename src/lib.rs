//! zed-secret-scanner — hardcoded secret detection for Zed via the `secret-scanner-lsp` language server.
//!
//! Tier 1 WASM boundary. This file is the only place that talks to
//! `zed_extension_api`: it resolves (or downloads) the Tier 3 server binary and
//! forwards `lsp.secret-scanner-lsp.settings`. Every decision is delegated to the Tier 2
//! crate `secret-scanner-core` so it is unit tested on the host.

use secret_scanner_core::release::{
    asset_name, binary_file_name, binary_rel_path, choose_binary_source, install_hint,
    newest_version_dir, release_tag, stale_version_dirs, version_dir, Arch, BinarySource, Os,
    RELEASE_REPOSITORY,
};
use zed_extension_api::settings::LspSettings;
use zed_extension_api::{
    self as zed, serde_json, Command, DownloadedFileType, LanguageServerId,
    LanguageServerInstallationStatus, Worktree,
};

/// Language server ID declared in `extension.toml`.
const SERVER_ID: &str = "secret-scanner-lsp";
/// The extension downloads the server release with exactly this version (FR-9).
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct SecretScannerExtension {
    cached_binary: Option<String>,
}

fn platform() -> (Os, Arch) {
    let (os, arch) = zed::current_platform();
    let os = match os {
        zed::Os::Mac => Os::Mac,
        zed::Os::Linux => Os::Linux,
        zed::Os::Windows => Os::Windows,
    };
    let arch = match arch {
        zed::Architecture::Aarch64 => Arch::Aarch64,
        zed::Architecture::X8664 => Arch::X86_64,
        zed::Architecture::X86 => Arch::X86,
    };
    (os, arch)
}

fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// Directory names in the extension work directory.
fn work_dir_entries() -> Vec<String> {
    std::fs::read_dir(".")
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn set_status(id: &LanguageServerId, status: LanguageServerInstallationStatus) {
    zed::set_language_server_installation_status(id, &status);
}

impl SecretScannerExtension {
    /// Uses the newest previously downloaded server when the release cannot be fetched.
    fn offline_fallback(
        &mut self,
        id: &LanguageServerId,
        os: Os,
        reason: &str,
    ) -> zed::Result<String> {
        let entries = work_dir_entries();
        if let Some(dir) = newest_version_dir(entries.iter().map(String::as_str)) {
            let path = format!("{dir}/{}", binary_file_name(os));
            if file_exists(&path) {
                set_status(id, LanguageServerInstallationStatus::None);
                self.cached_binary = Some(path.clone());
                return Ok(path);
            }
        }
        let message = install_hint(reason);
        set_status(
            id,
            LanguageServerInstallationStatus::Failed(message.clone()),
        );
        Err(message)
    }

    /// Downloads the release that matches [`VERSION`] and removes older cached versions.
    fn download(&mut self, id: &LanguageServerId, os: Os, arch: Arch) -> zed::Result<String> {
        let Some(asset_name) = asset_name(os, arch) else {
            return self.offline_fallback(id, os, "no prebuilt binary for this platform");
        };
        set_status(id, LanguageServerInstallationStatus::CheckingForUpdate);
        let release =
            match zed::github_release_by_tag_name(RELEASE_REPOSITORY, &release_tag(VERSION)) {
                Ok(release) => release,
                Err(err) => {
                    return self.offline_fallback(id, os, &format!("release lookup failed: {err}"))
                }
            };
        let Some(asset) = release.assets.iter().find(|a| a.name == asset_name) else {
            return self.offline_fallback(id, os, &format!("release has no asset {asset_name}"));
        };
        set_status(id, LanguageServerInstallationStatus::Downloading);
        let file_type = if asset_name.ends_with(".zip") {
            DownloadedFileType::Zip
        } else {
            DownloadedFileType::GzipTar
        };
        if let Err(err) = zed::download_file(&asset.download_url, &version_dir(VERSION), file_type)
        {
            return self.offline_fallback(id, os, &format!("download failed: {err}"));
        }
        let path = binary_rel_path(VERSION, os);
        if os != Os::Windows {
            zed::make_file_executable(&path)?;
        }
        if !file_exists(&path) {
            return self.offline_fallback(id, os, &format!("archive did not contain {path}"));
        }
        let entries = work_dir_entries();
        for stale in stale_version_dirs(entries.iter().map(String::as_str), VERSION) {
            let _ = std::fs::remove_dir_all(stale);
        }
        set_status(id, LanguageServerInstallationStatus::None);
        self.cached_binary = Some(path.clone());
        Ok(path)
    }
}

/// `lsp.secret-scanner-lsp.settings` (or an empty object) sent as init options and workspace config.
fn server_settings(worktree: &Worktree) -> serde_json::Value {
    LspSettings::for_worktree(SERVER_ID, worktree)
        .ok()
        .and_then(|s| s.settings)
        .unwrap_or_else(|| serde_json::json!({}))
}

impl zed::Extension for SecretScannerExtension {
    fn new() -> Self {
        SecretScannerExtension {
            cached_binary: None,
        }
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> zed::Result<Command> {
        let binary = LspSettings::for_worktree(SERVER_ID, worktree)
            .ok()
            .and_then(|s| s.binary);
        let configured = binary.as_ref().and_then(|b| b.path.clone());
        let args = binary
            .as_ref()
            .and_then(|b| b.arguments.clone())
            .unwrap_or_default();
        let env = binary
            .and_then(|b| b.env)
            .map(|env| env.into_iter().collect())
            .unwrap_or_default();

        let (os, arch) = platform();
        let current = binary_rel_path(VERSION, os);
        let cached = self
            .cached_binary
            .clone()
            .filter(|p| file_exists(p))
            .or_else(|| file_exists(&current).then_some(current));

        let command = match choose_binary_source(configured, &|name| worktree.which(name), cached) {
            BinarySource::Configured(path)
            | BinarySource::OnPath(path)
            | BinarySource::Cached(path) => path,
            BinarySource::Download => self.download(language_server_id, os, arch)?,
        };
        Ok(Command { command, args, env })
    }

    fn language_server_initialization_options(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> zed::Result<Option<serde_json::Value>> {
        Ok(Some(server_settings(worktree)))
    }

    fn language_server_workspace_configuration(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> zed::Result<Option<serde_json::Value>> {
        Ok(Some(server_settings(worktree)))
    }
}

zed::register_extension!(SecretScannerExtension);

#[cfg(test)]
mod tests {
    const MANIFEST: &str = include_str!("../extension.toml");

    fn manifest_lines() -> Vec<&'static str> {
        MANIFEST.lines().map(str::trim).collect()
    }

    /// Registry rules: kebab-case ID with the `-lsp` suffix, no slash commands or
    /// context servers, and the manifest version equals the crate version.
    #[test]
    fn manifest_follows_registry_rules() {
        let lines = manifest_lines();
        assert!(lines.contains(&"id = \"secret-scanner-lsp\""));
        assert!(lines.contains(&format!("version = \"{}\"", env!("CARGO_PKG_VERSION")).as_str()));
        assert!(lines.contains(&"[language_servers.secret-scanner-lsp]"));
        for required_lang in [
            "\"CSharp\",",
            "\"Docker\",",
            "\"ini\",",
            "\"Vue\",",
            "\"Shell Script\",",
            "\"Env\",",
            "\"dotenv\",",
        ] {
            assert!(
                lines.contains(&required_lang),
                "missing language {required_lang} in extension.toml"
            );
        }
        assert!(!MANIFEST.contains("[slash_commands"));
        assert!(!MANIFEST.contains("[context_servers"));
    }

    /// Capabilities stay scoped: downloads only, from this repository's releases
    /// and GitHub's release asset hosts; no process execution.
    #[test]
    fn capabilities_are_scoped() {
        assert!(!MANIFEST.contains("process:exec"));
        assert!(!MANIFEST.contains("host = \"*\""));
        let expected = r#"path = ["zed-extentions", "zed-secret-scanner", "releases", "**"]"#;
        assert!(MANIFEST.contains(expected));
        assert_eq!(MANIFEST.matches("[[capabilities]]").count(), 3);
    }
}
