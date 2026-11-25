//! Language server binary resolution and release asset naming (FR-9).
//!
//! The Tier 1 extension maps Zed's platform enums onto [`Os`] / [`Arch`] and
//! performs the host calls; every decision is made here so it is unit tested.

/// Executable name of the Tier 3 server.
pub const BINARY_NAME: &str = "secret-scanner-lsp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Mac,
    Windows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    X86,
}

/// Release tag that matches the extension version (`0.1.0` → `v0.1.0`).
///
/// The extension downloads the server release with the same version instead of
/// the latest one, so an extension release always runs the server it was tested with.
pub fn release_tag(version: &str) -> String {
    format!("v{version}")
}

/// Release archive name for a platform, or `None` when no binary is published for it.
pub fn asset_name(os: Os, arch: Arch) -> Option<String> {
    let (os_name, ext) = match os {
        Os::Linux => ("linux", "tar.gz"),
        Os::Mac => ("darwin", "tar.gz"),
        Os::Windows => ("windows", "zip"),
    };
    let arch_name = match (os, arch) {
        (_, Arch::X86_64) => "x86_64",
        (Os::Windows, Arch::Aarch64) | (_, Arch::X86) => return None,
        (Os::Mac, Arch::Aarch64) => "arm64",
        (_, Arch::Aarch64) => "aarch64",
    };
    Some(format!("{BINARY_NAME}-{os_name}-{arch_name}.{ext}"))
}

/// Executable file name for a platform.
pub fn binary_file_name(os: Os) -> String {
    match os {
        Os::Windows => format!("{BINARY_NAME}.exe"),
        _ => BINARY_NAME.to_string(),
    }
}

/// Cache directory (relative to the extension work dir) for one server version.
pub fn version_dir(version: &str) -> String {
    format!("{BINARY_NAME}-{}", release_tag(version))
}

/// Path of the cached executable for one server version.
pub fn binary_rel_path(version: &str, os: Os) -> String {
    format!("{}/{}", version_dir(version), binary_file_name(os))
}

fn parse_version_dir(name: &str) -> Option<(u64, u64, u64)> {
    let version = name.strip_prefix(BINARY_NAME)?.strip_prefix("-v")?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Cached version directories other than `keep_version`, to be removed after a download.
pub fn stale_version_dirs<'a>(
    entries: impl IntoIterator<Item = &'a str>,
    keep_version: &str,
) -> Vec<String> {
    let keep = version_dir(keep_version);
    entries
        .into_iter()
        .filter(|name| *name != keep && parse_version_dir(name).is_some())
        .map(str::to_string)
        .collect()
}

/// Newest cached version directory, used as an offline fallback.
pub fn newest_version_dir<'a>(entries: impl IntoIterator<Item = &'a str>) -> Option<String> {
    entries
        .into_iter()
        .filter_map(|name| parse_version_dir(name).map(|v| (v, name)))
        .max_by_key(|(v, _)| *v)
        .map(|(_, name)| name.to_string())
}

/// Where the language server binary comes from, in resolution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinarySource {
    /// `lsp.secret-scanner-lsp.binary.path` from Zed settings.
    Configured(String),
    /// `secret-scanner-lsp` found on the worktree `PATH`.
    OnPath(String),
    /// Previously downloaded binary for the current version.
    Cached(String),
    /// Nothing local; download the release that matches the extension version.
    Download,
}

/// Chooses the binary source (FR-9): settings → `PATH` → cache → download.
pub fn choose_binary_source(
    configured: Option<String>,
    which: &dyn Fn(&str) -> Option<String>,
    cached: Option<String>,
) -> BinarySource {
    if let Some(path) = configured.filter(|p| !p.trim().is_empty()) {
        return BinarySource::Configured(path);
    }
    if let Some(path) = which(BINARY_NAME) {
        return BinarySource::OnPath(path);
    }
    match cached {
        Some(path) => BinarySource::Cached(path),
        None => BinarySource::Download,
    }
}

/// Error shown when no binary could be found or downloaded.
pub fn install_hint(reason: &str) -> String {
    format!(
        "secret-scanner-lsp is not available ({reason}). Install it with \
         `cargo install --git {REPOSITORY_URL} secret-scanner-lsp`, put it on PATH, or set \
         `lsp.secret-scanner-lsp.binary.path` in your Zed settings."
    )
}

/// GitHub repository (`owner/name`) that publishes the server releases.
///
/// The public snapshot export rewrites the private development organisation to
/// the public release organisation (see `.public-export`).
pub const RELEASE_REPOSITORY: &str = "zed-extentions/zed-secret-scanner";
const REPOSITORY_URL: &str = "https://github.com/zed-extentions/zed-secret-scanner";

#[cfg(test)]
mod tests {
    use crate::release::{
        asset_name, binary_file_name, binary_rel_path, choose_binary_source, install_hint,
        newest_version_dir, release_tag, stale_version_dirs, version_dir, Arch, BinarySource, Os,
    };

    #[test]
    fn asset_names_per_platform() {
        assert_eq!(
            asset_name(Os::Linux, Arch::X86_64).as_deref(),
            Some("secret-scanner-lsp-linux-x86_64.tar.gz")
        );
        assert_eq!(
            asset_name(Os::Linux, Arch::Aarch64).as_deref(),
            Some("secret-scanner-lsp-linux-aarch64.tar.gz")
        );
        assert_eq!(
            asset_name(Os::Mac, Arch::Aarch64).as_deref(),
            Some("secret-scanner-lsp-darwin-arm64.tar.gz")
        );
        assert_eq!(
            asset_name(Os::Mac, Arch::X86_64).as_deref(),
            Some("secret-scanner-lsp-darwin-x86_64.tar.gz")
        );
        assert_eq!(
            asset_name(Os::Windows, Arch::X86_64).as_deref(),
            Some("secret-scanner-lsp-windows-x86_64.zip")
        );
        assert_eq!(asset_name(Os::Windows, Arch::Aarch64), None);
        assert_eq!(asset_name(Os::Linux, Arch::X86), None);
    }

    #[test]
    fn versioned_cache_layout() {
        assert_eq!(release_tag("0.1.0"), "v0.1.0");
        assert_eq!(version_dir("0.1.0"), "secret-scanner-lsp-v0.1.0");
        assert_eq!(binary_file_name(Os::Windows), "secret-scanner-lsp.exe");
        assert_eq!(
            binary_rel_path("0.1.0", Os::Linux),
            "secret-scanner-lsp-v0.1.0/secret-scanner-lsp"
        );
    }

    #[test]
    fn stale_and_newest_dirs() {
        let entries = [
            "secret-scanner-lsp-v0.1.0",
            "secret-scanner-lsp-v0.10.0",
            "secret-scanner-lsp-v0.2.0",
            "other",
            "secret-scanner-lsp-vbad",
        ];
        assert_eq!(
            stale_version_dirs(entries, "0.2.0"),
            vec![
                "secret-scanner-lsp-v0.1.0".to_string(),
                "secret-scanner-lsp-v0.10.0".to_string()
            ]
        );
        assert_eq!(
            newest_version_dir(entries).as_deref(),
            Some("secret-scanner-lsp-v0.10.0")
        );
        assert_eq!(newest_version_dir(["other"]), None);
    }

    #[test]
    fn resolution_order() {
        let on_path = |_: &str| Some("/usr/bin/secret-scanner-lsp".to_string());
        let missing = |_: &str| None;
        assert_eq!(
            choose_binary_source(Some("/opt/s".into()), &on_path, None),
            BinarySource::Configured("/opt/s".into())
        );
        assert_eq!(
            choose_binary_source(Some("  ".into()), &on_path, None),
            BinarySource::OnPath("/usr/bin/secret-scanner-lsp".into())
        );
        assert_eq!(
            choose_binary_source(None, &missing, Some("c".into())),
            BinarySource::Cached("c".into())
        );
        assert_eq!(
            choose_binary_source(None, &missing, None),
            BinarySource::Download
        );
        assert!(install_hint("offline").contains("lsp.secret-scanner-lsp.binary.path"));
    }
}
