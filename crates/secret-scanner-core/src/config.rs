//! Scanner configuration (FR-7). JSON decoding lives in the Tier 3 server; this
//! module only defines the model and its defaults.

/// Diagnostic severity reported for findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Information,
    Hint,
}

impl Severity {
    /// Canonical lowercase label for this severity.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Information => "information",
            Severity::Hint => "hint",
        }
    }

    /// Parses `error`, `warning`, `information` / `info`, or `hint` (case-insensitive).
    pub fn parse(value: &str) -> Option<Severity> {
        match value.to_ascii_lowercase().as_str() {
            "error" => Some(Severity::Error),
            "warning" | "warn" => Some(Severity::Warning),
            "information" | "info" => Some(Severity::Information),
            "hint" => Some(Severity::Hint),
            _ => None,
        }
    }
}

/// Default minimum length of a generic secret value.
pub const DEFAULT_ENTROPY_MIN_LENGTH: usize = 12;
/// Default Shannon entropy threshold (bits per character), as in gitleaks' generic rule.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 3.5;
/// Files larger than this are not scanned (1 MiB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;
/// Upper bound of files visited by a workspace scan.
pub const DEFAULT_WORKSPACE_MAX_FILES: usize = 5000;
/// Lines longer than this (minified code) are only checked by the exact token rules.
pub const GENERIC_MAX_LINE_LENGTH: usize = 4096;

/// Effective scanner settings.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanConfig {
    /// Rule IDs that are never reported.
    pub disabled_rules: Vec<String>,
    pub severity: Severity,
    /// Enables the keyword + entropy detector (`generic-api-key`).
    pub entropy_enabled: bool,
    pub entropy_threshold: f64,
    pub entropy_min_length: usize,
    /// Extra glob patterns of files to skip, relative to the workspace root.
    pub ignore_paths: Vec<String>,
    pub max_file_size: u64,
    /// Scan every workspace file on startup and publish diagnostics for all of them.
    pub workspace_scan: bool,
    pub workspace_max_files: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            disabled_rules: Vec::new(),
            severity: Severity::Warning,
            entropy_enabled: true,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            entropy_min_length: DEFAULT_ENTROPY_MIN_LENGTH,
            ignore_paths: Vec::new(),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            workspace_scan: false,
            workspace_max_files: DEFAULT_WORKSPACE_MAX_FILES,
        }
    }
}

impl ScanConfig {
    /// `true` unless `rule_id` is listed in `disabled_rules`.
    pub fn rule_enabled(&self, rule_id: &str) -> bool {
        !self.disabled_rules.iter().any(|id| id == rule_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{ScanConfig, Severity};

    #[test]
    fn severity_parsing() {
        assert_eq!(Severity::parse("ERROR"), Some(Severity::Error));
        assert_eq!(Severity::parse("warn"), Some(Severity::Warning));
        assert_eq!(Severity::parse("info"), Some(Severity::Information));
        assert_eq!(Severity::parse("hint"), Some(Severity::Hint));
        assert_eq!(Severity::parse("loud"), None);
        assert_eq!(Severity::Error.as_str(), "error");
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Information.as_str(), "information");
        assert_eq!(Severity::Hint.as_str(), "hint");
    }

    #[test]
    fn defaults_and_rule_toggle() {
        let mut config = ScanConfig::default();
        assert_eq!(config.severity, Severity::Warning);
        assert!(config.entropy_enabled);
        assert!(!config.workspace_scan);
        assert!(config.rule_enabled("jwt"));
        config.disabled_rules.push("jwt".into());
        assert!(!config.rule_enabled("jwt"));
    }
}
