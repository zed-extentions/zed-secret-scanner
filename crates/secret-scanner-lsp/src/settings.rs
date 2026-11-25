//! Decodes `lsp.secret-scanner-lsp.settings` JSON into [`ScanConfig`] (FR-7).

use secret_scanner_core::config::{ScanConfig, Severity};
use serde_json::Value;

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    Some(
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    )
}

/// Builds a [`ScanConfig`] from the settings object; missing or invalid keys keep defaults.
pub fn parse_config(value: Option<&Value>) -> ScanConfig {
    let mut config = ScanConfig::default();
    let Some(object) = value.and_then(Value::as_object) else {
        return config;
    };
    if let Some(rules) = string_list(object.get("disabledRules")) {
        config.disabled_rules = rules;
    }
    if let Some(severity) = object
        .get("severity")
        .and_then(Value::as_str)
        .and_then(Severity::parse)
    {
        config.severity = severity;
    }
    if let Some(entropy) = object.get("entropy").and_then(Value::as_object) {
        if let Some(enabled) = entropy.get("enabled").and_then(Value::as_bool) {
            config.entropy_enabled = enabled;
        }
        if let Some(threshold) = entropy.get("threshold").and_then(Value::as_f64) {
            if threshold.is_finite() && threshold >= 0.0 {
                config.entropy_threshold = threshold;
            }
        }
        if let Some(min) = entropy.get("minLength").and_then(Value::as_u64) {
            config.entropy_min_length = min as usize;
        }
    }
    if let Some(patterns) = string_list(object.get("ignorePaths")) {
        config.ignore_paths = patterns;
    }
    if let Some(size) = object.get("maxFileSize").and_then(Value::as_u64) {
        config.max_file_size = size;
    }
    if let Some(scan) = object.get("workspaceScan").and_then(Value::as_object) {
        if let Some(enabled) = scan.get("enabled").and_then(Value::as_bool) {
            config.workspace_scan = enabled;
        }
        if let Some(max) = scan.get("maxFiles").and_then(Value::as_u64) {
            config.workspace_max_files = max as usize;
        }
    }
    config
}

#[cfg(test)]
mod tests {
    use secret_scanner_core::config::{ScanConfig, Severity};
    use serde_json::json;

    use crate::settings::parse_config;

    #[test]
    fn missing_or_non_object_settings_use_defaults() {
        assert_eq!(parse_config(None), ScanConfig::default());
        assert_eq!(parse_config(Some(&json!(null))), ScanConfig::default());
        assert_eq!(parse_config(Some(&json!([1, 2]))), ScanConfig::default());
    }

    #[test]
    fn full_settings_object() {
        let config = parse_config(Some(&json!({
            "disabledRules": ["jwt", 3],
            "severity": "error",
            "entropy": {"enabled": false, "threshold": 4.0, "minLength": 20},
            "ignorePaths": ["**/fixtures/**"],
            "maxFileSize": 2048,
            "workspaceScan": {"enabled": true, "maxFiles": 10}
        })));
        assert_eq!(config.disabled_rules, vec!["jwt".to_string()]);
        assert_eq!(config.severity, Severity::Error);
        assert!(!config.entropy_enabled);
        assert_eq!(config.entropy_threshold, 4.0);
        assert_eq!(config.entropy_min_length, 20);
        assert_eq!(config.ignore_paths, vec!["**/fixtures/**".to_string()]);
        assert_eq!(config.max_file_size, 2048);
        assert!(config.workspace_scan);
        assert_eq!(config.workspace_max_files, 10);
    }

    #[test]
    fn invalid_values_are_ignored() {
        let config = parse_config(Some(
            &json!({"severity": "loud", "entropy": {"threshold": -1.0}}),
        ));
        assert_eq!(config.severity, Severity::Warning);
        assert_eq!(
            config.entropy_threshold,
            ScanConfig::default().entropy_threshold
        );
    }
}
