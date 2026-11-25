//! Text scanner that applies every enabled rule to a document (FR-1..FR-5).

use std::ops::Range;

use crate::allow::{ignores_next_line, ignores_own_line, is_placeholder};
use crate::config::{ScanConfig, GENERIC_MAX_LINE_LENGTH};
use crate::entropy::find_generic_assignments;
use crate::mask::mask_secret;
use crate::position::split_lines;
use crate::rules::{find_matches, GENERIC_RULE_ID, GENERIC_RULE_TITLE, RULES};

/// One detected secret. Offsets are bytes within `line`'s text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    /// Zero-based line number.
    pub line: usize,
    /// Byte range of the secret within the line.
    pub range: Range<usize>,
    /// Masked form of the secret, safe to show (FR-5).
    pub masked: String,
}

impl Finding {
    /// Diagnostic message; never contains the raw secret.
    pub fn message(&self) -> String {
        format!(
            "{} detected ({}). Remove it from the source, rotate it, and load it from the environment or a secret manager.",
            self.title, self.masked
        )
    }

    /// Markdown hover card; never contains the raw secret.
    pub fn hover_markdown(&self, severity: crate::config::Severity) -> String {
        format!(
            "**{}** (`{}`)\n\n\
             - **Severity:** `{}`\n\
             - **Masked value:** `{}`\n\
             - **Remediation:** Remove the secret from source code, rotate/revoke it, and load it from environment variables or a secret manager.\n\
             - **False positive?** Press `Ctrl+.` to insert `secret-scanner-lsp:ignore-next-line`, or append `secret-scanner-lsp:ignore` on the same line.",
            self.title,
            self.rule_id,
            severity.as_str(),
            self.masked,
        )
    }
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Scans one line and appends its findings to `out`.
fn scan_line(line_no: usize, line: &str, config: &ScanConfig, out: &mut Vec<Finding>) {
    let first = out.len();
    for rule in RULES {
        if !config.rule_enabled(rule.id) {
            continue;
        }
        for range in find_matches(rule, line) {
            let secret = &line[range.clone()];
            if is_placeholder(secret) {
                continue;
            }
            if out[first..].iter().any(|f| overlaps(&f.range, &range)) {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id,
                title: rule.title,
                line: line_no,
                masked: mask_secret(secret),
                range,
            });
        }
    }
    let generic_allowed = config.entropy_enabled
        && config.rule_enabled(GENERIC_RULE_ID)
        && line.len() <= GENERIC_MAX_LINE_LENGTH;
    if generic_allowed {
        for range in
            find_generic_assignments(line, config.entropy_min_length, config.entropy_threshold)
        {
            if out[first..].iter().any(|f| overlaps(&f.range, &range)) {
                continue;
            }
            out.push(Finding {
                rule_id: GENERIC_RULE_ID,
                title: GENERIC_RULE_TITLE,
                line: line_no,
                masked: mask_secret(&line[range.clone()]),
                range,
            });
        }
    }
    out[first..].sort_by_key(|f| f.range.start);
}

/// Scans `text` and returns all findings in document order.
pub fn scan_text(text: &str, config: &ScanConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut skip_next = false;
    for (line_no, line) in split_lines(text).into_iter().enumerate() {
        let skip_this = std::mem::replace(&mut skip_next, ignores_next_line(line));
        if skip_this || ignores_own_line(line) {
            continue;
        }
        scan_line(line_no, line, config, &mut findings);
    }
    findings
}

#[cfg(test)]
mod tests {
    use crate::config::ScanConfig;
    use crate::scanner::scan_text;

    fn gh() -> String {
        format!("ghp_{}", "a1B2".repeat(9))
    }

    #[test]
    fn reports_rule_line_range_and_mask() {
        let text = format!("first\nTOKEN={}\n", gh());
        let findings = scan_text(&text, &ScanConfig::default());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "github-pat");
        assert_eq!(f.line, 1);
        assert_eq!(f.range, 6..46);
        assert_eq!(f.masked, "ghp_…(40 chars)");
        assert!(!f.message().contains(&gh()));

        let hover = f.hover_markdown(crate::config::Severity::Warning);
        assert!(hover.contains(f.title));
        assert!(hover.contains("`github-pat`"));
        assert!(hover.contains("`warning`"));
        assert!(hover.contains("`ghp_…(40 chars)`"));
        assert!(hover.contains("Remediation"));
        assert!(hover.contains("secret-scanner-lsp:ignore-next-line"));
        assert!(hover.contains("secret-scanner-lsp:ignore"));
        assert!(!hover.contains(&gh()));
    }

    #[test]
    fn specific_rule_wins_over_generic() {
        let text = format!("api_token = \"{}\"", gh());
        let findings = scan_text(&text, &ScanConfig::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "github-pat");
    }

    #[test]
    fn generic_detector_and_toggles() {
        let text = "DB_PASSWORD=q8Zt3LmN0vB7xR2kW5yP";
        assert_eq!(
            scan_text(text, &ScanConfig::default())[0].rule_id,
            "generic-api-key"
        );
        let no_entropy = ScanConfig {
            entropy_enabled: false,
            ..ScanConfig::default()
        };
        assert!(scan_text(text, &no_entropy).is_empty());
        let disabled = ScanConfig {
            disabled_rules: vec!["github-pat".into()],
            ..ScanConfig::default()
        };
        assert!(scan_text(&gh(), &disabled).is_empty());
    }

    #[test]
    fn inline_markers_suppress_findings() {
        let text = format!(
            "a = \"{gh}\" # secret-scanner-lsp:ignore\n# secret-scanner-lsp:ignore-next-line\nb = \"{gh}\"\nc = \"{gh}\"\nd = \"{gh}\" // gitleaks:allow",
            gh = gh()
        );
        let lines: Vec<usize> = scan_text(&text, &ScanConfig::default())
            .iter()
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, vec![3]);
    }

    #[test]
    fn placeholders_are_not_reported() {
        let text = format!(
            "AWS_ACCESS_KEY_ID=AKIA{}EXAMPLE\nAPI_KEY=${{API_KEY}}",
            "IOSFODNN7"
        );
        assert!(scan_text(&text, &ScanConfig::default()).is_empty());
    }

    #[test]
    fn multiple_findings_on_one_line_are_ordered() {
        let aws = format!("AKIA{}", "Q".repeat(16));
        let text = format!("{} {}", gh(), aws);
        let ids: Vec<&str> = scan_text(&text, &ScanConfig::default())
            .iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(ids, vec!["github-pat", "aws-access-token"]);
    }
}
