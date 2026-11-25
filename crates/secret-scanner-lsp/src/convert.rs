//! Converts Tier 2 findings into LSP diagnostics and hover cards (FR-5).

use lsp_types::{
    Diagnostic, DiagnosticSeverity, Hover, HoverContents, MarkupContent, MarkupKind,
    NumberOrString, Position, Range,
};
use secret_scanner_core::config::{ScanConfig, Severity};
use secret_scanner_core::position::{byte_to_utf16_col, split_lines};
use secret_scanner_core::scanner::scan_text;

/// Diagnostic `source` of every finding.
pub const SOURCE: &str = "secret-scanner-lsp";

fn lsp_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Information => DiagnosticSeverity::INFORMATION,
        Severity::Hint => DiagnosticSeverity::HINT,
    }
}

/// Scans `text` and returns one diagnostic per finding, with UTF-16 positions.
pub fn diagnostics_for_text(text: &str, config: &ScanConfig) -> Vec<Diagnostic> {
    let lines = split_lines(text);
    scan_text(text, config)
        .into_iter()
        .map(|finding| {
            let line = lines.get(finding.line).copied().unwrap_or("");
            let line_no = finding.line as u32;
            Diagnostic {
                range: Range::new(
                    Position::new(line_no, byte_to_utf16_col(line, finding.range.start)),
                    Position::new(line_no, byte_to_utf16_col(line, finding.range.end)),
                ),
                severity: Some(lsp_severity(config.severity)),
                code: Some(NumberOrString::String(finding.rule_id.to_string())),
                source: Some(SOURCE.to_string()),
                message: finding.message(),
                ..Diagnostic::default()
            }
        })
        .collect()
}

/// Returns a masked Markdown hover card when `position` falls inside a finding.
pub fn hover_for_position(text: &str, position: Position, config: &ScanConfig) -> Option<Hover> {
    let lines = split_lines(text);
    let finding = scan_text(text, config).into_iter().find(|finding| {
        if finding.line as u32 != position.line {
            return false;
        }
        let line = lines.get(finding.line).copied().unwrap_or("");
        let start_col = byte_to_utf16_col(line, finding.range.start);
        let end_col = byte_to_utf16_col(line, finding.range.end);
        position.character >= start_col && position.character <= end_col
    })?;
    let line = lines.get(finding.line).copied().unwrap_or("");
    let line_no = finding.line as u32;
    let start_col = byte_to_utf16_col(line, finding.range.start);
    let end_col = byte_to_utf16_col(line, finding.range.end);
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: finding.hover_markdown(config.severity),
        }),
        range: Some(Range::new(
            Position::new(line_no, start_col),
            Position::new(line_no, end_col),
        )),
    })
}

#[cfg(test)]
mod tests {
    use lsp_types::{
        DiagnosticSeverity, HoverContents, MarkupKind, NumberOrString, Position, Range,
    };
    use secret_scanner_core::config::{ScanConfig, Severity};

    use crate::convert::{diagnostics_for_text, hover_for_position, SOURCE};

    #[test]
    fn positions_are_utf16_and_metadata_is_set() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let text = format!("x\n// é {token}\n");
        let config = ScanConfig {
            severity: Severity::Error,
            ..ScanConfig::default()
        };
        let diags = diagnostics_for_text(&text, &config);
        assert_eq!(diags.len(), 1);
        let d = &diags[0];
        assert_eq!(d.range.start, Position::new(1, 5));
        assert_eq!(d.range.end, Position::new(1, 45));
        assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(d.code, Some(NumberOrString::String("github-pat".into())));
        assert_eq!(d.source.as_deref(), Some(SOURCE));
        assert!(!d.message.contains(&token));
    }

    #[test]
    fn hover_returns_masked_markdown_only_within_finding_span() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let text = format!("clean line\n// é {token}\n");
        let config = ScanConfig::default();

        let hover = hover_for_position(&text, Position::new(1, 8), &config).expect("hover");
        assert_eq!(
            hover.range,
            Some(Range::new(Position::new(1, 5), Position::new(1, 45)))
        );
        let HoverContents::Markup(markup) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert_eq!(markup.kind, MarkupKind::Markdown);
        assert!(markup.value.contains("github-pat"));
        assert!(markup.value.contains("warning"));
        assert!(markup.value.contains("ghp_…(40 chars)"));
        assert!(markup.value.contains("Remediation"));
        assert!(!markup.value.contains(&token));

        assert!(hover_for_position(&text, Position::new(1, 0), &config).is_none());
        assert!(hover_for_position(&text, Position::new(0, 0), &config).is_none());

        let suppressed = format!("# secret-scanner-lsp:ignore-next-line\n// é {token}\n");
        assert!(hover_for_position(&suppressed, Position::new(1, 8), &config).is_none());
    }
}
