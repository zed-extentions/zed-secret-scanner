//! Inline suppression markers and placeholder detection (FR-4).

/// Suppresses findings on the line that contains it.
pub const IGNORE_LINE_MARKER: &str = "secret-scanner-lsp:ignore";
/// Suppresses findings on the line that follows it.
pub const IGNORE_NEXT_LINE_MARKER: &str = "secret-scanner-lsp:ignore-next-line";
/// gitleaks' inline marker, honoured so existing annotations keep working.
pub const GITLEAKS_ALLOW_MARKER: &str = "gitleaks:allow";

/// `true` when `line` suppresses its own findings.
pub fn ignores_own_line(line: &str) -> bool {
    if line.contains(GITLEAKS_ALLOW_MARKER) {
        return true;
    }
    line.match_indices(IGNORE_LINE_MARKER)
        .any(|(start, marker)| !line[start + marker.len()..].starts_with("-next-line"))
}

/// `true` when `line` suppresses the findings of the next line.
pub fn ignores_next_line(line: &str) -> bool {
    line.contains(IGNORE_NEXT_LINE_MARKER)
}

/// Substrings (lowercase) that mark a value as an example, template, or reference.
const PLACEHOLDER_FRAGMENTS: &[&str] = &[
    "example",
    "xxxx",
    "****",
    "${",
    "{{",
    "<",
    "your_",
    "your-",
    "changeme",
    "change_me",
    "placeholder",
    "dummy",
    "redacted",
    "replace_me",
    "insert_",
    "process.env",
    "os.environ",
    "getenv",
];

/// `true` when `value` is a placeholder rather than a real secret (FR-4).
pub fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if PLACEHOLDER_FRAGMENTS.iter().any(|f| lower.contains(f)) {
        return true;
    }
    if value.starts_with('$') || value.starts_with('%') {
        return true;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use crate::allow::{ignores_next_line, ignores_own_line, is_placeholder};

    #[test]
    fn line_markers() {
        assert!(ignores_own_line("key = \"x\" # secret-scanner-lsp:ignore"));
        assert!(ignores_own_line("key = \"x\" // gitleaks:allow"));
        assert!(!ignores_own_line("# secret-scanner-lsp:ignore-next-line"));
        assert!(ignores_own_line(
            "# secret-scanner-lsp:ignore-next-line secret-scanner-lsp:ignore"
        ));
        assert!(ignores_next_line(
            "  // secret-scanner-lsp:ignore-next-line"
        ));
        assert!(!ignores_next_line("key = 1"));
    }

    #[test]
    fn placeholders() {
        for value in [
            "AKIAIOSFODNN7EXAMPLE",
            "${API_KEY}",
            "{{ secret }}",
            "<your-token>",
            "xxxxxxxxxxxx",
            "************",
            "$TOKEN",
            "%TOKEN%",
            "",
            "aaaaaaaa",
        ] {
            assert!(is_placeholder(value), "{value}");
        }
        assert!(!is_placeholder("q8Zt3LmN0vB7xR2kW5yP"));
    }
}
