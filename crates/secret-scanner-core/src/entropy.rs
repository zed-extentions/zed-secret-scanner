//! Keyword + entropy detector for generic secret assignments (FR-3).
//!
//! Finds `key <op> value` pairs whose key names a credential (`api_key`,
//! `password`, `client_secret`, ...) and whose value is long and random enough to
//! be a real secret rather than a reference or placeholder.

use std::ops::Range;

use crate::allow::is_placeholder;

/// Key fragments (normalised to lowercase, `-`/`.` replaced by `_`) that name a credential.
const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "auth_key",
    "access_key",
    "private_key",
    "credential",
    "bearer",
];

/// Key suffixes that describe metadata about a credential rather than the credential itself.
const NON_SECRET_KEY_SUFFIXES: &[&str] = &[
    "_url",
    "_uri",
    "_path",
    "_file",
    "_dir",
    "_name",
    "_id",
    "_type",
    "_length",
    "_len",
    "_expiry",
    "_expires",
    "_expires_at",
    "_ttl",
    "_header",
    "_endpoint",
    "_field",
    "_count",
    "_enabled",
    "_policy",
    "_hash",
    "_prompt",
    "_label",
    "_placeholder",
];

/// Shannon entropy of `s` in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn normalise_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '-' | '.' => '_',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// `true` when `key` names a credential (FR-3).
pub fn is_secret_key(key: &str) -> bool {
    let normalised = normalise_key(key);
    if normalised.contains("tokenizer") {
        return false;
    }
    if NON_SECRET_KEY_SUFFIXES
        .iter()
        .any(|suffix| normalised.ends_with(suffix))
    {
        return false;
    }
    // camelCase keys such as `clientSecret` are lowercased to `clientsecret`, which still
    // contains `secret`; `apiKey` becomes `apikey`.
    SECRET_KEYWORDS
        .iter()
        .any(|keyword| normalised.contains(keyword))
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// Extracts the key that ends just before `op_start`, skipping whitespace and one quote.
fn key_before(line: &str, op_start: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut end = op_start;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let quote = if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
        end -= 1;
        Some(bytes[end])
    } else {
        None
    };
    let mut start = end;
    while start > 0 && is_key_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    if let Some(q) = quote {
        if start == 0 || bytes[start - 1] != q {
            return None;
        }
    }
    Some(&line[start..end])
}

/// Parses the value that starts at or after `from`, returning its byte range without quotes.
fn value_after(line: &str, from: usize) -> Option<(Range<usize>, bool)> {
    let bytes = line.as_bytes();
    let mut start = from;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let first = *bytes.get(start)?;
    if matches!(first, b'"' | b'\'' | b'`') {
        let content_start = start + 1;
        let len = bytes[content_start..]
            .iter()
            .position(|b| *b == first)
            .unwrap_or(bytes.len() - content_start);
        return Some((content_start..content_start + len, true));
    }
    // An escaped quote (`\"value\"`) inside an outer string literal, e.g. test code.
    if first == b'\\' && matches!(bytes.get(start + 1), Some(b'"' | b'\'')) {
        let quote = bytes[start + 1];
        let content_start = start + 2;
        let len = bytes[content_start..]
            .windows(2)
            .position(|w| w[0] == b'\\' && w[1] == quote)
            .unwrap_or(bytes.len() - content_start);
        return Some((content_start..content_start + len, true));
    }
    let len = bytes[start..]
        .iter()
        .take_while(|b| {
            !b.is_ascii_whitespace() && !matches!(**b, b',' | b';' | b')' | b'}' | b']' | b'\\')
        })
        .count();
    Some((start..start + len, false))
}

/// `true` when a value is prose or a pattern rather than a credential: it contains
/// whitespace, an alternation or escape, or a bracket pair (regexes, grammar notes).
fn looks_like_text_or_pattern(value: &str) -> bool {
    let has_pair = |open: char, close: char| value.contains(open) && value.contains(close);
    value.contains(char::is_whitespace)
        || value.contains(['|', '\\'])
        || has_pair('[', ']')
        || has_pair('{', '}')
}

/// `true` when a bare (unquoted) value looks like code rather than a literal.
fn looks_like_code(value: &str) -> bool {
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
    value.contains('(')
        || value.starts_with(['[', '{', '$', '%', '&', '*'])
        || !(has_digit && has_alpha)
}

/// Finds generic credential assignments in `line` (FR-3).
///
/// Returns the byte ranges of the values (quotes excluded).
pub fn find_generic_assignments(
    line: &str,
    min_length: usize,
    threshold: f64,
) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found: Vec<Range<usize>> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let (op_start, value_from) = match b {
            b'=' => {
                let prev = if i > 0 { bytes[i - 1] } else { b' ' };
                let next = bytes.get(i + 1).copied().unwrap_or(b' ');
                if matches!(prev, b'=' | b'!' | b'<' | b'>') || next == b'=' {
                    i += 1;
                    continue;
                }
                // `:=`, `?=`, `+=` share the key on their left.
                let op_start = if i > 0 && matches!(prev, b':' | b'?' | b'+') {
                    i - 1
                } else {
                    i
                };
                let value_from = if next == b'>' { i + 2 } else { i + 1 };
                (op_start, value_from)
            }
            b':' => {
                let prev = if i > 0 { bytes[i - 1] } else { b' ' };
                let next = bytes.get(i + 1).copied().unwrap_or(b' ');
                if prev == b':' || next == b':' || next == b'=' || line[i..].starts_with("://") {
                    i += 1;
                    continue;
                }
                (i, i + 1)
            }
            _ => {
                i += 1;
                continue;
            }
        };
        i += 1;
        let Some(key) = key_before(line, op_start) else {
            continue;
        };
        if !is_secret_key(key) {
            continue;
        }
        let Some((range, quoted)) = value_after(line, value_from) else {
            continue;
        };
        let value = &line[range.clone()];
        if value.len() < min_length || is_placeholder(value) || looks_like_text_or_pattern(value) {
            continue;
        }
        if !quoted && looks_like_code(value) {
            continue;
        }
        if shannon_entropy(value) < threshold {
            continue;
        }
        if found
            .iter()
            .any(|r| r.start < range.end && range.start < r.end)
        {
            continue;
        }
        found.push(range);
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::entropy::{find_generic_assignments, is_secret_key, shannon_entropy};

    fn values(line: &str) -> Vec<&str> {
        find_generic_assignments(line, 12, 3.5)
            .into_iter()
            .map(|r| &line[r])
            .collect()
    }

    #[test]
    fn entropy_of_known_strings() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
        assert!(shannon_entropy("q8Zt3LmN0vB7xR2kW5yP") > 4.0);
    }

    #[test]
    fn secret_key_names() {
        for key in [
            "api_key",
            "API-KEY",
            "apiKey",
            "clientSecret",
            "DB_PASSWORD",
            "auth.token",
            "x-api-key",
        ] {
            assert!(is_secret_key(key), "{key}");
        }
        for key in [
            "token_url",
            "password_hash",
            "tokenizer",
            "secret_name",
            "client_id",
            "name",
        ] {
            assert!(!is_secret_key(key), "{key}");
        }
    }

    #[test]
    fn detects_assignments_in_common_syntaxes() {
        let v = "q8Zt3LmN0vB7xR2kW5yP";
        assert_eq!(values(&format!("API_KEY={v}")), vec![v]);
        assert_eq!(values(&format!("api_key = \"{v}\"")), vec![v]);
        assert_eq!(values(&format!("\"apiKey\": \"{v}\",")), vec![v]);
        assert_eq!(values(&format!("password: {v}")), vec![v]);
        assert_eq!(values(&format!("token := \"{v}\"")), vec![v]);
        assert_eq!(values(&format!("'secret' => '{v}',")), vec![v]);
        assert_eq!(values(&format!("const clientSecret = `{v}`;")), vec![v]);
    }

    #[test]
    fn ignores_references_placeholders_and_low_entropy() {
        assert!(values("password = os.environ[\"DB_PASSWORD\"]").is_empty());
        assert!(values("api_key = get_api_key()").is_empty());
        assert!(values("API_KEY=${API_KEY}").is_empty());
        assert!(values("password: \"changeme-changeme\"").is_empty());
        assert!(values("token = \"aaaaaaaaaaaaaaaaaaaa\"").is_empty());
        assert!(values("secret = \"short1\"").is_empty());
        assert!(values("if password == \"q8Zt3LmN0vB7xR2kW5yP\" {").is_empty());
        assert!(values("token_url = \"https://q8Zt3LmN0vB7xR2kW5yP.example\"").is_empty());
        assert!(values("password = user_password").is_empty());
    }

    /// Regressions found by scanning the sibling extension repositories.
    #[test]
    fn regexes_prose_and_escaped_quotes() {
        assert!(values("secret_re='ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}'").is_empty());
        assert!(values("/// Number token: `-? (0 | [1-9][0-9]*) (. [0-9]+)?`").is_empty());
        let escaped = r#"let s = "token = \"q8Zt3LmN0vB7xR2kW5yP\"";"#;
        assert_eq!(values(escaped), vec!["q8Zt3LmN0vB7xR2kW5yP"]);
        let embedded = r#""API_KEY=q8Zt3LmN0vB7xR2kW5yP\nNEXT=1""#;
        assert_eq!(values(embedded), vec!["q8Zt3LmN0vB7xR2kW5yP"]);
    }
}
