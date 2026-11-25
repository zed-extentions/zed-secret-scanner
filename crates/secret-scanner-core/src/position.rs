//! Line splitting and UTF-16 column conversion for LSP positions (FR-5).

/// Splits `text` into lines without their `\n` / `\r\n` terminators.
///
/// A trailing newline does not produce an extra empty line.
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Converts a byte offset within `line` to an LSP UTF-16 column.
pub fn byte_to_utf16_col(line: &str, byte: usize) -> u32 {
    let byte = byte.min(line.len());
    line[..byte].chars().map(|c| c.len_utf16() as u32).sum()
}

/// Number of UTF-16 code units in `line`.
pub fn utf16_len(line: &str) -> u32 {
    byte_to_utf16_col(line, line.len())
}

/// Leading whitespace of `line`.
pub fn indentation(line: &str) -> &str {
    let len = line.len() - line.trim_start().len();
    &line[..len]
}

#[cfg(test)]
mod tests {
    use crate::position::{byte_to_utf16_col, indentation, split_lines, utf16_len};

    #[test]
    fn splits_lf_and_crlf() {
        assert_eq!(split_lines("a\r\nb\nc"), vec!["a", "b", "c"]);
        assert_eq!(split_lines("a\n"), vec!["a"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
    }

    #[test]
    fn utf16_columns() {
        let line = "é😀x";
        assert_eq!(byte_to_utf16_col(line, 0), 0);
        assert_eq!(byte_to_utf16_col(line, 2), 1);
        assert_eq!(byte_to_utf16_col(line, 6), 3);
        assert_eq!(utf16_len(line), 4);
        assert_eq!(indentation("    key"), "    ");
        assert_eq!(indentation("\tkey"), "\t");
    }
}
