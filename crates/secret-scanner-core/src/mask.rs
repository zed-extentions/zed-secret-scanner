//! Secret masking for messages (FR-5). Raw secret values never leave the scanner.

/// Number of leading characters kept visible at most.
const MAX_VISIBLE: usize = 4;

/// Masks `secret`, keeping at most four leading characters (and never more than a
/// quarter of the value), e.g. `ghp_…(40 chars)`.
pub fn mask_secret(secret: &str) -> String {
    let len = secret.chars().count();
    let visible = (len / 4).min(MAX_VISIBLE);
    let head: String = secret.chars().take(visible).collect();
    format!("{head}…({len} chars)")
}

#[cfg(test)]
mod tests {
    use crate::mask::mask_secret;

    #[test]
    fn masks_long_and_short_values() {
        assert_eq!(
            mask_secret(&format!("ghp_{}", "a".repeat(36))),
            "ghp_…(40 chars)"
        );
        assert_eq!(mask_secret("abcdefgh"), "ab…(8 chars)");
        assert_eq!(mask_secret("abc"), "…(3 chars)");
        assert_eq!(mask_secret("pässwörd1234"), "päs…(12 chars)");
    }
}
