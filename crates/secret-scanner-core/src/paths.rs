//! Path filtering for open documents and workspace scans (FR-8).

/// Directory names that are never scanned.
pub const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".turbo",
    "coverage",
    ".idea",
    ".gradle",
];

/// Lockfiles: integrity hashes would trip the entropy detector.
const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
    "flake.lock",
    "packages.lock.json",
];

/// Extensions of binary or generated files.
const SKIPPED_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tif", "tiff", "pdf", "zip", "gz", "tgz",
    "tar", "7z", "rar", "jar", "war", "class", "exe", "dll", "so", "dylib", "wasm", "o", "a",
    "lib", "bin", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "avi", "mkv", "webm",
    "pyc", "map", "lockb", "sqlite", "db",
];

/// `true` when `pattern` matches `text`. Supports `**` (any characters, including `/`),
/// `*` (any characters except `/`), and `?` (one character except `/`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') if p.get(1) == Some(&b'*') => {
                let mut rest = &p[2..];
                // `**/` also matches zero directories.
                if rest.first() == Some(&b'/') {
                    if go(&rest[1..], t) {
                        return true;
                    }
                    rest = &rest[1..];
                    return (0..t.len()).any(|i| t[i] == b'/' && go(rest, &t[i + 1..]));
                }
                (0..=t.len()).any(|i| go(rest, &t[i..]))
            }
            Some(b'*') => {
                let rest = &p[1..];
                let mut i = 0;
                loop {
                    if go(rest, &t[i..]) {
                        return true;
                    }
                    if i >= t.len() || t[i] == b'/' {
                        return false;
                    }
                    i += 1;
                }
            }
            Some(b'?') => !t.is_empty() && t[0] != b'/' && go(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Normalises a relative path to `/` separators without a leading `./`.
pub fn normalise(path: &str) -> String {
    let path = path.replace('\\', "/");
    path.strip_prefix("./").unwrap_or(&path).to_string()
}

/// `true` when the file at `relative_path` must not be scanned (FR-8).
///
/// Patterns without `/` match the file name; others match the whole relative path.
pub fn should_skip(relative_path: &str, ignore_patterns: &[String]) -> bool {
    let path = normalise(relative_path);
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some(file_name) = segments.pop() else {
        return true;
    };
    if segments.iter().any(|dir| SKIPPED_DIRS.contains(dir)) {
        return true;
    }
    let lower = file_name.to_ascii_lowercase();
    if LOCKFILES.contains(&lower.as_str()) {
        return true;
    }
    if lower.ends_with(".min.js") || lower.ends_with(".min.css") {
        return true;
    }
    if let Some((_, ext)) = lower.rsplit_once('.') {
        if SKIPPED_EXTENSIONS.contains(&ext) {
            return true;
        }
    }
    ignore_patterns.iter().any(|pattern| {
        let pattern = normalise(pattern);
        if pattern.contains('/') {
            glob_match(&pattern, &path)
        } else {
            glob_match(&pattern, file_name)
        }
    })
}

/// `true` when `sample` (the first bytes of a file) looks binary.
pub fn looks_binary(sample: &[u8]) -> bool {
    sample.contains(&0)
}

#[cfg(test)]
mod tests {
    use crate::paths::{glob_match, looks_binary, normalise, should_skip};

    #[test]
    fn glob_semantics() {
        assert!(glob_match("*.pem", "key.pem"));
        assert!(!glob_match("*.pem", "dir/key.pem"));
        assert!(glob_match("**/*.pem", "key.pem"));
        assert!(glob_match("**/*.pem", "a/b/key.pem"));
        assert!(glob_match("tests/**", "tests/fixtures/a.env"));
        assert!(glob_match(
            "**/fixtures/**",
            "crates/x/tests/fixtures/a.env"
        ));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "a/c"));
        assert!(!glob_match("src/*.rs", "src/a/b.rs"));
    }

    #[test]
    fn default_skips() {
        assert!(should_skip("node_modules/pkg/index.js", &[]));
        assert!(should_skip("a/.git/config", &[]));
        assert!(should_skip("Cargo.lock", &[]));
        assert!(should_skip("web/app.min.js", &[]));
        assert!(should_skip("img/logo.PNG", &[]));
        assert!(!should_skip("src/main.rs", &[]));
        assert!(!should_skip(".env", &[]));
    }

    #[test]
    fn user_patterns() {
        let patterns = vec!["**/fixtures/**".to_string(), "*.snap".to_string()];
        assert!(should_skip("tests/fixtures/leak.env", &patterns));
        assert!(should_skip("src/__snapshots__/a.snap", &patterns));
        assert!(!should_skip("src/config.rs", &patterns));
        assert_eq!(normalise(".\\src\\a.rs"), "src/a.rs");
        assert!(looks_binary(b"\x7fELF\0\0"));
        assert!(!looks_binary(b"plain text"));
    }
}
