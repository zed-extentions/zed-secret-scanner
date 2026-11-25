//! Filesystem walking for workspace scans and the CLI (FR-10, FR-11).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use secret_scanner_core::config::ScanConfig;
use secret_scanner_core::paths::{looks_binary, should_skip, SKIPPED_DIRS};

/// Path of `path` relative to the first root that contains it, with `/` separators.
pub fn relative_to_roots(path: &Path, roots: &[PathBuf]) -> String {
    for root in roots {
        if let Ok(rel) = path.strip_prefix(root) {
            let rel = rel.to_string_lossy().replace('\\', "/");
            if !rel.is_empty() {
                return rel;
            }
        }
    }
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Collects scannable files under `roots`, at most `config.workspace_max_files`.
pub fn collect_files(roots: &[PathBuf], config: &ScanConfig) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(dir) = stack.pop() {
        if files.len() >= config.workspace_max_files {
            break;
        }
        if dir.is_file() {
            files.push(dir);
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if !SKIPPED_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
                continue;
            }
            let rel = relative_to_roots(&path, roots);
            if should_skip(&rel, &config.ignore_paths) {
                continue;
            }
            files.push(path);
            if files.len() >= config.workspace_max_files {
                break;
            }
        }
    }
    files
}

/// Reads `path` as UTF-8 text, or `None` when it is too large, binary, or unreadable.
pub fn read_text(path: &Path, max_size: u64) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > max_size {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    fs::File::open(path).ok()?.read_to_end(&mut bytes).ok()?;
    let sample = &bytes[..bytes.len().min(8192)];
    if looks_binary(sample) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use secret_scanner_core::config::ScanConfig;

    use crate::workspace::{collect_files, read_text, relative_to_roots};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "secret-scanner-lsp-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walks_skipping_default_and_user_patterns() {
        let root = temp_dir("walk");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(root.join("fixtures")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), "x").unwrap();
        fs::write(root.join("fixtures/a.env"), "x").unwrap();
        fs::write(root.join("Cargo.lock"), "x").unwrap();
        fs::write(root.join("logo.png"), [0u8, 1, 2]).unwrap();
        let config = ScanConfig {
            ignore_paths: vec!["fixtures/**".into()],
            ..ScanConfig::default()
        };
        let roots = vec![root.clone()];
        let files: Vec<String> = collect_files(&roots, &config)
            .iter()
            .map(|p| relative_to_roots(p, &roots))
            .collect();
        assert_eq!(files, vec!["src/main.rs".to_string()]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn respects_max_files_and_reads_text_only() {
        let root = temp_dir("limits");
        for i in 0..5 {
            fs::write(root.join(format!("f{i}.txt")), "text").unwrap();
        }
        fs::write(root.join("bin.dat"), [b'a', 0, b'b']).unwrap();
        let config = ScanConfig {
            workspace_max_files: 3,
            ..ScanConfig::default()
        };
        assert_eq!(collect_files(std::slice::from_ref(&root), &config).len(), 3);
        assert_eq!(
            read_text(&root.join("f0.txt"), 1024).as_deref(),
            Some("text")
        );
        assert_eq!(read_text(&root.join("f0.txt"), 2), None);
        assert_eq!(read_text(&root.join("bin.dat"), 1024), None);
        let _ = fs::remove_dir_all(&root);
    }
}
