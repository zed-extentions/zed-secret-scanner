//! `secret-scanner-lsp scan` command-line interface (FR-11).

use std::path::PathBuf;
use std::process::ExitCode;

use secret_scanner_core::config::ScanConfig;
use secret_scanner_core::paths::normalise;
use secret_scanner_core::position::{byte_to_utf16_col, split_lines};
use secret_scanner_core::scanner::{scan_text, Finding};
use serde_json::json;

use crate::workspace::{collect_files, read_text};

pub const USAGE: &str = "\
Usage:
  secret-scanner-lsp                 Run the language server on stdin/stdout
  secret-scanner-lsp scan [--json] [--no-entropy] [--max-files N] [PATH...]
                              Scan files or directories (default: .) and print findings.
                              Exit status: 0 = clean, 1 = secrets found, 2 = usage error.
  secret-scanner-lsp --version";

struct Options {
    json: bool,
    config: ScanConfig,
    paths: Vec<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        json: false,
        config: ScanConfig {
            workspace_max_files: usize::MAX,
            ..ScanConfig::default()
        },
        paths: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => options.json = true,
            "--no-entropy" => options.config.entropy_enabled = false,
            "--max-files" => {
                let value = iter.next().ok_or("--max-files needs a number")?;
                options.config.workspace_max_files = value
                    .parse()
                    .map_err(|_| format!("invalid --max-files value `{value}`"))?;
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option `{flag}`")),
            path => options.paths.push(PathBuf::from(path)),
        }
    }
    if options.paths.is_empty() {
        options.paths.push(PathBuf::from("."));
    }
    Ok(options)
}

/// One finding with its file and 1-based UTF-16 column, ready to print.
struct Reported {
    path: String,
    line: usize,
    column: u32,
    finding: Finding,
}

fn render_text(reported: &[Reported]) -> String {
    reported
        .iter()
        .map(|r| {
            format!(
                "{}:{}:{}: [{}] {}\n",
                r.path,
                r.line + 1,
                r.column,
                r.finding.rule_id,
                r.finding.message()
            )
        })
        .collect()
}

fn render_json(reported: &[Reported]) -> String {
    let items: Vec<_> = reported
        .iter()
        .map(|r| {
            json!({
                "path": r.path,
                "line": r.line + 1,
                "column": r.column,
                "rule": r.finding.rule_id,
                "title": r.finding.title,
                "masked": r.finding.masked,
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
}

/// Runs `secret-scanner-lsp scan` with the arguments that follow `scan`.
pub fn run(args: &[String]) -> ExitCode {
    let options = match parse_args(args) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("secret-scanner-lsp scan: {err}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let roots = options.paths.clone();
    for root in &roots {
        if !root.exists() {
            eprintln!(
                "secret-scanner-lsp scan: path does not exist: {}",
                root.display()
            );
            return ExitCode::from(2);
        }
    }
    let mut reported = Vec::new();
    let files = collect_files(&roots, &options.config);
    for path in &files {
        let Some(text) = read_text(path, options.config.max_file_size) else {
            continue;
        };
        let lines = split_lines(&text);
        // Paths are shown as reached from the arguments, so results from several
        // roots stay distinguishable (`repo-a/src/x.rs`, `repo-b/src/x.rs`).
        let display = normalise(&path.to_string_lossy());
        for finding in scan_text(&text, &options.config) {
            let line = lines.get(finding.line).copied().unwrap_or("");
            reported.push(Reported {
                path: display.clone(),
                line: finding.line,
                column: byte_to_utf16_col(line, finding.range.start) + 1,
                finding,
            });
        }
    }
    if options.json {
        println!("{}", render_json(&reported));
    } else {
        print!("{}", render_text(&reported));
    }
    eprintln!(
        "secret-scanner-lsp: {} finding(s) in {} file(s) scanned",
        reported.len(),
        files.len()
    );
    if reported.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use secret_scanner_core::config::ScanConfig;
    use secret_scanner_core::scanner::scan_text;

    use crate::cli::{parse_args, render_json, render_text, run, Reported};

    #[test]
    fn missing_path_exits_with_usage_error() {
        let missing = std::env::temp_dir().join(format!(
            "secret-scanner-lsp-definitely-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        let code = run(&[missing.to_string_lossy().into_owned()]);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn parses_flags_and_default_path() {
        let options = parse_args(&["--json".into(), "--no-entropy".into()]).unwrap();
        assert!(options.json);
        assert!(!options.config.entropy_enabled);
        assert_eq!(options.paths.len(), 1);
        assert!(parse_args(&["--bogus".into()]).is_err());
        assert!(parse_args(&["--max-files".into(), "x".into()]).is_err());
    }

    #[test]
    fn renders_masked_text_and_json() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let finding = scan_text(&token, &ScanConfig::default()).remove(0);
        let reported = vec![Reported {
            path: "src/a.rs".into(),
            line: 0,
            column: 1,
            finding,
        }];
        let text = render_text(&reported);
        assert!(text.starts_with("src/a.rs:1:1: [github-pat] "));
        assert!(!text.contains(&token));
        let json = render_json(&reported);
        assert!(json.contains("\"rule\": \"github-pat\""));
        assert!(!json.contains(&token));
    }
}
