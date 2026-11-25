//! `secret-scanner-lsp` — Tier 3 native language server and CLI for `zed-secret-scanner`.
//!
//! * `secret-scanner-lsp` (no arguments, or `--stdio`): stdio LSP server that publishes
//!   hardcoded-secret diagnostics and "ignore" quick fixes (FR-5, FR-6, FR-10).
//! * `secret-scanner-lsp scan [--json] [PATH...]`: one-shot scan for terminals, Zed tasks,
//!   and CI; exits with status 1 when secrets are found (FR-11).
//!
//! Detection logic lives in the Tier 2 crate `secret-scanner-core`.

mod actions;
mod cli;
mod convert;
mod server;
mod settings;
mod workspace;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--stdio") => match server::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("secret-scanner-lsp: {err}");
                ExitCode::from(2)
            }
        },
        Some("scan") => cli::run(&args[1..]),
        Some("--version" | "-V") => {
            println!("secret-scanner-lsp {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!(
                "secret-scanner-lsp: unknown argument `{other}`\n\n{}",
                cli::USAGE
            );
            ExitCode::from(2)
        }
    }
}
