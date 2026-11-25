//! End-to-end JSON-RPC test: spawns the real `secret-scanner-lsp` binary and drives it like
//! an editor would (NFR-4). This catches "the command is not actually an LSP"
//! failures that unit tests cannot see.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

struct Client {
    child: Child,
    stdin: ChildStdin,
    messages: Receiver<Value>,
    next_id: i64,
}

fn read_message(reader: &mut BufReader<ChildStdout>) -> Option<Value> {
    let mut length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.strip_prefix("Content-Length: ") {
            length = value.parse::<usize>().ok();
        }
    }
    let mut body = vec![0; length?];
    reader.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

impl Client {
    fn start() -> Client {
        let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner-lsp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn secret-scanner-lsp");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = channel();
        thread::spawn(move || {
            while let Some(message) = read_message(&mut stdout) {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });
        Client {
            child,
            stdin,
            messages: rx,
            next_id: 1,
        }
    }

    fn send(&mut self, message: Value) {
        let body = message.to_string();
        write!(self.stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
        self.stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let message = self.recv();
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
    }

    fn recv(&self) -> Value {
        self.messages
            .recv_timeout(Duration::from_secs(10))
            .expect("server message within 10s")
    }

    /// Waits for the server to exit, killing it after 10 seconds so a hang fails fast.
    fn wait_exit(&mut self) -> std::process::ExitStatus {
        for _ in 0..100 {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("server did not exit within 10s after `exit`");
    }

    fn diagnostics_for(&self, uri: &str) -> Vec<Value> {
        loop {
            let message = self.recv();
            if message["method"] == "textDocument/publishDiagnostics"
                && message["params"]["uri"] == uri
            {
                return message["params"]["diagnostics"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
            }
        }
    }
}

#[test]
fn initialize_diagnose_quick_fix_and_shutdown() {
    let mut client = Client::start();
    let init = client.request(
        "initialize",
        json!({
            "processId": null,
            "rootUri": null,
            "capabilities": {},
            "initializationOptions": {"severity": "error"}
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "secret-scanner-lsp");
    assert_eq!(
        init["result"]["capabilities"]["textDocumentSync"]["change"],
        1
    );
    assert_eq!(init["result"]["capabilities"]["hoverProvider"], true);
    client.notify("initialized", json!({}));

    let uri = "file:///workspace/app.py";
    let token = format!("ghp_{}", "a1B2".repeat(9));
    let text = format!("def connect():\n    token = \"{token}\"\n");
    client.notify(
        "textDocument/didOpen",
        json!({"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": text}}),
    );
    let diagnostics = client.diagnostics_for(uri);
    assert_eq!(diagnostics.len(), 1);
    let diagnostic = &diagnostics[0];
    assert_eq!(diagnostic["code"], "github-pat");
    assert_eq!(diagnostic["severity"], 1);
    assert_eq!(
        diagnostic["range"]["start"],
        json!({"line": 1, "character": 13})
    );
    assert!(!diagnostic["message"].as_str().unwrap().contains(&token));

    let hover = client.request(
        "textDocument/hover",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 1, "character": 16}
        }),
    );
    let hover_text = hover["result"]["contents"]["value"].as_str().unwrap();
    assert!(hover_text.contains("github-pat"));
    assert!(hover_text.contains("error"));
    assert!(hover_text.contains("ghp_…(40 chars)"));
    assert!(hover_text.contains("Remediation"));
    assert!(!hover_text.contains(&token));

    let no_hover = client.request(
        "textDocument/hover",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 0, "character": 0}
        }),
    );
    assert!(no_hover["result"].is_null());

    let actions = client.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri},
            "range": diagnostic["range"],
            "context": {"diagnostics": [diagnostic]}
        }),
    );
    let edit = &actions["result"][0]["edit"]["changes"][uri][0];
    assert_eq!(
        edit["newText"],
        "    # secret-scanner-lsp:ignore-next-line\n"
    );
    let inline_edit = &actions["result"][1]["edit"]["changes"][uri][0];
    assert_eq!(inline_edit["newText"], " # secret-scanner-lsp:ignore");

    // Applying the edit and re-sending the document clears the diagnostic.
    let fixed = format!(
        "def connect():\n    # secret-scanner-lsp:ignore-next-line\n    token = \"{token}\"\n"
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": fixed}]}),
    );
    assert!(client.diagnostics_for(uri).is_empty());

    // Settings pushed by Zed take effect immediately.
    client.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": {"disabledRules": ["github-pat"]}}),
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument": {"uri": uri, "version": 3}, "contentChanges": [{"text": text}]}),
    );
    assert!(client.diagnostics_for(uri).is_empty());

    client.notify(
        "textDocument/didClose",
        json!({"textDocument": {"uri": uri}}),
    );
    assert!(client.diagnostics_for(uri).is_empty());

    let shutdown = client.request("shutdown", json!(null));
    assert!(shutdown.get("error").is_none());
    client.notify("exit", json!(null));
    let status = client.wait_exit();
    assert!(status.success());
}

#[test]
fn unknown_requests_get_method_not_found() {
    let mut client = Client::start();
    client.request(
        "initialize",
        json!({"processId": null, "rootUri": null, "capabilities": {}}),
    );
    client.notify("initialized", json!({}));
    let response = client.request("textDocument/definition", json!({}));
    assert_eq!(response["error"]["code"], -32601);
    client.request("shutdown", json!(null));
    client.notify("exit", json!(null));
    assert!(client.wait_exit().success());
}

#[test]
fn scan_cli_reports_and_sets_exit_code() {
    let dir = std::env::temp_dir().join(format!("secret-scanner-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("clean.txt"), "nothing here").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_secret-scanner-lsp"))
        .args(["scan", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    let token = format!("AKIA{}", "Q".repeat(16));
    std::fs::write(dir.join("leak.env"), format!("AWS_ACCESS_KEY_ID={token}\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_secret-scanner-lsp"))
        .args(["scan", "--json", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert!(report[0]["path"].as_str().unwrap().ends_with("/leak.env"));
    assert_eq!(report[0]["rule"], "aws-access-token");
    assert_eq!(report[0]["line"], 1);
    assert_eq!(report[0]["column"], 19);
    assert!(!stdout.contains(&token));

    let missing = dir.join("does-not-exist.env");
    let missing_output = Command::new(env!("CARGO_BIN_EXE_secret-scanner-lsp"))
        .args(["scan", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(missing_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_output.stderr).contains("path does not exist"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn workspace_scan_publishes_and_clears_when_disabled() {
    let dir = std::env::temp_dir().join(format!("secret-scanner-ws-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let token = format!("ghp_{}", "c3D4".repeat(9));
    let leak_path = dir.join("config.env");
    std::fs::write(&leak_path, format!("TOKEN={token}\n")).unwrap();

    let root_uri = lsp_types::Url::from_file_path(&dir).unwrap().to_string();
    let leak_uri = lsp_types::Url::from_file_path(&leak_path)
        .unwrap()
        .to_string();

    let mut client = Client::start();
    client.request(
        "initialize",
        json!({
            "processId": null,
            "rootUri": root_uri,
            "capabilities": {},
            "initializationOptions": {"workspaceScan": {"enabled": true, "maxFiles": 100}}
        }),
    );
    client.notify("initialized", json!({}));

    let diags = client.diagnostics_for(&leak_uri);
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["code"], "github-pat");

    // Disabling workspaceScan clears diagnostics for closed files.
    client.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": {"workspaceScan": {"enabled": false}}}),
    );
    assert!(client.diagnostics_for(&leak_uri).is_empty());

    client.request("shutdown", json!(null));
    client.notify("exit", json!(null));
    assert!(client.wait_exit().success());
    let _ = std::fs::remove_dir_all(&dir);
}
