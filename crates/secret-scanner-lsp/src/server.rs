//! stdio LSP server loop (FR-5, FR-6, FR-7, FR-10).

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_channel::Sender;
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeConfiguration, DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Notification as _, PublishDiagnostics,
};
use lsp_types::request::{CodeActionRequest, HoverRequest, Request as _};
use lsp_types::{
    CodeActionKind, CodeActionOptions, CodeActionParams, CodeActionProviderCapability,
    DidChangeConfigurationParams, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, Hover, HoverParams,
    HoverProviderCapability, InitializeParams, PublishDiagnosticsParams, SaveOptions,
    ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, Url,
};
use secret_scanner_core::config::ScanConfig;
use secret_scanner_core::paths::should_skip;
use serde_json::Value;

use crate::actions::ignore_actions;
use crate::convert::{diagnostics_for_text, hover_for_position};
use crate::settings::parse_config;
use crate::workspace::{collect_files, read_text, relative_to_roots};

type BoxError = Box<dyn Error + Send + Sync>;

struct Document {
    language_id: String,
    text: String,
}

struct Server {
    sender: Sender<Message>,
    config: ScanConfig,
    roots: Vec<PathBuf>,
    documents: HashMap<Url, Document>,
    /// URIs currently open in the editor; the workspace scan never overwrites them.
    open: Arc<Mutex<HashSet<Url>>>,
    /// URIs that received diagnostics from the background workspace scan (or closed-file re-scan).
    workspace_diagnosed: Arc<Mutex<HashSet<Url>>>,
}

/// Capabilities advertised in the `initialize` response.
pub fn capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::FULL),
                save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                    include_text: Some(false),
                })),
                ..TextDocumentSyncOptions::default()
            },
        )),
        code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
            code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
            ..CodeActionOptions::default()
        })),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        ..ServerCapabilities::default()
    }
}

#[allow(deprecated)] // `root_uri` / `root_path` are still sent by some clients.
fn workspace_roots(params: &InitializeParams) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = params
        .workspace_folders
        .iter()
        .flatten()
        .filter_map(|folder| folder.uri.to_file_path().ok())
        .collect();
    if roots.is_empty() {
        if let Some(path) = params
            .root_uri
            .as_ref()
            .and_then(|uri| uri.to_file_path().ok())
        {
            roots.push(path);
        }
    }
    roots
}

/// Runs the server on stdin/stdout until the client sends `exit`.
pub fn run() -> Result<(), BoxError> {
    let (connection, io_threads) = Connection::stdio();
    let capabilities = serde_json::to_value(capabilities())?;
    let init = serde_json::json!({
        "capabilities": capabilities,
        "serverInfo": ServerInfo {
            name: "secret-scanner-lsp".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        },
    });
    let (id, params) = connection.initialize_start()?;
    connection.initialize_finish(id, init)?;
    let params: InitializeParams = serde_json::from_value(params)?;
    let config = parse_config(params.initialization_options.as_ref());
    let mut server = Server {
        sender: connection.sender.clone(),
        config,
        roots: workspace_roots(&params),
        documents: HashMap::new(),
        open: Arc::new(Mutex::new(HashSet::new())),
        workspace_diagnosed: Arc::new(Mutex::new(HashSet::new())),
    };
    server.start_workspace_scan();
    server.main_loop(&connection)?;
    // The stdout writer thread only stops once every `Sender` clone is gone, so the
    // server (which owns one) and the connection must be dropped before joining.
    drop(server);
    drop(connection);
    io_threads.join()?;
    Ok(())
}

fn publish(sender: &Sender<Message>, uri: Url, text: Option<&str>, config: &ScanConfig) -> bool {
    let diagnostics = text
        .map(|text| diagnostics_for_text(text, config))
        .unwrap_or_default();
    let has_findings = !diagnostics.is_empty();
    let params = PublishDiagnosticsParams::new(uri, diagnostics, None);
    let _ = sender.send(Message::Notification(Notification::new(
        PublishDiagnostics::METHOD.to_string(),
        params,
    )));
    has_findings
}

impl Server {
    fn main_loop(&mut self, connection: &Connection) -> Result<(), BoxError> {
        for message in &connection.receiver {
            match message {
                Message::Request(request) => {
                    if connection.handle_shutdown(&request)? {
                        return Ok(());
                    }
                    self.on_request(request);
                }
                Message::Notification(notification) => self.on_notification(notification),
                Message::Response(_) => {}
            }
        }
        Ok(())
    }

    fn on_request(&mut self, request: Request) {
        let response = if request.method == CodeActionRequest::METHOD {
            match serde_json::from_value::<CodeActionParams>(request.params) {
                Ok(params) => {
                    let uri = params.text_document.uri;
                    let actions = self
                        .documents
                        .get(&uri)
                        .map(|doc| {
                            ignore_actions(
                                &uri,
                                &doc.language_id,
                                &doc.text,
                                &params.context.diagnostics,
                            )
                        })
                        .unwrap_or_default();
                    Response::new_ok(request.id, actions)
                }
                Err(err) => {
                    Response::new_err(request.id, ErrorCode::InvalidParams as i32, err.to_string())
                }
            }
        } else if request.method == HoverRequest::METHOD {
            match serde_json::from_value::<HoverParams>(request.params) {
                Ok(params) => {
                    let uri = params.text_document_position_params.text_document.uri;
                    let position = params.text_document_position_params.position;
                    let hover = self
                        .documents
                        .get(&uri)
                        .filter(|doc| {
                            doc.text.len() as u64 <= self.config.max_file_size
                                && !self.is_skipped(&uri)
                        })
                        .and_then(|doc| hover_for_position(&doc.text, position, &self.config));
                    Response::new_ok(request.id, hover as Option<Hover>)
                }
                Err(err) => {
                    Response::new_err(request.id, ErrorCode::InvalidParams as i32, err.to_string())
                }
            }
        } else {
            Response::new_err(
                request.id,
                ErrorCode::MethodNotFound as i32,
                format!("unsupported request {}", request.method),
            )
        };
        let _ = self.sender.send(Message::Response(response));
    }

    fn on_notification(&mut self, notification: Notification) {
        let method = notification.method.as_str();
        let params = notification.params;
        match method {
            DidOpenTextDocument::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidOpenTextDocumentParams>(params) {
                    let uri = p.text_document.uri;
                    self.set_open(&uri, true);
                    self.documents.insert(
                        uri.clone(),
                        Document {
                            language_id: p.text_document.language_id,
                            text: p.text_document.text,
                        },
                    );
                    self.publish_document(&uri);
                }
            }
            DidChangeTextDocument::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidChangeTextDocumentParams>(params) {
                    let uri = p.text_document.uri;
                    if let (Some(doc), Some(change)) = (
                        self.documents.get_mut(&uri),
                        p.content_changes.into_iter().last(),
                    ) {
                        doc.text = change.text;
                    }
                    self.publish_document(&uri);
                }
            }
            DidSaveTextDocument::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidSaveTextDocumentParams>(params) {
                    self.publish_document(&p.text_document.uri);
                }
            }
            DidCloseTextDocument::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidCloseTextDocumentParams>(params) {
                    let uri = p.text_document.uri;
                    self.documents.remove(&uri);
                    self.set_open(&uri, false);
                    self.publish_closed(uri);
                }
            }
            DidChangeConfiguration::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidChangeConfigurationParams>(params) {
                    self.update_config(&p.settings);
                }
            }
            _ => {}
        }
    }

    fn set_open(&self, uri: &Url, open: bool) {
        if let Ok(mut set) = self.open.lock() {
            if open {
                set.insert(uri.clone());
            } else {
                set.remove(uri);
            }
        }
    }

    fn is_skipped(&self, uri: &Url) -> bool {
        match uri.to_file_path() {
            Ok(path) => should_skip(
                &relative_to_roots(&path, &self.roots),
                &self.config.ignore_paths,
            ),
            Err(()) => false,
        }
    }

    fn publish_document(&self, uri: &Url) {
        let Some(doc) = self.documents.get(uri) else {
            return;
        };
        let too_large = doc.text.len() as u64 > self.config.max_file_size;
        let text = if too_large || self.is_skipped(uri) {
            None
        } else {
            Some(doc.text.as_str())
        };
        publish(&self.sender, uri.clone(), text, &self.config);
    }

    /// After closing, keep workspace-scan results for the file on disk; otherwise clear.
    fn publish_closed(&self, uri: Url) {
        let disk_text = if self.config.workspace_scan && !self.is_skipped(&uri) {
            uri.to_file_path()
                .ok()
                .and_then(|path| read_text(&path, self.config.max_file_size))
        } else {
            None
        };
        let has_findings = publish(
            &self.sender,
            uri.clone(),
            disk_text.as_deref(),
            &self.config,
        );
        if let Ok(mut set) = self.workspace_diagnosed.lock() {
            if has_findings {
                set.insert(uri);
            } else {
                set.remove(&uri);
            }
        }
    }

    fn update_config(&mut self, settings: &Value) {
        // Zed sends the `lsp.secret-scanner-lsp.settings` object; ignore empty pushes.
        if !settings.is_object() {
            return;
        }
        let config = parse_config(Some(settings));
        if config == self.config {
            return;
        }
        let was_workspace_scan = self.config.workspace_scan;
        let start_scan = config.workspace_scan && !was_workspace_scan;
        let stop_scan = !config.workspace_scan && was_workspace_scan;
        self.config = config;
        let uris: Vec<Url> = self.documents.keys().cloned().collect();
        for uri in &uris {
            self.publish_document(uri);
        }
        if stop_scan {
            let stale: Vec<Url> = self
                .workspace_diagnosed
                .lock()
                .map(|mut set| set.drain().collect())
                .unwrap_or_default();
            for uri in stale {
                if !self.documents.contains_key(&uri) {
                    publish(&self.sender, uri, None, &self.config);
                }
            }
        } else if start_scan {
            self.start_workspace_scan();
        }
    }

    /// Scans every workspace file in the background (FR-10) when enabled.
    fn start_workspace_scan(&self) {
        if !self.config.workspace_scan || self.roots.is_empty() {
            return;
        }
        let sender = self.sender.clone();
        let config = self.config.clone();
        let roots = self.roots.clone();
        let open = Arc::clone(&self.open);
        let workspace_diagnosed = Arc::clone(&self.workspace_diagnosed);
        thread::spawn(move || {
            for path in collect_files(&roots, &config) {
                let Ok(uri) = Url::from_file_path(&path) else {
                    continue;
                };
                let Some(text) = read_text(&path, config.max_file_size) else {
                    continue;
                };
                let diagnostics = diagnostics_for_text(&text, &config);
                if diagnostics.is_empty() {
                    continue;
                }
                let is_open = open.lock().map(|set| set.contains(&uri)).unwrap_or(false);
                if is_open {
                    continue;
                }
                if let Ok(mut set) = workspace_diagnosed.lock() {
                    set.insert(uri.clone());
                }
                let params = PublishDiagnosticsParams::new(uri, diagnostics, None);
                let _ = sender.send(Message::Notification(Notification::new(
                    PublishDiagnostics::METHOD.to_string(),
                    params,
                )));
            }
        });
    }
}
