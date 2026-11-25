//! "Ignore this secret" quick fixes (FR-6).

use std::collections::HashMap;

use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, Diagnostic, Position, Range, TextEdit, Url,
    WorkspaceEdit,
};
use secret_scanner_core::allow::{IGNORE_LINE_MARKER, IGNORE_NEXT_LINE_MARKER};
use secret_scanner_core::comment::{comment_style, render_comment};
use secret_scanner_core::position::{indentation, split_lines, utf16_len};

use crate::convert::SOURCE;

/// Builds two quick fixes per affected line:
/// 1. Insert `secret-scanner-lsp:ignore-next-line` as a comment above it (preferred).
/// 2. Append `secret-scanner-lsp:ignore` inline at the end of the flagged line.
///
/// Nothing is offered for files without comment syntax (e.g. JSON).
pub fn ignore_actions(
    uri: &Url,
    language_id: &str,
    text: &str,
    diagnostics: &[Diagnostic],
) -> Vec<CodeActionOrCommand> {
    let Some(style) = comment_style(uri.path(), language_id) else {
        return Vec::new();
    };
    let lines = split_lines(text);
    let mut by_line: Vec<(u32, Vec<Diagnostic>)> = Vec::new();
    for diagnostic in diagnostics {
        if diagnostic.source.as_deref() != Some(SOURCE) {
            continue;
        }
        let line = diagnostic.range.start.line;
        match by_line.iter_mut().find(|(l, _)| *l == line) {
            Some((_, list)) => list.push(diagnostic.clone()),
            None => by_line.push((line, vec![diagnostic.clone()])),
        }
    }
    let mut actions = Vec::new();
    for (line, diagnostics) in by_line {
        let Some(text_line) = lines.get(line as usize) else {
            continue;
        };

        let next_line_comment = render_comment(style, IGNORE_NEXT_LINE_MARKER);
        let next_line_edit = TextEdit::new(
            Range::new(Position::new(line, 0), Position::new(line, 0)),
            format!("{}{}\n", indentation(text_line), next_line_comment),
        );
        let mut next_line_changes = HashMap::new();
        next_line_changes.insert(uri.clone(), vec![next_line_edit]);
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Ignore this secret (add `{IGNORE_NEXT_LINE_MARKER}` above)"),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(diagnostics.clone()),
            edit: Some(WorkspaceEdit::new(next_line_changes)),
            is_preferred: Some(true),
            ..CodeAction::default()
        }));

        let line_end = utf16_len(text_line);
        let inline_comment = render_comment(style, IGNORE_LINE_MARKER);
        let inline_edit = TextEdit::new(
            Range::new(Position::new(line, line_end), Position::new(line, line_end)),
            format!(" {inline_comment}"),
        );
        let mut inline_changes = HashMap::new();
        inline_changes.insert(uri.clone(), vec![inline_edit]);
        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Ignore this secret inline (append `{IGNORE_LINE_MARKER}`)"),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(diagnostics),
            edit: Some(WorkspaceEdit::new(inline_changes)),
            is_preferred: Some(false),
            ..CodeAction::default()
        }));
    }
    actions
}

#[cfg(test)]
mod tests {
    use lsp_types::{CodeActionOrCommand, Diagnostic, Position, Range, Url};

    use crate::actions::ignore_actions;
    use crate::convert::SOURCE;

    fn diag(line: u32, source: &str) -> Diagnostic {
        Diagnostic {
            range: Range::new(Position::new(line, 4), Position::new(line, 10)),
            source: Some(source.to_string()),
            message: "m".into(),
            ..Diagnostic::default()
        }
    }

    #[test]
    fn inserts_indented_comment_above_the_line() {
        let uri = Url::parse("file:///w/app.py").unwrap();
        let text = "def f():\n    token = 'éx'\n";
        let actions = ignore_actions(
            &uri,
            "python",
            text,
            &[diag(1, SOURCE), diag(1, SOURCE), diag(0, "other")],
        );
        assert_eq!(actions.len(), 2);

        let CodeActionOrCommand::CodeAction(above) = &actions[0] else {
            panic!("expected a code action");
        };
        assert_eq!(above.is_preferred, Some(true));
        assert_eq!(above.diagnostics.as_ref().map(Vec::len), Some(2));
        let above_edits = &above.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri];
        assert_eq!(
            above_edits[0].new_text,
            "    # secret-scanner-lsp:ignore-next-line\n"
        );
        assert_eq!(above_edits[0].range.start, Position::new(1, 0));

        let CodeActionOrCommand::CodeAction(inline) = &actions[1] else {
            panic!("expected an inline code action");
        };
        assert_eq!(inline.is_preferred, Some(false));
        assert_eq!(inline.diagnostics.as_ref().map(Vec::len), Some(2));
        let inline_edits = &inline.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri];
        assert_eq!(inline_edits[0].new_text, " # secret-scanner-lsp:ignore");
        assert_eq!(inline_edits[0].range.start, Position::new(1, 16));
        assert_eq!(inline_edits[0].range.end, Position::new(1, 16));
    }

    #[test]
    fn no_action_for_json() {
        let uri = Url::parse("file:///w/config.json").unwrap();
        assert!(ignore_actions(&uri, "json", "{\"k\": \"v\"}", &[diag(0, SOURCE)]).is_empty());
    }
}
