//! Line comment syntax per file type, used by the "ignore" code action (FR-6).

/// How to wrap a marker in a comment for one file type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommentStyle {
    pub prefix: &'static str,
    pub suffix: &'static str,
}

const SLASH: CommentStyle = CommentStyle {
    prefix: "// ",
    suffix: "",
};
const HASH: CommentStyle = CommentStyle {
    prefix: "# ",
    suffix: "",
};
const DASH: CommentStyle = CommentStyle {
    prefix: "-- ",
    suffix: "",
};
const BLOCK: CommentStyle = CommentStyle {
    prefix: "/* ",
    suffix: " */",
};
const XML: CommentStyle = CommentStyle {
    prefix: "<!-- ",
    suffix: " -->",
};

fn style_for_extension(ext: &str) -> Option<CommentStyle> {
    let style = match ext {
        "rs" | "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" | "go" | "java"
        | "kt" | "kts" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "cs" | "swift" | "scala"
        | "dart" | "php" | "jsonc" | "json5" | "scss" | "less" | "groovy" | "gradle" | "zig"
        | "proto" => SLASH,
        "py" | "rb" | "sh" | "bash" | "zsh" | "fish" | "yaml" | "yml" | "toml" | "env" | "ini"
        | "conf" | "cfg" | "properties" | "r" | "pl" | "ps1" | "tf" | "tfvars" | "hcl" | "nix"
        | "ex" | "exs" | "cmake" | "mk" | "dockerfile" | "gitignore" | "editorconfig" => HASH,
        "sql" | "lua" | "hs" | "elm" => DASH,
        "css" => BLOCK,
        "html" | "htm" | "xml" | "md" | "markdown" | "vue" | "svelte" | "csproj" | "plist" => XML,
        _ => return None,
    };
    Some(style)
}

fn style_for_language_id(language_id: &str) -> Option<CommentStyle> {
    let id = language_id.to_ascii_lowercase();
    let style = match id.as_str() {
        "rust" | "javascript" | "typescript" | "tsx" | "javascriptreact" | "typescriptreact"
        | "go" | "java" | "kotlin" | "c" | "cpp" | "c++" | "csharp" | "c#" | "swift" | "scala"
        | "dart" | "zig" | "proto" | "php" | "jsonc" | "json5" | "scss" => SLASH,
        "python" | "ruby" | "shellscript" | "shell script" | "bash" | "powershell" | "yaml"
        | "toml" | "ini" | "env" | "dotenv" | "docker" | "dockerfile" | "terraform"
        | "terraform vars" | "hcl" | "nix" | "elixir" | "make" | "makefile" | "git commit"
        | "gitcommit" => HASH,
        "sql" | "lua" | "haskell" => DASH,
        "css" => BLOCK,
        "html" | "xml" | "markdown" | "vue" | "vue.js" | "svelte" => XML,
        _ => return None,
    };
    Some(style)
}

/// Resolves the comment style from the file path first, then the LSP language ID.
///
/// Returns `None` for formats without comments (JSON) or unknown types; the
/// ignore code action is not offered for those.
pub fn comment_style(path: &str, language_id: &str) -> Option<CommentStyle> {
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lower = file_name.to_ascii_lowercase();
    if lower == "json" || lower.ends_with(".json") {
        return None;
    }
    if lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env") {
        return Some(HASH);
    }
    if matches!(
        lower.as_str(),
        "dockerfile" | "makefile" | "gemfile" | "rakefile" | ".bashrc" | ".zshrc" | ".profile"
    ) {
        return Some(HASH);
    }
    if let Some((_, ext)) = lower.rsplit_once('.') {
        if let Some(style) = style_for_extension(ext) {
            return Some(style);
        }
    }
    style_for_language_id(language_id)
}

/// Renders `marker` as a full comment, e.g. `# secret-scanner-lsp:ignore-next-line`.
pub fn render_comment(style: CommentStyle, marker: &str) -> String {
    format!("{}{}{}", style.prefix, marker, style.suffix)
}

#[cfg(test)]
mod tests {
    use crate::comment::{comment_style, render_comment};

    #[test]
    fn styles_by_path_and_language() {
        let render =
            |path: &str, lang: &str| comment_style(path, lang).map(|s| render_comment(s, "m"));
        assert_eq!(render("/w/src/main.rs", ""), Some("// m".into()));
        assert_eq!(render("/w/config.yaml", ""), Some("# m".into()));
        assert_eq!(render("/w/.env.local", ""), Some("# m".into()));
        assert_eq!(render("/w/Dockerfile", ""), Some("# m".into()));
        assert_eq!(render("/w/query.sql", ""), Some("-- m".into()));
        assert_eq!(render("/w/site.css", ""), Some("/* m */".into()));
        assert_eq!(render("/w/README.md", ""), Some("<!-- m -->".into()));
        assert_eq!(render("C:\\w\\app.py", ""), Some("# m".into()));
        assert_eq!(render("/w/untitled", "python"), Some("# m".into()));
        assert_eq!(render("/w/untitled", "CSharp"), Some("// m".into()));
        assert_eq!(render("/w/untitled", "Scala"), Some("// m".into()));
        assert_eq!(render("/w/untitled", "Docker"), Some("# m".into()));
        assert_eq!(render("/w/untitled", "PowerShell"), Some("# m".into()));
        assert_eq!(render("/w/untitled", "ini"), Some("# m".into()));
        assert_eq!(render("/w/untitled", "Git Commit"), Some("# m".into()));
        assert_eq!(render("/w/untitled", "Vue.js"), Some("<!-- m -->".into()));
        assert_eq!(render("/w/package.json", "json"), None);
        assert_eq!(render("/w/unknown.zzz", ""), None);
    }
}
