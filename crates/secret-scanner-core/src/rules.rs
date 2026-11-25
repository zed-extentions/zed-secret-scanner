//! Built-in detection rules (FR-1, FR-2).
//!
//! Each rule is either a prefixed token with a fixed character set and length
//! bounds, or a small hand-written matcher for formats that a prefix cannot
//! describe (PEM private keys, JWTs, URL credentials, ...). Rule IDs follow the
//! gitleaks naming so that findings are recognisable to users of that tool.

use std::ops::Range;

/// Character classes used by token bodies. All classes are ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// `A-Z0-9`
    UpperDigit,
    /// `A-Za-z`
    Alpha,
    /// `A-Za-z0-9`
    Alnum,
    /// `A-Za-z0-9_`
    AlnumUnderscore,
    /// `A-Za-z0-9_-`
    UrlSafe,
    /// `0-9a-f`
    HexLower,
    /// `0-9a-fA-F`
    Hex,
    /// `A-Za-z0-9-`
    AlnumDash,
    /// `A-Za-z0-9/_`
    UrlPath,
    /// `A-Za-z0-9_-.=`
    DotSafe,
}

impl Charset {
    /// Returns `true` when `b` belongs to this character class.
    pub fn contains(self, b: u8) -> bool {
        match self {
            Charset::UpperDigit => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Charset::Alpha => b.is_ascii_alphabetic(),
            Charset::Alnum => b.is_ascii_alphanumeric(),
            Charset::AlnumUnderscore => b.is_ascii_alphanumeric() || b == b'_',
            Charset::UrlSafe => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
            Charset::HexLower => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            Charset::Hex => b.is_ascii_hexdigit(),
            Charset::AlnumDash => b.is_ascii_alphanumeric() || b == b'-',
            Charset::UrlPath => b.is_ascii_alphanumeric() || b == b'/' || b == b'_',
            Charset::DotSafe => {
                b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'='
            }
        }
    }
}

/// A token that starts with one of `prefixes`, followed by `min..=max` bytes of `charset`.
#[derive(Debug)]
pub struct TokenSpec {
    pub prefixes: &'static [&'static str],
    pub charset: Charset,
    pub min: usize,
    pub max: usize,
}

/// How a rule finds candidate secrets inside one line.
#[derive(Debug)]
pub enum Matcher {
    Token(TokenSpec),
    PrivateKey,
    Jwt,
    UrlCredentials,
    TerraformToken,
    AzureAccountKey,
}

/// A built-in detection rule.
#[derive(Debug)]
pub struct Rule {
    /// Stable identifier, reported as the diagnostic `code` and used in `disabledRules`.
    pub id: &'static str,
    /// Human readable name used in diagnostic messages.
    pub title: &'static str,
    pub matcher: Matcher,
}

/// Rule ID of the keyword + entropy detector implemented in [`crate::entropy`].
pub const GENERIC_RULE_ID: &str = "generic-api-key";
/// Title of the keyword + entropy detector.
pub const GENERIC_RULE_TITLE: &str = "Generic secret assignment";

const fn token(
    id: &'static str,
    title: &'static str,
    prefixes: &'static [&'static str],
    charset: Charset,
    min: usize,
    max: usize,
) -> Rule {
    Rule {
        id,
        title,
        matcher: Matcher::Token(TokenSpec {
            prefixes,
            charset,
            min,
            max,
        }),
    }
}

/// All built-in rules except [`GENERIC_RULE_ID`], in reporting priority order.
pub const RULES: &[Rule] = &[
    Rule {
        id: "private-key",
        title: "Private key",
        matcher: Matcher::PrivateKey,
    },
    token(
        "aws-access-token",
        "AWS access key ID",
        &["AKIA", "ASIA", "ABIA", "ACCA"],
        Charset::UpperDigit,
        16,
        16,
    ),
    Rule {
        id: "azure-storage-account-key",
        title: "Azure storage account key",
        matcher: Matcher::AzureAccountKey,
    },
    token(
        "github-pat",
        "GitHub personal access token",
        &["ghp_"],
        Charset::Alnum,
        36,
        36,
    ),
    token(
        "github-fine-grained-pat",
        "GitHub fine-grained personal access token",
        &["github_pat_"],
        Charset::AlnumUnderscore,
        82,
        82,
    ),
    token(
        "github-oauth",
        "GitHub OAuth access token",
        &["gho_"],
        Charset::Alnum,
        36,
        36,
    ),
    token(
        "github-app-token",
        "GitHub App token",
        &["ghu_", "ghs_"],
        Charset::Alnum,
        36,
        36,
    ),
    token(
        "github-refresh-token",
        "GitHub refresh token",
        &["ghr_"],
        Charset::Alnum,
        36,
        36,
    ),
    token(
        "gitlab-pat",
        "GitLab personal access token",
        &["glpat-"],
        Charset::UrlSafe,
        20,
        80,
    ),
    token(
        "slack-token",
        "Slack token",
        &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-"],
        Charset::AlnumDash,
        10,
        255,
    ),
    token(
        "slack-webhook-url",
        "Slack incoming webhook URL",
        &["https://hooks.slack.com/services/"],
        Charset::UrlPath,
        30,
        80,
    ),
    token(
        "stripe-access-token",
        "Stripe secret key",
        &[
            "sk_live_", "sk_test_", "sk_prod_", "rk_live_", "rk_test_", "rk_prod_",
        ],
        Charset::Alnum,
        10,
        99,
    ),
    token(
        "gcp-api-key",
        "Google Cloud API key",
        &["AIza"],
        Charset::UrlSafe,
        35,
        35,
    ),
    token(
        "gcp-oauth-client-secret",
        "Google OAuth client secret",
        &["GOCSPX-"],
        Charset::UrlSafe,
        28,
        28,
    ),
    token(
        "openai-api-key",
        "OpenAI API key",
        &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        Charset::UrlSafe,
        40,
        200,
    ),
    token(
        "anthropic-api-key",
        "Anthropic API key",
        &["sk-ant-api03-", "sk-ant-admin01-"],
        Charset::UrlSafe,
        80,
        120,
    ),
    token(
        "huggingface-access-token",
        "Hugging Face access token",
        &["hf_"],
        Charset::Alpha,
        34,
        34,
    ),
    token(
        "npm-access-token",
        "npm access token",
        &["npm_"],
        Charset::Alnum,
        36,
        36,
    ),
    token(
        "pypi-upload-token",
        "PyPI upload token",
        &["pypi-AgEIcHlwaS5vcmc"],
        Charset::UrlSafe,
        50,
        500,
    ),
    token(
        "sendgrid-api-token",
        "SendGrid API key",
        &["SG."],
        Charset::DotSafe,
        66,
        66,
    ),
    token(
        "twilio-api-key",
        "Twilio API key",
        &["SK"],
        Charset::Hex,
        32,
        32,
    ),
    token(
        "shopify-token",
        "Shopify access token",
        &["shpat_", "shpca_", "shppa_", "shpss_"],
        Charset::Hex,
        32,
        32,
    ),
    token(
        "digitalocean-token",
        "DigitalOcean token",
        &["dop_v1_", "doo_v1_", "dor_v1_"],
        Charset::HexLower,
        64,
        64,
    ),
    token(
        "square-token",
        "Square access token or secret",
        &["sq0atp-", "sq0csp-"],
        Charset::UrlSafe,
        22,
        43,
    ),
    token(
        "databricks-api-token",
        "Databricks API token",
        &["dapi"],
        Charset::HexLower,
        32,
        32,
    ),
    token(
        "age-secret-key",
        "age secret key",
        &["AGE-SECRET-KEY-1"],
        Charset::UpperDigit,
        58,
        58,
    ),
    Rule {
        id: "hashicorp-tf-api-token",
        title: "HashiCorp Terraform API token",
        matcher: Matcher::TerraformToken,
    },
    Rule {
        id: "jwt",
        title: "JSON Web Token",
        matcher: Matcher::Jwt,
    },
    Rule {
        id: "url-credentials",
        title: "Password in URL",
        matcher: Matcher::UrlCredentials,
    },
];

/// Every rule ID known to the scanner, including [`GENERIC_RULE_ID`].
pub fn all_rule_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = RULES.iter().map(|rule| rule.id).collect();
    ids.push(GENERIC_RULE_ID);
    ids
}

/// Returns the title of `rule_id`, if it is a known rule.
pub fn rule_title(rule_id: &str) -> Option<&'static str> {
    if rule_id == GENERIC_RULE_ID {
        return Some(GENERIC_RULE_TITLE);
    }
    RULES
        .iter()
        .find(|rule| rule.id == rule_id)
        .map(|rule| rule.title)
}

/// Finds every byte range of `line` matched by `rule`.
pub fn find_matches(rule: &Rule, line: &str) -> Vec<Range<usize>> {
    match &rule.matcher {
        Matcher::Token(spec) => find_tokens(spec, line),
        Matcher::PrivateKey => find_private_key(line),
        Matcher::Jwt => find_jwt(line),
        Matcher::UrlCredentials => find_url_credentials(line),
        Matcher::TerraformToken => find_terraform_token(line),
        Matcher::AzureAccountKey => find_azure_account_key(line),
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// `true` when the byte before `start` does not glue the match to a longer word.
fn boundary_before(bytes: &[u8], start: usize) -> bool {
    start == 0 || !is_word_byte(bytes[start - 1])
}

/// `true` when the byte at `end` does not glue the match to a longer word.
fn boundary_after(bytes: &[u8], end: usize) -> bool {
    end >= bytes.len() || !is_word_byte(bytes[end])
}

/// Length of the run of `charset` bytes starting at `from`.
fn run_len(bytes: &[u8], from: usize, charset: Charset) -> usize {
    bytes[from..]
        .iter()
        .take_while(|b| charset.contains(**b))
        .count()
}

fn find_tokens(spec: &TokenSpec, line: &str) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for prefix in spec.prefixes {
        for (start, _) in line.match_indices(prefix) {
            if !boundary_before(bytes, start) {
                continue;
            }
            let body_start = start + prefix.len();
            let body = run_len(bytes, body_start, spec.charset);
            if body < spec.min || body > spec.max {
                continue;
            }
            let end = body_start + body;
            if !boundary_after(bytes, end) {
                continue;
            }
            found.push(start..end);
        }
    }
    found.sort_by_key(|range| range.start);
    found
}

fn find_private_key(line: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    for (start, _) in line.match_indices("-----BEGIN ") {
        let rest = &line[start + "-----BEGIN ".len()..];
        let Some(close) = rest.find("-----") else {
            continue;
        };
        let label = &rest[..close];
        let is_private = label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK");
        let is_label = label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b' ' || b.is_ascii_digit());
        if is_private && is_label {
            let end = start + "-----BEGIN ".len() + close + "-----".len();
            found.push(start..end);
        }
    }
    found
}

fn find_jwt(line: &str) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for (start, _) in line.match_indices("eyJ") {
        if !boundary_before(bytes, start) || (start > 0 && bytes[start - 1] == b'.') {
            continue;
        }
        let header = run_len(bytes, start, Charset::UrlSafe);
        let dot1 = start + header;
        if header < 10 || bytes.get(dot1) != Some(&b'.') {
            continue;
        }
        let payload_start = dot1 + 1;
        if !line[payload_start..].starts_with("eyJ") {
            continue;
        }
        let payload = run_len(bytes, payload_start, Charset::UrlSafe);
        let dot2 = payload_start + payload;
        if payload < 10 || bytes.get(dot2) != Some(&b'.') {
            continue;
        }
        let signature = run_len(bytes, dot2 + 1, Charset::UrlSafe);
        if signature < 10 {
            continue;
        }
        found.push(start..dot2 + 1 + signature);
    }
    found
}

/// Passwords that only appear in documentation-style connection strings.
const DOC_URL_PASSWORDS: &[&str] = &["pass", "password", "passwd", "pwd", "secret", "xxx"];

fn find_url_credentials(line: &str) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for (sep, _) in line.match_indices("://") {
        let scheme_len = bytes[..sep]
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'+' || **b == b'-' || **b == b'.')
            .count();
        if scheme_len == 0 {
            continue;
        }
        let auth_start = sep + 3;
        let auth_len = bytes[auth_start..]
            .iter()
            .take_while(|b| {
                !b.is_ascii_whitespace()
                    && !matches!(**b, b'/' | b'@' | b'"' | b'\'' | b'`' | b'?' | b'#')
            })
            .count();
        let at = auth_start + auth_len;
        if bytes.get(at) != Some(&b'@') {
            continue;
        }
        let userinfo = &line[auth_start..at];
        let Some(colon) = userinfo.find(':') else {
            continue;
        };
        let user = &userinfo[..colon];
        let password = &userinfo[colon + 1..];
        let host_len = bytes[at + 1..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(**b, b'.' | b'-' | b'_'))
            .count();
        if user.is_empty() || password.len() < 3 || host_len == 0 {
            continue;
        }
        // Documentation examples such as `postgres://user:pass@host`.
        if DOC_URL_PASSWORDS.contains(&password.to_ascii_lowercase().as_str()) {
            continue;
        }
        let pass_start = auth_start + colon + 1;
        found.push(pass_start..at);
    }
    found
}

fn find_terraform_token(line: &str) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for (dot, _) in line.match_indices(".atlasv1.") {
        let lead = bytes[..dot]
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            .count();
        let tail_start = dot + ".atlasv1.".len();
        let tail = run_len(bytes, tail_start, Charset::DotSafe);
        if lead != 14 || !(60..=70).contains(&tail) {
            continue;
        }
        found.push(dot - lead..tail_start + tail);
    }
    found
}

fn find_azure_account_key(line: &str) -> Vec<Range<usize>> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for (start, _) in line.match_indices("AccountKey=") {
        let value_start = start + "AccountKey=".len();
        let len = bytes[value_start..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(**b, b'+' | b'/' | b'='))
            .count();
        if (86..=88).contains(&len) {
            found.push(value_start..value_start + len);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::rules::{all_rule_ids, find_matches, rule_title, Rule, GENERIC_RULE_ID, RULES};

    fn rule(id: &str) -> &'static Rule {
        RULES.iter().find(|r| r.id == id).expect("rule exists")
    }

    fn matched<'a>(id: &str, line: &'a str) -> Vec<&'a str> {
        find_matches(rule(id), line)
            .into_iter()
            .map(|range| &line[range])
            .collect()
    }

    #[test]
    fn rule_ids_are_unique_and_kebab_case() {
        let ids = all_rule_ids();
        for (i, id) in ids.iter().enumerate() {
            assert!(!ids[i + 1..].contains(id), "duplicate rule id {id}");
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{id} is not kebab-case"
            );
        }
        assert!(ids.contains(&GENERIC_RULE_ID));
        assert_eq!(
            rule_title("github-pat"),
            Some("GitHub personal access token")
        );
        assert_eq!(rule_title("nope"), None);
    }

    #[test]
    fn aws_access_key_requires_exact_length_and_boundaries() {
        let key = format!("AKIA{}", "Q".repeat(16));
        assert_eq!(
            matched("aws-access-token", &format!("id = \"{key}\"")),
            vec![key.as_str()]
        );
        assert!(matched("aws-access-token", &format!("XAKIA{}", "Q".repeat(16))).is_empty());
        assert!(matched("aws-access-token", &format!("AKIA{}", "Q".repeat(17))).is_empty());
        assert!(matched("aws-access-token", &format!("AKIA{}a", "Q".repeat(16))).is_empty());
    }

    #[test]
    fn github_tokens() {
        let pat = format!("ghp_{}", "a1B2".repeat(9));
        assert_eq!(
            matched("github-pat", &format!("token: {pat}")),
            vec![pat.as_str()]
        );
        let fine = format!("github_pat_{}", "Ab1_".repeat(20) + "xy");
        assert_eq!(
            matched("github-fine-grained-pat", &fine),
            vec![fine.as_str()]
        );
        let app = format!("ghs_{}", "Z9".repeat(18));
        assert_eq!(matched("github-app-token", &app), vec![app.as_str()]);
        assert!(matched("github-pat", "ghp_short").is_empty());
    }

    #[test]
    fn slack_and_stripe_tokens() {
        // Fixtures are assembled at runtime so that no token-shaped literal is
        // committed (keeps GitHub push protection and our own gate quiet).
        let slack = format!(
            "xox{}-{}-{}-{}",
            "b",
            "1".repeat(12),
            "2".repeat(13),
            "aBcD".repeat(4)
        );
        assert_eq!(
            matched("slack-token", &format!("SLACK={slack}")),
            vec![slack.as_str()]
        );
        let hook = format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            "0".repeat(8),
            "0".repeat(8),
            "X".repeat(24)
        );
        assert_eq!(matched("slack-webhook-url", &hook), vec![hook.as_str()]);
        let stripe = format!("sk_{}_{}", "live", "4eC3".repeat(6));
        assert_eq!(
            matched("stripe-access-token", &stripe),
            vec![stripe.as_str()]
        );
    }

    #[test]
    fn cloud_and_ai_provider_keys() {
        let gcp = format!("AIza{}", "Sy-_1".repeat(7));
        assert_eq!(matched("gcp-api-key", &gcp), vec![gcp.as_str()]);
        let openai = format!("sk-proj-{}", "Ab9_-".repeat(10));
        assert_eq!(matched("openai-api-key", &openai), vec![openai.as_str()]);
        let anthropic = format!("sk-ant-api03-{}", "Xy7-_".repeat(18));
        assert_eq!(
            matched("anthropic-api-key", &anthropic),
            vec![anthropic.as_str()]
        );
        let hf = format!("hf_{}", "abcDEF".repeat(5) + "ghIJ");
        assert_eq!(matched("huggingface-access-token", &hf), vec![hf.as_str()]);
        let npm = format!("npm_{}", "a1".repeat(18));
        assert_eq!(matched("npm-access-token", &npm), vec![npm.as_str()]);
    }

    #[test]
    fn sendgrid_twilio_shopify_digitalocean() {
        let sg = format!("SG.{}.{}", "a".repeat(22), "B".repeat(43));
        assert_eq!(matched("sendgrid-api-token", &sg), vec![sg.as_str()]);
        let twilio = format!("SK{}", "0123456789abcdef".repeat(2));
        assert_eq!(matched("twilio-api-key", &twilio), vec![twilio.as_str()]);
        assert!(matched("twilio-api-key", "SKIP_THIS_STEP").is_empty());
        let shop = format!("shpat_{}", "a1b2c3d4".repeat(4));
        assert_eq!(matched("shopify-token", &shop), vec![shop.as_str()]);
        let dop = format!("dop_v1_{}", "0a".repeat(32));
        assert_eq!(matched("digitalocean-token", &dop), vec![dop.as_str()]);
    }

    #[test]
    fn private_key_header_but_not_public_key() {
        let line = format!("-----BEGIN {} KEY-----", "RSA PRIVATE");
        assert_eq!(matched("private-key", &line), vec![line.as_str()]);
        let openssh = format!("-----BEGIN {} KEY-----", "OPENSSH PRIVATE");
        assert_eq!(
            matched("private-key", &format!("key = \"{openssh}\\nabc\"")),
            vec![openssh.as_str()]
        );
        assert!(matched("private-key", "-----BEGIN PUBLIC KEY-----").is_empty());
        assert!(matched("private-key", "-----BEGIN CERTIFICATE-----").is_empty());
    }

    #[test]
    fn jwt_needs_three_segments() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(matched("jwt", &format!("Bearer {jwt}")), vec![jwt]);
        assert!(matched("jwt", "eyJhbGciOiJIUzI1NiJ9.notapayload.sig").is_empty());
    }

    #[test]
    fn url_credentials_report_only_the_password() {
        assert_eq!(
            matched(
                "url-credentials",
                "DATABASE_URL=postgres://app:s3cr3tP4ss@db.internal:5432/app"
            ),
            vec!["s3cr3tP4ss"]
        );
        assert!(matched("url-credentials", "https://example.com/path").is_empty());
        assert!(matched("url-credentials", "git@github.com:org/repo.git").is_empty());
        assert!(matched("url-credentials", "https://user@host.com").is_empty());
        assert!(matched("url-credentials", "// e.g. postgres://user:pass@host").is_empty());
        assert!(matched("url-credentials", "redis://default:Password@cache").is_empty());
    }

    #[test]
    fn terraform_and_azure_and_age() {
        let tf = format!("{}.atlasv1.{}", "abcdefghij0123", "x".repeat(64));
        assert_eq!(matched("hashicorp-tf-api-token", &tf), vec![tf.as_str()]);
        let azure_key = "A".repeat(86) + "==";
        let conn = format!("DefaultEndpointsProtocol=https;AccountName=x;AccountKey={azure_key};");
        assert_eq!(
            matched("azure-storage-account-key", &conn),
            vec![azure_key.as_str()]
        );
        let age = format!("AGE-SECRET-KEY-1{}", "QPZRY9X8GF".repeat(5) + "2TVDW0S3");
        assert_eq!(matched("age-secret-key", &age), vec![age.as_str()]);
    }
}
