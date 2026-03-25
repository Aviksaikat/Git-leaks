use crate::cli::OutputFormat;
use crate::finding::Finding;

/// Controls how secrets are displayed in output.
#[derive(Clone, Copy)]
pub enum RevealLevel {
    /// Fully redacted: "****"
    Redacted,
    /// Partial: first 5 + last 5 chars (e.g. "0x3b0...1d76")
    Partial,
    /// Full secret shown (used for encrypted output files)
    Full,
}

pub fn print_findings(findings: &[Finding], format: &OutputFormat, reveal: bool) {
    let level = if reveal {
        RevealLevel::Partial
    } else {
        RevealLevel::Redacted
    };
    match format {
        OutputFormat::Human => print_human(findings, level),
        OutputFormat::Json => print_json(findings),
    }
}

/// Format findings as a string with full secret reveal (used for encrypted file output).
pub fn format_findings_full(findings: &[Finding], format: &OutputFormat) -> String {
    match format {
        OutputFormat::Human => format_human(findings, RevealLevel::Full),
        OutputFormat::Json => format_json(findings),
    }
}

fn print_human(findings: &[Finding], level: RevealLevel) {
    print!("{}", format_human(findings, level));
}

fn format_human(findings: &[Finding], level: RevealLevel) -> String {
    if findings.is_empty() {
        return "No leaked secrets found.\n".to_string();
    }

    let mut out = String::new();

    for finding in findings {
        let validation_tag = if finding.validated_evm_key {
            " [VERIFIED secp256k1]"
        } else {
            ""
        };
        out.push_str(&format!(
            "[LEAK] {}{}\n",
            finding.pattern_name, validation_tag
        ));
        out.push_str(&format!(
            "  Commit:  {} ({})\n",
            &finding.commit_hash[..8.min(finding.commit_hash.len())],
            finding.commit_date
        ));
        out.push_str(&format!("  Message: {}\n", finding.commit_message));
        out.push_str(&format!("  File:    {}\n", finding.file_path));
        out.push_str(&format!(
            "  Match:   {}\n",
            format_secret(&finding.matched_text, level)
        ));
        out.push_str("---\n");
    }

    let unique_commits: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.commit_hash.as_str()).collect();
    out.push_str(&format!(
        "\nFound {} leaked secret(s) across {} commit(s).\n",
        findings.len(),
        unique_commits.len()
    ));

    out
}

fn print_json(findings: &[Finding]) {
    print!("{}", format_json(findings));
}

fn format_json(findings: &[Finding]) -> String {
    match serde_json::to_string_pretty(findings) {
        Ok(json) => format!("{}\n", json),
        Err(e) => format!("Failed to serialize findings to JSON: {}\n", e),
    }
}

/// Print only the secret values, one per line (deduplicated).
pub fn print_list(findings: &[Finding]) {
    print!("{}", format_list(findings));
}

/// Format only the secret values, one per line (deduplicated).
pub fn format_list(findings: &[Finding]) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    for finding in findings {
        if seen.insert(&finding.matched_text) {
            out.push_str(&finding.matched_text);
            out.push('\n');
        }
    }
    out
}

/// Format a secret based on reveal level.
fn format_secret(secret: &str, level: RevealLevel) -> String {
    match level {
        RevealLevel::Full => secret.to_string(),
        RevealLevel::Partial => {
            if secret.len() <= 12 {
                return secret.to_string();
            }
            let prefix = &secret[..5];
            let suffix = &secret[secret.len() - 5..];
            format!("{}...{}", prefix, suffix)
        }
        RevealLevel::Redacted => "****".to_string(),
    }
}
