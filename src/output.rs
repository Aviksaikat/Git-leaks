use crate::cli::OutputFormat;
use crate::finding::Finding;

pub fn print_findings(findings: &[Finding], format: &OutputFormat, reveal: bool) {
    match format {
        OutputFormat::Human => print_human(findings, reveal),
        OutputFormat::Json => print_json(findings),
    }
}

/// Format findings as a string (used for encrypted file output).
pub fn format_findings(findings: &[Finding], format: &OutputFormat, reveal: bool) -> String {
    match format {
        OutputFormat::Human => format_human(findings, reveal),
        OutputFormat::Json => format_json(findings),
    }
}

fn print_human(findings: &[Finding], reveal: bool) {
    print!("{}", format_human(findings, reveal));
}

fn format_human(findings: &[Finding], reveal: bool) -> String {
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
        out.push_str(&format!("[LEAK] {}{}\n", finding.pattern_name, validation_tag));
        out.push_str(&format!("  Commit:  {} ({})\n", &finding.commit_hash[..8.min(finding.commit_hash.len())], finding.commit_date));
        out.push_str(&format!("  Message: {}\n", finding.commit_message));
        out.push_str(&format!("  File:    {}\n", finding.file_path));
        out.push_str(&format!("  Match:   {}\n", format_secret(&finding.matched_text, reveal)));
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

/// Format a secret for human-readable output.
/// --reveal: show first 5 + last 5 chars (e.g. "0x3b0...1d76")
/// default: fully redacted as "****"
fn format_secret(secret: &str, reveal: bool) -> String {
    if reveal {
        if secret.len() <= 12 {
            return secret.to_string();
        }
        let prefix = &secret[..5];
        let suffix = &secret[secret.len() - 5..];
        format!("{}...{}", prefix, suffix)
    } else {
        "****".to_string()
    }
}
