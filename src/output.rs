use crate::cli::OutputFormat;
use crate::finding::Finding;

pub fn print_findings(findings: &[Finding], format: &OutputFormat, reveal: bool) {
    match format {
        OutputFormat::Human => print_human(findings, reveal),
        OutputFormat::Json => print_json(findings),
    }
}

fn print_human(findings: &[Finding], reveal: bool) {
    if findings.is_empty() {
        println!("No leaked secrets found.");
        return;
    }

    for finding in findings {
        println!("[LEAK] {}", finding.pattern_name);
        println!("  Commit:  {} ({})", &finding.commit_hash[..8.min(finding.commit_hash.len())], finding.commit_date);
        println!("  Message: {}", finding.commit_message);
        println!("  File:    {}", finding.file_path);
        println!("  Match:   {}", format_secret(&finding.matched_text, reveal));
        println!("---");
    }

    let unique_commits: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.commit_hash.as_str()).collect();
    println!(
        "\nFound {} leaked secret(s) across {} commit(s).",
        findings.len(),
        unique_commits.len()
    );
}

fn print_json(findings: &[Finding]) {
    match serde_json::to_string_pretty(findings) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize findings to JSON: {}", e),
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
