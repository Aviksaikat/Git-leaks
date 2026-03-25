use crate::cli::OutputFormat;
use crate::finding::Finding;

pub fn print_findings(findings: &[Finding], format: &OutputFormat) {
    match format {
        OutputFormat::Human => print_human(findings),
        OutputFormat::Json => print_json(findings),
    }
}

fn print_human(findings: &[Finding]) {
    if findings.is_empty() {
        println!("No leaked secrets found.");
        return;
    }

    for finding in findings {
        println!("[LEAK] {}", finding.pattern_name);
        println!("  Commit:  {} ({})", &finding.commit_hash[..8.min(finding.commit_hash.len())], finding.commit_date);
        println!("  Message: {}", finding.commit_message);
        println!("  File:    {}", finding.file_path);
        println!("  Match:   {}", truncate_secret(&finding.matched_text));
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

/// Truncate a secret for human-readable output to avoid printing full keys.
fn truncate_secret(secret: &str) -> String {
    if secret.len() <= 20 {
        return secret.to_string();
    }
    let prefix = &secret[..12];
    let suffix = &secret[secret.len() - 4..];
    format!("{}...{}", prefix, suffix)
}
