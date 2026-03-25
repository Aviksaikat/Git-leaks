mod cli;
mod crypto;
mod finding;
mod orphans;
mod output;
mod patterns;
mod scanner;
mod validate;

use clap::Parser;

use cli::Args;
use finding::deduplicate;
use output::{format_findings_full, print_findings, print_list};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Handle --decrypt mode: just decrypt and print, then exit
    if let Some(ref path) = args.decrypt {
        let password = rpassword::prompt_password("Enter password to decrypt: ")
            .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))?;
        let content = crypto::decrypt_file(path, &password)?;

        if args.list {
            // Parse JSON from encrypted file to extract just the values
            let findings: Vec<finding::Finding> =
                serde_json::from_str(&content).unwrap_or_default();
            if findings.is_empty() {
                // Not JSON — try to extract "Match:" lines from human format
                for line in content.lines() {
                    if let Some(value) = line.trim().strip_prefix("Match:") {
                        println!("{}", value.trim());
                    }
                }
            } else {
                print_list(&findings);
            }
        } else {
            print!("{}", content);
        }
        return Ok(());
    }

    // If --output is set, prompt for password upfront before scanning
    let password = if args.output.is_some() {
        Some(crypto::prompt_password()?)
    } else {
        None
    };

    let findings = scanner::scan(&args)?;
    let findings = deduplicate(findings);

    // Print to stdout
    if args.list {
        print_list(&findings);
    } else {
        print_findings(&findings, &args.format, args.reveal);
    }

    // Write encrypted output file if requested — always JSON for --list compatibility
    if let (Some(ref path), Some(ref pw)) = (&args.output, &password) {
        // Encrypted file stores JSON with full secrets for reliable --list parsing later
        let content = format_findings_full(&findings, &cli::OutputFormat::Json);
        crypto::encrypt_and_write(&content, pw, path)?;
        eprintln!("\nEncrypted output written to: {:?}", path);
        eprintln!("Decrypt with: git-leaks --decrypt {:?}", path);
    }

    if !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
