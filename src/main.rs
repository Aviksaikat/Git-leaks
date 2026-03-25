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
use output::{format_findings, print_findings};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Handle --decrypt mode: just decrypt and print, then exit
    if let Some(ref path) = args.decrypt {
        let password = rpassword::prompt_password("Enter password to decrypt: ")
            .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))?;
        let content = crypto::decrypt_file(path, &password)?;
        print!("{}", content);
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

    // Always print to stdout
    print_findings(&findings, &args.format, args.reveal);

    // Write encrypted output file if requested
    if let (Some(ref path), Some(ref pw)) = (&args.output, &password) {
        // Encrypted file always uses full reveal + JSON for complete data
        let content = format_findings(&findings, &args.format, args.reveal);
        crypto::encrypt_and_write(&content, pw, path)?;
        eprintln!("\nEncrypted output written to: {:?}", path);
        eprintln!("Decrypt with: git-leaks --decrypt {:?}", path);
    }

    if !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
