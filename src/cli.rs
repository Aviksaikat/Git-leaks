use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "git-leaks",
    version,
    about = "Scan git history for leaked secrets in file contents"
)]
pub struct Args {
    /// Path to the git repository.
    #[arg(short, long, default_value = ".")]
    pub repo: PathBuf,

    /// Only scan commits after this date (e.g. "4 months ago", "2024-01-01").
    #[arg(long)]
    pub since: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "human")]
    pub format: OutputFormat,

    /// Only scan files with these extensions (comma-separated, e.g. "js,ts,py,env").
    #[arg(long)]
    pub extensions: Option<String>,

    /// Maximum blob size in bytes to scan (skip larger files).
    #[arg(long, default_value = "10485760")]
    pub max_file_size: u64,

    /// Scan all branches, not just HEAD.
    #[arg(long)]
    pub all_branches: bool,

    /// Also scan dangling/unreachable commits (found via git fsck).
    /// These are commits that were removed by force-push, rebase, or amend
    /// but still exist in local .git/objects before garbage collection.
    #[arg(long)]
    pub dangling: bool,

    /// Fetch and scan specific orphan commit SHAs from the remote.
    /// Useful for commits removed from branches but still on GitHub/GitLab.
    /// Accepts comma-separated SHAs or a file path prefixed with @.
    #[arg(long)]
    pub fetch_orphans: Option<String>,

    /// Auto-discover orphan commits from GitHub/GitLab API and local reflog.
    /// Finds force-pushed, squash-merged, and rebased-away commits.
    /// Requires GITHUB_TOKEN env var for private repos (optional for public).
    #[arg(long)]
    pub discover_orphans: bool,

    /// Only search for private key patterns (EVM, hex, PEM).
    /// Skips generic secrets, API keys, and AWS credentials.
    #[arg(long)]
    pub private_keys_only: bool,

    /// Show partial secret in output (first 5 + last 5 chars).
    /// Without this flag, secrets are fully redacted in human output.
    #[arg(long)]
    pub reveal: bool,

    /// Write output to an AES-256-GCM encrypted file.
    /// Prompts for a password at startup to encrypt the file.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Decrypt a previously encrypted output file and print its contents.
    /// Usage: git-leaks --decrypt <file>
    #[arg(long)]
    pub decrypt: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Human,
    Json,
}

impl Args {
    /// Parse the --extensions flag into a vec of lowercase extensions.
    pub fn extension_list(&self) -> Option<Vec<String>> {
        self.extensions.as_ref().map(|exts| {
            exts.split(',')
                .map(|e| e.trim().to_lowercase().trim_start_matches('.').to_string())
                .filter(|e| !e.is_empty())
                .collect()
        })
    }
}
