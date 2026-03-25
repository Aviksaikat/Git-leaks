mod cli;
mod finding;
mod orphans;
mod output;
mod patterns;
mod scanner;

use clap::Parser;

use cli::Args;
use finding::deduplicate;
use output::print_findings;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let findings = scanner::scan(&args)?;
    let findings = deduplicate(findings);

    print_findings(&findings, &args.format);

    if !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
