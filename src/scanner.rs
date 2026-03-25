use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::cli::Args;
use crate::finding::Finding;
use crate::patterns::PatternSet;

struct CommitInfo {
    hash: String,
    message: String,
    date: String,
}

pub fn scan(args: &Args) -> Result<Vec<Finding>> {
    let repo = gix::discover(&args.repo)
        .with_context(|| format!("Failed to open git repository at {:?}", args.repo))?;

    let ext_filter = args.extension_list();
    let max_size = args.max_file_size;

    // Parse --since into a unix timestamp
    let since_ts: Option<i64> = args.since.as_ref().and_then(|s| parse_since(s));

    // Collect commit tips from branches
    let tips = collect_tips(&repo, args.all_branches)?;
    if tips.is_empty() && !args.dangling && args.fetch_orphans.is_none() {
        eprintln!("No commits found.");
        return Ok(Vec::new());
    }

    // Walk reachable commits and collect IDs + metadata
    let mut commits: Vec<(gix::ObjectId, CommitInfo)> = Vec::new();
    let mut seen_ids: HashSet<gix::ObjectId> = HashSet::new();

    if !tips.is_empty() {
        let walk = repo
            .rev_walk(tips)
            .sorting(gix::revision::walk::Sorting::ByCommitTime(
                gix::traverse::commit::simple::CommitTimeOrder::NewestFirst,
            ))
            .all()?;

        for info_result in walk {
            let info = info_result?;
            let commit_time = info.commit_time.unwrap_or(0);

            // Apply --since filter: sorted newest-first, break when older
            if let Some(ts) = since_ts {
                if commit_time < ts {
                    break;
                }
            }

            let commit = info.id().object()?.into_commit();
            let message = commit
                .message_raw()
                .map(|m| m.to_string())
                .unwrap_or_default();
            let message_first_line = message.lines().next().unwrap_or("").to_string();

            let date = format_timestamp(commit_time);

            seen_ids.insert(info.id);
            commits.push((
                info.id,
                CommitInfo {
                    hash: info.id.to_string(),
                    message: message_first_line,
                    date,
                },
            ));
        }
    }

    let reachable_count = commits.len();

    // Resolve paths and drop the initial repo handle
    let git_dir = repo.path().to_path_buf();
    let work_dir = repo
        .workdir()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| git_dir.clone());
    drop(repo);

    // --dangling: find unreachable commits via git fsck
    if args.dangling {
        let dangling = collect_dangling_commits(&work_dir)?;
        let new_dangling: Vec<_> = dangling
            .into_iter()
            .filter(|id| !seen_ids.contains(id))
            .collect();

        if !new_dangling.is_empty() {
            eprintln!(
                "Found {} dangling/unreachable commits to scan...",
                new_dangling.len()
            );
            let dangling_repo = gix::open(&git_dir)
                .context("Failed to open repo for dangling commit scan")?;
            for oid in &new_dangling {
                if let Ok(commit) = dangling_repo.find_commit(*oid) {
                    let message = commit
                        .message_raw()
                        .map(|m| m.to_string())
                        .unwrap_or_default();
                    let message_first_line = message.lines().next().unwrap_or("").to_string();

                    let time = commit.time().map(|t| t.seconds).unwrap_or(0);

                    if let Some(ts) = since_ts {
                        if time < ts {
                            continue;
                        }
                    }

                    let date = format_timestamp(time);
                    seen_ids.insert(*oid);
                    commits.push((
                        *oid,
                        CommitInfo {
                            hash: oid.to_string(),
                            message: format!("[DANGLING] {}", message_first_line),
                            date,
                        },
                    ));
                }
            }
        }
    }

    // --fetch-orphans: fetch specific commits from remote, then reopen repo to read them
    if let Some(ref orphan_input) = args.fetch_orphans {
        let orphan_shas = parse_orphan_input(orphan_input)?;

        if !orphan_shas.is_empty() {
            eprintln!(
                "Fetching {} orphan commit(s) from remote...",
                orphan_shas.len()
            );
            let fetched = fetch_orphan_commits(&work_dir, &orphan_shas)?;

            // Reopen repo AFTER fetch so gix sees the newly-fetched objects
            let orphan_repo = gix::open(&git_dir)
                .context("Failed to reopen repo after fetching orphans")?;

            for sha in &fetched {
                let oid = gix::ObjectId::from_hex(sha.as_bytes())
                    .with_context(|| format!("Invalid SHA: {}", sha))?;

                if seen_ids.contains(&oid) {
                    continue;
                }

                match orphan_repo.find_commit(oid) {
                    Ok(commit) => {
                        let message = commit
                            .message_raw()
                            .map(|m| m.to_string())
                            .unwrap_or_default();
                        let message_first_line =
                            message.lines().next().unwrap_or("").to_string();

                        let time = commit.time().map(|t| t.seconds).unwrap_or(0);
                        let date = format_timestamp(time);

                        seen_ids.insert(oid);
                        commits.push((
                            oid,
                            CommitInfo {
                                hash: oid.to_string(),
                                message: format!("[ORPHAN] {}", message_first_line),
                                date,
                            },
                        ));
                    }
                    Err(e) => {
                        eprintln!(
                            "  Warning: fetched {} but cannot read commit: {}",
                            &sha[..8.min(sha.len())],
                            e
                        );
                    }
                }
            }
        }
    }

    // --discover-orphans: auto-discover orphan SHAs from reflog + GitHub/GitLab API
    if args.discover_orphans {
        eprintln!("Discovering orphan commits...");
        let discovered = crate::orphans::discover_orphan_shas(&work_dir)?;

        if discovered.is_empty() {
            eprintln!("  No orphan commits discovered.");
        } else {
            eprintln!(
                "  Discovered {} orphan candidate(s), fetching from remote...",
                discovered.len()
            );
            let fetched = fetch_orphan_commits(&work_dir, &discovered)?;

            if !fetched.is_empty() {
                let discover_repo = gix::open(&git_dir)
                    .context("Failed to reopen repo after fetching discovered orphans")?;

                for sha in &fetched {
                    let oid = match gix::ObjectId::from_hex(sha.as_bytes()) {
                        Ok(id) => id,
                        Err(_) => continue,
                    };

                    if seen_ids.contains(&oid) {
                        continue;
                    }

                    if let Ok(commit) = discover_repo.find_commit(oid) {
                        let message = commit
                            .message_raw()
                            .map(|m| m.to_string())
                            .unwrap_or_default();
                        let message_first_line =
                            message.lines().next().unwrap_or("").to_string();

                        let time = commit.time().map(|t| t.seconds).unwrap_or(0);

                        if let Some(ts) = since_ts {
                            if time < ts {
                                continue;
                            }
                        }

                        let date = format_timestamp(time);
                        seen_ids.insert(oid);
                        commits.push((
                            oid,
                            CommitInfo {
                                hash: oid.to_string(),
                                message: format!("[DISCOVERED] {}", message_first_line),
                                date,
                            },
                        ));
                    }
                }
            }
        }
    }

    let dangling_count = commits.len() - reachable_count;
    if dangling_count > 0 {
        eprintln!(
            "Scanning {} reachable + {} dangling/orphan commits ({} total)...",
            reachable_count,
            dangling_count,
            commits.len()
        );
    } else {
        eprintln!("Scanning {} commits...", commits.len());
    }

    // gix::Repository is not Sync, so we open a fresh repo per rayon thread
    // git_dir was captured earlier before any repo handles were dropped
    let repo_path = git_dir.clone();

    let findings: Mutex<Vec<Finding>> = Mutex::new(Vec::new());

    commits.par_iter().for_each(|(oid, commit_info)| {
        let thread_repo = match gix::open(&repo_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "Warning: failed to open repo for commit {}: {}",
                    &commit_info.hash[..8],
                    e
                );
                return;
            }
        };

        match scan_commit_tree(&thread_repo, oid, commit_info, &ext_filter, max_size) {
            Ok(commit_findings) => {
                if !commit_findings.is_empty() {
                    findings.lock().unwrap().extend(commit_findings);
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: failed to scan commit {}: {}",
                    &commit_info.hash[..8],
                    e
                );
            }
        }
    });

    Ok(findings.into_inner().unwrap())
}

fn scan_commit_tree(
    repo: &gix::Repository,
    oid: &gix::ObjectId,
    commit_info: &CommitInfo,
    ext_filter: &Option<Vec<String>>,
    max_size: u64,
) -> Result<Vec<Finding>> {
    let patterns = PatternSet::default_patterns();

    let commit = repo.find_commit(*oid)?;
    let tree = commit.tree()?;

    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;

    let mut findings = Vec::new();

    for entry in &recorder.records {
        if entry.mode.is_tree() || entry.mode.is_commit() {
            continue;
        }

        let path = entry.filepath.to_string();

        // Extension filter
        if let Some(exts) = ext_filter {
            let file_ext = std::path::Path::new(&path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase());
            match file_ext {
                Some(ext) if exts.contains(&ext) => {}
                _ => continue,
            }
        }

        // Read blob
        let obj = match repo.find_object(entry.oid) {
            Ok(obj) => obj,
            Err(_) => continue,
        };

        // Size check
        if obj.data.len() as u64 > max_size {
            continue;
        }

        // Binary detection: skip files with null bytes
        if is_likely_binary(&obj.data) {
            continue;
        }

        let text = String::from_utf8_lossy(&obj.data);

        // Pattern matching
        let matches = patterns.scan_text(&text);
        for (pattern_name, matched_text) in matches {
            findings.push(Finding {
                commit_hash: commit_info.hash.clone(),
                commit_message: commit_info.message.clone(),
                commit_date: commit_info.date.clone(),
                file_path: path.clone(),
                pattern_name: pattern_name.to_string(),
                matched_text,
            });
        }
    }

    Ok(findings)
}

/// Find dangling/unreachable commits using `git fsck`.
fn collect_dangling_commits(work_dir: &PathBuf) -> Result<Vec<gix::ObjectId>> {
    let output = Command::new("git")
        .args(["fsck", "--unreachable", "--no-reflogs", "--no-progress"])
        .current_dir(work_dir)
        .output()
        .context("Failed to run git fsck")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();

    for line in stdout.lines() {
        // Lines look like: "unreachable commit abc123..."
        if let Some(sha) = line.strip_prefix("unreachable commit ") {
            let sha = sha.trim();
            if let Ok(oid) = gix::ObjectId::from_hex(sha.as_bytes()) {
                commits.push(oid);
            }
        }
    }

    Ok(commits)
}

/// Fetch specific orphan commits from the remote by SHA.
/// GitHub/GitLab retain orphan objects — we can fetch them directly.
fn fetch_orphan_commits(work_dir: &PathBuf, shas: &[String]) -> Result<Vec<String>> {
    let mut fetched = Vec::new();

    for sha in shas {
        // Validate SHA format
        if sha.len() < 7 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            eprintln!("Warning: skipping invalid SHA: {}", sha);
            continue;
        }

        // Try to fetch the specific commit from origin
        let result = Command::new("git")
            .args(["fetch", "origin", sha])
            .current_dir(work_dir)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                eprintln!("  Fetched orphan commit: {}", &sha[..8.min(sha.len())]);
                fetched.push(sha.clone());
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Some servers don't allow fetching by SHA — try uploadpack.allowReachableSHA1InWant
                if stderr.contains("no such remote ref") || stderr.contains("couldn't find remote ref") {
                    // Try the protocol-level fetch as a fallback
                    let result2 = Command::new("git")
                        .args([
                            "fetch",
                            "--no-tags",
                            "origin",
                            &format!("{}:{}", sha, sha),
                        ])
                        .current_dir(work_dir)
                        .output();

                    match result2 {
                        Ok(out2) if out2.status.success() => {
                            eprintln!("  Fetched orphan commit (direct): {}", &sha[..8.min(sha.len())]);
                            fetched.push(sha.clone());
                        }
                        _ => {
                            eprintln!(
                                "  Warning: could not fetch orphan {}. Server may not allow SHA fetching.",
                                &sha[..8.min(sha.len())]
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "  Warning: failed to fetch {}: {}",
                        &sha[..8.min(sha.len())],
                        stderr.trim()
                    );
                }
            }
            Err(e) => {
                eprintln!("  Warning: git fetch failed for {}: {}", &sha[..8.min(sha.len())], e);
            }
        }
    }

    Ok(fetched)
}

/// Parse orphan input: comma-separated SHAs or @filepath.
fn parse_orphan_input(input: &str) -> Result<Vec<String>> {
    if let Some(path) = input.strip_prefix('@') {
        // Read SHAs from file, one per line
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read orphan SHAs from file: {}", path))?;
        Ok(content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect())
    } else {
        // Comma-separated SHAs
        Ok(input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }
}

fn collect_tips(repo: &gix::Repository, all_branches: bool) -> Result<Vec<gix::ObjectId>> {
    if all_branches {
        let mut tips = Vec::new();
        let refs = repo.references()?;
        for reference in refs.all()? {
            match reference {
                Ok(mut r) => {
                    match r.peel_to_id_in_place() {
                        Ok(id) => tips.push(id.detach()),
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
        if tips.is_empty() {
            if let Ok(head) = repo.head_id() {
                tips.push(head.detach());
            }
        }
        Ok(tips)
    } else {
        let head = repo.head_id().context("Repository has no HEAD")?;
        Ok(vec![head.detach()])
    }
}

fn parse_since(input: &str) -> Option<i64> {
    if let Ok(time) = gix::date::parse(input, Some(std::time::SystemTime::now())) {
        return Some(time.seconds);
    }
    parse_relative_duration(input)
}

fn parse_relative_duration(input: &str) -> Option<i64> {
    let input = input.trim().to_lowercase();
    let input = input.trim_end_matches(" ago").trim();

    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }

    let amount: i64 = parts[0].parse().ok()?;
    let unit = parts[1];

    let seconds_per_unit = match unit {
        "second" | "seconds" | "sec" | "secs" => 1i64,
        "minute" | "minutes" | "min" | "mins" => 60,
        "hour" | "hours" | "hr" | "hrs" => 3600,
        "day" | "days" => 86400,
        "week" | "weeks" => 604800,
        "month" | "months" => 2_592_000,
        "year" | "years" => 31_536_000,
        _ => return None,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;

    Some(now - (amount * seconds_per_unit))
}

fn format_timestamp(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_likely_binary(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let check = &data[..data.len().min(8192)];
    let null_count = check.iter().filter(|&&b| b == 0).count();
    null_count > 0
}
