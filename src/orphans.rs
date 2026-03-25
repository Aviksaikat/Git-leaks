use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Discovers orphan commit SHAs from multiple sources:
/// 1. Local reflog (old branch tips from force-pushes/rebases)
/// 2. GitHub/GitLab API (push events, PR commits)
pub fn discover_orphan_shas(work_dir: &Path) -> Result<Vec<String>> {
    let mut candidates: HashSet<String> = HashSet::new();

    // Layer 1: Local reflog — find old branch tips
    let reflog_shas = discover_from_reflog(work_dir)?;
    eprintln!(
        "  Reflog: found {} candidate SHAs from local history",
        reflog_shas.len()
    );
    candidates.extend(reflog_shas);

    // Layer 2: GitHub/GitLab API — push events + PR commits
    if let Some(remote_url) = get_remote_url(work_dir) {
        if let Some((platform, owner, repo)) = parse_remote_url(&remote_url) {
            match platform.as_str() {
                "github" => {
                    // Try gh CLI first (uses existing SSH/OAuth auth), fall back to curl+token
                    let api_shas = if has_gh_cli() {
                        eprintln!("  Using gh CLI for GitHub API (SSH auth)...");
                        discover_from_github_gh(&owner, &repo)?
                    } else {
                        let token = get_api_token(&platform);
                        eprintln!("  Using curl for GitHub API (token auth)...");
                        discover_from_github(&owner, &repo, token.as_deref())?
                    };
                    eprintln!(
                        "  GitHub API: found {} candidate SHAs from events + PRs",
                        api_shas.len()
                    );
                    candidates.extend(api_shas);
                }
                "gitlab" => {
                    let token = get_api_token(&platform);
                    let api_shas = discover_from_gitlab(&owner, &repo, token.as_deref())?;
                    eprintln!(
                        "  GitLab API: found {} candidate SHAs from events",
                        api_shas.len()
                    );
                    candidates.extend(api_shas);
                }
                _ => {}
            }
        }
    }

    // Layer 3: Filter out SHAs that are already reachable from branches
    let reachable = get_reachable_shas(work_dir)?;
    let orphans: Vec<String> = candidates
        .into_iter()
        .filter(|sha| !reachable.contains(sha))
        .collect();

    Ok(orphans)
}

/// Extract old branch tips from git reflog.
fn discover_from_reflog(work_dir: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["reflog", "--all", "--format=%H"])
        .current_dir(work_dir)
        .output()
        .context("Failed to run git reflog")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && l.len() >= 40)
        .collect())
}

/// Get all SHAs reachable from current branch tips.
fn get_reachable_shas(work_dir: &Path) -> Result<HashSet<String>> {
    let output = Command::new("git")
        .args(["rev-list", "--all"])
        .current_dir(work_dir)
        .output()
        .context("Failed to run git rev-list")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Get the remote origin URL.
fn get_remote_url(work_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(work_dir)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Parse a remote URL into (platform, owner, repo).
/// Handles: https://github.com/owner/repo.git, git@github.com:owner/repo.git,
///           https://gitlab.com/owner/repo.git, git@gitlab.com:owner/repo.git
fn parse_remote_url(url: &str) -> Option<(String, String, String)> {
    let url = url.trim().trim_end_matches(".git");

    // SSH format: git@github.com:owner/repo
    if let Some(rest) = url.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        let platform = detect_platform(host);
        let parts: Vec<&str> = path.splitn(2, '/').collect();
        if parts.len() == 2 {
            return Some((platform, parts[0].to_string(), parts[1].to_string()));
        }
    }

    // HTTPS format: https://github.com/owner/repo
    if url.starts_with("https://") || url.starts_with("http://") {
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let parts: Vec<&str> = without_scheme.splitn(3, '/').collect();
        if parts.len() >= 3 {
            let platform = detect_platform(parts[0]);
            return Some((platform, parts[1].to_string(), parts[2].to_string()));
        }
    }

    None
}

fn detect_platform(host: &str) -> String {
    if host.contains("github") {
        "github".to_string()
    } else if host.contains("gitlab") {
        "gitlab".to_string()
    } else {
        "unknown".to_string()
    }
}

fn get_api_token(platform: &str) -> Option<String> {
    match platform {
        "github" => std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .ok(),
        "gitlab" => std::env::var("GITLAB_TOKEN")
            .or_else(|_| std::env::var("GL_TOKEN"))
            .ok(),
        _ => None,
    }
}

/// Check if `gh` CLI is installed and authenticated.
fn has_gh_cli() -> bool {
    Command::new("gh")
        .args(["auth", "status"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Discover orphan SHAs from GitHub using `gh` CLI (uses existing SSH/OAuth auth).
fn discover_from_github_gh(owner: &str, repo: &str) -> Result<Vec<String>> {
    let mut shas = Vec::new();

    // 1. Push events — extract 'before' SHAs
    for page in 1..=10 {
        let endpoint = format!(
            "repos/{}/{}/events?page={}&per_page=100",
            owner, repo, page
        );
        let output = Command::new("gh")
            .args(["api", &endpoint])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => break,
        };

        let body = String::from_utf8_lossy(&output.stdout);
        let events: Vec<serde_json::Value> = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => break,
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if event["type"].as_str() != Some("PushEvent") {
                continue;
            }
            if let Some(before) = event["payload"]["before"].as_str() {
                if before.len() >= 40 && before != "0000000000000000000000000000000000000000" {
                    shas.push(before.to_string());
                }
            }
        }
    }

    // 2. PR commits from merged PRs
    let pr_endpoint = format!(
        "repos/{}/{}/pulls?state=closed&per_page=100",
        owner, repo
    );
    let output = Command::new("gh")
        .args(["api", &pr_endpoint])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let body = String::from_utf8_lossy(&output.stdout);
            let prs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

            for pr in &prs {
                if pr["merged_at"].as_str().is_none() {
                    continue;
                }

                let pr_number = match pr["number"].as_u64() {
                    Some(n) => n,
                    None => continue,
                };

                let commits_endpoint = format!(
                    "repos/{}/{}/pulls/{}/commits?per_page=100",
                    owner, repo, pr_number
                );
                let commits_output = Command::new("gh")
                    .args(["api", &commits_endpoint])
                    .output();

                if let Ok(co) = commits_output {
                    if co.status.success() {
                        let commits_body = String::from_utf8_lossy(&co.stdout);
                        let commits: Vec<serde_json::Value> =
                            serde_json::from_str(&commits_body).unwrap_or_default();
                        for commit in &commits {
                            if let Some(sha) = commit["sha"].as_str() {
                                shas.push(sha.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(shas)
}

/// Discover orphan SHAs from GitHub Events API + PR commits (curl fallback).
fn discover_from_github(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<String>> {
    let mut shas = Vec::new();

    // 1. Push events — extract 'before' SHAs (old branch tips)
    for page in 1..=10 {
        let url = format!(
            "https://api.github.com/repos/{}/{}/events?page={}",
            owner, repo, page
        );
        let body = http_get(&url, token)?;

        let events: Vec<serde_json::Value> = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => break,
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if event["type"].as_str() != Some("PushEvent") {
                continue;
            }
            // The 'before' SHA is the old branch tip — potentially orphaned after force-push
            if let Some(before) = event["payload"]["before"].as_str() {
                if before.len() >= 40 && before != "0000000000000000000000000000000000000000" {
                    shas.push(before.to_string());
                }
            }
        }
    }

    // 2. PR commits from merged PRs — squash-merged PRs orphan their original commits
    let pr_url = format!(
        "https://api.github.com/repos/{}/{}/pulls?state=closed&per_page=100",
        owner, repo
    );
    let body = http_get(&pr_url, token)?;
    let prs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

    for pr in &prs {
        if pr["merged_at"].as_str().is_none() {
            continue; // Not merged
        }

        let pr_number = match pr["number"].as_u64() {
            Some(n) => n,
            None => continue,
        };

        // Get commits for this PR
        let commits_url = format!(
            "https://api.github.com/repos/{}/{}/pulls/{}/commits?per_page=100",
            owner, repo, pr_number
        );
        let commits_body = http_get(&commits_url, token)?;
        let commits: Vec<serde_json::Value> =
            serde_json::from_str(&commits_body).unwrap_or_default();

        for commit in &commits {
            if let Some(sha) = commit["sha"].as_str() {
                shas.push(sha.to_string());
            }
        }
    }

    Ok(shas)
}

/// Discover orphan SHAs from GitLab Events API.
fn discover_from_gitlab(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<String>> {
    let mut shas = Vec::new();

    // URL-encode the project path (owner/repo -> owner%2Frepo)
    let project_id = format!("{}/{}", owner, repo).replace('/', "%2F");

    // Push events
    let url = format!(
        "https://gitlab.com/api/v4/projects/{}/events?action=pushed&per_page=100",
        project_id
    );
    let body = http_get(&url, token)?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

    for event in &events {
        if let Some(push_data) = event.get("push_data") {
            // commit_from is the old branch tip
            if let Some(from) = push_data["commit_from"].as_str() {
                if from.len() >= 40 && from != "0000000000000000000000000000000000000000" {
                    shas.push(from.to_string());
                }
            }
        }
    }

    // MR commits
    let mr_url = format!(
        "https://gitlab.com/api/v4/projects/{}/merge_requests?state=merged&per_page=100",
        project_id
    );
    let body = http_get(&mr_url, token)?;
    let mrs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

    for mr in &mrs {
        let mr_iid = match mr["iid"].as_u64() {
            Some(n) => n,
            None => continue,
        };

        let commits_url = format!(
            "https://gitlab.com/api/v4/projects/{}/merge_requests/{}/commits?per_page=100",
            project_id, mr_iid
        );
        let commits_body = http_get(&commits_url, token)?;
        let commits: Vec<serde_json::Value> =
            serde_json::from_str(&commits_body).unwrap_or_default();

        for commit in &commits {
            if let Some(sha) = commit["id"].as_str() {
                shas.push(sha.to_string());
            }
        }
    }

    Ok(shas)
}

/// Simple HTTP GET using curl (avoids adding reqwest dependency).
fn http_get(url: &str, token: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-L", "--max-time", "30"]);
    cmd.args(["-H", "Accept: application/vnd.github+json"]);
    cmd.args(["-H", "User-Agent: git-leaks"]);

    if let Some(t) = token {
        cmd.arg("-H");
        cmd.arg(format!("Authorization: Bearer {}", t));
    }

    cmd.arg(url);

    let output = cmd.output().context("Failed to run curl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("HTTP request failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
