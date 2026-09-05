//! Language-specific Git signature tests. Repositories are built at runtime.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::coverage::{ArtifactStatus, CoverageStatus};
use chaincheck::git::{scan_git, system_git};
use chaincheck::model::Severity;
use chaincheck::processutil::ToolProbe;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-camp-git-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn git_available() -> bool {
    matches!(system_git(), ToolProbe::Present)
}

fn git_ok(repo: &Path, env: &[(&str, &str)], args: &[&str]) -> bool {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn build_repo(
    base: &Path,
    name: &str,
    author_name: &str,
    email: &str,
    subject: &str,
) -> Option<PathBuf> {
    if !git_available() {
        return None;
    }
    let repo = base.join(name);
    fs::create_dir_all(&repo).ok()?;
    let env = [
        ("GIT_AUTHOR_DATE", "2026-08-05T12:00:00+00:00"),
        ("GIT_COMMITTER_DATE", "2026-08-05T12:00:00+00:00"),
        ("GIT_AUTHOR_NAME", author_name),
        ("GIT_AUTHOR_EMAIL", email),
        ("GIT_COMMITTER_NAME", author_name),
        ("GIT_COMMITTER_EMAIL", email),
    ];
    if !git_ok(&repo, &env, &["init", "-q"]) {
        return None;
    }
    if !git_ok(&repo, &env, &["config", "user.email", email]) {
        return None;
    }
    if !git_ok(&repo, &env, &["config", "user.name", author_name]) {
        return None;
    }
    let _ = git_ok(&repo, &env, &["config", "commit.gpgsign", "false"]);
    fs::write(repo.join("README.md"), "fixture\n").ok()?;
    if !git_ok(&repo, &env, &["add", "-A"]) {
        return None;
    }
    if !git_ok(&repo, &env, &["commit", "-q", "-m", subject]) {
        return None;
    }
    Some(repo)
}

#[test]
fn git_program_none_is_skipped_without_uninstalling() {
    let output = scan_git(&[PathBuf::from("/tmp/repo")], None);
    assert_eq!(output.coverage.status(), CoverageStatus::Skipped);
    assert!(output.findings.is_empty());
    if git_available() {
        assert!(matches!(system_git(), ToolProbe::Present));
    }
}

#[test]
fn git_worm_signature_is_high_when_git_exists() {
    if !git_available() {
        return;
    }
    let base = tmp();
    let Some(repo) = build_repo(
        &base,
        "git-high",
        "claude",
        "claude@users.noreply.github.com",
        "chore: update config",
    ) else {
        cleanup(&base);
        return;
    };
    let output = scan_git(&[repo], Some(Path::new("git")));
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "malicious-git-signature" && f.severity == Severity::High),
        "{:?}",
        output.findings
    );
    cleanup(&base);
}

#[test]
fn git_email_only_is_medium_when_git_exists() {
    if !git_available() {
        return;
    }
    let base = tmp();
    let Some(repo) = build_repo(
        &base,
        "git-email",
        "claude",
        "claude@users.noreply.github.com",
        "unrelated subject",
    ) else {
        cleanup(&base);
        return;
    };
    let output = scan_git(&[repo], Some(Path::new("git")));
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "suspicious-git-author" && f.severity == Severity::Medium),
        "{:?}",
        output.findings
    );
    assert!(
        output
            .findings
            .iter()
            .all(|f| f.code.as_str() != "malicious-git-signature")
    );
    cleanup(&base);
}

#[test]
fn git_display_name_is_not_required_for_high() {
    if !git_available() {
        return;
    }
    let base = tmp();
    let Some(repo) = build_repo(
        &base,
        "git-name",
        "not-claude",
        "claude@users.noreply.github.com",
        "chore: update config",
    ) else {
        cleanup(&base);
        return;
    };
    let output = scan_git(&[repo], Some(Path::new("git")));
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "malicious-git-signature" && f.severity == Severity::High),
        "{:?}",
        output.findings
    );
    cleanup(&base);
}

#[test]
fn oversized_git_stdout_is_partial_without_findings() {
    let base = tmp();
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let fake = base.join("fake-git");
    fs::write(
        &fake,
        "#!/bin/sh\ndd if=/dev/zero bs=1024 count=9000 2>/dev/null\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).unwrap();
    let output = scan_git(&[repo], Some(&fake));
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert!(
        output
            .coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::Oversized)
    );
    cleanup(&base);
}
