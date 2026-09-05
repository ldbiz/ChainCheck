//! Rust-only campaign payload, discovery, and corroboration-boundary tests.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::campaign::{
    CampaignIntelligence, DET_CREDENTIALS, DET_DNS_CACHE, DET_GIT_HISTORY, DET_HOSTS_FILE,
    LIMIT_PAYLOAD, discover_campaign, scan_campaign_artifacts, scan_payload,
};
use chaincheck::cli::ProcessConfig;
use chaincheck::coverage::{
    ArtifactStatus, CoverageStatus, DetectorCoverage, MAX_ARTIFACT_FAILURE_EXAMPLES,
};
use chaincheck::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, parse_malware_feed};
use chaincheck::model::{Ecosystem, Severity};
use chaincheck::npm::scan_artefact;
use chaincheck::scan::{DetectorOutput, HostDetectorOutputs, ScanScope, scan_with_host_outputs};

const TINY_NPM: &[u8] = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;
const TINY_PYPI: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;
const TWO_SIGNALS: &[u8] = b"execFileSync('bun');\nfetch('https://npm-cache.com/router');\n";

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-camp-fault-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn shared(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/shared")
        .join(relative)
}

fn snapshot() -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        EcosystemIntelligence::Available(parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap()),
        EcosystemIntelligence::Available(parse_malware_feed(TINY_PYPI, Ecosystem::Pypi).unwrap()),
    )
}

fn mkfifo(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn mkfifo(pathname: *const i8, mode: u32) -> i32;
    }
    let c = CString::new(path.as_os_str().as_bytes()).expect("fifo path");
    let rc = unsafe { mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
}

fn first_failure(output: &chaincheck::scan::DetectorOutput) -> Option<ArtifactStatus> {
    output
        .coverage
        .examples()
        .first()
        .map(|e| e.status)
        .or_else(|| output.coverage.failure_counts().keys().copied().next())
}

#[test]
fn oversized_payload_is_partial_without_a_finding() {
    let root = tmp();
    let path = root.join("setup.mjs");
    let file = File::create(&path).unwrap();
    file.set_len(LIMIT_PAYLOAD + 1).unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_failure(&output), Some(ArtifactStatus::Oversized));
    cleanup(&root);
}

#[test]
fn unreadable_payload_is_partial_without_a_finding() {
    let root = tmp();
    let path = root.join("setup.mjs");
    fs::write(&path, TWO_SIGNALS).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    let mut restore = fs::metadata(&path).unwrap().permissions();
    restore.set_mode(0o644);
    fs::set_permissions(&path, restore).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_failure(&output), Some(ArtifactStatus::Unreadable));
    cleanup(&root);
}

#[test]
fn symlink_payload_is_partial_without_unknown_hash_fallthrough() {
    let root = tmp();
    let target = root.join("target.mjs");
    fs::write(&target, TWO_SIGNALS).unwrap();
    let path = root.join("setup.mjs");
    symlink(&target, &path).unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_failure(&output), Some(ArtifactStatus::Unreadable));
    cleanup(&root);
}

#[test]
fn fifo_payload_is_partial_without_a_finding() {
    let root = tmp();
    let path = root.join("setup.mjs");
    mkfifo(&path);
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_failure(&output), Some(ArtifactStatus::Unreadable));
    cleanup(&root);
}

#[test]
fn malformed_parent_manifest_is_payload_partial_not_high() {
    let root = tmp();
    fs::write(root.join("package.json"), b"{not-json").unwrap();
    let path = root.join("setup.mjs");
    fs::write(&path, TWO_SIGNALS).unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert!(
        output
            .coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::ParseFailed)
    );
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].code.as_str(), "payload-pattern");
    assert_eq!(output.findings[0].severity, Severity::Medium);
    cleanup(&root);
}

#[test]
fn unreadable_parent_manifest_is_payload_partial_not_high() {
    let root = tmp();
    let manifest = root.join("package.json");
    fs::write(&manifest, br#"{"scripts":{"preinstall":"node setup.mjs"}}"#).unwrap();
    let mut perms = fs::metadata(&manifest).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&manifest, perms).unwrap();
    let path = root.join("setup.mjs");
    fs::write(&path, TWO_SIGNALS).unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    let mut restore = fs::metadata(&manifest).unwrap().permissions();
    restore.set_mode(0o644);
    fs::set_permissions(&manifest, restore).unwrap();
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].code.as_str(), "payload-pattern");
    assert_eq!(output.findings[0].severity, Severity::Medium);
    cleanup(&root);
}

#[test]
fn parent_inspection_failure_does_not_invent_a_malware_finding() {
    let root = tmp();
    fs::write(root.join("package.json"), b"{not-json").unwrap();
    let path = root.join("setup.mjs");
    fs::write(&path, b"console.log('benign');\n").unwrap();
    let output = scan_payload(&path, &CampaignIntelligence::bundled());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].code.as_str(), "payload-name");
    assert_eq!(output.findings[0].severity, Severity::Info);
    cleanup(&root);
}

#[test]
fn walk_discovers_vscode_and_claude_configs() {
    let root = tmp();
    let vscode = root.join(".vscode");
    let claude = root.join(".claude");
    fs::create_dir_all(&vscode).unwrap();
    fs::create_dir_all(&claude).unwrap();
    fs::copy(
        shared("campaign/config/vscode-strong/tasks.json"),
        vscode.join("tasks.json"),
    )
    .unwrap();
    fs::copy(
        shared("campaign/config/claude-weak/settings.json"),
        claude.join("settings.json"),
    )
    .unwrap();
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
    );
    let output = scan_campaign_artifacts(&artifacts, &CampaignIntelligence::bundled());
    let findings: Vec<_> = output.iter().flat_map(|o| o.findings.iter()).collect();
    assert!(
        findings
            .iter()
            .any(|f| f.code.as_str() == "malicious-config-content" && f.severity == Severity::High),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.code.as_str() == "config-ioc-reference" && f.severity == Severity::Medium),
        "{findings:?}"
    );
    cleanup(&root);
}

#[test]
fn walk_discovers_payload_under_node_modules() {
    let root = tmp();
    let nested = root.join("node_modules/pkg");
    fs::create_dir_all(&nested).unwrap();
    fs::copy(
        shared("campaign/payloads/benign-setup.mjs"),
        nested.join("setup.mjs"),
    )
    .unwrap();
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
    );
    assert!(
        artifacts
            .payloads
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == "setup.mjs")),
        "payloads: {:?}",
        artifacts.payloads
    );
    cleanup(&root);
}

#[test]
fn venv_payload_is_not_required_to_be_found() {
    let root = tmp();
    let venv = root.join(".venv");
    fs::create_dir_all(&venv).unwrap();
    fs::copy(
        shared("campaign/payloads/benign-setup.mjs"),
        venv.join("setup.mjs"),
    )
    .unwrap();
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
    );
    assert!(
        artifacts.payloads.is_empty(),
        "campaign walk must prune .venv: {:?}",
        artifacts.payloads
    );
    cleanup(&root);
}

#[test]
fn explicit_root_does_not_widen_to_home_payload() {
    let base = tmp();
    let project = base.join("project");
    let home = base.join("home");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(project.join("README"), b"ok").unwrap();
    fs::copy(
        shared("campaign/payloads/benign-setup.mjs"),
        home.join("setup.mjs"),
    )
    .unwrap();
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot {
            root: project.clone(),
        },
        &ProcessConfig::default(),
        Some(&home),
    );
    assert!(
        artifacts.payloads.is_empty(),
        "explicit root widened: {:?}",
        artifacts.payloads
    );

    let silent = |detector| DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: DetectorCoverage::skipped(detector),
    };
    let result = scan_with_host_outputs(
        ScanScope::ExplicitRoot { root: project },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(),
        &CampaignIntelligence::bundled(),
        HostDetectorOutputs {
            git: silent(DET_GIT_HISTORY),
            hosts: silent(DET_HOSTS_FILE),
            dns: silent(DET_DNS_CACHE),
            credentials: silent(DET_CREDENTIALS),
        },
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "payload-name"),
        "home payload leaked into explicit-root scan: {:?}",
        result.findings
    );
    let names: Vec<_> = result
        .coverage
        .iter()
        .map(|c| c.detector().as_str())
        .collect();
    assert!(names.contains(&"hosts-file"), "{names:?}");
    assert!(names.contains(&"dns-cache"), "{names:?}");
    assert!(names.contains(&"credentials"), "{names:?}");
    cleanup(&base);
}

#[test]
fn directory_symlink_does_not_escape_campaign_walk() {
    let base = tmp();
    let root = base.join("root");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::copy(
        shared("campaign/payloads/benign-setup.mjs"),
        outside.join("setup.mjs"),
    )
    .unwrap();
    symlink(&outside, root.join("link")).unwrap();
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
    );
    assert!(
        artifacts.payloads.is_empty(),
        "dir symlink escaped walk: {:?}",
        artifacts.payloads
    );
    cleanup(&base);
}

#[test]
fn whole_user_finds_payload_under_synthetic_npm_prefix() {
    let base = tmp();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let prefix = base.join("prefix");
    let modules = prefix.join("lib/node_modules/pkg");
    fs::create_dir_all(&modules).unwrap();
    fs::copy(
        shared("campaign/payloads/benign-setup.mjs"),
        modules.join("setup.mjs"),
    )
    .unwrap();
    let mut config = ProcessConfig::default();
    config.npm_config_prefix = Some(prefix);
    let artifacts = discover_campaign(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
    );
    assert!(
        artifacts
            .payloads
            .iter()
            .any(|p| p.ends_with("lib/node_modules/pkg/setup.mjs")),
        "global npm root payload missing: {:?}",
        artifacts.payloads
    );
    cleanup(&base);
}

#[test]
fn campaign_log_findings_are_not_package_evidence() {
    let output = scan_artefact(
        "npm-log",
        &shared("npm/logs/argv-install.log"),
        &snapshot().npm,
    )
    .unwrap();
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "campaign-ioc-log")
    );
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "npm-install-log")
    );
    assert!(
        output
            .package_evidence
            .iter()
            .all(|e| e.package.identity.name().as_str() == "keyv"),
        "{:?}",
        output.package_evidence
    );
    assert!(
        !output.package_evidence.is_empty(),
        "generic log evidence should still exist"
    );
}

#[test]
fn campaign_walk_retains_full_failure_counts_beyond_example_cap() {
    let root = tmp();
    let count = MAX_ARTIFACT_FAILURE_EXAMPLES + 3;
    let mut blocked = Vec::new();
    for i in 0..count {
        let dir = root.join(format!("blocked-{i}"));
        fs::create_dir_all(&dir).unwrap();
        let mut perms = fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&dir, perms).unwrap();
        blocked.push(dir);
    }
    let artifacts = discover_campaign(
        &ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
    );
    for dir in &blocked {
        let mut restore = fs::metadata(dir).unwrap().permissions();
        restore.set_mode(0o755);
        fs::set_permissions(dir, restore).unwrap();
    }
    assert_eq!(artifacts.walk_coverage.detector().as_str(), "campaign-walk");
    assert_eq!(
        artifacts.walk_coverage.failure_counts()[&ArtifactStatus::StatFailed],
        count as u32
    );
    assert_eq!(
        artifacts.walk_coverage.examples().len(),
        MAX_ARTIFACT_FAILURE_EXAMPLES
    );
    assert_eq!(artifacts.walk_coverage.status(), CoverageStatus::Partial);
    cleanup(&root);
}
