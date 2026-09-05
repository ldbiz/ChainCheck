//! Full scan integration for Python evidence.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::campaign::CampaignIntelligence;
use chaincheck::cli::ProcessConfig;
use chaincheck::coverage::DetectorCoverage;
use chaincheck::intelligence::{
    EcosystemIntelligence, FeedFailure, IntelligenceSnapshot, parse_malware_feed,
};
use chaincheck::model::{Ecosystem, EvidenceKind, Severity};
use chaincheck::npm::scan_npm;
use chaincheck::python::scan_python;
use chaincheck::scan::{HostDetectorOutputs, ScanOutcome, ScanScope, scan_with_host_outputs};

const TINY_NPM: &[u8] = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;
const TINY_PYPI: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-scan-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn snapshot(npm_ok: bool, pypi_ok: bool) -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        if npm_ok {
            EcosystemIntelligence::Available(parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap())
        } else {
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        },
        if pypi_ok {
            EcosystemIntelligence::Available(
                parse_malware_feed(TINY_PYPI, Ecosystem::Pypi).unwrap(),
            )
        } else {
            EcosystemIntelligence::Unavailable(FeedFailure::Timeout)
        },
    )
}

fn silent_host() -> HostDetectorOutputs {
    HostDetectorOutputs {
        git: chaincheck::scan::DetectorOutput {
            findings: vec![],
            package_evidence: vec![],
            coverage: DetectorCoverage::skipped(chaincheck::campaign::DET_GIT_HISTORY),
        },
        hosts: chaincheck::scan::DetectorOutput {
            findings: vec![],
            package_evidence: vec![],
            coverage: DetectorCoverage::skipped(chaincheck::campaign::DET_HOSTS_FILE),
        },
        dns: chaincheck::scan::DetectorOutput {
            findings: vec![],
            package_evidence: vec![],
            coverage: DetectorCoverage::skipped(chaincheck::campaign::DET_DNS_CACHE),
        },
        credentials: chaincheck::scan::DetectorOutput {
            findings: vec![],
            package_evidence: vec![],
            coverage: DetectorCoverage::skipped(chaincheck::campaign::DET_CREDENTIALS),
        },
    }
}

#[test]
fn python_installed_high_yields_exit_two() {
    let base = tmp();
    let home = base.join("home");
    let site = home.join(".local/lib/python3.12/site-packages");
    fs::create_dir_all(&site.join("evil_pkg-1.2.3.dist-info")).unwrap();
    fs::write(
        site.join("evil_pkg-1.2.3.dist-info/METADATA"),
        "Name: evil-pkg\nVersion: 1.2.3\n",
    )
    .unwrap();
    let result = scan_python(
        ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(true, true),
    );
    assert_eq!(result.outcome, ScanOutcome::StrongEvidence);
    assert!(
        result
            .findings
            .iter()
            .any(|f| { f.severity == Severity::High && f.kind == EvidenceKind::InstalledPackage })
    );
    cleanup(&base);
}

#[test]
fn python_declaration_medium_yields_exit_one() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("requirements.txt"), "evil-pkg==1.2.3\n").unwrap();
    let result = scan_python(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
    );
    assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
    cleanup(&base);
}

#[test]
fn pypi_finding_beats_unavailable_npm_intel() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("requirements.txt"), "evil-pkg==1.2.3\n").unwrap();
    let result = scan_with_host_outputs(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(false, true),
        &CampaignIntelligence::bundled(),
        silent_host(),
    );
    assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
    cleanup(&base);
}

#[test]
fn npm_only_tree_unchanged_by_python_scan() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root.join("node_modules/keyv")).unwrap();
    fs::write(
        root.join("node_modules/keyv/package.json"),
        r#"{"name":"keyv","version":"6.0.0"}"#,
    )
    .unwrap();
    let npm = scan_npm(
        ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
    );
    let full = scan_with_host_outputs(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
        &CampaignIntelligence::bundled(),
        silent_host(),
    );
    let npm_high = npm
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let full_high = full
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    assert_eq!(npm_high, full_high);
    cleanup(&base);
}

#[test]
fn npm_and_pypi_same_name_do_not_cross_match() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("requirements.txt"), "keyv==6.0.0\n").unwrap();
    let result = scan_python(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
    );
    assert!(result.findings.is_empty());
    cleanup(&base);
}

#[test]
fn constraint_nested_include_does_not_affect_exit() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("requirements.txt"),
        "-c requirements-constraints.txt\n",
    )
    .unwrap();
    fs::write(
        root.join("requirements-constraints.txt"),
        "-r requirements-nested.txt\n",
    )
    .unwrap();
    fs::write(root.join("requirements-nested.txt"), "evil-pkg==1.2.3\n").unwrap();
    let result = scan_python(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
    );
    assert!(result.findings.is_empty());
    assert!(result.package_evidence.is_empty());
    assert_eq!(result.outcome, ScanOutcome::Clean);
    cleanup(&base);
}

fn write_synthetic_uv_lock(path: &std::path::Path) {
    fs::write(
        path,
        r#"version = 1
revision = 3

[[package]]
name = "evil-pkg"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
"#,
    )
    .unwrap();
}

fn fixture_evil_wheel() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "tests/fixtures/python/wheel-cache/pip-wheels/hashed/ab/evil_pkg-1.2.3-py3-none-any.whl",
    )
}

#[test]
fn lockfile_and_wheel_cache_corroborate_high() {
    let base = tmp();
    let home = base.join("home");
    let project = home.join("project");
    fs::create_dir_all(&project).unwrap();
    write_synthetic_uv_lock(&project.join("uv.lock"));
    let wheels = base.join("pip-cache/wheels/hashed/ab");
    fs::create_dir_all(&wheels).unwrap();
    fs::copy(
        fixture_evil_wheel(),
        wheels.join("evil_pkg-1.2.3-py3-none-any.whl"),
    )
    .unwrap();
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        pip_cache_dir: Some(base.join("pip-cache")),
        ..ProcessConfig::default()
    };
    let result = scan_python(
        ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        snapshot(true, true),
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| { f.severity == Severity::High && f.code.as_str() == "corroborated-package" }),
        "lock + wheel must corroborate to HIGH: {:?}",
        result.findings
    );
    assert_eq!(result.outcome, ScanOutcome::StrongEvidence);
    cleanup(&base);
}

#[test]
fn manifest_and_lockfile_do_not_corroborate() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("requirements.txt"), "evil-pkg==1.2.3\n").unwrap();
    write_synthetic_uv_lock(&root.join("uv.lock"));
    let result = scan_python(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        None,
        snapshot(true, true),
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.code.as_str() == "corroborated-package"),
        "manifest + lock must not corroborate: {:?}",
        result.findings
    );
    assert_eq!(
        result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        2
    );
    assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
    cleanup(&base);
}
