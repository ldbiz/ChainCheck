//! Host, DNS, and credential inventory tests that do not use this machine's live cache.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::coverage::{ArtifactStatus, CoverageStatus};
use chaincheck::credentials::credential_inventory;
use chaincheck::host::{classify_dns_cache, scan_dns_cache, scan_hosts_file};
use chaincheck::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, parse_malware_feed};
use chaincheck::model::{Ecosystem, FindingSubject, Severity};
use chaincheck::scan::{normal_scan_exit, scan_outcome};

const TINY: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-camp-host-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn intel() -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Npm).unwrap()),
        EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap()),
    )
}

#[test]
fn hosts_file_mentions_are_info_host_findings() {
    let root = tmp();
    let hosts = root.join("hosts");
    fs::write(
        &hosts,
        "127.0.0.1 npm-cache.com\n::1 eth-mainnet.nodereal.io\n",
    )
    .unwrap();
    let output = scan_hosts_file(&hosts);
    assert_eq!(output.findings.len(), 2);
    assert!(output.findings.iter().all(|f| f.severity == Severity::Info
        && f.code.as_str() == "hosts-file-indicator"
        && f.subject == FindingSubject::Host
        && f.detail.contains("defensive block")));
    cleanup(&root);
}

#[test]
fn dns_stdout_fixtures_are_classified_without_resolvectl() {
    let both = classify_dns_cache("npm-cache.com\neth-mainnet.nodereal.io\n");
    assert_eq!(both.len(), 2);
    assert!(both.iter().all(|f| f.severity == Severity::Medium));
    let empty = classify_dns_cache("unrelated cache line");
    assert!(empty.is_empty());
}

#[test]
fn oversized_resolvectl_is_partial_without_findings() {
    let root = tmp();
    let fake = root.join("fake-resolvectl");
    fs::write(
        &fake,
        "#!/bin/sh\ndd if=/dev/zero bs=1024 count=3000 2>/dev/null\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).unwrap();
    let output = scan_dns_cache(Some(&fake));
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert!(
        output
            .coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::Oversized)
    );
    cleanup(&root);
}

#[test]
fn credentials_inventory_names_only_and_exposure_exit() {
    let home = tmp();
    fs::write(home.join(".pypirc"), "password = supersecret\n").unwrap();
    fs::write(
        home.join(".npmrc"),
        "//registry.npmjs.org/:_authToken=supersecret\n",
    )
    .unwrap();
    let output = credential_inventory(
        Some(&home),
        [
            ("UV_PUBLISH_TOKEN", "supersecret"),
            ("TWINE_PASSWORD", "supersecret"),
            ("PIP_INDEX_URL", "https://pypi.org/simple"),
            ("UV_INDEX_URL", "https://pypi.org/simple"),
        ],
    );
    assert!(
        output
            .findings
            .iter()
            .any(|f| f.code.as_str() == "credential-source"
                && f.location.as_ref().is_some_and(|p| p.ends_with(".pypirc")))
    );
    let env = output
        .findings
        .iter()
        .find(|f| f.code.as_str() == "credential-environment")
        .expect("env finding");
    assert!(env.detail.contains("UV_PUBLISH_TOKEN"));
    assert!(env.detail.contains("TWINE_PASSWORD"));
    assert!(!env.detail.contains("PIP_INDEX_URL"));
    assert!(!env.detail.contains("UV_INDEX_URL"));
    for finding in &output.findings {
        assert!(!finding.detail.contains("supersecret"));
        assert_eq!(finding.severity, Severity::Exposure);
        assert_eq!(finding.subject, FindingSubject::Host);
    }
    assert_eq!(
        normal_scan_exit(scan_outcome(&output.findings, &intel())),
        0
    );
    cleanup(&home);
}
