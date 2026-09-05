//! Python fault injection tests.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::coverage::ArtifactStatus;
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::Ecosystem;
use chaincheck::python::{LIMIT_METADATA, LIMIT_REQUIREMENTS, installed, pyproject, requirements};

const TINY: &[u8] = br#"[{"package_name":"evil","version":"1.0.0","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-fault-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn intel() -> EcosystemIntelligence {
    EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap())
}

#[test]
fn oversized_metadata_is_coverage_not_finding() {
    let base = tmp();
    let path = base.join("METADATA");
    let file = File::create(&path).unwrap();
    file.set_len(LIMIT_METADATA + 1).unwrap();
    let scan = installed::scan_metadata(&path, &intel());
    assert!(scan.findings.is_empty());
    assert_eq!(scan.status, ArtifactStatus::Oversized);
    cleanup(&base);
}

#[test]
fn duplicate_metadata_name_is_parse_failed() {
    let base = tmp();
    let path = base.join("METADATA");
    fs::write(&path, "Name: a\nName: b\nVersion: 1.0.0\n").unwrap();
    let scan = installed::scan_metadata(&path, &intel());
    assert!(scan.findings.is_empty());
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    cleanup(&base);
}

#[test]
fn constraint_glob_file_does_not_emit() {
    let base = tmp();
    let main = base.join("requirements.txt");
    let constraints = base.join("requirements-constraints.txt");
    fs::write(&main, "-c requirements-constraints.txt\n").unwrap();
    fs::write(&constraints, "evil==1.0.0\n").unwrap();
    let scans =
        requirements::scan_requirements_files(&[main, constraints], &intel(), &[base.clone()]);
    let findings: usize = scans.iter().map(|(_, s)| s.findings.len()).sum();
    assert_eq!(findings, 0);
    cleanup(&base);
}

#[test]
fn index_url_credentials_never_appear_in_findings() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(
        &path,
        "--index-url https://user:token@pypi.example/simple\nevil==1.0.0\n",
    )
    .unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    let detail = &scans[0].1.findings[0].detail;
    let location = scans[0].1.findings[0]
        .location
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    assert!(!detail.contains("token"));
    assert!(!detail.contains("user:"));
    assert!(!location.contains("token"));
    cleanup(&base);
}

#[test]
fn latin1_declared_non_utf8_is_unsupported_format() {
    let base = tmp();
    let path = base.join("requirements.txt");
    let mut bytes = Vec::from(b"# coding: latin-1\n");
    bytes.push(0xff);
    fs::write(&path, bytes).unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert!(scans[0].1.findings.is_empty());
    assert_eq!(scans[0].1.status, ArtifactStatus::UnsupportedFormat);
    cleanup(&base);
}

#[test]
fn oversized_requirements_is_coverage_not_finding() {
    let base = tmp();
    let path = base.join("requirements.txt");
    let file = File::create(&path).unwrap();
    file.set_len(LIMIT_REQUIREMENTS + 1).unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert!(scans[0].1.findings.is_empty());
    assert_eq!(scans[0].1.status, ArtifactStatus::Oversized);
    cleanup(&base);
}

#[test]
fn unreadable_metadata_is_unreadable() {
    let base = tmp();
    let path = base.join("METADATA");
    fs::write(&path, "Name: evil\nVersion: 1.0.0\n").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();
    let scan = installed::scan_metadata(&path, &intel());
    assert!(scan.findings.is_empty());
    assert_eq!(scan.status, ArtifactStatus::Unreadable);
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    let _ = fs::set_permissions(&path, perms);
    cleanup(&base);
}

#[test]
fn metadata_symlink_is_unreadable() {
    let base = tmp();
    let target = base.join("real");
    fs::write(&target, "Name: evil\nVersion: 1.0.0\n").unwrap();
    let link = base.join("METADATA");
    symlink(&target, &link).unwrap();
    let scan = installed::scan_metadata(&link, &intel());
    assert!(scan.findings.is_empty());
    assert_eq!(scan.status, ArtifactStatus::Unreadable);
    cleanup(&base);
}

#[test]
fn malformed_pyproject_is_partial_not_finding() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(&path, "not valid toml [[[\n").unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert!(scan.findings.is_empty());
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    cleanup(&base);
}

#[test]
fn relative_parent_include_does_not_escape_root() {
    let base = tmp();
    let root = base.join("project");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        root.join("requirements.txt"),
        "-r ../outside/requirements-evil.txt\n",
    )
    .unwrap();
    fs::write(outside.join("requirements-evil.txt"), "evil==1.0.0\n").unwrap();
    let scans = requirements::scan_requirements_files(
        &[root.join("requirements.txt")],
        &intel(),
        &[root.clone()],
    );
    let findings: usize = scans.iter().map(|(_, s)| s.findings.len()).sum();
    assert_eq!(findings, 0);
    assert!(scans.iter().all(|(_, s)| s.evidence.is_empty()));
    let parent = scans
        .iter()
        .find(|(p, _)| p.ends_with("requirements.txt"))
        .unwrap();
    assert_ne!(parent.1.status, ArtifactStatus::Inspected);
    cleanup(&base);
}

#[test]
fn absolute_outside_root_include_is_not_read() {
    let base = tmp();
    let root = base.join("project");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let evil = outside.join("requirements-evil.txt");
    fs::write(&evil, "evil==1.0.0\n").unwrap();
    fs::write(
        root.join("requirements.txt"),
        format!("-r {}\n", evil.display()),
    )
    .unwrap();
    let scans = requirements::scan_requirements_files(
        &[root.join("requirements.txt")],
        &intel(),
        &[root.clone()],
    );
    let findings: usize = scans.iter().map(|(_, s)| s.findings.len()).sum();
    assert_eq!(findings, 0);
    assert!(scans.iter().all(|(_, s)| s.evidence.is_empty()));
    cleanup(&base);
}

#[test]
fn intermediate_directory_symlink_include_is_not_read() {
    let base = tmp();
    let root = base.join("project");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("evil.txt"), "evil==1.0.0\n").unwrap();
    symlink(&outside, root.join("escape")).unwrap();
    fs::write(root.join("requirements.txt"), "-r escape/evil.txt\n").unwrap();
    let scans = requirements::scan_requirements_files(
        &[root.join("requirements.txt")],
        &intel(),
        &[root.clone()],
    );
    let findings: usize = scans.iter().map(|(_, s)| s.findings.len()).sum();
    assert_eq!(findings, 0);
    assert!(scans.iter().all(|(_, s)| s.evidence.is_empty()));
    cleanup(&base);
}

#[test]
fn failing_include_makes_parent_partial_and_keeps_child_status() {
    let base = tmp();
    let main = base.join("requirements.txt");
    let child = base.join("requirements-child.txt");
    fs::write(&main, "-r requirements-child.txt\n").unwrap();
    let mut bytes = Vec::from(b"# coding: latin-1\n");
    bytes.push(0xff);
    fs::write(&child, bytes).unwrap();
    let scans = requirements::scan_requirements_files(&[main.clone()], &intel(), &[base.clone()]);
    let parent = scans.iter().find(|(p, _)| p == &main).unwrap();
    let nested = scans.iter().find(|(p, _)| p == &child).unwrap();
    assert_ne!(parent.1.status, ArtifactStatus::Inspected);
    assert_eq!(nested.1.status, ArtifactStatus::UnsupportedFormat);
    assert!(parent.1.findings.is_empty());
    assert!(nested.1.findings.is_empty());
    cleanup(&base);
}

#[test]
fn include_graph_coverage_is_stable_across_seed_order() {
    let base = tmp();
    let a = base.join("requirements-a.txt");
    let b = base.join("requirements-b.txt");
    let nested = base.join("requirements-nested.txt");
    fs::write(&a, "-r requirements-nested.txt\n").unwrap();
    fs::write(&b, "-r requirements-nested.txt\n").unwrap();
    fs::write(&nested, "evil==1.0.0\n").unwrap();
    let left =
        requirements::scan_requirements_files(&[a.clone(), b.clone()], &intel(), &[base.clone()]);
    let right =
        requirements::scan_requirements_files(&[b.clone(), a.clone()], &intel(), &[base.clone()]);
    assert_eq!(left.len(), right.len());
    let mut left_keys: Vec<_> = left
        .iter()
        .map(|(p, s)| (p.clone(), s.status, s.findings.len()))
        .collect();
    let mut right_keys: Vec<_> = right
        .iter()
        .map(|(p, s)| (p.clone(), s.status, s.findings.len()))
        .collect();
    left_keys.sort();
    right_keys.sort();
    assert_eq!(left_keys, right_keys);
    cleanup(&base);
}

#[test]
fn constraint_only_nested_include_does_not_emit() {
    let base = tmp();
    let main = base.join("requirements.txt");
    let constraints = base.join("requirements-constraints.txt");
    let nested = base.join("requirements-nested.txt");
    fs::write(&main, "-c requirements-constraints.txt\n").unwrap();
    fs::write(&constraints, "-r requirements-nested.txt\n").unwrap();
    fs::write(&nested, "evil==1.0.0\n").unwrap();
    let scans = requirements::scan_requirements_files(
        &[main, constraints, nested],
        &intel(),
        &[base.clone()],
    );
    let findings: usize = scans.iter().map(|(_, s)| s.findings.len()).sum();
    let evidence: usize = scans.iter().map(|(_, s)| s.evidence.len()).sum();
    assert_eq!(findings, 0);
    assert_eq!(evidence, 0);
    cleanup(&base);
}
