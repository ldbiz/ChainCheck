//! Python declaration detector integration tests.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::coverage::ArtifactStatus;
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::{Ecosystem, EvidenceKind, FindingSubject, Severity};
use chaincheck::python::{installed, pipfile, pyproject, requirements, setup_cfg};

const TINY: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"},{"package_name":"wildcard-evil","version":"*","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-decl-{}-{nanos}-{n}",
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
fn requirements_exact_malware_is_medium() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "evil-pkg==1.2.3\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path.clone()], &intel(), &[base.clone()]);
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].1.status, ArtifactStatus::Inspected);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert_eq!(scans[0].1.findings[0].severity, Severity::Medium);
    assert_eq!(
        scans[0].1.findings[0].kind,
        EvidenceKind::DependencyDeclaration
    );
    cleanup(&base);
}

#[test]
fn requirements_range_wildcard_is_medium_identity_only() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "wildcard-evil>=1.0\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert!(scans[0].1.evidence.is_empty());
    cleanup(&base);
}

#[test]
fn extras_declaration_still_matches_wildcard_intelligence() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "wildcard-evil[security] >= 1\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert!(scans[0].1.evidence.is_empty());
    assert!(matches!(
        scans[0].1.findings[0].subject,
        FindingSubject::PackageIdentity(ref id) if id.name().as_str() == "wildcard-evil"
    ));
    cleanup(&base);
}

#[test]
fn pyproject_dependency_emits_without_project_identity() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[project]
name = "evil-pkg"
version = "1.2.3"
dependencies = ["evil-pkg==1.2.3"]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].severity, Severity::Medium);
    cleanup(&base);
}

#[test]
fn pipfile_custom_category_emits() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[docs]
evil-pkg = "==1.2.3"
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn setup_cfg_install_requires_emits() {
    let base = tmp();
    let path = base.join("setup.cfg");
    fs::write(
        &path,
        r#"
[options]
install_requires =
    evil-pkg == 1.2.3
"#,
    )
    .unwrap();
    let scan = setup_cfg::scan_setup_cfg(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn metadata_installed_is_high() {
    let base = tmp();
    let path = base.join("METADATA");
    fs::write(&path, "Name: evil-pkg\nVersion: 1.2.3\n").unwrap();
    let scan = installed::scan_metadata(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].severity, Severity::High);
    assert_eq!(scan.findings[0].kind, EvidenceKind::InstalledPackage);
    cleanup(&base);
}

#[test]
fn mixed_specifier_never_creates_package_evidence() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "evil-pkg==1.2.3,!=1.2.4\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert!(scans[0].1.findings.is_empty());
    assert!(scans[0].1.evidence.is_empty());
    cleanup(&base);
}

#[test]
fn mixed_specifier_matches_wildcard_by_identity_only() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "wildcard-evil>=1,==2\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert!(scans[0].1.evidence.is_empty());
    assert!(matches!(
        scans[0].1.findings[0].subject,
        FindingSubject::PackageIdentity(_)
    ));
    cleanup(&base);
}

#[test]
fn inline_comment_keeps_exact_declaration() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "evil-pkg==1.2.3  # pinned release\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert_eq!(scans[0].1.evidence.len(), 1);
    cleanup(&base);
}

#[test]
fn continued_hash_option_keeps_exact_declaration() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "evil-pkg==1.2.3 \\\n    --hash=sha256:deadbeef\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert_eq!(scans[0].1.evidence.len(), 1);
    let detail = &scans[0].1.findings[0].detail;
    assert!(!detail.contains("deadbeef"));
    assert!(!detail.contains("sha256"));
    cleanup(&base);
}

#[test]
fn pep735_fixture_include_group_finds_mypy() {
    let intel = EcosystemIntelligence::Available(
        parse_malware_feed(
            br#"[{"package_name":"mypy","version":"1.2.3","reason":"MALWARE"}]"#,
            Ecosystem::Pypi,
        )
        .unwrap(),
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python/declarations/pyproject/pep735-include.toml");
    let scan = pyproject::scan_pyproject(&path, &intel);
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.evidence.len(), 1);
}

#[test]
fn include_findings_belong_to_the_declaring_file() {
    let base = tmp();
    let main = base.join("requirements.txt");
    let nested = base.join("requirements-nested.txt");
    fs::write(&main, "-r requirements-nested.txt\n").unwrap();
    fs::write(&nested, "evil-pkg==1.2.3\n").unwrap();
    let scans = requirements::scan_requirements_files(&[main.clone()], &intel(), &[base.clone()]);
    let parent = scans.iter().find(|(p, _)| p == &main).unwrap();
    let child = scans.iter().find(|(p, _)| p == &nested).unwrap();
    assert!(parent.1.findings.is_empty());
    assert_eq!(parent.1.status, ArtifactStatus::Inspected);
    assert_eq!(child.1.findings.len(), 1);
    assert_eq!(child.1.status, ArtifactStatus::Inspected);
    cleanup(&base);
}

#[test]
fn include_graph_is_order_independent() {
    let base = tmp();
    let a = base.join("requirements-a.txt");
    let b = base.join("requirements-b.txt");
    let nested = base.join("requirements-nested.txt");
    fs::write(&a, "-r requirements-nested.txt\nbenign==1.0\n").unwrap();
    fs::write(&b, "-r requirements-nested.txt\n").unwrap();
    fs::write(&nested, "evil-pkg==1.2.3\n").unwrap();
    let first =
        requirements::scan_requirements_files(&[a.clone(), b.clone()], &intel(), &[base.clone()]);
    let second =
        requirements::scan_requirements_files(&[b.clone(), a.clone()], &intel(), &[base.clone()]);
    let summarise = |scans: &[(PathBuf, chaincheck::python::FileScan)]| {
        let mut rows: Vec<_> = scans
            .iter()
            .map(|(p, s)| (p.clone(), s.status, s.findings.len(), s.evidence.len()))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(summarise(&first), summarise(&second));
    let findings: usize = first.iter().map(|(_, s)| s.findings.len()).sum();
    assert_eq!(findings, 1);
    cleanup(&base);
}

#[test]
fn setup_cfg_multiline_requires_without_commas() {
    let base = tmp();
    let path = base.join("setup.cfg");
    fs::write(
        &path,
        r#"
[options]
install_requires =
    evil-pkg>=1
    evil-pkg==1.2.3
"#,
    )
    .unwrap();
    let scan = setup_cfg::scan_setup_cfg(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.evidence.len(), 1);
    cleanup(&base);
}

#[test]
fn pipfile_custom_category_file_spec_and_pin() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[docs]
evil-pkg = "==1.2.3"
other = {file = "https://example.invalid/pkg.whl"}
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn pyproject_recovers_valid_dependency_after_invalid_sibling() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[project]
dependencies = [
  123,
  "evil-pkg==1.2.3",
]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.evidence.len(), 1);
    cleanup(&base);
}

#[test]
fn pipfile_star_string_is_identity_only() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[packages]
wildcard-evil = "*"
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].severity, Severity::Medium);
    assert!(scan.evidence.is_empty());
    match &scan.findings[0].subject {
        FindingSubject::PackageIdentity(identity) => {
            assert_eq!(identity.name().as_str(), "wildcard-evil");
        }
        other => panic!("expected package identity, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn pipfile_star_table_is_identity_only() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[packages]
wildcard-evil = { version = "*" }
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert!(scan.evidence.is_empty());
    match &scan.findings[0].subject {
        FindingSubject::PackageIdentity(identity) => {
            assert_eq!(identity.name().as_str(), "wildcard-evil");
        }
        other => panic!("expected package identity, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn poetry_bare_version_emits_evidence() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[tool.poetry.dependencies]
evil-pkg = "1.2.3"
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.evidence.len(), 1);
    match &scan.findings[0].subject {
        FindingSubject::PackageExact(key) => {
            assert_eq!(key.identity.name().as_str(), "evil-pkg");
            assert_eq!(key.version.as_str(), "1.2.3");
        }
        other => panic!("expected exact package, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn poetry_caret_string_is_identity_only() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[tool.poetry.dependencies]
wildcard-evil = "^1.0.0"
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert!(scan.evidence.is_empty());
    match &scan.findings[0].subject {
        FindingSubject::PackageIdentity(identity) => {
            assert_eq!(identity.name().as_str(), "wildcard-evil");
        }
        other => panic!("expected package identity, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn poetry_caret_table_is_identity_only() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[tool.poetry.dependencies]
wildcard-evil = { version = "^1.0.0" }
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert!(scan.evidence.is_empty());
    cleanup(&base);
}

#[test]
fn pipfile_table_exact_version_emits_evidence() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[packages]
evil-pkg = { version = "==1.2.3" }
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.evidence.len(), 1);
    match &scan.findings[0].subject {
        FindingSubject::PackageExact(key) => {
            assert_eq!(key.identity.name().as_str(), "evil-pkg");
            assert_eq!(key.version.as_str(), "1.2.3");
        }
        other => panic!("expected exact package, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn distinct_exact_versions_keep_malware_listed_pin() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[project]
dependencies = ["evil-pkg==1.0.0", "evil-pkg==1.2.3"]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    match &scan.findings[0].subject {
        FindingSubject::PackageExact(key) => {
            assert_eq!(key.version.as_str(), "1.2.3");
        }
        other => panic!("expected malware-listed 1.2.3, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn distinct_exact_versions_across_poetry_and_project() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[project]
dependencies = ["evil-pkg==1.0.0"]

[tool.poetry.dependencies]
evil-pkg = "1.2.3"
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.findings.len(), 1);
    match &scan.findings[0].subject {
        FindingSubject::PackageExact(key) => {
            assert_eq!(key.version.as_str(), "1.2.3");
        }
        other => panic!("expected malware-listed 1.2.3, got {other:?}"),
    }
    cleanup(&base);
}

#[test]
fn poetry_multi_constraint_array_is_name_only() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[tool.poetry.dependencies]
wildcard-evil = [
  { version = ">=1,<2", python = "<3.12" },
  { version = ">=2", python = ">=3.12" },
]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].severity, Severity::Medium);
    assert!(scan.evidence.is_empty());
    assert!(matches!(
        scan.findings[0].subject,
        FindingSubject::PackageIdentity(_)
    ));
    cleanup(&base);
}

#[test]
fn poetry_malformed_constraint_array_is_partial() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[tool.poetry.dependencies]
evil-pkg = [1, { version = "1.2.3" }]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    assert!(scan.findings.is_empty());
    cleanup(&base);
}

#[test]
fn requirements_multibyte_name_does_not_panic_and_is_parse_failed() {
    let base = tmp();
    let path = base.join("requirements.txt");
    fs::write(&path, "é==1\nevil-pkg==1.2.3\n").unwrap();
    let scans = requirements::scan_requirements_files(&[path], &intel(), &[base.clone()]);
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].1.status, ArtifactStatus::ParseFailed);
    assert_eq!(scans[0].1.findings.len(), 1);
    assert_eq!(
        scans[0].1.findings[0].kind,
        EvidenceKind::DependencyDeclaration
    );
    cleanup(&base);
}

#[test]
fn pyproject_multibyte_name_is_skipped_without_finding() {
    let base = tmp();
    let path = base.join("pyproject.toml");
    fs::write(
        &path,
        r#"
[project]
dependencies = ["é==1", "evil-pkg==1.2.3"]
"#,
    )
    .unwrap();
    let scan = pyproject::scan_pyproject(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn pipfile_multibyte_name_is_skipped_without_finding() {
    let base = tmp();
    let path = base.join("Pipfile");
    fs::write(
        &path,
        r#"
[packages]
"é" = "==1"
evil-pkg = "==1.2.3"
"#,
    )
    .unwrap();
    let scan = pipfile::scan_pipfile(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn setup_cfg_multibyte_name_is_skipped_without_finding() {
    let base = tmp();
    let path = base.join("setup.cfg");
    fs::write(
        &path,
        r#"
[options]
install_requires =
    é==1
    evil-pkg == 1.2.3
"#,
    )
    .unwrap();
    let scan = setup_cfg::scan_setup_cfg(&path, &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    cleanup(&base);
}
