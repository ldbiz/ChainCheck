//! Python lockfile detector integration tests.

use std::path::PathBuf;

use chaincheck::coverage::{ArtifactStatus, CoverageStatus};
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::{Ecosystem, EvidenceKind, Severity};
use chaincheck::python::{
    DET_PDM_LOCK, DET_PIPFILE_LOCK, DET_POETRY_LOCK, DET_PYLOCK, DET_UV_LOCK, PythonArtifacts,
    lockfile, scan_python_artifacts,
};

const TINY: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;
const SIX: &[u8] = br#"[{"package_name":"six","version":"1.17.0","reason":"MALWARE"}]"#;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python")
        .join(relative)
}

fn intel() -> EcosystemIntelligence {
    EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap())
}

fn six_intel() -> EcosystemIntelligence {
    EcosystemIntelligence::Available(parse_malware_feed(SIX, Ecosystem::Pypi).unwrap())
}

fn detector_status(
    artifacts: &PythonArtifacts,
    id: chaincheck::coverage::DetectorId,
) -> CoverageStatus {
    scan_python_artifacts(artifacts, &intel())
        .into_iter()
        .find(|o| o.coverage.detector() == id)
        .map(|o| o.coverage.status())
        .unwrap_or(CoverageStatus::Skipped)
}

#[test]
fn pylock_proven_fixture_emits_resolution() {
    let scan = lockfile::scan_pylock(&fixture("locks/pylock/proven-1.0.toml"), &six_intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].kind, EvidenceKind::DependencyResolution);
    assert_eq!(scan.findings[0].severity, Severity::Medium);
}

#[test]
fn pylock_degraded_emits_with_partial_coverage() {
    let scan = lockfile::scan_pylock(&fixture("locks/pylock/degraded-1.1.toml"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert_eq!(scan.findings.len(), 1);
    let artifacts = PythonArtifacts {
        pylock_tomls: vec![fixture("locks/pylock/degraded-1.1.toml")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_PYLOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn pylock_unsupported_has_no_findings() {
    let scan = lockfile::scan_pylock(&fixture("locks/pylock/unsupported-2.0.toml"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert!(scan.findings.is_empty());
}

#[test]
fn pylock_malformed_missing_lock_version() {
    let scan = lockfile::scan_pylock(
        &fixture("locks/pylock/malformed-missing-version.toml"),
        &intel(),
    );
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    assert!(scan.findings.is_empty());
}

#[test]
fn pylock_malformed_sibling_keeps_valid_resolution() {
    let scan = lockfile::scan_pylock(
        &fixture("locks/pylock/proven-1.0-malformed-sibling.toml"),
        &intel(),
    );
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].kind, EvidenceKind::DependencyResolution);
    assert_eq!(scan.findings[0].severity, Severity::Medium);
    assert_eq!(scan.evidence.len(), 1);
    let artifacts = PythonArtifacts {
        pylock_tomls: vec![fixture("locks/pylock/proven-1.0-malformed-sibling.toml")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_PYLOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn uv_proven_emits_resolution() {
    let scan = lockfile::scan_uv_lock(&fixture("locks/uv/proven-v1.lock"), &six_intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn uv_virtual_package_is_not_pypi_resolution() {
    let intel = EcosystemIntelligence::Available(
        parse_malware_feed(
            br#"[{"package_name":"chaincheck-uv-fixture","version":"0.0.1","reason":"MALWARE"}]"#,
            Ecosystem::Pypi,
        )
        .unwrap(),
    );
    let scan = lockfile::scan_uv_lock(&fixture("locks/uv/proven-v1.lock"), &intel);
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert!(scan.findings.is_empty());
    assert!(scan.evidence.is_empty());
}

#[test]
fn uv_git_source_is_not_pypi_resolution() {
    let scan = lockfile::scan_uv_lock(&fixture("locks/uv/local-git.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert!(scan.findings.is_empty());
    assert!(scan.evidence.is_empty());
}

#[test]
fn uv_unsupported_version_2() {
    let scan = lockfile::scan_uv_lock(&fixture("locks/uv/unsupported-v2.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert!(scan.findings.is_empty());
    let artifacts = PythonArtifacts {
        uv_locks: vec![fixture("locks/uv/unsupported-v2.lock")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_UV_LOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn poetry_proven_2_1() {
    let scan = lockfile::scan_poetry_lock(&fixture("locks/poetry/proven-2.1.lock"), &six_intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn poetry_degraded_other_2_x() {
    let scan = lockfile::scan_poetry_lock(&fixture("locks/poetry/degraded-2.0.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert_eq!(scan.findings.len(), 1);
    let artifacts = PythonArtifacts {
        poetry_locks: vec![fixture("locks/poetry/degraded-2.0.lock")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_POETRY_LOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn poetry_unsupported_major_1() {
    let scan = lockfile::scan_poetry_lock(&fixture("locks/poetry/unsupported-1.1.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert!(scan.findings.is_empty());
}

#[test]
fn pipfile_lock_spec_6_only() {
    let scan =
        lockfile::scan_pipfile_lock(&fixture("locks/pipfile/proven-spec-6.lock"), &six_intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn pipfile_lock_other_spec_unsupported() {
    let scan =
        lockfile::scan_pipfile_lock(&fixture("locks/pipfile/unsupported-spec-5.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert!(scan.findings.is_empty());
    let artifacts = PythonArtifacts {
        pipfile_locks: vec![fixture("locks/pipfile/unsupported-spec-5.lock")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_PIPFILE_LOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn pdm_proven_fixture_version() {
    let scan = lockfile::scan_pdm_lock(&fixture("locks/pdm/proven-4.5.1.lock"), &six_intel());
    assert_eq!(scan.status, ArtifactStatus::Inspected);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn pdm_4_5_0_is_degraded_not_proven() {
    let scan = lockfile::scan_pdm_lock(&fixture("locks/pdm/degraded-4.5.0.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert_eq!(scan.findings.len(), 1);
}

#[test]
fn pdm_degraded_other_4_x() {
    let scan = lockfile::scan_pdm_lock(&fixture("locks/pdm/degraded-4.4.0.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert_eq!(scan.findings.len(), 1);
    let artifacts = PythonArtifacts {
        pdm_locks: vec![fixture("locks/pdm/degraded-4.4.0.lock")],
        ..empty_artifacts()
    };
    assert_eq!(
        detector_status(&artifacts, DET_PDM_LOCK),
        CoverageStatus::Partial
    );
}

#[test]
fn pdm_unsupported_major_3() {
    let scan = lockfile::scan_pdm_lock(&fixture("locks/pdm/unsupported-3.0.0.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
    assert!(scan.findings.is_empty());
}

#[test]
fn uv_float_schema_is_not_proven() {
    let scan = lockfile::scan_uv_lock(&fixture("locks/uv/malformed-float-1.9.lock"), &intel());
    assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    assert!(scan.findings.is_empty());
}

#[test]
fn pylock_and_poetry_reject_extra_version_components() {
    let pylock = lockfile::scan_pylock(&fixture("locks/pylock/malformed-1.0.0.toml"), &intel());
    assert_eq!(pylock.status, ArtifactStatus::ParseFailed);
    assert!(pylock.findings.is_empty());
    let extra = lockfile::scan_pylock(&fixture("locks/pylock/malformed-1.0.extra.toml"), &intel());
    assert_eq!(extra.status, ArtifactStatus::ParseFailed);
    let poetry =
        lockfile::scan_poetry_lock(&fixture("locks/poetry/malformed-2.1.foo.lock"), &intel());
    assert_eq!(poetry.status, ArtifactStatus::ParseFailed);
    assert!(poetry.findings.is_empty());
}

fn empty_artifacts() -> PythonArtifacts {
    use chaincheck::coverage::DetectorCoverage;
    use chaincheck::python::DET_DISCOVERY;
    PythonArtifacts {
        metadata: Vec::new(),
        requirements: Vec::new(),
        pyprojects: Vec::new(),
        pipfiles: Vec::new(),
        setup_cfgs: Vec::new(),
        pylock_tomls: Vec::new(),
        uv_locks: Vec::new(),
        poetry_locks: Vec::new(),
        pipfile_locks: Vec::new(),
        pdm_locks: Vec::new(),
        pip_wheel_roots: Vec::new(),
        pip_wheel_root_failures: Vec::new(),
        walk_coverage: DetectorCoverage::skipped(DET_DISCOVERY),
        include_roots: Vec::new(),
    }
}
