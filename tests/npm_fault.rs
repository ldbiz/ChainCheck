//! Rust-only fault injection for generic npm detectors.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::cli::ProcessConfig;
use chaincheck::coverage::{ArtifactStatus, CoverageStatus};
use chaincheck::discovery::walk_files;
use chaincheck::intelligence::{
    EcosystemIntelligence, FeedFailure, IntelligenceSnapshot, parse_malware_feed,
};
use chaincheck::model::Ecosystem;
use chaincheck::npm::{
    LIMIT_PACKAGE_JSON, LIMIT_PACKAGE_LOCK, apply_npm_corroboration, scan_artefact, scan_npm,
};
use chaincheck::scan::{ScanScope, merge_outputs, normal_scan_exit};

const TINY_NPM: &[u8] = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;
const TINY_PYPI: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-fault-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn available_npm() -> EcosystemIntelligence {
    EcosystemIntelligence::Available(parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap())
}

fn snapshot(npm: EcosystemIntelligence) -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        npm,
        EcosystemIntelligence::Available(parse_malware_feed(TINY_PYPI, Ecosystem::Pypi).unwrap()),
    )
}

fn shared(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/shared")
        .join(relative)
}

fn first_status(output: &chaincheck::scan::DetectorOutput) -> ArtifactStatus {
    output
        .coverage
        .examples()
        .first()
        .map(|e| e.status)
        .or_else(|| output.coverage.failure_counts().keys().copied().next())
        .unwrap_or(ArtifactStatus::Inspected)
}

#[test]
fn oversized_manifest_is_coverage_not_a_finding() {
    let root = tmp();
    let path = root.join("package.json");
    let file = File::create(&path).unwrap();
    file.set_len(LIMIT_PACKAGE_JSON + 1).unwrap();
    let output = scan_artefact("package-json", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::Oversized);
    cleanup(&root);
}

#[test]
fn oversized_lockfile_is_coverage_not_a_finding() {
    let root = tmp();
    let path = root.join("package-lock.json");
    let file = File::create(&path).unwrap();
    file.set_len(LIMIT_PACKAGE_LOCK + 1).unwrap();
    let output = scan_artefact("package-lock", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::Oversized);
    cleanup(&root);
}

#[test]
fn unreadable_manifest_is_coverage_not_a_finding() {
    let root = tmp();
    let path = root.join("package.json");
    fs::write(&path, br#"{"name":"keyv","version":"6.0.0"}"#).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();
    let output = scan_artefact("package-json", &path, &available_npm()).unwrap();
    let mut restore = fs::metadata(&path).unwrap().permissions();
    restore.set_mode(0o644);
    let _ = fs::set_permissions(&path, restore);
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::Unreadable);
    cleanup(&root);
}

#[test]
fn unknown_package_lock_version_is_unsupported_format() {
    let root = tmp();
    let path = root.join("package-lock.json");
    fs::write(
        &path,
        br#"{"lockfileVersion":99,"packages":{"node_modules/keyv":{"version":"6.0.0"}}}"#,
    )
    .unwrap();
    let output = scan_artefact("package-lock", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::UnsupportedFormat);
    cleanup(&root);
}

#[test]
fn unknown_pnpm_version_is_unsupported_format() {
    let root = tmp();
    let path = root.join("pnpm-lock.yaml");
    fs::write(&path, "lockfileVersion: '7.0'\npackages:\n  keyv@6.0.0:\n").unwrap();
    let output = scan_artefact("pnpm-lock", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::UnsupportedFormat);
    cleanup(&root);
}

#[test]
fn unknown_bun_lock_version_is_unsupported_format() {
    let root = tmp();
    let path = root.join("bun.lock");
    fs::write(
        &path,
        r#"{ "lockfileVersion": 2, "packages": { "keyv": ["keyv@6.0.0"] } }"#,
    )
    .unwrap();
    let output = scan_artefact("bun-lock", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::UnsupportedFormat);
    cleanup(&root);
}

#[test]
fn berry_metadata_marker_is_unsupported_format() {
    let path = shared("npm/yarn/berry-metadata/yarn.lock");
    let output = scan_artefact("yarn-lock", &path, &available_npm()).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert_eq!(first_status(&output), ArtifactStatus::UnsupportedFormat);
}

#[test]
fn npm_intel_unavailable_lockfile_stays_completed_exit_four() {
    let path = shared("npm/package-lock/v3-keyv/package-lock.json");
    let npm = EcosystemIntelligence::Unavailable(FeedFailure::Network);
    let output = scan_artefact("package-lock", &path, &npm).unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.status(), CoverageStatus::Completed);
    let merged = merge_outputs([output]);
    let result = chaincheck::scan::ScanResult::from_merged(
        ScanScope::ExplicitRoot { root: path },
        merged,
        snapshot(npm),
    );
    assert_eq!(normal_scan_exit(result.outcome), 4);
}

#[test]
fn explicit_root_does_not_walk_sibling_trees() {
    let base = tmp();
    let root = base.join("root");
    let sibling = base.join("sibling");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&sibling).unwrap();
    fs::copy(
        shared("negative/clean-package-lock/package-lock.json"),
        root.join("package-lock.json"),
    )
    .unwrap();
    fs::copy(
        shared("npm/package-lock/v3-keyv/package-lock.json"),
        sibling.join("package-lock.json"),
    )
    .unwrap();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let result = scan_npm(
        ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result.findings.is_empty(),
        "sibling lockfile leaked into explicit root: {:?}",
        result.findings
    );
    cleanup(&base);
}

#[test]
fn explicit_root_still_scans_host_cache_and_logs() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm artefacts").unwrap();
    let home = base.join("home");
    let cache = home.join(".npm/_cacache/index-v5");
    fs::create_dir_all(&cache).unwrap();
    copy_tree(&shared("npm/cache/index-v5-keyv"), &cache);
    let logs = home.join(".npm/_logs");
    fs::create_dir_all(&logs).unwrap();
    fs::copy(
        shared("npm/logs/reify-install.log"),
        logs.join("reify-install.log"),
    )
    .unwrap();

    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code.as_str() == "npm-cache-download"),
        "host cache should still run: {:?}",
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code.as_str() == "npm-install-log"),
        "host logs should still run: {:?}",
        result.findings
    );
    cleanup(&base);
}

#[test]
fn directory_symlink_is_not_descended() {
    let base = tmp();
    let root = base.join("root");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::copy(
        shared("npm/package-lock/v3-keyv/package-lock.json"),
        outside.join("package-lock.json"),
    )
    .unwrap();
    symlink(&outside, root.join("link")).unwrap();
    fs::write(root.join("ok.txt"), b"ok").unwrap();

    let walked = walk_files([&root], |_p, _n| false);
    assert!(
        !walked
            .files
            .iter()
            .any(|p| { p.file_name().is_some_and(|n| n == "package-lock.json") })
    );

    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let result = scan_npm(
        ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result.findings.is_empty(),
        "dir symlink must not yield lockfile findings: {:?}",
        result.findings
    );
    cleanup(&base);
}

#[test]
fn generic_walker_still_sees_venv() {
    let root = tmp();
    fs::create_dir_all(root.join(".venv/lib")).unwrap();
    fs::write(root.join(".venv/lib/hidden.txt"), b"x").unwrap();
    let walked = walk_files([&root], |_p, _n| false);
    assert!(
        walked
            .files
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == "hidden.txt"))
    );
    cleanup(&root);
}

#[test]
fn wildcard_intel_lockfile_and_cache_corroborate() {
    let root = tmp();
    let lock = root.join("package-lock.json");
    fs::write(
        &lock,
        r#"{
          "name": "fixture",
          "version": "1.0.0",
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "fixture", "version": "1.0.0"},
            "node_modules/wildcard-malware": {"version": "1.2.3"}
          }
        }"#,
    )
    .unwrap();
    let cache = root.join("index-v5");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join("entry"),
        "https://registry.npmjs.org/wildcard-malware/-/wildcard-malware-1.2.3.tgz\n",
    )
    .unwrap();
    let intel = EcosystemIntelligence::Available(
        parse_malware_feed(
            br#"[{"package_name":"wildcard-malware","version":"*","reason":"MALWARE"}]"#,
            Ecosystem::Npm,
        )
        .unwrap(),
    );
    let lock_out = scan_artefact("package-lock", &lock, &intel).unwrap();
    let cache_out = scan_artefact("npm-cache", &cache, &intel).unwrap();
    assert_eq!(lock_out.findings.len(), 1);
    assert_eq!(cache_out.findings.len(), 1);
    assert!(
        lock_out
            .findings
            .iter()
            .all(|f| f.code.as_str() == "lockfile-package")
    );
    assert!(
        cache_out
            .findings
            .iter()
            .all(|f| f.code.as_str() == "npm-cache-download")
    );
    let mut merged = merge_outputs([lock_out, cache_out]);
    apply_npm_corroboration(&mut merged.findings, &merged.package_evidence, &intel);
    assert!(
        merged
            .findings
            .iter()
            .any(|f| f.code.as_str() == "corroborated-package"),
        "wildcard intel must corroborate exact lock+cache keys: {:?}",
        merged.findings
    );
    cleanup(&root);
}

#[test]
fn missing_host_logs_remain_skipped() {
    let root = tmp();
    fs::write(root.join("README"), b"no npm").unwrap();
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let result = scan_npm(
        ScanScope::ExplicitRoot { root: root.clone() },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    let logs = result
        .coverage
        .iter()
        .find(|c| c.detector().as_str() == "npm-logs")
        .expect("npm-logs coverage");
    assert_eq!(logs.status(), CoverageStatus::Skipped);
    cleanup(&root);
}

#[test]
fn unreadable_host_logs_are_partial_coverage() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm").unwrap();
    let home = base.join("home");
    let logs = home.join(".npm/_logs");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("debug.log"), b"0 verbose argv\n").unwrap();
    let mut perms = fs::metadata(&logs).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&logs, perms).unwrap();
    if fs::read_dir(&logs).is_ok() {
        let mut restore = fs::metadata(&logs).unwrap().permissions();
        restore.set_mode(0o755);
        let _ = fs::set_permissions(&logs, restore);
        cleanup(&base);
        return;
    }
    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    let mut restore = fs::metadata(&logs).unwrap().permissions();
    restore.set_mode(0o755);
    let _ = fs::set_permissions(&logs, restore);
    let coverage = result
        .coverage
        .iter()
        .find(|c| c.detector().as_str() == "npm-logs")
        .expect("npm-logs coverage");
    assert_eq!(coverage.status(), CoverageStatus::Partial);
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "npm-install-log")
    );
    assert!(
        coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::Unreadable)
            || coverage
                .failure_counts()
                .contains_key(&ArtifactStatus::StatFailed)
    );
    cleanup(&base);
}

#[test]
fn host_logs_symlink_is_not_followed() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm").unwrap();
    let real_logs = base.join("real-logs");
    fs::create_dir_all(&real_logs).unwrap();
    fs::copy(
        shared("npm/logs/reify-install.log"),
        real_logs.join("reify.log"),
    )
    .unwrap();
    let home = base.join("home");
    fs::create_dir_all(home.join(".npm")).unwrap();
    symlink(&real_logs, home.join(".npm/_logs")).unwrap();

    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "npm-install-log"),
        "symlinked _logs must not be followed: {:?}",
        result.findings
    );
    let coverage = coverage_named(&result, "npm-logs");
    assert_eq!(coverage.status(), CoverageStatus::Partial);
    assert!(
        coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::Unreadable)
    );
    cleanup(&base);
}

#[test]
fn host_logs_parent_not_a_directory_is_partial() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm").unwrap();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join(".npm"), b"not-a-directory").unwrap();

    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    let coverage = coverage_named(&result, "npm-logs");
    assert_eq!(coverage.status(), CoverageStatus::Partial);
    assert!(
        coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::StatFailed)
    );
    cleanup(&base);
}

#[test]
fn host_cache_symlink_is_not_followed() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm").unwrap();
    let real_cache = base.join("real-cache");
    copy_tree(&shared("npm/cache/index-v5-keyv"), &real_cache);
    let home = base.join("home");
    fs::create_dir_all(home.join(".npm/_cacache")).unwrap();
    symlink(&real_cache, home.join(".npm/_cacache/index-v5")).unwrap();

    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "npm-cache-download"),
        "symlinked index-v5 must not be followed: {:?}",
        result.findings
    );
    let coverage = coverage_named(&result, "npm-cache");
    assert_eq!(coverage.status(), CoverageStatus::Partial);
    assert!(
        coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::Unreadable)
    );
    cleanup(&base);
}

#[test]
fn host_cache_parent_not_a_directory_is_partial() {
    let base = tmp();
    let root = base.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("README"), b"no npm").unwrap();
    let home = base.join("home");
    fs::create_dir_all(home.join(".npm")).unwrap();
    fs::write(home.join(".npm/_cacache"), b"not-a-directory").unwrap();

    let result = scan_npm(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        snapshot(available_npm()),
    );
    let coverage = coverage_named(&result, "npm-cache");
    assert_eq!(coverage.status(), CoverageStatus::Partial);
    assert!(
        coverage
            .failure_counts()
            .contains_key(&ArtifactStatus::StatFailed)
    );
    cleanup(&base);
}

#[test]
fn extra_npm_module_root_symlink_is_not_followed() {
    let base = tmp();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let real_modules = base.join("real-modules/pkg");
    fs::create_dir_all(&real_modules).unwrap();
    fs::write(
        real_modules.join("package.json"),
        br#"{"name":"keyv","version":"6.0.0"}"#,
    )
    .unwrap();
    let prefix = base.join("prefix");
    fs::create_dir_all(prefix.join("lib")).unwrap();
    symlink(base.join("real-modules"), prefix.join("lib/node_modules")).unwrap();

    let mut config = ProcessConfig::default();
    config.npm_config_prefix = Some(prefix);
    let result = scan_npm(
        ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        snapshot(available_npm()),
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "installed-package"),
        "symlinked global node_modules must not be followed: {:?}",
        result.findings
    );
    let walk = coverage_named(&result, "filesystem-walk");
    assert_eq!(walk.status(), CoverageStatus::Partial);
    assert!(
        walk.failure_counts()
            .contains_key(&ArtifactStatus::Unreadable)
    );
    cleanup(&base);
}

fn coverage_named<'a>(
    result: &'a chaincheck::scan::ScanResult,
    name: &str,
) -> &'a chaincheck::coverage::DetectorCoverage {
    result
        .coverage
        .iter()
        .find(|c| c.detector().as_str() == name)
        .unwrap_or_else(|| panic!("missing coverage {name}"))
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
