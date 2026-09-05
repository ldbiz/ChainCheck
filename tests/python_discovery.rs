//! Python discovery integration tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::cli::ProcessConfig;
use chaincheck::coverage::{ArtifactStatus, CoverageStatus};
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::Ecosystem;
use chaincheck::python::{
    DET_DISCOVERY, PythonHostLayout, discover_python_with_layout, scan_python_artifacts,
};
use chaincheck::scan::ScanScope;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-disc-it-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

#[test]
fn dot_venv_layout_finds_metadata() {
    let base = tmp();
    let home = base.join("home");
    let site = home.join(".venv/lib/python3.12/site-packages");
    fs::create_dir_all(&site.join("malware-1.0.0.dist-info")).unwrap();
    fs::write(
        site.join("malware-1.0.0.dist-info/METADATA"),
        "Name: malware\nVersion: 1.0.0\n",
    )
    .unwrap();
    fs::write(home.join(".venv/pyvenv.cfg"), "home = /tmp\n").unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn explicit_root_ignores_home_pipx_and_system_layout() {
    let base = tmp();
    let home = base.join("home");
    let root = base.join("project");
    fs::create_dir_all(
        &home.join(".local/share/pipx/venvs/t/lib/python3.12/site-packages/x-1.0.0.dist-info"),
    )
    .unwrap();
    fs::write(
        home.join(
            ".local/share/pipx/venvs/t/lib/python3.12/site-packages/x-1.0.0.dist-info/METADATA",
        ),
        "Name: x\nVersion: 1.0.0\n",
    )
    .unwrap();
    fs::create_dir_all(&root).unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    assert!(artifacts.metadata.is_empty());
    cleanup(&base);
}

#[test]
fn relocated_system_dist_packages_is_discovered() {
    let base = tmp();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let dist = base.join("usr/lib/python3/dist-packages/malware-2.0.0.dist-info");
    fs::create_dir_all(&dist).unwrap();
    fs::write(dist.join("METADATA"), "Name: malware\nVersion: 2.0.0\n").unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn extra_root_symlink_is_recorded_once() {
    let base = tmp();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let pipx_global = base.join("opt/pipx");
    fs::create_dir_all(&pipx_global).unwrap();
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, pipx_global.join("venvs")).unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: pipx_global,
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    assert_eq!(artifacts.walk_coverage.detector(), DET_DISCOVERY);
    let unreadable = artifacts
        .walk_coverage
        .failure_counts()
        .get(&ArtifactStatus::Unreadable)
        .copied()
        .unwrap_or(0);
    assert_eq!(unreadable, 1);
    let examples: Vec<_> = artifacts
        .walk_coverage
        .examples()
        .iter()
        .filter(|e| e.status == ArtifactStatus::Unreadable)
        .collect();
    assert_eq!(examples.len(), 1);
    cleanup(&base);
}

struct RestoreMode<'a> {
    path: &'a std::path::Path,
    mode: u32,
}

impl Drop for RestoreMode<'_> {
    fn drop(&mut self) {
        if let Ok(meta) = fs::metadata(self.path) {
            let mut perms = meta.permissions();
            perms.set_mode(self.mode);
            let _ = fs::set_permissions(self.path, perms);
        }
    }
}

#[test]
fn unreadable_site_packages_makes_discovery_partial_once() {
    let base = tmp();
    let home = base.join("home");
    let site = home.join(".venv/lib/python3.12/site-packages");
    fs::create_dir_all(&site).unwrap();
    fs::write(home.join(".venv/pyvenv.cfg"), "home = /tmp\n").unwrap();
    let original = fs::metadata(&site).unwrap().permissions().mode();
    let mut perms = fs::metadata(&site).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&site, perms).unwrap();
    let _restore = RestoreMode {
        path: &site,
        mode: original,
    };
    if fs::read_dir(&site).is_ok() {
        cleanup(&base);
        return;
    }
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    let intel = EcosystemIntelligence::Available(
        parse_malware_feed(
            br#"[{"package_name":"evil","version":"1.0.0","reason":"MALWARE"}]"#,
            Ecosystem::Pypi,
        )
        .unwrap(),
    );
    let findings: usize = scan_python_artifacts(&artifacts, &intel)
        .iter()
        .map(|o| o.findings.len())
        .sum();
    assert_eq!(findings, 0);
    assert!(artifacts.metadata.is_empty());
    assert_eq!(artifacts.walk_coverage.detector(), DET_DISCOVERY);
    assert_eq!(artifacts.walk_coverage.status(), CoverageStatus::Partial);
    let failures: u32 = artifacts.walk_coverage.failure_counts().values().sum();
    assert_eq!(failures, 1);
    let unreadable = artifacts
        .walk_coverage
        .failure_counts()
        .get(&ArtifactStatus::Unreadable)
        .copied()
        .unwrap_or(0);
    assert_eq!(unreadable, 1);
    drop(_restore);
    cleanup(&base);
}
