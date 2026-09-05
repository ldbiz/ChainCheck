//! pip wheel cache detector integration tests.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::cli::ProcessConfig;
use chaincheck::coverage::CoverageStatus;
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::{Ecosystem, EvidenceKind, Severity};
use chaincheck::python::{
    DET_PIP_WHEEL_CACHE, PythonHostLayout, discover_python_with_layout, scan_pip_wheel_cache,
    wheel_cache,
};
use chaincheck::scan::ScanScope;

const TINY: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-wheel-{}-{nanos}-{n}",
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

fn fixture_wheel_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python/wheel-cache/pip-wheels")
}

#[test]
fn fixture_wheel_emits_package_cache() {
    let output = scan_pip_wheel_cache(&[fixture_wheel_root()], &intel());
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].kind, EvidenceKind::PackageCache);
    assert_eq!(output.findings[0].severity, Severity::Medium);
    assert_eq!(output.coverage.status(), CoverageStatus::Completed);
}

#[test]
fn wheel_outside_pip_wheels_is_not_scanned() {
    let base = tmp();
    let home = base.join("home");
    let stray = home.join("downloads/evil-pkg-1.2.3-py3-none-any.whl");
    fs::create_dir_all(stray.parent().unwrap()).unwrap();
    fs::write(&stray, b"").unwrap();
    fs::create_dir_all(&home).unwrap();
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
    assert!(artifacts.pip_wheel_roots.is_empty());
    cleanup(&base);
}

#[test]
fn pip_cache_dir_whole_user_adds_wheels_root() {
    let base = tmp();
    let home = base.join("home");
    let wheels = base.join("pip-cache/wheels/hashed/cd");
    fs::create_dir_all(&wheels).unwrap();
    fs::write(wheels.join("evil_pkg-1.2.3-py3-none-any.whl"), b"").unwrap();
    fs::create_dir_all(&home).unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let config = ProcessConfig {
        pip_cache_dir: Some(base.join("pip-cache")),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &layout,
    );
    assert_eq!(artifacts.pip_wheel_roots.len(), 1);
    let output = scan_pip_wheel_cache(&artifacts.pip_wheel_roots, &intel());
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.coverage.detector(), DET_PIP_WHEEL_CACHE);
    cleanup(&base);
}

#[test]
fn explicit_root_adds_host_pip_wheel_cache() {
    let base = tmp();
    let home = base.join("home");
    let root = base.join("project");
    let wheels = home.join(".cache/pip/wheels/hashed/ef");
    fs::create_dir_all(&wheels).unwrap();
    fs::write(wheels.join("evil_pkg-1.2.3-py3-none-any.whl"), b"").unwrap();
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();
    let pipx_site =
        home.join(".local/share/pipx/venvs/t/lib/python3.12/site-packages/x-1.0.0.dist-info");
    fs::create_dir_all(&pipx_site).unwrap();
    fs::write(pipx_site.join("METADATA"), "Name: x\nVersion: 1.0.0\n").unwrap();
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
    assert_eq!(artifacts.pip_wheel_roots.len(), 1);
    assert!(artifacts.metadata.is_empty());
    let output = scan_pip_wheel_cache(&artifacts.pip_wheel_roots, &intel());
    assert_eq!(output.findings.len(), 1);
    cleanup(&base);
}

#[test]
fn whole_user_and_explicit_root_share_host_pip_wheel_cache() {
    let base = tmp();
    let home = base.join("home");
    let root = base.join("project");
    let wheels = home.join(".cache/pip/wheels/hashed/ef");
    fs::create_dir_all(&wheels).unwrap();
    fs::write(wheels.join("evil_pkg-1.2.3-py3-none-any.whl"), b"").unwrap();
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();
    let layout = PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    };
    let whole = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    let explicit = discover_python_with_layout(
        &ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        Some(&home),
        &layout,
    );
    assert_eq!(whole.pip_wheel_roots, explicit.pip_wheel_roots);
    assert_eq!(whole.pip_wheel_roots.len(), 1);
    assert!(explicit.metadata.is_empty());
    cleanup(&base);
}

#[test]
fn malformed_wheel_filename_is_silent() {
    let base = tmp();
    let wheels = base.join("wheels/ab");
    fs::create_dir_all(&wheels).unwrap();
    fs::write(wheels.join("not-a-valid-wheel.whl"), b"").unwrap();
    let output = scan_pip_wheel_cache(&[base.join("wheels")], &intel());
    assert!(output.findings.is_empty());
    assert_eq!(output.coverage.artefacts_inspected(), 1);
    assert_eq!(output.coverage.status(), CoverageStatus::Completed);
    cleanup(&base);
}

#[test]
fn wheel_cache_cap_marks_partial() {
    let base = tmp();
    let wheels = base.join("wheels/ab");
    fs::create_dir_all(&wheels).unwrap();
    for i in 0..4 {
        fs::write(
            wheels.join(format!("benign-pkg-1.0.0-py3-none-any-{i}.whl")),
            b"",
        )
        .unwrap();
    }
    let output = wheel_cache::scan_pip_wheel_cache_limited(&[base.join("wheels")], &intel(), 3);
    assert_eq!(output.coverage.status(), CoverageStatus::Partial);
    assert!(output.coverage.cap_reached());
    cleanup(&base);
}

#[test]
fn unreadable_wheel_root_records_failure() {
    use std::os::unix::fs::PermissionsExt;

    let base = tmp();
    let wheels = base.join("wheels");
    fs::create_dir_all(&wheels).unwrap();
    let original = fs::metadata(&wheels).unwrap().permissions().mode();
    let mut perms = fs::metadata(&wheels).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&wheels, perms).unwrap();
    if fs::read_dir(&wheels).is_ok() {
        let mut restore = fs::metadata(&wheels).unwrap().permissions();
        restore.set_mode(original);
        let _ = fs::set_permissions(&wheels, restore);
        cleanup(&base);
        return;
    }
    let output = scan_pip_wheel_cache(&[wheels.clone()], &intel());
    let failures: u32 = output.coverage.failure_counts().values().sum();
    assert_eq!(failures, 1);
    let mut restore = fs::metadata(&wheels).unwrap().permissions();
    restore.set_mode(original);
    let _ = fs::set_permissions(&wheels, restore);
    cleanup(&base);
}
