//! Poetry declaration and environment discovery tests.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::cli::ProcessConfig;
use chaincheck::intelligence::{EcosystemIntelligence, parse_malware_feed};
use chaincheck::model::{Ecosystem, FindingSubject};
use chaincheck::python::{
    PythonHostLayout, discover_python_with_layout, pyproject, scan_python_artifacts,
};
use chaincheck::scan::ScanScope;

const TINY: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"},{"package_name":"caret-pkg","version":"*","reason":"MALWARE"},{"package_name":"group-pkg","version":"2.0.0","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-py-poetry-{}-{nanos}-{n}",
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

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python")
        .join(relative)
}

fn empty_layout(base: &PathBuf) -> PythonHostLayout {
    PythonHostLayout {
        lib_prefixes: vec![base.join("usr/lib")],
        pipx_global_home: base.join("opt/pipx"),
    }
}

fn plant_poetry_venv(venv_root: &PathBuf) {
    let site = venv_root.join("demo-abc12345-py3.12/lib/python3.12/site-packages");
    fs::create_dir_all(&site.join("evil-pkg-1.2.3.dist-info")).unwrap();
    fs::write(
        site.join("evil-pkg-1.2.3.dist-info/METADATA"),
        "Name: evil-pkg\nVersion: 1.2.3\n",
    )
    .unwrap();
    fs::create_dir_all(venv_root.join("demo-abc12345-py3.12")).unwrap();
    fs::write(
        venv_root.join("demo-abc12345-py3.12/pyvenv.cfg"),
        "home = /tmp\n",
    )
    .unwrap();
}

#[test]
fn poetry_fixture_bare_version_is_exact() {
    let scan = pyproject::scan_pyproject(
        &fixture("declarations/pyproject/poetry-bare-and-caret.toml"),
        &intel(),
    );
    assert_eq!(scan.findings.len(), 3);
    assert_eq!(scan.evidence.len(), 2);
    let exact: Vec<_> = scan
        .findings
        .iter()
        .filter_map(|f| match &f.subject {
            FindingSubject::PackageExact(key) => Some(key.identity.name().as_str()),
            _ => None,
        })
        .collect();
    assert!(exact.contains(&"evil-pkg"));
    assert!(exact.contains(&"group-pkg"));
}

#[test]
fn poetry_fixture_caret_is_identity_only() {
    let scan = pyproject::scan_pyproject(
        &fixture("declarations/pyproject/poetry-bare-and-caret.toml"),
        &intel(),
    );
    let caret = scan.findings.iter().find(|f| {
        matches!(
            &f.subject,
            FindingSubject::PackageIdentity(id) if id.name().as_str() == "caret-pkg"
        )
    });
    assert!(caret.is_some());
    assert_eq!(scan.evidence.len(), 2);
}

#[test]
fn poetry_virtualenvs_path_whole_user_discovers_metadata() {
    let base = tmp();
    let home = base.join("home");
    let venv_root = base.join("custom-venvs");
    plant_poetry_venv(&venv_root);
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        poetry_virtualenvs_path: Some(venv_root),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_default_cache_whole_user_discovers_metadata() {
    let base = tmp();
    let home = base.join("home");
    plant_poetry_venv(&home.join(".cache/pypoetry/virtualenvs"));
    fs::create_dir_all(&home).unwrap();
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &ProcessConfig::default(),
        Some(&home),
        &empty_layout(&base),
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_xdg_cache_home_whole_user_discovers_metadata() {
    let base = tmp();
    let home = base.join("home");
    let xdg_cache = base.join("xdg-cache");
    plant_poetry_venv(&xdg_cache.join("pypoetry/virtualenvs"));
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        xdg_cache_home: Some(xdg_cache),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_cache_dir_whole_user_discovers_metadata() {
    let base = tmp();
    let home = base.join("home");
    let poetry_cache = base.join("poetry-cache");
    plant_poetry_venv(&poetry_cache.join("virtualenvs"));
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        poetry_cache_dir: Some(poetry_cache),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_virtualenvs_path_under_home_cache_is_not_suppressed() {
    let base = tmp();
    let home = base.join("home");
    let venv_root = home.join(".cache/pypoetry/virtualenvs");
    plant_poetry_venv(&venv_root);
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        poetry_virtualenvs_path: Some(venv_root),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_virtualenvs_path_under_pyvenv_pruned_child_is_not_suppressed() {
    let base = tmp();
    let home = base.join("home");
    let project_venv = home.join("project-venv");
    fs::create_dir_all(project_venv.join("lib/python3.12/site-packages")).unwrap();
    fs::write(project_venv.join("pyvenv.cfg"), "home = /tmp\n").unwrap();
    let venv_root = project_venv.join("poetry-virtualenvs");
    plant_poetry_venv(&venv_root);
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        poetry_virtualenvs_path: Some(venv_root.clone()),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::WholeUser { home: home.clone() },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert!(
        artifacts.include_roots.iter().any(|p| p == &venv_root),
        "configured Poetry root must remain an extra root"
    );
    assert_eq!(artifacts.metadata.len(), 1);
    cleanup(&base);
}

#[test]
fn poetry_virtualenv_not_added_for_explicit_root() {
    let base = tmp();
    let home = base.join("home");
    let root = base.join("project");
    let venv_root = base.join("custom-venvs");
    plant_poetry_venv(&venv_root);
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();
    let config = ProcessConfig {
        poetry_virtualenvs_path: Some(venv_root),
        ..ProcessConfig::default()
    };
    let artifacts = discover_python_with_layout(
        &ScanScope::ExplicitRoot { root },
        &config,
        Some(&home),
        &empty_layout(&base),
    );
    assert!(artifacts.metadata.is_empty());
    let findings: usize = scan_python_artifacts(&artifacts, &intel())
        .iter()
        .map(|o| o.findings.len())
        .sum();
    assert_eq!(findings, 0);
    cleanup(&base);
}
