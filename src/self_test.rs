//! Native offline self-test. Not a malware scan of the host.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::campaign::{CampaignIntelligence, scan_payload};
use crate::cli::ProcessConfig;
use crate::coverage::CoverageStatus;
use crate::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, parse_malware_feed};
use crate::model::{Ecosystem, Severity};
use crate::npm::scan_artefact;
use crate::python::scan_python;
use crate::scan::{HostDetectorOutputs, ScanOutcome, ScanScope, scan_with_host_outputs};

const NPM_INTEL: &[u8] = br#"[
  {"package_name":"keyv","version":"6.0.0","reason":"MALWARE"},
  {"package_name":"wildcard-malware","version":"*","reason":"MALWARE"}
]"#;
const PYPI_INTEL: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    path: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn temp_dir(prefix: &str) -> Result<Fixture, String> {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-selftest-{prefix}-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|err| {
        format!(
            "cannot create self-test directory {}: {err}",
            path.display()
        )
    })?;
    Ok(Fixture { path })
}

fn write(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create self-test parent {}: {err}", parent.display()))?;
    }
    fs::write(path, body)
        .map_err(|err| format!("cannot write self-test file {}: {err}", path.display()))
}

fn intel() -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        EcosystemIntelligence::Available(
            parse_malware_feed(NPM_INTEL, Ecosystem::Npm).expect("npm intel"),
        ),
        EcosystemIntelligence::Available(
            parse_malware_feed(PYPI_INTEL, Ecosystem::Pypi).expect("pypi intel"),
        ),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fail(name: &str, msg: impl Into<String>) -> Result<(), String> {
    Err(format!("{name}: {}", msg.into()))
}

fn has_code_severity(findings: &[crate::evidence::Finding], code: &str, min: Severity) -> bool {
    findings.iter().any(|f| {
        f.code.as_str() == code
            && matches!(
                (min, f.severity),
                (Severity::Confirmed, Severity::Confirmed)
                    | (Severity::High, Severity::High | Severity::Confirmed)
                    | (
                        Severity::Medium,
                        Severity::Medium | Severity::High | Severity::Confirmed
                    )
            )
    })
}

/// Run the native self-test. Returns whether every case passed.
pub fn run() -> bool {
    println!("SELF-TEST ONLY — NOT A MALWARE SCAN");
    println!();
    println!("ChainCheck is testing its detectors against temporary synthetic fixtures.");
    println!("MEDIUM, HIGH and CONFIRMED classifications below are expected results for those");
    println!("test fixtures. They are NOT findings from this computer.");
    println!();
    println!("No malware scan of this host is being performed by --self-test.");
    println!();

    let cases: &[(&str, fn() -> Result<(), String>)] = &[
        ("npm-lockfile-medium", case_npm_lockfile_medium),
        ("npm-installed-high", case_npm_installed_high),
        ("python-resolved-medium", case_python_resolved_medium),
        ("python-installed-high", case_python_installed_high),
        ("package-corroboration", case_package_corroboration),
        ("campaign-payload-high", case_campaign_payload_high),
        ("campaign-hash-confirmed", case_campaign_hash_confirmed),
        ("malformed-coverage", case_malformed_coverage),
        ("clean-negative", case_clean_negative),
    ];

    let mut failed = 0usize;
    for (name, case) in cases {
        match case() {
            Ok(()) => println!("ok  {name}"),
            Err(err) => {
                println!("FAIL {err}");
                failed += 1;
            }
        }
    }
    println!();
    if failed == 0 {
        println!("self-test passed");
        true
    } else {
        println!("self-test failed ({failed} case(s))");
        false
    }
}

fn case_npm_lockfile_medium() -> Result<(), String> {
    let fx = temp_dir("npm-lock")?;
    let lock = fx.path.join("package-lock.json");
    write(
        &lock,
        r#"{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0"},
    "node_modules/keyv": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"
    }
  }
}"#,
    )?;
    let output = scan_artefact("package-lock", &lock, &intel().npm)
        .map_err(|e| format!("npm-lockfile-medium: {e}"))?;
    if !has_code_severity(&output.findings, "lockfile-package", Severity::Medium) {
        return fail("npm-lockfile-medium", "missing MEDIUM lockfile-package");
    }
    Ok(())
}

fn case_npm_installed_high() -> Result<(), String> {
    let fx = temp_dir("npm-installed")?;
    let manifest = fx.path.join("node_modules/keyv/package.json");
    write(&manifest, r#"{"name":"keyv","version":"6.0.0"}"#)?;
    let output = scan_artefact("package-json", &manifest, &intel().npm)
        .map_err(|e| format!("npm-installed-high: {e}"))?;
    if !has_code_severity(&output.findings, "installed-package", Severity::High) {
        return fail("npm-installed-high", "missing HIGH installed-package");
    }
    Ok(())
}

fn case_python_resolved_medium() -> Result<(), String> {
    let fx = temp_dir("pylock")?;
    let lock = fx.path.join("pylock.toml");
    write(
        &lock,
        r#"lock-version = "1.0"

[[packages]]
name = "evil-pkg"
version = "1.2.3"
"#,
    )?;
    let result = scan_python(
        ScanScope::ExplicitRoot {
            root: fx.path.clone(),
        },
        &ProcessConfig::default(),
        None,
        intel(),
    );
    if !has_code_severity(&result.findings, "lockfile-package", Severity::Medium) {
        return fail(
            "python-resolved-medium",
            format!("missing MEDIUM lockfile-package; got {:?}", result.findings),
        );
    }
    if result.outcome != ScanOutcome::MediumEvidence {
        return fail(
            "python-resolved-medium",
            format!("outcome {:?}", result.outcome),
        );
    }
    Ok(())
}

fn case_python_installed_high() -> Result<(), String> {
    let fx = temp_dir("py-installed")?;
    let meta = fx
        .path
        .join(".venv/lib/python3.12/site-packages/evil_pkg-1.2.3.dist-info/METADATA");
    write(&meta, "Name: evil-pkg\nVersion: 1.2.3\n")?;
    let result = scan_python(
        ScanScope::ExplicitRoot {
            root: fx.path.clone(),
        },
        &ProcessConfig::default(),
        None,
        intel(),
    );
    if !has_code_severity(&result.findings, "installed-package", Severity::High) {
        return fail(
            "python-installed-high",
            format!("missing HIGH installed-package; got {:?}", result.findings),
        );
    }
    Ok(())
}

fn case_package_corroboration() -> Result<(), String> {
    let fx = temp_dir("corroborate")?;
    let project = fx.path.join("project");
    let home = fx.path.join("home");
    write(
        &project.join("package-lock.json"),
        r#"{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0"},
    "node_modules/keyv": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"
    }
  }
}"#,
    )?;
    let entry = serde_json::json!({
        "key": "make-fetch-happen:request-cache:https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
        "integrity": "sha512-placeholder",
        "time": 1785607003132u64,
        "size": 12345
    });
    write(
        &home.join(".npm/_cacache/index-v5/aa/bb/ccddeeff"),
        &format!("\n{}\t{}\n", "0".repeat(40), entry),
    )?;
    let result = scan_with_host_outputs(
        ScanScope::ExplicitRoot { root: project },
        &ProcessConfig::default(),
        Some(&home),
        intel(),
        &CampaignIntelligence::bundled(),
        HostDetectorOutputs::skipped(),
    );
    if !has_code_severity(&result.findings, "corroborated-package", Severity::High) {
        return fail(
            "package-corroboration",
            format!(
                "missing HIGH corroborated-package; got {:?}",
                result.findings
            ),
        );
    }
    Ok(())
}

fn case_campaign_payload_high() -> Result<(), String> {
    let fx = temp_dir("payload-high")?;
    write(
        &fx.path.join("package.json"),
        r#"{"name":"wormed-fixture","version":"1.0.0","scripts":{"preinstall":"node setup.mjs"}}"#,
    )?;
    write(
        &fx.path.join("setup.mjs"),
        "// fixture dropper\nexecFileSync(bun, ['Math_Symbol.js']);\nfetch('https://npm-cache.com/router');\n",
    )?;
    let output = scan_payload(&fx.path.join("setup.mjs"), &CampaignIntelligence::bundled());
    if !has_code_severity(&output.findings, "payload-pattern", Severity::High) {
        return fail(
            "campaign-payload-high",
            format!("missing HIGH payload-pattern; got {:?}", output.findings),
        );
    }
    Ok(())
}

fn case_campaign_hash_confirmed() -> Result<(), String> {
    let fx = temp_dir("payload-hash")?;
    let payload = fx.path.join("setup.mjs");
    let body = "export const setup = true;\n";
    write(&payload, body)?;
    let campaign = CampaignIntelligence::bundled()
        .with_injected_payload_hash(sha256_hex(body.as_bytes()), "self-test hash");
    let output = scan_payload(&payload, &campaign);
    if !has_code_severity(&output.findings, "malware-hash", Severity::Confirmed) {
        return fail(
            "campaign-hash-confirmed",
            format!("missing CONFIRMED malware-hash; got {:?}", output.findings),
        );
    }
    Ok(())
}

fn case_malformed_coverage() -> Result<(), String> {
    let fx = temp_dir("malformed")?;
    let lock = fx.path.join("package-lock.json");
    write(&lock, "{ not json")?;
    let output = scan_artefact("package-lock", &lock, &intel().npm)
        .map_err(|e| format!("malformed-coverage: {e}"))?;
    if !output.findings.is_empty() {
        return fail(
            "malformed-coverage",
            format!("expected no findings, got {:?}", output.findings),
        );
    }
    if output.coverage.status() != CoverageStatus::Partial {
        return fail(
            "malformed-coverage",
            format!(
                "expected Partial coverage, got {:?}",
                output.coverage.status()
            ),
        );
    }
    Ok(())
}

fn case_clean_negative() -> Result<(), String> {
    let fx = temp_dir("clean")?;
    let lock = fx.path.join("package-lock.json");
    write(
        &lock,
        r#"{
  "name": "clean",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "clean", "version": "1.0.0"},
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}"#,
    )?;
    let output = scan_artefact("package-lock", &lock, &intel().npm)
        .map_err(|e| format!("clean-negative: {e}"))?;
    if output.findings.iter().any(|f| f.severity.is_evidence()) {
        return fail(
            "clean-negative",
            format!("unexpected evidence {:?}", output.findings),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_self_test_passes() {
        assert!(run());
    }

    #[test]
    fn fixture_write_failure_is_self_test_error() {
        let fx = temp_dir("write-fail").expect("temp dir for write-fail test");
        let blocker = fx.path.join("not-a-dir");
        write(&blocker, "file").expect("create blocker file");
        let nested = blocker.join("child.txt");
        let err = write(&nested, "y").expect_err("write through file should fail");
        assert!(
            err.contains("cannot create self-test parent")
                || err.contains("cannot write self-test"),
            "{err}"
        );
    }
}
