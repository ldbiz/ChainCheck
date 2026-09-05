//! Shared-corpus compatibility tests for generic npm and campaign detectors.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::campaign::{
    CampaignIntelligence, content_ioc_matches, scan_ide_config, scan_payload,
};
use chaincheck::cli::{ParsedCli, ProcessConfig, parse_args, resolve_invocation};
use chaincheck::coverage::CoverageStatus;
use chaincheck::error::ProcessExit;
use chaincheck::evidence::Finding;
use chaincheck::intelligence::{
    EcosystemIntelligence, IntelligenceSnapshot, MalwareMatch, parse_malware_feed,
};
use chaincheck::model::{
    Ecosystem, EvidenceKind, FindingSubject, PackageIdentity, PackageVersion, Severity,
};
use chaincheck::npm::{apply_npm_corroboration, scan_artefact, scan_npm};
use chaincheck::scan::{DetectorOutput, ScanResult, ScanScope, merge_outputs, normal_scan_exit};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;

const GENERIC_CODES: &[&str] = &[
    "installed-package",
    "manifest-package",
    "manifest-dependency",
    "lockfile-package",
    "lockfile-text-match",
    "npm-cache-download",
    "npm-install-log",
    "corroborated-package",
];

const CAMPAIGN_CODES: &[&str] = &[
    "suspicious-install-hook",
    "malware-hash",
    "payload-pattern",
    "preinstall-payload-name",
    "payload-name",
    "malicious-config-content",
    "config-ioc-reference",
    "campaign-ioc-log",
    "context-ioc-log",
    "malicious-git-signature",
    "suspicious-git-author",
    "hosts-file-indicator",
    "dns-cache-indicator",
    "credential-source",
    "credential-environment",
];

const TINY_PYPI: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn shared_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("shared")
}

fn fixture(relative: &str) -> PathBuf {
    let raw = Path::new(relative);
    assert!(
        !raw.is_absolute(),
        "fixture path must be relative: {relative}"
    );
    let root = shared_root().canonicalize().expect("shared fixture root");
    let resolved = root.join(relative);
    assert!(resolved.exists(), "missing fixture: {relative}");
    let canonical = resolved.canonicalize().expect("canonicalize fixture");
    assert!(
        canonical.starts_with(&root),
        "fixture path escapes shared root: {relative}"
    );
    canonical
}

fn load_cases() -> (String, Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cases.json");
    let text = fs::read_to_string(&path).expect("cases.json");
    let doc: Value = serde_json::from_str(&text).expect("cases json");
    let default_intel = doc["intelligence"]
        .as_str()
        .expect("top-level intelligence")
        .to_owned();
    (default_intel, doc)
}

fn npm_intel_from(relative: &str) -> EcosystemIntelligence {
    let bytes = fs::read(fixture(relative)).expect("intel fixture");
    match parse_malware_feed(&bytes, Ecosystem::Npm) {
        Ok(feed) => EcosystemIntelligence::Available(feed),
        Err(failure) => EcosystemIntelligence::Unavailable(failure),
    }
}

fn snapshot_with(npm: EcosystemIntelligence) -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        npm,
        EcosystemIntelligence::Available(parse_malware_feed(TINY_PYPI, Ecosystem::Pypi).unwrap()),
    )
}

fn case_intel(case: &Value, default_intel: &str) -> EcosystemIntelligence {
    let inv = &case["invocation"];
    let relative = case
        .get("intelligence")
        .and_then(Value::as_str)
        .or_else(|| inv.get("intelligence").and_then(Value::as_str))
        .unwrap_or(default_intel);
    npm_intel_from(relative)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Norm {
    severity: String,
    code: String,
    package: Option<String>,
    version: Option<String>,
    evidence_class: Option<String>,
    wildcard: bool,
    campaign_family: Option<String>,
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Confirmed => "CONFIRMED",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Exposure => "EXPOSURE",
        Severity::Info => "INFO",
    }
}

fn class_for(kind: EvidenceKind) -> Option<&'static str> {
    match kind {
        EvidenceKind::InstalledPackage => Some("installed"),
        EvidenceKind::DependencyDeclaration => Some("manifest"),
        EvidenceKind::DependencyResolution => Some("lockfile"),
        EvidenceKind::PackageCache => Some("npm-cache"),
        EvidenceKind::InstallContext => Some("npm-log"),
        _ => None,
    }
}

fn normalize(finding: &Finding) -> Norm {
    let mut package = None;
    let mut version = None;
    let mut wildcard = false;
    let mut campaign_family = None;
    match &finding.subject {
        FindingSubject::PackageExact(key) => {
            package = Some(key.identity.name().as_str().to_owned());
            version = Some(key.version.as_str().to_owned());
        }
        FindingSubject::PackageIdentity(identity) => {
            package = Some(identity.name().as_str().to_owned());
            wildcard = true;
        }
        FindingSubject::Campaign(id) => {
            campaign_family = Some(id.as_str().to_owned());
        }
        _ => {}
    }
    Norm {
        severity: severity_name(finding.severity).to_owned(),
        code: finding.code.as_str().to_owned(),
        package,
        version,
        evidence_class: class_for(finding.kind).map(str::to_owned),
        wildcard,
        campaign_family,
    }
}

fn spec_to_norm(spec: &Value) -> Norm {
    Norm {
        severity: spec["severity"].as_str().unwrap_or("").to_owned(),
        code: spec["code"].as_str().unwrap_or("").to_owned(),
        package: spec
            .get("package")
            .and_then(Value::as_str)
            .map(str::to_owned),
        version: spec
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
        evidence_class: spec
            .get("evidence_class")
            .and_then(Value::as_str)
            .map(str::to_owned),
        wildcard: spec
            .get("wildcard")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        campaign_family: spec
            .get("campaign_family")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn is_compared(code: &str) -> bool {
    GENERIC_CODES.contains(&code) || CAMPAIGN_CODES.contains(&code)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn counts(findings: impl IntoIterator<Item = Norm>) -> HashMap<Norm, usize> {
    let mut map = HashMap::new();
    for item in findings {
        *map.entry(item).or_insert(0) += 1;
    }
    map
}

fn coverage_label(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Completed => "ran",
        CoverageStatus::Partial => "partial",
        CoverageStatus::Skipped => "skipped",
        CoverageStatus::Unsupported => "unsupported",
        CoverageStatus::NotApplicable => "not_applicable",
    }
}

fn include_case(case: &Value) -> bool {
    let ecosystem = case["ecosystem"].as_str().unwrap_or("");
    let classification = case["classification"].as_str().unwrap_or("");
    if !matches!(classification, "compatibility" | "intentional-change") {
        return false;
    }
    match ecosystem {
        "npm" | "campaign" => matches!(
            case["invocation"]["kind"].as_str(),
            Some("artefact" | "walk" | "compose" | "content-ioc")
        ),
        "intelligence" => case["invocation"]["kind"].as_str() == Some("feed"),
        "cli" => case["invocation"]["kind"].as_str() == Some("cli"),
        _ => false,
    }
}

fn run_feed(case: &Value) {
    let id = case["id"].as_str().unwrap();
    let file = case["invocation"]["files"][0].as_str().unwrap();
    let bytes = fs::read(fixture(file)).expect("feed fixture");
    let npm = match parse_malware_feed(&bytes, Ecosystem::Npm) {
        Ok(feed) => EcosystemIntelligence::Available(feed),
        Err(failure) => EcosystemIntelligence::Unavailable(failure),
    };
    let snap = snapshot_with(npm);
    let expected = &case["expected"];
    if let Some(count) = expected.get("feed_count").and_then(Value::as_u64) {
        let actual = match &snap.npm {
            EcosystemIntelligence::Available(feed) => feed.accepted_records() as u64,
            EcosystemIntelligence::Unavailable(_) => 0,
        };
        assert_eq!(actual, count, "{id}: feed_count");
    }
    let index = match &snap.npm {
        EcosystemIntelligence::Available(feed) => Some(feed.index()),
        EcosystemIntelligence::Unavailable(_) => None,
    };
    for pair in expected
        .get("malware_pairs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = pair[0].as_str().unwrap();
        let version = pair[1].as_str().unwrap();
        let hit = index.and_then(|idx| {
            idx.matches(
                &PackageIdentity::npm(name),
                Some(&PackageVersion::exact(version)),
            )
        });
        assert!(
            matches!(hit, Some(MalwareMatch::Exact | MalwareMatch::Wildcard)),
            "{id}: expected malware pair {name}@{version}, got {hit:?}"
        );
    }
    for pair in expected
        .get("malware_queries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = pair[0].as_str().unwrap();
        let version = pair[1].as_str().unwrap();
        let hit = index.and_then(|idx| {
            idx.matches(
                &PackageIdentity::npm(name),
                Some(&PackageVersion::exact(version)),
            )
        });
        assert!(
            matches!(hit, Some(MalwareMatch::Exact | MalwareMatch::Wildcard)),
            "{id}: expected malware query hit {name}@{version}, got {hit:?}"
        );
    }
    for pair in expected
        .get("not_malware_queries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = pair[0].as_str().unwrap();
        let version = pair[1].as_str().unwrap();
        let hit = index.and_then(|idx| {
            idx.matches(
                &PackageIdentity::npm(name),
                Some(&PackageVersion::exact(version)),
            )
        });
        assert_eq!(
            hit, None,
            "{id}: expected non-malware {name}@{version}, got {hit:?}"
        );
    }
    for name in json_str_list(&expected["wildcards"]) {
        let hit = index.and_then(|idx| {
            idx.matches(
                &PackageIdentity::npm(name),
                Some(&PackageVersion::exact("0.0.0")),
            )
        });
        assert_eq!(
            hit,
            Some(MalwareMatch::Wildcard),
            "{id}: expected wildcard {name}"
        );
    }
    if let Some(exit) = expected.get("exit_effect").and_then(Value::as_i64) {
        assert_eq!(
            i64::from(normal_scan_exit(scan_outcome_for(&snap))),
            exit,
            "{id}: exit_effect"
        );
    }
}

fn scan_outcome_for(snap: &IntelligenceSnapshot) -> chaincheck::scan::ScanOutcome {
    chaincheck::scan::scan_outcome(&[], snap)
}

fn run_cli(case: &Value) {
    let id = case["id"].as_str().unwrap();
    let argv: Vec<OsString> = case["invocation"]["cli_argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| OsString::from(v.as_str().unwrap()))
        .collect();
    let code = match parse_args(&argv, ProcessConfig::default()) {
        Err(err) => ProcessExit::Usage(err).exit_code(),
        Ok(ParsedCli::Help) => ProcessExit::Help.exit_code(),
        Ok(parsed) => match resolve_invocation(parsed, None) {
            Err(err) => ProcessExit::CouldNotStart(err).exit_code(),
            Ok(_) => panic!("{id}: CLI case unexpectedly resolved"),
        },
    };
    let expected = case["expected"]["exit_effect"].as_i64().unwrap();
    assert_eq!(i64::from(code), expected, "{id}: exit_effect");
}

fn json_str_list(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn run_content_ioc(case: &Value) {
    let id = case["id"].as_str().unwrap();
    let text = case["invocation"]["text"].as_str().unwrap_or("");
    let (high, medium) = content_ioc_matches(text);
    let expected = &case["expected"];
    assert_eq!(high, json_str_list(&expected["ioc_high"]), "{id}: ioc_high");
    assert_eq!(
        medium,
        json_str_list(&expected["ioc_medium"]),
        "{id}: ioc_medium"
    );
    if let Some(exit) = expected.get("exit_effect").and_then(Value::as_i64) {
        assert_eq!(exit, 0, "{id}: content-ioc exit_effect");
    }
}

fn campaign_intel_for(inv: &Value, path: &Path) -> CampaignIntelligence {
    let mut intel = CampaignIntelligence::bundled();
    if inv.get("inject_payload_hash").and_then(Value::as_bool) == Some(true) {
        let bytes = fs::read(path).expect("payload bytes");
        intel = intel.with_injected_payload_hash(sha256_hex(&bytes), "oracle injected hash");
    }
    intel
}

fn scan_named_artefact(
    artefact_type: &str,
    path: &Path,
    npm: &EcosystemIntelligence,
    campaign: &CampaignIntelligence,
) -> DetectorOutput {
    match artefact_type {
        "payload" => scan_payload(path, campaign),
        "ide-config" => scan_ide_config(path),
        other => scan_artefact(other, path, npm).unwrap(),
    }
}

fn run_case(case: &Value, default_intel: &str) -> ScanResult {
    let inv = &case["invocation"];
    let intel = snapshot_with(case_intel(case, default_intel));
    let kind = inv["kind"].as_str().unwrap();
    match kind {
        "artefact" => {
            let artefact_type = inv["artefact_type"].as_str().unwrap();
            let file = inv["files"][0].as_str().unwrap();
            let path = fixture(file);
            let campaign = campaign_intel_for(inv, &path);
            let output = scan_named_artefact(artefact_type, &path, &intel.npm, &campaign);
            finish(
                ScanScope::ExplicitRoot { root: path },
                vec![output],
                &intel,
                false,
            )
        }
        "walk" => {
            let dir = fixture(inv["files"][0].as_str().unwrap());
            let home = temp_dir("oracle-home");
            let result = scan_npm(
                ScanScope::ExplicitRoot { root: dir },
                &ProcessConfig::default(),
                Some(&home),
                intel,
            );
            let _ = fs::remove_dir_all(&home);
            result
        }
        "compose" => {
            let mut outputs = Vec::new();
            for step in inv["steps"].as_array().unwrap() {
                let artefact_type = step["artefact_type"].as_str().unwrap();
                let file = step["files"][0].as_str().unwrap();
                outputs.push(scan_artefact(artefact_type, &fixture(file), &intel.npm).unwrap());
            }
            finish(
                ScanScope::ExplicitRoot {
                    root: PathBuf::from("/oracle-compose"),
                },
                outputs,
                &intel,
                inv.get("corroborate")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )
        }
        other => panic!("unhandled kind {other}"),
    }
}

fn finish(
    scope: ScanScope,
    outputs: Vec<DetectorOutput>,
    intel: &IntelligenceSnapshot,
    corroborate: bool,
) -> ScanResult {
    let mut merged = merge_outputs(outputs);
    if corroborate {
        apply_npm_corroboration(&mut merged.findings, &merged.package_evidence, &intel.npm);
    }
    ScanResult::from_merged(scope, merged, intel.clone())
}

fn temp_dir(prefix: &str) -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-{prefix}-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assert_case(case: &Value, result: &ScanResult) {
    let id = case["id"].as_str().unwrap();
    let rust_direction = case.get("rust_direction").and_then(Value::as_str);
    if rust_direction == Some("coverage-not-finding") {
        assert!(
            result
                .findings
                .iter()
                .all(|f| !GENERIC_CODES.contains(&f.code.as_str())),
            "{id}: expected no generic findings, got {:?}",
            result.findings
        );
        let by_name: HashMap<_, _> = result
            .coverage
            .iter()
            .map(|c| (c.detector().as_str(), c.status()))
            .collect();
        match id {
            "bun-lockb-unsupported-finding" => {
                assert_eq!(by_name.get("bun-lockb"), Some(&CoverageStatus::Unsupported));
            }
            "parse-error-lockfile-finding" => {
                assert_eq!(by_name.get("npm-lockfile"), Some(&CoverageStatus::Partial));
            }
            "parse-error-manifest-finding" => {
                assert_eq!(by_name.get("manifest"), Some(&CoverageStatus::Partial));
            }
            _ => {}
        }
        return;
    }

    let expected = case.get("expected").expect("compatibility expected");
    if let Some(findings_spec) = expected.get("findings").and_then(Value::as_array) {
        let wanted = counts(
            findings_spec
                .iter()
                .map(spec_to_norm)
                .filter(|n| is_compared(&n.code)),
        );
        let actual = counts(
            result
                .findings
                .iter()
                .map(normalize)
                .filter(|n| is_compared(&n.code)),
        );
        assert_eq!(actual, wanted, "{id}: findings mismatch");
    }
    if let Some(absent) = expected.get("absent_codes").and_then(Value::as_array) {
        for code in absent {
            let code = code.as_str().unwrap();
            assert!(
                result.findings.iter().all(|f| f.code.as_str() != code),
                "{id}: expected no {code}"
            );
        }
    }
    if let Some(forbidden) = expected
        .get("corroboration_keys_must_not_include")
        .and_then(Value::as_array)
    {
        for pair in forbidden {
            let name = pair[0].as_str().unwrap();
            let version = pair[1].as_str().unwrap();
            assert!(
                !result.package_evidence.iter().any(|e| {
                    e.package.identity.name().as_str() == name
                        && e.package.version.as_str() == version
                }),
                "{id}: {name}@{version} unexpectedly in package_evidence"
            );
        }
    }
    if let Some(exit) = expected.get("exit_effect").and_then(Value::as_i64) {
        assert_eq!(
            i64::from(normal_scan_exit(result.outcome)),
            exit,
            "{id}: exit_effect"
        );
    }
    if let Some(coverage) = expected.get("coverage").and_then(Value::as_object) {
        let by_name: HashMap<_, _> = result
            .coverage
            .iter()
            .map(|c| (c.detector().as_str(), coverage_label(c.status())))
            .collect();
        for (detector, status) in coverage {
            let want = status.as_str().unwrap();
            assert_eq!(
                by_name.get(detector.as_str()).copied(),
                Some(want),
                "{id}: coverage[{detector}] {:?} != {want} ({by_name:?})",
                by_name.get(detector.as_str())
            );
        }
    }
}

#[test]
fn oracle_compatibility_cases() {
    let (default_intel, doc) = load_cases();
    let cases = doc["cases"].as_array().unwrap();
    let npm_selected: Vec<_> = cases
        .iter()
        .filter(|c| {
            c["ecosystem"].as_str() == Some("npm")
                && matches!(
                    c["invocation"]["kind"].as_str(),
                    Some("artefact" | "walk" | "compose")
                )
                && matches!(
                    c["classification"].as_str(),
                    Some("compatibility" | "intentional-change")
                )
        })
        .collect();
    assert!(
        npm_selected.len() >= 20,
        "expected a substantial npm case subset, got {}",
        npm_selected.len()
    );
    let selected: Vec<_> = cases.iter().filter(|c| include_case(c)).collect();
    assert_eq!(
        selected.len(),
        51,
        "Stage 0 corpus should be fully selected"
    );
    for case in selected {
        match case["invocation"]["kind"].as_str() {
            Some("content-ioc") => run_content_ioc(case),
            Some("feed") => run_feed(case),
            Some("cli") => run_cli(case),
            _ => {
                let result = run_case(case, &default_intel);
                assert_case(case, &result);
            }
        }
    }
}

#[test]
fn cases_document_records_reference_sha() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cases.json");
    let doc: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        doc["oracle_reference"].as_str(),
        Some("8caa0f1934d8276cd7c56b546aa2579f5c96d1ce")
    );
}

#[test]
fn fixture_path_rejects_escape() {
    let result = std::panic::catch_unwind(|| fixture("../outside.json"));
    assert!(result.is_err());
}
