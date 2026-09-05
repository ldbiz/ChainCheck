//! `Pipfile` dependency category parsing.

use std::path::Path;

use crate::coverage::ArtifactStatus;
use crate::fsutil::read_utf8_bounded;
use crate::intelligence::EcosystemIntelligence;

use super::spec::parse_pipfile_version;
use super::{DET_PIPFILE, FileScan, LIMIT_PIPFILE, emit_declaration};

const DENY_TABLES: &[&str] = &["source", "requires", "scripts", "pipenv"];

pub fn scan_pipfile(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_PIPFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pipfile(path, intel, &text),
        other => FileScan::failed(crate::fsutil::text_artifact_status(&other)),
    }
}

fn parse_pipfile(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut parse_failed = false;

    if let Some(table) = value.as_table() {
        for (key, entry) in table {
            if DENY_TABLES.contains(&key.as_str()) {
                continue;
            }
            if !entry.is_table() {
                continue;
            }
            parse_failed |= emit_pipfile_table(entry, path, intel, &mut findings, &mut evidence);
        }
    }

    let status = if parse_failed {
        ArtifactStatus::ParseFailed
    } else {
        ArtifactStatus::Inspected
    };
    FileScan {
        status,
        findings,
        evidence,
    }
}

const PACKAGE_TABLE_KEYS: &[&str] = &[
    "version", "extras", "git", "path", "file", "editable", "markers", "index",
];

fn is_package_table(table: &toml::Table) -> bool {
    table
        .keys()
        .any(|k| PACKAGE_TABLE_KEYS.contains(&k.as_str()))
}

fn emit_pipfile_table(
    table: &toml::Value,
    path: &Path,
    intel: &EcosystemIntelligence,
    findings: &mut Vec<crate::evidence::Finding>,
    evidence: &mut Vec<crate::evidence::PackageEvidence>,
) -> bool {
    let Some(table) = table.as_table() else {
        return true;
    };
    let mut failed = false;
    for (name, spec) in table {
        if name == "python_version" || name == "python_full_version" {
            continue;
        }
        match spec {
            toml::Value::String(version) => {
                emit_pipfile_version(name, version, path, intel, findings, evidence);
            }
            toml::Value::Table(inner) => {
                if let Some(version) = inner.get("version").and_then(|v| v.as_str()) {
                    emit_pipfile_version(name, version, path, intel, findings, evidence);
                } else if is_package_table(inner) {
                    emit_declaration(intel, name, None, path, DET_PIPFILE, findings, evidence);
                } else {
                    failed = true;
                }
            }
            _ => failed = true,
        }
    }
    failed
}

fn emit_pipfile_version(
    name: &str,
    version: &str,
    path: &Path,
    intel: &EcosystemIntelligence,
    findings: &mut Vec<crate::evidence::Finding>,
    evidence: &mut Vec<crate::evidence::PackageEvidence>,
) {
    if let Some(req) = parse_pipfile_version(name, version) {
        emit_declaration(
            intel,
            &req.name,
            req.exact_version.as_deref(),
            path,
            DET_PIPFILE,
            findings,
            evidence,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::{Ecosystem, EvidenceKind, FindingSubject, Severity};

    const TINY: &[u8] = br#"[{"package_name":"evil","version":"1.0.0","reason":"MALWARE"}]"#;
    const WILDCARD: &[u8] = br#"[{"package_name":"evil","version":"*","reason":"MALWARE"}]"#;

    fn exact_intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap())
    }

    fn wildcard_intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(WILDCARD, Ecosystem::Pypi).unwrap())
    }

    fn assert_wildcard_identity(scan: &FileScan) {
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert!(scan.evidence.is_empty());
        assert_eq!(scan.findings[0].severity, Severity::Medium);
        assert_eq!(scan.findings[0].kind, EvidenceKind::DependencyDeclaration);
        match &scan.findings[0].subject {
            FindingSubject::PackageIdentity(identity) => {
                assert_eq!(identity.name().as_str(), "evil");
                assert_ne!(identity.name().as_str(), "evil*");
            }
            other => panic!("expected package identity, got {other:?}"),
        }
    }

    #[test]
    fn requires_table_is_ignored() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[requires]
python_version = "3.12"
evil = "==1.0.0"
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &intel, text);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn custom_category_emits() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[docs]
evil = "==1.0.0"
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &intel, text);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn custom_category_file_spec_is_not_dropped() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[docs]
evil = "==1.0.0"
other = {file = "https://example.invalid/pkg.whl"}
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn custom_category_recovers_valid_entry_after_invalid_sibling() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[docs]
evil = "==1.0.0"
bad = 123
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn string_star_is_name_only_against_wildcard_intel() {
        let text = r#"
[packages]
evil = "*"
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &wildcard_intel(), text);
        assert_wildcard_identity(&scan);
    }

    #[test]
    fn table_star_is_name_only_against_wildcard_intel() {
        let text = r#"
[packages]
evil = { version = "*" }
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &wildcard_intel(), text);
        assert_wildcard_identity(&scan);
    }

    #[test]
    fn string_star_does_not_match_exact_only_intel() {
        let text = r#"
[packages]
evil = "*"
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &exact_intel(), text);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }

    #[test]
    fn table_star_does_not_match_exact_only_intel() {
        let text = r#"
[packages]
evil = { version = "*" }
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &exact_intel(), text);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }

    #[test]
    fn table_exact_version_still_emits_evidence() {
        let text = r#"
[packages]
evil = { version = "==1.0.0" }
"#;
        let scan = parse_pipfile(Path::new("Pipfile"), &exact_intel(), text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
        assert_eq!(scan.findings[0].severity, Severity::Medium);
        match &scan.findings[0].subject {
            FindingSubject::PackageExact(key) => {
                assert_eq!(key.identity.name().as_str(), "evil");
                assert_eq!(key.version.as_str(), "1.0.0");
            }
            other => panic!("expected exact package, got {other:?}"),
        }
    }
}
