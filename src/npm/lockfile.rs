//! npm lockfile parsers: package-lock/shrinkwrap, Yarn classic, pnpm, bun.lock.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::EvidenceClass;
use crate::fsutil::{read_utf8_bounded, text_artifact_status};
use crate::intelligence::EcosystemIntelligence;
use crate::model::{EvidenceKind, Severity};
use crate::scan::DetectorOutput;

use super::{
    CODE_LOCKFILE_PACKAGE, CODE_LOCKFILE_TEXT_MATCH, DET_BUN_LOCKB, DET_NPM_LOCKFILE,
    DET_PNPM_LOCKFILE, DET_TEXT_LOCKFILE, DET_YARN_LOCKFILE, FileScan, LIMIT_PACKAGE_LOCK,
    LIMIT_YARN_PNPM_BUN, emit_exact, exact_version_token, split_name_version, yarn_name,
};

pub(crate) fn scan_npm_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_PACKAGE_LOCK) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_npm_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

fn parse_npm_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let data: Value = match serde_json::from_str(text) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let version = json_lockfile_version(&data);
    let pairs = match version {
        Some(1) => {
            let Some(deps) = data.get("dependencies").and_then(Value::as_object) else {
                return FileScan::failed(ArtifactStatus::ParseFailed);
            };
            walk_dependencies(deps)
        }
        Some(2) | Some(3) => {
            let Some(packages) = data.get("packages").and_then(Value::as_object) else {
                return FileScan::failed(ArtifactStatus::ParseFailed);
            };
            walk_packages(packages)
        }
        _ => return FileScan::failed(ArtifactStatus::UnsupportedFormat),
    };
    emit_lock_pairs(path, intel, DET_NPM_LOCKFILE, CODE_LOCKFILE_PACKAGE, &pairs)
}

fn json_lockfile_version(data: &Value) -> Option<u64> {
    match data.get("lockfileVersion") {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|i| u64::try_from(i).ok())),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn walk_packages(packages: &Map<String, Value>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (pkg_path, meta) in packages {
        if pkg_path.is_empty() {
            continue;
        }
        let Some(meta) = meta.as_object() else {
            continue;
        };
        let Some(name) = derive_package_name(pkg_path, meta) else {
            continue;
        };
        let Some(version) = meta.get("version").and_then(Value::as_str) else {
            continue;
        };
        pairs.push((name, version.to_owned()));
    }
    pairs
}

fn derive_package_name(package_path: &str, meta: &Map<String, Value>) -> Option<String> {
    if let Some(name) = meta.get("name").and_then(Value::as_str) {
        if !name.is_empty() {
            return Some(name.to_owned());
        }
    }
    let marker = "node_modules/";
    let tail = package_path.rsplit_once(marker)?.1;
    let mut parts = tail.split('/');
    let first = parts.next().filter(|p| !p.is_empty())?;
    if first.starts_with('@') {
        let second = parts.next()?;
        Some(format!("{first}/{second}"))
    } else {
        Some(first.to_owned())
    }
}

fn walk_dependencies(node: &Map<String, Value>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    walk_dependencies_into(node, &mut pairs);
    pairs
}

fn walk_dependencies_into(node: &Map<String, Value>, pairs: &mut Vec<(String, String)>) {
    for (name, meta) in node {
        let Some(meta) = meta.as_object() else {
            continue;
        };
        if let Some(version) = meta.get("version").and_then(Value::as_str) {
            pairs.push((name.clone(), version.to_owned()));
        }
        if let Some(deps) = meta.get("dependencies").and_then(Value::as_object) {
            walk_dependencies_into(deps, pairs);
        }
    }
}

pub(crate) fn scan_yarn_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_YARN_PNPM_BUN) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_yarn_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

fn parse_yarn_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    if text
        .lines()
        .any(|line| line.trim_start().starts_with("__metadata:"))
    {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let mut pairs = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) && line.trim_end().ends_with(':') && !line.is_empty() {
            let header = line.trim_end().trim_end_matches(':');
            current_names = header.split(',').filter_map(yarn_name).collect();
            continue;
        }
        if let Some(version) = yarn_version_line(line) {
            for name in &current_names {
                pairs.push((name.clone(), version.clone()));
            }
        }
    }
    emit_lock_pairs(
        path,
        intel,
        DET_YARN_LOCKFILE,
        CODE_LOCKFILE_PACKAGE,
        &pairs,
    )
}

fn yarn_version_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("version:")
        .or_else(|| trimmed.strip_prefix("version"))?;
    let rest = rest.trim().trim_matches(|c| c == '"' || c == '\'');
    let token = rest.split_whitespace().next().unwrap_or("");
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

pub(crate) fn scan_pnpm_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_YARN_PNPM_BUN) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pnpm_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

#[derive(Deserialize)]
struct PnpmLock {
    #[serde(rename = "lockfileVersion", default)]
    lockfile_version: Option<PnpmVersion>,
    #[serde(default)]
    packages: Option<BTreeMap<String, serde::de::IgnoredAny>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PnpmVersion {
    String(String),
    Int(i64),
    Float(f64),
}

impl PnpmVersion {
    fn as_text(&self) -> String {
        match self {
            Self::String(s) => s.clone(),
            Self::Int(n) => n.to_string(),
            Self::Float(n) => n.to_string(),
        }
    }
}

fn parse_pnpm_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let parsed: PnpmLock = match serde_saphyr::from_str(text) {
        Ok(parsed) => parsed,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let version_text = parsed
        .lockfile_version
        .as_ref()
        .map(PnpmVersion::as_text)
        .unwrap_or_default();
    let legacy = version_text.starts_with('6');
    let modern = version_text.starts_with('9');
    if !legacy && !modern {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let Some(packages) = parsed.packages else {
        return FileScan::failed(ArtifactStatus::ParseFailed);
    };
    let mut pairs = Vec::new();
    for key in packages.keys() {
        if let Some(pair) = pnpm_key_to_pair(key) {
            pairs.push(pair);
        }
    }
    emit_lock_pairs(
        path,
        intel,
        DET_PNPM_LOCKFILE,
        CODE_LOCKFILE_PACKAGE,
        &pairs,
    )
}

fn pnpm_key_to_pair(key: &str) -> Option<(String, String)> {
    let mut spec = key
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_owned();
    if spec.is_empty() {
        return None;
    }
    if let Some(idx) = spec.find('(') {
        spec.truncate(idx);
    }
    if spec.is_empty() {
        return None;
    }
    if let Some(body) = spec.strip_prefix('/') {
        if let Some(rest) = body.strip_prefix('@') {
            let mut parts = rest.split('/');
            let scope = parts.next()?;
            let name = parts.next()?;
            let version = parts.next()?;
            if version.is_empty() {
                return None;
            }
            return Some((format!("@{scope}/{name}"), version.to_owned()));
        }
        let (name, version) = body.split_once('/')?;
        if name.is_empty() || version.is_empty() {
            return None;
        }
        return Some((name.to_owned(), version.to_owned()));
    }
    split_name_version(&spec)
}

pub(crate) fn scan_bun_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_YARN_PNPM_BUN) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_bun_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

fn parse_bun_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let options = jsonc_parser::ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
        ..Default::default()
    };
    let value: Value = match jsonc_parser::parse_to_serde_value(text, &options) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    match json_lockfile_version(&value) {
        Some(1) => {}
        _ => return FileScan::failed(ArtifactStatus::UnsupportedFormat),
    }
    let Some(packages) = value.get("packages").and_then(Value::as_object) else {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    };
    let mut pairs = Vec::new();
    for entry in packages.values() {
        let Some(Value::String(first)) = entry.as_array().and_then(|a| a.first()) else {
            continue;
        };
        let Some((name, version)) = split_name_version(first) else {
            continue;
        };
        if exact_version_token(&version) {
            pairs.push((name, version));
        }
    }
    emit_lock_pairs(
        path,
        intel,
        DET_TEXT_LOCKFILE,
        CODE_LOCKFILE_TEXT_MATCH,
        &pairs,
    )
}

pub(crate) fn scan_bun_lockb(paths: &[std::path::PathBuf]) -> DetectorOutput {
    if paths.is_empty() {
        return super::skipped(DET_BUN_LOCKB);
    }
    DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: DetectorCoverage::unsupported(DET_BUN_LOCKB),
    }
}

fn emit_lock_pairs(
    path: &Path,
    intel: &EcosystemIntelligence,
    detector: crate::coverage::DetectorId,
    code: crate::model::FindingCode,
    pairs: &[(String, String)],
) -> FileScan {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    for (name, version) in pairs {
        emit_exact(
            intel,
            name,
            version,
            path,
            detector,
            EvidenceClass::Lockfile,
            EvidenceKind::DependencyResolution,
            code,
            Severity::Medium,
            &mut findings,
            &mut evidence,
        );
    }
    FileScan {
        status: ArtifactStatus::Inspected,
        findings,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::parse_malware_feed;
    use crate::model::Ecosystem;
    use std::path::PathBuf;

    const TINY_NPM: &[u8] = br#"[{"package_name":"left-pad","version":"1.3.0","reason":"MALWARE"},{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;

    fn intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap())
    }

    fn shared(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/shared")
            .join(relative)
    }

    #[test]
    fn package_lock_v2_fixture_uses_packages_map() {
        let scan = scan_npm_lock(
            &shared("npm/package-lock/v2-left-pad/package-lock.json"),
            &intel(),
        );
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert!(scan.findings.iter().any(|f| {
            matches!(
                &f.subject,
                crate::model::FindingSubject::PackageExact(key)
                    if key.identity.name().as_str() == "left-pad"
                        && key.version.as_str() == "1.3.0"
            )
        }));
    }

    #[test]
    fn berry_metadata_is_unsupported_format() {
        let scan = scan_yarn_lock(&shared("npm/yarn/berry-metadata/yarn.lock"), &intel());
        assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn bun_lock_v1_fixture_is_structural() {
        let scan = scan_bun_lock(&shared("npm/bun/text-keyv/bun.lock"), &intel());
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(
            scan.findings[0].code.as_str(),
            crate::npm::CODE_LOCKFILE_TEXT_MATCH.as_str()
        );
    }
}
