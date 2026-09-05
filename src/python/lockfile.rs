//! Python lockfile parsers: pylock, uv, poetry, Pipfile.lock, pdm.

use std::path::Path;

use serde_json::Value;

use crate::coverage::ArtifactStatus;
use crate::fsutil::{read_utf8_bounded, text_artifact_status};
use crate::intelligence::EcosystemIntelligence;

use super::{
    DET_PDM_LOCK, DET_PIPFILE_LOCK, DET_POETRY_LOCK, DET_PYLOCK, DET_UV_LOCK, FileScan,
    LIMIT_LOCKFILE, emit_resolution,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockTier {
    Proven,
    Degraded,
    Unsupported,
}

pub fn scan_pylock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_LOCKFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pylock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

pub fn scan_uv_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_LOCKFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_uv_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

pub fn scan_poetry_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_LOCKFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_poetry_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

pub fn scan_pipfile_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_LOCKFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pipfile_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

pub fn scan_pdm_lock(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_LOCKFILE) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pdm_lock(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

fn parse_pylock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let tier = match pylock_tier(&value) {
        Some(t) => t,
        None => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    if tier == LockTier::Unsupported {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let (pairs, packages_malformed) = extract_toml_packages(&value, "packages");
    finish_lock(path, intel, DET_PYLOCK, tier, &pairs, packages_malformed)
}

fn pylock_tier(value: &toml::Value) -> Option<LockTier> {
    let version = value.get("lock-version")?.as_str()?;
    let (major, minor) = parse_dot_version(version)?;
    match major {
        1 if minor == 0 => Some(LockTier::Proven),
        1 => Some(LockTier::Degraded),
        _ => Some(LockTier::Unsupported),
    }
}

fn parse_uv_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let tier = match uv_tier(&value) {
        Some(t) => t,
        None => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    if tier == LockTier::Unsupported {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let (pairs, packages_malformed) = extract_uv_packages(&value);
    finish_lock(path, intel, DET_UV_LOCK, tier, &pairs, packages_malformed)
}

fn uv_tier(value: &toml::Value) -> Option<LockTier> {
    let version = match value.get("version") {
        Some(toml::Value::Integer(n)) => *n,
        Some(_) => return None,
        None => return None,
    };
    match version {
        1 => Some(LockTier::Proven),
        _ => Some(LockTier::Unsupported),
    }
}

fn parse_poetry_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let tier = match poetry_tier(&value) {
        Some(t) => t,
        None => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    if tier == LockTier::Unsupported {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let (pairs, packages_malformed) = extract_toml_packages(&value, "package");
    finish_lock(
        path,
        intel,
        DET_POETRY_LOCK,
        tier,
        &pairs,
        packages_malformed,
    )
}

fn poetry_tier(value: &toml::Value) -> Option<LockTier> {
    let version = value
        .get("metadata")
        .and_then(|m| m.get("lock-version"))
        .and_then(|v| v.as_str())?;
    let (major, minor) = parse_dot_version(version)?;
    match major {
        2 if minor == 1 => Some(LockTier::Proven),
        2 => Some(LockTier::Degraded),
        _ => Some(LockTier::Unsupported),
    }
}

fn parse_pdm_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let tier = match pdm_tier(&value) {
        Some(t) => t,
        None => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    if tier == LockTier::Unsupported {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let (pairs, packages_malformed) = extract_toml_packages(&value, "package");
    finish_lock(path, intel, DET_PDM_LOCK, tier, &pairs, packages_malformed)
}

fn pdm_tier(value: &toml::Value) -> Option<LockTier> {
    let version = value
        .get("metadata")
        .and_then(|m| m.get("lock_version"))
        .and_then(|v| v.as_str())?;
    let (major, minor, patch) = parse_triple_version(version)?;
    match major {
        4 if minor == 5 && patch == 1 => Some(LockTier::Proven),
        4 => Some(LockTier::Degraded),
        _ => Some(LockTier::Unsupported),
    }
}

fn parse_pipfile_lock(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let data: Value = match serde_json::from_str(text) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let tier = match pipfile_lock_tier(&data) {
        Some(t) => t,
        None => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    if tier == LockTier::Unsupported {
        return FileScan::failed(ArtifactStatus::UnsupportedFormat);
    }
    let (pairs, malformed) = extract_pipfile_lock_packages(&data);
    finish_lock(path, intel, DET_PIPFILE_LOCK, tier, &pairs, malformed)
}

fn pipfile_lock_tier(data: &Value) -> Option<LockTier> {
    let spec = data
        .get("_meta")
        .and_then(|m| m.get("pipfile-spec"))
        .and_then(Value::as_i64)?;
    match spec {
        6 => Some(LockTier::Proven),
        _ => Some(LockTier::Unsupported),
    }
}

fn extract_pipfile_lock_packages(data: &Value) -> (Vec<(String, String)>, bool) {
    let Some(root) = data.as_object() else {
        return (Vec::new(), true);
    };
    let mut pairs = Vec::new();
    let mut malformed = false;
    for (key, category) in root {
        if key == "_meta" {
            continue;
        }
        let Some(table) = category.as_object() else {
            malformed = true;
            continue;
        };
        for (name, entry) in table {
            match entry {
                Value::Object(obj) => {
                    if obj.contains_key("git") || obj.contains_key("path") {
                        continue;
                    }
                    let Some(version) = obj.get("version").and_then(Value::as_str) else {
                        continue;
                    };
                    if let Some(exact) = strip_pipfile_lock_version(version) {
                        pairs.push((name.clone(), exact));
                    }
                }
                _ => malformed = true,
            }
        }
    }
    pairs.sort();
    pairs.dedup();
    (pairs, malformed)
}

fn strip_pipfile_lock_version(version: &str) -> Option<String> {
    let version = version.trim();
    let rest = version
        .strip_prefix("===")
        .or_else(|| version.strip_prefix("=="))?;
    let exact = rest.trim();
    if exact.is_empty() || exact.contains('*') || exact.contains(',') {
        return None;
    }
    Some(exact.to_owned())
}

fn extract_uv_packages(value: &toml::Value) -> (Vec<(String, String)>, bool) {
    let Some(entries) = value.get("package") else {
        return (Vec::new(), false);
    };
    let Some(entries) = entries.as_array() else {
        return (Vec::new(), true);
    };
    let mut pairs = Vec::new();
    let mut malformed = false;
    for entry in entries {
        let Some(table) = entry.as_table() else {
            malformed = true;
            continue;
        };
        if !uv_is_registry_source(table) {
            continue;
        }
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            malformed = true;
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            malformed = true;
            continue;
        }
        pairs.push((name.to_owned(), version.to_owned()));
    }
    pairs.sort();
    pairs.dedup();
    (pairs, malformed)
}

fn uv_is_registry_source(table: &toml::Table) -> bool {
    table
        .get("source")
        .and_then(|v| v.as_table())
        .is_some_and(|source| source.contains_key("registry"))
}

fn extract_toml_packages(value: &toml::Value, key: &str) -> (Vec<(String, String)>, bool) {
    let Some(entries) = value.get(key) else {
        return (Vec::new(), false);
    };
    let Some(entries) = entries.as_array() else {
        return (Vec::new(), true);
    };
    let mut pairs = Vec::new();
    let mut malformed = false;
    for entry in entries {
        let Some(table) = entry.as_table() else {
            malformed = true;
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            malformed = true;
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            malformed = true;
            continue;
        }
        pairs.push((name.to_owned(), version.to_owned()));
    }
    pairs.sort();
    pairs.dedup();
    (pairs, malformed)
}

fn finish_lock(
    path: &Path,
    intel: &EcosystemIntelligence,
    detector: crate::coverage::DetectorId,
    tier: LockTier,
    pairs: &[(String, String)],
    malformed: bool,
) -> FileScan {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    for (name, version) in pairs {
        emit_resolution(
            intel,
            name,
            version,
            path,
            detector,
            &mut findings,
            &mut evidence,
        );
    }
    let status = if malformed {
        ArtifactStatus::ParseFailed
    } else {
        match tier {
            LockTier::Proven => ArtifactStatus::Inspected,
            LockTier::Degraded | LockTier::Unsupported => ArtifactStatus::UnsupportedFormat,
        }
    };
    FileScan {
        status,
        findings,
        evidence,
    }
}

fn parse_dot_version(version: &str) -> Option<(u32, u32)> {
    let version = version.trim();
    let mut parts = version.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

fn parse_triple_version(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts[1].parse().ok()?;
    let patch: u32 = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

pub(crate) fn is_pylock_filename(name: &str) -> bool {
    if name == "pylock.toml" {
        return true;
    }
    if !name.starts_with("pylock.") || !name.ends_with(".toml") {
        return false;
    }
    let middle = &name["pylock.".len()..name.len() - ".toml".len()];
    !middle.is_empty() && !middle.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::Ecosystem;
    use std::path::PathBuf;

    const TINY: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;

    fn intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap())
    }

    fn fixture(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python")
            .join(relative)
    }

    #[test]
    fn pylock_1_0_is_proven() {
        let scan = scan_pylock(&fixture("locks/pylock/proven-1.0.toml"), &six_intel());
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn pylock_1_1_is_degraded_with_findings() {
        let scan = scan_pylock(&fixture("locks/pylock/degraded-1.1.toml"), &intel());
        assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn pylock_major_2_is_unsupported() {
        let scan = scan_pylock(&fixture("locks/pylock/unsupported-2.0.toml"), &intel());
        assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
        assert!(scan.findings.is_empty());
    }

    fn six_intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"six","version":"1.17.0","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        )
    }

    #[test]
    fn uv_version_1_is_proven() {
        let scan = scan_uv_lock(&fixture("locks/uv/proven-v1.lock"), &six_intel());
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn uv_virtual_project_is_not_matched_as_pypi() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"chaincheck-uv-fixture","version":"0.0.1","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let scan = scan_uv_lock(&fixture("locks/uv/proven-v1.lock"), &intel);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }

    #[test]
    fn uv_float_version_is_malformed_not_proven() {
        let scan = scan_uv_lock(&fixture("locks/uv/malformed-float-1.9.lock"), &intel());
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }

    #[test]
    fn pylock_extra_version_components_are_malformed() {
        let scan = scan_pylock(&fixture("locks/pylock/malformed-1.0.0.toml"), &intel());
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
        let extra = scan_pylock(&fixture("locks/pylock/malformed-1.0.extra.toml"), &intel());
        assert_eq!(extra.status, ArtifactStatus::ParseFailed);
        assert!(extra.findings.is_empty());
    }

    #[test]
    fn poetry_extra_version_components_are_malformed() {
        let scan = scan_poetry_lock(&fixture("locks/poetry/malformed-2.1.foo.lock"), &intel());
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn uv_version_2_is_unsupported() {
        let scan = scan_uv_lock(&fixture("locks/uv/unsupported-v2.lock"), &intel());
        assert_eq!(scan.status, ArtifactStatus::UnsupportedFormat);
        assert!(scan.findings.is_empty());
    }
}
