//! `setup.cfg` static requires parsing without configparser interpolation.

use std::path::Path;

use crate::coverage::ArtifactStatus;
use crate::fsutil::read_utf8_bounded;
use crate::intelligence::EcosystemIntelligence;

use super::spec::parse_requirement;
use super::{DET_SETUP_CFG, FileScan, LIMIT_SETUP_CFG, emit_declaration};

pub fn scan_setup_cfg(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_SETUP_CFG) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_setup_cfg(path, intel, &text),
        other => FileScan::failed(crate::fsutil::text_artifact_status(&other)),
    }
}

fn parse_setup_cfg(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let sections = parse_ini(text);
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut parse_failed = false;

    if let Some(options) = sections.get("options") {
        if let Some(requires) = options.get("install_requires") {
            parse_failed |=
                emit_multiline_requires(requires, path, intel, &mut findings, &mut evidence);
        }
    }
    if let Some(extras) = sections.get("options.extras_require") {
        for (_key, value) in extras {
            parse_failed |=
                emit_multiline_requires(value, path, intel, &mut findings, &mut evidence);
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

fn emit_multiline_requires(
    text: &str,
    path: &Path,
    intel: &EcosystemIntelligence,
    findings: &mut Vec<crate::evidence::Finding>,
    evidence: &mut Vec<crate::evidence::PackageEvidence>,
) -> bool {
    let mut failed = false;
    for line in split_requires(text) {
        if line.contains("%(") {
            failed = true;
            continue;
        }
        if let Some(req) = parse_requirement(&line) {
            emit_declaration(
                intel,
                &req.name,
                req.exact_version.as_deref(),
                path,
                DET_SETUP_CFG,
                findings,
                evidence,
            );
        }
    }
    failed
}

fn split_requires(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in text.lines() {
        let mut current = String::new();
        let mut in_quote = None;
        for ch in line.chars() {
            match in_quote {
                Some(q) if ch == q => in_quote = None,
                None if ch == '"' || ch == '\'' => in_quote = Some(ch),
                None if ch == ',' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        items.push(trimmed.to_owned());
                    }
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            items.push(trimmed.to_owned());
        }
    }
    items
}

fn parse_ini(
    text: &str,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    let mut sections: std::collections::HashMap<String, std::collections::HashMap<String, String>> =
        std::collections::HashMap::new();
    let mut current = "default".to_owned();
    sections.insert(current.clone(), std::collections::HashMap::new());
    let mut last_key: Option<String> = None;

    for line in text.lines() {
        let raw = line;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_owned();
            sections
                .entry(current.clone())
                .or_insert_with(std::collections::HashMap::new);
            last_key = None;
            continue;
        }
        if raw.starts_with(' ') || raw.starts_with('\t') {
            if let Some(key) = &last_key {
                let section = sections.entry(current.clone()).or_default();
                let existing = section.get(key).cloned().unwrap_or_default();
                let joined = if existing.is_empty() {
                    line.trim().to_owned()
                } else {
                    format!("{existing}\n{}", line.trim())
                };
                section.insert(key.clone(), joined);
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_owned();
        let value = value.trim().to_owned();
        sections
            .entry(current.clone())
            .or_default()
            .insert(key.clone(), value);
        last_key = Some(key);
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::Ecosystem;

    const TINY: &[u8] = br#"[{"package_name":"evil","version":"1.0.0","reason":"MALWARE"},{"package_name":"wildcard-evil","version":"*","reason":"MALWARE"}]"#;

    #[test]
    fn multiline_install_requires() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[options]
install_requires =
    evil == 1.0.0,
    benign>=1.0
"#;
        let scan = parse_setup_cfg(Path::new("setup.cfg"), &intel, text);
        assert_eq!(scan.findings.len(), 1);
    }

    #[test]
    fn multiline_install_requires_without_commas() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[options]
install_requires =
    wildcard-evil>=1
    evil==1.0.0
"#;
        let scan = parse_setup_cfg(Path::new("setup.cfg"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 2);
        assert_eq!(scan.evidence.len(), 1);
        assert_eq!(scan.evidence[0].package.version.as_str(), "1.0.0");
    }

    #[test]
    fn multiline_extras_require_without_commas() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[options.extras_require]
dev =
    wildcard-evil>=1
    evil==1.0.0
"#;
        let scan = parse_setup_cfg(Path::new("setup.cfg"), &intel, text);
        assert_eq!(scan.findings.len(), 2);
        assert_eq!(scan.evidence.len(), 1);
        assert_eq!(scan.evidence[0].package.version.as_str(), "1.0.0");
    }

    #[test]
    fn interpolation_is_partial_but_valid_lines_remain() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[options]
install_requires =
    evil==1.0.0
    foo%(bar)s
"#;
        let scan = parse_setup_cfg(Path::new("setup.cfg"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert_eq!(scan.findings.len(), 1);
    }
}
