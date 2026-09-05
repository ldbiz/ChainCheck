//! `.dist-info/METADATA` installed-package evidence.

use std::path::Path;

use crate::coverage::ArtifactStatus;
use crate::fsutil::{ReadOutcome, read_bounded};
use crate::intelligence::EcosystemIntelligence;
use crate::model::{EvidenceKind, Severity};

use super::{CODE_INSTALLED, DET_INSTALLED, FileScan, LIMIT_METADATA, emit_exact_installed};

pub fn scan_metadata(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_bounded(path, LIMIT_METADATA) {
        ReadOutcome::Read(bytes) => parse_metadata(path, intel, &bytes),
        other => FileScan::failed(text_artifact_status_from_read(other)),
    }
}

fn text_artifact_status_from_read(outcome: ReadOutcome) -> ArtifactStatus {
    use crate::fsutil::{TextReadOutcome, text_artifact_status};
    match outcome {
        ReadOutcome::Read(bytes) => match String::from_utf8(bytes) {
            Ok(text) => text_artifact_status(&TextReadOutcome::Text(text)),
            Err(_) => ArtifactStatus::ParseFailed,
        },
        ReadOutcome::StatFailed { .. } => ArtifactStatus::StatFailed,
        ReadOutcome::Unreadable { .. } | ReadOutcome::NotRegular | ReadOutcome::Symlink => {
            ArtifactStatus::Unreadable
        }
        ReadOutcome::Oversized { .. } => ArtifactStatus::Oversized,
    }
}

fn parse_metadata(path: &Path, intel: &EcosystemIntelligence, bytes: &[u8]) -> FileScan {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let (name, version) = match parse_identity_headers(text) {
        Ok(pair) => pair,
        Err(status) => return FileScan::failed(status),
    };
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    emit_exact_installed(
        intel,
        &name,
        &version,
        path,
        DET_INSTALLED,
        EvidenceKind::InstalledPackage,
        CODE_INSTALLED,
        Severity::High,
        &mut findings,
        &mut evidence,
    );
    FileScan {
        status: ArtifactStatus::Inspected,
        findings,
        evidence,
    }
}

fn parse_identity_headers(text: &str) -> Result<(String, String), ArtifactStatus> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut in_body = false;
    for line in text.lines() {
        if in_body {
            break;
        }
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "Name" => {
                if name.is_some() {
                    return Err(ArtifactStatus::ParseFailed);
                }
                name = Some(value.to_owned());
            }
            "Version" => {
                if version.is_some() {
                    return Err(ArtifactStatus::ParseFailed);
                }
                version = Some(value.to_owned());
            }
            _ => {}
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok((name, version)),
        _ => Err(ArtifactStatus::ParseFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::Ecosystem;

    const TINY: &[u8] = br#"[{"package_name":"cool-pkg","version":"1.0.0","reason":"MALWARE"}]"#;

    #[test]
    fn duplicate_name_is_parse_failed() {
        let text = "Name: foo\nName: bar\nVersion: 1.0\n";
        assert!(matches!(
            parse_identity_headers(text),
            Err(ArtifactStatus::ParseFailed)
        ));
    }

    #[test]
    fn missing_version_is_parse_failed() {
        let text = "Name: foo\n";
        assert!(matches!(
            parse_identity_headers(text),
            Err(ArtifactStatus::ParseFailed)
        ));
    }

    #[test]
    fn valid_headers_parse() {
        let text = "Metadata-Version: 2.1\nName: Foo.Bar\nVersion: 1.2.3\n\nDescription\n";
        let (name, version) = parse_identity_headers(text).unwrap();
        assert_eq!(name, "Foo.Bar");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn metadata_high_on_malware_match() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let dir = std::env::temp_dir().join(format!("chaincheck-meta-{}", std::process::id()));
        let dist = dir.join("cool_pkg-1.0.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        let meta = dist.join("METADATA");
        std::fs::write(&meta, "Name: cool-pkg\nVersion: 1.0.0\n").unwrap();
        let scan = scan_metadata(&meta, &intel);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.findings[0].severity, Severity::High);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
