//! Campaign payload hashing and corroborating-signal grading.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::fsutil::{
    ReadOutcome, TextReadOutcome, artifact_status, read_bounded, read_utf8_bounded,
};
use crate::model::{EvidenceKind, Severity};
use crate::scan::DetectorOutput;

use super::content::content_signal_count;
use super::intelligence::CampaignIntelligence;
use super::{
    CODE_MALWARE_HASH, CODE_PAYLOAD_NAME, CODE_PAYLOAD_PATTERN, CODE_PREINSTALL_PAYLOAD_NAME,
    DET_PAYLOAD, LIMIT_PARENT_MANIFEST, LIMIT_PAYLOAD, campaign_finding,
};

pub enum ParentPreinstall {
    Referenced,
    NotReferenced,
    InspectionFailed {
        path: PathBuf,
        status: ArtifactStatus,
    },
}

pub fn scan_payload(path: &Path, intel: &CampaignIntelligence) -> DetectorOutput {
    scan_payloads(&[path.to_path_buf()], intel)
}

pub fn scan_payloads(paths: &[PathBuf], intel: &CampaignIntelligence) -> DetectorOutput {
    let mut findings = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_PAYLOAD);
    for path in paths {
        grade_one(path, intel, &mut coverage, &mut findings);
    }
    DetectorOutput {
        findings,
        package_evidence: Vec::new(),
        coverage,
    }
}

fn grade_one(
    path: &Path,
    intel: &CampaignIntelligence,
    coverage: &mut DetectorCoverage,
    findings: &mut Vec<crate::evidence::Finding>,
) {
    let outcome = read_bounded(path, LIMIT_PAYLOAD);
    match &outcome {
        ReadOutcome::Read(bytes) => {
            coverage.record_artifact(path.to_path_buf(), ArtifactStatus::Inspected);
            let digest = sha256_hex(bytes);
            if let Some(label) = intel.payload_label(&digest) {
                findings.push(campaign_finding(
                    Severity::Confirmed,
                    EvidenceKind::ExactPayloadHash,
                    CODE_MALWARE_HASH,
                    Some(path.to_path_buf()),
                    format!(
                        "Known malicious payload hash associated with ChainDrop/Shai-Hulud: \
                         SHA-256 {digest}; {label}"
                    ),
                ));
                return;
            }

            let parent = parent_preinstall_references(path);
            let preinstall_ref = match &parent {
                ParentPreinstall::Referenced => true,
                ParentPreinstall::NotReferenced | ParentPreinstall::InspectionFailed { .. } => {
                    false
                }
            };
            if let ParentPreinstall::InspectionFailed {
                path: failed,
                status,
            } = parent
            {
                coverage.record_artifact(failed, status);
            }

            let text = String::from_utf8_lossy(bytes);
            let signals = content_signal_count(&text);

            if preinstall_ref && signals >= 2 {
                findings.push(campaign_finding(
                    Severity::High,
                    EvidenceKind::CampaignIndicator,
                    CODE_PAYLOAD_PATTERN,
                    Some(path.to_path_buf()),
                    format!(
                        "ChainDrop/Shai-Hulud-specific pattern: unrecognised SHA-256 {digest}; \
                         a parent package.json runs this file at preinstall and it contains \
                         {signals} campaign signals"
                    ),
                ));
            } else if preinstall_ref {
                findings.push(campaign_finding(
                    Severity::Medium,
                    EvidenceKind::CampaignIndicator,
                    CODE_PREINSTALL_PAYLOAD_NAME,
                    Some(path.to_path_buf()),
                    format!(
                        "ChainDrop/Shai-Hulud campaign indicator: unrecognised SHA-256 {digest}; \
                         a parent package.json runs this reported payload filename at preinstall"
                    ),
                ));
            } else if signals >= 2 {
                findings.push(campaign_finding(
                    Severity::Medium,
                    EvidenceKind::CampaignIndicator,
                    CODE_PAYLOAD_PATTERN,
                    Some(path.to_path_buf()),
                    format!(
                        "ChainDrop/Shai-Hulud-specific pattern: unrecognised SHA-256 {digest}; \
                         file contains {signals} campaign signals"
                    ),
                ));
            } else {
                findings.push(campaign_finding(
                    Severity::Info,
                    EvidenceKind::Context,
                    CODE_PAYLOAD_NAME,
                    Some(path.to_path_buf()),
                    payload_name_info_detail(path, &digest),
                ));
            }
        }
        other => {
            coverage.record_artifact(path.to_path_buf(), artifact_status(other));
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn payload_name_info_detail(path: &Path, digest: &str) -> String {
    let lead = if path.file_name().and_then(|n| n.to_str()) == Some("setup.mjs") {
        "Known ChainDrop/Shai-Hulud-associated filename setup.mjs encountered \
         (setup.mjs is a common generic filename), but this file's SHA-256 does not match \
         a published malicious payload hash and no corroborating campaign indicators were found."
            .to_owned()
    } else {
        "Known ChainDrop/Shai-Hulud payload filename encountered, but this file's SHA-256 \
         does not match a published malicious payload hash and no corroborating campaign \
         indicators were found."
            .to_owned()
    };
    format!("{lead} SHA-256 {digest}. Filename alone is not evidence of compromise.")
}

pub fn parent_preinstall_references(payload_path: &Path) -> ParentPreinstall {
    let Some(leaf) = payload_path.file_name().and_then(|n| n.to_str()) else {
        return ParentPreinstall::NotReferenced;
    };
    let mut directory = match payload_path.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return ParentPreinstall::NotReferenced,
    };
    for _ in 0..3 {
        let manifest = directory.join("package.json");
        match read_utf8_bounded(&manifest, LIMIT_PARENT_MANIFEST) {
            TextReadOutcome::StatFailed { kind } if kind == io::ErrorKind::NotFound => {}
            TextReadOutcome::Text(text) => {
                let data: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(_) => {
                        return ParentPreinstall::InspectionFailed {
                            path: manifest,
                            status: ArtifactStatus::ParseFailed,
                        };
                    }
                };
                let preinstall = data
                    .get("scripts")
                    .and_then(Value::as_object)
                    .and_then(|scripts| scripts.get("preinstall"))
                    .and_then(Value::as_str);
                return if preinstall.is_some_and(|value| value.contains(leaf)) {
                    ParentPreinstall::Referenced
                } else {
                    ParentPreinstall::NotReferenced
                };
            }
            other => {
                return ParentPreinstall::InspectionFailed {
                    path: manifest,
                    status: crate::fsutil::text_artifact_status(&other),
                };
            }
        }
        let parent = directory.parent();
        match parent {
            Some(parent) if parent != directory => directory = parent.to_path_buf(),
            _ => break,
        }
    }
    ParentPreinstall::NotReferenced
}
