//! IDE/agent configuration content scanning.

use std::path::{Path, PathBuf};

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::fsutil::{read_text_lossy_bounded, text_artifact_status};
use crate::model::{EvidenceKind, Severity};
use crate::scan::DetectorOutput;

use super::content::content_ioc_matches;
use super::{
    CODE_CONFIG_IOC_REFERENCE, CODE_MALICIOUS_CONFIG_CONTENT, DET_IDE_CONFIG, LIMIT_IDE_CONFIG,
    campaign_finding,
};

pub fn scan_ide_config(path: &Path) -> DetectorOutput {
    scan_ide_configs(&[path.to_path_buf()])
}

pub fn scan_ide_configs(paths: &[PathBuf]) -> DetectorOutput {
    let mut findings = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_IDE_CONFIG);
    for path in paths {
        match read_text_lossy_bounded(path, LIMIT_IDE_CONFIG) {
            crate::fsutil::TextReadOutcome::Text(text) => {
                coverage.record_artifact(path.clone(), ArtifactStatus::Inspected);
                let (high, medium) = content_ioc_matches(&text);
                if !high.is_empty() {
                    findings.push(campaign_finding(
                        Severity::High,
                        EvidenceKind::CampaignIndicator,
                        CODE_MALICIOUS_CONFIG_CONTENT,
                        Some(path.clone()),
                        format!(
                            "ChainDrop/Shai-Hulud campaign indicator: configuration contains strong \
                             campaign/infrastructure evidence: {}",
                            high.iter()
                                .chain(medium.iter())
                                .copied()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                } else if !medium.is_empty() {
                    findings.push(campaign_finding(
                        Severity::Medium,
                        EvidenceKind::Context,
                        CODE_CONFIG_IOC_REFERENCE,
                        Some(path.clone()),
                        format!(
                            "ChainDrop/Shai-Hulud campaign indicator: configuration contains contextual \
                             strings requiring inspection: {}",
                            medium.join(", ")
                        ),
                    ));
                }
            }
            other => {
                coverage.record_artifact(path.clone(), text_artifact_status(&other));
            }
        }
    }
    DetectorOutput {
        findings,
        package_evidence: Vec::new(),
        coverage,
    }
}
