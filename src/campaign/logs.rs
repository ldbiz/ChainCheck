//! Campaign IOC findings from already-read npm debug log text.

use std::path::Path;

use crate::evidence::Finding;
use crate::model::{EvidenceKind, Severity};

use super::content::content_ioc_matches;
use super::{CODE_CAMPAIGN_IOC_LOG, CODE_CONTEXT_IOC_LOG, campaign_finding};

pub fn ioc_findings_from_log_text(path: &Path, text: &str) -> Vec<Finding> {
    let (high, medium) = content_ioc_matches(text);
    let mut findings = Vec::new();
    if !high.is_empty() {
        findings.push(campaign_finding(
            Severity::High,
            EvidenceKind::CampaignIndicator,
            CODE_CAMPAIGN_IOC_LOG,
            Some(path.to_path_buf()),
            format!(
                "ChainDrop/Shai-Hulud campaign indicator: log contains strong \
                 campaign/infrastructure IOC(s): {}",
                high.join(", ")
            ),
        ));
    }
    if !medium.is_empty() {
        findings.push(campaign_finding(
            Severity::Medium,
            EvidenceKind::Context,
            CODE_CONTEXT_IOC_LOG,
            Some(path.to_path_buf()),
            format!(
                "ChainDrop/Shai-Hulud campaign indicator: log contains contextual string(s): {}",
                medium.join(", ")
            ),
        ));
    }
    findings
}
