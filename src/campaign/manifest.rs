//! Suspicious campaign preinstall hooks in `package.json`.

use std::path::Path;

use serde_json::Value;

use crate::evidence::Finding;
use crate::model::{EvidenceKind, Severity};

use super::intelligence::PAYLOAD_NAMES;
use super::{CODE_SUSPICIOUS_INSTALL_HOOK, campaign_finding};

/// Campaign preinstall finding from an already-parsed manifest object.
pub fn preinstall_hook_finding(path: &Path, data: &Value) -> Option<Finding> {
    let scripts = data.get("scripts")?.as_object()?;
    let preinstall = scripts.get("preinstall")?.as_str()?;
    let lowered = preinstall.to_lowercase();
    if !PAYLOAD_NAMES
        .iter()
        .any(|name| lowered.contains(&name.to_lowercase()))
    {
        return None;
    }
    Some(campaign_finding(
        Severity::Medium,
        EvidenceKind::CampaignIndicator,
        CODE_SUSPICIOUS_INSTALL_HOOK,
        Some(path.to_path_buf()),
        format!(
            "ChainDrop/Shai-Hulud campaign indicator: preinstall invokes a reported \
             payload filename; filename alone is not proof: {preinstall}"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn case_insensitive_payload_filename_is_medium() {
        let data = json!({"scripts": {"preinstall": "node SETUP.MJS"}});
        let finding = preinstall_hook_finding(Path::new("/tmp/package.json"), &data).unwrap();
        assert_eq!(finding.code.as_str(), "suspicious-install-hook");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn unrelated_preinstall_is_silent() {
        let data = json!({"scripts": {"preinstall": "node install.js"}});
        assert!(preinstall_hook_finding(Path::new("/tmp/package.json"), &data).is_none());
    }
}
