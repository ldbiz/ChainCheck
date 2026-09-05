//! `package.json` identity, dependency declarations, and installed packages.

use std::path::Path;

use serde_json::Value;

use crate::coverage::ArtifactStatus;
use crate::evidence::EvidenceClass;
use crate::fsutil::{read_utf8_bounded, text_artifact_status};
use crate::intelligence::EcosystemIntelligence;
use crate::model::{EvidenceKind, Severity};

use crate::campaign::preinstall_hook_finding;

use super::{
    CODE_INSTALLED, CODE_MANIFEST_DEPENDENCY, CODE_MANIFEST_PACKAGE, DET_MANIFEST, FileScan,
    LIMIT_PACKAGE_JSON, emit_exact, emit_wildcard_identity, exact_version_token,
};

const DEP_SECTIONS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(crate) fn scan_manifest(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_PACKAGE_JSON) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_manifest(path, intel, &text),
        other => FileScan::failed(text_artifact_status(&other)),
    }
}

fn parse_manifest(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let data: Value = match serde_json::from_str(text) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };

    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let installed = path.components().any(|c| c.as_os_str() == "node_modules");

    if let (Some(name), Some(version)) = (
        data.get("name").and_then(Value::as_str),
        data.get("version").and_then(Value::as_str),
    ) {
        if installed {
            emit_exact(
                intel,
                name,
                version,
                path,
                DET_MANIFEST,
                EvidenceClass::Installed,
                EvidenceKind::InstalledPackage,
                CODE_INSTALLED,
                Severity::High,
                &mut findings,
                &mut evidence,
            );
        } else {
            emit_exact(
                intel,
                name,
                version,
                path,
                DET_MANIFEST,
                EvidenceClass::Manifest,
                EvidenceKind::DependencyDeclaration,
                CODE_MANIFEST_PACKAGE,
                Severity::Medium,
                &mut findings,
                &mut evidence,
            );
        }
    }

    for section in DEP_SECTIONS {
        let Some(map) = data.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (declared_name, spec) in map {
            match exact_dependency_pair(declared_name, spec) {
                Some((name, version)) => emit_exact(
                    intel,
                    &name,
                    &version,
                    path,
                    DET_MANIFEST,
                    EvidenceClass::Manifest,
                    EvidenceKind::DependencyDeclaration,
                    CODE_MANIFEST_DEPENDENCY,
                    Severity::Medium,
                    &mut findings,
                    &mut evidence,
                ),
                None => emit_wildcard_identity(intel, declared_name, path, &mut findings),
            }
        }
    }

    if let Some(finding) = preinstall_hook_finding(path, &data) {
        findings.push(finding);
    }

    FileScan {
        status: ArtifactStatus::Inspected,
        findings,
        evidence,
    }
}

fn exact_dependency_pair(declared_name: &str, spec: &Value) -> Option<(String, String)> {
    let Value::String(spec) = spec else {
        return None;
    };
    let mut value = spec.trim().to_owned();
    let mut actual_name = declared_name.to_owned();
    if let Some(target) = value.strip_prefix("npm:").map(str::to_owned) {
        let split = if target.starts_with('@') {
            let slash = target.find('/')?;
            let at = target[slash + 1..].find('@')?;
            slash + 1 + at
        } else {
            target.rfind('@')?
        };
        if split == 0 {
            return None;
        }
        actual_name = target[..split].to_owned();
        value = target[split + 1..].trim().to_owned();
    }
    if let Some(rest) = value.strip_prefix('=') {
        value = rest.trim().to_owned();
    }
    if value.starts_with('v') && value.len() > 1 && value.as_bytes()[1].is_ascii_digit() {
        value = value[1..].to_owned();
    }
    if !exact_version_token(&value) {
        return None;
    }
    Some((actual_name, value))
}
