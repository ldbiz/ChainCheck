//! Non-evidentiary credential-source inventory. Existence only; values never reported.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::campaign::{CODE_CREDENTIAL_ENVIRONMENT, CODE_CREDENTIAL_SOURCE, DET_CREDENTIALS};
use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::Finding;
use crate::model::{EvidenceKind, FindingSubject, Severity};
use crate::scan::DetectorOutput;

const FIXED_SOURCES: &[(&str, &str)] = &[
    (".npmrc", "npm credentials/config"),
    (".config/gh/hosts.yml", "GitHub CLI credentials"),
    (".git-credentials", "Git credential store"),
    (".aws/credentials", "AWS credentials"),
    (".aws/config", "AWS config"),
    (".kube/config", "Kubernetes config"),
    (".vault-token", "Vault token"),
    (".docker/config.json", "Docker registry credentials"),
    (
        ".config/gcloud/application_default_credentials.json",
        "Google Cloud credentials",
    ),
    (".pypirc", "PyPI credentials/config"),
];

const ENV_NAMES: &[&str] = &[
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "KUBECONFIG",
    "VAULT_TOKEN",
    "TWINE_PASSWORD",
    "UV_PUBLISH_TOKEN",
    "UV_PUBLISH_PASSWORD",
    "HATCH_INDEX_AUTH",
    "FLIT_PASSWORD",
    "POETRY_PYPI_TOKEN_PYPI",
];

fn listed_env_name(key: &OsStr) -> Option<&'static str> {
    ENV_NAMES
        .iter()
        .copied()
        .find(|name| key == OsStr::new(name))
}

fn exposure_finding(
    code: crate::model::FindingCode,
    location: Option<PathBuf>,
    detail: String,
) -> Finding {
    Finding {
        severity: Severity::Exposure,
        kind: EvidenceKind::Exposure,
        code,
        subject: FindingSubject::Host,
        location,
        detail,
        intelligence_source: None,
    }
}

pub fn credential_inventory(
    home: Option<&Path>,
    env: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
) -> DetectorOutput {
    let mut findings = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_CREDENTIALS);

    if let Some(home) = home {
        for (relative, kind) in FIXED_SOURCES {
            let path = home.join(relative);
            match path.symlink_metadata() {
                Ok(meta) if meta.is_file() => {
                    findings.push(exposure_finding(
                        CODE_CREDENTIAL_SOURCE,
                        Some(path),
                        format!(
                            "Informational inventory: {kind} present (normal on developer machines; \
                             not evidence of theft or compromise; contents were not inspected)"
                        ),
                    ));
                }
                _ => {}
            }
        }

        let ssh_dir = home.join(".ssh");
        match fs::read_dir(&ssh_dir) {
            Ok(entries) => {
                let mut keys: Vec<PathBuf> = Vec::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Ok(meta) = path.symlink_metadata() else {
                        continue;
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if name.starts_with("id_") && !name.ends_with(".pub") {
                        keys.push(path);
                    }
                }
                keys.sort();
                for key in keys {
                    findings.push(exposure_finding(
                        CODE_CREDENTIAL_SOURCE,
                        Some(key),
                        "Informational inventory: SSH private key present (normal on developer \
                         machines; not evidence of theft or compromise; contents were not inspected)"
                            .to_owned(),
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                coverage.record_artifact(ssh_dir, ArtifactStatus::Unreadable);
            }
        }
    }

    let mut present: Vec<&str> = Vec::new();
    for (key, value) in env {
        let Some(name) = listed_env_name(key.as_ref()) else {
            continue;
        };
        if value.as_ref().is_empty() {
            continue;
        }
        if !present.contains(&name) {
            present.push(name);
        }
    }
    present.sort_by_key(|name| {
        ENV_NAMES
            .iter()
            .position(|listed| listed == name)
            .unwrap_or(usize::MAX)
    });
    if !present.is_empty() {
        findings.push(exposure_finding(
            CODE_CREDENTIAL_ENVIRONMENT,
            None,
            format!(
                "Informational inventory: credential-shaped environment variables present \
                 (values not reported or retained; not evidence of theft or compromise): {}",
                present.join(", ")
            ),
        ));
    }

    DetectorOutput {
        findings,
        package_evidence: Vec::new(),
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageStatus;
    use crate::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, parse_malware_feed};
    use crate::model::Ecosystem;
    use crate::scan::normal_scan_exit;
    use crate::scan::scan_outcome;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "chaincheck-creds-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    const TINY: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;

    #[test]
    fn pypirc_is_exposure_only_and_values_never_appear() {
        let home = tmp();
        fs::write(home.join(".pypirc"), "password = supersecret\n").unwrap();
        let output = credential_inventory(
            Some(&home),
            [
                ("UV_PUBLISH_TOKEN", "supersecret"),
                ("PIP_INDEX_URL", "https://pypi.org/simple"),
            ],
        );
        assert!(
            output
                .findings
                .iter()
                .any(|f| f.code.as_str() == "credential-source")
        );
        let env = output
            .findings
            .iter()
            .find(|f| f.code.as_str() == "credential-environment")
            .unwrap();
        assert!(env.detail.contains("UV_PUBLISH_TOKEN"));
        assert!(!env.detail.contains("supersecret"));
        assert!(!env.detail.contains("PIP_INDEX_URL"));
        assert!(
            !output
                .findings
                .iter()
                .any(|f| f.detail.contains("supersecret"))
        );
        let intel = IntelligenceSnapshot::new(
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Npm).unwrap()),
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap()),
        );
        assert_eq!(normal_scan_exit(scan_outcome(&output.findings, &intel)), 0);
        assert_eq!(output.coverage.status(), CoverageStatus::Completed);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn index_url_presence_is_not_exposure() {
        let output = credential_inventory(
            None::<&Path>,
            [("PIP_INDEX_URL", "https://pypi.org/simple")],
        );
        assert!(output.findings.is_empty());
    }

    #[test]
    fn unrelated_environment_secret_is_not_retained() {
        let output = credential_inventory(
            None::<&Path>,
            [
                ("UNRELATED_SECRET", "unrelated-supersecret-value"),
                ("UV_PUBLISH_TOKEN", "supersecret"),
            ],
        );
        let env = output
            .findings
            .iter()
            .find(|f| f.code.as_str() == "credential-environment")
            .unwrap();
        assert!(env.detail.contains("UV_PUBLISH_TOKEN"));
        assert!(env.detail.contains("values not reported or retained"));
        assert!(!env.detail.contains("UNRELATED_SECRET"));
        assert!(!env.detail.contains("unrelated-supersecret-value"));
        assert!(!env.detail.contains("supersecret"));
    }
}
