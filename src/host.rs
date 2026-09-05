//! Retrospective Linux host network checks: `/etc/hosts` and systemd-resolved cache.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::campaign::intelligence::{EXFIL_DOMAIN, NODEREAL_DOMAIN};
use crate::campaign::{
    CODE_DNS_CACHE_INDICATOR, CODE_HOSTS_FILE_INDICATOR, DET_DNS_CACHE, DET_HOSTS_FILE,
    LIMIT_HOSTS, host_campaign_finding,
};
use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::Finding;
use crate::fsutil::{read_text_lossy_bounded, text_artifact_status};
use crate::model::{EvidenceKind, Severity};
use crate::processutil::{
    BoundedCommand, LIMIT_RESOLVECTL_STDOUT, ToolProbe, classify_probe, run_bounded,
    spawn_not_found,
};
use crate::scan::DetectorOutput;

const RESOLVECTL_TIMEOUT: Duration = Duration::from_secs(15);

pub fn scan_hosts_file(path: &Path) -> DetectorOutput {
    let mut coverage = DetectorCoverage::attempted(DET_HOSTS_FILE);
    match read_text_lossy_bounded(path, LIMIT_HOSTS) {
        crate::fsutil::TextReadOutcome::StatFailed { kind }
            if kind == std::io::ErrorKind::NotFound =>
        {
            return DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage: {
                    let mut skipped = DetectorCoverage::skipped(DET_HOSTS_FILE);
                    skipped.set_detail("/etc/hosts unavailable");
                    skipped
                },
            };
        }
        crate::fsutil::TextReadOutcome::Text(text) => {
            coverage.record_artifact(path.to_path_buf(), ArtifactStatus::Inspected);
            let lowered = text.to_lowercase();
            let mut findings = Vec::new();
            for domain in [EXFIL_DOMAIN, NODEREAL_DOMAIN] {
                if lowered.contains(domain) {
                    findings.push(host_campaign_finding(
                        Severity::Info,
                        EvidenceKind::Context,
                        CODE_HOSTS_FILE_INDICATOR,
                        Some(path.to_path_buf()),
                        format!(
                            "ChainDrop/Shai-Hulud network indicator: hosts file mentions {domain}; \
                             this is commonly a deliberate defensive block"
                        ),
                    ));
                }
            }
            DetectorOutput {
                findings,
                package_evidence: Vec::new(),
                coverage,
            }
        }
        other => {
            coverage.record_artifact(path.to_path_buf(), text_artifact_status(&other));
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
    }
}

pub fn classify_dns_cache(stdout: &str) -> Vec<Finding> {
    let lowered = stdout.to_lowercase();
    let mut findings = Vec::new();
    if lowered.contains(EXFIL_DOMAIN) {
        findings.push(host_campaign_finding(
            Severity::Medium,
            EvidenceKind::Context,
            CODE_DNS_CACHE_INDICATOR,
            None,
            format!(
                "ChainDrop/Shai-Hulud network indicator: recent DNS cache contains {EXFIL_DOMAIN}; \
                 DNS cache has no process attribution"
            ),
        ));
    }
    if lowered.contains(NODEREAL_DOMAIN) {
        findings.push(host_campaign_finding(
            Severity::Medium,
            EvidenceKind::Context,
            CODE_DNS_CACHE_INDICATOR,
            None,
            format!(
                "ChainDrop/Shai-Hulud network context: recent DNS cache contains shared provider \
                 domain {NODEREAL_DOMAIN}; not distinctive without the campaign contract"
            ),
        ));
    }
    findings
}

/// `resolvectl_program`: `None` means the binary is unavailable.
pub fn scan_dns_cache(resolvectl_program: Option<&Path>) -> DetectorOutput {
    let Some(program) = resolvectl_program else {
        let mut coverage = DetectorCoverage::skipped(DET_DNS_CACHE);
        coverage.set_detail("resolvectl not installed; Linux has no universal readable DNS cache");
        return DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage,
        };
    };
    let mut cmd = Command::new(program);
    cmd.arg("show-cache").arg("--no-pager");
    match run_bounded(cmd, RESOLVECTL_TIMEOUT, LIMIT_RESOLVECTL_STDOUT) {
        BoundedCommand::Completed { status, stdout } if status.success() => {
            let mut coverage = DetectorCoverage::attempted(DET_DNS_CACHE);
            coverage.record_artifact(
                PathBuf::from("systemd-resolved cache"),
                ArtifactStatus::Inspected,
            );
            let text = String::from_utf8_lossy(&stdout);
            DetectorOutput {
                findings: classify_dns_cache(&text),
                package_evidence: Vec::new(),
                coverage,
            }
        }
        BoundedCommand::Completed { .. } => DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::unsupported(DET_DNS_CACHE),
        },
        BoundedCommand::SpawnFailed(err) if spawn_not_found(&err) => {
            let mut coverage = DetectorCoverage::skipped(DET_DNS_CACHE);
            coverage
                .set_detail("resolvectl not installed; Linux has no universal readable DNS cache");
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
        BoundedCommand::SpawnFailed(_) => {
            let mut coverage = DetectorCoverage::attempted(DET_DNS_CACHE);
            coverage.record_artifact(
                PathBuf::from("systemd-resolved cache"),
                ArtifactStatus::Unreadable,
            );
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
        BoundedCommand::Oversized => {
            let mut coverage = DetectorCoverage::attempted(DET_DNS_CACHE);
            coverage.record_artifact(
                PathBuf::from("systemd-resolved cache"),
                ArtifactStatus::Oversized,
            );
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
        BoundedCommand::Timeout | BoundedCommand::Io(_) => {
            let mut coverage = DetectorCoverage::attempted(DET_DNS_CACHE);
            coverage.record_artifact(
                PathBuf::from("systemd-resolved cache"),
                ArtifactStatus::Unreadable,
            );
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
    }
}

pub fn scan_dns_cache_with_probe(probe: ToolProbe) -> DetectorOutput {
    match probe {
        ToolProbe::Present => scan_dns_cache(Some(Path::new("resolvectl"))),
        ToolProbe::Missing => scan_dns_cache(None),
        ToolProbe::Unsupported => DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::unsupported(DET_DNS_CACHE),
        },
        ToolProbe::Failed => {
            let mut coverage = DetectorCoverage::attempted(DET_DNS_CACHE);
            coverage.record_artifact(
                PathBuf::from("systemd-resolved cache"),
                ArtifactStatus::Unreadable,
            );
            DetectorOutput {
                findings: Vec::new(),
                package_evidence: Vec::new(),
                coverage,
            }
        }
    }
}

pub fn system_resolvectl() -> ToolProbe {
    let mut cmd = Command::new("resolvectl");
    cmd.arg("--version");
    classify_probe(&run_bounded(cmd, Duration::from_secs(5), 4096))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageStatus;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "chaincheck-hosts-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn hosts_mentions_are_info_not_compromise() {
        let root = tmp();
        let hosts = root.join("hosts");
        fs::write(&hosts, "127.0.0.1 npm-cache.com\n").unwrap();
        let output = scan_hosts_file(&hosts);
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].severity, Severity::Info);
        assert_eq!(output.findings[0].code.as_str(), "hosts-file-indicator");
        assert!(output.findings[0].detail.contains("defensive block"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_hosts_is_skipped() {
        let output = scan_hosts_file(Path::new("/tmp/chaincheck-no-such-hosts-file"));
        assert_eq!(output.coverage.status(), CoverageStatus::Skipped);
        assert!(output.findings.is_empty());
    }

    #[test]
    fn dns_cache_classifies_without_executing() {
        let findings = classify_dns_cache("npm-cache.com eth-mainnet.nodereal.io");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn resolvectl_absent_is_skipped() {
        let output = scan_dns_cache(None);
        assert_eq!(output.coverage.status(), CoverageStatus::Skipped);
    }

    #[test]
    fn missing_resolvectl_path_is_skipped() {
        let output = scan_dns_cache(Some(Path::new("/no/such/chaincheck-resolvectl")));
        assert_eq!(output.coverage.status(), CoverageStatus::Skipped);
        assert!(output.findings.is_empty());
    }

    #[test]
    fn non_executable_resolvectl_is_partial() {
        let root = tmp();
        let fake = root.join("not-executable");
        fs::write(&fake, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = fs::metadata(&fake).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&fake, perms).unwrap();
        let output = scan_dns_cache(Some(&fake));
        assert_eq!(output.coverage.status(), CoverageStatus::Partial);
        assert!(output.findings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nonzero_resolvectl_is_unsupported() {
        let output = scan_dns_cache(Some(Path::new("/bin/false")));
        assert_eq!(output.coverage.status(), CoverageStatus::Unsupported);
        assert!(output.findings.is_empty());
    }

    #[test]
    fn probe_failed_is_partial_without_running_cache() {
        let output = scan_dns_cache_with_probe(ToolProbe::Failed);
        assert_eq!(output.coverage.status(), CoverageStatus::Partial);
        assert!(output.findings.is_empty());
    }
}
