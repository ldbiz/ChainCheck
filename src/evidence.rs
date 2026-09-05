//! Package evidence, findings, and corroboration.
//!
//! Corroboration is typed: it uses [`EvidenceClass`] and [`PackageKey`], not
//! display strings.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::coverage::DetectorId;
use crate::intelligence::{EcosystemIntelligence, MalwareMatch};
use crate::model::{
    Ecosystem, EvidenceKind, FindingCode, FindingSubject, IntelligenceSourceId, PackageIdentity,
    PackageKey, PackageVersion, Severity,
};

/// Independent evidence class for package corroboration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum EvidenceClass {
    Manifest,
    Lockfile,
    Cache,
    InstallContext,
    Installed,
}

impl EvidenceClass {
    pub fn is_host_local(self) -> bool {
        matches!(self, Self::Cache | Self::InstallContext | Self::Installed)
    }
}

/// Exact package/version evidence from one detector. Unresolved declarations
/// cannot construct this type without a [`PackageKey`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvidence {
    pub package: PackageKey,
    pub class: EvidenceClass,
    pub location: PathBuf,
    pub detector: DetectorId,
}

/// Declaration-like observation. `exact_version: None` cannot become a [`PackageKey`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDeclaration {
    pub identity: PackageIdentity,
    pub exact_version: Option<PackageVersion>,
    pub location: PathBuf,
    pub detector: DetectorId,
    pub class: EvidenceClass,
}

impl PackageDeclaration {
    pub fn to_package_key(&self) -> Option<PackageKey> {
        Some(PackageKey::new(
            self.identity.clone(),
            self.exact_version.clone()?,
        ))
    }

    pub fn to_package_evidence(&self) -> Option<PackageEvidence> {
        Some(PackageEvidence {
            package: self.to_package_key()?,
            class: self.class,
            location: self.location.clone(),
            detector: self.detector,
        })
    }
}

/// A scanner finding. Coverage failures are not findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub kind: EvidenceKind,
    pub code: FindingCode,
    pub subject: FindingSubject,
    pub location: Option<PathBuf>,
    pub detail: String,
    pub intelligence_source: Option<IntelligenceSourceId>,
}

/// Exact-version keys that already have direct HIGH installed or install-context evidence.
pub fn direct_high_keys(findings: &[Finding]) -> HashSet<PackageKey> {
    findings
        .iter()
        .filter_map(|finding| {
            if finding.severity != Severity::High {
                return None;
            }
            match (&finding.kind, &finding.subject) {
                (
                    EvidenceKind::InstalledPackage | EvidenceKind::InstallContext,
                    FindingSubject::PackageExact(key),
                ) => Some(key.clone()),
                _ => None,
            }
        })
        .collect()
}

/// Wildcard intelligence matches identity only. It does not write [`PackageEvidence`].
pub fn wildcard_applies(identity: &PackageIdentity, wildcards: &HashSet<PackageIdentity>) -> bool {
    wildcards.contains(identity)
}

/// Keys that should emit corroborated HIGH.
///
/// `listed` comes from the matching ecosystem's [`crate::intelligence::MalwareIndex`].
pub fn corroborate(
    evidence: &[PackageEvidence],
    listed: &HashSet<PackageKey>,
    direct_high: &HashSet<PackageKey>,
) -> Vec<PackageKey> {
    let mut classes_by_key: HashMap<PackageKey, HashSet<EvidenceClass>> = HashMap::new();
    for item in evidence {
        classes_by_key
            .entry(item.package.clone())
            .or_default()
            .insert(item.class);
    }

    let mut keys: Vec<PackageKey> = classes_by_key
        .into_iter()
        .filter_map(|(key, classes)| {
            if !listed.contains(&key) {
                return None;
            }
            if direct_high.contains(&key) {
                return None;
            }
            if classes.len() < 2 {
                return None;
            }
            if !classes.iter().copied().any(EvidenceClass::is_host_local) {
                return None;
            }
            Some(key)
        })
        .collect();
    keys.sort();
    keys
}

/// Apply ecosystem corroboration to merged findings and package evidence.
pub fn apply_ecosystem_corroboration(
    findings: &mut Vec<Finding>,
    evidence: &[PackageEvidence],
    intel: &EcosystemIntelligence,
) {
    if matches!(intel, EcosystemIntelligence::Unavailable(_)) {
        return;
    }
    let listed: HashSet<PackageKey> = evidence
        .iter()
        .filter_map(|item| {
            match intel.lookup(&item.package.identity, Some(&item.package.version)) {
                Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
                    Some(item.package.clone())
                }
                Ok(None) | Err(_) => None,
            }
        })
        .collect();
    let direct = direct_high_keys(findings);
    for key in corroborate(evidence, &listed, &direct) {
        findings.push(corroborated_finding(key));
    }
}

/// HIGH corroborated finding for an exact listed key.
pub fn corroborated_finding(key: PackageKey) -> Finding {
    let intelligence_source = match key.identity.ecosystem() {
        Ecosystem::Npm => IntelligenceSourceId::NpmMalware,
        Ecosystem::Pypi => IntelligenceSourceId::PypiMalware,
    };
    Finding {
        severity: Severity::High,
        kind: EvidenceKind::Corroborated,
        code: FindingCode::from_static("corroborated-package"),
        subject: FindingSubject::PackageExact(key),
        location: None,
        detail: String::new(),
        intelligence_source: Some(intelligence_source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CampaignId, Ecosystem, EvidenceKind, FindingCode, FindingSubject, IntelligenceSourceId,
        PackageIdentity, PackageVersion,
    };

    fn detector() -> DetectorId {
        DetectorId::from_static("test")
    }

    fn key(ecosystem: Ecosystem, name: &str, version: &str) -> PackageKey {
        PackageKey::new(
            PackageIdentity::new(ecosystem, name),
            PackageVersion::exact(version),
        )
    }

    fn evidence(package: PackageKey, class: EvidenceClass, location: &str) -> PackageEvidence {
        PackageEvidence {
            package,
            class,
            location: PathBuf::from(location),
            detector: detector(),
        }
    }

    fn high_finding(kind: EvidenceKind, package: PackageKey) -> Finding {
        Finding {
            severity: Severity::High,
            kind,
            code: FindingCode::from_static("test-high"),
            subject: FindingSubject::PackageExact(package),
            location: None,
            detail: String::new(),
            intelligence_source: None,
        }
    }

    #[test]
    fn host_local_classification() {
        assert!(!EvidenceClass::Manifest.is_host_local());
        assert!(!EvidenceClass::Lockfile.is_host_local());
        assert!(EvidenceClass::Cache.is_host_local());
        assert!(EvidenceClass::InstallContext.is_host_local());
        assert!(EvidenceClass::Installed.is_host_local());
    }

    #[test]
    fn two_locations_of_same_class_are_one_class() {
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let listed = HashSet::from([pkg.clone()]);
        let items = [
            evidence(pkg.clone(), EvidenceClass::Lockfile, "/a/package-lock.json"),
            evidence(pkg.clone(), EvidenceClass::Lockfile, "/b/package-lock.json"),
        ];
        assert!(corroborate(&items, &listed, &HashSet::new()).is_empty());
    }

    #[test]
    fn unresolved_declaration_cannot_become_package_key() {
        let decl = PackageDeclaration {
            identity: PackageIdentity::new(Ecosystem::Npm, "wildcard-malware"),
            exact_version: None,
            location: PathBuf::from("/tmp/package.json"),
            detector: detector(),
            class: EvidenceClass::Manifest,
        };
        assert!(decl.to_package_key().is_none());
        assert!(decl.to_package_evidence().is_none());
    }

    #[test]
    fn exact_declaration_can_become_evidence() {
        let decl = PackageDeclaration {
            identity: PackageIdentity::new(Ecosystem::Npm, "keyv"),
            exact_version: Some(PackageVersion::exact("6.0.0")),
            location: PathBuf::from("/tmp/package.json"),
            detector: detector(),
            class: EvidenceClass::Manifest,
        };
        let evidence = decl.to_package_evidence().expect("exact version");
        assert_eq!(evidence.package.version.as_str(), "6.0.0");
        assert_eq!(evidence.class, EvidenceClass::Manifest);
    }

    #[test]
    fn listed_manifest_and_lockfile_do_not_corroborate() {
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let listed = HashSet::from([pkg.clone()]);
        let items = [
            evidence(pkg.clone(), EvidenceClass::Manifest, "/tmp/package.json"),
            evidence(pkg, EvidenceClass::Lockfile, "/tmp/package-lock.json"),
        ];
        assert!(corroborate(&items, &listed, &HashSet::new()).is_empty());
    }

    #[test]
    fn listed_lockfile_and_cache_corroborate() {
        // Oracle: lockfile-plus-cache-corroborates
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let listed = HashSet::from([pkg.clone()]);
        let items = [
            evidence(
                pkg.clone(),
                EvidenceClass::Lockfile,
                "/tmp/package-lock.json",
            ),
            evidence(pkg.clone(), EvidenceClass::Cache, "/tmp/index-v5"),
        ];
        assert_eq!(corroborate(&items, &listed, &HashSet::new()), vec![pkg]);
    }

    #[test]
    fn unlisted_lockfile_and_cache_do_not_corroborate() {
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let items = [
            evidence(
                pkg.clone(),
                EvidenceClass::Lockfile,
                "/tmp/package-lock.json",
            ),
            evidence(pkg, EvidenceClass::Cache, "/tmp/index-v5"),
        ];
        assert!(corroborate(&items, &HashSet::new(), &HashSet::new()).is_empty());
    }

    #[test]
    fn installed_high_suppresses_corroboration() {
        // Oracle: installed-high-suppresses-corroboration
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let listed = HashSet::from([pkg.clone()]);
        let items = [
            evidence(
                pkg.clone(),
                EvidenceClass::Lockfile,
                "/tmp/package-lock.json",
            ),
            evidence(pkg.clone(), EvidenceClass::Cache, "/tmp/index-v5"),
            evidence(
                pkg.clone(),
                EvidenceClass::Installed,
                "/tmp/node_modules/keyv",
            ),
        ];
        let findings = [high_finding(EvidenceKind::InstalledPackage, pkg.clone())];
        let direct = direct_high_keys(&findings);
        assert!(corroborate(&items, &listed, &direct).is_empty());
    }

    #[test]
    fn install_context_high_suppresses_cache_medium_does_not() {
        let pkg = key(Ecosystem::Npm, "keyv", "6.0.0");
        let listed = HashSet::from([pkg.clone()]);
        let items = [
            evidence(
                pkg.clone(),
                EvidenceClass::Lockfile,
                "/tmp/package-lock.json",
            ),
            evidence(pkg.clone(), EvidenceClass::Cache, "/tmp/index-v5"),
        ];
        let install_high = [high_finding(EvidenceKind::InstallContext, pkg.clone())];
        assert!(corroborate(&items, &listed, &direct_high_keys(&install_high)).is_empty());

        let cache_medium = [Finding {
            severity: Severity::Medium,
            kind: EvidenceKind::PackageCache,
            code: FindingCode::from_static("test-cache"),
            subject: FindingSubject::PackageExact(pkg.clone()),
            location: None,
            detail: String::new(),
            intelligence_source: None,
        }];
        assert_eq!(
            corroborate(&items, &listed, &direct_high_keys(&cache_medium)),
            vec![pkg]
        );
    }

    #[test]
    fn npm_and_pypi_same_name_do_not_cross_corroborate() {
        let npm = key(Ecosystem::Npm, "foo", "1");
        let pypi = key(Ecosystem::Pypi, "foo", "1");
        let listed = HashSet::from([npm.clone(), pypi.clone()]);
        let items = [
            evidence(
                npm.clone(),
                EvidenceClass::Lockfile,
                "/tmp/package-lock.json",
            ),
            evidence(pypi, EvidenceClass::Cache, "/tmp/pip-cache"),
        ];
        assert!(corroborate(&items, &listed, &HashSet::new()).is_empty());
    }

    #[test]
    fn wildcard_match_does_not_insert_package_evidence() {
        // Oracle: npm-package-json-wildcard-range / corroboration_keys_must_not_include
        let identity = PackageIdentity::new(Ecosystem::Npm, "wildcard-malware");
        let wildcards = HashSet::from([identity.clone()]);
        assert!(wildcard_applies(&identity, &wildcards));
        let decl = PackageDeclaration {
            identity,
            exact_version: None,
            location: PathBuf::from("/tmp/package.json"),
            detector: detector(),
            class: EvidenceClass::Manifest,
        };
        assert!(decl.to_package_evidence().is_none());
    }

    #[test]
    fn campaign_finding_is_not_package_evidence() {
        let finding = Finding {
            severity: Severity::High,
            kind: EvidenceKind::CampaignIndicator,
            code: FindingCode::from_static("test-campaign"),
            subject: FindingSubject::Campaign(CampaignId::new("test-campaign")),
            location: None,
            detail: String::new(),
            intelligence_source: Some(IntelligenceSourceId::CampaignBundled),
        };
        assert!(direct_high_keys(&[finding]).is_empty());
    }

    #[test]
    fn corroborated_finding_uses_ecosystem_intelligence_source() {
        let npm = key(Ecosystem::Npm, "keyv", "6.0.0");
        let finding = corroborated_finding(npm.clone());
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.kind, EvidenceKind::Corroborated);
        assert_eq!(finding.code.as_str(), "corroborated-package");
        assert_eq!(finding.subject, FindingSubject::PackageExact(npm));
        assert_eq!(
            finding.intelligence_source,
            Some(IntelligenceSourceId::NpmMalware)
        );
        let pypi = key(Ecosystem::Pypi, "evil", "1.0.0");
        assert_eq!(
            corroborated_finding(pypi).intelligence_source,
            Some(IntelligenceSourceId::PypiMalware)
        );
    }
}
