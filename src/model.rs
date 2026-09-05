//! Core identity and finding-related types.
//!
//! Package identity is ecosystem-aware. Exact versions are opaque strings.
//! Unresolved declarations never become [`PackageKey`] values.

use std::fmt;

/// Supported package ecosystems.
///
/// Display for PyPI uses “PyPI”; the variant is `Pypi`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
        }
    }
}

/// Package name stored on an identity.
///
/// For npm this is the caller-supplied spelling. For PyPI it is already
/// PEP 503-canonicalised by [`PackageIdentity::pypi`].
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// PEP 503 canonicalisation: lowercase, then collapse each run of `-`, `_`, `.` to `-`.
fn canonicalize_pypi_name(name: &str) -> String {
    let lowered = name.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut last_was_sep = false;
    for ch in lowered.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_sep {
                out.push('-');
                last_was_sep = true;
            }
        } else {
            out.push(ch);
            last_was_sep = false;
        }
    }
    out
}

/// Ecosystem plus name. Same textual name in npm and PyPI are distinct identities.
///
/// Construct through [`PackageIdentity::npm`] or [`PackageIdentity::pypi`] so PyPI
/// names are always PEP 503-canonicalised and npm names are not.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PackageIdentity {
    ecosystem: Ecosystem,
    name: PackageName,
}

impl PackageIdentity {
    /// npm identity: case-sensitive, no normalisation.
    pub fn npm(name: impl Into<String>) -> Self {
        Self {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new(name),
        }
    }

    /// PyPI identity: PEP 503 canonical name.
    pub fn pypi(name: impl Into<String>) -> Self {
        let raw = name.into();
        Self {
            ecosystem: Ecosystem::Pypi,
            name: PackageName::new(canonicalize_pypi_name(&raw)),
        }
    }

    /// Dispatching constructor. PyPI names are canonicalised; npm names are not.
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        match ecosystem {
            Ecosystem::Npm => Self::npm(name),
            Ecosystem::Pypi => Self::pypi(name),
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    pub fn name(&self) -> &PackageName {
        &self.name
    }
}

/// Opaque exact version string. No semver or PEP 440 interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PackageVersion(String);

impl PackageVersion {
    pub fn exact(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact package/version. Only construct this when a real exact version exists.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PackageKey {
    pub identity: PackageIdentity,
    pub version: PackageVersion,
}

impl PackageKey {
    pub fn new(identity: PackageIdentity, version: PackageVersion) -> Self {
        Self { identity, version }
    }
}

/// Strength of local evidence, not malware dangerousness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Severity {
    Confirmed,
    High,
    Medium,
    Exposure,
    Info,
}

impl Severity {
    /// MEDIUM, HIGH, and CONFIRMED affect scan exit; EXPOSURE and INFO do not.
    pub fn is_evidence(self) -> bool {
        matches!(self, Self::Confirmed | Self::High | Self::Medium)
    }
}

/// Semantic kind of a finding. Parse/unsupported coverage is not a variant.
///
/// Campaign payload-hash matches are distinct from other campaign indicators so
/// later detectors can branch on this type, not on [`FindingCode`] slugs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EvidenceKind {
    DependencyDeclaration,
    DependencyResolution,
    PackageCache,
    InstalledPackage,
    InstallContext,
    Corroborated,
    ExactPayloadHash,
    CampaignIndicator,
    Context,
    Exposure,
}

/// Stable textual finding code for later reporting. Scanner logic must not
/// match on the slug. Detector-specific constants belong with those detectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FindingCode(&'static str);

impl FindingCode {
    pub const fn from_static(slug: &'static str) -> Self {
        Self(slug)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Opaque campaign identifier. Campaign implementation details live later.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CampaignId(String);

impl CampaignId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a finding is about. Campaign findings are not forced into [`PackageKey`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum FindingSubject {
    PackageExact(PackageKey),
    PackageIdentity(PackageIdentity),
    Campaign(CampaignId),
    Host,
    Unspecified,
}

/// Identifier for which intelligence a finding drew on. Not feed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IntelligenceSourceId {
    NpmMalware,
    PypiMalware,
    CampaignBundled,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_and_pypi_same_text_are_distinct() {
        let npm = PackageIdentity::new(Ecosystem::Npm, "keyv");
        let pypi = PackageIdentity::new(Ecosystem::Pypi, "keyv");
        assert_ne!(npm, pypi);
        assert_eq!(Ecosystem::Pypi.display_name(), "PyPI");
    }

    #[test]
    fn pypi_names_are_lowercased() {
        assert_eq!(PackageIdentity::pypi("Foo"), PackageIdentity::pypi("foo"));
        assert_eq!(PackageIdentity::pypi("Foo").name().as_str(), "foo");
    }

    #[test]
    fn pypi_separators_are_equivalent() {
        let dash = PackageIdentity::pypi("cool-pkg");
        let underscore = PackageIdentity::pypi("cool_pkg");
        let dot = PackageIdentity::pypi("cool.pkg");
        assert_eq!(dash, underscore);
        assert_eq!(dash, dot);
        assert_eq!(dash.name().as_str(), "cool-pkg");
    }

    #[test]
    fn pypi_mixed_repeated_separators_collapse() {
        assert_eq!(
            PackageIdentity::pypi("A..B__C--D"),
            PackageIdentity::pypi("a-b-c-d")
        );
        assert_eq!(
            PackageIdentity::pypi("A..B__C--D").name().as_str(),
            "a-b-c-d"
        );
    }

    #[test]
    fn npm_names_are_not_normalised() {
        let mixed = PackageIdentity::npm("Cool_Pkg");
        assert_eq!(mixed.name().as_str(), "Cool_Pkg");
        assert_ne!(mixed, PackageIdentity::npm("cool-pkg"));
        assert_ne!(mixed, PackageIdentity::npm("cool_pkg"));
        assert_ne!(PackageIdentity::npm("KeyV"), PackageIdentity::npm("keyv"));
        assert_ne!(
            PackageIdentity::npm("Cool_Pkg"),
            PackageIdentity::pypi("Cool_Pkg")
        );
    }

    #[test]
    fn normalised_pypi_identities_hash_and_eq_equal() {
        use std::collections::HashSet;
        let a = PackageIdentity::pypi("Foo.Bar");
        let b = PackageIdentity::pypi("foo-bar");
        let c = PackageIdentity::pypi("FOO_BAR");
        assert_eq!(a, b);
        assert_eq!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(set.contains(&c));
    }

    #[test]
    fn new_dispatches_to_ecosystem_constructors() {
        assert_eq!(
            PackageIdentity::new(Ecosystem::Npm, "KeyV").name().as_str(),
            "KeyV"
        );
        assert_eq!(
            PackageIdentity::new(Ecosystem::Pypi, "KeyV")
                .name()
                .as_str(),
            "keyv"
        );
    }

    #[test]
    fn package_key_equality_is_ecosystem_name_and_opaque_version() {
        let npm_keyv = PackageKey::new(
            PackageIdentity::new(Ecosystem::Npm, "keyv"),
            PackageVersion::exact("6.0.0"),
        );
        let npm_keyv_space = PackageKey::new(
            PackageIdentity::new(Ecosystem::Npm, "keyv"),
            PackageVersion::exact("6.0.0 "),
        );
        let pypi_keyv = PackageKey::new(
            PackageIdentity::new(Ecosystem::Pypi, "keyv"),
            PackageVersion::exact("6.0.0"),
        );
        assert_eq!(
            npm_keyv,
            PackageKey::new(
                PackageIdentity::new(Ecosystem::Npm, "keyv"),
                PackageVersion::exact("6.0.0"),
            )
        );
        assert_ne!(npm_keyv, npm_keyv_space);
        assert_ne!(npm_keyv, pypi_keyv);
    }

    #[test]
    fn versions_are_opaque_exact_strings() {
        // Oracle: npm-opaque-installed-version uses release-alpha as an exact version.
        let alpha = PackageVersion::exact("release-alpha");
        assert_eq!(alpha.as_str(), "release-alpha");
        assert_ne!(
            PackageVersion::exact("1.0.0"),
            PackageVersion::exact("1.0.0+meta")
        );
        assert_ne!(
            PackageVersion::exact("v1.0.0"),
            PackageVersion::exact("1.0.0")
        );
    }

    #[test]
    fn finding_code_is_a_slug_not_scanner_logic() {
        let code = FindingCode::from_static("test-code");
        assert_eq!(code.as_str(), "test-code");
    }

    #[test]
    fn campaign_id_is_opaque() {
        let id = CampaignId::new("test-campaign");
        assert_eq!(id.as_str(), "test-campaign");
        assert_eq!(
            FindingSubject::Campaign(CampaignId::new("test-campaign")),
            FindingSubject::Campaign(id)
        );
    }

    #[test]
    fn evidence_severities_affect_exit_informational_do_not() {
        assert!(Severity::Confirmed.is_evidence());
        assert!(Severity::High.is_evidence());
        assert!(Severity::Medium.is_evidence());
        assert!(!Severity::Exposure.is_evidence());
        assert!(!Severity::Info.is_evidence());
    }

    #[test]
    fn payload_hash_is_typed_not_a_finding_code() {
        assert_ne!(
            EvidenceKind::ExactPayloadHash,
            EvidenceKind::CampaignIndicator
        );
        assert_ne!(EvidenceKind::ExactPayloadHash, EvidenceKind::Context);
        assert_ne!(EvidenceKind::CampaignIndicator, EvidenceKind::Exposure);
        // The same reporting slug must not be what distinguishes hash from indicator.
        assert_eq!(
            FindingCode::from_static("malware-hash"),
            FindingCode::from_static("malware-hash")
        );
        assert_ne!(
            EvidenceKind::ExactPayloadHash,
            EvidenceKind::CampaignIndicator
        );
    }
}
