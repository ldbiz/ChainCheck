//! Coverage ledger. Completely separate from findings.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Per-detector coverage status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CoverageStatus {
    Completed,
    Partial,
    Skipped,
    Unsupported,
    NotApplicable,
}

/// Outcome of inspecting one artefact. Not a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ArtifactStatus {
    Inspected,
    StatFailed,
    Unreadable,
    Oversized,
    ParseFailed,
    UnsupportedFormat,
}

/// Opaque detector identifier. Detector-specific names belong with those detectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DetectorId(&'static str);

impl DetectorId {
    pub const fn from_static(name: &'static str) -> Self {
        Self(name)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

pub const MAX_ARTIFACT_FAILURE_EXAMPLES: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactFailureExample {
    pub path: PathBuf,
    pub status: ArtifactStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoverageKind {
    Attempted,
    Skipped,
    Unsupported,
    NotApplicable,
}

/// Coverage for one detector. Counters are not freely mutable; status for an
/// attempted detector is derived from artefacts and cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectorCoverage {
    detector: DetectorId,
    kind: CoverageKind,
    artefacts_encountered: u32,
    artefacts_inspected: u32,
    failure_counts: BTreeMap<ArtifactStatus, u32>,
    examples: Vec<ArtifactFailureExample>,
    cap_reached: bool,
    detail: String,
}

impl DetectorCoverage {
    fn blank(detector: DetectorId, kind: CoverageKind) -> Self {
        Self {
            detector,
            kind,
            artefacts_encountered: 0,
            artefacts_inspected: 0,
            failure_counts: BTreeMap::new(),
            examples: Vec::new(),
            cap_reached: false,
            detail: String::new(),
        }
    }

    /// An attempted detector. Zero artefacts and no cap is [`CoverageStatus::Completed`].
    pub fn attempted(detector: DetectorId) -> Self {
        Self::blank(detector, CoverageKind::Attempted)
    }

    pub fn skipped(detector: DetectorId) -> Self {
        Self::blank(detector, CoverageKind::Skipped)
    }

    pub fn unsupported(detector: DetectorId) -> Self {
        Self::blank(detector, CoverageKind::Unsupported)
    }

    pub fn not_applicable(detector: DetectorId) -> Self {
        Self::blank(detector, CoverageKind::NotApplicable)
    }

    pub fn detector(&self) -> DetectorId {
        self.detector
    }

    pub fn status(&self) -> CoverageStatus {
        match self.kind {
            CoverageKind::Skipped => CoverageStatus::Skipped,
            CoverageKind::Unsupported => CoverageStatus::Unsupported,
            CoverageKind::NotApplicable => CoverageStatus::NotApplicable,
            CoverageKind::Attempted => completed_or_partial(
                self.artefacts_inspected,
                self.artefacts_encountered,
                &self.failure_counts,
                self.cap_reached,
            ),
        }
    }

    pub fn artefacts_encountered(&self) -> u32 {
        self.artefacts_encountered
    }

    pub fn artefacts_inspected(&self) -> u32 {
        self.artefacts_inspected
    }

    pub fn failure_counts(&self) -> &BTreeMap<ArtifactStatus, u32> {
        &self.failure_counts
    }

    pub fn examples(&self) -> &[ArtifactFailureExample] {
        &self.examples
    }

    pub fn cap_reached(&self) -> bool {
        self.cap_reached
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn set_detail(&mut self, detail: impl Into<String>) {
        self.detail = detail.into();
    }

    /// Record one artefact. Marks the detector as attempted. Failure examples are capped.
    pub fn record_artifact(&mut self, path: PathBuf, status: ArtifactStatus) {
        self.kind = CoverageKind::Attempted;
        self.artefacts_encountered += 1;
        if status == ArtifactStatus::Inspected {
            self.artefacts_inspected += 1;
            return;
        }
        *self.failure_counts.entry(status).or_insert(0) += 1;
        if self.examples.len() < MAX_ARTIFACT_FAILURE_EXAMPLES {
            self.examples.push(ArtifactFailureExample { path, status });
        }
    }

    /// Inspection cap reached. Marks the detector as attempted [`CoverageStatus::Partial`].
    pub fn mark_cap_reached(&mut self) {
        self.kind = CoverageKind::Attempted;
        self.cap_reached = true;
    }
}

fn completed_or_partial(
    artefacts_inspected: u32,
    artefacts_encountered: u32,
    failure_counts: &BTreeMap<ArtifactStatus, u32>,
    cap_reached: bool,
) -> CoverageStatus {
    let failures: u32 = failure_counts.values().copied().sum();
    if cap_reached || failures > 0 || artefacts_inspected != artefacts_encountered {
        CoverageStatus::Partial
    } else {
        CoverageStatus::Completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn detector() -> DetectorId {
        DetectorId::from_static("test-detector")
    }

    #[test]
    fn all_inspected_is_completed() {
        let mut coverage = DetectorCoverage::attempted(detector());
        coverage.record_artifact(PathBuf::from("/tmp/a"), ArtifactStatus::Inspected);
        coverage.record_artifact(PathBuf::from("/tmp/b"), ArtifactStatus::Inspected);
        coverage.record_artifact(PathBuf::from("/tmp/c"), ArtifactStatus::Inspected);
        assert_eq!(coverage.status(), CoverageStatus::Completed);
    }

    #[test]
    fn zero_artefacts_without_failures_is_completed() {
        assert_eq!(
            DetectorCoverage::attempted(detector()).status(),
            CoverageStatus::Completed
        );
    }

    #[test]
    fn parse_failed_cannot_remain_completed() {
        let mut coverage = DetectorCoverage::attempted(detector());
        coverage.record_artifact(PathBuf::from("/tmp/a.lock"), ArtifactStatus::ParseFailed);
        assert_eq!(coverage.status(), CoverageStatus::Partial);
        assert_eq!(coverage.artefacts_encountered(), 1);
        assert_eq!(coverage.artefacts_inspected(), 0);
        assert_eq!(coverage.failure_counts()[&ArtifactStatus::ParseFailed], 1);
        assert_eq!(coverage.examples().len(), 1);
        assert_eq!(
            coverage.examples()[0].path.as_path(),
            Path::new("/tmp/a.lock")
        );
    }

    #[test]
    fn unreadable_and_oversized_cannot_remain_completed() {
        let mut unread = DetectorCoverage::attempted(detector());
        unread.record_artifact(PathBuf::from("/tmp/x"), ArtifactStatus::Unreadable);
        assert_ne!(unread.status(), CoverageStatus::Completed);
        assert_eq!(unread.status(), CoverageStatus::Partial);

        let mut oversized = DetectorCoverage::attempted(detector());
        oversized.record_artifact(PathBuf::from("/tmp/y"), ArtifactStatus::Oversized);
        assert_eq!(oversized.status(), CoverageStatus::Partial);
    }

    #[test]
    fn thirteenth_example_is_dropped() {
        let mut coverage = DetectorCoverage::attempted(detector());
        for i in 0..(MAX_ARTIFACT_FAILURE_EXAMPLES + 1) {
            coverage.record_artifact(
                PathBuf::from(format!("/tmp/f{i}")),
                ArtifactStatus::Unreadable,
            );
        }
        assert_eq!(coverage.examples().len(), MAX_ARTIFACT_FAILURE_EXAMPLES);
        assert_eq!(
            coverage.failure_counts()[&ArtifactStatus::Unreadable],
            (MAX_ARTIFACT_FAILURE_EXAMPLES + 1) as u32
        );
        assert_eq!(coverage.status(), CoverageStatus::Partial);
    }

    #[test]
    fn cap_reached_is_partial() {
        let mut coverage = DetectorCoverage::attempted(detector());
        coverage.mark_cap_reached();
        assert_eq!(coverage.status(), CoverageStatus::Partial);
    }

    #[test]
    fn skipped_unsupported_not_applicable_are_explicit() {
        assert_eq!(
            DetectorCoverage::skipped(detector()).status(),
            CoverageStatus::Skipped
        );
        assert_eq!(
            DetectorCoverage::unsupported(detector()).status(),
            CoverageStatus::Unsupported
        );
        assert_eq!(
            DetectorCoverage::not_applicable(detector()).status(),
            CoverageStatus::NotApplicable
        );
    }
}
