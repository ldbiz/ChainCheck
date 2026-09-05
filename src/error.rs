//! Process-level errors and exit numbers, distinct from scan outcome.

use std::fmt;
use std::path::PathBuf;

use crate::scan::{ScanOutcome, normal_scan_exit};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageError {
    RootWithSelfTest,
    Unrecognized(String),
    ExtraOperand(String),
}

impl UsageError {
    pub const EXIT: i32 = 64;

    pub fn exit_code(&self) -> i32 {
        Self::EXIT
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootWithSelfTest => f.write_str("ROOT cannot be combined with --self-test."),
            Self::Unrecognized(arg) => write!(f, "unrecognised option: {arg}"),
            Self::ExtraOperand(arg) => write!(f, "unrecognised arguments: {arg}"),
        }
    }
}

impl std::error::Error for UsageError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartError {
    RootMissing { root: PathBuf },
    ReportDirUncreatable { path: PathBuf },
    ReportWriteFailed { path: PathBuf },
    HomeUnavailable,
}

impl StartError {
    pub const EXIT: i32 = 3;

    pub fn exit_code(&self) -> i32 {
        Self::EXIT
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMissing { root } => {
                write!(f, "scan root does not exist: {}", root.display())
            }
            Self::ReportDirUncreatable { path } => {
                write!(f, "cannot create report directory: {}", path.display())
            }
            Self::ReportWriteFailed { path } => {
                write!(f, "cannot write report file: {}", path.display())
            }
            Self::HomeUnavailable => {
                f.write_str("HOME is not set; cannot determine the default scan root.")
            }
        }
    }
}

impl std::error::Error for StartError {}

/// Process-level exit, including invocations that are not a normal scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessExit {
    Scan(ScanOutcome),
    Usage(UsageError),
    CouldNotStart(StartError),
    SelfTest { ok: bool },
    Help,
}

impl ProcessExit {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Scan(outcome) => normal_scan_exit(*outcome),
            Self::Usage(err) => err.exit_code(),
            Self::CouldNotStart(err) => err.exit_code(),
            Self::SelfTest { ok: true } => 0,
            Self::SelfTest { ok: false } => 1,
            Self::Help => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ScanOutcome;

    #[test]
    fn usage_and_start_exit_numbers() {
        assert_eq!(UsageError::RootWithSelfTest.exit_code(), 64);
        assert_eq!(
            StartError::RootMissing {
                root: PathBuf::from("/missing")
            }
            .exit_code(),
            3
        );
        assert_eq!(StartError::HomeUnavailable.exit_code(), 3);
        assert_eq!(
            StartError::ReportWriteFailed {
                path: PathBuf::from("/tmp/summary.txt")
            }
            .exit_code(),
            3
        );
        assert_eq!(ProcessExit::Help.exit_code(), 0);
    }

    #[test]
    fn self_test_failure_is_not_medium_scan_evidence() {
        let failed = ProcessExit::SelfTest { ok: false };
        assert_eq!(failed.exit_code(), 1);
        assert_ne!(failed, ProcessExit::Scan(ScanOutcome::MediumEvidence));
        assert_eq!(
            ProcessExit::Scan(ScanOutcome::MediumEvidence).exit_code(),
            1
        );
        assert_eq!(ProcessExit::SelfTest { ok: true }.exit_code(), 0);
    }
}
