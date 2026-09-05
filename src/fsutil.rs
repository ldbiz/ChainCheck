//! Bounded reads of attacker-controlled paths.
//!
//! Guarantees:
//! - The **final path component** is not followed if it is a symlink (`O_NOFOLLOW`).
//!   Intermediate path components may still be followed by the kernel; this helper
//!   does **not** by itself contain a read beneath an explicit scan ROOT.
//! - Future filesystem discovery must not descend directory symlinks and is
//!   responsible for maintaining explicit-root scope.
//! - Non-regular files (directories, FIFOs, devices, sockets) are not read.
//! - The body read is bounded to at most `limit + 1` bytes.
//!
//! Raw [`read_bounded`] is the core primitive. Text helpers choose UTF-8 policy
//! explicitly: [`read_utf8_bounded`] (strict) or [`read_text_lossy_bounded`].

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::coverage::ArtifactStatus;

/// Outcome of classifying a host directory candidate without following symlinks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDirKind {
    Absent,
    RealDirectory,
    DirectorySymlink,
    Failed(ArtifactStatus),
}

/// Classify a directory candidate using `symlink_metadata` only.
pub fn classify_host_dir(path: &Path) -> HostDirKind {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => HostDirKind::Absent,
        Err(_) => HostDirKind::Failed(ArtifactStatus::StatFailed),
        Ok(meta) => {
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                HostDirKind::DirectorySymlink
            } else if file_type.is_dir() {
                HostDirKind::RealDirectory
            } else {
                HostDirKind::Absent
            }
        }
    }
}

/// Linux `fcntl.h` flags. ChainCheck is Linux/WSL only.
const O_CLOEXEC: i32 = 0o2000000;
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;

/// Linux `ELOOP` — `O_NOFOLLOW` when the path is a symlink.
const ELOOP: i32 = 40;

#[derive(Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    Read(Vec<u8>),
    StatFailed { kind: io::ErrorKind },
    Unreadable { kind: io::ErrorKind },
    Oversized { size: Option<u64>, limit: u64 },
    NotRegular,
    Symlink,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TextReadOutcome {
    Text(String),
    InvalidUtf8,
    StatFailed { kind: io::ErrorKind },
    Unreadable { kind: io::ErrorKind },
    Oversized { size: Option<u64>, limit: u64 },
    NotRegular,
    Symlink,
}

pub fn read_bounded(path: &Path, limit: u64) -> ReadOutcome {
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts.custom_flags(O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    let file = match opts.open(path) {
        Ok(file) => file,
        Err(err) => return open_error(err),
    };

    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => return ReadOutcome::StatFailed { kind: err.kind() },
    };
    if !meta.is_file() {
        return ReadOutcome::NotRegular;
    }
    if meta.len() > limit {
        return ReadOutcome::Oversized {
            size: Some(meta.len()),
            limit,
        };
    }

    let mut buf = Vec::new();
    let mut limited = file.take(limit.saturating_add(1));
    match limited.read_to_end(&mut buf) {
        Ok(_) if (buf.len() as u64) > limit => ReadOutcome::Oversized { size: None, limit },
        Ok(_) => ReadOutcome::Read(buf),
        Err(err) => ReadOutcome::Unreadable { kind: err.kind() },
    }
}

pub fn read_utf8_bounded(path: &Path, limit: u64) -> TextReadOutcome {
    match read_bounded(path, limit) {
        ReadOutcome::Read(bytes) => match String::from_utf8(bytes) {
            Ok(text) => TextReadOutcome::Text(text),
            Err(_) => TextReadOutcome::InvalidUtf8,
        },
        other => text_from_read(other),
    }
}

/// Lossy UTF-8 for log-like artefacts. Structural parsers should use
/// [`read_bounded`] or [`read_utf8_bounded`] instead.
pub fn read_text_lossy_bounded(path: &Path, limit: u64) -> TextReadOutcome {
    match read_bounded(path, limit) {
        ReadOutcome::Read(bytes) => {
            TextReadOutcome::Text(String::from_utf8_lossy(&bytes).into_owned())
        }
        other => text_from_read(other),
    }
}

fn text_from_read(outcome: ReadOutcome) -> TextReadOutcome {
    match outcome {
        ReadOutcome::Read(_) => unreachable!("success handled by callers"),
        ReadOutcome::StatFailed { kind } => TextReadOutcome::StatFailed { kind },
        ReadOutcome::Unreadable { kind } => TextReadOutcome::Unreadable { kind },
        ReadOutcome::Oversized { size, limit } => TextReadOutcome::Oversized { size, limit },
        ReadOutcome::NotRegular => TextReadOutcome::NotRegular,
        ReadOutcome::Symlink => TextReadOutcome::Symlink,
    }
}

/// Map a read outcome onto coverage without creating a finding.
pub fn artifact_status(outcome: &ReadOutcome) -> ArtifactStatus {
    match outcome {
        ReadOutcome::Read(_) => ArtifactStatus::Inspected,
        ReadOutcome::StatFailed { .. } => ArtifactStatus::StatFailed,
        ReadOutcome::Unreadable { .. } | ReadOutcome::NotRegular | ReadOutcome::Symlink => {
            ArtifactStatus::Unreadable
        }
        ReadOutcome::Oversized { .. } => ArtifactStatus::Oversized,
    }
}

/// Map a text-read outcome onto coverage without creating a finding.
///
/// Invalid UTF-8 is a parse failure for structural artefacts. Log-like
/// artefacts should use [`read_text_lossy_bounded`] so this variant does not arise.
pub fn text_artifact_status(outcome: &TextReadOutcome) -> ArtifactStatus {
    match outcome {
        TextReadOutcome::Text(_) => ArtifactStatus::Inspected,
        TextReadOutcome::InvalidUtf8 => ArtifactStatus::ParseFailed,
        TextReadOutcome::StatFailed { .. } => ArtifactStatus::StatFailed,
        TextReadOutcome::Unreadable { .. }
        | TextReadOutcome::NotRegular
        | TextReadOutcome::Symlink => ArtifactStatus::Unreadable,
        TextReadOutcome::Oversized { .. } => ArtifactStatus::Oversized,
    }
}

fn open_error(err: io::Error) -> ReadOutcome {
    if is_eloop(&err) {
        return ReadOutcome::Symlink;
    }
    match err.kind() {
        io::ErrorKind::NotFound => ReadOutcome::StatFailed { kind: err.kind() },
        _ => ReadOutcome::Unreadable { kind: err.kind() },
    }
}

fn is_eloop(err: &io::Error) -> bool {
    err.raw_os_error() == Some(ELOOP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::ArtifactStatus;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    struct TmpDir {
        path: PathBuf,
    }

    impl TmpDir {
        fn new() -> Self {
            let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "chaincheck-fsutil-{}-{}-{n}",
                std::process::id(),
                nanos
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn mkfifo(path: &Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            fn mkfifo(pathname: *const i8, mode: u32) -> i32;
        }
        let c = CString::new(path.as_os_str().as_bytes()).expect("fifo path");
        let rc = unsafe { mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
    }

    #[test]
    fn missing_path_is_stat_failed_and_does_not_panic() {
        let tmp = TmpDir::new();
        let outcome = read_bounded(&tmp.path().join("missing"), 1024);
        assert!(matches!(outcome, ReadOutcome::StatFailed { .. }));
        assert_eq!(artifact_status(&outcome), ArtifactStatus::StatFailed);
    }

    #[test]
    fn regular_file_within_limit_is_read() {
        let tmp = TmpDir::new();
        let file = tmp.path().join("ok.txt");
        fs::write(&file, b"hello").unwrap();
        match read_bounded(&file, 1024) {
            ReadOutcome::Read(bytes) => assert_eq!(bytes, b"hello"),
            other => panic!("unexpected {other:?}"),
        }
        match read_utf8_bounded(&file, 1024) {
            TextReadOutcome::Text(text) => assert_eq!(text, "hello"),
            other => panic!("unexpected {other:?}"),
        }
        match read_text_lossy_bounded(&file, 1024) {
            TextReadOutcome::Text(text) => assert_eq!(text, "hello"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            artifact_status(&read_bounded(&file, 1024)),
            ArtifactStatus::Inspected
        );
    }

    #[test]
    fn regular_file_over_limit_is_oversized() {
        let tmp = TmpDir::new();
        let file = tmp.path().join("big.bin");
        fs::write(&file, [0u8; 16]).unwrap();
        match read_bounded(&file, 8) {
            ReadOutcome::Oversized { size, limit } => {
                assert_eq!(size, Some(16));
                assert_eq!(limit, 8);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            artifact_status(&read_bounded(&file, 8)),
            ArtifactStatus::Oversized
        );
    }

    #[test]
    fn file_exactly_at_limit_is_read() {
        let tmp = TmpDir::new();
        let file = tmp.path().join("exact.bin");
        fs::write(&file, [1u8; 8]).unwrap();
        match read_bounded(&file, 8) {
            ReadOutcome::Read(bytes) => assert_eq!(bytes.len(), 8),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn symlink_to_regular_file_is_symlink_not_target_bytes() {
        let tmp = TmpDir::new();
        let target = tmp.path().join("target.txt");
        fs::write(&target, b"secret").unwrap();
        let link = tmp.path().join("link.txt");
        symlink(&target, &link).unwrap();
        assert_eq!(read_bounded(&link, 1024), ReadOutcome::Symlink);
        assert_eq!(
            artifact_status(&ReadOutcome::Symlink),
            ArtifactStatus::Unreadable
        );
    }

    #[test]
    fn directory_is_not_regular() {
        let tmp = TmpDir::new();
        assert_eq!(read_bounded(tmp.path(), 1024), ReadOutcome::NotRegular);
        assert_eq!(
            artifact_status(&ReadOutcome::NotRegular),
            ArtifactStatus::Unreadable
        );
    }

    #[test]
    fn fifo_is_not_regular_and_does_not_block() {
        let tmp = TmpDir::new();
        let fifo = tmp.path().join("pipe");
        mkfifo(&fifo);
        assert_eq!(read_bounded(&fifo, 1024), ReadOutcome::NotRegular);
    }

    #[test]
    fn strict_utf8_rejects_invalid_bytes_lossy_does_not() {
        let tmp = TmpDir::new();
        let file = tmp.path().join("bad.bin");
        fs::write(&file, [0xff, 0xfe, b'x']).unwrap();
        assert_eq!(read_utf8_bounded(&file, 1024), TextReadOutcome::InvalidUtf8);
        match read_text_lossy_bounded(&file, 1024) {
            TextReadOutcome::Text(text) => assert!(text.contains('x')),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn artifact_status_does_not_create_a_finding() {
        // Mapping is coverage-only; there is no Finding constructor from ReadOutcome.
        let statuses = [
            artifact_status(&ReadOutcome::StatFailed {
                kind: io::ErrorKind::NotFound,
            }),
            artifact_status(&ReadOutcome::Unreadable {
                kind: io::ErrorKind::PermissionDenied,
            }),
            artifact_status(&ReadOutcome::Oversized {
                size: Some(9),
                limit: 8,
            }),
            artifact_status(&ReadOutcome::NotRegular),
            artifact_status(&ReadOutcome::Symlink),
        ];
        assert!(statuses.iter().all(|s| *s != ArtifactStatus::Inspected));
    }

    #[test]
    fn text_artifact_status_maps_invalid_utf8_to_parse_failed() {
        assert_eq!(
            text_artifact_status(&TextReadOutcome::InvalidUtf8),
            ArtifactStatus::ParseFailed
        );
        assert_eq!(
            text_artifact_status(&TextReadOutcome::Text(String::from("ok"))),
            ArtifactStatus::Inspected
        );
        assert_eq!(
            text_artifact_status(&TextReadOutcome::Oversized {
                size: Some(9),
                limit: 8,
            }),
            ArtifactStatus::Oversized
        );
    }
}
