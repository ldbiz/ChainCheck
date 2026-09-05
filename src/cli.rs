//! CLI contract: optional ROOT, `--self-test`, usage exit 64.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{StartError, UsageError};
use crate::scan::ScanScope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invocation {
    Scan {
        scope: ScanScope,
        config: ProcessConfig,
    },
    SelfTest,
}

/// Parsed argv before HOME is required for a default whole-user scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCli {
    Help,
    SelfTest,
    Scan {
        root: Option<PathBuf>,
        config: ProcessConfig,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProcessConfig {
    pub report_dir: Option<PathBuf>,
    pub no_progress: bool,
    pub npm_config_cache: Option<PathBuf>,
    pub npm_config_prefix: Option<PathBuf>,
    pub pipx_home: Option<PathBuf>,
    pub pipx_global_home: Option<PathBuf>,
    pub uv_tool_dir: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_cache_home: Option<PathBuf>,
    pub pip_cache_dir: Option<PathBuf>,
    pub poetry_cache_dir: Option<PathBuf>,
    pub poetry_virtualenvs_path: Option<PathBuf>,
}

impl ProcessConfig {
    pub fn from_env() -> Self {
        Self::from_env_iter(env::vars_os())
    }

    pub fn from_env_iter(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        let mut config = Self::default();
        for (key, value) in vars {
            if key == "CHAINCHECK_REPORT_DIR" && !value.is_empty() {
                config.report_dir = Some(PathBuf::from(value));
            } else if key == "CHAINCHECK_NO_PROGRESS" && value == "1" {
                config.no_progress = true;
            } else if key == "npm_config_cache" && !value.is_empty() {
                config.npm_config_cache = Some(PathBuf::from(value));
            } else if key == "npm_config_prefix" && !value.is_empty() {
                config.npm_config_prefix = Some(PathBuf::from(value));
            } else if key == "PIPX_HOME" && !value.is_empty() {
                config.pipx_home = Some(PathBuf::from(value));
            } else if key == "PIPX_GLOBAL_HOME" && !value.is_empty() {
                config.pipx_global_home = Some(PathBuf::from(value));
            } else if key == "UV_TOOL_DIR" && !value.is_empty() {
                config.uv_tool_dir = Some(PathBuf::from(value));
            } else if key == "XDG_DATA_HOME" && !value.is_empty() {
                config.xdg_data_home = Some(PathBuf::from(value));
            } else if key == "XDG_CACHE_HOME" && !value.is_empty() {
                config.xdg_cache_home = Some(PathBuf::from(value));
            } else if key == "PIP_CACHE_DIR" && !value.is_empty() {
                config.pip_cache_dir = Some(PathBuf::from(value));
            } else if key == "POETRY_CACHE_DIR" && !value.is_empty() {
                config.poetry_cache_dir = Some(PathBuf::from(value));
            } else if key == "POETRY_VIRTUALENVS_PATH" && !value.is_empty() {
                config.poetry_virtualenvs_path = Some(PathBuf::from(value));
            }
        }
        config
    }
}

/// Parse argv. Does not consult HOME.
pub fn parse_args(argv: &[OsString], config: ProcessConfig) -> Result<ParsedCli, UsageError> {
    let mut self_test = false;
    let mut root: Option<PathBuf> = None;
    let mut end_of_options = false;

    for arg in argv {
        if !end_of_options {
            if arg == "--" {
                end_of_options = true;
                continue;
            }
            if arg == "--help" || arg == "-h" {
                return Ok(ParsedCli::Help);
            }
            if arg == "--self-test" {
                self_test = true;
                continue;
            }
            if is_option(arg) {
                return Err(UsageError::Unrecognized(arg_to_string(arg)));
            }
        }
        if root.is_some() {
            return Err(UsageError::ExtraOperand(arg_to_string(arg)));
        }
        root = Some(PathBuf::from(arg));
    }

    if self_test && root.is_some() {
        return Err(UsageError::RootWithSelfTest);
    }
    if self_test {
        return Ok(ParsedCli::SelfTest);
    }

    Ok(ParsedCli::Scan { root, config })
}

/// Expand `~` and `~/…` using `home`. Other paths, including `~user`, are unchanged.
pub fn expand_user_path(path: &Path, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if text == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return home.join(rest);
    }
    path.to_path_buf()
}

/// UTC `YYYYMMDDTHHMMSSZ` from Unix seconds. Used for default report directories.
pub fn utc_stamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_stamp_from_unix(secs)
}

fn utc_stamp_from_unix(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let tod = unix_secs % 86_400;
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Howard Hinnant `civil_from_days`. `z` is days since Unix epoch.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    (y as i32, m as u32, d as u32)
}

pub fn resolve_report_dir(
    config: &ProcessConfig,
    home: Option<&Path>,
    now: SystemTime,
) -> Result<PathBuf, StartError> {
    if let Some(path) = &config.report_dir {
        return Ok(expand_user_path(path, home));
    }
    let home = home.ok_or(StartError::HomeUnavailable)?;
    Ok(home.join(format!("chaincheck-{}", utc_stamp(now))))
}

pub fn ensure_report_dir(path: &Path) -> Result<(), StartError> {
    fs::create_dir_all(path).map_err(|_| StartError::ReportDirUncreatable {
        path: path.to_path_buf(),
    })
}

/// Resolve scan scope. HOME is required only for a default whole-user scan.
/// Explicit ROOT is `~`-expanded then must be an existing directory.
pub fn resolve_scan_scope(
    root: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<ScanScope, StartError> {
    match root {
        Some(root) => {
            let expanded = expand_user_path(&root, home.as_deref());
            if !expanded.is_dir() {
                return Err(StartError::RootMissing { root: expanded });
            }
            Ok(ScanScope::ExplicitRoot { root: expanded })
        }
        None => Ok(ScanScope::WholeUser {
            home: home.ok_or(StartError::HomeUnavailable)?,
        }),
    }
}

pub fn resolve_invocation(
    parsed: ParsedCli,
    home: Option<PathBuf>,
) -> Result<Invocation, StartError> {
    match parsed {
        ParsedCli::SelfTest => Ok(Invocation::SelfTest),
        ParsedCli::Scan { root, config } => Ok(Invocation::Scan {
            scope: resolve_scan_scope(root, home)?,
            config,
        }),
        ParsedCli::Help => {
            unreachable!("help is handled before invocation resolution")
        }
    }
}

fn is_option(arg: &OsString) -> bool {
    let Some(text) = arg.to_str() else {
        return false;
    };
    text.starts_with('-') && text != "-"
}

fn arg_to_string(arg: &OsString) -> String {
    arg.to_string_lossy().into_owned()
}

pub fn help_text() -> &'static str {
    "\
ChainCheck is a read-only Linux/WSL scanner for retrospective evidence
of known malicious software supply-chain activity.

Usage:
  chaincheck [ROOT]
  chaincheck --self-test

Targeting ROOT limits the filesystem walk to that directory; host-level
checks still run independently. ROOT cannot be combined with --self-test.

Environment:
  CHAINCHECK_REPORT_DIR  Report directory (default: $HOME/chaincheck-<UTC timestamp>).
  CHAINCHECK_NO_PROGRESS Set to 1 to disable the terminal scan progress bar.

Exit codes: 0=no MEDIUM/HIGH/CONFIRMED evidence; 1=MEDIUM; 2=HIGH/CONFIRMED;
3=could not start; 4=otherwise-clean scan with unavailable required intelligence;
64=unrecognised option.
"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn parse(args: &[&str]) -> Result<ParsedCli, UsageError> {
        parse_args(&os(args), ProcessConfig::default())
    }

    #[test]
    fn no_root_with_home_is_whole_user() {
        let parsed = parse(&[]).unwrap();
        match parsed {
            ParsedCli::Scan { root: None, .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        let invocation = resolve_invocation(parsed, Some(PathBuf::from("/home/user"))).unwrap();
        match invocation {
            Invocation::Scan {
                scope: ScanScope::WholeUser { home },
                ..
            } => assert_eq!(home, PathBuf::from("/home/user")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn no_root_without_home_is_start_failure_3() {
        let parsed = parse(&[]).unwrap();
        let err = resolve_invocation(parsed, None).unwrap_err();
        assert_eq!(err, StartError::HomeUnavailable);
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn explicit_root_without_home_is_valid() {
        let dir = std::env::temp_dir().join(format!(
            "chaincheck-cli-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let parsed = parse(&[dir.to_str().unwrap()]).unwrap();
        let invocation = resolve_invocation(parsed, None).unwrap();
        match invocation {
            Invocation::Scan {
                scope: ScanScope::ExplicitRoot { root },
                ..
            } => assert_eq!(root, dir),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_root_is_start_failure_3() {
        // Oracle: cli-nonexistent-root-exit-3
        let parsed = parse(&["/chaincheck-oracle-nonexistent-root-9f3c2a"]).unwrap();
        let err = resolve_invocation(parsed, None).unwrap_err();
        assert_eq!(
            err,
            StartError::RootMissing {
                root: PathBuf::from("/chaincheck-oracle-nonexistent-root-9f3c2a")
            }
        );
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn tilde_root_expands_before_validation() {
        let base = std::env::temp_dir().join(format!(
            "chaincheck-cli-tilde-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let home = base.join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let parsed = parse(&["~/project"]).unwrap();
        let invocation = resolve_invocation(parsed, Some(home.clone())).unwrap();
        match invocation {
            Invocation::Scan {
                scope: ScanScope::ExplicitRoot { root },
                ..
            } => assert_eq!(root, project),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn utc_stamp_epoch_leap_and_year_boundary() {
        assert_eq!(utc_stamp_from_unix(0), "19700101T000000Z");
        assert_eq!(utc_stamp_from_unix(1_709_164_800), "20240229T000000Z");
        assert_eq!(utc_stamp_from_unix(1_735_689_599), "20241231T235959Z");
        assert_eq!(utc_stamp_from_unix(1_735_689_600), "20250101T000000Z");
    }

    #[test]
    fn default_report_dir_uses_home_and_utc_stamp() {
        let home = PathBuf::from("/home/user");
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_709_164_800);
        let path = resolve_report_dir(&ProcessConfig::default(), Some(&home), now).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/chaincheck-20240229T000000Z")
        );
        let err = resolve_report_dir(&ProcessConfig::default(), None, now).unwrap_err();
        assert_eq!(err, StartError::HomeUnavailable);
    }

    #[test]
    fn report_dir_env_expands_tilde() {
        let home = PathBuf::from("/home/user");
        let config = ProcessConfig {
            report_dir: Some(PathBuf::from("~/reports")),
            ..ProcessConfig::default()
        };
        let path = resolve_report_dir(&config, Some(&home), UNIX_EPOCH).unwrap();
        assert_eq!(path, PathBuf::from("/home/user/reports"));
    }

    #[test]
    fn one_root_is_explicit() {
        match parse(&["/tmp/project"]).unwrap() {
            ParsedCli::Scan {
                root: Some(root), ..
            } => assert_eq!(root, PathBuf::from("/tmp/project")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn self_test_flag() {
        match parse(&["--self-test"]).unwrap() {
            ParsedCli::SelfTest => {}
            other => panic!("unexpected {other:?}"),
        }
        let invocation = resolve_invocation(ParsedCli::SelfTest, None).unwrap();
        assert_eq!(invocation, Invocation::SelfTest);
    }

    #[test]
    fn root_plus_self_test_is_usage_64() {
        // Oracle: cli-root-plus-self-test-exit-64
        let err = parse(&[".", "--self-test"]).unwrap_err();
        assert_eq!(err, UsageError::RootWithSelfTest);
        assert_eq!(err.exit_code(), 64);
        let err = parse(&["--self-test", "/tmp/root"]).unwrap_err();
        assert_eq!(err, UsageError::RootWithSelfTest);
    }

    #[test]
    fn unknown_option_is_usage_64() {
        // Oracle: cli-unknown-option-exit-64
        let err = parse(&["--chaincheck-oracle-not-an-option"]).unwrap_err();
        assert!(matches!(err, UsageError::Unrecognized(_)));
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn extra_positional_is_usage_64() {
        let err = parse(&["/a", "/b"]).unwrap_err();
        assert!(matches!(err, UsageError::ExtraOperand(_)));
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn help_does_not_require_home() {
        assert!(matches!(parse(&["--help"]).unwrap(), ParsedCli::Help));
        assert!(matches!(parse(&["-h"]).unwrap(), ParsedCli::Help));
    }

    #[test]
    fn process_config_from_env() {
        let config = ProcessConfig::from_env_iter([
            (
                OsString::from("CHAINCHECK_REPORT_DIR"),
                OsString::from("/tmp/reports"),
            ),
            (
                OsString::from("CHAINCHECK_NO_PROGRESS"),
                OsString::from("1"),
            ),
            (
                OsString::from("npm_config_cache"),
                OsString::from("/tmp/npm-cache"),
            ),
            (
                OsString::from("npm_config_prefix"),
                OsString::from("/tmp/npm-prefix"),
            ),
            (OsString::from("PIPX_HOME"), OsString::from("/tmp/pipx")),
            (
                OsString::from("PIPX_GLOBAL_HOME"),
                OsString::from("/opt/custom-pipx"),
            ),
            (
                OsString::from("UV_TOOL_DIR"),
                OsString::from("/tmp/uv-tools"),
            ),
            (OsString::from("XDG_DATA_HOME"), OsString::from("/tmp/xdg")),
            (
                OsString::from("XDG_CACHE_HOME"),
                OsString::from("/tmp/xdg-cache"),
            ),
            (
                OsString::from("PIP_CACHE_DIR"),
                OsString::from("/tmp/pip-cache"),
            ),
            (
                OsString::from("POETRY_CACHE_DIR"),
                OsString::from("/tmp/poetry-cache"),
            ),
            (
                OsString::from("POETRY_VIRTUALENVS_PATH"),
                OsString::from("/tmp/poetry-venvs"),
            ),
        ]);
        assert_eq!(
            config.report_dir.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/reports"))
        );
        assert!(config.no_progress);
        assert_eq!(
            config.npm_config_cache.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/npm-cache"))
        );
        assert_eq!(
            config.npm_config_prefix.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/npm-prefix"))
        );
        assert_eq!(
            config.pipx_home.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/pipx"))
        );
        assert_eq!(
            config.pipx_global_home.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/opt/custom-pipx"))
        );
        assert_eq!(
            config.uv_tool_dir.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/uv-tools"))
        );
        assert_eq!(
            config.xdg_data_home.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/xdg"))
        );
        assert_eq!(
            config.xdg_cache_home.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/xdg-cache"))
        );
        assert_eq!(
            config.pip_cache_dir.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/pip-cache"))
        );
        assert_eq!(
            config.poetry_cache_dir.as_deref().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/poetry-cache"))
        );
        assert_eq!(
            config
                .poetry_virtualenvs_path
                .as_deref()
                .map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/tmp/poetry-venvs"))
        );
    }

    #[test]
    fn no_progress_requires_one() {
        let config = ProcessConfig::from_env_iter([(
            OsString::from("CHAINCHECK_NO_PROGRESS"),
            OsString::from("true"),
        )]);
        assert!(!config.no_progress);
    }
}
