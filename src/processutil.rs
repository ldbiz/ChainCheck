//! Bounded, concurrently drained subprocess execution.
//!
//! Stdout is read on a dedicated thread so a child cannot deadlock on a full
//! pipe. Output is capped. This is not a generic command framework.

use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const LIMIT_GIT_STDOUT: usize = 8_000_000;
pub const LIMIT_RESOLVECTL_STDOUT: usize = 2_000_000;

const READER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum BoundedCommand {
    Completed { status: ExitStatus, stdout: Vec<u8> },
    Timeout,
    Oversized,
    SpawnFailed(io::Error),
    Io(io::Error),
}

enum ReaderMsg {
    Done(Vec<u8>),
    Oversized,
    Io(io::Error),
}

/// Result of a short availability probe. Not a command-execution framework.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolProbe {
    Present,
    Missing,
    Unsupported,
    Failed,
}

/// Classify a bounded-run result from an availability probe or tool invocation.
pub fn classify_probe(result: &BoundedCommand) -> ToolProbe {
    match result {
        BoundedCommand::Completed { status, .. } if status.success() => ToolProbe::Present,
        BoundedCommand::Completed { .. } => ToolProbe::Unsupported,
        BoundedCommand::SpawnFailed(err) if err.kind() == io::ErrorKind::NotFound => {
            ToolProbe::Missing
        }
        BoundedCommand::SpawnFailed(_)
        | BoundedCommand::Timeout
        | BoundedCommand::Oversized
        | BoundedCommand::Io(_) => ToolProbe::Failed,
    }
}

pub fn spawn_not_found(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
}

pub fn run_bounded(mut cmd: Command, timeout: Duration, max_stdout: usize) -> BoundedCommand {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return BoundedCommand::SpawnFailed(err),
    };
    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        terminate_group(&mut child, pid);
        return BoundedCommand::Io(io::Error::other("child stdout missing"));
    };

    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let _ = tx.send(read_capped(stdout, max_stdout));
    });

    let deadline = Instant::now() + timeout;
    let mut reader_msg: Option<ReaderMsg> = None;
    let mut child_status: Option<ExitStatus> = None;
    let mut oversized = false;

    loop {
        if reader_msg.is_none() {
            match rx.try_recv() {
                Ok(ReaderMsg::Oversized) => oversized = true,
                Ok(msg) => reader_msg = Some(msg),
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    reader_msg = Some(ReaderMsg::Io(io::Error::other("stdout reader dropped")));
                }
            }
        }

        if child_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => child_status = Some(status),
                Ok(None) => {}
                Err(err) => {
                    terminate_group(&mut child, pid);
                    finish_reader(reader_msg.take(), &rx, reader);
                    return BoundedCommand::Io(err);
                }
            }
        }

        if oversized {
            terminate_group(&mut child, pid);
            finish_reader(reader_msg.take(), &rx, reader);
            return BoundedCommand::Oversized;
        }

        if Instant::now() >= deadline {
            terminate_group(&mut child, pid);
            finish_reader(reader_msg.take(), &rx, reader);
            return BoundedCommand::Timeout;
        }

        if let Some(status) = child_status {
            if let Some(msg) = reader_msg.take() {
                let _ = reader.join();
                return match msg {
                    ReaderMsg::Done(stdout) => BoundedCommand::Completed { status, stdout },
                    ReaderMsg::Oversized => BoundedCommand::Oversized,
                    ReaderMsg::Io(err) => BoundedCommand::Io(err),
                };
            }
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_group(child: &mut Child, pid: u32) {
    kill_process_group(pid);
    let _ = child.kill();
    let _ = child.wait();
}

fn kill_process_group(pid: u32) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    let Ok(pgid) = i32::try_from(pid) else {
        return;
    };
    if pgid > 0 {
        unsafe {
            kill(-pgid, SIGKILL);
        }
    }
}

fn finish_reader(already: Option<ReaderMsg>, rx: &Receiver<ReaderMsg>, reader: JoinHandle<()>) {
    if already.is_some() {
        let _ = reader.join();
        return;
    }
    match rx.recv_timeout(READER_SHUTDOWN_GRACE) {
        Ok(_) => {
            let _ = reader.join();
        }
        Err(_) => {}
    }
}

fn read_capped(mut stdout: impl Read, max_stdout: usize) -> ReaderMsg {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stdout.read(&mut chunk) {
            Ok(0) => return ReaderMsg::Done(buf),
            Ok(n) => {
                if buf.len().saturating_add(n) > max_stdout {
                    return ReaderMsg::Oversized;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return ReaderMsg::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    #[test]
    fn successful_bounded_output() {
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hello");
        match run_bounded(cmd, Duration::from_secs(5), 1024) {
            BoundedCommand::Completed { status, stdout } => {
                assert!(status.success() || status.signal().is_none());
                assert!(String::from_utf8_lossy(&stdout).contains("hello"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn oversized_output_is_not_completed() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("dd if=/dev/zero bs=1024 count=50 2>/dev/null");
        match run_bounded(cmd, Duration::from_secs(5), 100) {
            BoundedCommand::Oversized => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn timeout_while_stdout_remains_live() {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        match run_bounded(cmd, Duration::from_millis(200), 1024) {
            BoundedCommand::Timeout => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn descendant_retaining_stdout_is_timeout() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("/bin/sleep 30 & printf ready\n");
        let started = Instant::now();
        match run_bounded(cmd, Duration::from_millis(200), 1024) {
            BoundedCommand::Timeout => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "run_bounded exceeded the overall deadline: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn classify_probe_distinguishes_missing_unsupported_and_failed() {
        let mut missing = Command::new("/no/such/chaincheck-tool");
        missing.arg("--version");
        assert_eq!(
            classify_probe(&run_bounded(missing, Duration::from_secs(1), 64)),
            ToolProbe::Missing
        );

        let unsupported = Command::new("/bin/false");
        assert_eq!(
            classify_probe(&run_bounded(unsupported, Duration::from_secs(1), 64)),
            ToolProbe::Unsupported
        );

        let mut timed_out = Command::new("/bin/sleep");
        timed_out.arg("30");
        assert_eq!(
            classify_probe(&run_bounded(timed_out, Duration::from_millis(200), 64)),
            ToolProbe::Failed
        );

        let mut present = Command::new("/bin/echo");
        present.arg("ok");
        assert_eq!(
            classify_probe(&run_bounded(present, Duration::from_secs(1), 64)),
            ToolProbe::Present
        );
    }
}
