//! Run a command and capture its output under a time limit and a byte cap —
//! the primitive behind every measurement that reads a guest's answer on the
//! host.
//!
//! Without limits, `wait_with_output` reads everything into memory and waits
//! forever: a guest that answers `cat` with gigabytes, or never answers,
//! drives the host into the OOM killer or hangs the caller (homeserver audit
//! 3, B83 and B112). Both end here as an error, never as a partial answer.
//! Until vantage 0.4.0 this loop lived twice, in gast-pruefung and in
//! signoff; the two copies had drifted in how they treated a stream a
//! grandchild kept open after the child had exited.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a command may run and how much it may write per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The process is killed once it has run this long.
    pub timeout: Duration,
    /// More than this many bytes on stdout or on stderr end the process;
    /// the output is discarded, nothing is kept in memory beyond the cap.
    pub max_bytes: u64,
}

impl Limits {
    pub const fn new(timeout: Duration, max_bytes: u64) -> Self {
        Limits { timeout, max_bytes }
    }
}

/// What a finished command left behind. Output is decoded lossily: the
/// caller measures text, and an invalid byte in a guest's answer is not
/// a reason to drop the whole answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// `None` when the process was killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Captured {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Why a command yielded no answer. Each variant carries what a message
/// needs, so callers can word it in their own language; `Display` gives
/// an English default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The program could not be started at all.
    Spawn(String),
    /// A stream exceeded `max_bytes`. The process was killed and the
    /// output discarded.
    TooMuchOutput { max_bytes: u64 },
    /// The process ran past `timeout` and was killed.
    TimedOut { timeout: Duration },
    /// The process ended, but a descendant kept stdout or stderr open
    /// until `timeout` ran out (`systemd-run --pipe` hands the pipes to the
    /// unit in the guest, and a process there may outlive it).
    OutputHeldOpen { timeout: Duration },
    /// Writing stdin failed for a reason other than the program closing it
    /// early (EPIPE is not an error: a program need not read all of it).
    Stdin(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Spawn(e) => write!(f, "cannot start: {e}"),
            CaptureError::TooMuchOutput { max_bytes } => write!(
                f,
                "more than {max_bytes} bytes of output — killed, output discarded"
            ),
            CaptureError::TimedOut { timeout } => {
                write!(f, "still running after {} s — killed", timeout.as_secs())
            }
            CaptureError::OutputHeldOpen { timeout } => write!(
                f,
                "exited, but the output stayed open until the limit of {} s",
                timeout.as_secs()
            ),
            CaptureError::Stdin(e) => write!(f, "stdin: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Runs `cmd`, feeds it `stdin` (or `/dev/null`), and returns its exit code
/// and both streams — or why that did not happen.
///
/// Both streams are read in their own threads, each with the cap: a full
/// stderr must not block stdout. When a reader reaches the cap it stops
/// reading and sets a flag; the loop below kills the child immediately
/// instead of letting it wait on a full pipe until the timeout. stdin is
/// written in a thread as well — a program that does not read would
/// otherwise hang `write_all` on a full pipe, before any timeout.
pub fn run(
    cmd: &mut Command,
    stdin: Option<&[u8]>,
    limits: Limits,
) -> Result<Captured, CaptureError> {
    let Limits { timeout, max_bytes } = limits;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd
        .spawn()
        .map_err(|e| CaptureError::Spawn(e.to_string()))?;
    let too_much = Arc::new(AtomicBool::new(false));
    let reader = |r: Option<Box<dyn Read + Send>>| {
        let too_much = too_much.clone();
        std::thread::spawn(move || -> Vec<u8> {
            let Some(mut r) = r else {
                return Vec::new();
            };
            let mut v = Vec::new();
            let _ = (&mut r).take(max_bytes + 1).read_to_end(&mut v);
            if v.len() as u64 > max_bytes {
                v.truncate(max_bytes as usize);
                too_much.store(true, Ordering::SeqCst);
            }
            v
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|r| Box::new(r) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|r| Box::new(r) as Box<dyn Read + Send>),
    );
    let writer = stdin.map(|bytes| {
        let mut pipe = child.stdin.take().expect("stdin was requested");
        let bytes = bytes.to_vec();
        std::thread::spawn(move || pipe.write_all(&bytes))
    });
    let deadline = Instant::now() + timeout;
    let kill = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let status = loop {
        if too_much.load(Ordering::SeqCst) {
            kill(&mut child);
            return Err(CaptureError::TooMuchOutput { max_bytes });
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                kill(&mut child);
                return Err(CaptureError::TimedOut { timeout });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                kill(&mut child);
                return Err(CaptureError::Spawn(e.to_string()));
            }
        }
    };
    // (No let chain: the crate is edition 2021.)
    if let Some(Ok(Err(e))) = writer.map(|w| w.join()) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(CaptureError::Stdin(e.to_string()));
        }
    }
    // The pipes can outlive the child; wait for them, but only until the
    // deadline.
    while !(out.is_finished() && err.is_finished()) {
        if Instant::now() >= deadline {
            return Err(CaptureError::OutputHeldOpen { timeout });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    if too_much.load(Ordering::SeqCst) {
        return Err(CaptureError::TooMuchOutput { max_bytes });
    }
    Ok(Captured {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    fn limits(ms: u64, max_bytes: u64) -> Limits {
        Limits::new(Duration::from_millis(ms), max_bytes)
    }

    /// B83: a flood is killed and discarded — not read to the end, not
    /// kept in memory.
    #[test]
    fn a_flood_is_killed_not_read() {
        let t0 = Instant::now();
        let e = run(&mut sh("yes flood"), None, limits(30_000, 1 << 20));
        assert_eq!(e, Err(CaptureError::TooMuchOutput { max_bytes: 1 << 20 }));
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    }

    /// B83: a program that never ends, ends at the deadline.
    #[test]
    fn a_hang_ends_at_the_deadline() {
        let t0 = Instant::now();
        let e = run(&mut sh("sleep 30"), None, limits(300, 1 << 20));
        assert!(matches!(e, Err(CaptureError::TimedOut { .. })), "{e:?}");
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    /// A program that does not read stdin does not hang the writer.
    #[test]
    fn a_program_that_ignores_stdin_does_not_block() {
        let big = vec![b'x'; 1 << 20];
        let t0 = Instant::now();
        let e = run(&mut sh("sleep 30"), Some(&big), limits(300, 1 << 20));
        assert!(e.is_err());
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    /// A grandchild keeps stdout open after the child exited.
    #[test]
    fn an_output_held_open_ends_at_the_deadline() {
        let t0 = Instant::now();
        let e = run(&mut sh("sleep 30 & exit 0"), None, limits(500, 1 << 20));
        assert!(
            matches!(e, Err(CaptureError::OutputHeldOpen { .. })),
            "{e:?}"
        );
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    /// A program that stops reading stdin early is not an error (EPIPE).
    #[test]
    fn early_close_of_stdin_is_not_an_error() {
        let big = vec![b'x'; 1 << 20];
        let e = run(
            &mut sh("head -c 1 >/dev/null; exit 0"),
            Some(&big),
            limits(10_000, 1 << 20),
        )
        .unwrap();
        assert_eq!(e.code, Some(0));
    }

    #[test]
    fn the_usual_case_arrives_whole() {
        let e = run(
            &mut sh("cat; echo failure >&2; exit 3"),
            Some(b"hello\n"),
            limits(10_000, 1 << 20),
        )
        .unwrap();
        assert_eq!(
            (e.code, e.stdout.as_str(), e.stderr.as_str()),
            (Some(3), "hello\n", "failure\n")
        );
        assert!(!e.success());
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let e = run(
            &mut Command::new("/nonexistent/program"),
            None,
            limits(1000, 1 << 20),
        );
        assert!(matches!(e, Err(CaptureError::Spawn(_))), "{e:?}");
    }

    #[test]
    fn errors_say_what_happened_in_english() {
        let s = CaptureError::TooMuchOutput { max_bytes: 7 }.to_string();
        assert!(s.contains("7 bytes"), "{s}");
        let s = CaptureError::TimedOut {
            timeout: Duration::from_secs(9),
        }
        .to_string();
        assert!(s.contains("9 s"), "{s}");
    }
}
