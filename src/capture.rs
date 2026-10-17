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
//!
//! EVERY THREAD ENDS AT THE DEADLINE (0.4.1). Killing the child closes
//! nothing on the far side of a pipe: with `systemd-run --pipe` the write
//! ends belong to the unit in the guest, and a reader blocked in `read(2)`
//! on such a pipe would sit there as long as the guest pleases — a leaked
//! thread and an open descriptor per aborted command. The readers and the
//! stdin writer therefore `poll(2)` with the time that is left, and `run`
//! joins all of them before it returns, on the error paths too. What the
//! guest's own unit does after the deadline is the guest's business; a
//! `GuestCommand` sets `RuntimeMaxSec=` to the same limit so the guest's
//! systemd ends it as well.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
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

/// Milliseconds left until `deadline`, for `poll(2)`, rounded UP; `None`
/// once it has passed.
fn left_ms(deadline: Instant) -> Option<libc::c_int> {
    let left = deadline.checked_duration_since(Instant::now())?;
    let ms = left.as_micros().div_ceil(1000);
    Some(ms.clamp(1, libc::c_int::MAX as u128) as libc::c_int)
}

/// Waits until `fd` is ready for `events` or the deadline passes. `true`
/// means ready (or hung up — a read then returns 0, a write EPIPE); `false`
/// is returned ONLY once `Instant::now() >= deadline`. A `poll` that times
/// out early (its argument is whole milliseconds) loops: in 0.4.1 it
/// returned `false` up to a millisecond before the deadline, and `run`
/// then took a stream a grandchild still held for a closed one — seen as
/// a flaky test in the Nix sandbox, a wrong `Ok` in production.
#[allow(unsafe_code)]
fn ready(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> bool {
    loop {
        let Some(ms) = left_ms(deadline) else {
            return false;
        };
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: `p` is a valid, initialised pollfd that lives for the
        // call; nfds is 1; poll writes only into `p.revents`.
        let rc = unsafe { libc::poll(&mut p, 1, ms) };
        if rc > 0 {
            return true;
        }
        if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            // EBADF, EINVAL: nothing more to wait for; let read/write report.
            return true;
        }
        // rc == 0 (timed out) or EINTR: back to the clock.
    }
}

/// Reads `r` until EOF, the cap plus one byte, or the deadline — whichever
/// comes first — and drops it, closing the host's end of the pipe.
fn read_until<R: Read + AsRawFd>(
    mut r: R,
    max_bytes: u64,
    deadline: Instant,
    too_much: Arc<AtomicBool>,
) -> Vec<u8> {
    let fd = r.as_raw_fd();
    let mut v = Vec::new();
    let mut buf = [0u8; 16 << 10];
    while (v.len() as u64) <= max_bytes {
        if !ready(fd, libc::POLLIN, deadline) {
            break;
        }
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => v.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if v.len() as u64 > max_bytes {
        v.truncate(max_bytes as usize);
        too_much.store(true, Ordering::SeqCst);
    }
    v
}

/// `read_until` in its own thread; `None` (no pipe) yields nothing.
fn spawn_reader<R: Read + AsRawFd + Send + 'static>(
    r: Option<R>,
    max_bytes: u64,
    deadline: Instant,
    too_much: Arc<AtomicBool>,
) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || match r {
        Some(r) => read_until(r, max_bytes, deadline, too_much),
        None => Vec::new(),
    })
}

/// Writes `bytes` to `w` until done, EPIPE, or the deadline, then drops it.
fn write_until<W: Write + AsRawFd>(
    mut w: W,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), std::io::Error> {
    let fd = w.as_raw_fd();
    let mut done = 0;
    while done < bytes.len() {
        if !ready(fd, libc::POLLOUT, deadline) {
            return Ok(()); // the deadline, reported by the caller's wait
        }
        // At most PIPE_BUF per write: POLLOUT promises that much room, and
        // a blocking write of MORE than fits blocks until all of it went
        // through — with a reader that never reads, until the far side
        // closes (measured: 30 s against `sleep 30`, the deadline ignored).
        let chunk = bytes.len().min(done + libc::PIPE_BUF);
        match w.write(&bytes[done..chunk]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Runs `cmd`, feeds it `stdin` (or `/dev/null`), and returns its exit code
/// and both streams — or why that did not happen.
///
/// Both streams are read in their own threads, each with the cap: a full
/// stderr must not block stdout. When a reader reaches the cap it stops
/// reading and sets a flag; the loop below kills the child immediately
/// instead of letting it wait on a full pipe until the timeout. stdin is
/// written in a thread as well — a program that does not read would
/// otherwise hang `write_all` on a full pipe, before any timeout. Every
/// thread stops at the deadline and is joined before `run` returns.
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
    let deadline = Instant::now() + timeout;
    let too_much = Arc::new(AtomicBool::new(false));
    let out = spawn_reader(child.stdout.take(), max_bytes, deadline, too_much.clone());
    let err = spawn_reader(child.stderr.take(), max_bytes, deadline, too_much.clone());
    let writer = stdin.map(|bytes| {
        let pipe = child.stdin.take().expect("stdin was requested");
        let bytes = bytes.to_vec();
        std::thread::spawn(move || write_until(pipe, &bytes, deadline))
    });
    // Joins every thread; each ends by the deadline at the latest, so this
    // cannot hang longer than the limit the caller chose.
    let finish = |out: JoinHandle<Vec<u8>>,
                  err: JoinHandle<Vec<u8>>,
                  writer: Option<JoinHandle<Result<(), std::io::Error>>>| {
        let o = out.join().unwrap_or_default();
        let e = err.join().unwrap_or_default();
        let w = writer.map(|w| w.join().unwrap_or(Ok(())));
        (o, e, w)
    };
    let kill = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let status = loop {
        if too_much.load(Ordering::SeqCst) {
            kill(&mut child);
            finish(out, err, writer);
            return Err(CaptureError::TooMuchOutput { max_bytes });
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                kill(&mut child);
                finish(out, err, writer);
                return Err(CaptureError::TimedOut { timeout });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                kill(&mut child);
                finish(out, err, writer);
                return Err(CaptureError::Spawn(e.to_string()));
            }
        }
    };
    // The child is gone. Its pipes can outlive it (a grandchild, the unit
    // behind `systemd-run --pipe`): the readers stop at the deadline either
    // way, and a reader that had to is the finding.
    let (stdout, stderr, written) = finish(out, err, writer);
    if Instant::now() >= deadline {
        return Err(CaptureError::OutputHeldOpen { timeout });
    }
    if too_much.load(Ordering::SeqCst) {
        return Err(CaptureError::TooMuchOutput { max_bytes });
    }
    // (No let chain: the crate is edition 2021.)
    if let Some(Err(e)) = written {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(CaptureError::Stdin(e.to_string()));
        }
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
        assert!(matches!(e, Err(CaptureError::TimedOut { .. })), "{e:?}");
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    /// A grandchild keeps stdout open after the child exited. The run ends
    /// at the deadline — and `run` has JOINED both readers by then: the
    /// time bound below (well under the grandchild's 30 s) is only possible
    /// if the readers returned, and a reader that returns drops its `File`
    /// and so closes the host's end of the pipe although the grandchild
    /// still holds the far side (review finding of 2026-10-17: readers
    /// blocked in read(2) outlived the command as detached threads).
    #[test]
    fn an_output_held_open_ends_at_the_deadline_with_readers_joined() {
        let t0 = Instant::now();
        let e = run(&mut sh("sleep 30 & exit 0"), None, limits(500, 1 << 20));
        assert!(
            matches!(e, Err(CaptureError::OutputHeldOpen { .. })),
            "{e:?}"
        );
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }

    /// The same, for a grandchild that holds stdin's read end: the writer
    /// stops at the deadline instead of blocking on a full pipe forever.
    #[test]
    fn a_writer_to_a_held_open_stdin_ends_at_the_deadline() {
        let big = vec![b'x'; 4 << 20];
        let t0 = Instant::now();
        let e = run(
            &mut sh("sleep 30 <&0 & exit 0"),
            Some(&big),
            limits(500, 1 << 20),
        );
        assert!(
            matches!(e, Err(CaptureError::OutputHeldOpen { .. })),
            "{e:?}"
        );
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }

    /// The invariant the readers rely on: `ready` says `false` only once
    /// the deadline has passed by `Instant` — never a millisecond early.
    #[test]
    fn ready_is_false_only_after_the_deadline() {
        // A pipe nobody writes to: poll can only time out.
        let mut c = sh("sleep 5");
        c.stdout(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let fd = child.stdout.as_ref().unwrap().as_raw_fd();
        for us in [1_500u64, 2_300, 100, 0] {
            let deadline = Instant::now() + Duration::from_micros(us);
            assert!(!ready(fd, libc::POLLIN, deadline));
            assert!(Instant::now() >= deadline, "{us} us");
        }
        let _ = child.kill();
        let _ = child.wait();
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

    /// Exactly the cap is still an answer; one byte more is not.
    #[test]
    fn the_cap_is_inclusive() {
        let e = run(
            &mut sh("head -c 1024 /dev/zero"),
            None,
            limits(10_000, 1024),
        )
        .unwrap();
        assert_eq!(e.stdout.len(), 1024);
        let e = run(
            &mut sh("head -c 1025 /dev/zero"),
            None,
            limits(10_000, 1024),
        );
        assert_eq!(e, Err(CaptureError::TooMuchOutput { max_bytes: 1024 }));
        // stderr counts the same way.
        let e = run(
            &mut sh("head -c 5000 /dev/zero >&2"),
            None,
            limits(10_000, 1024),
        );
        assert_eq!(e, Err(CaptureError::TooMuchOutput { max_bytes: 1024 }));
    }

    /// Big stdin that IS read goes through whole (gast-pruefung measured
    /// 140 000 bytes through systemd-run --pipe; here 4 MiB through cat).
    #[test]
    fn big_stdin_is_written_whole() {
        let big = vec![b'y'; 4 << 20];
        let e = run(&mut sh("cat | wc -c"), Some(&big), limits(10_000, 1 << 20)).unwrap();
        assert_eq!(e.stdout.trim(), (4 << 20).to_string());
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
