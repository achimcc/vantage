//! `vantage run` into a guest via systemd-run. The three switches are not
//! options: without --wait the output is empty, without --collect a failure
//! stays behind as a red unit in the guest, and systemd-run --machine= does
//! not search PATH (203/EXEC).

use crate::cli::RunArgs;
use crate::curl_guard;
use crate::host::PROFILE;

pub fn resolve_program(p: &str) -> String {
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("{PROFILE}/{p}")
    }
}

pub fn systemd_run_argv(guest: &str, program: &str, args: &[String]) -> Vec<String> {
    systemd_run_argv_with(guest, &[], program, args)
}

/// Like `systemd_run_argv`, with unit properties (`-p Name=value`) placed
/// before `--`. `RuntimeMaxSec=`, `User=`, `LoadCredential=` go here; the
/// three switches stay, whatever the caller adds.
pub fn systemd_run_argv_with(
    guest: &str,
    properties: &[String],
    program: &str,
    args: &[String],
) -> Vec<String> {
    let mut v: Vec<String> = [
        &format!("--machine={guest}"),
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for p in properties {
        v.push("-p".to_string());
        v.push(p.clone());
    }
    v.push("--".to_string());
    v.push(program.to_string());
    v.extend(args.iter().cloned());
    v
}

/// Why a guest command yielded no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    /// systemd-run answered 203/EXEC: the program is not in the guest's
    /// profile (or not executable — systemd does not tell them apart).
    NotInProfile { guest: String, program: String },
    /// The host side failed: spawn, timeout, output cap.
    Capture(crate::capture::CaptureError),
}

impl std::fmt::Display for GuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestError::NotInProfile { guest, program } => {
                write!(f, "{program} is not in the profile of {guest} (203/EXEC)")
            }
            GuestError::Capture(e) => write!(f, "systemd-run: {e}"),
        }
    }
}

impl std::error::Error for GuestError {}

impl From<crate::capture::CaptureError> for GuestError {
    fn from(e: crate::capture::CaptureError) -> Self {
        GuestError::Capture(e)
    }
}

/// A command in a guest, run from the host with its output captured — the
/// library form of `vantage run` for tools that read the answer instead of
/// showing it (gast-pruefung, signoff). The program is resolved like on the
/// command line: an absolute path as given, anything else in the guest's
/// system profile. stdin is `/dev/null` unless the caller passes bytes
/// (a curlrc, a JSON-RPC request) — never the operator's terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommand {
    pub guest: String,
    pub program: String,
    pub args: Vec<String>,
    pub properties: Vec<String>,
}

impl GuestCommand {
    pub fn new(guest: &str, program: &str) -> Self {
        GuestCommand {
            guest: guest.to_string(),
            program: resolve_program(program),
            args: Vec::new(),
            properties: Vec::new(),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// A property of the transient unit (`-p Name=value`).
    pub fn property(mut self, p: impl Into<String>) -> Self {
        self.properties.push(p.into());
        self
    }

    /// The argv for `systemd-run`, three switches included.
    pub fn argv(&self) -> Vec<String> {
        systemd_run_argv_with(&self.guest, &self.properties, &self.program, &self.args)
    }

    /// Runs it and captures the answer under `limits`. 203/EXEC becomes
    /// `GuestError::NotInProfile`; every other exit code is the program's
    /// and comes back in `Captured`.
    pub fn capture(
        &self,
        stdin: Option<&[u8]>,
        limits: crate::capture::Limits,
    ) -> Result<crate::capture::Captured, GuestError> {
        let mut cmd = std::process::Command::new(format!("{PROFILE}/systemd-run"));
        cmd.args(self.argv());
        let out = crate::capture::run(&mut cmd, stdin, limits)?;
        if out.code == Some(203) {
            return Err(GuestError::NotInProfile {
                guest: self.guest.clone(),
                program: self.program.clone(),
            });
        }
        Ok(out)
    }
}

pub fn exec_args(self_exe: &str, r: &RunArgs) -> (String, Vec<String>) {
    let mut a = vec!["__exec".to_string()];
    for (n, p) in &r.header_files {
        a.push("--header-file".into());
        a.push(format!("{n}={p}"));
    }
    for h in &r.headers {
        a.push("--header".into());
        a.push(h.clone());
    }
    a.push("--".into());
    a.push(resolve_program(&r.program));
    a.extend(r.args.iter().cloned());
    (self_exe.to_string(), a)
}

pub fn validate(r: &RunArgs) -> Result<(), String> {
    let wants_headers = !r.header_files.is_empty() || !r.headers.is_empty();
    if wants_headers && !curl_guard::is_curl(&r.program) {
        return Err(format!(
            "--header/--header-file only work with curl, not {}",
            r.program
        ));
    }
    if curl_guard::is_curl(&r.program) {
        curl_guard::check(&r.args)?;
        if !r.header_files.is_empty() {
            curl_guard::check_no_echo(&r.args)?;
        }
    }
    Ok(())
}

/// vantage re-enters the guest through its own store path, which the guest
/// shares with the host (spike 2026-09-21, point 1).
pub fn self_exe() -> Result<String, String> {
    let p = std::env::current_exe().map_err(|e| format!("cannot find my own binary: {e}"))?;
    let s = p.to_string_lossy().into_owned();
    if !s.starts_with("/nix/store/") {
        return Err(format!(
            "vantage must run from /nix/store to re-enter a guest (runs from {s})"
        ));
    }
    Ok(s)
}

/// systemd-run's 203/EXEC, translated. systemd reports ENOENT and EACCES
/// alike as 203, so for the program itself this is always 127. If the
/// program was vantage re-entering itself (`reexec`), the guest cannot see
/// vantage's store path — a tool error, not a missing program.
pub fn exec_203(guest: &str, program: &str, reexec: bool) -> (i32, String) {
    if reexec {
        return (
            crate::app::EXIT_TOOL,
            format!(
                "vantage: vantage's store path is not visible in {guest} (store not shared?) \
                 — {program} (203/EXEC)"
            ),
        );
    }
    let name = program.rsplit('/').next().unwrap_or(program);
    (
        127,
        format!("vantage: `{name}` is not in the profile of {guest} (203/EXEC) — {program}"),
    )
}

/// Runs with inherited stdout/stderr; returns the program's exit code.
/// `reexec`: `program` is vantage itself (`__exec`), not the user's program.
///
/// stdin is `/dev/null` here as well (audit 4, B217): `systemd-run --pipe`
/// would hand the caller's stdin to the guest program, and a transient unit
/// without `--pty` already gets null — this makes it explicit on both paths,
/// so a guest program can never read the operator's terminal or the pipe of
/// a tool call.
pub fn run_in_guest(guest: &str, program: &str, args: &[String], reexec: bool) -> i32 {
    let st = std::process::Command::new(format!("{PROFILE}/systemd-run"))
        .args(systemd_run_argv(guest, program, args))
        .stdin(std::process::Stdio::null())
        .status();
    match st {
        Ok(s) => match s.code() {
            Some(203) => {
                let (code, msg) = exec_203(guest, program, reexec);
                eprintln!("{msg}");
                code
            }
            Some(c) => c,
            None => crate::app::EXIT_TOOL,
        },
        Err(e) => {
            eprintln!("vantage: systemd-run: {e}");
            crate::app::EXIT_TOOL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn program_resolved_in_the_guest_profile() {
        assert_eq!(resolve_program("curl"), "/run/current-system/sw/bin/curl");
        assert_eq!(resolve_program("/nix/store/x/bin/y"), "/nix/store/x/bin/y");
    }
    #[test]
    fn systemd_run_always_carries_the_three_switches() {
        let a = systemd_run_argv("g", "/p/curl", &v(&["-sS"]));
        assert_eq!(
            a,
            v(&[
                "--machine=g",
                "--wait",
                "--pipe",
                "--quiet",
                "--collect",
                "--",
                "/p/curl",
                "-sS"
            ])
        );
    }
    #[test]
    fn properties_go_before_the_double_dash() {
        let a = systemd_run_argv_with(
            "g",
            &v(&["RuntimeMaxSec=600", "User=sonarr"]),
            "/p/cat",
            &v(&["/etc/machine-id"]),
        );
        assert_eq!(
            a,
            v(&[
                "--machine=g",
                "--wait",
                "--pipe",
                "--quiet",
                "--collect",
                "-p",
                "RuntimeMaxSec=600",
                "-p",
                "User=sonarr",
                "--",
                "/p/cat",
                "/etc/machine-id"
            ])
        );
    }
    #[test]
    fn guest_command_resolves_the_program_and_builds_the_argv() {
        let c = GuestCommand::new("media-01", "curl")
            .args(["-sS", "-K", "-"])
            .property("RuntimeMaxSec=600");
        assert_eq!(c.program, "/run/current-system/sw/bin/curl");
        assert_eq!(
            c.argv(),
            v(&[
                "--machine=media-01",
                "--wait",
                "--pipe",
                "--quiet",
                "--collect",
                "-p",
                "RuntimeMaxSec=600",
                "--",
                "/run/current-system/sw/bin/curl",
                "-sS",
                "-K",
                "-"
            ])
        );
        let c = GuestCommand::new("g", "/nix/store/x/bin/y").arg("z");
        assert_eq!(c.program, "/nix/store/x/bin/y");
        assert_eq!(c.args, v(&["z"]));
    }
    #[test]
    fn guest_errors_name_guest_and_program() {
        let e = GuestError::NotInProfile {
            guest: "koch-01".into(),
            program: "/run/current-system/sw/bin/curl".into(),
        };
        assert_eq!(
            e.to_string(),
            "/run/current-system/sw/bin/curl is not in the profile of koch-01 (203/EXEC)"
        );
        let e: GuestError = crate::capture::CaptureError::TimedOut {
            timeout: std::time::Duration::from_secs(5),
        }
        .into();
        assert!(e.to_string().starts_with("systemd-run: "), "{e}");
    }
    #[test]
    fn exec_args_carry_paths_not_values() {
        let r = RunArgs {
            guest: "g".into(),
            header_files: vec![("X-Api-Key".into(), "/run/k".into())],
            headers: v(&["Accept: a"]),
            as_service: None,
            program: "curl".into(),
            args: v(&["http://x/"]),
        };
        let (p, a) = exec_args("/nix/store/v/bin/vantage", &r);
        assert_eq!(p, "/nix/store/v/bin/vantage");
        assert_eq!(
            a,
            v(&[
                "__exec",
                "--header-file",
                "X-Api-Key=/run/k",
                "--header",
                "Accept: a",
                "--",
                "/run/current-system/sw/bin/curl",
                "http://x/"
            ])
        );
    }
    #[test]
    fn validate_rules() {
        let mut r = RunArgs {
            guest: "g".into(),
            program: "curl".into(),
            args: v(&["-H", "X: y"]),
            ..Default::default()
        };
        assert!(validate(&r).is_err());
        r.args = v(&["http://x/"]);
        assert!(validate(&r).is_ok());
        r.program = "wget".into();
        r.headers = v(&["A: b"]);
        assert!(validate(&r).unwrap_err().contains("curl"));
    }
    #[test]
    fn exec_203_of_the_program_is_127() {
        let (c, m) = exec_203("signal-01", "/run/current-system/sw/bin/signal-cli", false);
        assert_eq!(c, 127);
        assert!(
            m.contains("`signal-cli` is not in the profile of signal-01"),
            "{m}"
        );
    }
    #[test]
    fn exec_203_of_vantage_itself_is_a_tool_error() {
        let (c, m) = exec_203("g", "/nix/store/abc-vantage/bin/vantage", true);
        assert_eq!(c, 125);
        assert!(
            m.contains("vantage's store path is not visible in g (store not shared?)"),
            "{m}"
        );
        assert!(!m.contains("profile"), "{m}");
    }
    #[test]
    fn verbose_refused_only_with_a_header_file() {
        let mut r = RunArgs {
            guest: "g".into(),
            program: "curl".into(),
            args: v(&["-sv", "http://x/"]),
            ..Default::default()
        };
        assert!(validate(&r).is_ok(), "no secret in play: -v is fine");
        r.headers = v(&["Accept: a"]);
        assert!(validate(&r).is_ok(), "a plain --header is in argv anyway");
        r.header_files = vec![("X-Api-Key".into(), "/run/k".into())];
        assert!(validate(&r).unwrap_err().contains("-v"));
        r.args = v(&["--trace-ascii", "-", "http://x/"]);
        assert!(validate(&r).unwrap_err().contains("--trace-ascii"));
    }
}
