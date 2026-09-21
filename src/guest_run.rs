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
    let mut v: Vec<String> = [
        &format!("--machine={guest}"),
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
        "--",
        program,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.extend(args.iter().cloned());
    v
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

/// Runs with inherited stdio; returns the program's exit code. `reexec`:
/// `program` is vantage itself (`__exec`), not the user's program.
pub fn run_in_guest(guest: &str, program: &str, args: &[String], reexec: bool) -> i32 {
    let st = std::process::Command::new(format!("{PROFILE}/systemd-run"))
        .args(systemd_run_argv(guest, program, args))
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
