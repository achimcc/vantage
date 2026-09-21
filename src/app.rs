//! Dispatch and exit codes. Tool errors are 125 (like env(1) and timeout(1))
//! so they never collide with the exit code of the measured program.

use crate::cli::{self, Cmd};

pub const EXIT_TOOL: i32 = 125;

pub const USAGE: &str = "\
vantage — measure inside a systemd-nspawn guest from the right vantage point

  vantage run   <guest> [--header-file 'Name=/path/in/guest']… [--header 'Name: value']…
                        [--as-service <unit>] -- <program> <args…>
  vantage probe --from <guest> <target-guest>:<port> [--path /p] [-6]
  vantage where <guest>

Runs on the host as root. Exit: the program's code; 125 tool error, 127 not in
the guest's profile (systemd's 203/EXEC), 126 not executable (only where vantage
execs itself: --as-service, __exec). probe: 0 answered, 1 finding, 2 tool error.
";

pub fn main(argv: &[String]) -> i32 {
    match cli::parse(argv) {
        Ok(Cmd::Help) => {
            print!("{USAGE}");
            0
        }
        Ok(Cmd::Version) => {
            println!("vantage {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(cmd) => dispatch(cmd),
        Err(e) => {
            eprintln!("vantage: {e}\n\n{USAGE}");
            // probe's tool errors are 2 (0 answered, 1 finding); 125 is run's.
            if argv.first().map(String::as_str) == Some("probe") {
                2
            } else {
                EXIT_TOOL
            }
        }
    }
}

fn dispatch(cmd: Cmd) -> i32 {
    match cmd {
        Cmd::Exec(a) => crate::exec::run(&a),
        Cmd::Run(r) => run(&r),
        Cmd::Probe(a) => match crate::config::load() {
            Ok(cfg) => crate::probe::probe(&crate::host::Real, &cfg, &a),
            Err(e) => {
                eprintln!("vantage: {e}");
                2
            }
        },
        Cmd::Where { guest } => match crate::where_cmd::run(&crate::host::Real, &guest) {
            Ok(t) => {
                print!("{t}");
                0
            }
            Err(e) => {
                eprintln!("vantage: {e}");
                EXIT_TOOL
            }
        },
        Cmd::Help | Cmd::Version => unreachable!("handled in main"),
    }
}

fn run(r: &crate::cli::RunArgs) -> i32 {
    use crate::guest_run as g;
    if let Err(e) = g::validate(r) {
        eprintln!("vantage: {e}");
        return EXIT_TOOL;
    }
    if let Err(e) = crate::machine::leader(&crate::host::Real, &r.guest) {
        eprintln!("vantage: {e}");
        return EXIT_TOOL;
    }
    if let Some(unit) = &r.as_service {
        // Headers are handled by the forked child itself (as the service
        // user, in its namespaces and root) — no re-exec of vantage here.
        return crate::service::run_as_service(
            &crate::host::Real,
            &r.guest,
            unit,
            &r.program,
            &r.args,
            &r.headers,
            &r.header_files,
        );
    }
    if r.header_files.is_empty() && r.headers.is_empty() {
        return g::run_in_guest(&r.guest, &g::resolve_program(&r.program), &r.args, false);
    }
    match g::self_exe() {
        Ok(me) => {
            let (p, a) = g::exec_args(&me, r);
            g::run_in_guest(&r.guest, &p, &a, true)
        }
        Err(e) => {
            eprintln!("vantage: {e}");
            EXIT_TOOL
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
    fn probe_parse_errors_are_probe_tool_errors() {
        assert_eq!(main(&v(&["probe", "b:80"])), 2, "--from missing");
        assert_eq!(main(&v(&["probe", "--from", "a", "b:x"])), 2);
        assert_eq!(main(&v(&["probe", "--bogus"])), 2);
    }
    #[test]
    fn other_parse_errors_stay_125() {
        assert_eq!(main(&v(&["run", "g"])), EXIT_TOOL);
        assert_eq!(main(&v(&["frobnicate"])), EXIT_TOOL);
    }
}
