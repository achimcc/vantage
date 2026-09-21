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

Runs on the host as root. Exit: the program's code; 125 tool error, 126 not
executable, 127 not in the guest's profile. probe: 0 answered, 1 finding, 2 tool error.
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
            EXIT_TOOL
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
        _ => {
            eprintln!("vantage: not implemented yet");
            EXIT_TOOL
        }
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
        let h = crate::host::Real;
        if r.header_files.is_empty() && r.headers.is_empty() {
            return crate::service::run_as_service(&h, &r.guest, unit, &r.program, &r.args);
        }
        return match g::self_exe() {
            Ok(me) => {
                let (p, a) = g::exec_args(&me, r);
                crate::service::run_as_service(&h, &r.guest, unit, &p, &a)
            }
            Err(e) => {
                eprintln!("vantage: {e}");
                EXIT_TOOL
            }
        };
    }
    if r.header_files.is_empty() && r.headers.is_empty() {
        return g::run_in_guest(&r.guest, &g::resolve_program(&r.program), &r.args);
    }
    match g::self_exe() {
        Ok(me) => {
            let (p, a) = g::exec_args(&me, r);
            g::run_in_guest(&r.guest, &p, &a)
        }
        Err(e) => {
            eprintln!("vantage: {e}");
            EXIT_TOOL
        }
    }
}
