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

fn dispatch(_cmd: Cmd) -> i32 {
    eprintln!("vantage: not implemented yet");
    EXIT_TOOL
}
