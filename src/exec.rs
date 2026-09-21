//! `vantage __exec`: runs INSIDE the guest (vantage re-enters itself via its
//! store path, which the guest shares with the host). Reads --header-file
//! there, writes the curlrc into a memfd and execs curl with
//! `-K /proc/self/fd/<n>`. The journal line of the transient unit therefore
//! shows paths, never values.

use crate::cli::ExecArgs;
use crate::curlrc;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;

pub fn run(a: &ExecArgs) -> i32 {
    let mut headers = a.headers.clone();
    for (name, path) in &a.header_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vantage: --header-file {name}: cannot read {path}: {e}");
                return crate::app::EXIT_TOOL;
            }
        };
        match curlrc::header_from_file(name, &content) {
            Ok(h) => headers.push(h),
            Err(e) => {
                eprintln!("vantage: {e}");
                return crate::app::EXIT_TOOL;
            }
        }
    }
    let rc = match curlrc::render(&headers) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vantage: {e}");
            return crate::app::EXIT_TOOL;
        }
    };
    let name = CString::new("vantage-curlrc").unwrap();
    // No MFD_CLOEXEC: curl must inherit the descriptor across exec.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        eprintln!("vantage: memfd_create: {}", std::io::Error::last_os_error());
        return crate::app::EXIT_TOOL;
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    if let Err(e) = f.write_all(rc.as_bytes()) {
        eprintln!("vantage: writing the curlrc: {e}");
        return crate::app::EXIT_TOOL;
    }
    std::mem::forget(f); // keep fd open for curl
    let err = std::process::Command::new(&a.program)
        .arg("-K")
        .arg(format!("/proc/self/fd/{fd}"))
        .args(&a.args)
        .exec();
    exec_error_code(&a.program, &err)
}

/// Maps a failed exec to the env(1) convention.
pub fn exec_error_code(program: &str, err: &std::io::Error) -> i32 {
    eprintln!("vantage: cannot run {program}: {err}");
    match err.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    }
}
