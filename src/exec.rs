//! `vantage __exec`: runs INSIDE the guest (vantage re-enters itself via its
//! store path, which the guest shares with the host). Reads --header-file
//! there, writes the curlrc into a memfd and execs curl with
//! `-K /proc/self/fd/<n>`. The journal line of the transient unit therefore
//! shows paths, never values.

use crate::cli::ExecArgs;
use crate::curlrc;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;

/// Reads the --header-file files (as whoever calls this, in whatever mount
/// namespace and root it lives in), renders the curlrc and writes it into a
/// memfd WITHOUT close-on-exec, so curl can read it as `/proc/self/fd/<n>`.
/// Returns the descriptor. Errors name header names and paths, never values.
/// Used by `__exec` and by the forked child of `--as-service`.
pub fn curlrc_memfd(headers: &[String], header_files: &[(String, String)]) -> Result<i32, String> {
    let mut all = headers.to_vec();
    for (name, path) in header_files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("--header-file {name}: cannot read {path}: {e}"))?;
        all.push(curlrc::header_from_file(name, &content)?);
    }
    let rc = curlrc::render(&all)?;
    let name = CString::new("vantage-curlrc").unwrap();
    // No MFD_CLOEXEC: curl must inherit the descriptor across exec.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    if let Err(e) = f.write_all(rc.as_bytes()) {
        return Err(format!("writing the curlrc: {e}"));
    }
    Ok(f.into_raw_fd()) // keep the fd open for curl
}

pub fn run(a: &ExecArgs) -> i32 {
    let fd = match curlrc_memfd(&a.headers, &a.header_files) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("vantage: {e}");
            return crate::app::EXIT_TOOL;
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn curlrc_lands_in_an_inheritable_memfd() {
        let d = tempfile::tempdir().unwrap();
        let key = d.path().join("key");
        std::fs::File::create(&key)
            .unwrap()
            .write_all(b"geheim-4711\n")
            .unwrap();
        let fd = curlrc_memfd(
            &["Accept: a/b".to_string()],
            &[("X-Api-Key".to_string(), key.display().to_string())],
        )
        .unwrap();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, 0, "curl must inherit the fd");
        let rc = std::fs::read_to_string(format!("/proc/self/fd/{fd}")).unwrap();
        unsafe { libc::close(fd) };
        assert_eq!(
            rc,
            "header = \"Accept: a/b\"\nheader = \"X-Api-Key: geheim-4711\"\n"
        );
    }

    #[test]
    fn unreadable_header_file_names_the_path_never_a_value() {
        let e = curlrc_memfd(&[], &[("X".to_string(), "/nonexistent/k".to_string())]).unwrap_err();
        assert!(e.contains("/nonexistent/k"), "{e}");
    }
}
