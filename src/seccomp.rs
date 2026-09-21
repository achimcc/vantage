//! Copies the seccomp filters of a running process: read with ptrace
//! (PTRACE_SECCOMP_GET_FILTER, needs CAP_SYS_ADMIN — root on the host), load
//! with seccomp(2). Index 0 is the most recently installed filter, so they are
//! loaded from the highest index down. Measured 2026-09-21 on the server:
//! sftpgo 36 filters, the service stood still for 174–524 µs.

use std::time::{Duration, Instant};

const PTRACE_SECCOMP_GET_FILTER: libc::c_uint = 0x420c;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

pub struct Filter(pub Vec<libc::sock_filter>);

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

pub fn read_filters(pid: i32) -> Result<(Vec<Filter>, Duration), String> {
    unsafe {
        let null = std::ptr::null_mut::<libc::c_void>();
        if libc::ptrace(libc::PTRACE_SEIZE, pid, null, null) < 0 {
            return Err(os_err("PTRACE_SEIZE"));
        }
        let t0 = Instant::now();
        let mut result = Ok(Vec::new());
        if libc::ptrace(libc::PTRACE_INTERRUPT, pid, null, null) < 0 {
            result = Err(os_err("PTRACE_INTERRUPT"));
        } else {
            let mut st = 0;
            libc::waitpid(pid, &mut st, libc::__WALL);
            let mut out = Vec::new();
            for i in 0..512usize {
                let n = libc::ptrace(PTRACE_SECCOMP_GET_FILTER, pid, i as *mut libc::c_void, null);
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::ENOENT) {
                        result = Err(format!("PTRACE_SECCOMP_GET_FILTER[{i}]: {e}"));
                    }
                    break;
                }
                let mut buf = vec![
                    libc::sock_filter {
                        code: 0,
                        jt: 0,
                        jf: 0,
                        k: 0
                    };
                    n as usize
                ];
                if libc::ptrace(
                    PTRACE_SECCOMP_GET_FILTER,
                    pid,
                    i as *mut libc::c_void,
                    buf.as_mut_ptr() as *mut libc::c_void,
                ) != n
                {
                    result = Err(os_err("PTRACE_SECCOMP_GET_FILTER (copy)"));
                    break;
                }
                out.push(Filter(buf));
            }
            if result.is_ok() {
                result = Ok(out);
            }
        }
        // Always detach, whatever happened above.
        libc::ptrace(libc::PTRACE_DETACH, pid, null, null);
        let stood = t0.elapsed();
        result.map(|f| (f, stood))
    }
}

pub fn load_filters(filters: &[Filter]) -> Result<(), String> {
    for (i, f) in filters.iter().enumerate().rev() {
        let prog = libc::sock_fprog {
            len: f.0.len() as u16,
            filter: f.0.as_ptr() as *mut libc::sock_filter,
        };
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0 as libc::c_ulong,
                &prog,
            )
        };
        if r != 0 {
            return Err(os_err(&format!("seccomp load [{i}]")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns EPERM for getppid, allows everything else.
    fn deny_getppid() -> Filter {
        Filter(vec![
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            }, // ld nr
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_getppid as u32,
            }, // jeq
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x0005_0000 | libc::EPERM as u32,
            }, // ret errno
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            }, // ret allow
        ])
    }

    fn in_child(f: impl FnOnce() -> i32) -> i32 {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                libc::_exit(f());
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            libc::WEXITSTATUS(st)
        }
    }

    #[test]
    fn loaded_filter_takes_effect() {
        let code = in_child(|| unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return 10;
            }
            if load_filters(&[deny_getppid()]).is_err() {
                return 11;
            }
            let r = libc::syscall(libc::SYS_getppid);
            if r == -1 && *libc::__errno_location() == libc::EPERM {
                0
            } else {
                12
            }
        });
        assert_eq!(code, 0);
    }

    /// A skip is allowed only for a refusal on permission grounds: EPERM or
    /// EACCES from PTRACE_SEIZE (no ptrace rights over the child), or EACCES
    /// from the first PTRACE_SECCOMP_GET_FILTER while the test lacks
    /// CAP_SYS_ADMIN — the kernel's own check for that request, and the
    /// normal case for a non-root `cargo test` or a Nix builder.
    fn may_skip(e: &str, has_sys_admin: bool) -> bool {
        let denied = e.contains("Operation not permitted") || e.contains("Permission denied");
        (e.starts_with("PTRACE_SEIZE:") && denied)
            || (!has_sys_admin
                && e.starts_with("PTRACE_SECCOMP_GET_FILTER[0]:")
                && e.contains("Permission denied"))
    }

    /// CAP_SYS_ADMIN (bit 21) in this process's effective set.
    fn has_sys_admin() -> bool {
        let st = std::fs::read_to_string("/proc/self/status").unwrap();
        crate::proc_status::parse(&st).cap_eff & (1 << 21) != 0
    }

    #[test]
    fn only_a_permission_refusal_may_skip() {
        assert!(may_skip(
            "PTRACE_SEIZE: Operation not permitted (os error 1)",
            true
        ));
        assert!(may_skip(
            "PTRACE_SEIZE: Permission denied (os error 13)",
            true
        ));
        assert!(may_skip(
            "PTRACE_SECCOMP_GET_FILTER[0]: Permission denied (os error 13)",
            false
        ));
        assert!(
            !may_skip(
                "PTRACE_SECCOMP_GET_FILTER[0]: Permission denied (os error 13)",
                true
            ),
            "with CAP_SYS_ADMIN a refused read is a failure"
        );
        assert!(!may_skip(
            "PTRACE_INTERRUPT: Operation not permitted (os error 1)",
            false
        ));
        assert!(!may_skip(
            "PTRACE_SECCOMP_GET_FILTER[0]: Invalid argument (os error 22)",
            false
        ));
        assert!(!may_skip(
            "PTRACE_SECCOMP_GET_FILTER[1]: Permission denied (os error 13)",
            false
        ));
        assert!(!may_skip(
            "PTRACE_SEIZE: No such process (os error 3)",
            false
        ));
    }

    #[test]
    fn filters_read_back_as_loaded_or_skip_with_reason() {
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let _ = load_filters(&[deny_getppid()]);
                loop {
                    libc::pause();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let r = read_filters(pid);
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
            match r {
                Ok((f, _)) => {
                    assert_eq!(f.len(), 1);
                    assert_eq!(f[0].0.len(), 4);
                }
                Err(e) => {
                    // Only a permission refusal skips (see may_skip); the
                    // server acceptance is the real proof. Anything else is
                    // a failure, not a skip.
                    assert!(may_skip(&e, has_sys_admin()), "read-back failed: {e}");
                    eprintln!("SKIPPED read-back: {e}");
                }
            }
        }
    }
}
