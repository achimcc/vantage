//! Copies the seccomp filters of a running process: read with ptrace
//! (PTRACE_SECCOMP_GET_FILTER, needs CAP_SYS_ADMIN — root on the host), load
//! with seccomp(2). Index 0 is the most recently installed filter, so they are
//! loaded from the highest index down. Measured 2026-09-21 on the server:
//! sftpgo 36 filters, the service stood still for 174–524 µs.

use std::time::{Duration, Instant};

const PTRACE_SECCOMP_GET_FILTER: libc::c_uint = 0x420c;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
/// The longest classic BPF program the kernel accepts (`BPF_MAXINSNS`,
/// include/uapi/linux/bpf_common.h). PTRACE_SECCOMP_GET_FILTER copies a
/// whole filter to user space WITHOUT being told how large the buffer is,
/// so every buffer handed to it holds this many instructions — whatever
/// the kernel said the length was a moment ago.
const BPF_MAXINSNS: usize = 4096;

pub struct Filter(pub Vec<libc::sock_filter>);

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

#[allow(unsafe_code)]
pub fn read_filters(pid: i32) -> Result<(Vec<Filter>, Duration), String> {
    // SAFETY: ptrace(2) and waitpid(2) on a foreign pid; the kernel checks
    // the pid and our rights and answers with an error. The only pointers
    // handed over are `&mut st` (a live local int) and, in the copying
    // PTRACE_SECCOMP_GET_FILTER, `buf`: a Vec of BPF_MAXINSNS sock_filter.
    // The kernel writes the whole filter behind the index and never more
    // than BPF_MAXINSNS instructions — it accepts no longer program — so the
    // write stays inside `buf` whichever filter the index names by then.
    // That matters: only the seized THREAD is stopped, and the length asked
    // for one call earlier is not a promise about this one. `i` travels in
    // the address argument as a plain number and is never dereferenced.
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
                    BPF_MAXINSNS
                ];
                let copied = libc::ptrace(
                    PTRACE_SECCOMP_GET_FILTER,
                    pid,
                    i as *mut libc::c_void,
                    buf.as_mut_ptr() as *mut libc::c_void,
                );
                if copied < 0 {
                    result = Err(os_err("PTRACE_SECCOMP_GET_FILTER (copy)"));
                    break;
                }
                // A filter list that moved between the two calls is not the
                // one this copy set out to read: say so instead of keeping
                // a mix of two states.
                if copied != n {
                    result = Err(format!(
                        "PTRACE_SECCOMP_GET_FILTER[{i}]: the filter changed while it was read \
                         ({n} instructions, then {copied})"
                    ));
                    break;
                }
                buf.truncate(copied as usize);
                buf.shrink_to_fit();
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

/// Die gelesenen Filter gegen `Seccomp_filters` aus `/proc/<pid>/status`
/// (Audit 3, A1-7/B108). Gelesen wird hoechstens 512 Stueck, und der Dienst
/// kann zwischen dem Lesen von status und dem ptrace einen Filter
/// nachladen: Stimmt die Zahl nicht, ist die Nachbildung nicht die des
/// Dienstes -- dann wird GAR KEIN Filter geladen und die Berichtszeile nennt
/// `seccomp (…)` unter `NOT:`, statt eine Teilmenge als `seccomp=<n>`
/// auszugeben.
pub fn checked(read: Result<Vec<Filter>, String>, reported: u32) -> Result<Vec<Filter>, String> {
    let f = read?;
    if f.len() as u64 != reported as u64 {
        return Err(format!(
            "read {} filters, the process has {reported} (Seccomp_filters)",
            f.len()
        ));
    }
    Ok(f)
}

#[allow(unsafe_code)]
pub fn load_filters(filters: &[Filter]) -> Result<(), String> {
    for (i, f) in filters.iter().enumerate().rev() {
        let prog = libc::sock_fprog {
            len: f.0.len() as u16,
            filter: f.0.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: seccomp(2) reads `prog` and the `len` instructions behind
        // `prog.filter` and keeps its own copy; both are borrowed from `f`,
        // which outlives the call. `len` is never more than the Vec's length
        // (the cast to u16 can only shorten it), and the kernel only reads
        // through the `*mut` the struct asks for.
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

    #[allow(unsafe_code)]
    fn in_child(f: impl FnOnce() -> i32) -> i32 {
        // SAFETY: fork(2) in a test process that has other threads: the
        // child runs only `f` and leaves with _exit, so no destructor and no
        // atexit handler of the parent runs twice. `f` may allocate, which
        // glibc supports after fork (it resets the malloc locks in the
        // child). `&mut st` is a live local int for waitpid.
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

    /// B108: 36 Filter meldet der Kernel fuer sonarr (aufgezeichnetes
    /// status), 35 kamen ueber ptrace zurueck -- keine Nachbildung.
    #[test]
    fn filter_count_must_match_the_status_line() {
        let st = crate::proc_status::parse(include_str!("../tests/fixtures/status-sonarr.txt"));
        assert_eq!(st.seccomp_filters, 36);
        let n = |k: usize| Ok((0..k).map(|_| deny_getppid()).collect::<Vec<_>>());
        assert_eq!(checked(n(36), st.seccomp_filters).unwrap().len(), 36);
        let e = checked(n(35), st.seccomp_filters).err().unwrap();
        assert_eq!(e, "read 35 filters, the process has 36 (Seccomp_filters)");
        // 512 ist die Lesegrenze: mehr als das faellt hier auf.
        assert!(checked(n(512), 600).is_err());
        // Ein Lesefehler bleibt der Lesefehler.
        assert_eq!(
            checked(Err("PTRACE_SEIZE: x".into()), 36).err().unwrap(),
            "PTRACE_SEIZE: x"
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn loaded_filter_takes_effect() {
        // SAFETY: prctl(2) and getppid(2) take no pointers; __errno_location
        // returns this thread's errno, valid for as long as the thread lives.
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
    #[allow(unsafe_code)]
    fn filters_read_back_as_loaded_or_skip_with_reason() {
        // SAFETY: fork(2) in a test process that has other threads: the
        // child builds one filter (an allocation, which glibc supports after
        // fork), loads it and pauses until SIGKILL; it never returns into
        // the test harness. The parent's kill and waitpid name the pid fork
        // just returned; waitpid accepts a null status pointer.
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
