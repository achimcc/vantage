//! `--as-service <unit>`: run a program as a replica of the RUNNING service
//! process — its namespaces, cgroup, IDs, capabilities, no_new_privs and
//! seccomp filters — not a freshly built sandbox. Spike 2026-09-21 (spec 6.1):
//!
//! * Supplementary groups are set with HOST gids before entering the user
//!   namespace: services carry groups their own namespace does not map
//!   (sonarr 109000), and setgroups(2) from inside would refuse them.
//! * Namespaces are entered user LAST: as host root we have rights over all
//!   child namespaces; after joining `user` we would lack them for a `mnt`
//!   owned by a parent.
//! * Seccomp is copied from the process (ptrace) and loaded last before exec.
//! * The environment of the service is never copied — it can carry secrets.
//! * The umask is copied (file-mode measurements depend on it); SIGPIPE is
//!   reset to SIG_DFL, which Rust's runtime had set to SIG_IGN.
//! * Not reproduced, and said so in the report line: LSM labels and rlimits.

use crate::host::{Host, PROFILE};
use crate::proc_status::{self, Status};
use crate::seccomp;
use std::ffi::CString;

pub struct Groups {
    pub inner: Vec<u32>,
    pub unmapped: Vec<u32>,
}

pub fn split_groups(gid_map: &str, host_groups: &[u32]) -> Groups {
    let mut g = Groups {
        inner: vec![],
        unmapped: vec![],
    };
    for &h in host_groups {
        match proc_status::map_to_inner(gid_map, h) {
            Some(i) => g.inner.push(i),
            None => g.unmapped.push(h),
        }
    }
    g
}

#[allow(clippy::too_many_arguments)]
pub fn report_line(
    unit: &str,
    guest_pid: u32,
    uid: u32,
    gid: u32,
    groups: &Groups,
    st: &Status,
    seccomp: &Result<usize, String>,
    nnp_added: bool,
) -> String {
    let mut gl: Vec<String> = groups.inner.iter().map(|g| g.to_string()).collect();
    gl.extend(groups.unmapped.iter().map(|g| format!("+{g}(unmapped)")));
    let nnp = if nnp_added {
        "nnp(added)"
    } else if st.no_new_privs {
        "nnp"
    } else {
        "no-nnp"
    };
    let (sc, not_sc) = match (st.seccomp_mode, seccomp) {
        (2, Ok(n)) => (n.to_string(), None),
        (2, Err(e)) => ("?".to_string(), Some(e.clone())),
        _ => ("none".to_string(), None),
    };
    let not = match not_sc {
        None => "lsm,rlimits".to_string(),
        Some(e) => format!("lsm,rlimits,seccomp ({e})"),
    };
    format!(
        "vantage: as {unit} (pid {guest_pid}): ns=all uid={uid} gid={gid} groups={} caps={:#x} umask={:04o} {nnp} seccomp={sc} · NOT: {not}",
        gl.join(","),
        st.cap_eff,
        st.umask
    )
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL in arguments")
}

/// `err` is captured by the caller right after the failing call, before
/// anything (e.g. `format!`) can clobber errno.
fn fail(what: &str, err: std::io::Error) -> ! {
    eprintln!("vantage: {what}: {err}");
    unsafe { libc::_exit(crate::app::EXIT_TOOL) }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const CAP_V3: u32 = 0x2008_0522;

/// Returns the program's exit code. On return the calling process has joined
/// the service's namespaces, cgroup and supplementary groups: the caller
/// must do nothing but exit with the returned code.
pub fn run_as_service(
    h: &dyn Host,
    guest: &str,
    unit: &str,
    program: &str,
    args: &[String],
) -> i32 {
    let tool = crate::app::EXIT_TOOL;
    let unit = crate::machine::unit_name(unit);
    let (host_pid, guest_pid) = match crate::machine::service_host_pid(h, guest, &unit) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vantage: {e}");
            return tool;
        }
    };
    let read = |p: String| h.read(&p);
    let (st, uid_map, gid_map, cg) = match (
        read(format!("/proc/{host_pid}/status")),
        read(format!("/proc/{host_pid}/uid_map")),
        read(format!("/proc/{host_pid}/gid_map")),
        read(format!("/proc/{host_pid}/cgroup")),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (proc_status::parse(&a), b, c, d),
        _ => {
            eprintln!("vantage: cannot read /proc/{host_pid} — did {unit} just restart?");
            return tool;
        }
    };
    let (Some(uid), Some(gid)) = (
        proc_status::map_to_inner(&uid_map, st.uid),
        proc_status::map_to_inner(&gid_map, st.gid),
    ) else {
        eprintln!("vantage: {unit}'s uid/gid is not mapped in its own namespace");
        return tool;
    };
    let groups = split_groups(&gid_map, &st.groups);
    let filters: Result<Vec<seccomp::Filter>, String> = if st.seccomp_mode == 2 {
        seccomp::read_filters(host_pid as i32).map(|(f, _)| f)
    } else {
        Ok(vec![])
    };
    let filters_count = filters.as_ref().map(|f| f.len()).map_err(String::clone);
    let nnp_added = !st.no_new_privs && matches!(&filters, Ok(f) if !f.is_empty());
    let last_cap: u32 = h
        .read("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40);
    let cg_path = match cg.lines().find_map(|l| l.strip_prefix("0::")) {
        Some(p) => format!("/sys/fs/cgroup{}/cgroup.procs", p.trim()),
        None => {
            eprintln!("vantage: no cgroup v2 path for {unit}");
            return tool;
        }
    };
    let report = report_line(
        &unit,
        guest_pid,
        uid,
        gid,
        &groups,
        &st,
        &filters_count,
        nnp_added,
    );

    // Everything the child needs is prepared before any namespace switch:
    // no heap allocation between fork and execve.
    let prog = crate::guest_run::resolve_program(program);
    let mut argv_s = vec![prog.clone()];
    argv_s.extend(args.iter().cloned());
    let argv_c: Vec<CString> = argv_s.iter().map(|s| cstr(s)).collect();
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let env_c = [cstr(&format!("PATH={PROFILE}"))];
    let envp: [*const libc::c_char; 2] = [env_c[0].as_ptr(), std::ptr::null()];
    let prog_c = cstr(&prog);
    let filters = filters.unwrap_or_default();

    let ns = ["cgroup", "ipc", "uts", "net", "pid", "mnt", "user"];
    let mut fds = Vec::new();
    for n in ns {
        match std::fs::File::open(format!("/proc/{host_pid}/ns/{n}")) {
            Ok(f) => fds.push(f),
            Err(e) => {
                eprintln!("vantage: /proc/{host_pid}/ns/{n}: {e}");
                return tool;
            }
        }
    }
    if let Err(e) = std::fs::write(&cg_path, format!("{}\n", std::process::id())) {
        eprintln!("vantage: joining {cg_path}: {e}");
        return tool;
    }
    // SAFETY: plain syscalls on prepared, NUL-terminated buffers that outlive
    // the calls; vantage is single-threaded, so fork() leaves no lock held.
    unsafe {
        use std::os::fd::AsRawFd;
        if libc::setgroups(st.groups.len(), st.groups.as_ptr()) != 0 {
            fail("setgroups (host gids)", std::io::Error::last_os_error());
        }
        for (n, f) in ns.iter().zip(&fds) {
            if libc::setns(f.as_raw_fd(), 0) != 0 {
                let e = std::io::Error::last_os_error();
                fail(&format!("setns {n}"), e);
            }
        }
        let child = libc::fork();
        if child < 0 {
            fail("fork", std::io::Error::last_os_error());
        }
        if child > 0 {
            let mut s = 0;
            while libc::waitpid(child, &mut s, 0) < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EINTR) {
                    fail("waitpid", e);
                }
            }
            // The parent is now inside the service's namespaces and cgroup
            // (and carries its supplementary groups): the caller must do
            // nothing with this process but exit with the returned code.
            return if libc::WIFEXITED(s) {
                libc::WEXITSTATUS(s)
            } else {
                128 + libc::WTERMSIG(s)
            };
        }
        // Child: now inside the pid namespace.
        for cap in 0..=last_cap {
            if (st.cap_bnd >> cap) & 1 == 0
                && libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0
            {
                fail("PR_CAPBSET_DROP", std::io::Error::last_os_error());
            }
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            fail("setresgid", std::io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            fail("PR_SET_KEEPCAPS", std::io::Error::last_os_error());
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            fail("setresuid", std::io::Error::last_os_error());
        }
        let hdr = CapHeader {
            version: CAP_V3,
            pid: 0,
        };
        let data = [
            CapData {
                effective: st.cap_eff as u32,
                permitted: st.cap_prm as u32,
                inheritable: st.cap_inh as u32,
            },
            CapData {
                effective: (st.cap_eff >> 32) as u32,
                permitted: (st.cap_prm >> 32) as u32,
                inheritable: (st.cap_inh >> 32) as u32,
            },
        ];
        if libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) != 0 {
            fail("capset", std::io::Error::last_os_error());
        }
        for cap in 0..=last_cap {
            if (st.cap_amb >> cap) & 1 == 1
                && libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0,
                    0,
                ) != 0
            {
                fail("PR_CAP_AMBIENT_RAISE", std::io::Error::last_os_error());
            }
        }
        if (st.no_new_privs || nnp_added) && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            fail("PR_SET_NO_NEW_PRIVS", std::io::Error::last_os_error());
        }
        libc::umask(st.umask as libc::mode_t);
        // Rust's runtime ignores SIGPIPE; a raw execve would pass that on.
        if libc::signal(libc::SIGPIPE, libc::SIG_DFL) == libc::SIG_ERR {
            fail("signal SIGPIPE", std::io::Error::last_os_error());
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            fail("chdir /", std::io::Error::last_os_error());
        }
        eprintln!("{report}");
        if let Err(e) = seccomp::load_filters(&filters) {
            eprintln!("vantage: {e}");
            libc::_exit(crate::app::EXIT_TOOL);
        }
        libc::execve(prog_c.as_ptr(), argv_p.as_ptr(), envp.as_ptr());
        let e = std::io::Error::last_os_error();
        eprintln!("vantage: cannot run {prog}: {e}");
        libc::_exit(if e.raw_os_error() == Some(libc::ENOENT) {
            127
        } else {
            126
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SONARR: &str = include_str!("../tests/fixtures/status-sonarr.txt");
    const SONARR_GID_MAP: &str = include_str!("../tests/fixtures/gid_map-sonarr.txt");

    #[test]
    fn unmapped_groups_are_kept_apart() {
        let st = crate::proc_status::parse(SONARR);
        let g = split_groups(SONARR_GID_MAP, &st.groups);
        assert!(g.unmapped.contains(&109000));
        assert_eq!(g.inner.len() + g.unmapped.len(), st.groups.len());
    }

    #[test]
    fn report_says_what_is_reproduced_and_what_not() {
        let st = Status {
            cap_eff: 0x400,
            umask: 0o002,
            no_new_privs: true,
            seccomp_mode: 2,
            ..Default::default()
        };
        let g = Groups {
            inner: vec![9000, 950],
            unmapped: vec![109000],
        };
        let l = report_line("sftpgo.service", 284, 950, 9000, &g, &st, &Ok(36), false);
        assert_eq!(
            l,
            "vantage: as sftpgo.service (pid 284): ns=all uid=950 gid=9000 \
                       groups=9000,950,+109000(unmapped) caps=0x400 umask=0002 nnp seccomp=36 · NOT: lsm,rlimits"
        );
        let l = report_line(
            "x.service",
            1,
            1,
            1,
            &Groups {
                inner: vec![],
                unmapped: vec![],
            },
            &st,
            &Err("PTRACE_SEIZE: Operation not permitted".into()),
            true,
        );
        assert!(l.contains("nnp(added)"), "{l}");
        assert!(
            l.ends_with("NOT: lsm,rlimits,seccomp (PTRACE_SEIZE: Operation not permitted)"),
            "{l}"
        );
        let none = Status {
            seccomp_mode: 0,
            ..Default::default()
        };
        let l = report_line(
            "y.service",
            1,
            1,
            1,
            &Groups {
                inner: vec![],
                unmapped: vec![],
            },
            &none,
            &Ok(0),
            false,
        );
        assert!(l.contains("umask=0022 no-nnp seccomp=none"), "{l}");
        assert!(l.ends_with("NOT: lsm,rlimits"), "{l}");
    }
}
