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
//! * The root directory is reproduced: `/proc/<pid>/root` is opened before
//!   the namespace switch and the child chroots into it, so a unit with
//!   `RootDirectory=` (e.g. `confinement.enable`) sees its own root. The
//!   report line says `root=own` when that root differs from the GUEST's
//!   own root (`/proc/<leader pid>/root`) — compared on the HOST, before any
//!   `setns`. Comparing after joining the service's mount namespace does not
//!   work: for a confined unit, systemd has already pivoted that namespace's
//!   `/` onto the confined root, so it is trivially equal to itself.
//! * With --header/--header-file the child itself — as the service user, in
//!   the service's mount namespace and root — reads the files and hands curl
//!   a curlrc in a memfd; there is no re-exec of vantage on this path.
//! * Not reproduced, and said so in the report line: LSM labels, rlimits,
//!   securebits, the keyring and seccomp's filter flags.
//! * Der Zielprozess wird direkt nach der Auswahl per pidfd festgehalten;
//!   bevor der erste Namensraum betreten wird, muss er (ueber das pidfd, in
//!   `/proc/self/fdinfo`) noch leben, dieselbe Gast-PID haben und sein
//!   PID-Namensraum der des Gast-Leaders sein (Audit 3, A1-7/B108).

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
    root_own: bool,
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
    // Securebits, Schluesselbund und die Flags der Seccomp-Filter (LOG,
    // SPEC_ALLOW, NEW_LISTENER) bildet vantage nie nach (B108); die Flags
    // werden nur genannt, wo Filter kopiert wurden.
    let base = "lsm,rlimits,securebits,keyring";
    let not = match (not_sc, sc.as_str()) {
        (Some(e), _) => format!("{base},seccomp ({e})"),
        (None, "none") => base.to_string(),
        (None, _) => format!("{base},seccomp-flags"),
    };
    let root = if root_own { " root=own" } else { "" };
    format!(
        "vantage: as {unit} (pid {guest_pid}): ns=all uid={uid} gid={gid} groups={} caps={:#x} umask={:04o} {nnp} seccomp={sc}{root} · NOT: {not}",
        gl.join(","),
        st.cap_eff,
        st.umask
    )
}

/// Ist der Prozess hinter dem pidfd noch der Hauptprozess des Dienstes?
/// `fdinfo` ist `/proc/self/fdinfo/<pidfd>`: `Pid:` ist dort -1, sobald der
/// Prozess beendet und abgeraeumt ist -- solange nicht, kann seine PID auch
/// nicht an einen anderen gegangen sein, und alles, was ueber
/// `/proc/<host_pid>` geoeffnet wurde, gehoert zu IHM. `NSpid` muss so tief
/// sein wie beim Gast-Leader (`depth`) und dort die Gast-PID tragen: Ein
/// Wirtsprozess mit derselben Nummer (`NSpid:\t4242`) besteht nicht mehr
/// (Audit 3, A1-7/B108). Vorher las dies `/proc/<pid>/status` und verglich
/// nur das letzte Feld.
pub fn still_main(fdinfo: &str, host_pid: u32, guest_pid: u32, depth: usize) -> bool {
    let pid = fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse::<i64>().ok());
    let ns = proc_status::parse(fdinfo).nspid;
    pid == Some(host_pid as i64)
        && ns.first() == Some(&host_pid)
        && ns.len() == depth
        && ns.last() == Some(&guest_pid)
}

/// pidfd_open(2): haelt den Prozess fest, nicht die Nummer.
#[allow(unsafe_code)]
fn pidfd_open(pid: u32) -> Result<std::os::fd::OwnedFd, std::io::Error> {
    use std::os::fd::FromRawFd;
    // SAFETY: Systemaufruf ohne Zeiger; ein Rueckgabewert >= 0 ist ein
    // frisch geoeffneter FD, den nur dieses OwnedFd besitzt (O_CLOEXEC ist
    // bei pidfd_open immer gesetzt).
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` ist >= 0 (oben geprueft) und frisch von pidfd_open, siehe
    // oben: Dieses OwnedFd ist sein einziger Besitzer.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// Ist der Namensraum hinter dem geoeffneten FD derselbe wie hinter `path`
/// (`/proc/<pid>/ns/<typ>`)? nsfs-Inodes, verglichen mit dev und ino.
pub fn same_ns(fd: &std::fs::File, path: &str) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::MetadataExt;
    let a = fd.metadata()?;
    let b = std::fs::metadata(path)?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

/// dev/inode of the directory `/proc/<pid>/root` resolves to, from the
/// host's own mount namespace — read before any `setns`.
#[allow(unsafe_code)]
fn stat_root(pid: u32) -> Result<(libc::dev_t, libc::ino_t), std::io::Error> {
    let path = cstr(&format!("/proc/{pid}/root"));
    // SAFETY: `libc::stat` is a plain C struct of integers; all-zero is a
    // valid value for it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a NUL-terminated CString and `st` a live, writable
    // `libc::stat`; both outlive the call.
    if unsafe { libc::stat(path.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_dev, st.st_ino))
}

/// A unit with `RootDirectory=` has its own root: a plain dev/inode
/// comparison, done on the host before any namespace is joined. Comparing
/// *inside* the service's mount namespace does not work — for a confined
/// unit systemd already pivots that namespace's `/` onto the confined root,
/// so it is trivially equal to itself.
fn roots_differ(service: (libc::dev_t, libc::ino_t), guest: (libc::dev_t, libc::ino_t)) -> bool {
    service != guest
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL in arguments")
}

/// `err` is captured by the caller right after the failing call, before
/// anything (e.g. `format!`) can clobber errno.
#[allow(unsafe_code)]
fn fail(what: &str, err: std::io::Error) -> ! {
    eprintln!("vantage: {what}: {err}");
    // SAFETY: _exit(2) takes no pointer and never returns. Skipping
    // destructors and atexit handlers is intended: `fail` is also called in
    // the forked child, where they are the parent's.
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
#[allow(clippy::too_many_arguments)]
#[allow(unsafe_code)]
pub fn run_as_service(
    h: &dyn Host,
    guest: &str,
    unit: &str,
    program: &str,
    args: &[String],
    headers: &[String],
    header_files: &[(String, String)],
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
    // Sofort festhalten (B108): Ab hier kann die Nummer nicht mehr an einen
    // anderen Prozess gehen, ohne dass die Pruefung vor dem ersten setns es
    // sieht.
    let pidfd = match pidfd_open(host_pid) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("vantage: pidfd_open {host_pid}: {e} — did {unit} just restart?");
            return tool;
        }
    };
    let leader_pid = match crate::machine::leader(h, guest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vantage: {e}");
            return tool;
        }
    };
    let depth = match h.read(&format!("/proc/{leader_pid}/status")) {
        Ok(s) => proc_status::parse(&s).nspid.len(),
        Err(e) => {
            eprintln!("vantage: {e}");
            return tool;
        }
    };
    // root=own: a plain host-side comparison against the GUEST's root, done
    // before any setns — see `roots_differ`.
    let root_own = match (stat_root(host_pid), stat_root(leader_pid)) {
        (Ok(svc), Ok(g)) => roots_differ(svc, g),
        (Err(e), _) => {
            eprintln!("vantage: stat /proc/{host_pid}/root: {e}");
            return tool;
        }
        (_, Err(e)) => {
            eprintln!("vantage: stat /proc/{leader_pid}/root: {e}");
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
        seccomp::checked(
            seccomp::read_filters(host_pid as i32).map(|(f, _)| f),
            st.seccomp_filters,
        )
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
        root_own,
    );
    let wants_rc = !headers.is_empty() || !header_files.is_empty();

    // Everything the child needs is prepared before any namespace switch:
    // no heap allocation between fork and execve — except for the curlrc
    // when headers are asked for (the child is single-threaded).
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
    // The service's root directory, taken before any namespace switch
    // (like nsenter --root): the child chroots into it.
    let root_path = cstr(&format!("/proc/{host_pid}/root"));
    // SAFETY: `root_path` is a NUL-terminated CString that outlives the call.
    let rootfd = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if rootfd < 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("vantage: /proc/{host_pid}/root: {e}");
        return tool;
    }
    // Everything is opened: is it still the same process? A restart in
    // between would have us join a stranger's (or no) namespaces. Gefragt
    // wird das pidfd, nicht die Nummer (B108).
    {
        use std::os::fd::AsRawFd;
        match std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())) {
            Ok(s) if still_main(&s, host_pid, guest_pid, depth) => {}
            _ => {
                eprintln!("vantage: {unit} restarted during setup, try again");
                return tool;
            }
        }
    }
    // Der PID-Namensraum, in den gleich gewechselt wird, muss der des Gastes
    // sein -- am geoeffneten FD gemessen, nicht am Pfad (B108).
    let pid_ns = &fds[ns.iter().position(|n| *n == "pid").expect("pid in ns")];
    match same_ns(pid_ns, &format!("/proc/{leader_pid}/ns/pid")) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "vantage: pid {host_pid} is not in {guest}'s pid namespace — not the service"
            );
            return tool;
        }
        Err(e) => {
            eprintln!("vantage: /proc/{leader_pid}/ns/pid: {e}");
            return tool;
        }
    }
    if let Err(e) = std::fs::write(&cg_path, format!("{}\n", std::process::id())) {
        eprintln!("vantage: joining {cg_path}: {e}");
        return tool;
    }
    // SAFETY: plain syscalls on prepared, NUL-terminated buffers that outlive
    // the calls; vantage is single-threaded, so fork() leaves no lock held.
    // In detail: the argv/envp pointer arrays end in a null pointer and point
    // into CStrings (`argv_c`, `rc_argv`, `env_c`, `prog_c`) that live until
    // execve or _exit; setgroups reads `st.groups.len()` gids from that very
    // Vec; setns gets descriptors of the still-open files in `fds`; `rootfd`
    // is the open O_PATH descriptor from above and is closed once, in the
    // child, after its last use;
    // capset reads a `repr(C)` header and the two data elements that
    // _LINUX_CAPABILITY_VERSION_3 expects; `&mut s` is a live local int.
    unsafe {
        use std::os::fd::AsRawFd;
        // NOT DUMPABLE BEFORE THE FIRST setns (audit 3 of the homeserver,
        // B82). From the fork until `setresuid` the child lives in the
        // guest's pid and user namespaces with kuid 0; `setns(user)` does not
        // reset dumpability, so CAP_SYS_PTRACE in the GUEST's user namespace
        // -- which guest root holds -- was enough to PTRACE_SEIZE it or open
        // its /proc/<pid>/fd (the operator's ssh channels). Not dumpable,
        // ptrace needs CAP_SYS_PTRACE in the namespace mm->user_ns names: the
        // host's. `execve` of the target resets it (runc's nsexec does the
        // same). Set here, it covers the parent and is inherited by the child.
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            fail("PR_SET_DUMPABLE 0", std::io::Error::last_os_error());
        }
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
        // Child: now inside the pid namespace. `root_own` was decided on the
        // host, before this setns — see the comment at `roots_differ`. What
        // is left here is only the mechanics: chroot into the service's root
        // while still privileged.
        if libc::fchdir(rootfd) != 0 {
            fail(
                "fchdir to the service's root",
                std::io::Error::last_os_error(),
            );
        }
        if libc::chroot(c".".as_ptr()) != 0 {
            fail(
                "chroot into the service's root",
                std::io::Error::last_os_error(),
            );
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            fail("chdir /", std::io::Error::last_os_error());
        }
        libc::close(rootfd);
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
        eprintln!("{report}");
        // Headers: read the files HERE — as the service user, in its mount
        // namespace and root — into a curlrc memfd, and put -K in front of
        // curl's own arguments. The child is single-threaded, so allocating
        // is safe; seccomp is not loaded yet, so memfd_create is allowed.
        let rc_argv: Vec<CString>;
        let mut rc_argv_p: Vec<*const libc::c_char> = Vec::new();
        let argv_final = if wants_rc {
            let fd = match crate::exec::curlrc_memfd(headers, header_files) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("vantage: {e}");
                    libc::_exit(crate::app::EXIT_TOOL);
                }
            };
            let mut v = vec![prog.clone(), "-K".into(), format!("/proc/self/fd/{fd}")];
            v.extend(args.iter().cloned());
            rc_argv = v.iter().map(|s| cstr(s)).collect();
            rc_argv_p.extend(rc_argv.iter().map(|c| c.as_ptr()));
            rc_argv_p.push(std::ptr::null());
            rc_argv_p.as_ptr()
        } else {
            argv_p.as_ptr()
        };
        if let Err(e) = seccomp::load_filters(&filters) {
            eprintln!("vantage: {e}");
            libc::_exit(crate::app::EXIT_TOOL);
        }
        libc::execve(prog_c.as_ptr(), argv_final, envp.as_ptr());
        let e = std::io::Error::last_os_error();
        let is_enoent = e.raw_os_error() == Some(libc::ENOENT);
        let hint = if is_enoent && root_own {
            " (the service has its own root directory — only programs inside it exist there)"
        } else {
            ""
        };
        eprintln!("vantage: cannot run {prog}: {e}{hint}");
        libc::_exit(if is_enoent { 127 } else { 126 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SONARR: &str = include_str!("../tests/fixtures/status-sonarr.txt");
    const SONARR_GID_MAP: &str = include_str!("../tests/fixtures/gid_map-sonarr.txt");

    /// B82: the process stops being dumpable BEFORE it enters the first
    /// namespace and before the fork -- the window guest root could ptrace
    /// into. Entering namespaces needs root, so this guards the order in the
    /// source; the hostile-guest VM test checks the behaviour.
    #[test]
    fn not_dumpable_before_the_first_setns_and_the_fork() {
        let src = include_str!("service.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        let at = |needle: &str| {
            code.find(needle)
                .unwrap_or_else(|| panic!("{needle} missing from service.rs"))
        };
        let dumpable = at("libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)");
        assert!(dumpable < at("libc::setns("), "PR_SET_DUMPABLE after setns");
        assert!(dumpable < at("libc::fork()"), "PR_SET_DUMPABLE after fork");
    }

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
        let l = report_line(
            "sftpgo.service",
            284,
            950,
            9000,
            &g,
            &st,
            &Ok(36),
            false,
            false,
        );
        assert_eq!(
            l,
            "vantage: as sftpgo.service (pid 284): ns=all uid=950 gid=9000 \
                       groups=9000,950,+109000(unmapped) caps=0x400 umask=0002 nnp seccomp=36 · NOT: lsm,rlimits,securebits,keyring,seccomp-flags"
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
            false,
        );
        assert!(l.contains("nnp(added)"), "{l}");
        assert!(
            l.ends_with(
                "NOT: lsm,rlimits,securebits,keyring,seccomp (PTRACE_SEIZE: Operation not permitted)"
            ),
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
            false,
        );
        assert!(l.contains("umask=0022 no-nnp seccomp=none"), "{l}");
        assert!(l.ends_with("NOT: lsm,rlimits,securebits,keyring"), "{l}");
        assert!(!l.contains("root="), "{l}");
    }

    #[test]
    fn own_root_directory_is_named() {
        let st = Status {
            seccomp_mode: 0,
            ..Default::default()
        };
        let g = Groups {
            inner: vec![],
            unmapped: vec![],
        };
        let l = report_line("c.service", 7, 1, 1, &g, &st, &Ok(0), false, true);
        assert!(
            l.contains("seccomp=none root=own · NOT: lsm,rlimits,securebits,keyring"),
            "{l}"
        );
    }

    /// B108: Die Berichtszeile, wenn ptrace weniger Filter liefert, als der
    /// Kernel in status meldet -- `seccomp (…)` unter NOT, keine Zahl.
    #[test]
    fn a_short_filter_read_is_named_under_not() {
        let st = crate::proc_status::parse(SONARR);
        let read: Result<Vec<seccomp::Filter>, String> =
            Ok((0..35).map(|_| seccomp::Filter(vec![])).collect());
        let n = seccomp::checked(read, st.seccomp_filters).map(|f| f.len());
        let g = split_groups(SONARR_GID_MAP, &st.groups);
        let l = report_line("sonarr.service", 251, 274, 274, &g, &st, &n, false, false);
        assert!(l.contains(" seccomp=? "), "{l}");
        assert!(
            l.ends_with("seccomp (read 35 filters, the process has 36 (Seccomp_filters))"),
            "{l}"
        );
    }

    /// `fdinfo` so, wie der Kernel sie fuer ein pidfd schreibt (pidfs,
    /// 6.12: pos/flags/mnt_id/ino, dann Pid und NSpid).
    fn fdinfo(pid: &str, nspid: &str) -> String {
        format!(
            "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t4242\nPid:\t{pid}\nNSpid:\t{nspid}\n"
        )
    }

    #[test]
    fn restarted_service_is_noticed_through_the_pidfd() {
        assert!(still_main(&fdinfo("2001", "2001\t251"), 2001, 251, 2));
        assert!(!still_main(&fdinfo("2001", "2001\t252"), 2001, 251, 2));
        // Beendet und abgeraeumt: Pid -1, NSpid ebenso.
        assert!(!still_main(&fdinfo("-1", "-1"), 2001, 251, 2));
        assert!(!still_main("pos:\t0\n", 2001, 251, 2));
    }

    /// B108 (Audit-Beleg `a2_still_main_prueft_keinen_namensraum`): Ein
    /// WIRTSprozess mit Wirts-PID 4242 hat `NSpid:\t4242` -- ein Feld. Fuer
    /// die Gast-PID 4242 eines Gastes (Tiefe 2) besteht er nicht.
    #[test]
    fn a_host_process_is_not_the_guest_pid_of_the_same_number() {
        assert!(!still_main(&fdinfo("4242", "4242"), 4242, 4242, 2));
        assert!(!still_main("Name:\tsshd\nNSpid:\t4242\n", 4242, 4242, 2));
    }

    /// Gegen den echten Kernel: pidfd auf ein Kind, fdinfo lesen, Kind
    /// beenden und abraeumen, fdinfo noch einmal lesen.
    #[test]
    fn pidfd_fdinfo_of_a_real_process() {
        use std::os::fd::AsRawFd;
        let own = crate::proc_status::parse(&std::fs::read_to_string("/proc/self/status").unwrap());
        let depth = own.nspid.len();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let fd = pidfd_open(pid).unwrap();
        let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
        let info = std::fs::read_to_string(&path).unwrap();
        assert!(still_main(&info, pid, pid, depth), "{info}");
        assert!(!still_main(&info, pid, pid + 1, depth), "{info}");
        // Derselbe PID-Namensraum wie dieser Test; ein anderer Typ ist ein
        // anderer Inode.
        let own_pid_ns = std::fs::File::open("/proc/self/ns/pid").unwrap();
        assert!(same_ns(&own_pid_ns, &format!("/proc/{pid}/ns/pid")).unwrap());
        assert!(!same_ns(&own_pid_ns, &format!("/proc/{pid}/ns/net")).unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
        let info = std::fs::read_to_string(&path).unwrap();
        assert!(!still_main(&info, pid, pid, depth), "{info}");
    }

    #[test]
    fn roots_differ_is_a_plain_dev_ino_comparison() {
        // Same device, same inode — the common case (no RootDirectory=).
        assert!(!roots_differ((8, 100), (8, 100)));
        // Same device, own inode — RootDirectory= below the guest's root.
        assert!(roots_differ((8, 200), (8, 100)));
        // A confined unit can also sit on its own tmpfs/overlay device.
        assert!(roots_differ((9, 1), (8, 100)));
    }
}
