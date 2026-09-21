//! `/proc/<pid>/status` and `uid_map`/`gid_map`, read from the host.
//! IDs in status are host IDs (the reader's namespace); the map translates
//! them into the IDs of the process's own user namespace.

#[derive(Debug, PartialEq, Clone)]
pub struct Status {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
    pub no_new_privs: bool,
    pub seccomp_mode: u32,
    pub seccomp_filters: u32,
    pub nspid: Vec<u32>,
    /// File mode creation mask (octal in status). 0o022 if the kernel does not report it.
    pub umask: u32,
}

impl Default for Status {
    fn default() -> Self {
        Status {
            uid: 0,
            gid: 0,
            groups: vec![],
            cap_inh: 0,
            cap_prm: 0,
            cap_eff: 0,
            cap_bnd: 0,
            cap_amb: 0,
            no_new_privs: false,
            seccomp_mode: 0,
            seccomp_filters: 0,
            nspid: vec![],
            umask: 0o022,
        }
    }
}

fn nums(s: &str) -> Vec<u32> {
    s.split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect()
}
fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim(), 16).unwrap_or(0)
}

pub fn parse(s: &str) -> Status {
    let mut st = Status::default();
    for line in s.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k {
            // Real, effective, saved, fs — the effective ID decides access.
            "Uid" => st.uid = nums(v).get(1).copied().unwrap_or(0),
            "Gid" => st.gid = nums(v).get(1).copied().unwrap_or(0),
            "Groups" => st.groups = nums(v),
            "CapInh" => st.cap_inh = hex(v),
            "CapPrm" => st.cap_prm = hex(v),
            "CapEff" => st.cap_eff = hex(v),
            "CapBnd" => st.cap_bnd = hex(v),
            "CapAmb" => st.cap_amb = hex(v),
            "NoNewPrivs" => st.no_new_privs = v.trim() == "1",
            "Seccomp" => st.seccomp_mode = v.trim().parse().unwrap_or(0),
            "Seccomp_filters" => st.seccomp_filters = v.trim().parse().unwrap_or(0),
            "NSpid" => st.nspid = nums(v),
            "Umask" => st.umask = u32::from_str_radix(v.trim(), 8).unwrap_or(0o022),
            _ => {}
        }
    }
    st
}

/// Host ID → ID inside the namespace described by `map` ("inside outside count" lines).
pub fn map_to_inner(map: &str, host_id: u32) -> Option<u32> {
    for line in map.lines() {
        let n: Vec<u64> = line
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if let [inside, outside, count] = n[..] {
            let h = host_id as u64;
            if h >= outside && h < outside + count {
                return Some((inside + (h - outside)) as u32);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    const SFTPGO: &str = include_str!("../tests/fixtures/status-sftpgo.txt");
    const SONARR: &str = include_str!("../tests/fixtures/status-sonarr.txt");
    const SONARR_GID_MAP: &str = include_str!("../tests/fixtures/gid_map-sonarr.txt");

    #[test]
    fn umask_defaults_to_022_when_absent() {
        assert_eq!(parse("Uid:\t1\t1\t1\t1\n").umask, 0o022);
    }

    #[test]
    fn parses_the_recorded_sftpgo_status() {
        let s = parse(SFTPGO);
        assert_eq!(s.uid, 700950);
        assert_eq!(s.cap_bnd, 0x400);
        assert_eq!(s.cap_eff, 0x400);
        assert!(s.no_new_privs);
        assert_eq!(s.seccomp_mode, 2);
        assert_eq!(s.seccomp_filters, 36);
        assert_eq!(s.nspid.len(), 2);
        assert_eq!(s.umask, 0o002, "recorded: 'Umask:\t0002'");
        // Recorded fixture: NSpid ends on 194, not the 284 the plan guessed.
        assert_eq!(*s.nspid.last().unwrap(), 194);
    }
    #[test]
    fn sonarr_carries_a_group_its_namespace_cannot_see() {
        let s = parse(SONARR);
        assert!(s.groups.contains(&109000));
        assert_eq!(map_to_inner(SONARR_GID_MAP, 109000), None);
        assert!(map_to_inner(SONARR_GID_MAP, s.gid).is_some());
    }
    #[test]
    fn map_to_inner_ranges() {
        let m = "         0     700000      65536\n";
        assert_eq!(map_to_inner(m, 700950), Some(950));
        assert_eq!(map_to_inner(m, 765536), None);
        assert_eq!(map_to_inner(m, 1), None);
    }
}
