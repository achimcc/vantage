//! Guests as machined and the cgroup tree see them. Nothing here reads the
//! inventory of a particular repository: machined knows the machines, their
//! addresses and their leader.

use crate::host::Host;
use crate::proc_status;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_addresses(json: &str) -> Result<Vec<IpAddr>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("machined answer: {e}"))?;
    let list = v["data"][0]
        .as_array()
        .ok_or("machined answer: no address list")?;
    let mut out = Vec::new();
    for entry in list {
        let fam = entry[0].as_u64().unwrap_or(0);
        let bytes: Vec<u8> = entry[1]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|b| b.as_u64().map(|x| x as u8))
                    .collect()
            })
            .unwrap_or_default();
        match (fam, bytes.len()) {
            (2, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ))),
            (10, 16) => {
                let a: [u8; 16] = bytes.try_into().unwrap();
                out.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
    }
    Ok(out)
}

pub fn pick(addrs: &[IpAddr], v6: bool) -> Option<IpAddr> {
    addrs.iter().copied().find(|a| match a {
        IpAddr::V4(_) => !v6,
        IpAddr::V6(x) => v6 && (x.segments()[0] & 0xffc0) != 0xfe80,
    })
}

pub fn parse_show(out: &str, key: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
}

/// "0::/machine.slice/container@x.service/payload/init.scope" → the payload dir.
pub fn payload_dir(leader_cgroup: &str) -> Result<String, String> {
    let path = leader_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or("leader cgroup: no cgroup v2 line")?;
    let (dir, _) = path
        .trim_end()
        .rsplit_once('/')
        .ok_or("leader cgroup: unexpected path")?;
    Ok(format!("/sys/fs/cgroup{dir}"))
}

pub fn unit_name(unit: &str) -> String {
    if unit.contains('.') {
        unit.to_string()
    } else {
        format!("{unit}.service")
    }
}

pub fn leader(h: &dyn Host, guest: &str) -> Result<u32, String> {
    let o = h.cmd("machinectl", &["show", guest, "-p", "Leader"])?;
    parse_show(&o.stdout, "Leader")
        .and_then(|v| v.trim().parse().ok())
        .filter(|&p: &u32| o.code == 0 && p > 0)
        .ok_or(format!("no running machine '{guest}' (machinectl list)"))
}

pub fn addresses(h: &dyn Host, guest: &str) -> Result<Vec<IpAddr>, String> {
    let o = h.cmd(
        "busctl",
        &[
            "--json=short",
            "call",
            "org.freedesktop.machine1",
            "/org/freedesktop/machine1",
            "org.freedesktop.machine1.Manager",
            "GetMachineAddresses",
            "s",
            guest,
        ],
    )?;
    if o.code != 0 {
        return Err(format!(
            "machined has no addresses for '{guest}': {}",
            crate::text::visible(o.stderr.trim())
        ));
    }
    parse_addresses(&o.stdout)
}

/// The running main process of `unit` in `guest`: (host pid, guest pid).
pub fn service_host_pid(h: &dyn Host, guest: &str, unit: &str) -> Result<(u32, u32), String> {
    let unit = unit_name(unit);
    let l = leader(h, guest)?;
    let payload = payload_dir(&h.read(&format!("/proc/{l}/cgroup"))?)?;
    let procs = h
        .read(&format!("{payload}/system.slice/{unit}/cgroup.procs"))
        .map_err(|_| format!("{unit} has no cgroup in {guest} — is it running?"))?;
    let o = h.cmd("systemctl", &["-M", guest, "show", "-p", "MainPID", &unit])?;
    let main: u32 = parse_show(&o.stdout, "MainPID")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    if main == 0 {
        return Err(format!(
            "{unit} in {guest} has no running main process (MainPID=0)"
        ));
    }
    for pid in procs.split_whitespace() {
        if let Ok(st) = h.read(&format!("/proc/{pid}/status")) {
            if proc_status::parse(&st).nspid.last() == Some(&main) {
                return Ok((pid.parse().unwrap(), main));
            }
        }
    }
    Err(format!(
        "MainPID {main} of {unit} not found among the host processes of its cgroup"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn addresses_from_the_recorded_busctl_answer() {
        let a = parse_addresses(include_str!("../tests/fixtures/addresses-media-01.json")).unwrap();
        assert_eq!(
            pick(&a, false),
            Some("10.0.10.10".parse::<IpAddr>().unwrap())
        );
        let v6 = pick(&a, true).unwrap();
        assert!(v6.is_ipv6());
        assert!(
            !v6.to_string().starts_with("fe80"),
            "link-local is never the vantage point"
        );
    }
    #[test]
    fn show_output() {
        assert_eq!(
            parse_show("MainPID=251\nUser=sonarr\n", "MainPID").as_deref(),
            Some("251")
        );
        assert_eq!(parse_show("User=x\n", "MainPID"), None);
    }
    #[test]
    fn payload_dir_from_the_recorded_leader_cgroup() {
        let d = payload_dir(include_str!("../tests/fixtures/leader-cgroup.txt")).unwrap();
        assert_eq!(
            d,
            "/sys/fs/cgroup/machine.slice/container@media-01.service/payload"
        );
    }
    #[test]
    fn unit_names() {
        assert_eq!(unit_name("sonarr"), "sonarr.service");
        assert_eq!(unit_name("sonarr.service"), "sonarr.service");
    }
    #[test]
    fn service_host_pid_maps_main_pid_through_nspid() {
        use crate::host::fake::Fake;
        let payload = "/sys/fs/cgroup/machine.slice/container@media-01.service/payload";
        let h = Fake::default()
            .on("machinectl show media-01 -p Leader", 0, "Leader=1000\n")
            .file(
                "/proc/1000/cgroup",
                "0::/machine.slice/container@media-01.service/payload/init.scope\n",
            )
            .file(
                &format!("{payload}/system.slice/sonarr.service/cgroup.procs"),
                "2000\n2001\n",
            )
            .on(
                "systemctl -M media-01 show -p MainPID sonarr.service",
                0,
                "MainPID=251\n",
            )
            .file("/proc/2000/status", "NSpid:\t2000\t250\n")
            .file("/proc/2001/status", "NSpid:\t2001\t251\n");
        assert_eq!(
            service_host_pid(&h, "media-01", "sonarr").unwrap(),
            (2001, 251)
        );
    }
    #[test]
    fn service_without_main_pid_is_an_error() {
        use crate::host::fake::Fake;
        let payload = "/sys/fs/cgroup/machine.slice/container@m.service/payload";
        let h = Fake::default()
            .on("machinectl show m -p Leader", 0, "Leader=1\n")
            .file(
                "/proc/1/cgroup",
                "0::/machine.slice/container@m.service/payload/init.scope\n",
            )
            .file(
                &format!("{payload}/system.slice/x.service/cgroup.procs"),
                "",
            )
            .on("systemctl -M m show -p MainPID x.service", 0, "MainPID=0\n");
        assert!(service_host_pid(&h, "m", "x")
            .unwrap_err()
            .contains("MainPID=0"));
    }
}
