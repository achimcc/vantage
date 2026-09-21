//! `vantage where <guest>`: the vantage point itself — addresses, which
//! measuring tools the guest's profile has, and the running units.

use crate::host::{Host, PROFILE};
use crate::machine;

const TOOLS: &[&str] = &["curl", "socat", "jq", "bash", "findmnt"];

pub fn run(h: &dyn Host, guest: &str) -> Result<String, String> {
    let leader = machine::leader(h, guest)?;
    let addrs = machine::addresses(h, guest)?;
    let payload = machine::payload_dir(&h.read(&format!("/proc/{leader}/cgroup"))?)?;
    let mut t = format!("{guest} (leader pid {leader})\n  addresses: ");
    t.push_str(
        &addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    t.push_str("\n  tools:");
    for tool in TOOLS {
        let yes = h.exists(&format!("/proc/{leader}/root{PROFILE}/{tool}"));
        t.push_str(&format!(" {tool} {}", if yes { "yes" } else { "no" }));
    }
    t.push_str("\n  running units:\n");
    let slice = format!("{payload}/system.slice");
    for u in h.list_dir(&slice)? {
        if !u.ends_with(".service") {
            continue;
        }
        if let Ok(p) = h.read(&format!("{slice}/{u}/cgroup.procs")) {
            if let Some(first) = p.split_whitespace().next() {
                t.push_str(&format!("    {u} (host pid {first})\n"));
            }
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::Fake;
    #[test]
    fn lists_addresses_tools_and_running_units() {
        let payload = "/sys/fs/cgroup/machine.slice/container@g.service/payload";
        let mut h = Fake::default()
            .on("machinectl show g -p Leader", 0, "Leader=77\n")
            .on("busctl --json=short call org.freedesktop.machine1 /org/freedesktop/machine1 org.freedesktop.machine1.Manager GetMachineAddresses s g",
                0, "{\"type\":\"a(iay)\",\"data\":[[[2,[10,0,1,10]]]]}")
            .file("/proc/77/cgroup", "0::/machine.slice/container@g.service/payload/init.scope\n")
            .file("/proc/77/root/run/current-system/sw/bin/curl", "")
            .file(&format!("{payload}/system.slice/a.service/cgroup.procs"), "5\n")
            .file(&format!("{payload}/system.slice/b.service/cgroup.procs"), "");
        h.dirs.insert(
            format!("{payload}/system.slice"),
            vec!["a.service".into(), "b.service".into(), "x.slice".into()],
        );
        let t = run(&h, "g").unwrap();
        assert!(t.contains("10.0.1.10"), "{t}");
        assert!(t.contains("curl yes") && t.contains("socat no"), "{t}");
        assert!(t.contains("a.service (host pid 5)"), "{t}");
        assert!(
            !t.contains("b.service"),
            "units without a process are not running: {t}"
        );
    }
}
