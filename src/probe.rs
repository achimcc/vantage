//! `vantage probe --from A B:port`: curl from guest A to B's zone address,
//! then — on a timeout — the host journal for the drop line of exactly this
//! probe. vantage chooses curl's source port (--local-port) itself, because
//! `%{local_port}` is empty after a connect timeout, and the kernel log line
//! carries SPT= (spike 2026-09-21, point 6).

use crate::cli::ProbeArgs;
use crate::config::Config;
use crate::host::{Host, PROFILE};
use crate::machine;
use std::net::IpAddr;

#[derive(Debug)]
pub enum Verdict {
    Answered(String),
    Refused,
    DroppedAtEdge,
    DroppedElsewhere,
    TimedOutUnknown,
}

impl Verdict {
    pub fn exit_code(&self) -> i32 {
        if matches!(self, Verdict::Answered(_)) {
            0
        } else {
            1
        }
    }
    pub fn text(&self) -> String {
        match self {
            Verdict::Answered(c) => format!("answered {c}"),
            Verdict::Refused => {
                "refused (RST: nothing listens, or the target's firewall rejects)".into()
            }
            Verdict::DroppedAtEdge => {
                "dropped at zone edge — the host's forward chain, not the service; \
                an edge belongs in the declared set only if a SERVICE needs this path"
                    .into()
            }
            Verdict::DroppedElsewhere => {
                "dropped elsewhere — timeout without a drop line on the host: \
                the source's egress lock or the target's own firewall"
                    .into()
            }
            Verdict::TimedOutUnknown => "timed out (no drop_log_prefix in /etc/vantage.toml — \
                zone edge vs. elsewhere unknown)"
                .into(),
        }
    }
}

pub fn verdict(
    curl_exit: i32,
    http_code: &str,
    drop_seen: Option<bool>,
) -> Result<Verdict, String> {
    match curl_exit {
        0 => Ok(Verdict::Answered(http_code.to_string())),
        // TCP connected, but no (complete) HTTP answer: the path is open.
        35 | 52 | 56 => Ok(Verdict::Answered(format!(
            "no HTTP response (curl exit {curl_exit})"
        ))),
        7 => Ok(Verdict::Refused),
        28 => Ok(match drop_seen {
            Some(true) => Verdict::DroppedAtEdge,
            Some(false) => Verdict::DroppedElsewhere,
            None => Verdict::TimedOutUnknown,
        }),
        127 | 203 => Err("curl is not in the profile of the source guest".into()),
        c => Err(format!(
            "curl failed with exit {c} — no statement about the path"
        )),
    }
}

/// Addresses as nf_log writes them: v4 dotted, v6 as eight full groups (%pI6).
pub fn kernel_addr(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => a
            .segments()
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

pub fn matches(
    line: &str,
    prefix: &str,
    src: &IpAddr,
    dst: &IpAddr,
    sport: u16,
    dport: u16,
) -> bool {
    line.contains(prefix)
        && line.contains(&format!(" SRC={} ", kernel_addr(src)))
        && line.contains(&format!(" DST={} ", kernel_addr(dst)))
        && line.contains(&format!(" SPT={sport} "))
        && line.contains(&format!(" DPT={dport} "))
}

/// A source port in 40000..60000 that differs between parallel probes.
pub fn source_port(pid: u32, now: u64) -> u16 {
    40000 + ((pid as u64).wrapping_mul(2654435761) ^ now) as u16 % 20000
}

pub fn probe(h: &dyn Host, cfg: &Config, a: &ProbeArgs) -> i32 {
    probe_with_port(h, cfg, a, source_port(std::process::id(), h.now()))
}

pub fn probe_with_port(h: &dyn Host, cfg: &Config, a: &ProbeArgs, sport: u16) -> i32 {
    let addr = |g: &str| -> Result<IpAddr, String> {
        let all = machine::addresses(h, g)?;
        machine::pick(&all, a.v6).ok_or(format!(
            "{g} has no {} address",
            if a.v6 { "v6" } else { "v4" }
        ))
    };
    let (src, dst) = match (addr(&a.from), addr(&a.target)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("vantage: {e}");
            return 2;
        }
    };
    let host = match dst {
        IpAddr::V6(d) => format!("[{d}]"),
        IpAddr::V4(d) => d.to_string(),
    };
    let url = format!("http://{host}:{}{}", a.port, a.path);
    let t0 = h.now();
    let machine_arg = format!("--machine={}", a.from);
    let curl = format!("{PROFILE}/curl");
    let sport_s = sport.to_string();
    let out = match h.cmd(
        "systemd-run",
        &[
            &machine_arg,
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--",
            &curl,
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "6",
            "--local-port",
            &sport_s,
            &url,
        ],
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("vantage: {e}");
            return 2;
        }
    };
    let drop_seen = if out.code == 28 {
        match &cfg.drop_log_prefix {
            None => None,
            Some(p) => {
                let since = format!("@{}", t0.saturating_sub(1));
                let mut seen = false;
                for attempt in 0..2 {
                    if attempt > 0 {
                        h.sleep_ms(1000);
                    }
                    match h.cmd(
                        "journalctl",
                        &["--no-pager", "-o", "cat", "--since", &since, "--grep", p],
                    ) {
                        Ok(j) if j.code == 0 || j.code == 1 => {
                            seen = j
                                .stdout
                                .lines()
                                .any(|l| matches(l, p, &src, &dst, sport, a.port));
                        }
                        Ok(j) => {
                            eprintln!("vantage: journalctl: {}", j.stderr.trim());
                            return 2;
                        }
                        Err(e) => {
                            eprintln!("vantage: {e}");
                            return 2;
                        }
                    }
                    if seen {
                        break;
                    }
                }
                Some(seen)
            }
        }
    } else {
        None
    };
    match verdict(out.code, out.stdout.trim(), drop_seen) {
        Ok(v) => {
            println!(
                "vantage: probe {} ({src}) -> {} ({dst}):{}{} sport {sport}: {}",
                a.from,
                a.target,
                a.port,
                a.path,
                v.text()
            );
            v.exit_code()
        }
        Err(e) => {
            eprintln!("vantage: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::Fake;
    use std::net::IpAddr;
    const LINE: &str = include_str!("../tests/fixtures/drop-line.txt");
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn verdict_table() {
        assert!(matches!(verdict(0, "200", None), Ok(Verdict::Answered(c)) if c == "200"));
        assert!(matches!(verdict(0, "401", None), Ok(Verdict::Answered(_))));
        assert!(
            matches!(verdict(52, "000", None), Ok(Verdict::Answered(c)) if c.contains("curl exit 52"))
        );
        assert!(matches!(verdict(7, "000", None), Ok(Verdict::Refused)));
        assert!(matches!(
            verdict(28, "000", Some(true)),
            Ok(Verdict::DroppedAtEdge)
        ));
        assert!(matches!(
            verdict(28, "000", Some(false)),
            Ok(Verdict::DroppedElsewhere)
        ));
        assert!(matches!(
            verdict(28, "000", None),
            Ok(Verdict::TimedOutUnknown)
        ));
        assert!(verdict(127, "", None).unwrap_err().contains("curl"));
        assert!(verdict(6, "000", None).is_err());
    }
    #[test]
    fn exit_codes() {
        assert_eq!(Verdict::Answered("200".into()).exit_code(), 0);
        for v in [
            Verdict::Refused,
            Verdict::DroppedAtEdge,
            Verdict::DroppedElsewhere,
            Verdict::TimedOutUnknown,
        ] {
            assert_eq!(v.exit_code(), 1);
        }
    }
    #[test]
    fn recorded_drop_line_matches_only_its_own_probe() {
        let (s, d) = (ip("10.0.110.10"), ip("10.0.10.10"));
        assert!(matches(LINE, "zonenkante-ungedeckt", &s, &d, 46576, 47113));
        assert!(
            !matches(LINE, "zonenkante-ungedeckt", &s, &d, 46577, 47113),
            "another source port is another probe"
        );
        assert!(!matches(LINE, "zonenkante-ungedeckt", &s, &d, 46576, 4711));
        assert!(!matches(
            LINE,
            "zonenkante-ungedeckt",
            &ip("10.0.110.1"),
            &d,
            46576,
            47113
        ));
        assert!(!matches(LINE, "anderes-praefix", &s, &d, 46576, 47113));
    }
    #[test]
    fn v6_is_written_like_the_kernel_log() {
        assert_eq!(
            kernel_addr(&ip("fd00::10")),
            "fd00:0000:0000:0000:0000:0000:0000:0010"
        );
        assert_eq!(kernel_addr(&ip("10.0.1.2")), "10.0.1.2");
    }

    fn addr_json(a: [u8; 4]) -> String {
        format!(
            "{{\"type\":\"a(iay)\",\"data\":[[[2,[{},{},{},{}]]]]}}",
            a[0], a[1], a[2], a[3]
        )
    }
    fn busctl(g: &str) -> String {
        format!(
            "busctl --json=short call org.freedesktop.machine1 /org/freedesktop/machine1 org.freedesktop.machine1.Manager GetMachineAddresses s {g}"
        )
    }

    #[test]
    fn timeout_with_our_drop_line_is_the_zone_edge() {
        let a = ProbeArgs {
            from: "koch-01".into(),
            target: "media-01".into(),
            port: 47113,
            path: "/".into(),
            v6: false,
        };
        let cfg = Config {
            drop_log_prefix: Some("zonenkante-ungedeckt".into()),
        };
        let sport = source_port(4242, 1000);
        let curl = format!(
            "systemd-run --machine=koch-01 --wait --pipe --quiet --collect -- /run/current-system/sw/bin/curl -sS -o /dev/null -w %{{http_code}} --max-time 6 --local-port {sport} http://10.0.10.10:47113/"
        );
        let line = LINE.replace("SPT=46576", &format!("SPT={sport}"));
        let h = Fake {
            now: 1000,
            ..Default::default()
        }
        .on(&busctl("koch-01"), 0, &addr_json([10, 0, 110, 10]))
        .on(&busctl("media-01"), 0, &addr_json([10, 0, 10, 10]))
        .on(&curl, 28, "000")
        .on(
            "journalctl --no-pager -o cat --since @999 --grep zonenkante-ungedeckt",
            0,
            &line,
        );
        assert_eq!(probe_with_port(&h, &cfg, &a, sport), 1);
        assert!(h.asked.borrow().iter().any(|q| q.starts_with("journalctl")));
    }
}
