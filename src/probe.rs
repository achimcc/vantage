//! `vantage probe --from A B:port`: curl from guest A to B's zone address,
//! then — on a connect timeout — the host journal for the drop line of
//! exactly this probe. vantage chooses curl's source port (--local-port)
//! itself, because `%{local_port}` is empty after a connect timeout, and the
//! kernel log line carries SPT= (spike 2026-09-21, point 6).
//!
//! `%{time_connect}` tells a timeout BEFORE the connection (a drop somewhere)
//! from one AFTER it (the service accepted and did not answer in time): only
//! the first kind is a question for the drop log.

use crate::cli::ProbeArgs;
use crate::config::Config;
use crate::host::{Host, PROFILE};
use crate::machine;
use std::net::IpAddr;

const MAX_TIME: &str = "6";

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
            // curl's exit 7 is an RST as much as an ICMP reject or
            // EHOSTUNREACH — curl's own line (printed after this) says which.
            Verdict::Refused => "refused (connection refused or host unreachable)".into(),
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

/// curl's `-w '%{http_code} %{time_connect}'` → (code, seconds to connect).
/// `time_connect` is 0 when no connection was made.
pub fn parse_write_out(w: &str) -> Result<(String, f64), String> {
    let mut it = w.split_whitespace();
    let (Some(code), Some(tc), None) = (it.next(), it.next(), it.next()) else {
        return Err(format!(
            "curl's -w output is not '<code> <time_connect>': {w:?}"
        ));
    };
    let tc: f64 = tc
        .parse()
        .map_err(|_| format!("curl's time_connect is not a number: {tc:?}"))?;
    Ok((code.to_string(), tc))
}

pub fn verdict(
    curl_exit: i32,
    http_code: &str,
    time_connect: f64,
    drop_seen: Option<bool>,
) -> Result<Verdict, String> {
    match curl_exit {
        0 => Ok(Verdict::Answered(http_code.to_string())),
        // TCP connected, but no (complete) HTTP answer: the path is open.
        35 | 52 | 56 => Ok(Verdict::Answered(format!(
            "no HTTP response (curl exit {curl_exit})"
        ))),
        7 => Ok(Verdict::Refused),
        // Connected, then no answer within --max-time: a slow service.
        28 if time_connect > 0.0 => Ok(Verdict::Answered(format!(
            "no HTTP response within {MAX_TIME} s"
        ))),
        28 => Ok(match drop_seen {
            Some(true) => Verdict::DroppedAtEdge,
            Some(false) => Verdict::DroppedElsewhere,
            None => Verdict::TimedOutUnknown,
        }),
        127 | 203 => Err("curl is not in the profile of the source guest".into()),
        45 => Err(
            "curl could not bind its source port (exit 45) — no statement about the path".into(),
        ),
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

/// The drop line of THIS probe: prefix, destination and both ports. SRC= is
/// not required — a guest can have several addresses, and the source port
/// vantage chose already singles out the probe.
pub fn matches(line: &str, prefix: &str, dst: &IpAddr, sport: u16, dport: u16) -> bool {
    line.contains(prefix)
        && line.contains(&format!(" DST={} ", kernel_addr(dst)))
        && line.contains(&format!(" SPT={sport} "))
        && line.contains(&format!(" DPT={dport} "))
}

/// A source port in 40000..60000 that differs between parallel probes.
pub fn source_port(pid: u32, now: u64) -> u16 {
    40000 + ((pid as u64).wrapping_mul(2654435761) ^ now) as u16 % 20000
}

/// The port for the first attempt and a different one for the single retry
/// after curl's exit 45 (local port in use).
pub fn source_ports(pid: u32, now: u64) -> (u16, u16) {
    let a = source_port(pid, now);
    let mut b = source_port(pid, now + 1);
    if b == a {
        b = 40000 + (a - 40000 + 1) % 20000;
    }
    (a, b)
}

/// The verdict line, and for `refused` curl's own first stderr line — it
/// says whether it was a refusal or an unreachable host.
///
/// Both carry text from the SOURCE guest (the HTTP code curl wrote there, its
/// stderr): every control character is made visible (B81).
pub fn report_lines(head: &str, v: &Verdict, curl_stderr: &str) -> Vec<String> {
    let mut out = vec![format!("vantage: {head}: {}", v.text())];
    if matches!(v, Verdict::Refused) {
        if let Some(l) = curl_stderr.lines().map(str::trim).find(|l| !l.is_empty()) {
            out.push(format!("vantage: curl said: {l}"));
        }
    }
    out.into_iter().map(|l| crate::text::visible(&l)).collect()
}

pub fn probe(h: &dyn Host, cfg: &Config, a: &ProbeArgs) -> i32 {
    probe_with_ports(h, cfg, a, source_ports(std::process::id(), h.now()))
}

fn run_curl(
    h: &dyn Host,
    a: &ProbeArgs,
    url: &str,
    sport: u16,
) -> Result<crate::host::Out, String> {
    let machine_arg = format!("--machine={}", a.from);
    let curl = format!("{PROFILE}/curl");
    let sport_s = sport.to_string();
    h.cmd(
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
            "%{http_code} %{time_connect}",
            "--max-time",
            MAX_TIME,
            "--local-port",
            &sport_s,
            url,
        ],
    )
}

pub fn probe_with_ports(h: &dyn Host, cfg: &Config, a: &ProbeArgs, ports: (u16, u16)) -> i32 {
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
            eprintln!("vantage: {}", crate::text::visible(&e));
            return 2;
        }
    };
    let host = match dst {
        IpAddr::V6(d) => format!("[{d}]"),
        IpAddr::V4(d) => d.to_string(),
    };
    let url = format!("http://{host}:{}{}", a.port, a.path);
    let t0 = h.now();
    let mut sport = ports.0;
    let mut out = match run_curl(h, a, &url, sport) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("vantage: {}", crate::text::visible(&e));
            return 2;
        }
    };
    if out.code == 45 {
        // The chosen source port was taken; one more try with another.
        sport = ports.1;
        out = match run_curl(h, a, &url, sport) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("vantage: {}", crate::text::visible(&e));
                return 2;
            }
        };
    }
    let (code, time_connect) = match out.code {
        // Only these carry a -w line vantage relies on.
        0 | 7 | 28 | 35 | 52 | 56 => match parse_write_out(&out.stdout) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("vantage: {}", crate::text::visible(&e));
                return 2;
            }
        },
        _ => (String::new(), 0.0),
    };
    let drop_seen = if out.code == 28 && time_connect == 0.0 {
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
                        // Only the kernel's own lines: a guest writes to its
                        // console, and that lands in the host journal too
                        // (container@<g>.service, _TRANSPORT=stdout) -- a
                        // forged drop line there must not count (audit 3,
                        // A1-6). A match, not `-k`: that implies `-b`.
                        &[
                            "--no-pager",
                            "-o",
                            "cat",
                            "--since",
                            &since,
                            "--grep",
                            p,
                            "_TRANSPORT=kernel",
                        ],
                    ) {
                        Ok(j) if j.code == 0 || j.code == 1 => {
                            seen = j.stdout.lines().any(|l| matches(l, p, &dst, sport, a.port));
                        }
                        Ok(j) => {
                            eprintln!(
                                "vantage: journalctl: {}",
                                crate::text::visible(j.stderr.trim())
                            );
                            return 2;
                        }
                        Err(e) => {
                            eprintln!("vantage: {}", crate::text::visible(&e));
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
    match verdict(out.code, &code, time_connect, drop_seen) {
        Ok(v) => {
            let head = format!(
                "probe {} ({src}) -> {} ({dst}):{}{} sport {sport}",
                a.from, a.target, a.port, a.path
            );
            for l in report_lines(&head, &v, &out.stderr) {
                println!("{l}");
            }
            v.exit_code()
        }
        Err(e) => {
            eprintln!("vantage: {}", crate::text::visible(&e));
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
        assert!(matches!(verdict(0, "200", 0.001, None), Ok(Verdict::Answered(c)) if c == "200"));
        assert!(matches!(
            verdict(0, "401", 0.001, None),
            Ok(Verdict::Answered(_))
        ));
        assert!(
            matches!(verdict(52, "000", 0.001, None), Ok(Verdict::Answered(c)) if c.contains("curl exit 52"))
        );
        assert!(matches!(verdict(7, "000", 0.0, None), Ok(Verdict::Refused)));
        assert!(matches!(
            verdict(28, "000", 0.0, Some(true)),
            Ok(Verdict::DroppedAtEdge)
        ));
        assert!(matches!(
            verdict(28, "000", 0.0, Some(false)),
            Ok(Verdict::DroppedElsewhere)
        ));
        assert!(matches!(
            verdict(28, "000", 0.0, None),
            Ok(Verdict::TimedOutUnknown)
        ));
        assert!(verdict(127, "", 0.0, None).unwrap_err().contains("curl"));
        assert!(verdict(6, "000", 0.0, None).is_err());
        assert!(verdict(45, "000", 0.0, None).is_err());
    }
    #[test]
    fn timeout_after_connect_is_a_slow_service_not_a_drop() {
        // The connection was accepted (time_connect > 0): whatever the drop
        // log says, the path is open — the service just did not answer.
        for seen in [None, Some(false), Some(true)] {
            let v = verdict(28, "000", 0.000412, seen).unwrap();
            assert!(
                matches!(&v, Verdict::Answered(c) if c == "no HTTP response within 6 s"),
                "{v:?}"
            );
            assert_eq!(v.exit_code(), 0);
        }
    }
    #[test]
    fn refused_does_not_claim_an_rst() {
        let t = Verdict::Refused.text();
        assert!(t.contains("connection refused or host unreachable"), "{t}");
        assert!(!t.contains("RST"), "{t}");
    }
    #[test]
    fn write_out_is_code_and_connect_time() {
        assert_eq!(
            parse_write_out("200 0.001234").unwrap(),
            ("200".into(), 0.001234)
        );
        assert_eq!(
            parse_write_out("000 0.000000\n").unwrap(),
            ("000".into(), 0.0)
        );
        assert!(parse_write_out("").is_err());
        assert!(parse_write_out("000").is_err());
        assert!(parse_write_out("000 x").is_err());
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
        let d = ip("10.0.10.10");
        assert!(matches(LINE, "zonenkante-ungedeckt", &d, 46576, 47113));
        assert!(
            !matches(LINE, "zonenkante-ungedeckt", &d, 46577, 47113),
            "another source port is another probe"
        );
        assert!(!matches(LINE, "zonenkante-ungedeckt", &d, 46576, 4711));
        assert!(!matches(
            LINE,
            "zonenkante-ungedeckt",
            &ip("10.0.10.1"),
            46576,
            47113
        ));
        assert!(!matches(LINE, "anderes-praefix", &d, 46576, 47113));
    }
    #[test]
    fn v6_is_written_like_the_kernel_log() {
        assert_eq!(
            kernel_addr(&ip("fd00::10")),
            "fd00:0000:0000:0000:0000:0000:0000:0010"
        );
        assert_eq!(kernel_addr(&ip("10.0.1.2")), "10.0.1.2");
    }
    #[test]
    fn retry_port_differs_from_the_first() {
        for pid in [1u32, 4242, 99999] {
            for now in [0u64, 1000, 1_700_000_000] {
                let (a, b) = source_ports(pid, now);
                assert_ne!(a, b);
                assert!((40000..60000).contains(&a) && (40000..60000).contains(&b));
            }
        }
    }
    #[test]
    fn refused_report_carries_curls_own_first_line() {
        let r = report_lines(
            "probe x",
            &Verdict::Refused,
            "curl: (7) Failed to connect to 10.0.10.10 port 80: No route to host\nmore\n",
        );
        assert_eq!(r.len(), 2, "{r:?}");
        assert!(r[0].contains("refused"), "{r:?}");
        assert_eq!(
            r[1],
            "vantage: curl said: curl: (7) Failed to connect to 10.0.10.10 port 80: No route to host"
        );
        assert_eq!(
            report_lines("probe x", &Verdict::Refused, "  \n").len(),
            1,
            "no empty curl line"
        );
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
    fn curl_cmd(sport: u16) -> String {
        format!(
            "systemd-run --machine=koch-01 --wait --pipe --quiet --collect -- /run/current-system/sw/bin/curl -sS -o /dev/null -w %{{http_code}} %{{time_connect}} --max-time 6 --local-port {sport} http://10.0.10.10:47113/"
        )
    }
    fn args() -> ProbeArgs {
        ProbeArgs {
            from: "koch-01".into(),
            target: "media-01".into(),
            port: 47113,
            path: "/".into(),
            v6: false,
        }
    }
    fn cfg() -> Config {
        Config {
            drop_log_prefix: Some("zonenkante-ungedeckt".into()),
        }
    }
    fn guests() -> Fake {
        Fake {
            now: 1000,
            ..Default::default()
        }
        .on(&busctl("koch-01"), 0, &addr_json([10, 0, 110, 10]))
        .on(&busctl("media-01"), 0, &addr_json([10, 0, 10, 10]))
    }

    #[test]
    fn timeout_with_our_drop_line_is_the_zone_edge() {
        let sport = 46001;
        let line = LINE.replace("SPT=46576", &format!("SPT={sport}"));
        let h = guests().on(&curl_cmd(sport), 28, "000 0.000000").on(
            "journalctl --no-pager -o cat --since @999 --grep zonenkante-ungedeckt _TRANSPORT=kernel",
            0,
            &line,
        );
        assert_eq!(probe_with_ports(&h, &cfg(), &args(), (sport, 46002)), 1);
        assert!(h.asked.borrow().iter().any(|q| q.starts_with("journalctl")));
    }
    #[test]
    fn slow_service_is_answered_and_never_asks_the_journal() {
        let sport = 46001;
        let h = guests().on(&curl_cmd(sport), 28, "000 0.000412");
        assert_eq!(probe_with_ports(&h, &cfg(), &args(), (sport, 46002)), 0);
        assert!(!h.asked.borrow().iter().any(|q| q.starts_with("journalctl")));
    }
    #[test]
    fn port_in_use_is_retried_once_with_the_second_port() {
        let h = guests().on(&curl_cmd(46001), 45, "000 0.000000").on(
            &curl_cmd(46002),
            0,
            "200 0.000300",
        );
        assert_eq!(probe_with_ports(&h, &cfg(), &args(), (46001, 46002)), 0);
        let h = guests().on(&curl_cmd(46001), 45, "000 0.000000").on(
            &curl_cmd(46002),
            45,
            "000 0.000000",
        );
        assert_eq!(
            probe_with_ports(&h, &cfg(), &args(), (46001, 46002)),
            2,
            "a second 45 is a tool error"
        );
    }
    #[test]
    fn refused_is_a_finding_with_curls_stderr() {
        let h = guests().on_err(
            &curl_cmd(46001),
            7,
            "000 0.000000",
            "curl: (7) Failed to connect\n",
        );
        assert_eq!(probe_with_ports(&h, &cfg(), &args(), (46001, 46002)), 1);
    }

    /// B81: what the source guest wrote (its HTTP code, curl's stderr) never
    /// reaches the terminal with a control character in it.
    #[test]
    fn guest_text_in_the_report_carries_no_control_byte() {
        let v = Verdict::Refused;
        let lines = report_lines(
            "probe a -> b",
            &v,
            "curl: (7) \x1b]52;c;S0FOQVJJRQ==\x07\x1b[2J boom\n",
        );
        assert_eq!(lines.len(), 2);
        for l in &lines {
            assert!(!l.bytes().any(|b| b < 0x20 || b == 0x7f), "{l:?}");
        }
        assert!(lines[1].contains("\\x1b]52;"), "{:?}", lines[1]);
        let answered = report_lines("probe a -> b", &Verdict::Answered("\x1b[2J200".into()), "");
        assert!(!answered[0].contains('\x1b'), "{:?}", answered[0]);
    }
}
