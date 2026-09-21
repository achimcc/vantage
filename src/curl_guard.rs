//! Refuses header- and credential-carrying curl options in argv.
//!
//! systemd logs the argv of a transient unit ("Started [systemd-run] curl -H
//! 'X-Api-Key: …'"), and the guest journal keeps it until the key is rotated.
//! This does not guess whether a value is secret — header options are simply
//! not allowed in argv. Headers go through --header / --header-file, which
//! vantage writes into a curlrc that never touches argv.

const FORBIDDEN_LONG: &[&str] = &[
    "--header",
    "--user",
    "--proxy-user",
    "--oauth2-bearer",
    "--proxy-header",
];
const FORBIDDEN_SHORT: &[char] = &['H', 'u', 'U'];
/// Short options that take a value: the rest of the cluster is that value.
const SHORT_WITH_VALUE: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

fn refuse(opt: &str) -> String {
    format!(
        "curl {opt} would put a header or credential into argv, and systemd writes argv into \
         the guest journal; use vantage --header 'Name: value' or --header-file 'Name=/path' instead"
    )
}

pub fn is_curl(program: &str) -> bool {
    program.rsplit('/').next() == Some("curl")
}

pub fn check(args: &[String]) -> Result<(), String> {
    for (i, a) in args.iter().enumerate() {
        if let Some(long) = a.strip_prefix("--") {
            if long.is_empty() {
                break;
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a.as_str(), None),
            };
            if FORBIDDEN_LONG.contains(&name) {
                return Err(refuse(name));
            }
            if name == "--config" {
                let v = inline.or(args.get(i + 1).map(String::as_str));
                if v == Some("-") {
                    return Err(refuse("--config -"));
                }
            }
        } else if let Some(cluster) = a.strip_prefix('-') {
            for (pos, c) in cluster.char_indices() {
                if FORBIDDEN_SHORT.contains(&c) {
                    return Err(refuse(&format!("-{c}")));
                }
                if c == 'K' {
                    let rest = &cluster[pos + 1..];
                    let v = if rest.is_empty() {
                        args.get(i + 1).map(String::as_str)
                    } else {
                        Some(rest)
                    };
                    if v == Some("-") {
                        return Err(refuse("-K -"));
                    }
                }
                if SHORT_WITH_VALUE.contains(c) {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn plain_args_pass() {
        assert!(check(&v(&[
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://x/"
        ]))
        .is_ok());
    }
    #[test]
    fn header_options_refused_in_every_spelling() {
        for a in [
            &["-H", "X: y"][..],
            &["--header", "X: y"],
            &["--header=X: y"],
            &["-sH", "X: y"],
            &["-HX: y"],
            &["-u", "a:b"],
            &["--user=a:b"],
            &["-U", "a:b"],
            &["--proxy-user", "a:b"],
            &["--oauth2-bearer", "t"],
            &["--proxy-header", "X: y"],
        ] {
            assert!(check(&v(a)).is_err(), "{a:?} must be refused");
        }
    }
    #[test]
    fn config_from_stdin_refused_file_allowed() {
        assert!(check(&v(&["-K", "-"])).is_err());
        assert!(check(&v(&["-K-"])).is_err());
        assert!(check(&v(&["--config=-"])).is_err());
        assert!(check(&v(&["--config", "-"])).is_err());
        assert!(check(&v(&["-K", "/run/rc"])).is_ok());
    }
    #[test]
    fn value_of_arg_option_is_not_scanned() {
        // -X takes the rest of the cluster as its value: "-XHEAD" is not -H.
        assert!(check(&v(&["-XHEAD", "http://x/"])).is_ok());
        assert!(check(&v(&["-sSo", "/dev/null"])).is_ok());
    }
    #[test]
    fn refusal_names_the_way_out_and_not_the_value() {
        let e = check(&v(&["-H", "X-Api-Key: geheim123"])).unwrap_err();
        assert!(e.contains("--header-file"));
        assert!(!e.contains("geheim123"));
    }
    #[test]
    fn is_curl_by_basename() {
        assert!(is_curl("curl"));
        assert!(is_curl("/run/current-system/sw/bin/curl"));
        assert!(!is_curl("/bin/curly"));
    }
}
