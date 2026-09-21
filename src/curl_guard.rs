//! Refuses header- and credential-carrying curl options in argv.
//!
//! systemd logs the argv of a transient unit ("Started [systemd-run] curl -H
//! 'X-Api-Key: …'"), and the guest journal keeps it until the key is rotated.
//! This does not guess whether a value is secret — header options are simply
//! not allowed in argv. Headers go through --header / --header-file, which
//! vantage writes into a curlrc that never touches argv.
//!
//! A second check, [`check_no_echo`], applies once a --header-file is in
//! play: options that print the request headers (and so the secret) to the
//! terminal are refused too.

const FORBIDDEN_LONG: &[&str] = &[
    "--header",
    "--user",
    "--proxy-user",
    "--oauth2-bearer",
    "--proxy-header",
];
/// Real curl options in their own right that happen to be prefixes of a
/// forbidden name (`--head` of `--header`, `--proxy` of `--proxy-user` and
/// `--proxy-header`) and must stay allowed despite the prefix rule below.
const LONG_PREFIX_EXCEPTIONS: &[&str] = &["--head", "--proxy"];
const FORBIDDEN_SHORT: &[char] = &['H', 'u', 'U'];

/// Options that write the request headers — with them the secret from a
/// --header-file — to the terminal (or a trace file).
const ECHO_LONG: &[&str] = &[
    "--verbose",
    "--trace",
    "--trace-ascii",
    "--trace-config",
    "--libcurl",
];
const ECHO_SHORT: &[char] = &['v'];

/// Short options that take a value: the rest of the cluster is that value.
const SHORT_WITH_VALUE: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

fn refuse(opt: &str) -> String {
    format!(
        "curl {opt} would put a header or credential into argv, and systemd writes argv into \
         the guest journal; use vantage --header 'Name: value' or --header-file 'Name=/path' instead"
    )
}

fn refuse_echo(opt: &str) -> String {
    format!(
        "curl {opt} would print the request headers — and with them the secret from \
         --header-file — to the terminal or a trace file; leave it out when using --header-file"
    )
}

pub fn is_curl(program: &str) -> bool {
    program.rsplit('/').next() == Some("curl")
}

/// curl ≥ 8.3 accepts an `--expand-` prefix on every long option
/// (`--expand-header`, `--expand-user`, …) — it expands `{{variables}}` in the
/// value and otherwise is the same option. `--expand-header` → `--header`.
fn strip_expand(name: &str) -> String {
    match name.strip_prefix("--expand-") {
        Some(rest) if !rest.is_empty() => format!("--{rest}"),
        _ => name.to_string(),
    }
}

/// curl accepts unambiguous prefix abbreviations of long options
/// (`--heade` for `--header`, `--proxy-h` for `--proxy-header`, `--oauth`
/// for `--oauth2-bearer`, ...); a name that is a strict-or-equal prefix of
/// a listed option is refused too, so an abbreviation can't slip past.
/// `exceptions` are real curl options of their own (`--head`, `--proxy`).
fn matches_long(name: &str, list: &[&str], exceptions: &[&str]) -> bool {
    if exceptions.contains(&name) {
        return false;
    }
    list.iter().any(|f| f.starts_with(name))
}

/// Same idea for `--config`: `--conf`/`--confi`/... also select it. A
/// minimum length of six keeps shorter, more ambiguous prefixes (`--con`,
/// `--co`) out of scope — they are not exercised by curl's own matcher here.
fn is_config_option(name: &str) -> bool {
    name == "--config" || ("--config".starts_with(name) && name.len() >= 6)
}

/// One curl argument as the checks see it.
enum Opt<'a> {
    /// A long option, `--expand-` already stripped; inline `=value` if any;
    /// index of the argument.
    Long(String, Option<&'a str>, usize),
    /// A short option inside a cluster; the rest of the cluster after it;
    /// index of the argument.
    Short(char, &'a str, usize),
}

/// Walks curl's argv up to `--` and calls `f` for every option. The value of
/// a short option that takes one (the rest of its cluster) is not scanned.
fn walk<'a>(
    args: &'a [String],
    mut f: impl FnMut(Opt<'a>) -> Result<(), String>,
) -> Result<(), String> {
    for (i, a) in args.iter().enumerate() {
        if let Some(long) = a.strip_prefix("--") {
            if long.is_empty() {
                break;
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a.as_str(), None),
            };
            f(Opt::Long(strip_expand(name), inline, i))?;
        } else if let Some(cluster) = a.strip_prefix('-') {
            for (pos, c) in cluster.char_indices() {
                f(Opt::Short(c, &cluster[pos + c.len_utf8()..], i))?;
                if SHORT_WITH_VALUE.contains(c) {
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn check(args: &[String]) -> Result<(), String> {
    walk(args, |o| match o {
        Opt::Long(name, inline, i) => {
            if matches_long(&name, FORBIDDEN_LONG, LONG_PREFIX_EXCEPTIONS) {
                return Err(refuse(&name));
            }
            if is_config_option(&name) {
                let v = inline.or(args.get(i + 1).map(String::as_str));
                if v == Some("-") {
                    return Err(refuse("--config -"));
                }
            }
            Ok(())
        }
        Opt::Short(c, rest, i) => {
            if FORBIDDEN_SHORT.contains(&c) {
                return Err(refuse(&format!("-{c}")));
            }
            if c == 'K' {
                let v = if rest.is_empty() {
                    args.get(i + 1).map(String::as_str)
                } else {
                    Some(rest)
                };
                if v == Some("-") {
                    return Err(refuse("-K -"));
                }
            }
            Ok(())
        }
    })
}

/// Called only when a --header-file is given: refuses the options that would
/// print the request headers, secret included. The message names the option,
/// never a value.
pub fn check_no_echo(args: &[String]) -> Result<(), String> {
    walk(args, |o| match o {
        Opt::Long(name, _, _) if matches_long(&name, ECHO_LONG, &[]) => {
            // Name the full option, not the abbreviation the caller typed.
            let full = ECHO_LONG
                .iter()
                .find(|f| f.starts_with(name.as_str()))
                .unwrap_or(&"--verbose");
            Err(refuse_echo(full))
        }
        Opt::Short(c, _, _) if ECHO_SHORT.contains(&c) => Err(refuse_echo(&format!("-{c}"))),
        _ => Ok(()),
    })
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
    #[test]
    fn long_option_abbreviations_refused() {
        for a in [
            &["--heade", "X"][..],
            &["--proxy-h", "X"],
            &["--oauth", "t"],
            &["--us=a:b"],
        ] {
            assert!(check(&v(a)).is_err(), "{a:?} must be refused");
        }
    }
    #[test]
    fn config_abbreviation_from_stdin_refused() {
        assert!(check(&v(&["--conf", "-"])).is_err());
    }
    #[test]
    fn expand_prefix_does_not_hide_a_forbidden_option() {
        for a in [
            &["--expand-header", "X: {{k}}"][..],
            &["--expand-header=X: y"],
            &["--expand-user", "a:b"],
            &["--expand-proxy-user", "a:b"],
            &["--expand-oauth2-bearer", "t"],
            &["--expand-proxy-header", "X: y"],
            &["--expand-heade", "X"],
            &["--expand-config", "-"],
            &["--expand-conf=-"],
        ] {
            assert!(check(&v(a)).is_err(), "{a:?} must be refused");
        }
        let e = check(&v(&["--expand-header", "X: geheim"])).unwrap_err();
        assert!(!e.contains("geheim"), "{e}");
    }
    #[test]
    fn expand_prefix_keeps_own_options_allowed() {
        assert!(check(&v(&["--expand-head"])).is_ok());
        assert!(check(&v(&["--expand-proxy", "http://p"])).is_ok());
        assert!(check(&v(&["--expand-url", "http://x/{{p}}"])).is_ok());
        assert!(check(&v(&["--expand-config", "/run/rc"])).is_ok());
    }
    #[test]
    fn options_that_print_request_headers_refused() {
        for a in [
            &["-v"][..],
            &["-sv"],
            &["-vs"],
            &["-sSv", "http://x/"],
            &["--verbose"],
            &["--verb"],
            &["--expand-verbose"],
            &["--trace", "-"],
            &["--trace=/tmp/t"],
            &["--trace-ascii", "-"],
            &["--trace-asc", "-"],
            &["--trace-config", "all"],
            &["--expand-trace-ascii", "-"],
            &["--libcurl", "-"],
            &["--libc", "-"],
        ] {
            let e = check_no_echo(&v(a)).expect_err(&format!("{a:?} must be refused"));
            assert!(e.contains("secret"), "{e}");
        }
    }
    #[test]
    fn echo_check_leaves_other_options_alone() {
        assert!(check_no_echo(&v(&["-sS", "-o", "/dev/null", "http://x/"])).is_ok());
        // -o takes the rest of the cluster: "-ov" writes to a file named "v".
        assert!(check_no_echo(&v(&["-ov"])).is_ok());
        assert!(check_no_echo(&v(&["--version"])).is_ok());
        assert!(check_no_echo(&v(&["--trace-time"])).is_ok());
        assert!(check_no_echo(&v(&["--no-verbose"])).is_ok());
        assert!(check_no_echo(&v(&["-w", "%{http_code}", "--", "-v"])).is_ok());
    }
    #[test]
    fn echo_refusal_names_the_option_never_the_value() {
        let e = check_no_echo(&v(&["--trace=/tmp/geheim"])).unwrap_err();
        assert!(e.contains("--trace"), "{e}");
        assert!(!e.contains("geheim"), "{e}");
    }
    #[test]
    fn own_options_that_are_prefixes_stay_allowed() {
        assert!(check(&v(&["--head"])).is_ok());
        assert!(check(&v(&["--proxy", "http://p"])).is_ok());
        assert!(check(&v(&["--user-agent", "x"])).is_ok());
        assert!(check(&v(&["--conf", "/run/rc"])).is_ok());
    }
}
