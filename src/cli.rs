//! Command line → `Cmd`. Hand-written: the grammar is small, and every
//! branch is a test.

#[derive(Debug, PartialEq)]
pub enum Cmd {
    Run(RunArgs),
    Probe(ProbeArgs),
    Where { guest: String },
    Exec(ExecArgs),
    Help,
    Version,
}

#[derive(Debug, PartialEq, Default)]
pub struct RunArgs {
    pub guest: String,
    pub header_files: Vec<(String, String)>,
    pub headers: Vec<String>,
    pub as_service: Option<String>,
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct ProbeArgs {
    pub from: String,
    pub target: String,
    pub port: u16,
    pub path: String,
    pub v6: bool,
}

#[derive(Debug, PartialEq, Default)]
pub struct ExecArgs {
    pub header_files: Vec<(String, String)>,
    pub headers: Vec<String>,
    pub program: String,
    pub args: Vec<String>,
}

/// `--name value` or `--name=value`. Returns the value and advances `i`.
fn value(argv: &[String], i: &mut usize, name: &str) -> Result<Option<String>, String> {
    let a = &argv[*i];
    if a == name {
        *i += 1;
        return argv
            .get(*i)
            .cloned()
            .map(Some)
            .ok_or(format!("{name} needs a value"));
    }
    if let Some(v) = a.strip_prefix(&format!("{name}=")) {
        return Ok(Some(v.to_string()));
    }
    Ok(None)
}

fn header_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_header_file(spec: &str) -> Result<(String, String), String> {
    let (name, path) = spec
        .split_once('=')
        .ok_or("--header-file wants NAME=/absolute/path")?;
    if !header_name_ok(name) {
        return Err(format!("--header-file: '{name}' is not a header name"));
    }
    if !path.starts_with('/') {
        return Err(
            "--header-file: the path must be absolute (it is read inside the guest)".into(),
        );
    }
    Ok((name.to_string(), path.to_string()))
}

/// `(header_files, headers, as_service, program, args)`.
type HeadersAndProgram = (
    Vec<(String, String)>,
    Vec<String>,
    Option<String>,
    String,
    Vec<String>,
);

/// Options shared by `run` and `__exec`, up to `--`, then program and args.
fn headers_and_program(
    argv: &[String],
    mut i: usize,
    allow_service: bool,
) -> Result<HeadersAndProgram, String> {
    let (mut files, mut headers, mut service) = (Vec::new(), Vec::new(), None);
    while i < argv.len() && argv[i] != "--" {
        if let Some(v) = value(argv, &mut i, "--header-file")? {
            files.push(parse_header_file(&v)?);
        } else if let Some(v) = value(argv, &mut i, "--header")? {
            if !v.contains(':') {
                return Err("--header wants 'Name: value', got no colon".into());
            }
            headers.push(v);
        } else if allow_service {
            match value(argv, &mut i, "--as-service")? {
                Some(v) => service = Some(v),
                None => return Err(format!("unknown option {}", argv[i])),
            }
        } else {
            return Err(format!("unknown option {}", argv[i]));
        }
        i += 1;
    }
    if i >= argv.len() {
        return Err("missing '--' before the program".into());
    }
    let rest = &argv[i + 1..];
    let (program, args) = rest.split_first().ok_or("missing program after '--'")?;
    Ok((files, headers, service, program.clone(), args.to_vec()))
}

pub fn parse(argv: &[String]) -> Result<Cmd, String> {
    let Some(first) = argv.first() else {
        return Ok(Cmd::Help);
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Cmd::Help),
        "-V" | "--version" => Ok(Cmd::Version),
        "run" => {
            let guest = argv
                .get(1)
                .filter(|g| !g.starts_with('-'))
                .ok_or("run: missing guest")?;
            let (header_files, headers, as_service, program, args) =
                headers_and_program(argv, 2, true)?;
            Ok(Cmd::Run(RunArgs {
                guest: guest.clone(),
                header_files,
                headers,
                as_service,
                program,
                args,
            }))
        }
        "__exec" => {
            let (header_files, headers, _, program, args) = headers_and_program(argv, 1, false)?;
            Ok(Cmd::Exec(ExecArgs {
                header_files,
                headers,
                program,
                args,
            }))
        }
        "where" => {
            let guest = argv.get(1).ok_or("where: missing guest")?;
            if argv.len() > 2 {
                return Err("where takes exactly one guest".into());
            }
            Ok(Cmd::Where {
                guest: guest.clone(),
            })
        }
        "probe" => {
            let (mut from, mut target, mut path, mut v6) = (None, None, "/".to_string(), false);
            let mut i = 1;
            while i < argv.len() {
                if let Some(v) = value(argv, &mut i, "--from")? {
                    from = Some(v);
                } else if let Some(v) = value(argv, &mut i, "--path")? {
                    path = v;
                } else if argv[i] == "-6" {
                    v6 = true;
                } else if argv[i].starts_with('-') {
                    return Err(format!("unknown option {}", argv[i]));
                } else if target.is_none() {
                    target = Some(argv[i].clone());
                } else {
                    return Err(format!("unexpected argument {}", argv[i]));
                }
                i += 1;
            }
            let from = from.ok_or("probe: --from <guest> is required")?;
            let t = target.ok_or("probe: missing <guest>:<port>")?;
            let (target, port) = t
                .rsplit_once(':')
                .ok_or("probe: target must be <guest>:<port>")?;
            let port: u16 = port
                .parse()
                .map_err(|_| format!("probe: '{port}' is not a port"))?;
            if !path.starts_with('/') {
                return Err("probe: --path must start with '/'".into());
            }
            Ok(Cmd::Probe(ProbeArgs {
                from,
                target: target.to_string(),
                port,
                path,
                v6,
            }))
        }
        other => Err(format!("unknown command {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn run_plain() {
        let c = parse(&v(&["run", "media-01", "--", "curl", "-sS", "http://x/"])).unwrap();
        assert_eq!(
            c,
            Cmd::Run(RunArgs {
                guest: "media-01".into(),
                header_files: vec![],
                headers: vec![],
                as_service: None,
                program: "curl".into(),
                args: v(&["-sS", "http://x/"]),
            })
        );
    }

    #[test]
    fn run_with_options_both_spellings() {
        let c = parse(&v(&[
            "run",
            "g",
            "--header-file",
            "X-Api-Key=/run/k",
            "--header=Accept: a/b",
            "--as-service=sonarr.service",
            "--",
            "/abs/curl",
        ]))
        .unwrap();
        let Cmd::Run(r) = c else { panic!() };
        assert_eq!(r.header_files, vec![("X-Api-Key".into(), "/run/k".into())]);
        assert_eq!(r.headers, v(&["Accept: a/b"]));
        assert_eq!(r.as_service.as_deref(), Some("sonarr.service"));
        assert_eq!(r.program, "/abs/curl");
    }

    #[test]
    fn run_needs_program_after_dashdash() {
        assert!(parse(&v(&["run", "g"])).is_err());
        assert!(parse(&v(&["run", "g", "--"])).is_err());
    }

    #[test]
    fn header_file_must_be_name_eq_absolute_path() {
        assert!(parse(&v(&[
            "run",
            "g",
            "--header-file",
            "X-Api-Key",
            "--",
            "curl"
        ]))
        .is_err());
        assert!(parse(&v(&[
            "run",
            "g",
            "--header-file",
            "X-Api-Key=rel/path",
            "--",
            "curl"
        ]))
        .is_err());
        assert!(parse(&v(&[
            "run",
            "g",
            "--header-file",
            "Bad Name=/p",
            "--",
            "curl"
        ]))
        .is_err());
    }

    #[test]
    fn header_needs_colon() {
        assert!(parse(&v(&["run", "g", "--header", "Accept", "--", "curl"])).is_err());
    }

    #[test]
    fn unknown_option_is_error() {
        assert!(parse(&v(&["run", "g", "--bogus", "--", "curl"])).is_err());
    }

    #[test]
    fn probe_full() {
        let c = parse(&v(&[
            "probe",
            "--from",
            "media-01",
            "req-01:5055",
            "--path",
            "/api",
            "-6",
        ]))
        .unwrap();
        assert_eq!(
            c,
            Cmd::Probe(ProbeArgs {
                from: "media-01".into(),
                target: "req-01".into(),
                port: 5055,
                path: "/api".into(),
                v6: true
            })
        );
    }

    #[test]
    fn probe_defaults_and_errors() {
        let Cmd::Probe(p) = parse(&v(&["probe", "--from", "a", "b:80"])).unwrap() else {
            panic!()
        };
        assert_eq!(p.path, "/");
        assert!(!p.v6);
        assert!(parse(&v(&["probe", "b:80"])).is_err()); // --from fehlt
        assert!(parse(&v(&["probe", "--from", "a", "b"])).is_err()); // Port fehlt
        assert!(parse(&v(&["probe", "--from", "a", "b:x"])).is_err()); // Port keine Zahl
        assert!(parse(&v(&["probe", "--from", "a", "b:80", "--path", "api"])).is_err());
    }

    #[test]
    fn where_and_exec_and_help() {
        assert_eq!(
            parse(&v(&["where", "g"])).unwrap(),
            Cmd::Where { guest: "g".into() }
        );
        let Cmd::Exec(e) =
            parse(&v(&["__exec", "--header-file", "A=/f", "--", "/c", "u"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(e.program, "/c");
        assert_eq!(e.args, v(&["u"]));
        assert_eq!(parse(&v(&[])).unwrap(), Cmd::Help);
        assert_eq!(parse(&v(&["--help"])).unwrap(), Cmd::Help);
        assert_eq!(parse(&v(&["--version"])).unwrap(), Cmd::Version);
    }
}
