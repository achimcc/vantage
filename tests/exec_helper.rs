use std::io::Write;
use std::process::Command;

/// Writes an executable script from a CHILD process. Written from the test
/// process itself, the write descriptor is open while a parallel test forks;
/// that child holds it until its own exec, and executing the script then
/// fails with ETXTBSY ("Text file busy") -- seen in the Nix build.
fn script(p: &std::path::Path, body: &str) {
    let mut c = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(p)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(body.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());
}

fn fake_curl(dir: &std::path::Path) -> std::path::PathBuf {
    // Prints its argv, then the curlrc it was given with -K.
    let p = dir.join("curl");
    script(&p, "#!/bin/sh\necho \"ARGS:$*\"\ncat \"$2\"\n");
    p
}

#[test]
fn header_file_reaches_curl_through_the_rc_not_argv() {
    let d = tempfile::tempdir().unwrap();
    let key = d.path().join("key");
    std::fs::File::create(&key)
        .unwrap()
        .write_all(b"geheim-4711\n")
        .unwrap();
    let curl = fake_curl(d.path());
    let out = Command::new(env!("CARGO_BIN_EXE_vantage"))
        .args([
            "__exec",
            "--header-file",
            &format!("X-Api-Key={}", key.display()),
            "--header",
            "Accept: application/json",
            "--",
        ])
        .arg(&curl)
        .arg("http://x/")
        .output()
        .unwrap();
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{so} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let args_line = so.lines().find(|l| l.starts_with("ARGS:")).unwrap();
    assert!(args_line.contains("-K /proc/self/fd/"), "{args_line}");
    assert!(args_line.ends_with("http://x/"), "{args_line}");
    assert!(
        !args_line.contains("geheim"),
        "the value must not be in argv"
    );
    assert!(so.contains("header = \"Accept: application/json\""), "{so}");
    assert!(so.contains("header = \"X-Api-Key: geheim-4711\""), "{so}");
}

#[test]
fn missing_program_is_127_unreadable_file_is_125() {
    let d = tempfile::tempdir().unwrap();
    let st = Command::new(env!("CARGO_BIN_EXE_vantage"))
        .args(["__exec", "--header", "A: b", "--", "/nonexistent/curl"])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(127));
    let out = Command::new(env!("CARGO_BIN_EXE_vantage"))
        .args(["__exec", "--header-file", "X=/nonexistent/key", "--"])
        .arg(fake_curl(d.path()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
}

/// SigIgn of the shell that runs this script, as hex from /proc/$$/status.
fn sigign_script(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("sigign");
    script(
        &p,
        "#!/bin/sh\nwhile read -r k v; do [ \"$k\" = SigIgn: ] && echo \"SIGIGN=$v\"; done < /proc/$$/status\nexit 0\n",
    );
    p
}

fn sigpipe_ignored(stdout: &[u8]) -> bool {
    let so = String::from_utf8_lossy(stdout);
    let hex = so
        .lines()
        .find_map(|l| l.strip_prefix("SIGIGN="))
        .unwrap_or_else(|| panic!("no SigIgn line in {so:?}"));
    // Signal 13 is bit 12 of the mask.
    u64::from_str_radix(hex.trim(), 16).unwrap() & (1 << (libc::SIGPIPE - 1)) != 0
}

#[test]
fn exec_hands_the_program_sigpipe_at_default() {
    let d = tempfile::tempdir().unwrap();
    let script = sigign_script(d.path());

    // Positive control: the measurement sees an ignored SIGPIPE.
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(&script);
    unsafe {
        c.pre_exec(|| {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            Ok(())
        });
    }
    let ctl = c.output().unwrap();
    assert!(
        sigpipe_ignored(&ctl.stdout),
        "control: SIG_IGN must be visible"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_vantage"))
        .args(["__exec", "--header", "A: b", "--"])
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !sigpipe_ignored(&out.stdout),
        "the program must not inherit Rust's SIG_IGN for SIGPIPE"
    );
}
