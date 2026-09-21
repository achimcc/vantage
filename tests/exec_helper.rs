use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn fake_curl(dir: &std::path::Path) -> std::path::PathBuf {
    // Prints its argv, then the curlrc it was given with -K.
    let p = dir.join("curl");
    std::fs::write(&p, "#!/bin/sh\necho \"ARGS:$*\"\ncat \"$2\"\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
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
