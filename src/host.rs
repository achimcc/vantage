//! Everything vantage asks the host. The real implementation runs programs
//! from the system profile; tests replay recorded answers.

pub const PROFILE: &str = "/run/current-system/sw/bin";

#[derive(Debug, Clone, Default)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait Host {
    fn cmd(&self, prog: &str, args: &[&str]) -> Result<Out, String>;
    fn read(&self, path: &str) -> Result<String, String>;
    fn exists(&self, path: &str) -> bool;
    fn list_dir(&self, path: &str) -> Result<Vec<String>, String>;
    fn now(&self) -> u64;
    fn sleep_ms(&self, ms: u64);
}

pub struct Real;

impl Host for Real {
    fn cmd(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
        let o = std::process::Command::new(format!("{PROFILE}/{prog}"))
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        Ok(Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }
    fn read(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
    }
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
    fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        let mut v: Vec<String> = std::fs::read_dir(path)
            .map_err(|e| format!("{path}: {e}"))?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        Ok(v)
    }
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Replays recorded answers. Keys: "prog arg1 arg2" for commands, the
    /// path for files. An unrecorded question is a test failure, not a guess.
    #[derive(Default)]
    pub struct Fake {
        pub cmds: HashMap<String, Out>,
        pub files: HashMap<String, String>,
        pub dirs: HashMap<String, Vec<String>>,
        pub now: u64,
        pub asked: RefCell<Vec<String>>,
    }
    impl Fake {
        pub fn on(mut self, cmd: &str, code: i32, stdout: &str) -> Self {
            self.cmds.insert(
                cmd.to_string(),
                Out {
                    code,
                    stdout: stdout.into(),
                    stderr: String::new(),
                },
            );
            self
        }
        pub fn file(mut self, path: &str, content: &str) -> Self {
            self.files.insert(path.to_string(), content.to_string());
            self
        }
    }
    impl Host for Fake {
        fn cmd(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
            let key = std::iter::once(prog)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.asked.borrow_mut().push(key.clone());
            self.cmds
                .get(&key)
                .cloned()
                .ok_or(format!("unrecorded command: {key}"))
        }
        fn read(&self, path: &str) -> Result<String, String> {
            self.files
                .get(path)
                .cloned()
                .ok_or(format!("{path}: No such file or directory"))
        }
        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }
        fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
            self.dirs
                .get(path)
                .cloned()
                .ok_or(format!("{path}: No such file or directory"))
        }
        fn now(&self) -> u64 {
            self.now
        }
        fn sleep_ms(&self, _ms: u64) {}
    }
}
