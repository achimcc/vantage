//! vantage — measure inside a systemd-nspawn guest from the right vantage
//! point. The binary is `vantage` (`app::main`); the crate is also a
//! library for tools that run commands in guests and read the answer
//! (gast-pruefung, signoff): see `guest_run::GuestCommand`, `capture`
//! and `curlrc::CurlRc`, and "As a library" in the README.

pub mod app;
pub mod capture;
pub mod cli;
pub mod config;
pub mod curl_guard;
pub mod curlrc;
pub mod exec;
pub mod guest_run;
pub mod host;
pub mod machine;
pub mod probe;
pub mod proc_status;
pub mod seccomp;
pub mod service;
pub mod text;
pub mod where_cmd;
// (Further modules are added by the following tasks here.)
