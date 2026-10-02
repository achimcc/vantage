# Security

## Reporting a vulnerability

Please report a suspected vulnerability privately, through GitHub's
**"Report a vulnerability"** button on the *Security* tab of this repository
(private vulnerability reporting). Do not open a public issue for it.

Say what you observed, how to reproduce it, and which version or commit you
looked at. You will get an answer within a week.

## Supported versions

Only the latest tagged release is supported. A fix lands on `main` and in a
new tag; older tags are not patched.

## What is checked on every commit

`nix flake check` runs, besides tests, clippy and rustfmt:

- **`audit`** — `cargo-audit` against the RustSec advisory database, pinned as
  a flake input and read offline. Renovate refreshes the pin weekly.
- **`deny`** — `cargo-deny` on bans, sources and licenses (`deny.toml`): no
  dependency from an unknown registry or git repository, no wildcard version.

`unsafe` code is denied crate-wide (`[lints.rust]` in `Cargo.toml`), and so is
an unsafe operation outside an `unsafe` block. vantage cannot do without it:
it calls what std does not wrap — `setns`, `ptrace`, `seccomp`, `pidfd_open`,
`capset`, `memfd_create`. The 17 `unsafe` blocks sit in 12 functions (five of
them tests), each function marked `#[allow(unsafe_code)]`, each block with a
`SAFETY` comment naming what it relies on.
