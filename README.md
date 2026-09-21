# vantage

Measure inside a systemd-nspawn guest from the right vantage point.

`vantage` runs on a NixOS host as root and executes commands inside
systemd-nspawn guests correctly — with the right namespace order, the right
capabilities and supplementary groups, and without leaking secrets into
`/proc/*/cmdline` or the guest's journal.

## Usage

```
vantage run   <guest> [--header-file 'Name=/path/in/guest']… [--header 'Name: value']…
                      [--as-service <unit>] -- <program> <args…>
vantage probe --from <guest> <target-guest>:<port> [--path /p] [-6]
vantage where <guest>
```

Exit codes for `run`: the program's own code; 125 tool error, 126 not
executable, 127 not found in the guest's profile.

Exit codes for `probe`: 0 answered, 1 finding (refused, dropped, timed out),
2 tool error.

## Development

```
nix develop -c cargo test
nix develop -c cargo clippy --all-targets -- -D warnings
```
