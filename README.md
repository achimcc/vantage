# vantage

Measure inside a systemd-nspawn guest from the right vantage point.

A measurement taken from the wrong place is green while the thing it stands
in for fails. `curl` run as root, next to the service, sails through a
`chmod` that the service's own `RestrictSUIDSGID` or seccomp filter would
have refused — root doesn't carry the sandbox the service runs under.
`curl` against `127.0.0.1`, or from the host instead of the guest, reaches a
port through a path the service's own firewall would have dropped. And
`curl -H 'X-Api-Key: …'` puts the key in argv; `systemd-run` logs a transient
unit's argv into its start line, which lands in the guest's journal and
stays there until the key is rotated. `vantage` runs the measurement from
inside the guest — as the running service itself, if asked — and keeps
secrets out of argv.

## Usage

```
vantage run   <guest> [--header 'Name: value']… [--header-file 'Name=/path/in/guest']…
                      [--as-service <unit>] -- <program> <args…>
vantage probe --from <guest> <target-guest>:<port> [--path /p] [-6]
vantage where <guest>
```

Runs on a NixOS host, as root.

### `run`

```
$ vantage run web --header 'Accept: application/json' \
    --header-file 'X-Api-Key=/run/secrets/sonarr-api-key' \
    -- curl -sS https://localhost:8989/api/v3/system/status
```

Runs `<program>` inside `<guest>` as a transient unit
(`systemd-run --machine=<guest> --wait --pipe --quiet --collect`), so it sees
the guest's own firewall, network namespace and mounts — not the host's, and
not `127.0.0.1`.

`--header` and `--header-file` only work with `curl`. Before anything runs,
`vantage` refuses a curl argument that would put a header or credential into
argv — `-H`/`--header`, `-u`/`--user`, `-U`/`--proxy-user`,
`--proxy-header`, `--oauth2-bearer`, their unambiguous abbreviations, and
`-K -`/`--config -` — because that argv ends up in the guest's journal via
the transient unit's start line. `--header 'Name: value'` **does** still
appear in argv itself, so it is only for headers that carry nothing secret
(`Accept`, `Content-Type`, …). An actual secret goes through
`--header-file 'Name=/path/in/guest'`: only the *path* is in argv, never the
value. `vantage` reads that file *inside* the guest and hands curl a curlrc
over a memfd (`-K /proc/self/fd/<n>`), so the value is in no argv at all.

#### `--as-service <unit>`

```
$ vantage run web --as-service sftpgo.service -- ls -la /uploads
vantage: as sftpgo.service (pid 284): ns=all uid=950 gid=9000 groups=9000,950,+109000(unmapped) \
  caps=0x400 umask=0002 nnp seccomp=36 · NOT: lsm,rlimits
```

Plain `run` puts the program inside the guest; `--as-service <unit>` puts it
inside the *running service's own process context* — because even inside
the guest, a generic root shell doesn't carry the sandbox a hardened unit
runs under. A green measurement without seccomp says nothing about a
service with `RestrictSUIDSGID`.

Reproduced, joining in this order — `cgroup`, `ipc`, `uts`, `net`, `pid`,
`mnt`, `user`, user namespace last, because as host root vantage has rights
over every child namespace only until it joins `user`:

- the unit's **namespaces** and its **cgroup**;
- **uid/gid and supplementary groups**, including groups the service's own
  user namespace does not map (kept apart in the report line as
  `+GID(unmapped)`) — the host GIDs are set with `setgroups(2)` *before*
  `setns` into `user`, because from inside the target namespace an unmapped
  GID would be refused;
- **capabilities** — bounding set, effective, permitted, inheritable and
  ambient;
- **`no_new_privs`** (and, if the service carries seccomp filters but had
  not set it itself, `nnp(added)`);
- **umask** (file-mode measurements depend on it);
- **seccomp filters**, copied from the live process via `ptrace` and loaded
  back in the same order (index 0 is the most recently installed filter, so
  they load from the highest index down), as the very last step before
  `execve`.

Not reproduced, and said so on the report line after `NOT:`: **LSM labels**
and **rlimits**. The service's own **environment is never copied** — it can
carry secrets; the child gets only `PATH=/run/current-system/sw/bin`. While
`vantage` reads the filters via `ptrace`, the service stands still —
measured 174–524 µs, well under a millisecond.

### `probe`

```
$ vantage probe --from web db:5432
```

Runs `curl` inside `<guest>` against the target guest's zone address and
port, and turns the result into one of five verdicts:

| curl result | verdict | exit |
|---|---|---|
| HTTP answer (exit 0) | answered | 0 |
| TCP connected, no full HTTP answer (exit 35, 52 or 56) | answered — "no HTTP response (curl exit …)" | 0 |
| connection refused (exit 7) | refused — nothing listens, or the target's own firewall rejects | 1 |
| timeout (exit 28), host's drop log matches this probe | dropped at zone edge | 1 |
| timeout (exit 28), `drop_log_prefix` configured but no match | dropped elsewhere — the source's egress lock or the target's own firewall | 1 |
| timeout (exit 28), no `drop_log_prefix` configured | timed out — zone edge vs. elsewhere unknown | 1 |
| anything else (curl not in the guest's profile, journalctl failure, …) | tool error | 2 |

`vantage` picks curl's own source port (`--local-port`) itself rather than
letting the kernel choose one, because `%{local_port}` is empty after a
connect timeout and the kernel's drop-log line has to be matched back to
*this* probe and no other, by `SRC=`/`DST=`/`SPT=`/`DPT=`. Telling a
dropped-at-the-edge timeout from any other timeout needs
`/etc/vantage.toml`:

```toml
drop_log_prefix = "guest-forward-drop"
```

the log prefix of the host's forward-drop rule. Without the file, every
timeout comes back as "timed out … zone edge vs. elsewhere unknown".

### `where`

```
$ vantage where web
web (leader pid 4711)
  addresses: 10.0.1.10
  tools: curl yes socat no jq yes bash yes findmnt yes
  running units:
    sonarr.service (host pid 5)
```

The vantage point itself: the guest's addresses, which of the tools a
measurement typically needs are actually in its profile, and which units
are running there right now.

## Exit codes

`run`: the program's own exit code; **125** tool error, **126** not
executable, **127** not found in the guest's profile (including a bare
`203`/`EXEC` from `systemd-run`, translated).

`probe`: **0** answered, **1** a finding (refused / dropped / timed out),
**2** tool error.

## Limits

- Only works against **systemd-nspawn guests that share the host's
  `/nix/store`** — `vantage` re-enters the guest through its own store path,
  and refuses to run from anywhere else.
- Runs as **root on the host**.
- `--as-service` does not reproduce **LSM labels** or **rlimits**; the
  report line says so.
- While `vantage` reads a service's seccomp filters via `ptrace`, that
  service is paused — measured 174–524 µs.

## Development

```
nix develop -c cargo test
nix develop -c cargo clippy --all-targets -- -D warnings
nix flake check
```

## License

AGPL-3.0-only, see [LICENSE](LICENSE).
