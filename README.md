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
`--proxy-header`, `--oauth2-bearer`, their unambiguous abbreviations, their
`--expand-` forms (curl ≥ 8.3 accepts `--expand-header`, `--expand-user`, …),
and `-K -`/`--config -` — because that argv ends up in the guest's journal via
the transient unit's start line. `--header 'Name: value'` **does** still
appear in argv itself, so it is only for headers that carry nothing secret
(`Accept`, `Content-Type`, …). An actual secret goes through
`--header-file 'Name=/path/in/guest'`: only the *path* is in argv, never the
value. `vantage` reads that file *inside* the guest and hands curl a curlrc
over a memfd (`-K /proc/self/fd/<n>`), so the value is in no argv at all.

With a `--header-file`, `vantage` also refuses the curl options that print
the request headers — and with them the secret — to the terminal or a trace
file: `-v`/`--verbose` (also inside a cluster such as `-sv`), `--trace`,
`--trace-ascii`, `--trace-config` and `--libcurl`, again including
abbreviations and `--expand-` forms.

**A secret in the URL is not protected.** `curl 'http://…/api?apikey=…'`
puts the key into argv like `-H` would, and from there into the guest's
journal — `vantage` does not parse URLs. Send the key as a header with
`--header-file` instead (most APIs that take `?apikey=` also take
`X-Api-Key:`).

Plain `run` with headers re-enters the guest through vantage's own store
path (`vantage __exec`, which reads the files and execs curl), so only this
case needs the guest to share the host's `/nix/store`. With `--as-service`
there is no re-exec: the forked child reads the files itself (see below).

#### `--as-service <unit>`

```
$ vantage run web --as-service sftpgo.service -- ls -la /uploads
vantage: as sftpgo.service (pid 284): ns=all uid=950 gid=9000 groups=9000,950,+109000(unmapped) \
  caps=0x400 umask=0002 nnp seccomp=36 · NOT: lsm,rlimits,securebits,keyring,seccomp-flags
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
- the **root directory** — `/proc/<pid>/root` is opened before the namespace
  switch and the child `chroot`s into it, so a unit with `RootDirectory=`
  (NixOS `confinement.enable`) sees its own root, not the guest's. The report
  line says `root=own` when that root differs from the guest's own root —
  compared on the host, before any `setns`, since after joining the service's
  own mount namespace `/` is already the confined root and the comparison
  would trivially agree with itself. Inside such a root only what the unit
  mounts exists: the program has to be there too, or it is 127 (the message
  says so, when `root=own` applies);
- **umask** (file-mode measurements depend on it);
- **seccomp filters**, copied from the live process via `ptrace` and loaded
  back in the same order (index 0 is the most recently installed filter, so
  they load from the highest index down), as the very last step before
  `execve`. The number read back has to equal `Seccomp_filters` in
  `/proc/<pid>/status`; if it does not (more than 512 filters, or a filter
  added in between), no filter is loaded and the report line says
  `seccomp=?` and `NOT: …,seccomp (read N filters, the process has M …)`.

With `--header`/`--header-file`, the forked child — already as the service
user, in the service's mount namespace and root, before the seccomp filters
are loaded — reads the files, writes the curlrc into a memfd and execs curl
with `-K /proc/self/fd/<n>`. So `--header-file` paths are the paths *the
service* sees, and a file the service may not read is an error (125).

The target is held by a **pidfd** from the moment it is chosen. Before the
first `setns`, `/proc/self/fdinfo/<pidfd>` has to show it still alive, with
the guest pid the guest's systemd named and an `NSpid` as deep as the guest
leader's; and the opened `pid` namespace descriptor has to be the leader's
pid namespace. If the service restarts while `vantage` sets up, or the pid
is not a process of that guest (a host process with the same number — for
instance another `vantage` that has joined the service's cgroup), `vantage`
stops with 125 instead of joining a stranger.

Which process is the service is still the guest's word: MainPID comes from
the guest's systemd and the candidates from a cgroup the guest controls. A
compromised guest can have a harmless process of its own replicated —
`--as-service` measures a guest's sandbox, it is not evidence *against* the
guest.

Not reproduced, and said so on the report line after `NOT:`: **LSM labels**,
**rlimits**, **securebits**, the **keyring**, and — where filters were
copied — the **flags** a seccomp filter was loaded with (`LOG`,
`SPEC_ALLOW`, `NEW_LISTENER`). The service's own **environment is never copied** — it can
carry secrets; the child gets only `PATH=/run/current-system/sw/bin`. While
`vantage` reads the filters via `ptrace`, the service stands still —
measured 174–524 µs, well under a millisecond.

### `probe`

```
$ vantage probe --from web db:5432
```

Runs `curl` inside `<guest>` against the target guest's zone address and
port (`-w '%{http_code} %{time_connect}' --max-time 6`), and turns the
result into one of these verdicts:

| curl result | verdict | exit |
|---|---|---|
| HTTP answer (exit 0) | answered | 0 |
| TCP connected, no full HTTP answer (exit 35, 52 or 56) | answered — "no HTTP response (curl exit …)" | 0 |
| timeout (exit 28) *after* the connection was accepted (`time_connect` > 0) | answered — "no HTTP response within 6 s": a slow service, the path is open | 0 |
| exit 7 | refused (connection refused or host unreachable) — nothing listens, the target's firewall rejects, or an ICMP reject/EHOSTUNREACH; curl's own first stderr line follows and says which | 1 |
| connect timeout (exit 28, `time_connect` 0), host's drop log matches this probe | dropped at zone edge | 1 |
| connect timeout, `drop_log_prefix` configured but no match | dropped elsewhere — the source's egress lock or the target's own firewall | 1 |
| connect timeout, no `drop_log_prefix` configured | timed out — zone edge vs. elsewhere unknown | 1 |
| anything else (curl not in the guest's profile, journalctl failure, a second exit 45, …) | tool error | 2 |

`vantage` picks curl's own source port (`--local-port`) itself rather than
letting the kernel choose one, because `%{local_port}` is empty after a
connect timeout and the kernel's drop-log line has to be matched back to
*this* probe and no other, by prefix, `DST=`, `SPT=` and `DPT=` (not `SRC=`:
a guest can have several addresses). If that port is taken (curl exit 45),
the probe is retried once with a second port. Telling a
dropped-at-the-edge timeout from any other timeout needs
`/etc/vantage.toml`:

```toml
drop_log_prefix = "guest-forward-drop"
```

the log prefix of the host's forward-drop rule. Without the file, every
timeout comes back as "timed out … zone edge vs. elsewhere unknown".

Only a journal entry whose `_TRANSPORT` is `kernel` counts as the drop
line: `journalctl` is asked with that match, and vantage checks the field of
every entry it gets back (`-o json`) once more. A guest's console lands in
the host journal too (`container@<g>.service`, `_TRANSPORT=stdout`), and the
guest knows the source port from curl's argv — a forged line there is not a
drop.

**What `probe` does not prove.** curl runs in the *source* guest, through
that guest's systemd; its exit code and `-w` line are the source guest's
word. A compromised source can report `answered 200` for a path that is
closed, or `refused` for one that is open. Only `dropped at zone edge` rests
on the host (the kernel's own log line). To *prove* that a path is blocked
against a hostile source, read the zone edge's counters on the host (e.g.
groundtruth's), not a probe verdict.

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

`run`: the program's own exit code; **125** tool error, **127** program not
found in the guest's profile, **126** program not executable.

- For plain `run`, `systemd-run` reports a program it cannot start as
  `203`/`EXEC` — ENOENT and EACCES alike — and `vantage` turns that into
  **127**. A `203` for vantage *itself* (the `__exec` re-entry with headers)
  means the guest cannot see vantage's store path: **125**, "store not
  shared?".
- **126** comes only from paths where vantage itself calls `execve`:
  `--as-service`, and `vantage __exec` for plain `run` with headers.
- A program killed by signal *n*: **128+n** with `--as-service`; otherwise
  whatever `systemd-run` reports.

`probe`: **0** answered, **1** a finding (refused / dropped / timed out),
**2** tool error — including a command line that does not parse.

## Limits

- Only works against **systemd-nspawn guests**. Plain `run` with
  `--header`/`--header-file` re-enters the guest through vantage's own
  store path, so that case needs a guest that shares the host's
  `/nix/store`, and a `vantage` that runs from `/nix/store` (it refuses to
  otherwise). Without headers, and with `--as-service`, it does not.
- Runs as **root on the host**.
- `--as-service` does not reproduce **LSM labels**, **rlimits**,
  **securebits**, the **keyring** or **seccomp filter flags**; the report
  line says so. Which process it replicates is the guest's choice (MainPID
  from the guest's systemd).
- `probe`'s verdict belongs to the source guest, except `dropped at zone
  edge` (a kernel log line on the host) — see above.
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
