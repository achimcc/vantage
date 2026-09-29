# Änderungen

Frühere Versionen (bis 0.2.1) sind nur in den Commit-Nachrichten beschrieben
(`git log`).

## 0.3.0 — 2026-09-29

Audit 3 des Homeservers (2026-09-27), zwei low-Befunde.

### B107 (A1-6): `probe` — das Urteil gehört dem Quellgast

- Die Drop-Zeile kommt jetzt als `journalctl -o json --all` zurück, und
  vantage prüft das Feld `_TRANSPORT` **jedes** Eintrags selbst: Gezählt wird
  nur `kernel`. Die Match-Angabe `_TRANSPORT=kernel` (seit 0.2.0) bleibt als
  erste Hälfte; fällt sie je weg, zählt eine Konsolenzeile des Gastes
  (`container@<g>.service`, `_TRANSPORT=stdout`) trotzdem nicht.
- Hilfe und README sagen jetzt, was `probe` gegen einen übernommenen
  Quellgast NICHT beweist: `answered`, `refused` und `dropped elsewhere` sind
  sein Wort, nur `dropped at zone edge` stützt sich auf den Wirt. Wer eine
  Sperre beweisen will, liest die Zähler der Zonenkante (groundtruth).

### B108 (A1-7): `--as-service` — Ziel und Nachbildung wählt der Gast

- Der Zielprozess wird direkt nach der Auswahl per **pidfd** festgehalten.
  Vor dem ersten `setns` muss `/proc/self/fdinfo/<pidfd>` ihn noch lebend
  zeigen, mit der Gast-PID und einem `NSpid` so tief wie beim Gast-Leader.
  Vorher las vantage `/proc/<pid>/status` über die Nummer und verglich nur
  das letzte `NSpid`-Feld — ein Wirtsprozess mit derselben Nummer bestand.
- Der geöffnete `pid`-Namensraum-FD muss der PID-Namensraum des
  Gast-Leaders sein (dev/ino), sonst Abbruch mit 125.
- Schon die Auswahl verlangt dieselbe `NSpid`-Tiefe wie der Leader: Der
  Elternprozess eines zweiten `vantage run --as-service` sitzt in der cgroup
  des Dienstes und wurde bei gleicher Nummer genommen.
- Die gelesenen Seccomp-Filter werden gegen `Seccomp_filters` aus
  `/proc/<pid>/status` gezählt. Weicht die Zahl ab (mehr als 512, oder ein
  Filter kam dazwischen), wird keiner geladen; die Zeile sagt `seccomp=?`
  und `NOT: …,seccomp (read N filters, the process has M (Seccomp_filters))`.
- **Neue Ausgabe:** `NOT:` nennt jetzt immer auch `securebits,keyring`, und
  wo Filter kopiert wurden `seccomp-flags` (LOG, SPEC_ALLOW, NEW_LISTENER
  werden nicht nachgebildet). Vorher stand dort nur `lsm,rlimits`.

### Bewusst nicht umgesetzt

- Der Gast bestimmt weiter, WELCHER seiner Prozesse nachgebildet wird
  (MainPID aus seinem systemd, Kandidaten aus seiner delegierten cgroup).
  Das lässt sich im Werkzeug nicht beheben; README und Grenzen sagen es.
- Der Elternprozess schreibt sich weiter in die cgroup des Dienstes, und der
  Gast könnte ihn über `cgroup.freeze` anhalten (vantage hängt). Ein Beitritt
  erst im Kind nach `setns(cgroup)` scheitert voraussichtlich an der Prüfung
  des gemeinsamen Vorfahren im cgroup-Namensraum; das braucht eine Messung
  als root, die hier nicht möglich war.
- vantage liest keine Zähler der Zonenkante selbst: Welche nft-Zähler das
  sind, ist Sache des Wirts (groundtruth), nicht eines allgemeinen Werkzeugs.
