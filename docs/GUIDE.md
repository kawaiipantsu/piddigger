# piddigger operator guide

`piddigger` is a read-only forensic investigator for a single running Linux
process. This guide covers what each view shows, how collection and tracing
behave on a live host, and how the evidence case is structured.

- [Threat model and ground rules](#threat-model-and-ground-rules)
- [Attaching to a process](#attaching-to-a-process)
- [The views](#the-views)
- [Triage findings](#triage-findings)
- [Live tracing and capture](#live-tracing-and-capture)
- [Evidence case layout](#evidence-case-layout)
- [Data sources and limits](#data-sources-and-limits)
- [Build and Debian packages](#build-and-debian-packages)

## Threat model and ground rules

piddigger is for **authorized defensive work** on systems you are responsible
for: incident response, threat hunting and forensic triage of a suspicious
process you already have on the box.

- **Collection is read-only.** Building the views reads `/proc/<pid>` and never
  writes to, signals or stops the target.
- **Tracing and dumps are opt-in.** strace, ltrace, perf, bpftrace, tcpdump,
  gdb and gcore are only launched when you choose them, and each states its
  impact (`observe` / `ptrace` / `pause`) before it runs.
- **Findings are leads, not verdicts.** Every finding carries the evidence that
  triggered it and a suggested next step; benign software can trip several of
  them. You decide.
- **Preserve before you contain.** A deleted or in-memory binary, a reverse
  shell's socket or RWX memory can vanish the moment the process exits or is
  killed. Snapshot first.

## Attaching to a process

```sh
piddigger 4982          # attach to a known PID
piddigger               # open the process picker
sudo piddigger 4982     # root or CAP_SYS_PTRACE → complete visibility
piddigger --demo        # synthetic suspicious process, no root, no live /proc
```

In the picker (`p`), type to filter by name, PID, user or command line; `Enter`
attaches. Kernel threads are hidden unless you ask for them. You can re-attach
to a different PID at any time with `p`.

Run as **root** (or grant `CAP_SYS_PTRACE`) for full visibility. As an ordinary
user you can still fully inspect your own processes; for others, several
`/proc` entries (`environ`, `maps` of privileged processes, another user's fds)
return permission denied, and piddigger records that in the errors it surfaces.

## The views

The left menu switches views; number/letter keys jump directly.

- **Overview** — a dashboard: identity, open files, connections, memory maps,
  live CPU/RSS meters and the top findings, all on one screen.
- **Tree** — the ancestry chain up to PID 1 and the target's children, so you
  can see *what launched this* and *what it launched*.
- **Files** — every open descriptor with type, flags and size. Deleted-but-open
  files and memfds are highlighted; `Enter` recovers the selected one into the
  case.
- **Network** — every socket the process holds, resolved from its own
  descriptors: TCP/UDP/raw/unix/packet/netlink, with state and queue depth.
  Raw and AF_PACKET sockets (sniffers, BPF backdoors) are flagged.
- **Memory** — the RSS/PSS/anon/file/swap summary and the full map table.
  Writable+executable (RWX), deleted-file-backed and memfd regions are marked.
- **Security** — real/effective/saved UID and GID, groups, loginuid,
  capabilities (effective and bounding, dangerous ones highlighted), seccomp
  mode, no_new_privs, LSM label, tracer, namespaces and cgroup.
- **Threads** — per-thread state, user/system CPU ticks, current CPU and wait
  channel.
- **Environ** — the process environment. Injection- and anti-forensics-relevant
  variables (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `HISTFILE`, `PATH`) are
  highlighted. Press `n` to hide values when screen-sharing.
- **Activity** — a live timeline. Each refresh is diffed against the previous
  one and new/closed descriptors, sockets, threads, children and executable
  mappings are logged with a timestamp.
- **Findings** — the full triage list with the why, the evidence and the next
  step for each lead.
- **Trace** — streamed output of the running capture, colourised, with the
  command, elapsed time and line count.
- **Evidence** — hashes and timestamps for the executable, case status and the
  live chain-of-custody log.

## Triage findings

The findings engine looks for patterns that matter in an intrusion, for
example:

- **Fileless / deleted execution** — running from a memfd, or the executable
  unlinked after start.
- **Masquerading** — `comm` that differs from the executable, or a user-space
  process disguised with a bracketed `[kworker/...]` argv[0]; a PID hidden from
  the `/proc` listing.
- **Reverse / bind shells** — a shell descended from a network service, or a
  shell with stdin/stdout/stderr wired to a socket.
- **Injection** — `LD_PRELOAD`/`LD_AUDIT` set, an active `/etc/ld.so.preload`,
  or executable mappings backed by deleted files, memfds or writable paths.
- **Suspicious memory** — RWX regions and anonymous executable memory.
- **Sniffers** — AF_PACKET and raw sockets.
- **Privilege** — effective root from a non-root real UID; powerful
  capabilities on a non-root process; an attached tracer.
- **Anti-forensics** — history disabled via `HISTFILE`/`HISTSIZE`.

Severity is `INFO` → `LOW` → `MEDIUM` → `HIGH`. A finding is a reason to look,
not proof of compromise. JIT runtimes (JVM, browsers, Node) use RWX memory;
log daemons keep rotated files deleted-but-open; containers use private
namespaces. Read the evidence line and the suggested next step.

## Live tracing and capture

Open the trace menu with `R`, pick a profile, set a duration with `+`/`-`, and
confirm. Output streams into the **Trace** view and is written to
`trace/<profile>-<UTC>.log` in the case, then hashed when the run ends. Stop a
running capture early with `x` (piddigger sends SIGINT first so tools flush
their summaries, then escalates).

| Profile | Tool | Impact | What it answers |
| :-- | :-- | :-- | :-- |
| Syscalls · everything / file / network / process / summary | strace | ptrace | What syscalls, files, connections and child execs are happening now |
| Library calls | ltrace | ptrace | Which libc/library functions are called |
| CPU counters | perf stat | observe | Context switches, faults, cycles, instructions |
| CPU profile · hot functions | perf record | observe | Where CPU time goes (DSO/symbol); `perf.data` kept |
| eBPF · syscall counts / file opens / fork & exec | bpftrace | observe | Kernel-side behaviour without ptrace |
| Traffic on the target's ports | tcpdump | observe | Packets on the ports the process uses; `pcap` kept |
| Thread backtraces | gdb | pause | A one-shot stack of every thread |
| Memory image | gcore | pause | A full core dump for offline analysis |

`observe` is kernel-side and does not stop the target. `ptrace` attaches
(slows the target and is visible through `TracerPid`; only one tracer at a
time). `pause` briefly stops every thread. If kernel `yama/ptrace_scope`
restricts attaching, piddigger warns you to run as root.

Install the tools you need — they are not hard dependencies:

```sh
sudo apt install strace ltrace linux-perf bpftrace tcpdump gdb
```

## Evidence case layout

Press `s` to open a case (on first use) and preserve a snapshot. Volatile data
is copied first.

```text
piddigger-case-<host>-<pid>-<UTC>/
  case.json            tool name/version + SHA-256, collector euid/pid, host, target
  custody.log          append-only: OPEN, COLLECT, SNAPSHOT, TRACE, VERIFY, WARN, CLOSE
  SHA256SUMS           sha256sum -c compatible manifest of every artifact
  snap-001-<UTC>/
    proc/              raw copies of stat, status, maps, smaps, net/*, environ, …
    report.json        the full parsed snapshot
    findings.json      triage findings (machine readable)
    findings.txt       triage report (human readable)
    activity.jsonl     the observed activity timeline
    exe/<name>.bin     the executable, copied through /proc/<pid>/exe
    recovered/         deleted-but-open and memfd files, recovered through their fds
  trace/               strace / perf / bpftrace / tcpdump / gdb output
```

Every artifact is created once and sealed read-only (mode 0400); the case
directory is mode 0700. The executable is read through `/proc/<pid>/exe`, so a
**deleted or memfd binary is still captured**. Hashes are computed as data is
written. Verify the whole case any time with `v` in the UI, or offline:

```sh
cd piddigger-case-web-prod-07-4982-20261006T121314Z
sha256sum -c SHA256SUMS
less custody.log
```

## Data sources and limits

- All live data comes from `/proc/<pid>`; user and group names from
  `/etc/passwd`; interface names from `/sys/class/net`.
- Socket details come from the target's `/proc/<pid>/net/*` tables, matched to
  the socket inodes behind its descriptors — so you see exactly the sockets this
  process holds, not the whole host.
- Address families not exposed under `/proc/net` (vsock, bluetooth, AF_ALG) show
  as a socket with the family noted rather than being dropped.
- CPU percentage is derived from the delta of used ticks between refreshes; it
  needs at least two samples.
- `N/A` means unavailable (permission, kernel config, or the field does not
  apply); piddigger never fabricates a value.
- A process can exit mid-investigation. piddigger keeps the last snapshot,
  pauses refresh and marks it exited.

## Build and Debian packages

Requires Linux, Rust 1.94+, make, binutils and dpkg-deb.

```sh
make build            # release binary at target/release/piddigger
make test             # unit tests (parsers, findings, evidence, tracing)
make check            # fmt --check + clippy -D warnings + tests
make deb              # dist/piddigger_<version>_<arch>.deb
make demo             # run against the synthetic process
make preview          # regenerate documentation SVGs (needs python3-pyte)
sudo make install     # install to /usr/bin and /usr/share/doc
```

The package declares its **actual** minimum glibc, derived from the built
binary, plus `libgcc-s1`. The trace tools are `Recommends`/`Suggests`, so the
package installs without them and piddigger tells you what to add when a capture
needs one. CI builds and packages for amd64 and arm64.
