# HTTP READY

Detect all ports responding to HTTP and HTTPS requests during a pentest.

During pentests, some ports are not identified by nmap as HTTP/HTTPS — this script probes every open port with both protocols and reports which ones respond.

## Requirements

- `nmap` — used for host discovery (`-sn`) and as the port-scan fallback. Its `nmap-services` file (`/usr/share/nmap/nmap-services`, path configurable via `v_services_file`) also supplies the port frequency ranking used for tiered scanning
- `curl` — used to probe open ports with HTTP/HTTPS
- `sudo` — required for host discovery and root port scans

Optional port scanners (used when available, in this priority):

1. `masscan` — very fast, raw-SYN scanner (`--rate` configurable via `v_masscan_rate`, default 50000; run as `v_masscan_jobs` concurrent shards, default 10)
2. `rustscan` — fast Rust port scanner
3. `nmap` — fallback

## Usage

```bash
bash http_ready.sh
```

The script prompts for a host, IP range, or hosts file in nmap format:

```
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : 192.168.1.254
```

Input is validated — only alphanumeric characters, dots, slashes, dashes, underscores, and commas are accepted.

## How it works

1. **Discover live hosts** — `nmap -sn` finds which hosts are up, so port scanning only targets live hosts. They are saved to `live_hosts.txt` rather than printed, so the terminal shows only probe results; set `v_show_hosts=1` to list them as well.
2. **Port scan in tiers** — the first available scanner on the PATH is used: `masscan`, then `rustscan`, then `nmap`. Ports are scanned in tiers ordered by real-world frequency (most common first), not in numeric order.
3. **Extract host/port pairs** from the scanner output.
4. **Probe** every open port with both `http://` and `https://` via `curl` in parallel (`v_thread` concurrent probes).

All 65535 ports are still covered — tiering only changes the order they are scanned in, so hits on common HTTP ports (80, 443, 8080, …) appear within seconds instead of after a full sweep.

### Tiered scanning

Port order comes from the open-frequency column of `/usr/share/nmap/nmap-services`. `v_tiers` holds the cut points (default `"100 1000 8387"`), producing four tiers:

| Tier | Ports | Contents |
|------|-------|----------|
| 1 | 100 | most common (80, 443, 22, 21, 25, …) |
| 2 | 900 | next most common |
| 3 | 7387 | remaining named services |
| 4 | 57148 | everything with no `nmap-services` entry |

The tiers are disjoint and sum to exactly 65535. Each tier is scanned, probed, and written to `http_ready.txt` before the next begins, so results accumulate as the run progresses. If `nmap-services` is missing, the script falls back to a single all-ports scan.

### Parallel masscan shards

Each tier is scanned by `v_masscan_jobs` masscan processes (default 10) run concurrently with `xargs -P`, using masscan's `--shard i/N` to split the address/port space. All shards share one `--seed`, which is what makes the split disjoint and complete: verified against an unsharded run, 10 shards emit exactly the same set of (host, port) pairs with no duplicates and no gaps.

**`--rate` is per process, so it is divided across the shards** — 10 shards at the default 50000 run at 5000 pps each, keeping the aggregate at `v_masscan_rate` rather than 10x it. This matters because masscan is stateless and does not retry: oversubscribing the link does not raise an error, it silently drops replies and loses ports. Set `v_masscan_jobs=1` for a single process per tier.

Each shard writes its own log and records its exit status. If a shard fails — sudo timing out mid-run, adapter contention, a resource limit — the run reports it:

```
[progress] WARNING: 2/10 masscan shard(s) failed on tier 3 -- those ports were not scanned
[progress]   masscan: FAIL: permission denied
...
[progress] NOTE: at least one tier did not scan cleanly -- some ports were not covered. Re-run to confirm.
```

This matters because a dead shard is otherwise invisible: its slice of the port space is simply never scanned, the tier still reports "done", and the missing ports look exactly like ports that are not open. A failed tier no longer aborts the run — the remaining tiers cover different ports and the results already probed are kept — but the summary states that coverage is incomplete.

Sharding parallelises the scan across processes; it does not raise the total packet rate. If masscan reports a sustained rate far below `v_masscan_rate` (e.g. ~2 kpps against a configured 50000), the link — not the process count — is the bottleneck, and `v_masscan_rate` should be lowered to match what the link actually sustains.

### Probing during the scan

With `v_stream=1` (default), open ports are probed *while* the scanner is still running — `masscan` and `nmap` flush their greppable output incrementally, so the script picks up new host/port pairs every 5s and probes them immediately rather than waiting for the scan to finish. A post-scan sweep catches anything the streamer missed, so a scanner that buffers its output costs responsiveness but never results. Probe output files are keyed by host+port, so a pair seen by both paths is probed once. Set `v_stream=0` to probe per tier only. (Streaming is skipped for `rustscan`, which writes its output at the end.)

Press `Ctrl-C` at any time to stop the current scan cleanly (the scanner's process group is terminated). Results already probed are kept — `http_ready.txt` retains everything found by the completed tiers. Scanner status output is written to per-scanner logs (so it can't garble the terminal); masscan's live status (`% done, found=N`) is shown inline in the progress lines.

### Status panel

In a terminal, `[progress]` messages are pinned to a small block at the **bottom** of the screen (default 6 lines, `v_status_lines`) while results print above it as ordinary output:

```
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.12 Port :443 +++ https://192.168.1.12:443 --- https_code : 200
...                          ← results scroll here, full scrollback preserved
────────────────────────────────────────────────────────────
[progress] Tier 3/4: 7387 port(s) on 8 host(s) with masscan...
[progress] 10 masscan shard(s), 5000 pps each (~50000 pps total)
[progress] tier 3/4 (masscan)... 00:32:10
[progress] 25 open port(s) probed so far.
```

**Results stay scrollable.** The scroll region covers the area *above* the status block, so results scroll through the normal screen area and land in the terminal's scrollback — mouse wheel, `shift+PageUp` and tmux copy-mode all work on them as usual. (Putting the results inside a scroll region instead would keep them out of the scrollback entirely: anything scrolling past the top would be gone from the screen for good. That is why the status block is at the bottom rather than the top.)

The panel keeps the most recent messages, and the repeating scanner-status line updates in place rather than pushing the others out. Implemented with the VT100 scroll-region (DECSTBM) escape written directly, so it does not depend on a terminfo entry. The region is always reset on exit — including on Ctrl-C — so the terminal is never left clamped.

Set `v_status_lines=0` to disable. The panel turns itself off automatically when stdout is not a terminal (piped, redirected, run from cron) or when the terminal is too short, falling back to plain sequential output with no escape codes.

Responding ports are printed to stdout **as each probe returns**, so hits appear live while the scan is still running rather than only in a summary at the end. Lines where the response code is `000` (nothing listening for that protocol) are suppressed from the terminal but still saved in full to `http_ready.txt`. Each open port is probed concurrently via per-port temp files to avoid output interleaving.

## Example — single host

```bash
bash http_ready.sh
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : 192.168.1.254
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443 +++ https://192.168.1.254:443 --- https_code : 302
```

```bash
cat http_ready.txt
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443 +++ http://192.168.1.254:443 --- http_code : 000
Host : 192.168.1.254 Port :443 +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.254 Port :53 +++ http://192.168.1.254:53 --- http_code : 000
Host : 192.168.1.254 Port :5060 +++ http://192.168.1.254:5060 --- http_code : 000
Host : 192.168.1.254 Port :80 +++ https://192.168.1.254:80 --- https_code : 000
Host : 192.168.1.254 Port :53 +++ https://192.168.1.254:53 --- https_code : 000
Host : 192.168.1.254 Port :5060 +++ https://192.168.1.254:5060 --- https_code : 000
```

## Example — hosts file

```bash
bash http_ready.sh
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : hosts.txt
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.65 Port :49152 +++ http://192.168.1.65:49152 --- http_code : 404
Host : 192.168.1.65 Port :9080 +++ http://192.168.1.65:9080 --- http_code : 200
Host : 192.168.1.65 Port :9999 +++ http://192.168.1.65:9999 --- http_code : 403
Host : 192.168.1.30 Port :80 +++ http://192.168.1.30:80 --- http_code : 200
Host : 192.168.1.254 Port :443 +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.30 Port :49152 +++ http://192.168.1.30:49152 --- http_code : 404
```

## Changes (latest)

- **Status panel**: `[progress]` messages are pinned to a small block at the bottom of the terminal (`v_status_lines`, default 6) while results print above it. Results use the terminal's real scrollback -- mouse wheel and shift+PageUp work on them, which a scroll region holding the results would have prevented. Disabled automatically when stdout is not a TTY; the scroll region is restored on every exit path including Ctrl-C
- **Shard failures are reported**: a masscan shard that dies no longer silently skips its slice of the port space -- failed shards are counted, masscan's error is shown, and the summary flags that coverage is incomplete
- **Parallel masscan**: each tier is now scanned by `v_masscan_jobs` concurrent masscan shards (default 10, via `--shard i/N` with a shared `--seed`). `--rate` is divided across them so the aggregate packet rate stays at `v_masscan_rate` instead of multiplying by the shard count
- **Live results**: responding ports print as each probe returns, instead of only in the summary after every tier finished. `000` responses stay out of the terminal but remain in `http_ready.txt`
- **Tiered scanning**: ports are now scanned in order of real-world frequency (from `nmap-services`) instead of numerically, so common HTTP ports are found first. Coverage is unchanged — the tiers are disjoint and sum to all 65535 ports. Cut points are configurable via `v_tiers`
- **Probing during the scan** (`v_stream=1`): open ports are probed while the scanner is still running, instead of only after it exits. A post-scan sweep still catches anything missed, so no result depends on the scanner flushing early
- **Ctrl-C keeps partial results**: `http_ready.txt` now retains everything the completed tiers found instead of being lost with the temp directory
- Scanner priority: `masscan` → `rustscan` → `nmap` (first one found on the PATH is used)
- Host discovery (`nmap -sn`) always runs first so port scanning only targets live hosts — full scans of a `/24` no longer waste time on down hosts
- **Ctrl-C fix**: background jobs ignore SIGINT (POSIX), so the script now enables job control (`set -m`) and traps INT/TERM to kill the scanner's process group (SIGTERM, then SIGKILL) before exiting
- Scanner status output (e.g. masscan's `\r` progress) is redirected to per-scanner logs so it no longer interleaves with `[progress]` lines
- `sudo -v` authenticates once up front; background scanners use `sudo -n` (no terminal prompt needed)
- nmap speedups: `-T5`, `-n` (no reverse DNS), `--max-retries 2`, `-sS` instead of `-sT`
- **Bug fix**: probing failed when `curl` returned non-zero for refused/timed-out ports — curl failures are now tolerated
- Expanded input validation to allow commas (nmap range/group syntax)
- Added `sudo` to file-based host discovery for consistency with direct input
- **Bug fix**: `grep -v "Up"` was inverting the match, removing all live hosts and probing nothing — corrected to `grep "Up"` (later superseded by matching `Ports:` lines)
- **Bug fix**: `grep "Up"` matched only the `Status: Up` line (which has no port data), so no candidates were ever probed — now matches `Ports:` lines
- Replaced non-portable `grep -Po` (PCRE) with `grep -oE` + `tr`
- Replaced `grep` subprocess calls in `probe_host_port()` with bash parameter expansion for ~2x fewer forks per probe
- Eliminated race condition: each probe writes to its own temp file; merged with `find -exec cat {} +` after all probes complete
- **Bug fix**: `grep -v '000'` incorrectly filtered ports containing `000` (e.g., `:1000`, `:2000`) — now filters `grep -vE '(http|https)_code : 000'` matching only the response code field
- Fixed inconsistent spacing in HTTPS output format
- Added `trap` to clean up temp directory on exit
- `v_workdir` is now exported so forked `bash -c` processes can resolve the temp path
