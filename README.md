# HTTP READY

Detect all ports responding to HTTP and HTTPS requests during a pentest.

During pentests, some ports are not identified by nmap as HTTP/HTTPS — this script probes every open port with both protocols and reports which ones respond.

## Requirements

- `nmap` — used for host discovery (`-sn`) and as the port-scan fallback
- `curl` — used to probe open ports with HTTP/HTTPS
- `sudo` — required for host discovery and root port scans

Optional port scanners (used when available, in this priority):

1. `masscan` — very fast, raw-SYN scanner (`--rate` configurable via `v_masscan_rate`, default 50000)
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

1. **Discover live hosts** — `nmap -sn` finds which hosts are up, so port scanning only targets live hosts.
2. **Port scan** — the first available scanner on the PATH is used: `masscan`, then `rustscan`, then `nmap`. All open ports (1-65535) are scanned.
3. **Extract host/port pairs** from the scanner output.
4. **Probe** every open port with both `http://` and `https://` via `curl` in parallel (`v_thread` concurrent probes).

Press `Ctrl-C` at any time to stop the current scan cleanly (the scanner's process group is terminated). Scanner status output is written to per-scanner logs, keeping the terminal output clean.

Results are printed to stdout (filtering out lines where the response code itself is 000) and saved in full to `http_ready.txt`. Each open port is probed concurrently via per-port temp files to avoid output interleaving.

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
