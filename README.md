# HTTP READY

Detect all ports responding to HTTP and HTTPS requests during a pentest.

During pentests, some ports are not identified by nmap as HTTP/HTTPS — this script probes every open port with both protocols and reports which ones respond.

## Requirements

- `nmap`
- `curl`
- `sudo` (required for SYN/connect scans)

## Usage

```bash
bash http_ready.sh
```

The script prompts for a host, IP range, or hosts file in nmap format:

```
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : 192.168.1.254
```

Input is validated — only alphanumeric characters, dots, slashes, dashes, and underscores are accepted.

Results are printed to stdout (non-000 responses only) and saved in full to `http_ready.txt`.

## Example — single host

```bash
bash http_ready.sh
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : 192.168.1.254
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
```

```bash
cat http_ready.txt
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443 +++ http://192.168.1.254:443 --- http_code : 000
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.254 Port :53 +++ http://192.168.1.254:53 --- http_code : 000
Host : 192.168.1.254 Port :5060 +++ http://192.168.1.254:5060 --- http_code : 000
Host : 192.168.1.254 Port :80  +++ https://192.168.1.254:80 --- https_code : 000
Host : 192.168.1.254 Port :53  +++ https://192.168.1.254:53 --- https_code : 000
Host : 192.168.1.254 Port :5060  +++ https://192.168.1.254:5060 --- https_code : 000
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
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.30 Port :49152 +++ http://192.168.1.30:49152 --- http_code : 404
```

## Changes (latest)

- Added `set -uo pipefail` for strict error handling
- Added input validation to block command injection
- Extracted curl probing into `probe_host_port()` function — fixes broken variable expansion in `xargs`
- All variables properly double-quoted
- `read` uses `-r` flag
- Removed unused variable `s_namp`
- `rm` replaced with `rm -f`
- Removed useless use of `cat` in pipeline
