#!/bin/bash
set -m
set -uo pipefail
#Function to detect all port responding to http request during a pentest
#-------------------------
#String def
#-------------------------
s_host_def="Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0"
v_debug=0
v_workdir=$(mktemp -d)
v_host_list="${v_workdir}/hosts.nmap"
v_port_list="${v_workdir}/ports.nmap"
v_host_ports="${v_workdir}/host_ports.ready"
v_wait=5
v_thread=500
v_nmap_stats="60s"
v_min_paral=200
v_max_paral=400
v_masscan_rate=50000
export v_workdir
trap 'rm -rf "$v_workdir"' EXIT
v_has_masscan=0
if command -v masscan >/dev/null 2>&1; then
    v_has_masscan=1
fi
v_has_rustscan=0
if command -v rustscan >/dev/null 2>&1; then
    v_has_rustscan=1
fi
# Stop the running scanner and exit cleanly on Ctrl-C / kill. Background jobs
# ignore SIGINT (POSIX), so kill the scanner's process group with SIGTERM.
v_scan_pid=""
cleanup_scan() {
    echo "" >&2
    echo "[progress] Interrupted, stopping scanner..." >&2
    if [[ -n "$v_scan_pid" ]]; then
        kill -TERM -- "-$v_scan_pid" 2>/dev/null
        sleep 1
        kill -KILL -- "-$v_scan_pid" 2>/dev/null
    fi
    exit 130
}
trap cleanup_scan INT TERM
#-----------------------------
#Generate Nmap file
#-----------------------------
mkdir -p "$v_workdir"
echo "$s_host_def"
read -r -p "Hosts(s) : " v_host_def

# Input validation: allow only safe characters (alphanumeric, dots, slashes, dashes, underscores)
if [[ ! "$v_host_def" =~ ^[a-zA-Z0-9./_,\-]+$ ]]; then
    echo "Error: invalid input '$v_host_def'" >&2
    exit 1
fi

# Authenticate in the foreground so backgrounded sudo (-n) never needs to
# prompt on the terminal (job-controlled background groups would be stopped
# by SIGTTIN when reading /dev/tty).
echo "[progress] Checking sudo access..."
if ! sudo -v; then
    echo "[progress] sudo authentication failed" >&2
    exit 1
fi

echo "[progress] Discovering live hosts..."
v_disco_stats=""
[[ $v_debug == 1 ]] && v_disco_stats="-stats-every $v_nmap_stats"
(
    if test -f "$v_host_def"; then
        sudo -n nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
    else
        sudo -n nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
    fi
) &
v_scan_pid=$!
while kill -0 "$v_scan_pid" 2>/dev/null; do
    echo "[progress] Host discovery still running... $(date '+%H:%M:%S')"
    sleep 15
done
wait "$v_scan_pid"
if [[ $? -ne 0 ]]; then
    echo "[progress] Host discovery failed" >&2
    exit 1
fi
v_scan_pid=""

if [[ ! -s "$v_host_list" ]]; then
    echo "[progress] No live hosts found, nothing to scan." >&2
    exit 0
fi

v_port_scanner="nmap"
if [[ $v_has_masscan == 1 ]]; then
    v_port_scanner="masscan"
elif [[ $v_has_rustscan == 1 ]]; then
    v_port_scanner="rustscan"
fi

echo "[progress] Scanning $(( $(wc -l < "$v_host_list") )) live host(s) with $v_port_scanner..."
case $v_port_scanner in
    masscan)
        (
            sudo -n masscan -iL "$v_host_list" -p1-65535 --rate "$v_masscan_rate" -oG "$v_port_list" >"$v_workdir/masscan.log" 2>&1
        ) &
        ;;
    rustscan)
        v_rs_out="${v_workdir}/rustscan.out"
        (
            rustscan -n -g -a "$v_host_list" > "$v_rs_out" 2>"$v_workdir/rustscan.log"
        ) &
        ;;
    nmap)
        (
            sudo -n nmap -n -T5 -sS --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" --max-retries 2 -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list" >"$v_workdir/nmap.log" 2>&1
        ) &
        ;;
esac
v_scan_pid=$!
while kill -0 "$v_scan_pid" 2>/dev/null; do
    echo "[progress] $v_port_scanner still running... $(date '+%H:%M:%S')"
    sleep 15
done
wait "$v_scan_pid"
if [[ $? -ne 0 ]]; then
    echo "[progress] $v_port_scanner failed" >&2
    exit 1
fi
v_scan_pid=""

echo "[progress] Extracting candidate host/port pairs..."
count=0
if [[ $v_port_scanner == rustscan ]]; then
    while IFS= read -r line; do
        count=$((count + 1))
        if (( count % 100 == 0 )); then
            echo "[progress] Processed $count candidate lines..."
        fi
        host=$(echo "$line" | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}')
        if [[ -n "$host" ]]; then
            echo "------ host :$host ------" >> "$v_host_ports"
            ports=$(echo "$line" | sed -E 's/.*\[([0-9,]+)\]/\1/' | tr ',' ' ')
            for y in $ports; do
                echo "$host --- Ports: $y" >> "$v_host_ports"
            done
        fi
    done < "$v_rs_out"
else
    while IFS= read -r line; do
        count=$((count + 1))
        if (( count % 100 == 0 )); then
            echo "[progress] Processed $count candidate lines..."
        fi
        host=$(echo "$line" | grep -Eo '([0-9]{1,3}[\\.]){3}[0-9]{1,3}')
        if [[ $? == 0 ]]; then
            echo "------ host :$host ------" >> "$v_host_ports"
            ports=$(echo "$line" | grep -oE '[0-9]+/' | tr -d '/')
            if [[ -n "$ports" ]]; then
                for y in $ports; do
                    echo "$host --- Ports: $y" >> "$v_host_ports"
                done
            fi
        fi
    done < <(grep "Ports:" "$v_port_list")
fi

#-----------------------------
#Compute result
#-----------------------------
probe_host_port() {
    local entry="$1"
    local wait="$2"
    local host port out
    host="${entry%% ---*}"
    port="${entry##*Ports: }"
    out="$v_workdir/results/${host}_${port}.tmp"
    if [[ $v_debug == 1 ]]; then
        echo "[progress] probing http(s)://${host}:${port}" >&2
    fi
    curl -s -m "$wait" -o /dev/null -w "Host : ${host} Port :${port} +++ http://${host}:${port} --- http_code : %{response_code}\n" "http://${host}:${port}" >> "$out" || true
    curl -s -m "$wait" -o /dev/null -k -w "Host : ${host} Port :${port} +++ https://${host}:${port} --- https_code : %{response_code}\n" "https://${host}:${port}" >> "$out" || true
}
export -f probe_host_port

rm -f http_ready.txt
mkdir -p "$v_workdir/results"
probe_count=$(grep -- '--- Ports:' "$v_host_ports" | wc -l | tr -d ' ')
echo "[progress] Probing $probe_count discovered port candidates (${v_thread} in parallel)..."
(
    grep -- '--- Ports:' "$v_host_ports" | xargs -P "$v_thread" -I{} bash -c 'probe_host_port "{}" '"$v_wait"
) &
v_scan_pid=$!
while kill -0 "$v_scan_pid" 2>/dev/null; do
    done_count=$(find "$v_workdir/results" -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')
    echo "[progress] Probed $done_count/$probe_count candidates..."
    sleep 5
done
wait "$v_scan_pid"
if [[ $? -ne 0 ]]; then
    echo "[progress] Probing failed" >&2
    exit 1
fi
v_scan_pid=""
echo "[progress] Finished probing all candidates."
find "$v_workdir/results" -name '*.tmp' -exec cat {} + | tee http_ready.txt | grep -vE '(http|https)_code : 000'

#-----------------------------
#Output
#-----------------------------
if [[ $v_debug == 1 ]]; then
    echo "---output---"
    echo "$v_workdir"
    cat "$v_host_ports"
    echo "---end output---"
fi
#-----------------------------
