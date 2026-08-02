#!/bin/bash
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
export v_workdir
trap 'rm -rf "$v_workdir"' EXIT
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

echo "[progress] Discovering live hosts..."
v_disco_stats=""
[[ $v_debug == 1 ]] && v_disco_stats="-stats-every $v_nmap_stats"
(
    if test -f "$v_host_def"; then
        sudo nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
    else
        sudo nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
    fi
) &
discovery_pid=$!
while kill -0 "$discovery_pid" 2>/dev/null; do
    echo "[progress] Host discovery still running... $(date '+%H:%M:%S')"
    sleep 15
done
wait "$discovery_pid"

if [[ $? -ne 0 ]]; then
    echo "[progress] Host discovery failed" >&2
    exit 1
fi

echo "[progress] Scanning open ports on discovered hosts..."
(
    sudo nmap -n -T5 -sS --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" --max-retries 2 -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list"
) &
scan_pid=$!
while kill -0 "$scan_pid" 2>/dev/null; do
    echo "[progress] Port scan still running... $(date '+%H:%M:%S')"
    sleep 15
done
wait "$scan_pid"

if [[ $? -ne 0 ]]; then
    echo "[progress] Port scan failed" >&2
    exit 1
fi

#-----------------------------
#Generate function file
#-----------------------------
echo "[progress] Extracting candidate host/port pairs..."
count=0
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
    curl -s -m "$wait" -o /dev/null -w "Host : ${host} Port :${port} +++ http://${host}:${port} --- http_code : %{response_code}\n" "http://${host}:${port}" >> "$out"
    curl -s -m "$wait" -o /dev/null -k -w "Host : ${host} Port :${port} +++ https://${host}:${port} --- https_code : %{response_code}\n" "https://${host}:${port}" >> "$out"
}
export -f probe_host_port

rm -f http_ready.txt
mkdir -p "$v_workdir/results"
probe_count=$(grep -- '--- Ports:' "$v_host_ports" | wc -l | tr -d ' ')
echo "[progress] Probing $probe_count discovered port candidates (${v_thread} in parallel)..."
(
    grep -- '--- Ports:' "$v_host_ports" | xargs -P "$v_thread" -I{} bash -c 'probe_host_port "{}" '"$v_wait"
) &
probe_pid=$!
while kill -0 "$probe_pid" 2>/dev/null; do
    done_count=$(find "$v_workdir/results" -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')
    echo "[progress] Probed $done_count/$probe_count candidates..."
    sleep 5
done
wait "$probe_pid"
if [[ $? -ne 0 ]]; then
    echo "[progress] Probing failed" >&2
    exit 1
fi
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
