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
(
    if test -f "$v_host_def"; then
        if [[ $v_debug == 1 ]]; then
            sudo nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -stats-every "$v_nmap_stats" -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
        else
            sudo nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
        fi
    else
        if [[ $v_debug == 1 ]]; then
            sudo nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -stats-every "$v_nmap_stats" "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
        else
            sudo nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list"
        fi
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
    if [[ $v_debug == 1 ]]; then
        sudo nmap -sS --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list"
    else
        sudo nmap -sT --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list"
    fi
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
        echo "------ host :$host ------" | tee -a "$v_host_ports" >/dev/null 2>&1
        ports=$(echo "$line" | grep -oE '[0-9]+/' | tr -d '/')
        if [[ -n "$ports" ]]; then
            for y in $ports; do
                echo "$host --- Ports: $y" | tee -a "$v_host_ports" >/dev/null 2>&1
            done
        fi
    fi
done < <(grep "Up" "$v_port_list")

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
    echo "[progress] probing http(s)://${host}:${port}" >&2
    curl -s -m "$wait" -o /dev/null -w "Host : ${host} Port :${port} +++ http://${host}:${port} --- http_code : %{response_code}\n" "http://${host}:${port}" >> "$out"
    curl -s -m "$wait" -o /dev/null -k -w "Host : ${host} Port :${port} +++ https://${host}:${port} --- https_code : %{response_code}\n" "https://${host}:${port}" >> "$out"
}
export -f probe_host_port

rm -f http_ready.txt
mkdir -p "$v_workdir/results"
probe_count=$(grep -- '--- Ports:' "$v_host_ports" | wc -l | tr -d ' ')
echo "[progress] Probing $probe_count discovered port candidates..."
probe_index=0
while IFS= read -r entry; do
    probe_index=$((probe_index + 1))
    if (( probe_index % 50 == 0 )); then
        echo "[progress] Probed $probe_index/$probe_count candidates so far..."
    fi
    probe_host_port "$entry" "$v_wait"
done < <(grep -- '--- Ports:' "$v_host_ports")
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
