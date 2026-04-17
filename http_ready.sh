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
#-----------------------------
#Generate Nmap file
#-----------------------------
mkdir -p "$v_workdir"
echo "$s_host_def"
read -r -p "Hosts(s) : " v_host_def

# Input validation: allow only safe characters (alphanumeric, dots, slashes, dashes, underscores)
if [[ ! "$v_host_def" =~ ^[a-zA-Z0-9./_\-]+$ ]]; then
    echo "Error: invalid input '$v_host_def'" >&2
    exit 1
fi

if test -f "$v_host_def"; then
    if [[ $v_debug == 1 ]]; then
        nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -stats-every "$v_nmap_stats" -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" >/dev/null 2>&1
    else
        nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" >/dev/null 2>&1
    fi
else
    if [[ $v_debug == 1 ]]; then
        sudo nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn -stats-every "$v_nmap_stats" "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" >/dev/null 2>&1
    else
        sudo nmap -n --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" >/dev/null 2>&1
    fi
fi

if [[ $v_debug == 1 ]]; then
    sudo nmap -sS --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list" >/dev/null 2>&1
else
    sudo nmap -sT --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -stats-every "$v_nmap_stats" -iL "$v_host_list" -oG "$v_port_list" >/dev/null 2>&1
fi

#-----------------------------
#Generate function file
#-----------------------------
grep -v "Up" "$v_port_list" | while read -r line; do
    host=$(echo "$line" | grep -Eo '([0-9]{1,3}[\\.]){3}[0-9]{1,3}')
    if [[ $? == 0 ]]; then
        echo "------ host :$host ------" | tee -a "$v_host_ports" >/dev/null 2>&1
        ports=$(echo "$line" | grep -Po '(?<= )([0-9]{1,})(?=/)')
        if [[ $? == 0 ]]; then
            for y in $ports; do
                echo "$host --- Ports: $y" | tee -a "$v_host_ports" >/dev/null 2>&1
            done
        fi
    fi
done

#-----------------------------
#Compute result
#-----------------------------
probe_host_port() {
    local entry="$1"
    local wait="$2"
    local host port
    host=$(grep -Eo "^([0-9]{1,3}\.){3}[0-9]{1,3}" <<< "$entry")
    port=$(grep -Po "(?<=Ports: )[0-9]+" <<< "$entry")
    curl -s -m "$wait" -o /dev/null -w "Host : ${host} Port :${port} +++ http://${host}:${port} --- http_code : %{response_code}\n" "http://${host}:${port}"
    curl -s -m "$wait" -o /dev/null -k -w "Host : ${host} Port :${port}  +++ https://${host}:${port} --- https_code : %{response_code}\n" "https://${host}:${port}"
}
export -f probe_host_port

rm -f http_ready.txt
grep -v "host" "$v_host_ports" | xargs -P "$v_thread" -I{} bash -c 'probe_host_port "{}" '"$v_wait" \
    | tee -a http_ready.txt | grep -v '000'

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
