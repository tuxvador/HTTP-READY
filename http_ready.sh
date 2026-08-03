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
# Number of masscan workers run concurrently (via xargs -P) using --shard, so
# the tier's address/port space is split N ways. NOTE: --rate is per process, so
# v_masscan_rate is divided across the workers to keep the aggregate packet rate
# at v_masscan_rate rather than N times it. masscan is stateless and does not
# retry, so oversubscribing the link shows up as missed ports, not as errors.
# Set to 1 to run a single masscan process per tier.
v_masscan_jobs=10
# Tiered scanning: ports are scanned in order of real-world frequency (from
# nmap-services), most common first, so HTTP hits on well-known ports land in
# the results within seconds instead of after a full 65535-port sweep.
# v_tiers holds the cut points; the final tier is always "everything not yet
# scanned", so all 65535 ports are still covered exactly once.
v_tiers="100 1000 8387"
v_services_file="/usr/share/nmap/nmap-services"
# Probe discovered ports while the scan is still running (masscan/nmap write
# their greppable output incrementally). 0 disables and probes per tier only.
v_stream=1
# Split-screen output: keep [progress] lines in a fixed region at the top of the
# terminal and let results scroll underneath, so the two never interleave.
# Height of the progress region in lines; 0 disables the split entirely.
v_status_lines=15
export v_workdir
# split_stop is defined below; guard the call so the trap is safe if the script
# exits before it exists. Restoring the scroll region on every exit path keeps a
# failed or interrupted run from leaving the terminal clamped.
trap 'declare -F split_stop >/dev/null && split_stop; rm -rf "$v_workdir"' EXIT
#-----------------------------
#Split-screen output
#-----------------------------
# The terminal is divided into a fixed status region at the top (progress
# messages) and a scrolling region below it (results), using the VT100
# DECSTBM margin sequence. Escapes are written directly rather than through
# tput so this does not depend on a terminfo entry being present.
#
# status() writes progress lines; they are kept in a ring buffer and the region
# is redrawn in place, so the newest v_status_lines messages are always visible.
# emit() writes result lines; they scroll normally in the lower region.
#
# Falls back to plain sequential output when stdout is not a TTY (piped to a
# file, run from cron) or when v_status_lines is 0.
v_split=0
v_status_file="${v_workdir}/status.lines"
if [[ -t 1 && $v_status_lines -gt 0 ]]; then
    v_term_lines=$( (tput lines 2>/dev/null) || echo 0 )
    [[ -n "$v_term_lines" ]] || v_term_lines=0
    # Need room for the status region plus a usable scrolling area.
    if (( v_term_lines >= v_status_lines + 5 )); then
        v_split=1
    fi
fi
: > "$v_status_file"

split_start() {
    (( v_split == 1 )) || return 0
    printf '\033[2J'                                   # clear screen
    printf '\033[%d;%dr' $((v_status_lines + 1)) "$v_term_lines"   # scroll region below status
    printf '\033[%d;1H' $((v_status_lines + 1))        # park cursor in scroll region
}

split_stop() {
    (( v_split == 1 )) || return 0
    printf '\033[r'                                    # reset scroll region to full screen
    printf '\033[%d;1H' "$v_term_lines"                # cursor to bottom
    printf '\033[?25h'                                 # ensure cursor visible
}

# Redraw the status region from the ring buffer. Cursor position is saved and
# restored so this never disturbs where results are scrolling.
split_redraw() {
    (( v_split == 1 )) || return 0
    local i=0 line
    printf '\033[s'                                    # save cursor
    printf '\033[?25l'                                 # hide cursor while redrawing
    while IFS= read -r line; do
        i=$((i + 1))
        printf '\033[%d;1H\033[2K%.*s' "$i" "$((${COLUMNS:-200}))" "$line"
    done < "$v_status_file"
    # Blank any unused rows so stale text does not linger.
    while (( i < v_status_lines )); do
        i=$((i + 1))
        printf '\033[%d;1H\033[2K' "$i"
    done
    # Separator on the last status row.
    printf '\033[%d;1H\033[2K\033[2m%s\033[0m' "$v_status_lines" \
        "$(printf '%.0s─' $(seq 1 "${COLUMNS:-80}"))"
    printf '\033[u'                                    # restore cursor
    printf '\033[?25h'
}

# Progress/status message: goes to the top region when split, stdout otherwise.
status() {
    if (( v_split == 1 )); then
        # Keep only the most recent (v_status_lines - 1) messages; the last row
        # is the separator.
        printf '%s\n' "$*" >> "$v_status_file"
        local keep=$((v_status_lines - 1))
        tail -n "$keep" "$v_status_file" > "$v_status_file.tmp" 2>/dev/null && mv "$v_status_file.tmp" "$v_status_file"
        split_redraw
    else
        printf '%s\n' "$*"
    fi
}
export v_status_lines v_split v_status_file

# Result line: scrolls in the lower region (or plain stdout when not split).
# Exported so probe_host_port() can use it from `xargs`-spawned subshells.
emit() {
    printf '%s\n' "$*"
}
export -f emit

v_has_masscan=0
if command -v masscan >/dev/null 2>&1; then
    v_has_masscan=1
fi
v_has_rustscan=0
if command -v rustscan >/dev/null 2>&1; then
    v_has_rustscan=1
fi

# Collapse a sorted list of port numbers into masscan/nmap range syntax
# (1,2,3,7 -> 1-3,7). Without this the last tier is ~57k comma-separated
# ports, which overflows the command line.
compress_ports() {
    awk 'NR==1 {s=$1; p=$1; next}
         $1==p+1 {p=$1; next}
         {printf "%s%s", (o++?",":""), (s==p?s:s"-"p); s=$1; p=$1}
         END {if (NR) printf "%s%s\n", (o++?",":""), (s==p?s:s"-"p)}'
}

# Write frequency-ordered port tiers to $v_workdir/tier.N (one port per line,
# numerically sorted). Ports are ranked by the open-frequency column of
# nmap-services; everything absent from that file forms the final tier so the
# union of all tiers is still 1-65535. Falls back to a single all-ports tier
# when nmap-services is unavailable.
build_tiers() {
    local ranked="$v_workdir/ranked.txt"
    local n=0 start=1 cut
    if [[ ! -r "$v_services_file" ]]; then
        status "[progress] $v_services_file not found, scanning all ports in one pass."
        seq 1 65535 > "$v_workdir/tier.1"
        v_tier_count=1
        return 0
    fi
    awk '$2 ~ /\/tcp$/ {split($2, a, "/"); if (a[1]+0 >= 1 && a[1]+0 <= 65535) print a[1], $3}' \
        "$v_services_file" | sort -k2 -rn | awk '!seen[$1]++ {print $1}' > "$ranked"
    for cut in $v_tiers; do
        (( cut > $(wc -l < "$ranked") )) && cut=$(wc -l < "$ranked")
        (( cut < start )) && continue
        n=$((n + 1))
        sed -n "${start},${cut}p" "$ranked" | sort -n > "$v_workdir/tier.$n"
        start=$((cut + 1))
    done
    # Final tier: every port with no nmap-services entry. Done with awk rather
    # than comm so it does not depend on lexical vs numeric sort order.
    n=$((n + 1))
    awk 'NR==FNR {known[$1]; next} !($1 in known)' "$ranked" <(seq 1 65535) > "$v_workdir/tier.$n"
    [[ -s "$v_workdir/tier.$n" ]] || { rm -f "$v_workdir/tier.$n"; n=$((n - 1)); }
    v_tier_count=$n
}
# Stop the running scanner and exit cleanly on Ctrl-C / kill. Background jobs
# ignore SIGINT (POSIX), so kill the scanner's process group with SIGTERM.
# We `wait` on the scanner (not a sleep loop) so the INT/TERM trap fires reliably.
v_scan_pid=""
v_notify_pid=""
v_stream_pid=""
cleanup_scan() {
    # Restore the full-screen scroll region first: leaving DECSTBM set would
    # confine the user's shell to the lower part of the terminal after exit.
    split_stop
    echo "" >&2
    echo "[progress] Interrupted, stopping scanner..." >&2
    if [[ -n "$v_notify_pid" ]]; then
        kill -TERM -- "-$v_notify_pid" 2>/dev/null
    fi
    if [[ -n "$v_stream_pid" ]]; then
        kill -TERM -- "-$v_stream_pid" 2>/dev/null
    fi
    if [[ -n "$v_scan_pid" ]]; then
        kill -TERM -- "-$v_scan_pid" 2>/dev/null
        sleep 1
        kill -KILL -- "-$v_scan_pid" 2>/dev/null
    fi
    # Keep whatever the completed tiers already found.
    if [[ -d "$v_workdir/results" ]]; then
        find "$v_workdir/results" -name '*.tmp' -exec cat {} + > http_ready.txt 2>/dev/null
        v_partial=$(find "$v_workdir/results" -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')
        echo "[progress] Kept $v_partial probed port(s) in http_ready.txt" >&2
    fi
    exit 130
}
trap cleanup_scan INT TERM

# Wait for the current scanner ($v_scan_pid) while printing periodic progress.
# Optional $3 log file tail is shown for masscan's status (found=N, etc.).
wait_scan() {
    v_wait_msg="$1"
    v_wait_int="$2"
    v_wait_log="${3:-}"
    (
        # This runs in a subshell, so it cannot update the parent's ring buffer
        # in memory -- but status() works through the shared status file and
        # writes escapes straight to the terminal, so both still apply here.
        # The repeating "still running" line replaces its previous copy instead
        # of filling the region, so the surrounding context stays visible.
        while kill -0 "$v_scan_pid" 2>/dev/null; do
            extra=""
            if [[ -n "$v_wait_log" && -s "$v_wait_log" ]]; then
                extra=" | $(tr '\r' '\n' < "$v_wait_log" | grep -v '^$' | tail -1)"
            fi
            if (( v_split == 1 )); then
                grep -v "^\[progress\] $v_wait_msg\.\.\. " "$v_status_file" > "$v_status_file.w" 2>/dev/null
                mv "$v_status_file.w" "$v_status_file" 2>/dev/null
            fi
            status "[progress] $v_wait_msg... $(date '+%H:%M:%S')$extra"
            sleep "$v_wait_int"
        done
    ) &
    v_notify_pid=$!
    wait "$v_scan_pid"
    local rc=$?
    kill -TERM -- "-$v_notify_pid" 2>/dev/null
    wait "$v_notify_pid" 2>/dev/null
    v_notify_pid=""
    return "$rc"
}
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

# Split the terminal only after the host prompt and the sudo password prompt,
# so neither is drawn into (or cleared by) the status region.
split_start

status "[progress] Discovering live hosts..."
v_disco_stats=""
[[ $v_debug == 1 ]] && v_disco_stats="-stats-every $v_nmap_stats"
# When split, discovered IPs go to the host list only -- printing them would
# scatter them through the results region. They are summarised in the status
# region instead. Without the split, keep the original streaming `tee` output.
if (( v_split == 1 )); then
    v_disco_sink="/dev/null"
else
    v_disco_sink="/dev/stdout"
fi
(
    if test -f "$v_host_def"; then
        sudo -n nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats -iL "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" > "$v_disco_sink"
    else
        sudo -n nmap -n -T5 --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" -sn $v_disco_stats "$v_host_def" | grep "scan report for" | grep -Eo "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" | tee "$v_host_list" > "$v_disco_sink"
    fi
) &
v_scan_pid=$!
wait_scan "Host discovery still running" 15
if [[ $? -ne 0 ]]; then
    status "[progress] Host discovery failed"
    exit 1
fi
v_scan_pid=""

if [[ ! -s "$v_host_list" ]]; then
    status "[progress] No live hosts found, nothing to scan."
    exit 0
fi
if (( v_split == 1 )); then
    status "[progress] $(wc -l < "$v_host_list") live host(s): $(tr '\n' ' ' < "$v_host_list" | cut -c1-100)"
fi

v_port_scanner="nmap"
if [[ $v_has_masscan == 1 ]]; then
    v_port_scanner="masscan"
elif [[ $v_has_rustscan == 1 ]]; then
    v_port_scanner="rustscan"
fi

#-----------------------------
#Compute result
#-----------------------------
# Probe one host:port with both http and https. The output file name is derived
# from host+port, so probing the same pair twice (streamer and final sweep)
# simply rewrites the same file instead of duplicating a result.
# Responding ports are printed as soon as curl returns, so hits appear live
# rather than only in the summary at the end. Each line is emitted with a single
# printf because probes run under `xargs -P` and separate writes would interleave.
probe_host_port() {
    local entry="$1"
    local wait="$2"
    local host port out line
    host="${entry%% ---*}"
    port="${entry##*Ports: }"
    out="$v_workdir/results/${host}_${port}.tmp"
    # Claim this pair before probing. The result file is not created until the
    # first curl returns (up to $wait seconds), so a file-existence check alone
    # lets the streamer's next pass re-probe a port whose probe is still in
    # flight. mkdir is atomic: only one caller can create the claim directory,
    # so concurrent passes and the post-scan sweep cannot double-probe.
    mkdir "$v_workdir/claim/${host}_${port}" 2>/dev/null || return 0
    if [[ $v_debug == 1 ]]; then
        echo "[progress] probing http(s)://${host}:${port}" >&2
    fi
    : > "$out"
    line=$(curl -s -m "$wait" -o /dev/null -w "Host : ${host} Port :${port} +++ http://${host}:${port} --- http_code : %{response_code}" "http://${host}:${port}") || true
    if [[ -n "$line" ]]; then
        printf '%s\n' "$line" >> "$out"
        [[ "$line" == *"http_code : 000" ]] || printf '%s\n' "$line"
    fi
    line=$(curl -s -m "$wait" -o /dev/null -k -w "Host : ${host} Port :${port} +++ https://${host}:${port} --- https_code : %{response_code}" "https://${host}:${port}") || true
    if [[ -n "$line" ]]; then
        printf '%s\n' "$line" >> "$out"
        [[ "$line" == *"https_code : 000" ]] || printf '%s\n' "$line"
    fi
}
export -f probe_host_port

# Turn a scanner's greppable output into "host --- Ports: N" lines on stdout.
# Reads the file named by $1. Emitting to stdout (rather than appending to a
# global) lets the same parser feed both the live streamer and the post-scan
# sweep; callers dedupe against $v_workdir/results.
extract_pairs() {
    local src="$1" line host ports y
    if [[ $v_port_scanner == rustscan ]]; then
        while IFS= read -r line; do
            host=$(echo "$line" | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}')
            [[ -n "$host" ]] || continue
            ports=$(echo "$line" | sed -E 's/.*\[([0-9,]+)\]/\1/' | tr ',' ' ')
            for y in $ports; do
                echo "$host --- Ports: $y"
            done
        done < "$src"
    else
        while IFS= read -r line; do
            host=$(echo "$line" | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}')
            [[ -n "$host" ]] || continue
            ports=$(echo "$line" | grep -oE '[0-9]+/' | tr -d '/')
            for y in $ports; do
                echo "$host --- Ports: $y"
            done
        done < <(grep "Ports:" "$src" 2>/dev/null)
    fi
}

# Merge the per-shard masscan outputs for the current tier into $v_port_list so
# the parsers downstream only ever read one file. No-op for single-process
# scanners, which write $v_port_list directly.
collect_shards() {
    [[ $v_port_scanner == masscan ]] || return 0
    cat "$v_workdir/shard.$v_tier".* > "$v_port_list" 2>/dev/null || true
}

# Filter "host --- Ports: N" lines on stdin down to pairs not yet claimed. This
# is an early cheap filter only -- probe_host_port() claims atomically, which is
# what actually prevents double-probing. Checks the claim dir rather than the
# result file because a probe in flight has a claim but no result yet.
filter_unprobed() {
    local line host port
    while IFS= read -r line; do
        host="${line%% ---*}"
        port="${line##*Ports: }"
        [[ -d "$v_workdir/claim/${host}_${port}" ]] && continue
        echo "$line"
    done
}

# Probe every pending pair in $1 (a file of "host --- Ports: N" lines).
probe_pairs_file() {
    local pending="$1" label="$2" n
    [[ -s "$pending" ]] || return 0
    n=$(grep -c -- '--- Ports:' "$pending" 2>/dev/null)
    [[ -n "$n" ]] || n=0
    (( n > 0 )) || return 0
    status "[progress] Probing $n $label candidate(s) (${v_thread} in parallel)..."
    grep -- '--- Ports:' "$pending" | xargs -r -P "$v_thread" -I{} bash -c 'probe_host_port "{}" '"$v_wait" || true
}

rm -f http_ready.txt
mkdir -p "$v_workdir/results" "$v_workdir/claim"

build_tiers
v_live_hosts=$(wc -l < "$v_host_list")

for v_tier in $(seq 1 "$v_tier_count"); do
    v_tier_file="$v_workdir/tier.$v_tier"
    [[ -s "$v_tier_file" ]] || continue
    v_tier_ports=$(compress_ports < "$v_tier_file")
    v_tier_n=$(wc -l < "$v_tier_file")
    v_port_list="$v_workdir/ports.$v_tier"
    : > "$v_port_list"
    status "[progress] Tier $v_tier/$v_tier_count: $v_tier_n port(s) on $v_live_hosts host(s) with $v_port_scanner..."
    case $v_port_scanner in
        masscan)
            # Split the tier across $v_masscan_jobs shards run concurrently.
            # All shards must share one --seed or they do not partition the
            # space correctly. --rate is per process, so divide it to keep the
            # aggregate at v_masscan_rate.
            v_shards=$v_masscan_jobs
            (( v_shards < 1 )) && v_shards=1
            v_shard_rate=$(( v_masscan_rate / v_shards ))
            (( v_shard_rate < 1 )) && v_shard_rate=1
            v_seed=$RANDOM$RANDOM
            rm -f "$v_workdir/shard.$v_tier".*
            if (( v_shards > 1 )); then
                status "[progress] $v_shards masscan shard(s), ${v_shard_rate} pps each (~${v_masscan_rate} pps total)"
            fi
            (
                seq 1 "$v_shards" | xargs -r -P "$v_shards" -I{} \
                    sudo -n masscan -iL "$v_host_list" -p"$v_tier_ports" \
                        --rate "$v_shard_rate" --seed "$v_seed" --shard {}/"$v_shards" \
                        -oG "$v_workdir/shard.$v_tier.{}" >"$v_workdir/masscan.log" 2>&1
            ) &
            ;;
        rustscan)
            v_port_list="${v_workdir}/rustscan.$v_tier"
            : > "$v_port_list"
            (
                rustscan -n -g -a "$v_host_list" -p "$(tr '\n' ',' < "$v_tier_file" | sed 's/,$//')" > "$v_port_list" 2>"$v_workdir/rustscan.log"
            ) &
            ;;
        nmap)
            (
                sudo -n nmap -n -T5 -sS --min-parallelism="$v_min_paral" --max-parallelism="$v_max_paral" --max-retries 2 -stats-every "$v_nmap_stats" -p"$v_tier_ports" -iL "$v_host_list" -oG "$v_port_list" >"$v_workdir/nmap.log" 2>&1
            ) &
            ;;
    esac
    v_scan_pid=$!

    # Probe ports as the scanner reports them. masscan/nmap flush greppable
    # output incrementally, so this overlaps probing with the scan. Anything the
    # streamer misses is still caught by the post-scan extraction below, so a
    # scanner that buffers its output only costs responsiveness, not results.
    v_stream_pid=""
    if [[ $v_stream == 1 && $v_port_scanner != rustscan ]]; then
        (
            while kill -0 "$v_scan_pid" 2>/dev/null; do
                sleep 5
                collect_shards
                [[ -s "$v_port_list" ]] || continue
                extract_pairs "$v_port_list" | filter_unprobed \
                    | xargs -r -P "$v_thread" -I{} bash -c 'probe_host_port "{}" '"$v_wait" 2>/dev/null || true
            done
        ) &
        v_stream_pid=$!
    fi

    if [[ $v_port_scanner == masscan ]]; then
        wait_scan "tier $v_tier/$v_tier_count ($v_port_scanner)" 15 "$v_workdir/masscan.log"
    else
        wait_scan "tier $v_tier/$v_tier_count ($v_port_scanner)" 15
    fi
    v_rc=$?
    if [[ -n "$v_stream_pid" ]]; then
        kill -TERM -- "-$v_stream_pid" 2>/dev/null
        wait "$v_stream_pid" 2>/dev/null
        v_stream_pid=""
    fi
    if [[ $v_rc -ne 0 ]]; then
        status "[progress] $v_port_scanner failed on tier $v_tier"
        exit 1
    fi
    v_scan_pid=""

    # Catch anything the streamer did not get to, then probe the leftovers.
    collect_shards
    extract_pairs "$v_port_list" >> "$v_host_ports"
    v_todo="$v_workdir/todo.$v_tier"
    extract_pairs "$v_port_list" | filter_unprobed > "$v_todo"
    probe_pairs_file "$v_todo" "tier $v_tier"

    v_found=$(find "$v_workdir/results" -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')
    status "[progress] Tier $v_tier done. $v_found open port(s) probed so far."
    # Publish results after every tier so an interrupted run still leaves output.
    find "$v_workdir/results" -name '*.tmp' -exec cat {} + > http_ready.txt 2>/dev/null
done

# Responding ports were already printed live by probe_host_port, so the summary
# only needs to write the full log and report the totals.
find "$v_workdir/results" -name '*.tmp' -exec cat {} + > http_ready.txt 2>/dev/null
v_responded=$(grep -cvE '(http|https)_code : 000' http_ready.txt 2>/dev/null)
[[ -n "$v_responded" ]] || v_responded=0
v_probed=$(find "$v_workdir/results" -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')
status "[progress] Finished. $v_responded HTTP/HTTPS response(s) from $v_probed open port(s); full log in http_ready.txt"

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
