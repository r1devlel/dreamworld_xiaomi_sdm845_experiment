#!/system/bin/sh
# Dipper #116 runtime gaming profile (reversible)
# Usage: su -c 'sh /storage/emulated/0/kerneldev/game-tune.sh on|off|status'
# This does NOT enable bypass charging. It only changes performance/audio/network knobs.

set -u

STATE=/data/local/tmp/game-tune.state
AUDIO_STATE=/data/local/tmp/game-tune.audio
TAB=$(printf '\t')

need_root() {
    [ "$(id -u)" = "0" ] || {
        echo "error: jalankan sebagai root: su -c 'sh $0 $1'"
        exit 1
    }
}

save_write() {
    path="$1"
    value="$2"
    [ -e "$path" ] || return 0
    # trim trailing whitespace: input_boost_freq is exported with a trailing
    # space, and its parser rejects that extra token on restore.
    cur=$(cat "$path" 2>/dev/null | tr -d '\r' | sed 's/[[:space:]]*$//')
    printf '%s\t%s\n' "$path" "$cur" >> "$STATE"
    printf '%s\n' "$value" > "$path" 2>/dev/null
}

save_write_sched() {
    path="$1"
    value="$2"
    [ -e "$path" ] || return 0
    cur=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$path" 2>/dev/null)
    printf '%s\t%s\n' "$path" "$cur" >> "$STATE"
    printf '%s\n' "$value" > "$path" 2>/dev/null
}

save_tinymix() {
    control="$1"
    raw=$(tinymix "$control" 2>/dev/null | sed -n 's/^[^:]*: *//p')
    [ -n "$raw" ] || return 0
    case "$raw" in
        [0-9-]*)
            # integer: first token is the current value
            cur=$(printf '%s\n' "$raw" | awk '{print $1}')
            ;;
        *)
            # enum: the selected value is the token prefixed with '>'
            cur=$(printf '%s\n' "$raw" | tr ' ' '\n' | sed -n 's/^>//p')
            ;;
    esac
    [ -n "$cur" ] || return 0
    printf '%s\t%s\n' "$control" "$cur" >> "$AUDIO_STATE"
}

apply_audio() {
    command -v tinymix >/dev/null 2>&1 || return 0
    : > "$AUDIO_STATE"
    for c in "RX HPH Mode" "RX0 Digital Volume" "RX1 Digital Volume" \
             "RX2 Digital Volume" "RX3 Digital Volume" "RX4 Digital Volume" \
             "RX7 Digital Volume" "RX8 Digital Volume"; do
        save_tinymix "$c"
    done
    tinymix "RX HPH Mode" CLS_H_HIFI >/dev/null 2>&1
    for c in "RX0 Digital Volume" "RX1 Digital Volume" "RX2 Digital Volume" \
             "RX3 Digital Volume" "RX4 Digital Volume" "RX7 Digital Volume" \
             "RX8 Digital Volume"; do
        tinymix "$c" 87 >/dev/null 2>&1
    done
}

restore_audio() {
    [ -s "$AUDIO_STATE" ] || return 0
    command -v tinymix >/dev/null 2>&1 || return 0
    while IFS="$TAB" read -r c v; do
        [ -n "$c" ] || continue
        tinymix "$c" "$v" >/dev/null 2>&1
    done < "$AUDIO_STATE"
    rm -f "$AUDIO_STATE"
}

apply_cpu() {
    # little cluster
    save_write /sys/devices/system/cpu/cpufreq/policy0/scaling_governor schedutil
    save_write /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq 1056000
    save_write /sys/devices/system/cpu/cpufreq/policy0/schedutil/hispeed_freq 1420800
    save_write /sys/devices/system/cpu/cpufreq/policy0/schedutil/up_rate_limit_us 0

    # big cluster
    save_write /sys/devices/system/cpu/cpufreq/policy4/scaling_governor schedutil
    save_write /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq 1209600
    save_write /sys/devices/system/cpu/cpufreq/policy4/schedutil/hispeed_freq 1843200
    save_write /sys/devices/system/cpu/cpufreq/policy4/schedutil/up_rate_limit_us 0

    # input boost: silver 1.42 GHz, gold 1.843 GHz, 400 ms
    save_write /sys/module/cpu_boost/parameters/input_boost_freq \
        "0:1420800 1:1420800 2:1420800 3:1420800 4:1843200 5:1843200 6:1843200 7:1843200"
    save_write /sys/module/cpu_boost/parameters/input_boost_ms 400
    save_write /sys/module/cpu_boost/parameters/sched_boost_on_input 1
}

apply_gpu() {
    save_write /sys/class/kgsl/kgsl-3d0/devfreq/governor msm-adreno-tz
    save_write /sys/class/kgsl/kgsl-3d0/min_pwrlevel 4
    save_write /sys/class/kgsl/kgsl-3d0/max_pwrlevel 0
    save_write /sys/class/kgsl/kgsl-3d0/idle_timer 80
    save_write /sys/class/kgsl/kgsl-3d0/throttling 1
    save_write /sys/class/kgsl/kgsl-3d0/force_clk_on 0
}

apply_io() {
    for d in /sys/block/sd*; do
        [ -d "$d/queue" ] || continue
        save_write_sched "$d/queue/scheduler" deadline
        save_write "$d/queue/read_ahead_kb" 256
        save_write "$d/queue/nr_requests" 128
        save_write "$d/queue/iostats" 0
        save_write "$d/queue/rq_affinity" 2
    done
}

apply_network() {
    save_write /proc/sys/net/ipv4/tcp_congestion_control bbr
    save_write /proc/sys/net/core/default_qdisc fq_codel
    save_write /proc/sys/net/ipv4/tcp_low_latency 1
    save_write /proc/sys/net/ipv4/tcp_no_metrics_save 1
    save_write /proc/sys/net/ipv4/tcp_fastopen 3

    if command -v iw >/dev/null 2>&1; then
        ps=$(iw dev wlan0 get power_save 2>/dev/null | sed -n 's/.*: //p')
        [ -n "$ps" ] && printf '%s\t%s\n' "wifi_power_save" "$ps" >> "$STATE"
        iw dev wlan0 set power_save off >/dev/null 2>&1
    fi
}

apply_on() {
    if [ -s "$STATE" ] || [ -s "$AUDIO_STATE" ]; then
        echo "error: profile sudah aktif; jalankan off dulu"
        exit 1
    fi
    : > "$STATE"
    apply_cpu
    apply_gpu
    apply_io
    apply_network
    apply_audio
    echo "game profile: ON"
    echo "catatan: charging/bypass tidak diubah"
}

restore_off() {
    if [ ! -s "$STATE" ] && [ ! -s "$AUDIO_STATE" ]; then
        echo "game profile: belum ada state; tidak ada yang direstore"
        return 0
    fi

    if [ -s "$STATE" ]; then
        while IFS="$TAB" read -r p v; do
            [ -n "$p" ] || continue
            if [ "$p" = "wifi_power_save" ]; then
                iw dev wlan0 set power_save "$v" >/dev/null 2>&1
            elif [ -e "$p" ]; then
                printf '%s\n' "$v" > "$p" 2>/dev/null
            fi
        done < "$STATE"
    fi
    restore_audio
    rm -f "$STATE"
    echo "game profile: OFF"
}

show_status() {
    echo "=== input boost ==="
    for f in input_boost_freq input_boost_ms sched_boost_on_input; do
        printf '%-24s ' "$f"
        cat "/sys/module/cpu_boost/parameters/$f" 2>/dev/null
    done
    echo "=== cpu ==="
    for p in policy0 policy4; do
        printf '%-8s governor=%s min=%s hispeed=%s\n' "$p" \
            "$(cat /sys/devices/system/cpu/cpufreq/$p/scaling_governor 2>/dev/null)" \
            "$(cat /sys/devices/system/cpu/cpufreq/$p/scaling_min_freq 2>/dev/null)" \
            "$(cat /sys/devices/system/cpu/cpufreq/$p/schedutil/hispeed_freq 2>/dev/null)"
    done
    echo "=== gpu ==="
    for f in devfreq/governor min_pwrlevel max_pwrlevel idle_timer throttling; do
        printf '%-18s ' "$f"
        cat "/sys/class/kgsl/kgsl-3d0/$f" 2>/dev/null
    done
    echo "=== io ==="
    for d in /sys/block/sd*; do
        [ -d "$d/queue" ] || continue
        printf '%-10s scheduler=%s read_ahead=%s\n' "$(basename "$d")" \
            "$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$d/queue/scheduler" 2>/dev/null)" \
            "$(cat "$d/queue/read_ahead_kb" 2>/dev/null)"
    done
    echo "=== audio ==="
    command -v tinymix >/dev/null 2>&1 && {
        tinymix "RX HPH Mode" 2>/dev/null
        tinymix "RX0 Digital Volume" 2>/dev/null
    }
}

case "${1:-status}" in
    on)
        need_root on
        apply_on
        ;;
    off)
        need_root off
        restore_off
        ;;
    status)
        show_status
        ;;
    *)
        echo "usage: su -c 'sh $0 on|off|status'"
        exit 1
        ;;
esac
