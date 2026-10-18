#!/usr/bin/env bash
# ais run container entrypoint. Materialises the per-run settings into the
# tmpfs config dir, reads the claude argv from the mounted input directory
# and runs claude with the prompt on stdin. Credentials arrive in the
# environment and never touch a file.
#
# After claude exits, it writes the CPU time and peak memory of the
# container (its cgroup v2 counters) to usage.json in the output directory,
# and exits with claude's code.
#
# AIS_IN_DIR, AIS_OUT_DIR, AIS_CGROUP_DIR, AIS_CLAUDE_BIN and
# CLAUDE_CONFIG_DIR are overridable so the test suite can run this file on
# the host against a fake claude.
set -euo pipefail

IN="${AIS_IN_DIR:-/run/ais/in}"
OUT="${AIS_OUT_DIR:-/run/ais/out}"
CGROUP="${AIS_CGROUP_DIR:-/sys/fs/cgroup}"
CLAUDE="${AIS_CLAUDE_BIN:-claude}"
CFG="${CLAUDE_CONFIG_DIR:-/run/ais/cfg/claude}"
HOME="${HOME:-/run/ais/home/ais}"
export HOME

# No token, no run. Exit 78 (EX_CONFIG) so the daemon can tell a missing
# credential from a model failure.
if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
    echo "[entrypoint] CLAUDE_CODE_OAUTH_TOKEN is not set" >&2
    exit 78
fi
# An API key silently takes precedence over the OAuth token in -p mode. A
# run that quietly billed a different account is worse than a failed one.
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[entrypoint] ANTHROPIC_API_KEY is set; it would override the OAuth token. Refusing." >&2
    exit 78
fi

for f in argv.json prompt.md settings.json; do
    if [ ! -r "$IN/$f" ]; then
        echo "[entrypoint] missing input file $IN/$f" >&2
        exit 78
    fi
done

mkdir -p "$CFG" "$HOME"
chmod 700 "$CFG"
install -m 600 "$IN/settings.json" "$CFG/settings.json"
# Mark onboarding done so a first-run wizard can never block a headless run.
printf '{"hasCompletedOnboarding":true}\n' > "$CFG/.claude.json"
chmod 600 "$CFG/.claude.json"

# argv.json is a JSON array written by the daemon; elements never contain
# newlines (validated host-side), so one element per line is exact.
mapfile -t ARGV < <(jq -r '.[]' "$IN/argv.json")
if [ "${#ARGV[@]}" -eq 0 ]; then
    echo "[entrypoint] argv.json is empty" >&2
    exit 78
fi

# claude runs as a child so that this script can read the usage after it
# exits. tini sends a `stop` to this script; the trap passes it on, and the
# loop waits until claude has really exited.
"$CLAUDE" "${ARGV[@]}" < "$IN/prompt.md" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true' TERM INT HUP
rc=0
wait "$pid" || rc=$?
while kill -0 "$pid" 2>/dev/null; do
    rc=0
    wait "$pid" || rc=$?
done
trap - TERM INT HUP

# Usage: best effort. A missing counter is 0, a failed write is ignored.
cpu=0 user=0 sys=0 peak=0
if [ -r "$CGROUP/cpu.stat" ]; then
    while read -r key val; do
        case "$key" in
            usage_usec) cpu=$val ;;
            user_usec) user=$val ;;
            system_usec) sys=$val ;;
        esac
    done < "$CGROUP/cpu.stat"
fi
if [ -r "$CGROUP/memory.peak" ]; then
    read -r peak < "$CGROUP/memory.peak" || peak=0
fi
printf '{"cpu_usec":%d,"user_usec":%d,"system_usec":%d,"mem_peak":%d}\n' "$cpu" "$user" "$sys" "$peak" \
    > "$OUT/usage.json" 2>/dev/null || true
exit "$rc"
