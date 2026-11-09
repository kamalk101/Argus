#!/usr/bin/env bash
# Prove that reconnecting recovers state: a second connection to the same session must be handed the
# full snapshot (`state`, `stats`) again, not a delta that assumes the first connection survived.
#
#   bash scripts/check-sse-reconnect.sh
#
# Uses `--max-time` on every read: an event stream never ends, so the read is always cut by a timeout.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="$HOME/.dotnet/dotnet.exe"
agent_dll="$repo/src/Argus.Agent/bin/Debug/net8.0-windows/argus-agent.dll"
work="$(mktemp -d)"

cleanup() {
    if [ -n "${agent_pid:-}" ] && kill -0 "$agent_pid" 2>/dev/null; then kill "$agent_pid" 2>/dev/null || true; fi
    rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

"$dotnet" "$agent_dll" --port 0 \
    --target "C:\\Windows\\System32\\notepad.exe" --duration 60 \
    --record "$work/s.jsonl" --db "$work/s.db" \
    --ready-file "$work/ready.txt" > "$work/out.log" 2> "$work/err.log" &
agent_pid=$!

for _ in $(seq 1 150); do
    [ -f "$work/ready.txt" ] && break
    kill -0 "$agent_pid" 2>/dev/null || { echo "agent exited; see $work/err.log" >&2; exit 3; }
    sleep 0.2
done

read -r port token sid < <(python -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(d['port'], d['token'], d['sessionId'])
" "$(cygpath -w "$work/ready.txt")" | tr -d '\r')

base="http://127.0.0.1:$port"
fail=0

# One connection: read frames until the timeout stops us, then record which types arrived.
read_frames() {
    curl -s --max-time 3 -N -H "Authorization: Bearer $token" -H 'Accept: text/event-stream' \
        "$base/api/sessions/$sid/stream" | grep -a '^event:' | sort -u | tr '\n' ' ' || true
}

first="$(read_frames)"
second="$(read_frames)"

for frame in state stats; do
    if grep -q "event: $frame" <<< "$first"; then
        printf 'PASS first connection carries %-6s frames\n' "$frame"
    else
        printf 'FAIL first connection carries %-6s frames (got: %s)\n' "$frame" "$first"
        fail=$((fail + 1))
    fi

    if grep -q "event: $frame" <<< "$second"; then
        printf 'PASS reconnect carries %-6s again — a reconnected client is not left with deltas\n' "$frame"
    else
        printf 'FAIL reconnect carries %-6s (got: %s)\n' "$frame" "$second"
        fail=$((fail + 1))
    fi
done

if [ "$fail" -eq 0 ]; then echo "sse reconnect: all checks passed"; else echo "sse reconnect: $fail check(s) failed"; fi
exit $((fail > 0))
