#!/usr/bin/env bash
# Verify the SSE stream ticket live, against a real elevated agent.
#
#   bash scripts/check-stream-ticket.sh
#
# The event stream never completes, so every probe here uses `curl --max-time`: a status code
# printed before curl is killed is the answer, and nothing can hang. (`Invoke-WebRequest` blocks
# forever on an open stream, which is why this is not PowerShell.)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="$HOME/.dotnet/dotnet.exe"
agent_dll="$repo/src/Argus.Agent/bin/Debug/net8.0-windows/argus-agent.dll"
work="$(mktemp -d)"
log="$work/agent.log"

cleanup() {
    if [ -n "${agent_pid:-}" ] && kill -0 "$agent_pid" 2>/dev/null; then kill "$agent_pid" 2>/dev/null || true; fi
    rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

[ -f "$agent_dll" ] || { echo "agent not built: $agent_dll" >&2; exit 2; }

"$dotnet" "$agent_dll" --port 0 \
    --target "C:\\Windows\\System32\\notepad.exe" --duration 90 \
    --record "$work/s.jsonl" --db "$work/s.db" \
    --ready-file "$work/ready.txt" > "$work/out.log" 2> "$work/err.log" &
agent_pid=$!

for _ in $(seq 1 150); do
    [ -f "$work/ready.txt" ] && break
    kill -0 "$agent_pid" 2>/dev/null || { echo "agent exited; see $work/err.log" >&2; cat "$work/err.log" >&2; exit 3; }
    sleep 0.2
done
[ -f "$work/ready.txt" ] || { echo "no ready file; see $work/err.log" >&2; exit 3; }

read -r port token sid < <(python -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(d['port'], d['token'], d['sessionId'])
" "$(cygpath -w "$work/ready.txt")" | tr -d '\r')

[ "$(net session >/dev/null 2>&1 && echo yes || echo no)" = "yes" ] || echo "warning: not elevated; the agent should have refused to start"

base="http://127.0.0.1:$port"
code() { curl -s -o /dev/null --max-time 3 -w '%{http_code}' "$@"; }

fail=0
check() {
    local name=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        printf 'PASS %-42s expected %-4s got %s\n' "$name" "$expected" "$actual"
    else
        printf 'FAIL %-42s expected %-4s got %s\n' "$name" "$expected" "$actual"
        fail=$((fail + 1))
    fi
}

check "stream with no token or ticket" 401 "$(code "$base/api/sessions/$sid/stream")"
check "ticket endpoint without a token" 401 "$(code -X POST "$base/api/sessions/$sid/stream-ticket")"

ticket="$(curl -s --max-time 5 -X POST -H "Authorization: Bearer $token" "$base/api/sessions/$sid/stream-ticket" \
    | python -c "import json,sys; print(json.load(sys.stdin)['ticket'])" | tr -d '\r')"
check "ticket issued to an authorised caller" 48 "${#ticket}"

check "fresh ticket opens the stream" 200 "$(code -H 'Accept: text/event-stream' "$base/api/sessions/$sid/stream?ticket=$ticket")"
check "the same ticket is refused again" 401 "$(code -H 'Accept: text/event-stream' "$base/api/sessions/$sid/stream?ticket=$ticket")"

second="$(curl -s --max-time 5 -X POST -H "Authorization: Bearer $token" "$base/api/sessions/$sid/stream-ticket" \
    | python -c "import json,sys; print(json.load(sys.stdin)['ticket'])" | tr -d '\r')"
check "a ticket for another session is refused" 401 "$(code "$base/api/sessions/11111111-1111-1111-1111-111111111111/stream?ticket=$second")"

check "the bearer token still works on the stream" 200 "$(code -H "Authorization: Bearer $token" "$base/api/sessions/$sid/stream")"
check "scores endpoint" 200 "$(code -H "Authorization: Bearer $token" "$base/api/sessions/$sid/scores")"

if [ "$fail" -eq 0 ]; then echo "stream ticket: all checks passed"; else echo "stream ticket: $fail check(s) failed"; fi
exit $((fail > 0))
