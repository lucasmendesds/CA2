#!/usr/bin/env bash
# Quick summary of vuln-demo audit log.
#   usage: ./parse_logs.sh [path/to/access.log]
# Default path: ./access.log next to this script.
set -uo pipefail

LOG="${1:-$(dirname "$0")/access.log}"

if [[ ! -f "$LOG" ]]; then
    echo "log file not found: $LOG" >&2
    exit 1
fi

# Pull a logfmt key out of a single line. Strips surrounding quotes if present.
get() {
    local key="$1" line="$2"
    # Match key="quoted value" OR key=bareword
    local v
    v=$(printf '%s\n' "$line" | grep -oE "${key}=(\"([^\"\\\\]|\\\\.)*\"|[^ ]+)" | head -1 | cut -d= -f2-)
    # strip optional surrounding quotes
    [[ "$v" == \"*\" ]] && v="${v:1:${#v}-2}"
    printf '%s' "$v"
}

echo "== event counts =="
grep -oE 'event=[A-Za-z_]+' "$LOG" | sort | uniq -c | sort -rn

echo
echo "== login failures (last 20) =="
grep 'event=login_failure' "$LOG" | tail -20 | while read -r line; do
    printf '  %s  ip=%s  user=%s\n' \
        "$(get ts "$line")" "$(get ip "$line")" "$(get user "$line")"
done

echo
echo "== logins flagged as SQLi (sqli_suspected=true) =="
grep 'event=login_success' "$LOG" | grep 'sqli_suspected=true' | while read -r line; do
    printf '  %s  ip=%s  attempted=%s  -> got=%s\n' \
        "$(get ts "$line")" "$(get ip "$line")" \
        "$(get attempted_user "$line")" "$(get user "$line")"
done

echo
echo "== comment searches flagged as SQLi =="
grep 'event=comment_search' "$LOG" | grep 'sqli_suspected=true' | while read -r line; do
    printf '  %s  ip=%s  q=%s\n' \
        "$(get ts "$line")" "$(get ip "$line")" "$(get q "$line")"
done

echo
echo "== comments flagged as XSS =="
grep 'event=comment_posted' "$LOG" | grep 'xss_suspected=true' | while read -r line; do
    printf '  %s  ip=%s  user=%s  body=%s\n' \
        "$(get ts "$line")" "$(get ip "$line")" \
        "$(get user "$line")" "$(get body_preview "$line")"
done

echo
echo "== top source IPs =="
grep -oE 'ip=[^ ]+' "$LOG" | sort | uniq -c | sort -rn | head -10
