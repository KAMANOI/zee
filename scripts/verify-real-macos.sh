#!/bin/bash
# Real-machine check on macOS: egress cut and full cut, each as
#   cut -> curl must fail -> restore -> curl must succeed
# then confirm pf and the network services are back to how they were.
#
# Run once, from the repository root, with an administrator password:
#   sudo bash scripts/verify-real-macos.sh
# The script never reads or stores the password (sudo asks for it).
#
# The network goes down for a few seconds per step (full cut disables every
# network service). Safety: an EXIT trap restores, and a background timer
# flushes Zee's pf anchor and re-enables the recorded services after
# SAFETY_SECONDS even if this script is stuck.
set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo bash scripts/verify-real-macos.sh" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
URL="${URL:-https://www.apple.com/library/test/success.html}"
SAFETY_SECONDS="${SAFETY_SECONDS:-90}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/docs/verification/real-macos-$STAMP"
mkdir -p "$OUT"
chown "${SUDO_USER:-root}" "$OUT" 2>/dev/null || true

# 1. Record the current state (pf rules / pf status / network services).
pfctl -s info > "$OUT/pf-info.before.txt" 2>&1
pfctl -s rules > "$OUT/pf-rules.before.txt" 2>&1
networksetup -listallnetworkservices > "$OUT/services.before.txt" 2>&1
PF_WAS_ENABLED=0
grep -q "Status: Enabled" "$OUT/pf-info.before.txt" && PF_WAS_ENABLED=1

restore_everything() {
  pfctl -a com.apple/zee-egress-cut -F all >/dev/null 2>&1
  pfctl -a zee-egress-cut -F all >/dev/null 2>&1
  # Re-enable exactly the services that were enabled before (no '*').
  tail -n +2 "$OUT/services.before.txt" | while IFS= read -r svc; do
    case "$svc" in ''|\**) ;; *) networksetup -setnetworkserviceenabled "$svc" on >/dev/null 2>&1 ;; esac
  done
  if [ "$PF_WAS_ENABLED" -eq 0 ]; then pfctl -d >/dev/null 2>&1; fi
}

trap 'restore_everything' EXIT
# Ignore SIGHUP so the timer survives a dropped terminal (e.g. over SSH when
# the full cut takes the connection down).
( trap '' HUP; sleep "$SAFETY_SECONDS"; restore_everything ) &
SAFETY_PID=$!

# 2. egress, then full (Zee's own cut and restore; dry_run does not apply here).
rc=0
for method in egress full; do
  PYTHONPATH="$REPO/src" "$PY" "$REPO/scripts/real_cut_check.py" --method "$method" \
    --url "$URL" --label "macos-real" --out "$OUT/$method.json" --safety-seconds 45 || rc=1
  sleep 3
done

# 3. Put pf / services back to the recorded state and compare.
restore_everything
kill "$SAFETY_PID" 2>/dev/null
pfctl -s info > "$OUT/pf-info.after.txt" 2>&1
pfctl -s rules > "$OUT/pf-rules.after.txt" 2>&1
networksetup -listallnetworkservices > "$OUT/services.after.txt" 2>&1
same_rules=false; cmp -s "$OUT/pf-rules.before.txt" "$OUT/pf-rules.after.txt" && same_rules=true
same_services=false; cmp -s "$OUT/services.before.txt" "$OUT/services.after.txt" && same_services=true
pf_after=0; grep -q "Status: Enabled" "$OUT/pf-info.after.txt" && pf_after=1
cat > "$OUT/summary.json" <<EOF
{"mac": "$(sysctl -n hw.model)", "macos": "$(sw_vers -productVersion)",
 "pf_enabled_before": $PF_WAS_ENABLED, "pf_enabled_after": $pf_after,
 "pf_main_rules_unchanged": $same_rules, "network_services_unchanged": $same_services,
 "all_cut_checks_passed": $([ $rc -eq 0 ] && echo true || echo false)}
EOF
chown -R "${SUDO_USER:-root}" "$OUT" 2>/dev/null || true
cat "$OUT/summary.json"
echo "results: $OUT"
exit $rc
