#!/bin/bash
# Real-machine check on macOS: egress cut and full cut, each as
#   cut -> curl must fail -> restore -> curl must succeed
# then confirm pf and the network services are back to how they were:
# first as Zee's own restore left them, then after this script's cleanup.
#
# Run once, from the repository root, with an administrator password:
#   sudo bash scripts/verify-real-macos.sh
# The script never reads or stores the password (sudo asks for it).
# It runs this working tree's code (.venv, src/) as root: run it only in a
# working tree you trust, owned by you, that no other user can write to.
#
# The network goes down for a few seconds per step (full cut disables every
# network service). Safety: an EXIT / INT / HUP / TERM trap restores, and a
# background timer flushes Zee's pf anchor and re-enables the recorded
# services after SAFETY_SECONDS even if this script is stuck. The script
# refuses to start if anything it needs to put back cannot be read first.
set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo bash scripts/verify-real-macos.sh" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
URL="${URL:-https://www.apple.com/library/test/success.html}"
SAFETY_SECONDS="${SAFETY_SECONDS:-180}"
STAMP="$(date +%Y%m%d-%H%M%S)"
PARENT="$REPO/docs/verification"
OUT="$PARENT/real-macos-$STAMP"
ANCHORS="com.apple/zee-egress-cut zee-egress-cut"

abort() { echo "ABORT (nothing was cut): $*" >&2; exit 2; }

# Output: no symlink anywhere on the way, and a new directory (mkdir without
# -p fails if the name already exists, as a file, directory or link).
for d in "$REPO/docs" "$PARENT"; do
  [ -L "$d" ] && abort "$d is a symbolic link"
done
[ -d "$PARENT" ] || abort "$PARENT not found"
mkdir "$OUT" || abort "cannot create $OUT"

# 1. Record the current state. Every read must succeed and look right, or
#    the cleanup would not know what to put back.
pfctl -s info > "$OUT/pf-info.before.txt" 2>&1 || abort "pfctl -s info failed"
PF_BEFORE="$(awk '/^Status:/ {print $2}' "$OUT/pf-info.before.txt")"
case "$PF_BEFORE" in Enabled|Disabled) ;; *) abort "pf status unreadable" ;; esac
pfctl -s rules > "$OUT/pf-rules.before.txt" 2>&1 || abort "pfctl -s rules failed"
networksetup -listallnetworkservices > "$OUT/services.before.txt" 2>&1 || abort "networksetup failed"
head -1 "$OUT/services.before.txt" | grep -q "asterisk" || abort "network service list unreadable"
[ "$(tail -n +2 "$OUT/services.before.txt" | grep -c .)" -gt 0 ] || abort "no network services listed"
# A Zee cut already in force must not be undone by this test.
for a in $ANCHORS; do
  rules="$(pfctl -a "$a" -s rules 2>/dev/null)" || abort "pfctl -a $a unreadable"
  [ -z "$(echo "$rules" | grep -v ALTQ)" ] || abort "Zee pf rules already loaded in $a: restore that cut first"
done
[ "$PF_BEFORE" = Enabled ] && PF_WAS_ENABLED=1 || PF_WAS_ENABLED=0

restore_everything() {
  local ok=0
  for a in $ANCHORS; do pfctl -a "$a" -F all >/dev/null 2>&1 || ok=1; done
  # Re-enable exactly the services that were enabled before (no '*').
  while IFS= read -r svc; do
    case "$svc" in ''|\**) ;; *) networksetup -setnetworkserviceenabled "$svc" on >/dev/null 2>&1 || ok=1 ;; esac
  done < <(tail -n +2 "$OUT/services.before.txt")
  if [ "$PF_WAS_ENABLED" -eq 0 ]; then pfctl -d >/dev/null 2>&1; fi  # "not enabled" is fine
  return $ok
}

SAFETY_PID=""
on_exit() {
  restore_everything
  [ -n "$SAFETY_PID" ] && kill "$SAFETY_PID" 2>/dev/null
}
trap on_exit EXIT
trap 'exit 130' INT HUP TERM
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
cut_rc=$rc

snapshot() {  # $1 = suffix; returns non-zero if any read fails
  pfctl -s info > "$OUT/pf-info.$1.txt" 2>&1 &&
  pfctl -s rules > "$OUT/pf-rules.$1.txt" 2>&1 &&
  networksetup -listallnetworkservices > "$OUT/services.$1.txt" 2>&1 &&
  { for a in $ANCHORS; do pfctl -a "$a" -s rules 2>/dev/null | grep -v ALTQ || true; done; } > "$OUT/zee-anchors.$1.txt"
}
same_as_before() {  # $1 = suffix -> prints true/false for pf status, main rules, services, Zee anchors empty
  local pf; pf="$(awk '/^Status:/ {print $2}' "$OUT/pf-info.$1.txt")"
  [ "$pf" = "$PF_BEFORE" ] && echo -n true || echo -n false; echo -n " "
  cmp -s "$OUT/pf-rules.before.txt" "$OUT/pf-rules.$1.txt" && echo -n true || echo -n false; echo -n " "
  cmp -s "$OUT/services.before.txt" "$OUT/services.$1.txt" && echo -n true || echo -n false; echo -n " "
  [ ! -s "$OUT/zee-anchors.$1.txt" ] && echo true || echo false
}

# 3a. As Zee's own restore left it (before this script puts anything back).
if snapshot after-zee; then read -r z_pf z_rules z_svc z_anchor <<< "$(same_as_before after-zee)"
else z_pf=false; z_rules=false; z_svc=false; z_anchor=false; rc=1; fi
# 3b. After this script's cleanup (the safety net), then stop the timer.
restore_everything || rc=1
kill "$SAFETY_PID" 2>/dev/null; SAFETY_PID=""
if snapshot after; then read -r f_pf f_rules f_svc f_anchor <<< "$(same_as_before after)"
else f_pf=false; f_rules=false; f_svc=false; f_anchor=false; rc=1; fi
for v in $z_pf $z_rules $z_svc $z_anchor $f_pf $f_rules $f_svc $f_anchor; do
  [ "$v" = true ] || rc=1
done

cat > "$OUT/summary.json" <<EOF
{"mac": "$(sysctl -n hw.model)", "macos": "$(sw_vers -productVersion)",
 "pf_status_before": "$PF_BEFORE",
 "after_zee_restore": {"pf_status_unchanged": $z_pf, "pf_main_rules_unchanged": $z_rules,
                       "network_services_unchanged": $z_svc, "zee_anchors_empty": $z_anchor},
 "after_script_cleanup": {"pf_status_unchanged": $f_pf, "pf_main_rules_unchanged": $f_rules,
                          "network_services_unchanged": $f_svc, "zee_anchors_empty": $f_anchor},
 "all_cut_checks_passed": $([ $cut_rc -eq 0 ] && echo true || echo false),
 "exit_code": $rc}
EOF
chown -R "${SUDO_USER:-root}" "$OUT" 2>/dev/null || true
cat "$OUT/summary.json"
echo "results: $OUT"
exit $rc
