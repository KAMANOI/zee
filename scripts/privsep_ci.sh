#!/usr/bin/env bash
# Privsep checks on a disposable CI runner (.github/workflows/privsep.yml).
# Never run this on a real machine: it creates users and drives a root daemon.
#
# Env: PY ZEE_SRC SOCK STATE WATCH_USER OUTSIDER (a uid that can reach the
#      socket but is not allowed) KEY (approver private key, unreadable by
#      WATCH_USER) DAEMON_PID_CMD STOP_AS_USER_CMD ACTIVE_CMD
#      REAL_CUT=1 (Linux netns only): TEST_URL, DECOY, WATCH_CONFIG
set -uo pipefail
X=/tmp/zee-xfer
mkdir -p "$X" && chmod 755 "$X"
fails=0
pass() { echo "PASS: $*" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"; }
fail() { echo "FAIL: $*" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"; fails=$((fails + 1)); }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
zee_as() {  # zee privsep <sub> ... as $1
  local u=$1 sub=$2; shift 2
  sudo -u "$u" env PYTHONPATH="$ZEE_SRC" "$PY" -m zee privsep "$sub" "$@" --socket "$SOCK"
}
ok() { jq -e '.ok == true' >/dev/null; }
# A refusal must be the OS saying no: non-zero exit AND a permission message
# (a missing command or a typo must never count as "denied").
denied() {
  local err rc
  err=$("$@" 2>&1 >/dev/null); rc=$?
  echo "  -> rc=$rc ${err:0:200}"
  [ $rc -ne 0 ] && grep -Eqi 'permission denied|not permitted|authentication required|access denied|not privileged|must be run as root|requires root' <<<"$err"
}
field() { jq -r "$1"; }

signed() {  # signed <admin_op> [k=v ...]: challenge as WATCH_USER, sign as the approver, submit
  local op=$1; shift
  zee_as "$WATCH_USER" challenge "$op" "$@" >"$X/req.json" 2>"$X/code.txt" || { cat "$X/req.json" "$X/code.txt" >&2; return 1; }
  local code
  code=$(sed -n 's/.*: \([0-9][0-9]\)$/\1/p' "$X/code.txt")
  PYTHONPATH="$ZEE_SRC" "$PY" -m zee privsep digest --request "$X/req.json" --entered "$code" --out "$X/d.bin"
  openssl pkeyutl -sign -inkey "$KEY" -in "$X/d.bin" -out "$X/sig.der"
  chmod 644 "$X"/req.json "$X"/sig.der
  echo "$code" >"$X/last_code"
  zee_as "$WATCH_USER" submit --request "$X/req.json" --entered "$code" --key-id phone --signature "$X/sig.der"
}

online() { sudo ip netns exec zt curl -sS -m 3 -o /dev/null "$TEST_URL"; }
offline() { ! online; }  # a function: `bash -c "! online"` would not see it (and "pass")

echo "== status from the watch user (peer uid from the kernel)"
st=$(zee_as "$WATCH_USER" status)
echo "$st"
check "watch user can ask status" ok <<<"$st"
check "daemon runs as root" test "$(sudo ps -o user= -p "$(eval "$DAEMON_PID_CMD")" | tr -d ' ')" = root

echo "== a uid that can open the socket but is not allowed"
r=$(sudo -u "$OUTSIDER" env PYTHONPATH="$ZEE_SRC" "$PY" -m zee privsep status --socket "$SOCK")
echo "$r"
check "other uid refused by the uid check (not by file mode)" test "$(field .error <<<"$r")" = peer_not_allowed

echo "== the watch user cannot read or write the daemon's state"
check "state dir not listable" denied sudo -u "$WATCH_USER" ls "$STATE"
check "ledger not writable" denied sudo -u "$WATCH_USER" sh -c 'echo forged >> "$1"' _ "$STATE/cut_state.jsonl"
check "approved config not writable" denied sudo -u "$WATCH_USER" sh -c 'echo x >> "$1"' _ "$STATE/assets.toml"
check "approver key not readable" denied sudo -u "$WATCH_USER" cat "$KEY"
check "daemon code not writable" denied sudo -u "$WATCH_USER" sh -c 'echo x >> "$1"' _ "$ZEE_SRC/zee/privsep/daemon.py"

echo "== the watch user cannot stop the daemon"
pid=$(eval "$DAEMON_PID_CMD")
check "kill as watch user fails" denied sudo -u "$WATCH_USER" kill -TERM "$pid"
check "service stop as watch user fails" denied bash -c "$STOP_AS_USER_CMD"
sleep 1
check "daemon still running after both" bash -c "$ACTIVE_CMD"

echo "== unsigned management is refused"
r=$(sudo -u "$WATCH_USER" env PYTHONPATH="$ZEE_SRC" "$PY" -c "
import json; from zee.privsep.client import call
print(json.dumps([call('$SOCK', {'op': o, 'asset_id': 'ws'}) for o in ('restore', 'stop', 'auto_set')]))")
echo "$r"
check "restore/stop/auto_set as plain requests: unknown_op" test "$(jq -r '[.[].error] | unique | join(",")' <<<"$r")" = unknown_op
zee_as "$WATCH_USER" challenge restore asset_id=ws scope=all >"$X/req.json" 2>/dev/null
head -c 72 /dev/urandom >"$X/forged.der" && chmod 644 "$X"/*
r=$(zee_as "$WATCH_USER" submit --request "$X/req.json" --entered 00 --key-id phone --signature "$X/forged.der")
echo "$r"
check "restore with a forged signature: bad_signature" test "$(field .refused <<<"$r")" = bad_signature
check "status is still alive" bash -c "$ACTIVE_CMD"

echo "== cut before the signed auto switch"
cutreq() { sudo -u "$WATCH_USER" env PYTHONPATH="$ZEE_SRC" "$PY" -c "
from zee.privsep.client import privsep_cut; from zee.responder.blocker import CutRequest
print(privsep_cut('$SOCK')(CutRequest('ws', 'change', 'high')))"; }
r=$(cutreq); echo "$r"
check "cut refused without auto permission" grep -q no_permission <<<"$r"

echo "== signed auto_set on, and replay"
r=$(signed auto_set state=on); echo "$r"
check "signed auto_set on accepted" ok <<<"$r"
r=$(zee_as "$WATCH_USER" submit --request "$X/req.json" --entered "$(cat "$X/last_code")" --key-id phone --signature "$X/sig.der"); echo "$r"
check "same signed request again: refused" test "$(field .refused <<<"$r")" = unknown_request

if [ "${REAL_CUT:-0}" = 1 ]; then
  echo "== real cut through zee watch (watch as $WATCH_USER, daemon root in netns zt)"
  check "baseline: test server reachable" online
  st=$(zee_as "$WATCH_USER" status); echo "$st"
  check "watch config equals the approved copy (no findings)" test "$(field '.findings | length' <<<"$st")" = 0
  sudo -u "$WATCH_USER" bash -c "cd ~ && nohup env PYTHONPATH='$ZEE_SRC' '$PY' -m zee -c '$WATCH_CONFIG' watch >~/watch.log 2>&1 &"
  for _ in $(seq 30); do sudo grep -q 'running' "/home/$WATCH_USER/watch.log" && break; sleep 1; done
  sudo -u "$WATCH_USER" sh -c "echo touched >> '$DECOY'"
  # the seeding itself logs a read-class "[event] decoy open": wait for the change event's result
  for _ in $(seq 60); do sudo grep -q 'decoy modify →' "/home/$WATCH_USER/watch.log" && break; sleep 1; done
  sudo cat "/home/$WATCH_USER/watch.log"
  check "watch reports cut=yes" sudo grep -q 'cut=yes' "/home/$WATCH_USER/watch.log"
  check "test server unreachable during the cut" offline
  st=$(zee_as "$WATCH_USER" status); echo "$st"
  check "daemon ledger has the cut" test "$(field '.unresolved | join(",")' <<<"$st")" = ws
  check "still unreachable after the refused unsigned restores" offline
  r=$(signed restore asset_id=ws scope=recorded); echo "$r"
  check "signed restore accepted and verified" ok <<<"$r"
  check "test server reachable after restore" online
  st=$(zee_as "$WATCH_USER" status); echo "$st"
  check "ledger resolved" test "$(field '.unresolved | length' <<<"$st")" = 0
fi

echo "== signed stop"
r=$(signed stop); echo "$r"
check "signed stop accepted" ok <<<"$r"
sleep 5
check "daemon stopped and not restarted by the supervisor" bash -c "! $ACTIVE_CMD"
check "socket no longer answers" bash -c "! sudo -u '$WATCH_USER' env PYTHONPATH='$ZEE_SRC' '$PY' -m zee privsep status --socket '$SOCK' >/dev/null 2>&1"

echo "failures: $fails"
exit $((fails > 0))
