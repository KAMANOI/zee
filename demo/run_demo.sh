#!/usr/bin/env bash
# Zee containment demo — recording run.
#
# DEMO ONLY. See demo/README.md for the full explanation, disclaimers,
# and the isolation-environment decision (sandbox-exec, not Docker/VM —
# neither is installed on this machine and it does not have RAM to
# spare for a new hypervisor/daemon).
#
# What this does, in order:
#   1. creates a disposable sandbox directory under demo/.run/<ts>/
#   2. fills it with fake "documents" (make_dummy_files.py)
#   3. starts `zee watch` in dry_run mode (default/safe) pointed at
#      decoy files inside that sandbox dir — this also seeds the decoys
#   4. runs the mock attacker (mock_attacker.py) against the sandbox,
#      confined by sandbox-exec (demo/sandbox.sb) — no network, no
#      writes outside the sandbox
#   5. prints `zee status` (the "what Zee saw / blocked" screen)
#   6. stops the watcher and prints where the logs and sandbox dir are
#
# Usage: demo/run_demo.sh   (run from the repo root, venv activated)

set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "[run_demo] activate the venv first: source .venv-demo/bin/activate" >&2
  exit 1
fi

if [ "$(uname)" != "Darwin" ]; then
  echo "[run_demo] this script's isolation step uses macOS sandbox-exec; not supported on $(uname)." >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="demo/.run/${TS}"
SANDBOX_DIR_REL="${RUN_DIR}/sandbox"
mkdir -p "${SANDBOX_DIR_REL}"
SANDBOX_DIR="$(python3 -c "import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())" "${SANDBOX_DIR_REL}")"

echo "[run_demo] sandbox dir: ${SANDBOX_DIR}"
python3 demo/make_dummy_files.py "${SANDBOX_DIR}"

mkdir -p "${SANDBOX_DIR}/.payload"
cp demo/mock_attacker.py "${SANDBOX_DIR}/.payload/mock_attacker.py"

ASSETS_TOML="${RUN_DIR}/assets.demo.toml"
sed "s#__SANDBOX_DIR__#${SANDBOX_DIR}#g" demo/assets.demo.toml.tmpl > "${ASSETS_TOML}"
echo "[run_demo] wrote ${ASSETS_TOML}"

if [ ! -f "${HOME}/.zee/restore_token" ]; then
  echo "[run_demo] no restore_token yet — generating one (needed for 'zee restore' later)"
  python3 -m zee.cli init-restore-token
fi

echo "[run_demo] starting zee watch (dry_run) ..."
python3 -m zee.cli -c "${ASSETS_TOML}" watch > "${RUN_DIR}/watch.log" 2>&1 &
WATCH_PID=$!
trap 'kill "${WATCH_PID}" 2>/dev/null || true' EXIT

sleep 2
echo "----------------------------------------------------------------"
echo " zee watch is running (log: ${RUN_DIR}/watch.log)."
echo " Start screen recording now, then press Enter to run the mock attack."
echo "----------------------------------------------------------------"
read -r _

echo "[run_demo] running mock attacker, sandboxed (no network, no writes outside the sandbox) ..."
sandbox-exec -D SANDBOX_DIR="${SANDBOX_DIR}" -f demo/sandbox.sb \
  python3 "${SANDBOX_DIR}/.payload/mock_attacker.py" "${SANDBOX_DIR}"

sleep 2
echo "----------------------------------------------------------------"
echo " zee watch log (what Zee saw) — ${RUN_DIR}/watch.log"
echo "----------------------------------------------------------------"
grep -E '^\[(seeded|event|zee watch)\]' "${RUN_DIR}/watch.log" || cat "${RUN_DIR}/watch.log"

echo "----------------------------------------------------------------"
echo " zee status (trap activity summary) — record this screen for the 'operations list' shot"
echo "----------------------------------------------------------------"
python3 -m zee.cli status

kill "${WATCH_PID}" 2>/dev/null || true
trap - EXIT

echo "----------------------------------------------------------------"
echo "[run_demo] done."
echo "  sandbox dir : ${SANDBOX_DIR}  (fake files only — safe to inspect or discard)"
echo "  watch log   : ${RUN_DIR}/watch.log"
echo "  assets.toml : ${ASSETS_TOML}"
echo "----------------------------------------------------------------"
