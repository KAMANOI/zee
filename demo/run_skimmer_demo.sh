#!/usr/bin/env bash
# Zee containment demo — JS-skimmer scenario, HEADLESS run.
#
# DEMO ONLY. Reuses the exact isolation + state-isolation machinery of
# run_demo.sh (sandbox-exec via demo/sandbox.sb, per-run XDG_STATE_HOME,
# dry_run watcher) but swaps the ransomware mock for mock_skimmer.py, which
# reproduces the Gambit (2026-09-22) file-layer techniques: append a loader
# to JS decoys (+ reset mtime), a write-back "cron" loop, and a cleanup
# delete. Unlike run_demo.sh it does NOT pause for a screen recording — it
# runs end to end and writes logs, so it works in a headless session.
#
# Usage: demo/run_skimmer_demo.sh   (repo root, venv-demo activated)

set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "[run_skimmer] activate the venv first: source .venv-demo/bin/activate" >&2
  exit 1
fi
if [ "$(uname)" != "Darwin" ]; then
  echo "[run_skimmer] isolation step uses macOS sandbox-exec; not supported on $(uname)." >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="demo/.run/skimmer-${TS}"
SANDBOX_DIR_REL="${RUN_DIR}/sandbox"
mkdir -p "${SANDBOX_DIR_REL}/assets/js"
SANDBOX_DIR="$(python3 -c "import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())" "${SANDBOX_DIR_REL}")"

export XDG_STATE_HOME
XDG_STATE_HOME="$(python3 -c "import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())" "${RUN_DIR}/state")"
mkdir -p "${XDG_STATE_HOME}"

echo "[run_skimmer] sandbox dir: ${SANDBOX_DIR}"
python3 demo/make_dummy_files.py "${SANDBOX_DIR}"

mkdir -p "${SANDBOX_DIR}/.payload"
cp demo/mock_skimmer.py "${SANDBOX_DIR}/.payload/mock_skimmer.py"

ASSETS_TOML="${RUN_DIR}/assets.skimmer.toml"
sed "s#__SANDBOX_DIR__#${SANDBOX_DIR}#g" demo/assets.skimmer.toml.tmpl > "${ASSETS_TOML}"
echo "[run_skimmer] wrote ${ASSETS_TOML}"

echo "[run_skimmer] starting zee watch (dry_run) ..."
python3 -m zee.cli -c "${ASSETS_TOML}" watch > "${RUN_DIR}/watch.log" 2>&1 &
WATCH_PID=$!
trap 'kill "${WATCH_PID}" 2>/dev/null || true' EXIT

sleep 2
if ! kill -0 "${WATCH_PID}" 2>/dev/null; then
  echo "[run_skimmer] zee watch exited immediately — see ${RUN_DIR}/watch.log:" >&2
  cat "${RUN_DIR}/watch.log" >&2
  exit 1
fi

echo "[run_skimmer] running mock skimmer, sandboxed (no network, no writes outside the sandbox) ..."
sandbox-exec -D SANDBOX_DIR="${SANDBOX_DIR}" -f demo/sandbox.sb \
  python3 "${SANDBOX_DIR}/.payload/mock_skimmer.py" "${SANDBOX_DIR}"

sleep 2
echo "----------------------------------------------------------------"
echo " zee watch log (what Zee saw):"
echo "----------------------------------------------------------------"
cat "${RUN_DIR}/watch.log"

echo "----------------------------------------------------------------"
echo " zee status:"
echo "----------------------------------------------------------------"
python3 -m zee.cli status | tee "${RUN_DIR}/status.txt"

kill "${WATCH_PID}" 2>/dev/null || true
trap - EXIT

echo "----------------------------------------------------------------"
echo "[run_skimmer] done."
echo "  watch log : ${RUN_DIR}/watch.log"
echo "  status    : ${RUN_DIR}/status.txt"
echo "----------------------------------------------------------------"
