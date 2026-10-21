# Model file checks (G221–G229)

Design source: HDR outbox `20261020-Zee-モデルファイル検査設計/00_報告.md` (not in this repo). Decisions
(representative, 2026-10-20): implement it on a separate branch, no release; a pickle is always a
person's call, but a lone MEDIUM only blocks `--promote-to`, it does not stop an import.

## What was built

`src/zee/gate/modelfiles.py`, called from `static_checks.scan_tree` after the other checks, so every
kind of artifact gets it. Codes and behaviour: `docs/gate.md`. Gate numbers G221–G229 were free on
v0.16.0 (the highest was G220); G225 is now in `GAP_CODES`.

Deviations from the design, on purpose:
- GGUF chat template with nothing odd is **LOW** (shown), not MEDIUM: most instruct GGUFs carry one.
  Jinja internals in it are HIGH.
- G228 (companion `.py`) is a small `ast` walk of import-time code; it does not reuse the G203/G204/G501
  word lists, so the same word can appear twice (under different codes).
- Per-file hash records / re-scan of only the changed files (design 3.4) are **not** built: `zee gate audit`
  still re-checks the whole tree, and a pickle model never reaches PinRegistry through `promote` (it is
  refused). Registering a hand-installed pickle for audit is a separate design.

## Independent check on the design (ASTRA / Codex gpt-6-astra, read-only)
- Round 1 (before this work): 64, five points, reflected in the design.
- Round 2 (2026-10-20, before implementing): **80, needs fixing**, four highs about under-specified rules. Handled:
  * first-byte detection vs. ordinary files: a format is *confirmed* by magic (zip / GGUF / HDF5 /
    safetensors / pickle PROTO 2-5); a model-like suffix is only a *candidate* and is parsed; an
    unparsable `.pt .pth .ckpt .pkl .pickle .joblib` is G225, a stray `.bin` is ignored; a text-protocol
    pickle with no model-like name is not recognised (stated in the limits).
  * broken pickle: G224 (HIGH) needs an import before the break; **G225 is always added** when a pickle is
    cut off, over the cap or holds an unresolvable import, so the result is G221 + HIGH + G225,
    partial, exit 3. `genops` does not validate the stack (e.g. `R.` on an empty stack): stated as a limit.
  * zip: every member is looked at: `*.pkl` / `*.pickle`, or a member that starts like a pickle (not under
    `/data/`), is read in memory; a zip inside a zip, an encrypted member and over 20,000 members are G225.
  * size: a read inside a pickle over 16 MiB or a stream over 64 MiB stops the analysis (G225) before
    anything is allocated; `sha256_tree` hashes in chunks; manifests in `adapters.py` are capped at 8 MiB
    (G912 above that). There is no total budget across the tree (stated).
- Round 3 (2026-10-21, Codex on the branch diff: 62, needs fixing), five points handled:
  * a zip is recognised by its first bytes whatever its suffix (a pickle zip renamed `weights.dat` is read);
    an ordinary zip (`.docx`, `.whl` ...) with no pickle and no Keras config raises nothing, so its nested /
    encrypted members are not gaps there.
  * a broken zip member (CRC mismatch, unsupported compression) in a Keras config is G225, not a crash.
  * a companion `.py` too deeply nested for the `ast` walk (e.g. a long `1+1+...` chain) is G225; calls
    already seen are still reported.
  * a later pickle stream that started (PROTO) and imported, then breaks off, is broken (G224 / G225); raw
    tensor bytes after the last stream are still not (either alone happens by chance in raw data).
  * GGUF: version other than 2 / 3 is G225; a tensor table that does not fit the file (count, > 4 dims,
    offsets past the end, tensors with no data) or a key-value table that runs past the end is G226.
  * (medium) per-file diff cache: not built, see above.
