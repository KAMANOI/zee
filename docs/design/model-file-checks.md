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
- Round 4 (2026-10-21, four findings that persisted through round 3 because the earlier fixes were
  point-patches). Root cause and single rule applied to all four: **the scanner must never return "ok"
  for a region it could not actually read and verify** — a failed read / parse / decompress, or a region
  whose contents cannot be positively confirmed as raw tensor data, resolves to G225 (or G226 when the
  format is definitively contradicted). Fail toward "unscanned", never toward "ok".
  * kerascrash (HIGH): a DEFLATE-corrupt `config.json` raised `zlib.error` uncaught and aborted the whole
    scan (CRC mismatch was caught, DEFLATE corruption was not). Fixed by one helper, `_read_member`, that
    is the single place a zip member is decompressed; every decode failure at header-read or body-read
    (`zlib.error`, `lzma.LZMAError`, `BadZipFile`, `NotImplementedError`, `EOFError`, `OSError`) maps to
    G225. Pickle members are now read through it into memory, so a decompression fault can no longer be
    swallowed mid-scan as "ok".
  * zipbypass (HIGH): a dangerous pickle at `.../data/payload.bin` was skipped by **path** alone (any
    member under `data/` was treated as a raw tensor slot). Path is no longer a skip reason: every member
    that starts with a pickle PROTO is read whatever its path, and `sure` (name-confirmed pickle) is now
    derived only from a `.pkl` / `.pickle` member name — a raw-tensor slot that merely starts like a pickle
    is read but flags nothing unless it parses as a real stream. **Deliberate deviation:** confirming which
    members are genuine tensor storages by parsing `data.pkl`'s persistent-id index was *not* built; the
    conservative content check replaces the path skip instead (unconfirmed members are scanned, not
    trusted). A legacy `.pt` zip whose raw `data/N` storage happens to start `0x80 0x02-05` and parses an
    import before failing will now flag (exit 2/3 where it was 0) — the safe direction. A `sure=False`
    member (known a pickle only by its magic bytes) is dropped as "not a pickle" only on a genuine parse
    failure (`broken`); a member that parsed cleanly up to the read cap (`limit`) is kept as G225, so a
    dangerous `__reduce__` padded past 16/64 MiB under a non-`.pkl` name cannot slip through.
  * pickletail (MEDIUM): a valid pickle followed by a proto-0 second stream (`c<module>\n<name>\n`, first
    byte `0x63`, not `0x80`) that imported then truncated still returned "ok", because cut-off detection
    required a `0x80` PROTO marker. There is no verified tensor-data span in a bare pickle file, so any
    failed trailing segment that imported anything (GLOBAL / STACK_GLOBAL / EXT) is now a cut-off stream
    (G224 + G225); a segment that imported nothing is still raw trailing data (ok). A legacy non-zip `.pt`
    whose raw tail parses an import before failing will now flag (the safe direction).
  * ggufvalidation (MEDIUM): a 58-byte GGUF declaring a 1,000,000-element F32 tensor with one byte of data
    returned "ok" — only the offset was bounds-checked, not the tensor's byte length. Now each tensor's
    required bytes are computed from dims × dtype size over its block (ceil, so never underestimated),
    honouring `general.alignment` (default 32; a non-power-of-two is G226), and `data_start + max tensor
    end ≤ file size` is verified; a shortfall is G226. The dtype→(block, type_size) table is taken verbatim
    from llama.cpp `gguf-py/gguf/constants.py` `GGML_QUANT_SIZES`; a tensor of a type not in the table
    cannot be sized and makes the file a gap (G225), not a pass.

## 既知の残存リスク（2026-10-21・残存リスク明記で確定）

3回の外部レビュー（Codex ASTRA）で層を厚くしたが、敵対的に作り込んだファイルで以下は依然すり抜ける。モデルファイル検査は**出荷するが、唯一の防衛線ではない**（信頼できない配布元のモデルは別経路でも審査する前提）。次に腰を据えて直すなら専用パーサの導入が必要（別タスク）。

- **zipbypass（高）**: ZIP メンバー `data/payload.bin` を PROTO マーカーの無いプロトコル0/1の eval 参照 pickle にすると指摘ゼロ。生テンソルの除外を「形式と参照関係の確認が取れた場合に限る」まで厳密化できていない。
- **zipreadgap（中）**: 先頭読み取りの展開エラーを空データ扱いするため、非 .pkl メンバーの DEFLATE 破損が G225 なしで通る経路が残る。
- **kerasescape（中）**: config.json の class_name を `Lambda` と書くと JSON 上は Lambda と等価でも G229 が出ない（復号後の再帰検査が未実装）。
- **stdtype（中）**: safetensors の未知 dtype でサイズ検証を省くため、`dtype=NOT_A_DTYPE・shape=[1000000]・実データ1バイト` が指摘ゼロ。

対応方針（確定）：上記を既知の制約として明記したうえで現行版を出す。利用者向けには「未知形式・改変ファイルは完全には検知しない。配布元の信頼とハッシュ照合を併用」と案内する。
