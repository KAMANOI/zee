"""Retired in spec v4.

The v2 build shipped a built-in OS-indexer allowlist here. Spec v4
revoked that approach for a structural reason: none of the current
watcher backends (Linux inotify / macOS kqueue / Windows
ReadDirectoryChangesW) report the process that touched the decoy, so
no name-based allowlist can take effect at detect time on this MVP.
Bundling a default allowlist that cannot fire would create a false
sense of safety.

False-positive control is instead split across three layers:
  - placement (spec block B-1): keep decoys outside what backup / AV /
    indexer software walks. README/STARTER_GUIDE document this.
  - configuration-scan pre-warning (spec B-2, future work).
  - trigger limitation (spec block C): auto-cut runs only on
    change-class touches, which legitimate bulk readers do not
    perform on decoys under normal operation.

This file is intentionally empty and kept only to make the v2 → v4
removal visible in git history. Safe to delete.
"""
