"""Retired in spec v4.

The v2 build shipped a built-in OS-indexer allowlist. Spec v4
revoked that approach because no current watcher backend reports
the touching process, so the responder cannot consult an allowlist
at decoy-touch time. False-positive control now relies on placement
guidance (README) and the change-class trigger limit in
responder/sequence.py.

This file is intentionally empty and kept only to make the v2 → v4
removal visible in git history. Safe to delete.
"""
