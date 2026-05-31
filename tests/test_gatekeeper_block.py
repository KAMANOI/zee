"""Retired in spec v4.

The hard-block on response_mode=auto + dry_run=false was the v2
approach. Spec v4 replaces it with a structurally narrower trigger
condition on op_class=="change" inside responder/sequence.py — see
tests/test_op_class_gate.py for its replacement tests.

This file is intentionally empty (pytest collects no tests from it)
and is kept only to make the v2 → v4 deletion visible in git history.
Safe to delete.
"""
