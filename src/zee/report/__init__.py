"""Incident report bundling for external handoff (police / PPC).

See docs/design/incident-report.md. This package only reads files other
Zee commands already wrote (``zee export`` output, canary-hit logs) and
numbers the operator already computed (dilution match counts); it does
not touch the internals of those commands, and it never submits
anything itself (see ``incident_report.py`` module docstring).
"""
