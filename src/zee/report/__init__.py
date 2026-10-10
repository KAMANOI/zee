"""Incident report bundling for external handoff (police / PPC).

See docs/design/incident-report.md. This package only reads a file
another Zee command already wrote (``zee export`` output); it does not
touch that command's internals, and it never submits anything itself
(see ``incident_report.py`` module docstring).
"""
