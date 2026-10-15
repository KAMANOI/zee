"""Privilege separation (prototype, off by default): a root cut daemon and its client.

Design: docs/design/privsep.md. Used only when assets.toml has a
``[privsep]`` table; without it ``zee watch`` cuts in-process as before.
"""
