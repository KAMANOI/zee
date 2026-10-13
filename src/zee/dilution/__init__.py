"""Decoy PII record generation — value dilution for exfiltrated data.

Distinct from zee.decoy (filesystem tripwire canaries): this package
generates dummy personal-record rows + a holder-only ledger, meant to
be mixed into a backup/export so a stolen copy is harder to resell at
full price. See docs/design/decoy-pii-dilution.md for the full design
and the data-source research it depends on.

Writes files only. Does not touch any database or network.
"""
