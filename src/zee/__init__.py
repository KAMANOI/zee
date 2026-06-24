"""Zee — lightweight decoy tripwire and post-intrusion containment layer.

Zee runs in dry_run by default. It does not actually cut connections
unless an asset profile is explicitly promoted to auto/staged mode.

Zee does not prevent intrusion. It adds one narrow, high-confidence
detection signal (decoy contact) and optionally a containment action.
"""

__version__ = "0.8.0"
