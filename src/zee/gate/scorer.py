"""Map flags to a LOW / MEDIUM / HIGH verdict (safeinspect heritage).

Rule: any high-severity flag => HIGH. Otherwise sum severity weights
(low=1, medium=4, high=10):
    >= 10 => HIGH   (e.g. several medium findings stacking up)
    >= 4  => MEDIUM
    else  => LOW

Thresholds are deliberately simple and tunable. Evidence is always
attached to flags so an operator can review false positives — this is
risk reduction, not complete detection (invariant I5).
"""

from __future__ import annotations

from .model import Flag, RiskLevel, Severity

_HIGH_TOTAL = 10
_MEDIUM_TOTAL = 4


def score(flags: list[Flag]) -> tuple[RiskLevel, int]:
    total = sum(f.severity.weight for f in flags)
    if any(f.severity is Severity.HIGH for f in flags):
        return RiskLevel.HIGH, total
    if total >= _HIGH_TOTAL:
        return RiskLevel.HIGH, total
    if total >= _MEDIUM_TOTAL:
        return RiskLevel.MEDIUM, total
    return RiskLevel.LOW, total
