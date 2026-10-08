"""Pure-stdlib 2D polygon containment — no shapely (core stays dependency-free).

Inputs are expected in a shared planar coordinate system (e.g. the Japan
Plane Rectangular CS a 公共座標系 parcel extract uses). Callers are
responsible for rejecting mismatched CRSs before this module sees them.
"""

from __future__ import annotations

Point = tuple[float, float]
Polygon = tuple[Point, ...]


def point_in_polygon(point: Point, polygon: Polygon) -> bool:
    """Ray-casting point-in-polygon test. Boundary points count as inside."""
    x, y = point
    n = len(polygon)
    inside = False
    for i in range(n):
        x1, y1 = polygon[i]
        x2, y2 = polygon[(i + 1) % n]
        if (x1 == x and y1 == y):
            return True
        if (y1 > y) != (y2 > y):
            x_intersect = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if x_intersect == x:
                return True
            if x_intersect > x:
                inside = not inside
    return inside


def polygon_fully_inside(candidate: Polygon, container: Polygon) -> bool:
    """True iff every vertex of ``candidate`` lies inside (or on) ``container``.

    Deliberately conservative: a parcel straddling a park boundary is
    rejected rather than guessed at. This is a vertex test, not a true
    area-coverage test (ponytail: no polygon-clipping library available
    stdlib-only; add exact area overlap if boundary-straddling parcels
    turn out to matter in practice).
    """
    return all(point_in_polygon(v, container) for v in candidate)
