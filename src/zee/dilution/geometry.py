"""Pure-stdlib 2D polygon containment — no shapely (core stays dependency-free).

Inputs are expected in a shared planar coordinate system (e.g. the Japan
Plane Rectangular CS a 公共座標系 parcel extract uses). Callers are
responsible for rejecting mismatched CRSs before this module sees them
(parcels.load_parcels / load_public_land enforce a matching ``crs`` tag).
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


def _orientation(a: Point, b: Point, c: Point) -> int:
    val = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
    if val > 0:
        return 1
    if val < 0:
        return -1
    return 0


def _on_segment(a: Point, b: Point, p: Point) -> bool:
    return (min(a[0], b[0]) <= p[0] <= max(a[0], b[0])
            and min(a[1], b[1]) <= p[1] <= max(a[1], b[1]))


def segments_intersect(a1: Point, a2: Point, b1: Point, b2: Point) -> bool:
    """True if segment a1-a2 crosses segment b1-b2 (touching at a shared
    endpoint does not count — adjacent polygon edges share endpoints)."""
    o1 = _orientation(a1, a2, b1)
    o2 = _orientation(a1, a2, b2)
    o3 = _orientation(b1, b2, a1)
    o4 = _orientation(b1, b2, a2)

    if o1 != o2 and o3 != o4:
        return True
    # collinear overlap cases (excluding mere shared endpoints)
    if o1 == 0 and _on_segment(a1, a2, b1) and b1 not in (a1, a2):
        return True
    if o2 == 0 and _on_segment(a1, a2, b2) and b2 not in (a1, a2):
        return True
    if o3 == 0 and _on_segment(b1, b2, a1) and a1 not in (b1, b2):
        return True
    if o4 == 0 and _on_segment(b1, b2, a2) and a2 not in (b1, b2):
        return True
    return False


def _edges(polygon: Polygon) -> list[tuple[Point, Point]]:
    n = len(polygon)
    return [(polygon[i], polygon[(i + 1) % n]) for i in range(n)]


def polygon_fully_inside(candidate: Polygon, container: Polygon) -> bool:
    """True iff ``candidate`` lies entirely within ``container``.

    Two conditions, both required — vertex containment alone is not
    enough: a candidate can have every vertex inside a concave (e.g.
    U-shaped) container while an edge still cuts through the notch and
    exits the container in between vertices.

    1. every vertex of candidate is inside (or on the boundary of) container
    2. no edge of candidate crosses any edge of container

    Degenerate inputs (fewer than 3 vertices) are rejected outright —
    the whole decoy-dilution property rests on this check being
    conservative, so malformed geometry fails closed rather than being
    silently treated as "trivially inside".
    """
    if len(candidate) < 3 or len(container) < 3:
        return False
    if not all(point_in_polygon(v, container) for v in candidate):
        return False
    for a1, a2 in _edges(candidate):
        for b1, b2 in _edges(container):
            if segments_intersect(a1, a2, b1, b2):
                return False
    return True
