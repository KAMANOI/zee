"""Load parcel (地番) and public-land (都市公園・河川区域) extracts, and find
parcels that lie fully inside public land — the non-residential anchors
for Layer 2 (see docs/design/decoy-pii-dilution.md §1-2).

v1 input format is a simple JSON stand-in for the real MOJ 登記所備付地図
データ / KSJ P13・河川区域 extracts (which require GML/shapefile parsing
and manual G空間情報センター downloads — out of scope for this
prototype; see design doc §1 "確認できなかった点"). The real parsers are
a follow-on task; this module only needs the post-parse shape below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..errors import Z804_CRS_MISMATCH, ZeeError
from .geometry import Point, Polygon, polygon_fully_inside

_ALLOWED_PUBLIC_LAND_KINDS = frozenset({"park", "river"})


@dataclass(frozen=True)
class Parcel:
    chiban: str  # e.g. "サンプル町一丁目45番"
    town: str    # e.g. "サンプル町一丁目"
    vertices: Polygon
    representative_point: Point


def load_parcels(path: Path) -> tuple[list[Parcel], str]:
    """Returns (parcels, crs). ``crs`` must match load_public_land's crs —
    callers are required to check this (find_nonresidential_parcels does)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    crs = data["crs"]
    out = []
    for row in data["parcels"]:
        verts = tuple((float(x), float(y)) for x, y in row["vertices"])
        rep = tuple(row["representative_point"])
        out.append(Parcel(
            chiban=row["chiban"],
            town=row["town"],
            vertices=verts,
            representative_point=(float(rep[0]), float(rep[1])),
        ))
    return out, crs


def load_public_land(path: Path) -> tuple[list[Polygon], str]:
    """Returns (polygons, crs). Only 'park'/'river' kinds are included —
    an unrecognized kind is rejected rather than silently treated as
    public land (fail-closed on unexpected input, e.g. the design doc's
    explicitly-excluded 駐車場 or a future 'residential' tag), and so is any
    polygon carrying 'holes' (fail-closed until holes are modelled)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    crs = data["crs"]
    polys = []
    for poly in data["polygons"]:
        kind = poly.get("kind")
        if kind not in _ALLOWED_PUBLIC_LAND_KINDS:
            continue
        # Holes (ponds, sandbars: non-public land inside the outer ring) are
        # not modelled by polygon_fully_inside; ignoring them would pass a
        # parcel sitting in the hole. Drop such polygons (design doc §10).
        if poly.get("holes"):
            continue
        polys.append(tuple((float(x), float(y)) for x, y in poly["vertices"]))
    return polys, crs


def find_nonresidential_parcels(
    parcels: list[Parcel], parcels_crs: str,
    public_land: list[Polygon], public_land_crs: str,
    real_towns: frozenset[str],
) -> list[Parcel]:
    """Parcels fully contained in at least one public-land polygon, in a
    real (ABR-confirmed) town.

    Conservative by construction (geometry.polygon_fully_inside): a
    parcel straddling the boundary, or with degenerate geometry, is
    excluded, not guessed at. A parcel whose town doesn't match the
    real town-name master is excluded too — don't trust an un-verified
    town string when the whole Layer-2 safety property rests on it
    being real and the chiban coming from the matching record.
    """
    if parcels_crs != public_land_crs:
        raise ZeeError(Z804_CRS_MISMATCH, f"{parcels_crs!r} != {public_land_crs!r}")
    return [
        p for p in parcels
        if p.town in real_towns
        and any(polygon_fully_inside(p.vertices, land) for land in public_land)
    ]
