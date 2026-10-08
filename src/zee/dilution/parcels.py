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

from .geometry import Point, Polygon, polygon_fully_inside


@dataclass(frozen=True)
class Parcel:
    chiban: str  # e.g. "サンプル町一丁目45番"
    town: str    # e.g. "サンプル町一丁目"
    vertices: Polygon
    representative_point: Point


def load_parcels(path: Path) -> list[Parcel]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
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
    return out


def load_public_land(path: Path) -> list[Polygon]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        tuple((float(x), float(y)) for x, y in poly["vertices"])
        for poly in data["polygons"]
    ]


def find_nonresidential_parcels(
    parcels: list[Parcel], public_land: list[Polygon],
) -> list[Parcel]:
    """Parcels fully contained in at least one public-land polygon.

    Conservative by construction (geometry.polygon_fully_inside): a
    parcel straddling the boundary is excluded, not guessed at.
    """
    return [
        p for p in parcels
        if any(polygon_fully_inside(p.vertices, land) for land in public_land)
    ]
