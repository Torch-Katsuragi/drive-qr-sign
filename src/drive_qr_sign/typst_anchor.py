"""Typst の押印枠アンカーを、PDF の署名フィールド座標に変換する。

書類生成側（Typst）が押印枠の位置を metadata として持ち、こちらはそれを読むだけ。
アプリは書類の種類を知らずに済む（docs/DESIGN.md「PDF が署名欄を自己記述する」）。

Typst 座標は左上原点、PDF 座標は左下原点なので、ページ高さを使って反転させる。
"""

from __future__ import annotations

import json
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader

from .signing import FieldPlacement

ANCHOR_LABEL = "<sig-anchor>"
QR_LABEL = "<qr-anchor>"


def query_anchors(
    typ_file: Path | str, *, root: Path | str | None = None, inputs: dict | None = None
) -> list[dict]:
    """Typst ソースから押印枠の metadata を取り出す。

    返る各要素は {role, page, x, y, w, h}。page は 1 始まり、単位はすべて pt（左上原点）。
    """
    import typst  # dev 依存。アプリ本体の実行時には要らない

    raw = typst.query(
        str(typ_file),
        ANCHOR_LABEL,
        field="value",
        format="json",
        root=str(root) if root else None,
        sys_inputs=inputs or {},
    )
    return json.loads(raw)


def _resolve(obj):
    return obj.get_object() if hasattr(obj, "get_object") else obj


def _media_box(page) -> list[float]:
    """ページの /MediaBox を返す。無ければ親ノードから継承する（PDF 仕様どおり）。"""
    node = page
    while node is not None:
        box = node.get("/MediaBox")
        if box is not None:
            return [float(_resolve(v)) for v in _resolve(box)]
        node = _resolve(node.get("/Parent")) if node.get("/Parent") is not None else None
    raise ValueError("/MediaBox が見つからない")


def query_qr_anchor(
    typ_file: Path | str, *, root: Path | str | None = None, inputs: dict | None = None
) -> dict | None:
    """QR を置いた矩形。カメラで紙を見たときの基準になる。"""
    import typst

    raw = typst.query(
        str(typ_file), QR_LABEL, field="value", format="json",
        root=str(root) if root else None,
        sys_inputs=inputs or {},
    )
    found = json.loads(raw)
    return found[0] if found else None


def page_heights(pdf_file: Path | str) -> list[float]:
    """各ページの高さ（pt）を返す。座標の上下反転に要る。"""
    heights: list[float] = []
    with open(pdf_file, "rb") as inf:
        reader = PdfFileReader(inf)
        count = int(_resolve(_resolve(reader.root["/Pages"])["/Count"]))
        for page_ix in range(count):
            pages, ix, _ = reader.find_page_container(page_ix)
            page = _resolve(_resolve(_resolve(pages)["/Kids"])[ix])
            box = _media_box(page)
            heights.append(box[3] - box[1])
    return heights


def anchors_to_placements(anchors: list[dict], heights: list[float]) -> list[FieldPlacement]:
    """アンカーを PDF 座標の署名フィールド指定に変換する。"""
    placements: list[FieldPlacement] = []
    for anchor in anchors:
        page_ix = int(anchor["page"]) - 1  # Typst は 1 始まり、pyHanko は 0 始まり
        height = heights[page_ix]
        x1 = float(anchor["x"])
        y_top = float(anchor["y"])
        w = float(anchor["w"])
        h = float(anchor["h"])
        placements.append(
            FieldPlacement(
                name=str(anchor["role"]),
                page=page_ix,
                box=(x1, height - y_top - h, x1 + w, height - y_top),
            )
        )
    return placements
