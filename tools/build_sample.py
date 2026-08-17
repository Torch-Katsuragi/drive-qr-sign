"""サンプル書類をビルドして、押印枠に空の署名フィールドを注入する。

    python tools/build_sample.py

out/sample.pdf（Typst の出力そのまま）と out/sample-fields.pdf（署名欄つき）を作る。
本番では書類生成ワークフローがこれと同じことをする。
"""

from __future__ import annotations

from pathlib import Path

import typst

from drive_qr_sign.signing import add_signature_fields, list_signature_fields
from drive_qr_sign.typst_anchor import anchors_to_placements, page_heights, query_anchors

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "tools" / "sample_doc.typ"
OUT_DIR = REPO_ROOT / "out"


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    plain_pdf = OUT_DIR / "sample.pdf"
    field_pdf = OUT_DIR / "sample-fields.pdf"

    typst.compile(str(SOURCE), output=str(plain_pdf))
    print(f"compiled: {plain_pdf}")

    anchors = query_anchors(SOURCE)
    print(f"anchors : {anchors}")

    placements = anchors_to_placements(anchors, page_heights(plain_pdf))
    for placement in placements:
        box = ", ".join(f"{v:.1f}" for v in placement.box)
        print(f"  {placement.name}: page={placement.page} box=({box})")

    add_signature_fields(plain_pdf, field_pdf, placements)
    print(f"fields  : {field_pdf}")
    print(f"empty   : {list_signature_fields(field_pdf, filled=False)}")


if __name__ == "__main__":
    main()
