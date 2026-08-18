"""QR を焼き込んだ書類を作り、Drive に置く。

    python tools/build_document.py [--upload]

やっていること:

1. Drive に file id を**予約する**（`files.generateIds`）
2. その id から署名ページの URL を作り、QR に焼く
3. Typst でコンパイル（QR が紙面に入る）
4. 押印枠の座標に空の署名フィールドを注入する
5. QR の矩形を PDF に書く（カメラで見たときの基準になる）
6. 予約した id でアップロードする

file id の鶏卵問題——QR に URL を焼くには id が要るが、id はアップロード後にしか
決まらない——を、先に予約することで解いている。後から埋め込む工程を作らない。
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import segno
import typst

from drive_qr_sign.drive import build_service
from drive_qr_sign.layout import write_qr_rect
from drive_qr_sign.qr import sign_url
from drive_qr_sign.signing import add_signature_fields, list_signature_fields
from drive_qr_sign.typst_anchor import (
    anchors_to_placements,
    page_heights,
    query_anchors,
    query_qr_anchor,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "tools" / "sample_doc.typ"
OUT_DIR = REPO_ROOT / "out"
SECRETS = REPO_ROOT / "secrets"


def reserve_file_id(service) -> str:
    return service.files().generateIds(count=1, space="drive").execute()["ids"][0]


def main(argv: list[str]) -> int:
    upload = "--upload" in argv
    OUT_DIR.mkdir(exist_ok=True)

    config = json.loads((SECRETS / "dev-drive.json").read_text(encoding="utf-8"))
    origin = config.get("origin", "http://localhost:8765")
    qr_secret = config["qr_secret"].encode("utf-8")

    service = build_service(SECRETS / "service-account.json") if upload else None
    file_id = reserve_file_id(service) if upload else config["file_id"]

    url = sign_url(origin, qr_secret, file_id)
    qr_png = OUT_DIR / "document-qr.png"
    # 誤り訂正は高め。紙は折れるし汚れる
    segno.make(url, error="h").save(str(qr_png), scale=12, border=2)
    print(f"file id : {file_id}")
    print(f"QR の URL: {url}")

    # ⚠Typst に渡すパスにバックスラッシュは使えない。root からの相対にして区切りも / にする
    inputs = {"qr": "/" + qr_png.relative_to(REPO_ROOT).as_posix()}
    plain = OUT_DIR / "document.pdf"
    typst.compile(str(SOURCE), output=str(plain), root=str(REPO_ROOT), sys_inputs=inputs)

    heights = page_heights(plain)
    placements = anchors_to_placements(query_anchors(SOURCE, root=REPO_ROOT, inputs=inputs), heights)
    with_fields = OUT_DIR / "document-fields.pdf"
    add_signature_fields(plain, with_fields, placements)

    qr_anchor = query_qr_anchor(SOURCE, root=REPO_ROOT, inputs=inputs)
    ready = OUT_DIR / "document-ready.pdf"
    if qr_anchor:
        page_ix = int(qr_anchor["page"]) - 1
        height = heights[page_ix]
        x, y, w, h = (float(qr_anchor[k]) for k in ("x", "y", "w", "h"))
        write_qr_rect(with_fields, ready, page=page_ix, box=(x, height - y - h, x + w, height - y))
    else:
        ready = with_fields

    print(f"押印枠  : {list_signature_fields(ready, filled=False)}")
    print(f"できた  : {ready}")

    if upload:
        from googleapiclient.http import MediaIoBaseUpload

        media = MediaIoBaseUpload(io.BytesIO(Path(ready).read_bytes()), mimetype="application/pdf")
        service.files().create(
            body={"id": file_id, "name": "drive-qr-sign_QR入り_支出調書サンプル.pdf"},
            media_body=media,
            fields="id",
        ).execute()
        print(f"Drive に置いた: https://drive.google.com/file/d/{file_id}/view")
        print("⚠署名者と、アプリのサービスアカウントに共有すること")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
