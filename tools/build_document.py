"""QR を焼き込んだ書類を作り、Drive に置く。

    python tools/build_document.py [<書類.typ>] [--name "書類の名前"] [--upload]

書類を省略すると、同梱のサンプル（tools/sample_doc.typ）を使う。

やっていること:

1. Drive に file id を**予約する**（`files.generateIds`）
2. その id から署名ページの URL を作り、QR に焼く
3. Typst でコンパイル（QR が紙面に入る）
4. 押印枠の座標に空の署名フィールドを注入する
5. 予約した id でアップロードする

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
from drive_qr_sign.qr import sign_url
from drive_qr_sign.signing import add_signature_fields, list_signature_fields
from drive_qr_sign.typst_anchor import anchors_to_placements, page_heights, query_anchors

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "tools" / "sample_doc.typ"
OUT_DIR = REPO_ROOT / "out"
SECRETS = REPO_ROOT / "secrets"


def reserve_file_id(service) -> str:
    return service.files().generateIds(count=1, space="drive").execute()["ids"][0]


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="QR を焼き込んだ書類を作る")
    parser.add_argument("source", nargs="?", default=str(SOURCE), help="Typst の書類（省略時はサンプル）")
    parser.add_argument("--name", default=None, help="Drive に置くときのファイル名")
    parser.add_argument("--upload", action="store_true", help="Drive に置く（省略時は手元に作るだけ）")
    args = parser.parse_args(argv)

    source = Path(args.source).resolve()
    if not source.is_file():
        raise SystemExit(f"書類が無い: {source}")
    upload = args.upload
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
    typst.compile(str(source), output=str(plain), root=str(REPO_ROOT), sys_inputs=inputs)

    heights = page_heights(plain)
    placements = anchors_to_placements(query_anchors(source, root=REPO_ROOT, inputs=inputs), heights)
    ready = OUT_DIR / "document-ready.pdf"
    add_signature_fields(plain, ready, placements)

    print(f"押印枠  : {list_signature_fields(ready, filled=False)}")
    print(f"できた  : {ready}")

    if upload:
        from googleapiclient.http import MediaIoBaseUpload

        media = MediaIoBaseUpload(io.BytesIO(Path(ready).read_bytes()), mimetype="application/pdf")
        service.files().create(
            body={"id": file_id, "name": args.name or f"{source.stem}.pdf"},
            media_body=media,
            fields="id",
        ).execute()
        print(f"Drive に置いた: https://drive.google.com/file/d/{file_id}/view")
        print("⚠署名者と、アプリのサービスアカウントに共有すること")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
