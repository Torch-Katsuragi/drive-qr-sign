"""紙の上の座標を PDF 自身に持たせる。

カメラで紙にかざしたとき、押印枠がどこにあるかを知る必要がある。
署名フィールドの矩形は PDF から読めるが、**QR がどこにあるか**は読めない。
それが分からないと、カメラに写った QR を基準に紙面の座標へ変換できない。

だから QR の矩形も PDF に書いておく。位置情報を PDF 側に持たせるのは
署名欄と同じ考え方で、アプリは書類の種類を知らないまま済む（docs/DESIGN.md）。
"""

from __future__ import annotations

import io
import json

from pyhanko.pdf_utils.generic import DictionaryObject, NameObject, TextStringObject
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

# 文書情報辞書に置く独自キー。PDF の仕様上、独自キーを足すのは許されている
LAYOUT_KEY = "/DriveQrSignLayout"


def write_qr_rect(src, dst, *, page: int, box: tuple[float, float, float, float]) -> None:
    """QR の矩形を PDF に書く。増分更新なので紙面は変わらない。

    box は PDF 座標（左下原点・pt）で (x1, y1, x2, y2)。
    """
    payload = json.dumps({"qr": {"page": page, "box": list(box)}}, ensure_ascii=False)
    with open(src, "rb") as inf, open(dst, "wb") as outf:
        writer = IncrementalPdfFileWriter(inf)
        info = writer.trailer.raw_get("/Info").get_object() if "/Info" in writer.trailer else None
        if info is None:
            info = DictionaryObject()
            writer.trailer[NameObject("/Info")] = writer.add_object(info)
        info[NameObject(LAYOUT_KEY)] = TextStringObject(payload)
        writer.update_container(info)
        writer.write(outf)


def read_qr_rect(pdf: bytes) -> dict | None:
    """書いておいた QR の矩形を読む。無ければ None（QR を焼いていない書類）。"""
    reader = PdfFileReader(io.BytesIO(pdf))
    if "/Info" not in reader.trailer:
        return None
    raw = reader.trailer.raw_get("/Info").get_object().get(LAYOUT_KEY)
    if raw is None:
        return None
    try:
        return json.loads(str(raw))["qr"]
    except (ValueError, KeyError):
        return None


def describe(pdf: bytes) -> dict:
    """紙の上に何がどこにあるか。カメラ表示（AR）が必要とする情報の全部。

    座標はすべて PDF 座標（左下原点・pt）。カメラ側は QR の矩形を手がかりに
    この座標系へ変換する。
    """
    from pyhanko.sign import fields as sig_fields

    reader = PdfFileReader(io.BytesIO(pdf))
    pages, _, _ = reader.find_page_container(0)
    page = _resolve(_resolve(_resolve(pages)["/Kids"])[0])
    media = [float(_resolve(v)) for v in _resolve(_media_box(page))]

    signed_by = {}
    for embedded in reader.embedded_signatures:
        name = embedded.sig_object.get("/Name")
        signed_by[embedded.field_name] = str(name) if name else ""

    boxes, silent = [], []
    for name, value, ref in sig_fields.enumerate_sig_fields(reader):
        rect = ref.get_object().get("/Rect")
        box = [float(_resolve(v)) for v in _resolve(rect)] if rect is not None else [0, 0, 0, 0]
        entry = {
            "name": name,
            "box": box,
            "signed": name in signed_by,
            "signer": signed_by.get(name, ""),
        }
        # 不可視署名（サイレント組）は紙の上に場所を持たない。脇にカードで出す
        if box[2] - box[0] <= 0 or box[3] - box[1] <= 0:
            if entry["signed"]:
                silent.append({"signer": entry["signer"]})
        else:
            boxes.append(entry)

    return {
        "page": {"width": media[2] - media[0], "height": media[3] - media[1]},
        "qr": read_qr_rect(pdf),
        "fields": boxes,
        "silent": silent,
    }


def _resolve(obj):
    return obj.get_object() if hasattr(obj, "get_object") else obj


def _media_box(page):
    node = page
    while node is not None:
        box = node.get("/MediaBox")
        if box is not None:
            return box
        parent = node.get("/Parent")
        node = _resolve(parent) if parent is not None else None
    raise ValueError("/MediaBox が見つからない")
