"""QR の矩形を PDF に持たせる。

カメラで紙を見たときに押印枠の位置を割り出すには、QR がどこにあるかが要る。
署名フィールドの矩形は PDF から読めるが、QR の位置はどこにも書かれていない。
"""

from __future__ import annotations

from pathlib import Path

from drive_qr_sign.layout import read_qr_rect, write_qr_rect
from drive_qr_sign.signing import list_signature_fields

BOX = (476.2, 722.8, 538.6, 785.2)


def test_qr_rect_survives_the_round_trip(fields_pdf: Path, tmp_path: Path):
    out = tmp_path / "with-qr.pdf"
    write_qr_rect(fields_pdf, out, page=0, box=BOX)

    stored = read_qr_rect(out.read_bytes())
    assert stored["page"] == 0
    assert [round(v, 1) for v in stored["box"]] == list(BOX)


def test_writing_the_rect_does_not_touch_the_signature_fields(fields_pdf: Path, tmp_path: Path):
    """増分更新で書くので、押印枠も紙面も変わらない。"""
    out = tmp_path / "with-qr.pdf"
    write_qr_rect(fields_pdf, out, page=0, box=BOX)

    assert list_signature_fields(out, filled=False) == list_signature_fields(fields_pdf, filled=False)


def test_document_without_a_qr_returns_none(fields_pdf: Path):
    assert read_qr_rect(fields_pdf.read_bytes()) is None
