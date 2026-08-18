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


def test_describe_reports_boxes_and_signatures(fields_pdf: Path, dev_cert, tmp_path: Path):
    """カメラ表示が要る情報が揃っていること。"""
    from drive_qr_sign.layout import describe
    from drive_qr_sign.signing import load_signer, sign_field, sign_invisible

    with_qr = tmp_path / "with-qr.pdf"
    write_qr_rect(fields_pdf, with_qr, page=0, box=BOX)

    key, cert = dev_cert
    signer = load_signer(key, cert)
    signed = tmp_path / "signed.pdf"
    sign_field(with_qr, signed, field_name="組合長", signer=signer, tsa_url=None, signer_name="a@example.test")
    both = tmp_path / "both.pdf"
    sign_invisible(signed, both, field_name="silent-x", signer=signer, tsa_url=None, signer_name="b@example.test")

    layout = describe(both.read_bytes())

    assert round(layout["page"]["width"]) == 595 and round(layout["page"]["height"]) == 842
    assert layout["qr"]["page"] == 0

    by_name = {f["name"]: f for f in layout["fields"]}
    assert by_name["組合長"]["signed"] and by_name["組合長"]["signer"] == "a@example.test"
    assert not by_name["参事"]["signed"]
    # 不可視署名は紙の上に場所を持たないので、枠ではなく脇のカードに回る
    assert "silent-x" not in by_name
    assert layout["silent"] == [{"signer": "b@example.test"}]
