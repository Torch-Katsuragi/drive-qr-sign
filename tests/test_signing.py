"""署名コアの回帰テスト。

既定ではネットワークに出ない（TSA を使わない）。TSA まで通したいときは:

    pytest -m network
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from asn1crypto import pem, x509 as asn1x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from drive_qr_sign.signing import (
    FREE_TSA_URL,
    add_signature_fields,
    list_signature_fields,
    load_signer,
    sign_field,
)
from drive_qr_sign.typst_anchor import anchors_to_placements, page_heights, query_anchors

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DOC = REPO_ROOT / "tools" / "sample_doc.typ"

sys.path.insert(0, str(REPO_ROOT / "tools"))


@pytest.fixture(scope="session")
def dev_cert(tmp_path_factory) -> tuple[Path, Path]:
    from make_dev_cert import make_dev_cert

    return make_dev_cert(tmp_path_factory.mktemp("cert"))


@pytest.fixture(scope="session")
def sample_pdf(tmp_path_factory) -> Path:
    """Typst でサンプル書類をコンパイルしただけの PDF。"""
    import typst

    out = tmp_path_factory.mktemp("doc") / "sample.pdf"
    typst.compile(str(SAMPLE_DOC), output=str(out))
    return out


@pytest.fixture(scope="session")
def fields_pdf(sample_pdf: Path, tmp_path_factory) -> Path:
    """押印枠に空の署名フィールドを注入した PDF。"""
    out = tmp_path_factory.mktemp("fields") / "sample-fields.pdf"
    placements = anchors_to_placements(query_anchors(SAMPLE_DOC), page_heights(sample_pdf))
    add_signature_fields(sample_pdf, out, placements)
    return out


def test_anchors_carry_roles():
    """役職はラベル名ではなく metadata の中身で運ばれる（アプリが役職名を先に知らなくてよい）。"""
    roles = [anchor["role"] for anchor in query_anchors(SAMPLE_DOC)]
    assert roles == ["組合長", "参事", "担当"]


def test_anchor_coordinates_are_flipped(sample_pdf: Path):
    """Typst は左上原点、PDF は左下原点。反転していないと枠と署名欄がずれる。"""
    heights = page_heights(sample_pdf)
    anchors = query_anchors(SAMPLE_DOC)
    placements = anchors_to_placements(anchors, heights)

    assert len(heights) == 1
    for anchor, placement in zip(anchors, placements):
        x1, y1, x2, y2 = placement.box
        assert placement.page == anchor["page"] - 1
        assert x1 == pytest.approx(anchor["x"])
        assert x2 == pytest.approx(anchor["x"] + anchor["w"])
        assert y2 == pytest.approx(heights[0] - anchor["y"])
        assert y1 < y2


def test_fields_are_named_after_roles(fields_pdf: Path):
    assert list_signature_fields(fields_pdf, filled=False) == ["組合長", "参事", "担当"]
    assert list_signature_fields(fields_pdf, filled=True) == []


def test_sign_fills_only_the_named_field(fields_pdf: Path, dev_cert, tmp_path: Path):
    key, cert = dev_cert
    out = tmp_path / "signed.pdf"
    sign_field(
        fields_pdf,
        out,
        field_name="担当",
        signer=load_signer(key, cert),
        tsa_url=None,
        signer_name="テスト太郎",
    )
    assert list_signature_fields(out, filled=True) == ["担当"]
    assert list_signature_fields(out, filled=False) == ["組合長", "参事"]


def test_unknown_field_is_refused(fields_pdf: Path, dev_cert, tmp_path: Path):
    """アプリが勝手に署名欄を作って署名することがないのを確かめる。"""
    key, cert = dev_cert
    with pytest.raises(Exception):
        sign_field(
            fields_pdf,
            tmp_path / "nope.pdf",
            field_name="理事長",  # この PDF には無い欄
            signer=load_signer(key, cert),
            tsa_url=None,
        )


def _validation_context(cert_path: Path) -> ValidationContext:
    _, _, der = pem.unarmor(cert_path.read_bytes())
    return ValidationContext(
        trust_roots=[asn1x509.Certificate.load(der)],
        allow_fetching=False,
        revocation_mode="soft-fail",
    )


def test_signature_validates_and_covers_whole_file(fields_pdf: Path, dev_cert, tmp_path: Path):
    key, cert = dev_cert
    out = tmp_path / "signed.pdf"
    sign_field(fields_pdf, out, field_name="組合長", signer=load_signer(key, cert), tsa_url=None)

    with open(out, "rb") as inf:
        embedded = PdfFileReader(inf).embedded_signatures[0]
        status = validate_pdf_signature(embedded, signer_validation_context=_validation_context(cert))
        assert embedded.field_name == "組合長"
        # PAdES = /ETSI.CAdES.detached。ここが変わると Acrobat から見た署名の種類が変わる
        assert str(embedded.sig_object["/SubFilter"]) == "/ETSI.CAdES.detached"
        assert status.intact and status.valid and status.trusted
        assert status.coverage.name == "ENTIRE_FILE"


@pytest.mark.network
def test_timestamp_is_embedded(fields_pdf: Path, dev_cert, tmp_path: Path):
    key, cert = dev_cert
    out = tmp_path / "signed-tsa.pdf"
    sign_field(fields_pdf, out, field_name="参事", signer=load_signer(key, cert), tsa_url=FREE_TSA_URL)

    with open(out, "rb") as inf:
        embedded = PdfFileReader(inf).embedded_signatures[0]
        status = validate_pdf_signature(embedded, signer_validation_context=_validation_context(cert))
        # TSA 証明書は信頼していないので trusted にはならない。時刻が入っていることだけ見る
        assert status.timestamp_validity is not None
        assert status.timestamp_validity.timestamp is not None
