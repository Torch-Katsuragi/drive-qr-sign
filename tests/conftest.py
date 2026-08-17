"""テスト全体で使う素材。

サンプル書類は毎回 Typst からビルドする。書類生成側の記法が壊れたら
署名側のテストも落ちてほしいため（ここが繋がっていないと、
アンカーの書き方を変えた日に気づけない）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from drive_qr_sign.signing import add_signature_fields
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
