"""署名ページ。

Google ログインと Drive は Protocol 越しなので、ここでは偽物を差し込んで検証する。
TSA には出ない（tsa_url=None）。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import io

from PIL import Image

from drive_qr_sign.documents import LocalDocumentStore
from drive_qr_sign.seal_store import LocalSealStore
from drive_qr_sign.identity import SignerDirectory, SignerEntry, silent_field_name
from drive_qr_sign.qr import make_mac
from drive_qr_sign.signing import list_signature_fields, load_signer
from drive_qr_sign.web import create_app

SECRET = b"test-secret-do-not-use"
FILE_ID = "sample"


class FakeIdentityProvider:
    """ログイン済みの人を固定で返す。本物は Google の OIDC に置き換わる。"""

    def __init__(self, email: str | None = None):
        self.email = email

    def verified_email(self, request) -> str | None:
        return self.email


@pytest.fixture
def env(fields_pdf: Path, dev_cert, tmp_path: Path):
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    key, cert = dev_cert
    identity = FakeIdentityProvider()
    store = LocalDocumentStore(store_dir)
    app = create_app(
        document_store=store,
        signer_directory=SignerDirectory(
            {
                "Soumu@example.test": SignerEntry(role="担当", seal_text="佐々木"),
                "kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本"),
                "kanji@example.test": None,  # 押印枠を持たない人
            }
        ),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,  # テストはネットワークに出ない
        seal_store=LocalSealStore(tmp_path / "seals"),
    )
    return TestClient(app), identity, store_dir


def _url(file_id: str = FILE_ID, secret: bytes = SECRET) -> str:
    return f"/s/{file_id}?m={make_mac(secret, file_id)}"


def test_status(env):
    """`/healthz` ではない。Cloud Run のフロントエンドがそのパスを横取りするため。"""
    client, _, _ = env
    assert client.get("/status").json() == {"status": "ok"}


def test_forged_qr_is_refused(env):
    client, _, _ = env
    assert client.get(f"/s/{FILE_ID}?m=deadbeef").status_code == 403
    # 別の鍵で作られた MAC も通らない
    assert client.get(_url(secret=b"attacker")).status_code == 403


def test_unknown_document(env):
    client, _, _ = env
    assert client.get(_url("no-such-doc")).status_code == 404


def test_anonymous_visitor_is_asked_to_log_in(env):
    client, _, _ = env
    body = client.get(_url()).text
    assert "ログイン" in body
    assert "<button" not in body  # 押せるボタンは出ない


def test_signer_sees_their_own_field(env):
    client, identity, _ = env
    identity.email = "soumu@example.test"  # 対応表は大文字小文字を区別しない
    body = client.get(_url()).text
    assert "担当として署名する" in body


def test_stranger_cannot_sign(env):
    """見る権限が無い人は押せない。

    本番ではこの判定が Drive の共有設定になる（開発用の既定は名簿で代用）。
    """
    client, identity, _ = env
    identity.email = "yoso@example.test"
    body = client.get(_url()).text
    assert "<button" not in body
    assert "この書類を見る権限がありません" in body


def test_stranger_post_is_refused(env):
    client, identity, store_dir = env
    identity.email = "yoso@example.test"
    # csrf は自分のメールで計算できてしまうので、閲覧権の判定が最後の砦になる
    csrf = _extract_csrf_for(client, identity, "kanji@example.test")
    identity.email = "yoso@example.test"

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 403
    assert not (store_dir / f"{FILE_ID}.signed.pdf").exists()


def test_person_without_a_field_signs_invisibly(env):
    """押印枠を持たない人はサイレント署名。押印枠は空のまま、紙面は変わらない。"""
    client, identity, store_dir = env
    identity.email = "kanji@example.test"

    body = client.get(_url()).text
    assert "確認したことを記録する" in body

    csrf = _extract_csrf(body)
    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert response.status_code == 200
    signed = store_dir / f"{FILE_ID}.signed.pdf"
    assert list_signature_fields(signed, filled=True) == [silent_field_name("kanji@example.test")]
    # 押印枠には一切触れていない
    assert list_signature_fields(signed, filled=False) == ["組合長", "参事", "担当"]


def test_silent_signature_is_not_repeated(env):
    client, identity, _ = env
    identity.email = "kanji@example.test"
    url = f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}"

    csrf = _extract_csrf(client.get(_url()).text)
    assert client.post(url, data={"csrf": csrf}).status_code == 200
    assert "確認済み" in client.get(_url()).text
    assert client.post(url, data={"csrf": csrf}).status_code == 409


def test_seal_lands_in_the_box(env, fields_pdf: Path):
    """押印枠に朱色の印影が乗ること。pyHanko 既定の紫のアートが出ていないことも見る。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    def render(path):
        doc = pdfium.PdfDocument(str(path))
        doc.init_forms()
        return doc[0].render(scale=2, draw_annots=True, may_draw_forms=True).to_pil().convert("RGB")

    before = render(fields_pdf)
    after = render(store_dir / f"{FILE_ID}.signed.pdf")
    # 組合長の枠（PDF座標 311.8-379.8pt, 上端 105.3pt から）を scale=2 の画素に直した範囲
    box = (int(311.8 * 2), int(105.3 * 2), int(379.9 * 2), int(173.4 * 2))
    changed = [
        after.getpixel((x, y))
        for x in range(box[0], box[2])
        for y in range(box[1], box[3])
        if after.getpixel((x, y)) != before.getpixel((x, y))
    ]
    assert changed, "押印枠の中身が変わっていない"
    assert any(r > g + 60 and r > b + 60 for r, g, b in changed), "朱色の芯が無い"
    # pyHanko 既定の紫のアートが出ていれば、青が赤を上回る画素が混ざる
    # （朱色のアンチエイリアスは白に寄るだけなので、赤が青を下回ることはない）
    assert all(r >= b for r, g, b in changed)


def test_viewer_is_shown_to_signers(env):
    """押す前に中身が読めること。紙の代わりになる最低条件。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"

    body = client.get(_url()).text
    assert 'id="document"' in body
    assert "/static/viewer.js" in body

    response = client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}")
    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"


def test_pdfjs_is_served_from_this_app(env):
    """外部 CDN に依存しない。ネットワークを絞った導入先でも動くこと。"""
    client, _, _ = env
    assert client.get("/static/pdfjs/pdf.min.mjs").status_code == 200
    assert client.get("/static/pdfjs/pdf.worker.min.mjs").status_code == 200


def test_document_is_not_shown_without_login(env):
    """QR は紙に刷られて出回る。URL を知っているだけでは中身を見せない。"""
    client, _, _ = env
    assert client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}").status_code == 401
    assert 'id="document"' not in client.get(_url()).text


def test_document_is_not_shown_to_strangers(env):
    client, identity, _ = env
    identity.email = "yoso@example.test"
    assert client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}").status_code == 403
    assert 'id="document"' not in client.get(_url()).text


def _blue_png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGBA", (200, 200), (20, 90, 220, 255)).save(buffer, format="PNG")
    return buffer.getvalue()


def test_registered_image_is_used_instead_of_the_generated_seal(env):
    """本人が登録した画像が、生成した丸印より優先されること。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"

    seal_csrf = _extract_csrf(client.get("/seal").text)
    assert client.post("/seal", data={"csrf": seal_csrf}, files={"image": ("me.png", _blue_png(), "image/png")}).status_code == 200

    csrf = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    doc = pdfium.PdfDocument(str(store_dir / f"{FILE_ID}.signed.pdf"))
    doc.init_forms()
    page = doc[0].render(scale=2, draw_annots=True, may_draw_forms=True).to_pil().convert("RGB")
    r, g, b = page.getpixel((int(345 * 2), int(139 * 2)))  # 組合長の枠の中心
    assert b > r + 60, "登録した画像ではなく生成した丸印が押されている"


def test_seal_upload_requires_login(env):
    client, _, _ = env
    assert client.get("/seal").status_code == 401
    assert client.post("/seal", data={"csrf": "x"}, files={"image": ("me.png", _blue_png(), "image/png")}).status_code == 401


def test_seal_upload_rejects_garbage(env):
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get("/seal").text)
    response = client.post(
        "/seal", data={"csrf": csrf}, files={"image": ("x.png", b"not an image", "image/png")}
    )
    assert response.status_code == 400


def test_deleting_the_registration_falls_back_to_generation(env):
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get("/seal").text)
    client.post("/seal", data={"csrf": csrf}, files={"image": ("me.png", _blue_png(), "image/png")})
    assert "登録した画像を印影に使っています" in client.get("/seal").text

    client.post("/seal/delete", data={"csrf": csrf})
    assert "名前から作った丸印" in client.get("/seal").text


def test_silent_signature_keeps_the_page_unchanged(env, fields_pdf: Path):
    """紙面が変わっていないことを、ページの描画結果そのもので確かめる。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kanji@example.test"
    csrf = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    def render(path) -> bytes:
        doc = pdfium.PdfDocument(str(path))
        doc.init_forms()
        return doc[0].render(scale=1, draw_annots=True, may_draw_forms=True).to_pil().tobytes()

    assert render(store_dir / f"{FILE_ID}.signed.pdf") == render(fields_pdf)


def _extract_csrf_for(client, identity, email: str) -> str:
    identity.email = email
    return _extract_csrf(client.get(_url()).text)


def test_signing_fills_only_that_field(env):
    client, identity, store_dir = env
    identity.email = "soumu@example.test"

    csrf = _extract_csrf(client.get(_url()).text)
    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert response.status_code == 200
    signed = store_dir / f"{FILE_ID}.signed.pdf"
    assert list_signature_fields(signed, filled=True) == ["担当"]
    assert list_signature_fields(signed, filled=False) == ["組合長", "参事"]


def test_second_signer_does_not_erase_the_first(env):
    """回覧なので順番に押される。後の人の署名が前の人の署名を消さないこと。"""
    client, identity, store_dir = env

    for email in ("soumu@example.test", "kumiaicho@example.test"):
        identity.email = email
        csrf = _extract_csrf(client.get(_url()).text)
        assert client.post(
            f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf}
        ).status_code == 200

    signed = store_dir / f"{FILE_ID}.signed.pdf"
    assert list_signature_fields(signed, filled=True) == ["組合長", "担当"]
    assert list_signature_fields(signed, filled=False) == ["参事"]


def test_signing_twice_is_refused(env):
    client, identity, _ = env
    identity.email = "soumu@example.test"
    url = f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}"

    csrf = _extract_csrf(client.get(_url()).text)
    assert client.post(url, data={"csrf": csrf}).status_code == 200
    # 2回目は空欄が無いので弾かれる
    assert client.post(url, data={"csrf": csrf}).status_code == 409


def test_post_without_csrf_is_refused(env):
    client, identity, store_dir = env
    identity.email = "soumu@example.test"

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": "x"})

    assert response.status_code == 403
    assert not (store_dir / f"{FILE_ID}.signed.pdf").exists()


def test_anonymous_post_is_refused(env):
    client, _, store_dir = env
    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": "x"})
    assert response.status_code == 401
    assert not (store_dir / f"{FILE_ID}.signed.pdf").exists()


def test_cannot_sign_a_field_that_is_not_yours(env):
    """割り当てのある人でも、別人の欄は押せない。

    役職名を直接 POST できる余地を残していないことの確認でもある。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)
    identity.email = "soumu@example.test"  # 途中で別人に入れ替わっても組合長欄は押せない

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 403  # csrf が本人のものではない


def _extract_csrf(html: str) -> str:
    marker = 'name="csrf" value="'
    start = html.index(marker) + len(marker)
    return html[start : html.index('"', start)]
