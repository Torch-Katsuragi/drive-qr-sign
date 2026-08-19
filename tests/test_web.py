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
from drive_qr_sign.identity import SignerDirectory, SignerEntry, silent_field_name
from drive_qr_sign.qr import make_mac
from drive_qr_sign.signing import list_signature_fields, load_signer, sign_field
from drive_qr_sign.web import create_app

SECRET = b"test-secret-do-not-use"
PNG_MAGIC = bytes.fromhex("89504e470d0a1a0a")  # PNG のマジックナンバー
FILE_ID = "sample"


class FakeIdentityProvider:
    """ログイン済みの人を固定で返す。本物は Google の OIDC に置き換わる。"""

    def __init__(self, email: str | None = None):
        self.email = email

    def verified_email(self, request) -> str | None:
        return self.email


class CountingStore:
    """Drive の代わり。何回取りに行ったかを数える。"""

    def __init__(self, inner):
        self.inner = inner
        self.fetches = 0

    def fetch(self, file_id: str) -> bytes:
        self.fetches += 1
        return self.inner.fetch(file_id)

    def store_signed(self, file_id: str, pdf: bytes):
        return self.inner.store_signed(file_id, pdf)

    def content_hash(self, file_id: str):
        return self.inner.content_hash(file_id)


@pytest.fixture
def env(fields_pdf: Path, dev_cert, tmp_path: Path):
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    key, cert = dev_cert
    identity = FakeIdentityProvider()
    store = CountingStore(LocalDocumentStore(store_dir))
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
    )
    client = TestClient(app)
    client.store = store  # 取りに行った回数を見るテスト用
    return client, identity, store_dir


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


def test_uploaded_image_is_used_for_that_signature(env):
    """その場でアップロードした画像で押せること。保管はしない。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"

    csrf = _extract_csrf(client.get(_url()).text)
    response = client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": csrf},
        files={"seal_image": ("me.png", _blue_png(), "image/png")},
    )
    assert response.status_code == 200

    doc = pdfium.PdfDocument(str(store_dir / f"{FILE_ID}.signed.pdf"))
    doc.init_forms()
    page = doc[0].render(scale=2, draw_annots=True, may_draw_forms=True).to_pil().convert("RGB")
    r, g, b = page.getpixel((int(345 * 2), int(145 * 2)))  # 組合長の枠の中ほど
    assert b > r + 60, "アップロードした画像ではなく生成した丸印が押されている"


def test_garbage_upload_is_refused(env):
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)

    response = client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": csrf},
        files={"seal_image": ("x.png", b"not an image", "image/png")},
    )
    assert response.status_code == 400
    assert not (store_dir / f"{FILE_ID}.signed.pdf").exists()


def test_stamp_preview_needs_login(env):
    client, _, _ = env
    assert client.get("/seal/preview.png").status_code == 401


def test_stamp_preview_is_an_image(env):
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    response = client.get("/seal/preview.png")
    assert response.status_code == 200
    assert response.content[:8] == PNG_MAGIC


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


def _unsigned_boxes(html: str) -> str:
    """「未署名の押印枠:」の行だけを取り出す（押した人の一覧と混ざらないように）。"""
    return html.split("未署名の押印枠:")[1].split("</p>")[0]


def _extract_csrf(html: str) -> str:
    marker = 'name="csrf" value="'
    start = html.index(marker) + len(marker)
    return html[start : html.index('"', start)]


def test_signer_can_take_back_their_own_signature(env):
    """押し間違えたときに取り消せること。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == ["組合長"]

    body = client.get(_url()).text
    assert "署名を取り消す" in body

    response = client.post(f"/s/{FILE_ID}/revoke?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 200
    signed = store_dir / f"{FILE_ID}.signed.pdf"
    assert list_signature_fields(signed, filled=True) == []
    assert list_signature_fields(signed, filled=False) == ["組合長", "参事", "担当"]


def test_the_signing_account_is_always_on_screen(env):
    """誰として押すのかが、押す前に必ず見えていること。取り違えは後から直せない。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    body = client.get(_url()).text
    assert '/account/icon.png' in body
    assert "kumiaicho@example.test" in body

    icon = client.get("/account/icon.png")
    assert icon.status_code == 200
    assert icon.content.startswith(PNG_MAGIC)


def test_the_account_icon_is_the_same_picture_that_lands_on_paper(env):
    """右上の顔と紙に載る印が違うと、確認の役に立たない。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    from drive_qr_sign.seal import compose_stamp

    icon = Image.open(io.BytesIO(client.get("/account/icon.png").content))
    stamp = Image.open(io.BytesIO(client.get("/seal/preview.png").content)).convert("RGBA")
    # 押印枠に入るのは、この顔の上にアドレスの帯を足したもの
    assert compose_stamp(icon, "kumiaicho@example.test") == stamp


def test_the_account_is_not_shown_to_a_visitor_who_has_not_logged_in(env):
    client, _, _ = env
    assert "/account/icon.png" not in client.get(_url()).text
    assert client.get("/account/icon.png").status_code == 401


def test_signing_comes_back_to_the_same_page(env):
    """押した後に「署名しました」という画面へ移らず、同じ画面のボタンが入れ替わること。

    完了画面は読むだけで、閉じる操作をもう1回させる。押した結果は書類とボタンを
    見れば分かるので置かない。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert response.status_code == 200
    assert str(response.url).endswith(_url())  # 303 で署名ページへ戻っている
    body = response.text
    assert "組合長として署名する" not in body  # 押すボタンは消えて
    assert "署名を取り消す" in body  # 同じ場所が取り消しに変わる
    assert 'id="document"' in body  # 書類も一緒に出ている


def test_the_revoke_button_stays_greyed_out_when_locked(env):
    """取り消せないときもボタンは残す。消すと「取り消せる場所がある」ごと見えなくなる。"""
    client, identity, _ = env
    for who in ("kumiaicho@example.test", "soumu@example.test"):
        identity.email = who
        csrf = _extract_csrf(client.get(_url()).text)
        client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    identity.email = "kumiaicho@example.test"
    body = client.get(_url()).text
    assert "disabled" in body
    assert "いまは取り消せません" in body


def test_cannot_take_back_once_someone_signed_after_you(env):
    """後の人の署名は自分の署名を含めて覆っている。抜くと相手のものが壊れる。"""
    client, identity, store_dir = env

    identity.email = "kumiaicho@example.test"
    first = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": first})

    identity.email = "soumu@example.test"
    second = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": second})

    identity.email = "kumiaicho@example.test"
    body = client.get(_url()).text
    assert "いまは取り消せません" in body
    assert client.post(
        f"/s/{FILE_ID}/revoke?m={make_mac(SECRET, FILE_ID)}", data={"csrf": first}
    ).status_code == 409
    # 2人ぶんとも残っている（並びはPDF内のフィールド順で、押した順ではない）
    assert sorted(list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True)) == sorted(
        ["組合長", "担当"]
    )


def test_the_last_signer_can_still_take_theirs_back(env):
    """順に押した後でも、いちばん上の人は外せる（積んだ順に外れる）。"""
    client, identity, store_dir = env
    for who in ("kumiaicho@example.test", "soumu@example.test"):
        identity.email = who
        csrf = _extract_csrf(client.get(_url()).text)
        client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    csrf = _extract_csrf(client.get(_url()).text)  # いまは soumu
    assert client.post(
        f"/s/{FILE_ID}/revoke?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf}
    ).status_code == 200
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == ["組合長"]


def test_one_screen_costs_one_trip_to_the_store(env):
    """署名ページと書類本体で、同じものを2回取りに行かない。

    実測で、画面1枚のために Drive へ4往復していた（fetch 1.1秒・permissions.list 0.3秒）。
    体感の重さはここで、描画側ではなかった。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"

    client.get(_url())
    client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}")

    assert client.store.fetches == 1


def test_the_document_is_not_fetched_for_someone_who_cannot_have_it(env):
    """断る相手のために書類を落とさない。取ってから断ると、その分だけ待たされる。"""
    client, identity, _ = env
    url = f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}"

    assert client.get(url).status_code == 401  # 未ログイン
    identity.email = "yoso@example.test"
    assert client.get(url).status_code == 403  # 共有されていない
    assert client.store.fetches == 0


def test_signing_never_builds_on_a_remembered_copy(env, dev_cert):
    """署名は必ず最新を土台にする。古い版に押すと、あいだの人の署名を落とす。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)  # ここで手元に覚える

    # 別の経路（別インスタンスの署名など）で、その間に担当欄が埋まる
    key, cert = dev_cert
    signed = io.BytesIO()
    sign_field(
        io.BytesIO((store_dir / f"{FILE_ID}.pdf").read_bytes()),
        signed,
        field_name="担当",
        signer=load_signer(key, cert),
        tsa_url=None,
        signer_name="soumu@example.test",
    )
    (store_dir / f"{FILE_ID}.signed.pdf").write_bytes(signed.getvalue())

    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert sorted(list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True)) == sorted(
        ["組合長", "担当"]
    )


def test_signing_does_not_download_what_it_already_has(env):
    """画面を見てそのまま押したとき、書類を取りに行くのは1回だけ。

    「最新である」ことは版番号を聞けば分かる（数百バイト）。同じものを
    もう一度丸ごと落とす（1MB・1秒前後）必要はない。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    csrf = _extract_csrf(client.get(_url()).text)

    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert client.store.fetches == 1


def test_the_record_is_still_sent_when_the_answer_comes_first(fields_pdf: Path, dev_cert, tmp_path: Path):
    """記録メールは画面を返したあとに送る。「あとで」にしたせいで送られない、を防ぐ。"""
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    sent = []

    class RecordingNotifier:
        def notify(self, notice):
            sent.append(notice)

    key, cert = dev_cert
    identity = FakeIdentityProvider("kumiaicho@example.test")
    app = create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory({"kumiaicho@example.test": SignerEntry(role="組合長")}),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
        notifier=RecordingNotifier(),
    )
    client = TestClient(app)
    csrf = _extract_csrf(client.get(_url()).text)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert [notice.signer_email for notice in sent] == ["kumiaicho@example.test"]


def test_a_signature_made_elsewhere_shows_up_on_the_next_screen(
    fields_pdf: Path, dev_cert, tmp_path: Path, monkeypatch
):
    """手元の写しは長く持つが、使う前に版番号で確かめるので古い状態は見せない。

    確かめたばかりの数秒はそのまま使う（画面1枚ぶんの連続した要求をまとめるため）。
    ここではその窓を0にして、確かめる側だけを見る。
    """
    from drive_qr_sign import web

    monkeypatch.setattr(web, "VERIFIED_TTL", 0)

    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    key, cert = dev_cert
    identity = FakeIdentityProvider("kanji@example.test")  # 押印枠を持たない人
    app = web.create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory({"kanji@example.test": None}),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    client = TestClient(app)
    assert "組合長" in _unsigned_boxes(client.get(_url()).text)

    # 別の経路（別インスタンスなど）で組合長が押される
    signed = io.BytesIO()
    sign_field(
        io.BytesIO((store_dir / f"{FILE_ID}.pdf").read_bytes()),
        signed,
        field_name="組合長",
        signer=load_signer(key, cert),
        tsa_url=None,
        signer_name="kumiaicho@example.test",
    )
    (store_dir / f"{FILE_ID}.signed.pdf").write_bytes(signed.getvalue())

    assert "組合長" not in _unsigned_boxes(client.get(_url()).text)


def test_the_document_links_to_the_original_in_drive(fields_pdf: Path, dev_cert, tmp_path: Path):
    """原本を開く先は Drive。版履歴もコメントもそちらにあり、共有もそこで決まっている。"""
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    class DriveLike(LocalDocumentStore):
        def web_url(self, file_id: str) -> str:
            return f"https://drive.google.com/file/d/{file_id}/view"

    key, cert = dev_cert
    app = create_app(
        document_store=DriveLike(store_dir),
        signer_directory=SignerDirectory({"kumiaicho@example.test": SignerEntry(role="組合長")}),
        identity_provider=FakeIdentityProvider("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    body = TestClient(app).get(_url()).text
    assert f"https://drive.google.com/file/d/{FILE_ID}/view" in body
    # 見出しは置かない（本文中の "書類の中身" は CSS のコメントにも出るので、タグで見る）
    assert "<h2" not in body


def test_without_drive_the_app_still_offers_the_pdf(env):
    """Drive を使わない導入先では、アプリが配る PDF への導線が残る。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    body = client.get(_url()).text
    assert "PDF を開く" in body
    assert "drive.google.com" not in body


def test_the_signer_can_pick_which_seal_to_press(env):
    """押される絵をタップすると候補が並び、選んだものが押される。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    body = client.get(_url()).text

    # アイコンを持たない開発用の身元確認なので、候補は「自動生成」だけ＋アップロード
    assert 'name="seal_choice" value="generated"' in body
    assert 'type="file" name="seal_image"' in body
    assert "/seal/preview.png?choice=generated" in body


def test_the_preview_shows_the_chosen_kind(env):
    """候補ごとの絵が引けること（選ぶ画面に並べるため）。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    generated = client.get("/seal/preview.png?choice=generated")
    assert generated.status_code == 200
    assert generated.content.startswith(PNG_MAGIC)


def test_choosing_the_generated_seal_ignores_the_registered_image(fields_pdf: Path, dev_cert, tmp_path: Path):
    """名簿に画像が指定されていても、自動生成を選べば生成した丸印が押される。"""
    pytest.importorskip("pypdfium2")
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    # 名簿に指定する画像（真っ青の四角）を用意する
    registered = tmp_path / "registered.png"
    Image.new("RGB", (200, 200), (0, 0, 255)).save(registered)

    key, cert = dev_cert
    identity = FakeIdentityProvider("kumiaicho@example.test")
    app = create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory(
            {"kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本", seal_image=registered)}
        ),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    client = TestClient(app)
    body = client.get(_url()).text
    assert 'value="registered"' in body  # 名簿の印影も候補に並ぶ

    chosen = Image.open(io.BytesIO(client.get("/seal/preview.png?choice=generated").content)).convert("RGB")
    pixels = list(chosen.getdata())
    # 生成した丸印は朱色。名簿の青い画像は選ばれていない
    assert any(r > 150 and b < 100 for r, g, b in pixels)
    assert not any(b > 150 and r < 100 for r, g, b in pixels)


def test_the_account_icon_appears_as_a_choice_when_there_is_one(fields_pdf: Path, dev_cert, tmp_path: Path):
    """アイコンを持っている人には、その候補が並ぶ（持っていない人には出さない）。"""
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    class WithPicture(FakeIdentityProvider):
        def picture_url(self, request):
            return "https://lh3.googleusercontent.com/a/xyz"

    key, cert = dev_cert
    app = create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory({"kumiaicho@example.test": SignerEntry(role="組合長")}),
        identity_provider=WithPicture("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    body = TestClient(app).get(_url()).text
    assert 'value="icon"' in body
    assert "アカウントのアイコン" in body


def test_a_signature_that_lands_mid_flight_is_not_overwritten(
    fields_pdf: Path, dev_cert, tmp_path: Path
):
    """署名しているあいだに別の人が押していたら、その版で上書きしない。

    Drive には「この版のときだけ書き換える」条件付き更新が無いので、
    書き戻す直前にもう一度版を確かめる。⚠隙間が完全に消えるわけではない
    （鍵と `--max-instances=1` と併せて初めて塞がる）。
    """
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    key, cert = dev_cert

    class RacingStore(LocalDocumentStore):
        """署名しているあいだに、別の人の署名が入ってくる倉庫。

        割り込みは**土台を読んだ後・書き戻す前**に起こす。そこが塞ぎたい隙間で、
        読む前に割り込まれた場合は、新しい土台の上で署名し直せばよいだけ。
        """

        def __init__(self, root):
            super().__init__(root)
            self.hash_calls = 0

        def content_hash(self, file_id: str):
            self.hash_calls += 1
            if self.hash_calls == 2:  # 書き戻す直前の確認
                signed = io.BytesIO()
                sign_field(
                    io.BytesIO(super().fetch(file_id)),
                    signed,
                    field_name="担当",
                    signer=load_signer(key, cert),
                    tsa_url=None,
                    signer_name="soumu@example.test",
                )
                super().store_signed(file_id, signed.getvalue())
            return super().content_hash(file_id)

    store = RacingStore(store_dir)
    app = create_app(
        document_store=store,
        signer_directory=SignerDirectory({"kumiaicho@example.test": SignerEntry(role="組合長")}),
        identity_provider=FakeIdentityProvider("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    client = TestClient(app)
    csrf = _extract_csrf(client.get(_url()).text)

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    assert response.status_code == 409
    assert "もう一度押してください" in response.text
    # 割り込んだ側の署名は残っている（消されていない）
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == ["担当"]


def test_a_document_without_your_seal_box_is_not_called_signed(sample_pdf: Path, dev_cert, tmp_path: Path):
    """押印枠が無い書類を「署名済み」と言わない。

    Typst 以外で作った書類には押印枠が無いことがある。名簿に役職があっても、
    その書類に枠が無ければ、押す場所が無いだけ。確認の記録は残せる。
    """
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    # 押印枠を注入していない、素の PDF（Word などから出した書類の代役）
    (store_dir / f"{FILE_ID}.pdf").write_bytes(sample_pdf.read_bytes())

    key, cert = dev_cert
    app = create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory({"kumiaicho@example.test": SignerEntry(role="組合長")}),
        identity_provider=FakeIdentityProvider("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    client = TestClient(app)
    body = client.get(_url()).text

    assert "署名済み" not in body
    assert "確認したことを記録する" in body  # 紙面に出ない署名なら残せる

    csrf = _extract_csrf(body)
    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 200
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == [
        silent_field_name("kumiaicho@example.test")
    ]


def test_who_has_signed_is_visible_including_the_invisible_ones(env):
    """紙面に出ない署名も、画面には出す。

    紙を見ても不可視署名は分からない。回覧が回りきったかを判断するのは人なので、
    「誰が確認したか」が画面で見えないと、この機能は使えない。
    """
    client, identity, _ = env

    identity.email = "kumiaicho@example.test"  # 押印枠を持つ人
    client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": _extract_csrf(client.get(_url()).text)},
    )
    identity.email = "kanji@example.test"  # 押印枠を持たない人（不可視署名）
    client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": _extract_csrf(client.get(_url()).text)},
    )

    # 3人目（まだ押していない人）から見て、2人とも見えること
    identity.email = "soumu@example.test"
    body = client.get(_url()).text
    assert "2人が署名" in body  # ラベルは数だけ
    assert "kumiaicho@example.test" in body  # 押すと出る一覧に、両方入っている
    assert "kanji@example.test" in body
