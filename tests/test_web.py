"""書類の一覧と、そこから呼ぶ署名・取り消し。

Google ログインと Drive は Protocol 越しなので、ここでは偽物を差し込んで検証する。
TSA には出ない（tsa_url=None）。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import io
import re

from PIL import Image

from drive_qr_sign.documents import LocalDocumentStore, SharedDocument, field_mark
from drive_qr_sign.identity import SignerDirectory, SignerEntry, silent_field_name
from drive_qr_sign.qr import make_mac
from drive_qr_sign.signing import list_signature_fields, load_signer, sign_field
from drive_qr_sign.web import STATIC_PREFIX, _csrf_token, create_app

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

    def shared_with(self, email: str):
        return self.inner.shared_with(email)


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
    """紙に刷った QR の URL（書類ごとの署名ページがあった頃のもの）。"""
    return f"/s/{file_id}?m={make_mac(secret, file_id)}"


def _csrf(email: str, file_id: str = FILE_ID) -> str:
    """一覧の行に埋めてあるのと同じ値。画面から拾わずに作る。"""
    return _csrf_token(SECRET, file_id, email)


def _detail(client, file_id: str = FILE_ID, mac: str | None = None):
    """一覧で書類を開いたときに読む、押した人と取り消せるかどうか。"""
    return client.get(f"/s/{file_id}/detail?m={mac or make_mac(SECRET, file_id)}")


def _signed_rows(body: str) -> list[str]:
    """署名済みの一覧に並んだ書類の file id。"""
    return re.findall(r'data-revoke="/s/([^/"]+)/revoke', body)


def test_status(env):
    """`/healthz` ではない。Cloud Run のフロントエンドがそのパスを横取りするため。"""
    client, _, _ = env
    assert client.get("/status").json() == {"status": "ok"}


def test_forged_qr_is_refused(env):
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    assert _detail(client, mac="deadbeef").status_code == 403
    # 別の鍵で作られた MAC も通らない
    assert _detail(client, mac=make_mac(b"attacker", FILE_ID)).status_code == 403


def test_unknown_document(env):
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    assert _detail(client, "no-such-doc").status_code == 404


def test_anonymous_visitor_is_asked_to_log_in(env):
    client, _, _ = env
    body = client.get("/").text
    assert "ログイン" in body
    assert "<button" not in body  # 押せるボタンは出ない


def test_signer_sees_their_own_field(env):
    client, identity, _ = env
    identity.email = "soumu@example.test"  # 対応表は大文字小文字を区別しない
    body = client.get("/").text
    assert "担当欄" in body


def test_stranger_cannot_sign(env):
    """見る権限が無い人には中身も押した人も見せない。

    本番ではこの判定が Drive の共有設定になる（開発用の既定は名簿で代用）。
    """
    client, identity, _ = env
    identity.email = "yoso@example.test"
    assert _detail(client).status_code == 403


def test_stranger_post_is_refused(env):
    client, identity, store_dir = env
    identity.email = "yoso@example.test"
    # csrf は自分のメールで計算できてしまうので、閲覧権の判定が最後の砦になる
    csrf = _csrf("yoso@example.test")

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 403
    assert not (store_dir / f"{FILE_ID}.signed.pdf").exists()


def test_person_without_a_field_signs_invisibly(env):
    """押印枠を持たない人はサイレント署名。押印枠は空のまま、紙面は変わらない。"""
    client, identity, store_dir = env
    identity.email = "kanji@example.test"

    body = client.get("/").text
    assert "確認の記録" in body

    csrf = _csrf(identity.email)
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

    csrf = _csrf(identity.email)
    assert client.post(url, data={"csrf": csrf}).status_code == 200
    assert _signed_rows(client.get("/?view=signed").text) == [FILE_ID]
    assert client.post(url, data={"csrf": csrf}).status_code == 409


def test_seal_lands_in_the_box(env, fields_pdf: Path):
    """押印枠に朱色の印影が乗ること。pyHanko 既定の紫のアートが出ていないことも見る。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _csrf(identity.email)
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

    body = client.get("/").text
    assert 'class="viewer"' in body
    assert f"{STATIC_PREFIX}/inbox.js" in body

    response = client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}")
    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"


def test_pdfjs_is_served_from_this_app(env):
    """外部 CDN に依存しない。ネットワークを絞った導入先でも動くこと。"""
    client, _, _ = env
    assert client.get(f"{STATIC_PREFIX}/pdfjs/pdf.min.mjs").status_code == 200
    assert client.get(f"{STATIC_PREFIX}/pdfjs/pdf.worker.min.mjs").status_code == 200


def test_document_is_not_shown_without_login(env):
    """QR は紙に刷られて出回る。URL を知っているだけでは中身を見せない。"""
    client, _, _ = env
    assert client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}").status_code == 401
    assert 'class="viewer"' not in client.get("/").text


def test_document_is_not_shown_to_strangers(env):
    client, identity, _ = env
    identity.email = "yoso@example.test"
    assert client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}").status_code == 403


def _blue_png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGBA", (200, 200), (20, 90, 220, 255)).save(buffer, format="PNG")
    return buffer.getvalue()


def test_uploaded_image_is_used_for_that_signature(env):
    """その場でアップロードした画像で押せること。保管はしない。"""
    pdfium = pytest.importorskip("pypdfium2")
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"

    csrf = _csrf(identity.email)
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
    csrf = _csrf(identity.email)

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
    csrf = _csrf(identity.email)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    def render(path) -> bytes:
        doc = pdfium.PdfDocument(str(path))
        doc.init_forms()
        return doc[0].render(scale=1, draw_annots=True, may_draw_forms=True).to_pil().tobytes()

    assert render(store_dir / f"{FILE_ID}.signed.pdf") == render(fields_pdf)





def test_signing_fills_only_that_field(env):
    client, identity, store_dir = env
    identity.email = "soumu@example.test"

    csrf = _csrf(identity.email)
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
        csrf = _csrf(identity.email)
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

    csrf = _csrf(identity.email)
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
    csrf = _csrf(identity.email)
    identity.email = "soumu@example.test"  # 途中で別人に入れ替わっても組合長欄は押せない

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 403  # csrf が本人のものではない








def test_signer_can_take_back_their_own_signature(env):
    """押し間違えたときに取り消せること。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    csrf = _csrf(identity.email)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == ["組合長"]

    assert _detail(client).json()["revocable"] is True

    response = client.post(f"/s/{FILE_ID}/revoke?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})
    assert response.status_code == 200
    signed = store_dir / f"{FILE_ID}.signed.pdf"
    assert list_signature_fields(signed, filled=True) == []
    assert list_signature_fields(signed, filled=False) == ["組合長", "参事", "担当"]


def test_the_signing_account_is_always_on_screen(env):
    """誰として押すのかが、押す前に必ず見えていること。取り違えは後から直せない。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    body = client.get("/").text
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
    assert "/account/icon.png" not in client.get("/").text
    assert client.get("/account/icon.png").status_code == 401


def test_signing_comes_back_to_the_list(env):
    """押した書類は署名待ちから外れ、署名済みに移る。取り消しもそこからできる。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"

    response = client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": _csrf(identity.email)},
        follow_redirects=False,
    )

    assert response.status_code == 303  # JS が動かない端末は一覧へ戻る
    assert response.headers["location"] == "/"
    assert "data-action" not in client.get("/").text
    signed = client.get("/?view=signed").text
    assert _signed_rows(signed) == [FILE_ID]
    assert "組合長欄" in signed


def test_the_old_qr_leads_to_the_list(env):
    """書類ごとの署名ページは廃止した。刷ってしまった QR は一覧へ案内する。"""
    client, _, _ = env
    response = client.get(_url(), follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/"


def test_the_revoke_button_stays_greyed_out_when_locked(env):
    """取り消せないときもボタンは残す。消すと「取り消せる場所がある」ごと見えなくなる。"""
    client, identity, _ = env
    for who in ("kumiaicho@example.test", "soumu@example.test"):
        identity.email = who
        csrf = _csrf(identity.email)
        client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    identity.email = "kumiaicho@example.test"
    # 署名済みの一覧には残り、開くと「取り消せない」と分かる（ボタンの灰色は inbox.js）
    assert FILE_ID in _signed_rows(client.get("/?view=signed").text)
    assert _detail(client).json()["revocable"] is False


def test_cannot_take_back_once_someone_signed_after_you(env):
    """後の人の署名は自分の署名を含めて覆っている。抜くと相手のものが壊れる。"""
    client, identity, store_dir = env

    identity.email = "kumiaicho@example.test"
    first = _csrf(identity.email)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": first})

    identity.email = "soumu@example.test"
    second = _csrf(identity.email)
    client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": second})

    identity.email = "kumiaicho@example.test"
    assert _detail(client).json()["revocable"] is False
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
        csrf = _csrf(identity.email)
        client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    csrf = _csrf(identity.email)  # いまは soumu
    assert client.post(
        f"/s/{FILE_ID}/revoke?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf}
    ).status_code == 200
    assert list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True) == ["組合長"]


def test_opening_a_document_costs_one_trip_to_the_store(env):
    """開いたときの押した人の一覧と書類本体で、同じものを2回取りに行かない。

    実測で、画面1枚のために Drive へ4往復していた（fetch 1.1秒・permissions.list 0.3秒）。
    体感の重さはここで、描画側ではなかった。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"

    _detail(client)
    client.get(f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}")

    assert client.store.fetches == 1


def test_the_document_is_not_fetched_for_someone_who_cannot_have_it(env):
    """断る相手のために書類を落とさない。取ってから断ると、その分だけ待たされる。"""
    client, identity, _ = env
    url = f"/s/{FILE_ID}/document.pdf?m={make_mac(SECRET, FILE_ID)}"

    assert client.get(url).status_code == 401  # 未ログイン
    assert _detail(client).status_code == 401
    identity.email = "yoso@example.test"
    assert client.get(url).status_code == 403  # 共有されていない
    assert _detail(client).status_code == 403
    assert client.store.fetches == 0


def test_signing_never_builds_on_a_remembered_copy(env, dev_cert):
    """署名は必ず最新を土台にする。古い版に押すと、あいだの人の署名を落とす。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    _detail(client)  # ここで手元に覚える
    csrf = _csrf(identity.email)

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
    """開いて見てそのまま押したとき、書類を取りに行くのは1回だけ。

    「最新である」ことは版番号を聞けば分かる（数百バイト）。同じものを
    もう一度丸ごと落とす（1MB・1秒前後）必要はない。
    """
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    _detail(client)
    csrf = _csrf(identity.email)

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
    csrf = _csrf(identity.email)
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
    assert "組合長" in _detail(client).json()["empty_fields"]

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

    assert "組合長" not in _detail(client).json()["empty_fields"]


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
    detail = _detail(TestClient(app)).json()
    assert detail["document_url"] == f"https://drive.google.com/file/d/{FILE_ID}/view"


def test_without_drive_the_app_still_offers_the_pdf(env):
    """Drive を使わない導入先では、アプリが配る PDF への導線が残る（inbox.js が出す）。"""
    client, identity, _ = env
    identity.email = "kumiaicho@example.test"
    assert _detail(client).json()["document_url"] is None
    assert f"/s/{FILE_ID}/document.pdf?m=" in client.get("/").text


def test_the_signer_can_pick_which_seal_to_press(env):
    """押される絵をタップすると候補が並び、選んだものが押される。"""
    client, identity, store_dir = env
    identity.email = "kumiaicho@example.test"
    body = client.get("/").text

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
    body = client.get("/").text
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
    body = TestClient(app).get("/").text
    assert 'value="icon"' in body
    assert "アカウントのアイコン" in body


def test_the_generated_seal_is_the_default_even_with_an_icon(
    fields_pdf: Path, dev_cert, tmp_path: Path
):
    """アイコンを持っている人でも、既定は生成した丸印。

    押印枠に入るのは印であって顔写真ではない。何も選ばなかった人の紙面が
    アカウントの設定次第で変わらないよう、既定は名簿から作る。
    """
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    (store_dir / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())

    class WithPicture(FakeIdentityProvider):
        def picture_url(self, request):
            return "https://lh3.googleusercontent.com/a/xyz"

    key, cert = dev_cert
    app = create_app(
        document_store=LocalDocumentStore(store_dir),
        signer_directory=SignerDirectory(
            {"kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本")}
        ),
        identity_provider=WithPicture("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    body = TestClient(app).get("/").text
    # 選択肢は並び順がそのまま既定。生成がアイコンより先に来る
    assert body.index('value="generated"') < body.index('value="icon"')

    # 何も選ばずに押したときの絵が、生成を選んだときの絵と同じ
    client = TestClient(app)
    default = client.get("/seal/preview.png").content
    generated = client.get("/seal/preview.png", params={"choice": "generated"}).content
    assert default == generated


def test_a_signature_that_lands_mid_flight_is_not_overwritten(
    fields_pdf: Path, dev_cert, tmp_path: Path
):
    """署名しているあいだに別の人が押していたら、その版で上書きせず、取り直して押し直す。

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
    csrf = _csrf("kumiaicho@example.test")

    response = client.post(f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf})

    # 重なったら、割り込んだ版を取り直してその上に押し直す（押した人にやり直させない）
    assert response.status_code == 200
    # 割り込んだ側の署名は残っていて（消されていない）、自分の署名も入っている
    assert sorted(list_signature_fields(store_dir / f"{FILE_ID}.signed.pdf", filled=True)) == ["担当", "組合長"]


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
    body = client.get("/").text

    assert "data-action" in body  # 署名待ちに並ぶ
    assert "確認の記録" in body  # 紙面に出ない署名なら残せる
    assert _signed_rows(client.get("/?view=signed").text) == []

    csrf = _csrf("kumiaicho@example.test")
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
        data={"csrf": _csrf(identity.email)},
    )
    identity.email = "kanji@example.test"  # 押印枠を持たない人（不可視署名）
    client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}",
        data={"csrf": _csrf(identity.email)},
    )

    # 3人目（まだ押していない人）から見て、2人とも見えること
    identity.email = "soumu@example.test"
    signed_by = _detail(client).json()["signed_by"]
    assert signed_by == [
        {"who": "kumiaicho@example.test", "role": "組合長"},
        {"who": "kanji@example.test", "role": None},
    ]


# --- 署名待ちの一覧 ---------------------------------------------------------


@pytest.fixture
def inbox(fields_pdf: Path, sample_pdf: Path, dev_cert, tmp_path: Path):
    """押印枠つきの書類2件と、押印枠の無い書類1件を置いた倉庫。"""
    store_dir = tmp_path / "inbox"
    store_dir.mkdir()
    for name in ("doc-a", "doc-b"):
        (store_dir / f"{name}.pdf").write_bytes(fields_pdf.read_bytes())
    (store_dir / "memo.pdf").write_bytes(sample_pdf.read_bytes())

    key, cert = dev_cert
    identity = FakeIdentityProvider()
    store = CountingStore(LocalDocumentStore(store_dir))
    app = create_app(
        document_store=store,
        signer_directory=SignerDirectory(
            {
                "kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本"),
                "kanji@example.test": None,
            }
        ),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    client = TestClient(app)
    client.store = store
    return client, identity, store_dir


def _inbox_rows(body: str) -> list[tuple[str, str]]:
    """一覧の各行の (署名 POST 先, csrf)。"""
    import re

    return re.findall(r'data-action="([^"]+)"\s+data-csrf="([^"]+)"', body)


def test_the_inbox_asks_visitors_to_log_in(inbox):
    client, _, _ = inbox
    body = client.get("/").text
    assert "ログイン" in body
    assert "data-action" not in body


def test_the_inbox_lists_what_is_waiting_for_you(inbox):
    """押印枠が空いている書類は欄つきで、枠の無い書類は確認の記録として並ぶ。"""
    client, identity, _ = inbox
    identity.email = "kumiaicho@example.test"
    body = client.get("/").text

    rows = _inbox_rows(body)
    assert [action.split("/")[2] for action, _ in rows] == ["doc-a", "doc-b", "memo"]
    assert body.count("組合長欄") == 2
    assert "確認の記録" in body
    # 開いたときに読む先は、行ごとの MAC を持つ
    assert f"/s/doc-a/detail?m={make_mac(SECRET, 'doc-a')}" in body


def test_the_inbox_signs_through_the_same_door_as_the_qr(inbox):
    """一覧から押す。押した書類は署名待ちから消え、署名済みに移る。"""
    client, identity, store_dir = inbox
    identity.email = "kumiaicho@example.test"

    for action, csrf in _inbox_rows(client.get("/").text)[:2]:
        assert client.post(action, data={"csrf": csrf}).status_code == 200

    assert list_signature_fields(store_dir / "doc-a.signed.pdf", filled=True) == ["組合長"]
    assert list_signature_fields(store_dir / "doc-b.signed.pdf", filled=True) == ["組合長"]
    remaining = [action.split("/")[2] for action, _ in _inbox_rows(client.get("/").text)]
    assert remaining == ["memo"]
    assert _signed_rows(client.get("/?view=signed").text) == ["doc-a", "doc-b"]


def test_the_inbox_hides_what_you_already_signed_silently(inbox):
    client, identity, _ = inbox
    identity.email = "kanji@example.test"
    rows = _inbox_rows(client.get("/").text)
    assert len(rows) == 3

    action, csrf = rows[0]
    assert client.post(action, data={"csrf": csrf}).status_code == 200
    assert len(_inbox_rows(client.get("/").text)) == 2


def test_the_inbox_does_not_download_unchanged_documents_again(inbox):
    """一覧のたびに全件落とすと件数ぶん待たせる。中身が同じなら前の判定を使う。"""
    client, identity, _ = inbox
    identity.email = "kumiaicho@example.test"

    client.get("/")
    first = client.store.fetches
    assert first == 3
    client.get("/")
    assert client.store.fetches == first


def test_opening_a_document_from_the_inbox_does_not_download_it_again(inbox):
    """一覧のために落とした中身は、開いて読むときにも使う。"""
    client, identity, _ = inbox
    identity.email = "kumiaicho@example.test"

    client.get("/")
    before = client.store.fetches
    response = client.get(f"/s/doc-a/document.pdf?m={make_mac(SECRET, 'doc-a')}")
    assert response.status_code == 200
    assert client.store.fetches == before


def test_without_a_listing_store_the_inbox_says_so(fields_pdf: Path, dev_cert, tmp_path: Path):
    """一覧を出せない倉庫でも、画面は落ちずにそう伝える。"""

    class NoListing:
        def __init__(self, inner):
            self.inner = inner

        def fetch(self, file_id):
            return self.inner.fetch(file_id)

        def store_signed(self, file_id, pdf):
            return self.inner.store_signed(file_id, pdf)

    (tmp_path / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())
    key, cert = dev_cert
    app = create_app(
        document_store=NoListing(LocalDocumentStore(tmp_path)),
        signer_directory=SignerDirectory({"kumiaicho@example.test": "組合長"}),
        identity_provider=FakeIdentityProvider("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    body = TestClient(app).get("/").text
    assert "一覧を出せません" in body


def test_revoking_from_the_signed_list_puts_it_back(inbox):
    """署名済みの一覧から取り消すと、署名待ちに戻る。"""
    client, identity, store_dir = inbox
    identity.email = "kumiaicho@example.test"
    action, csrf = _inbox_rows(client.get("/").text)[0]
    client.post(action, data={"csrf": csrf})

    response = client.post(
        f"/s/doc-a/revoke?m={make_mac(SECRET, 'doc-a')}",
        data={"csrf": _csrf(identity.email, "doc-a")},
        headers={"X-Requested-With": "inbox"},
    )
    assert response.json() == {"status": "revoked"}
    assert list_signature_fields(store_dir / "doc-a.signed.pdf", filled=True) == []
    assert "doc-a" in [a.split("/")[2] for a, _ in _inbox_rows(client.get("/").text)]
    assert _signed_rows(client.get("/?view=signed").text) == []


class MarkingStore(CountingStore):
    """埋まっている欄を書き留められる倉庫（Drive の appProperties の代わり）。"""

    def __init__(self, inner):
        super().__init__(inner)
        self.marks: dict[str, tuple[str, frozenset[str]]] = {}
        self.fetched: list[str] = []

    def fetch(self, file_id: str) -> bytes:
        self.fetched.append(file_id)
        return super().fetch(file_id)

    def record_filled(self, file_id: str, content_hash: str, filled: list[str]) -> None:
        self.marks[file_id] = (content_hash, frozenset(field_mark(name) for name in filled))

    def shared_with(self, email: str):
        found = []
        for shared in self.inner.shared_with(email):
            recorded = self.marks.get(shared.file_id)
            filled = recorded[1] if recorded and recorded[0] == shared.content_hash else None
            found.append(SharedDocument(shared.file_id, shared.name, shared.content_hash, filled))
        return found


def _marking_app(store, dev_cert):
    key, cert = dev_cert
    identity = FakeIdentityProvider("kumiaicho@example.test")
    app = create_app(
        document_store=store,
        signer_directory=SignerDirectory(
            {
                "kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本"),
                "kanji@example.test": None,
            }
        ),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
    )
    return TestClient(app), identity


def test_signed_documents_are_not_downloaded_to_list_them(
    fields_pdf: Path, sample_pdf: Path, dev_cert, tmp_path: Path
):
    """署名済みの書類は溜まっていく。書き留めた欄を見て、中身を落とさずに署名済みへ回す。

    覚え書き（プロセスの中）が消えた後、つまり Cloud Run が立ち上がり直した後でも
    落とさないことを見る。
    """
    for name in ("doc-a", "doc-b"):
        (tmp_path / f"{name}.pdf").write_bytes(fields_pdf.read_bytes())
    store = MarkingStore(LocalDocumentStore(tmp_path))

    client, identity = _marking_app(store, dev_cert)
    client.post(f"/s/doc-a/sign?m={make_mac(SECRET, 'doc-a')}", data={"csrf": _csrf(identity.email, "doc-a")})

    # 立ち上がり直した（覚え書きが空の）アプリで一覧を出す
    fresh, _ = _marking_app(store, dev_cert)
    store.fetched.clear()
    body = fresh.get("/?view=signed").text

    assert _signed_rows(body) == ["doc-a"]
    assert store.fetched == ["doc-b"]  # 落としたのは、まだ押していない書類だけ


def test_listing_writes_down_what_it_had_to_check(fields_pdf: Path, dev_cert, tmp_path: Path):
    """書き留めが無い書類は、確かめたついでに書き留める。次からは落とさない。"""
    (tmp_path / "doc-a.pdf").write_bytes(fields_pdf.read_bytes())
    store = MarkingStore(LocalDocumentStore(tmp_path))
    client, _ = _marking_app(store, dev_cert)

    client.get("/")

    content_hash, filled = store.marks["doc-a"]
    assert content_hash == store.content_hash("doc-a")
    assert filled == frozenset()  # まだ誰も押していない


def test_a_stale_note_is_not_trusted(fields_pdf: Path, dev_cert, tmp_path: Path):
    """書き留めた後にアプリの外で中身が変わったら、その書き留めは使わない。"""
    (tmp_path / "doc-a.pdf").write_bytes(fields_pdf.read_bytes())
    store = MarkingStore(LocalDocumentStore(tmp_path))
    # 「組合長欄は埋まっている」と書き留めてあるが、それは別の中身についてのもの
    store.marks["doc-a"] = ("some-older-content", frozenset({field_mark("組合長")}))
    client, _ = _marking_app(store, dev_cert)

    assert [a.split("/")[2] for a, _ in _inbox_rows(client.get("/").text)] == ["doc-a"]


