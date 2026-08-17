"""署名ページ。

Google ログインと Drive は Protocol 越しなので、ここでは偽物を差し込んで検証する。
TSA には出ない（tsa_url=None）。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from drive_qr_sign.documents import LocalDocumentStore
from drive_qr_sign.identity import RoleDirectory
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
        role_directory=RoleDirectory({"Soumu@example.test": "担当", "kumiaicho@example.test": "組合長"}),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,  # テストはネットワークに出ない
    )
    return TestClient(app), identity, store_dir


def _url(file_id: str = FILE_ID, secret: bytes = SECRET) -> str:
    return f"/s/{file_id}?m={make_mac(secret, file_id)}"


def test_healthz(env):
    client, _, _ = env
    assert client.get("/healthz").json() == {"status": "ok"}


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


def test_person_without_a_field_cannot_sign(env):
    client, identity, _ = env
    identity.email = "yoso@example.test"
    body = client.get(_url()).text
    assert "<button" not in body
    assert "割り当てられた署名欄が、この書類にはありません" in body


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
