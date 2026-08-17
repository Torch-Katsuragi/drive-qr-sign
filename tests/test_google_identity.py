"""Google ログイン（OIDC）。

Google には出ない。トークン交換と ID トークン検証を差し替えて、
アプリ側の判断（何を信じて何を弾くか）だけを見る。
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from drive_qr_sign.google_identity import (
    SESSION_COOKIE,
    ClientSecrets,
    GoogleIdentityProvider,
)

CLIENT = ClientSecrets("client-id.apps.googleusercontent.com", "client-secret")
REDIRECT = "http://localhost:8765/oauth2/callback"


def make_provider(claims: dict, **kwargs) -> GoogleIdentityProvider:
    """指定のクレームを返す Google の代わりを差し込んだ provider。"""
    captured: dict = {}

    def exchange(*, code, code_verifier, redirect_uri, client):
        captured["code"] = code
        captured["verifier"] = code_verifier
        return {"id_token": "dummy"}

    def verify(token, client_id):
        # nonce は認可リクエストで送ったものが返る、という Google のふるまいを再現する
        return {**claims, "nonce": claims.get("nonce", captured.get("nonce"))}

    provider = GoogleIdentityProvider(
        CLIENT,
        redirect_uri=REDIRECT,
        session_secret="test-session-secret",
        cookie_secure=False,
        exchange_code=exchange,
        verify_id_token=verify,
        **kwargs,
    )
    provider._captured = captured  # テストから覗く用
    return provider


def client_for(provider: GoogleIdentityProvider) -> TestClient:
    app = FastAPI()
    app.include_router(provider.router)
    return TestClient(app, follow_redirects=False)


def start_login(client: TestClient, provider: GoogleIdentityProvider, next_url: str = "/s/abc"):
    """/login を叩き、Google へ飛ばされる URL のクエリを返す。"""
    response = client.get("/login", params={"next": next_url})
    query = parse_qs(urlparse(response.headers["location"]).query)
    provider._captured["nonce"] = query["nonce"][0]
    return response, query


def test_login_redirects_to_google_with_pkce_and_nonce():
    provider = make_provider({})
    client = client_for(provider)
    response, query = start_login(client, provider)

    assert response.status_code == 303
    assert response.headers["location"].startswith("https://accounts.google.com/")
    assert query["client_id"] == [CLIENT.client_id]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] and query["nonce"] and query["state"]


def test_only_openid_and_email_are_requested():
    """Drive スコープを要求しないことが、この設計の要（docs/DESIGN.md）。"""
    provider = make_provider({})
    _, query = start_login(client_for(provider), provider)
    assert query["scope"] == ["openid email"]


def test_profile_scope_is_opt_in():
    provider = make_provider({}, scopes=("openid", "email", "profile"))
    _, query = start_login(client_for(provider), provider)
    assert query["scope"] == ["openid email profile"]


def test_successful_login_sets_the_session():
    provider = make_provider({"email": "signer@example.test", "email_verified": True})
    client = client_for(provider)
    _, query = start_login(client, provider, next_url="/s/abc?m=xyz")

    response = client.get("/oauth2/callback", params={"code": "auth-code", "state": query["state"][0]})

    assert response.status_code == 303
    assert response.headers["location"] == "/s/abc?m=xyz"  # 元の署名ページへ戻る
    assert SESSION_COOKIE in response.cookies
    assert provider._captured["code"] == "auth-code"


def test_unverified_email_is_refused():
    """email_verified が false のアカウントを本人性の根拠にしない。"""
    provider = make_provider({"email": "signer@example.test", "email_verified": False})
    client = client_for(provider)
    _, query = start_login(client, provider)

    response = client.get("/oauth2/callback", params={"code": "c", "state": query["state"][0]})
    assert response.status_code == 403


def test_mismatched_nonce_is_refused():
    """他所で取られた ID トークンを持ち込まれても通さない。"""
    provider = make_provider(
        {"email": "signer@example.test", "email_verified": True, "nonce": "別のログインのnonce"}
    )
    client = client_for(provider)
    _, query = start_login(client, provider)

    response = client.get("/oauth2/callback", params={"code": "c", "state": query["state"][0]})
    assert response.status_code == 403


def test_state_must_match_the_cookie():
    """勝手に組み立てた認可レスポンスを投げ込まれても通さない。"""
    provider = make_provider({"email": "signer@example.test", "email_verified": True})
    client = client_for(provider)
    _, query = start_login(client, provider)
    client.cookies.clear()  # 別のブラウザから叩かれた状況

    response = client.get("/oauth2/callback", params={"code": "c", "state": query["state"][0]})
    assert response.status_code == 403


def test_external_next_url_is_ignored():
    """戻り先に外部 URL を書かれても、自分のサイト内に丸める。"""
    provider = make_provider({"email": "signer@example.test", "email_verified": True})
    client = client_for(provider)
    _, query = start_login(client, provider, next_url="https://phishing.example/steal")

    response = client.get("/oauth2/callback", params={"code": "c", "state": query["state"][0]})
    assert response.headers["location"] == "/"


def test_session_survives_and_carries_the_picture():
    provider = make_provider(
        {
            "email": "signer@example.test",
            "email_verified": True,
            "picture": "https://lh3.googleusercontent.com/a/xyz",
        }
    )
    client = client_for(provider)
    _, query = start_login(client, provider)
    client.get("/oauth2/callback", params={"code": "c", "state": query["state"][0]})

    app = FastAPI()
    app.include_router(provider.router)

    @app.get("/whoami")
    def whoami(request: Request):
        return {"email": provider.verified_email(request), "picture": provider.picture_url(request)}

    probe = TestClient(app)
    probe.cookies.set(SESSION_COOKIE, client.cookies[SESSION_COOKIE])
    body = probe.get("/whoami").json()
    assert body["email"] == "signer@example.test"
    assert body["picture"].startswith("https://lh3.googleusercontent.com/")


def test_tampered_session_cookie_is_ignored():
    provider = make_provider({})
    app = FastAPI()

    @app.get("/whoami")
    def whoami(request: Request):
        return {"email": provider.verified_email(request)}

    probe = TestClient(app)
    probe.cookies.set(SESSION_COOKIE, "eyJlbWFpbCI6ICJib3NzQGV4YW1wbGUudGVzdCJ9.fake.signature")
    assert probe.get("/whoami").json() == {"email": None}


def test_client_secrets_are_read_from_the_console_json(tmp_path):
    path = tmp_path / "client.json"
    path.write_text(
        '{"web": {"client_id": "abc.apps.googleusercontent.com", "client_secret": "s3cret",'
        ' "redirect_uris": ["http://localhost:8765/oauth2/callback"]}}',
        encoding="utf-8",
    )
    secrets = ClientSecrets.load(path)
    assert secrets.client_id == "abc.apps.googleusercontent.com"
    assert secrets.client_secret == "s3cret"


def test_client_secrets_rejects_a_file_without_credentials(tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text('{"note": "これは違うファイル"}', encoding="utf-8")
    with pytest.raises(ValueError):
        ClientSecrets.load(path)
