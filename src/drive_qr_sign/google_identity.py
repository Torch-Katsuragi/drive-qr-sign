"""Google アカウントでのログイン（OpenID Connect）。

署名者に求めるのは `openid` と `email` だけ。Drive のスコープは要求しない。
これが崩れると、未審査アプリの警告画面を無料 Gmail の署名者に見せることになり、
導入できる組織が激減する（docs/DESIGN.md）。

`profile` を足すと ID トークンに `picture` が乗り、アカウントのアイコンを印影に使えるようになる。
非センシティブなので警告画面は増えないが、既定では要求しない。使いたい組織だけ `scopes` で足す。

アプリが信じるのは「Google が検証済みだと言っているメールアドレス」だけで、
そこから先（誰が押印枠を持つか）は署名者名簿が決める。
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets as secrets_module
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

logger = logging.getLogger(__name__)

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

BASE_SCOPES = ("openid", "email")
SESSION_COOKIE = "signer"
FLOW_COOKIE = "oauth_flow"
SESSION_MAX_AGE = 12 * 60 * 60  # 半日。回覧1件を押すには十分で、共有端末に残り続けない長さ
FLOW_MAX_AGE = 10 * 60


@dataclass(frozen=True)
class ClientSecrets:
    client_id: str
    client_secret: str

    @staticmethod
    def load(path: Path | str) -> "ClientSecrets":
        """Google Cloud コンソールが吐く JSON をそのまま読む。

        コンソールの「JSON をダウンロード」で落ちるファイルを想定していて、
        中身を人が写し替える必要はない（写し間違いも、どこかに貼り付ける事故も起きない）。
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        section = data.get("web") or data.get("installed") or data
        try:
            return ClientSecrets(section["client_id"], section["client_secret"])
        except KeyError as exc:
            raise ValueError(f"client_id / client_secret が見つからない: {path}") from exc


def _exchange_code(
    *, code: str, code_verifier: str, redirect_uri: str, client: ClientSecrets
) -> dict:
    import requests

    response = requests.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


# 許容する時計のずれ。0 だと、端末の時計が1秒遅れているだけで
# 「Token used too early」でログインできない（実機で踏んだ）
CLOCK_SKEW_SECONDS = 30


def _verify_id_token(token: str, client_id: str) -> dict:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token as google_id_token

    return google_id_token.verify_oauth2_token(
        token,
        google_requests.Request(),
        client_id,
        clock_skew_in_seconds=CLOCK_SKEW_SECONDS,
    )


class GoogleIdentityProvider:
    """OIDC のログイン一式。`router` を app に載せると /login と /oauth2/callback が生える。

    exchange_code と verify_id_token は差し替えられる。テストで Google に出ないため。
    """

    def __init__(
        self,
        client: ClientSecrets,
        *,
        redirect_uri: str,
        session_secret: bytes | str,
        scopes: tuple[str, ...] = BASE_SCOPES,
        cookie_secure: bool = True,
        exchange_code=_exchange_code,
        verify_id_token=_verify_id_token,
    ):
        self.client = client
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.cookie_secure = cookie_secure
        self._exchange_code = exchange_code
        self._verify_id_token = verify_id_token
        self._sessions = URLSafeTimedSerializer(session_secret, salt="signer-session")
        self._flows = URLSafeTimedSerializer(session_secret, salt="oauth-flow")
        self.router = self._build_router()

    # --- アプリから見える面 ------------------------------------------------

    def verified_email(self, request: Request) -> str | None:
        session = self._session(request)
        return session.get("email") if session else None

    def picture_url(self, request: Request) -> str | None:
        """アイコンの URL。`profile` スコープを要求していなければ常に None。"""
        session = self._session(request)
        return session.get("picture") if session else None

    def _session(self, request: Request) -> dict | None:
        raw = request.cookies.get(SESSION_COOKIE)
        if not raw:
            return None
        try:
            return self._sessions.loads(raw, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return None  # 期限切れか改竄。未ログインとして扱う

    # --- ログインの経路 ----------------------------------------------------

    def _build_router(self) -> APIRouter:
        router = APIRouter()

        @router.get("/login")
        def login(request: Request, next: str = "/") -> RedirectResponse:
            verifier = secrets_module.token_urlsafe(64)
            nonce = secrets_module.token_urlsafe(16)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
                .decode("ascii")
                .rstrip("=")
            )
            # 戻り先は自分のサイト内に限る。外部 URL を書かれると踏み台になる
            destination = next if next.startswith("/") and not next.startswith("//") else "/"
            state = self._flows.dumps(
                {"verifier": verifier, "nonce": nonce, "next": destination}
            )

            query = urlencode(
                {
                    "client_id": self.client.client_id,
                    "redirect_uri": self.redirect_uri,
                    "response_type": "code",
                    "scope": " ".join(self.scopes),
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "prompt": "select_account",
                }
            )
            response = RedirectResponse(f"{AUTH_ENDPOINT}?{query}", status_code=303)
            self._set_cookie(response, FLOW_COOKIE, state, FLOW_MAX_AGE)
            return response

        @router.get("/oauth2/callback")
        def callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
            # state はクッキーと突き合わせる。認可レスポンスの差し込みを防ぐ
            if not code or not state or state != request.cookies.get(FLOW_COOKIE):
                raise HTTPException(status_code=403, detail="ログインをやり直してください")
            try:
                flow = self._flows.loads(state, max_age=FLOW_MAX_AGE)
            except BadSignature:
                raise HTTPException(status_code=403, detail="ログインをやり直してください")

            try:
                tokens = self._exchange_code(
                    code=code,
                    code_verifier=flow["verifier"],
                    redirect_uri=self.redirect_uri,
                    client=self.client,
                )
                claims = self._verify_id_token(tokens["id_token"], self.client.client_id)
            except Exception:
                # 失敗の中身は署名者に見せない。原因はログに残す
                logger.exception("トークンの取得・検証に失敗した")
                raise HTTPException(status_code=403, detail="ログインをやり直してください")

            if claims.get("nonce") != flow["nonce"]:
                raise HTTPException(status_code=403, detail="ログインをやり直してください")
            # 確認できていないメールアドレスは本人性の根拠にならない
            if not claims.get("email") or not claims.get("email_verified"):
                raise HTTPException(status_code=403, detail="確認済みのメールアドレスがありません")

            session = {"email": claims["email"]}
            if claims.get("picture"):
                session["picture"] = claims["picture"]

            response = RedirectResponse(flow["next"], status_code=303)
            self._set_cookie(response, SESSION_COOKIE, self._sessions.dumps(session), SESSION_MAX_AGE)
            response.delete_cookie(FLOW_COOKIE)
            return response

        @router.get("/logout")
        def logout() -> RedirectResponse:
            response = RedirectResponse("/", status_code=303)
            response.delete_cookie(SESSION_COOKIE)
            return response

        return router

    def _set_cookie(self, response: RedirectResponse, name: str, value: str, max_age: int) -> None:
        response.set_cookie(
            name,
            value,
            max_age=max_age,
            httponly=True,
            samesite="lax",
            secure=self.cookie_secure,
        )
