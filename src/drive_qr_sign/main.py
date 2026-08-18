"""本番（Cloud Run）の入口。

設定はすべて環境変数から受け取る。Cloud Run では Secret Manager の中身を
`--set-secrets` で環境変数に流し込むので、アプリ側に Secret Manager の
クライアントコードは要らない。

    QR_SECRET          QR の HMAC 鍵
    SESSION_SECRET     ログインのセッションクッキーの署名鍵
    SIGNING_KEY_PEM    署名鍵（PEM）
    SIGNING_CERT_PEM   署名証明書（PEM）
    OAUTH_CLIENT_JSON  OAuth クライアント（コンソールの JSON そのまま）
    SIGNERS_JSON       署名者名簿 {"a@example.com": {"role": "組合長", "seal_text": "松本"}}
    PUBLIC_ORIGIN      このサービスの URL（https://... 。リダイレクト URI の組み立てに使う）
    TSA_URL            省略すると freeTSA
    OAUTH_SCOPES       省略すると openid email
    GMAIL_SENDER_JSON  署名の記録メールを送るアカウントの資格情報。無ければ送らない

Drive は Cloud Run に紐づいたサービスアカウントで触るので、鍵ファイルは持たない。

印影の登録（`/seal`）は無効。Cloud Run のファイルシステムは使い捨てで、
インスタンスはいつ入れ替わってもおかしくない（起動しっぱなしにしても同じ）。
置き場を Drive などに持たせるまでは「名簿の文字から生成」だけにする。
"""

from __future__ import annotations

import json
import os

from .drive import DriveDocumentStore, build_default_service
from .google_identity import BASE_SCOPES, ClientSecrets, GoogleIdentityProvider
from .identity import SignerDirectory, SignerEntry
from .notify import GmailNotifier, build_gmail_service_from_info
from .signing import FREE_TSA_URL, load_signer_from_pem
from .web import create_app


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"環境変数 {name} が無い")
    return value


def _signer_directory() -> SignerDirectory:
    raw = json.loads(_required("SIGNERS_JSON"))
    return SignerDirectory(
        {
            email: (SignerEntry(**value) if isinstance(value, dict) else value)
            for email, value in raw.items()
        }
    )


def _identity_provider() -> GoogleIdentityProvider:
    client = json.loads(_required("OAUTH_CLIENT_JSON"))
    section = client.get("web") or client.get("installed") or client
    scopes = tuple(os.environ.get("OAUTH_SCOPES", " ".join(BASE_SCOPES)).split())
    return GoogleIdentityProvider(
        ClientSecrets(section["client_id"], section["client_secret"]),
        redirect_uri=f"{_required('PUBLIC_ORIGIN').rstrip('/')}/oauth2/callback",
        session_secret=_required("SESSION_SECRET"),
        scopes=scopes,
        cookie_secure=True,  # 本番は https なので必ず付ける
    )


def _notifier():
    """署名の記録メール。資格情報が無ければ送らない（導入組織が選ぶオプション）。"""
    raw = os.environ.get("GMAIL_SENDER_JSON")
    if not raw:
        return None
    return GmailNotifier(build_gmail_service_from_info(json.loads(raw)))


def build() -> "object":
    store = DriveDocumentStore(build_default_service())
    return create_app(
        document_store=store,
        signer_directory=_signer_directory(),
        identity_provider=_identity_provider(),
        signer=load_signer_from_pem(
            _required("SIGNING_KEY_PEM").encode("utf-8"),
            _required("SIGNING_CERT_PEM").encode("utf-8"),
        ),
        qr_secret=_required("QR_SECRET").encode("utf-8"),
        tsa_url=os.environ.get("TSA_URL", FREE_TSA_URL),
        can_read=store.can_read,
        # 印影の登録先が無いので、生成した丸印だけになる
        seal_store=None,
        notifier=_notifier(),
    )


app = build()
