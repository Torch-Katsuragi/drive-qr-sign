"""本番（Cloud Run）の入口。

設定はすべて環境変数から受け取る。Cloud Run では Secret Manager の中身を
`--set-secrets` で環境変数に流し込むので、アプリ側に Secret Manager の
クライアントコードは要らない。

    QR_SECRET          QR の HMAC 鍵
    SESSION_SECRET     ログインのセッションクッキーの署名鍵
    SIGNING_KEY_KMS    署名鍵を Cloud KMS に置く場合の鍵バージョン名。あるとこちらが優先
    SIGNING_KEY_PEM    署名鍵（PEM）。KMS を使わない場合
    SIGNING_CERT_PEM   署名証明書（PEM）
    OAUTH_CLIENT_JSON  OAuth クライアント（コンソールの JSON そのまま）
    SIGNERS_JSON       署名者名簿 {"a@example.com": {"role": "組合長", "seal_text": "松本"}}
    PUBLIC_ORIGIN      このサービスの URL（https://... 。リダイレクト URI の組み立てに使う）
    TSA_URL            省略すると freeTSA
    OAUTH_SCOPES       省略すると openid email
    RESEND_API_KEY     署名の記録メールを送る鍵（Resend）。あるとこちらが優先される
    NOTICE_SENDER      その差出人（例: 〇〇工房 <no-reply@example.com>）
    GMAIL_SENDER_JSON  Gmail から送る場合の資格情報。無ければ送らない

Drive は Cloud Run に紐づいたサービスアカウントで触るので、鍵ファイルは持たない。

印影は保管しない。アカウントのアイコンか、名簿の文字から生成した丸印を使い、
どうしても別の絵で押したい人はその署名のときだけアップロードする。
置き場を持たないので、Cloud Run のファイルシステムが使い捨てであることを気にせずに済む。
"""

from __future__ import annotations

import json
import logging
import os

from .drive import DriveDocumentStore, build_default_service
from .google_identity import BASE_SCOPES, ClientSecrets, GoogleIdentityProvider
from .identity import SignerDirectory, SignerEntry
from .notify import GmailNotifier, ResendNotifier, build_gmail_service_from_info
from .kms import load_kms_signer
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
    """署名の記録メール。資格情報が無ければ送らない（導入組織が選ぶオプション）。

    送信専用サービス（Resend）を優先する。Google アカウントを1つ増やして守るより、
    送信だけができる鍵を1本持つほうが、漏れたときにできることが少ない。
    Gmail 経路は、送信サービスを使わない導入先のために残す。
    """
    api_key = os.environ.get("RESEND_API_KEY")
    if api_key:
        return ResendNotifier(api_key, _required("NOTICE_SENDER"))

    raw = os.environ.get("GMAIL_SENDER_JSON")
    if not raw:
        return None
    return GmailNotifier(build_gmail_service_from_info(json.loads(raw)))


def _configure_logging() -> None:
    """アプリのログを標準出力に出す。

    ⚠これが無いと `logger.info` は消える。uvicorn は自前のロガーだけを設定するので、
    アプリ側のロガーは root（既定 WARNING）に落ちて捨てられる。
    Cloud Run のログに押印の内訳が出ないのはこれが原因だった（実測して発見）。
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")


def _signer():
    """署名鍵。KMS に置いてあればそちら、無ければ PEM を読む。

    ⚠PEM は鍵そのものがプロセスのメモリに載る。アプリを取られたら鍵ごと持ち出せる。
    KMS なら出てこない（できるのは「署名して」と頼むことだけで、その記録も残る）。
    """
    key_version = os.environ.get("SIGNING_KEY_KMS")
    if key_version:
        logging.getLogger(__name__).info("署名鍵: KMS %s", key_version)
        return load_kms_signer(key_version, _required("SIGNING_CERT_PEM").encode("utf-8"))
    logging.getLogger(__name__).warning("署名鍵: PEM（鍵がプロセスに載る。KMS に移せる）")
    return load_signer_from_pem(
        _required("SIGNING_KEY_PEM").encode("utf-8"),
        _required("SIGNING_CERT_PEM").encode("utf-8"),
    )


def build() -> "object":
    _configure_logging()
    # 起動したことを1行残す。押すのが遅かったとき、コンテナの起動待ちだったのか
    # 中の処理が重かったのかを、ログの並びだけで見分けられるようにする
    logging.getLogger(__name__).info("起動")
    store = DriveDocumentStore(build_default_service())
    return create_app(
        document_store=store,
        signer_directory=_signer_directory(),
        identity_provider=_identity_provider(),
        signer=_signer(),
        qr_secret=_required("QR_SECRET").encode("utf-8"),
        tsa_url=os.environ.get("TSA_URL", FREE_TSA_URL),
        can_read=store.can_read,
        notifier=_notifier(),
    )


app = build()
