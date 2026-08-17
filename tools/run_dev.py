"""開発用サーバ。

Drive はまだ無く、ローカルのディレクトリを倉庫代わりに使う。

本人確認は2通りで、`secrets/oauth-client.json`（Google Cloud コンソールの
「JSON をダウンロード」で落ちるファイル）があれば本物の Google ログインになり、
無ければ `?as=<メールアドレス>` で名乗れる偽の身元確認になる。
偽のほうを package の外（tools/）に置いてあるのは、
偽の認証がライブラリ側に紛れ込まないようにするため。

    python tools/run_dev.py

起動時に、署名できる URL を印字する。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import uvicorn

from drive_qr_sign.documents import LocalDocumentStore
from drive_qr_sign.google_identity import ClientSecrets, GoogleIdentityProvider
from drive_qr_sign.identity import SignerDirectory, SignerEntry
from drive_qr_sign.qr import sign_url
from drive_qr_sign.seal_store import LocalSealStore
from drive_qr_sign.signing import load_signer
from drive_qr_sign.web import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "out"
STORE_DIR = OUT_DIR / "dev-store"
SECRETS_DIR = REPO_ROOT / "secrets"

HOST = "127.0.0.1"  # 待ち受けはループバックだけ
# 表に出す名前は localhost に揃える。OAuth のリダイレクト URI は文字列一致で照合されるので、
# 127.0.0.1 と localhost を混ぜると redirect_uri_mismatch になる
PUBLIC_ORIGIN = "http://localhost:8765"
PORT = 8765
FILE_ID = "sample"

# 開発用の固定鍵。本番は Secret Manager から読む
DEV_QR_SECRET = b"dev-only-qr-secret"
DEV_SESSION_SECRET = "dev-only-session-secret"

# Google Cloud コンソールの「JSON をダウンロード」で落ちるファイルの置き場。
# ここに置くだけで本物の Google ログインに切り替わる（secrets/ は .gitignore 済み）
CLIENT_SECRETS = Path(__file__).resolve().parent.parent / "secrets" / "oauth-client.json"

# 署名者名簿。導入組織ごとに設定する唯一の業務知識。
# 役職が None の人は押印枠を持たず、押すと不可視署名になる
DEV_SIGNERS = {
    "kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本"),
    "sanji@example.test": SignerEntry(role="参事", seal_text="山田"),
    "tantou@example.test": SignerEntry(role="担当", seal_text="佐々木"),
    "kanji@example.test": None,  # 押印枠なし＝サイレント署名
}

# 実在のアカウントで試すとき用。secrets/ は .gitignore 済みなので、
# 個人のメールアドレスがリポジトリに入らない。
#   {"someone@example.com": {"role": "組合長", "seal_text": "松本"}, "other@example.com": null}
SIGNERS_OVERRIDE = Path(__file__).resolve().parent.parent / "secrets" / "dev-signers.json"


def load_signers() -> dict:
    if not SIGNERS_OVERRIDE.exists():
        return DEV_SIGNERS
    import json

    raw = json.loads(SIGNERS_OVERRIDE.read_text(encoding="utf-8"))
    return {
        email: (SignerEntry(**value) if isinstance(value, dict) else value)
        for email, value in raw.items()
    }


DEV_COOKIE = "dev_as"


class DevIdentityProvider:
    """`?as=` で名乗った通りに信じる、開発専用の身元確認。

    本番の OIDC はログイン結果をセッション Cookie に置く。ここでも同じく Cookie に落とすのは、
    POST 先の URL に本人情報を載せずに済ませるため（載せると、紙に刷る URL や
    リファラに個人が漏れる設計になってしまう）。
    """

    def verified_email(self, request) -> str | None:
        return request.query_params.get("as") or request.cookies.get(DEV_COOKIE)


async def remember_dev_identity(request, call_next):
    """`?as=` が来たら Cookie に覚える。開発用サーバだけのふるまい。"""
    response = await call_next(request)
    who = request.query_params.get("as")
    if who:
        response.set_cookie(DEV_COOKIE, who, httponly=True, samesite="lax")
    return response


def prepare() -> None:
    """サンプル書類と開発用証明書を用意する。"""
    STORE_DIR.mkdir(parents=True, exist_ok=True)

    fields_pdf = OUT_DIR / "sample-fields.pdf"
    if not fields_pdf.exists():
        raise SystemExit("先に python tools/build_sample.py を実行してください")
    shutil.copyfile(fields_pdf, STORE_DIR / f"{FILE_ID}.pdf")
    # 前回の実行で押した署名は持ち越さない（毎回まっさらな回覧から始める）
    (STORE_DIR / f"{FILE_ID}.signed.pdf").unlink(missing_ok=True)

    if not (SECRETS_DIR / "dev-key.pem").exists():
        from make_dev_cert import make_dev_cert

        make_dev_cert(SECRETS_DIR)


def build_identity_provider():
    """本物の Google ログインが使えるならそちら、無ければ偽の身元確認。"""
    if not CLIENT_SECRETS.exists():
        print(f"! {CLIENT_SECRETS} が無いので ?as= で名乗る開発用ログインを使う")
        return DevIdentityProvider(), True

    print(f"Google ログインを使う（{CLIENT_SECRETS.name}）")
    return (
        GoogleIdentityProvider(
            ClientSecrets.load(CLIENT_SECRETS),
            redirect_uri=f"{PUBLIC_ORIGIN}/oauth2/callback",
            session_secret=DEV_SESSION_SECRET,
            cookie_secure=False,  # localhost は http なので secure だと Cookie が付かない
        ),
        False,
    )


def main() -> None:
    prepare()
    signers = load_signers()
    identity_provider, is_fake = build_identity_provider()
    app = create_app(
        document_store=LocalDocumentStore(STORE_DIR),
        signer_directory=SignerDirectory(signers),
        identity_provider=identity_provider,
        signer=load_signer(SECRETS_DIR / "dev-key.pem", SECRETS_DIR / "dev-cert.pem"),
        qr_secret=DEV_QR_SECRET,
        tsa_url=None,  # 開発中は TSA に出ない。本番は freeTSA か認定TSA
        seal_store=LocalSealStore(OUT_DIR / "dev-seals"),
    )
    if is_fake:
        app.middleware("http")(remember_dev_identity)

    url = sign_url(PUBLIC_ORIGIN, DEV_QR_SECRET, FILE_ID)
    print("QR に焼く URL（開発用）:")
    if is_fake:
        for email, entry in signers.items():
            label = entry.role if entry else "サイレント"
            print(f"  {label:<6} {url}&as={email}")
    else:
        print(f"  {url}")
        print("  ログインするアカウントは、下の名簿に載っているものにする:")
        for email, entry in signers.items():
            print(f"    {(entry.role if entry else 'サイレント'):<6} {email}")

    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(REPO_ROOT / "tools"))
    main()
