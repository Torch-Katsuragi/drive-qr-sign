"""開発用サーバ。

Google ログインも Drive も無い状態で署名ページを見るためのもの。
本人確認は `?as=<メールアドレス>` で偽装できる——つまり本番では絶対に使えない。
その割り切りを package の外（tools/）に置いてあるのは、
偽の認証がライブラリ側に紛れ込まないようにするため。

    python tools/run_dev.py

起動時に、署名できる URL を印字する。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import uvicorn

from drive_qr_sign.documents import LocalDocumentStore
from drive_qr_sign.identity import SignerDirectory
from drive_qr_sign.qr import sign_url
from drive_qr_sign.signing import load_signer
from drive_qr_sign.web import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "out"
STORE_DIR = OUT_DIR / "dev-store"
SECRETS_DIR = REPO_ROOT / "secrets"

HOST = "127.0.0.1"
PORT = 8765
FILE_ID = "sample"

# 開発用の固定鍵。本番は Secret Manager から読む
DEV_QR_SECRET = b"dev-only-qr-secret"

# 署名者名簿。導入組織ごとに設定する唯一の業務知識。
# 役職が None の人は押印枠を持たず、押すと不可視署名になる
DEV_SIGNERS = {
    "kumiaicho@example.test": "組合長",
    "sanji@example.test": "参事",
    "tantou@example.test": "担当",
    "kanji@example.test": None,
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


def main() -> None:
    prepare()
    app = create_app(
        document_store=LocalDocumentStore(STORE_DIR),
        signer_directory=SignerDirectory(DEV_SIGNERS),
        identity_provider=DevIdentityProvider(),
        signer=load_signer(SECRETS_DIR / "dev-key.pem", SECRETS_DIR / "dev-cert.pem"),
        qr_secret=DEV_QR_SECRET,
        tsa_url=None,  # 開発中は TSA に出ない。本番は freeTSA か認定TSA
    )
    app.middleware("http")(remember_dev_identity)

    url = sign_url(f"http://{HOST}:{PORT}", DEV_QR_SECRET, FILE_ID)
    print("QR に焼く URL（開発用）:")
    for email, role in DEV_SIGNERS.items():
        print(f"  {(role or 'サイレント'):<6} {url}&as={email}")

    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(REPO_ROOT / "tools"))
    main()
