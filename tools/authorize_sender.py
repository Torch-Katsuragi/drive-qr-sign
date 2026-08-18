"""署名の記録メールを送るアカウントの資格情報を作る。

    python tools/authorize_sender.py

ブラウザが開くので、**送信専用にしたいアカウント**でログインして許可する。
`secrets/gmail-sender.json` に refresh token が保存され、以後はそれで送れる。

要求するスコープは `gmail.send` だけ。読む権限は与えない。

> [!NOTE] ここだけは警告画面が出る
> `gmail.send` は Google の分類で「機密性の高いスコープ」なので、未審査アプリだと
> 「このアプリは Google で確認されていません」が出る。署名者には出ない——
> 署名者が使うのは `openid`+`email` だけで、この画面を踏むのは
> 送信アカウントを用意する管理者の1回きり。

既存の OAuth クライアント（secrets/oauth-client.json）をそのまま使う。
リダイレクト URI も登録済みのものを使い回すので、コンソールでの追加作業は要らない。
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from google_auth_oauthlib.flow import Flow

REPO_ROOT = Path(__file__).resolve().parent.parent
CLIENT_SECRETS = REPO_ROOT / "secrets" / "oauth-client.json"
OUTPUT = REPO_ROOT / "secrets" / "gmail-sender.json"

# 開発用 OAuth クライアントに登録済みのリダイレクト URI をそのまま使う
REDIRECT_URI = "http://localhost:8765/oauth2/callback"
PORT = 8765

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


class CallbackHandler(BaseHTTPRequestHandler):
    code: str | None = None

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        CallbackHandler.code = (query.get("code") or [None])[0]
        message = "許可されました。ターミナルに戻ってください。" if CallbackHandler.code else "許可されませんでした。"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"<meta charset='utf-8'><p>{message}</p>".encode("utf-8"))

    def log_message(self, *args):  # サーバのアクセスログは出さない
        return


def main() -> None:
    if not CLIENT_SECRETS.exists():
        raise SystemExit(f"{CLIENT_SECRETS} が無い。先に OAuth クライアントの JSON を置く")

    flow = Flow.from_client_secrets_file(str(CLIENT_SECRETS), scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    url, _ = flow.authorization_url(access_type="offline", prompt="consent")

    print("このURLをブラウザで開いて、送信専用にしたいアカウントで許可する:", flush=True)
    print(url, flush=True)
    print(f"待機中… ({REDIRECT_URI})", flush=True)
    # 別プロセスから URL を拾えるようにしておく（自動化のため）
    (REPO_ROOT / "out" / "authorize-url.txt").write_text(url, encoding="utf-8")

    server = HTTPServer(("127.0.0.1", PORT), CallbackHandler)
    while CallbackHandler.code is None:
        server.handle_request()
    server.server_close()

    flow.fetch_token(code=CallbackHandler.code)
    OUTPUT.write_text(flow.credentials.to_json(), encoding="utf-8")
    print(f"保存した: {OUTPUT}")


if __name__ == "__main__":
    sys.exit(main())
