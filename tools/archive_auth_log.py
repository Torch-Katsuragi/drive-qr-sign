"""Google の認証監査ログを取り出して、Drive に置く。

    python tools/archive_auth_log.py --folder <DriveフォルダのID> [--days 7]

なぜ要るか——署名を捏造できるのはアプリの管理者だが、**Google が作るログは
管理者にも消せない**（保持期間の変更も削除もできない）。捏造された署名について
「その時刻に本人が認証した記録が Google 側に無い」と示せる。

⚠**Google 側の保持は6か月**。書類は何年も残るので、消える前に自分の側へ移す。
Vault が扱えるのは Gmail や Drive の中身であって監査ログではないので、
**Drive にファイルとして置く**ことで初めて Vault の保持ルールに乗る。

⚠これで防げるのは「**後から辻褄を合わせる捏造**」まで。取り出した束に
タイムスタンプ（`--timestamp`）を付ければ、後年になって作った記録は入れられない。
一方、**本人が正当に認証した直後に別の書類へ署名する**形の捏造は防げない
（Google 側のログには文書との結びつきが無いため）。

必要な権限:

- `admin.reports.audit.readonly`（管理者アカウントで許可する）
- `drive.file`（このツールが作ったファイルにだけ触れる）

初回は `--authorize` で許可を取り、`secrets/auth-log-reader.json` に保存する。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
CLIENT_SECRETS = REPO_ROOT / "secrets" / "oauth-client.json"
CREDENTIALS = REPO_ROOT / "secrets" / "auth-log-reader.json"
REDIRECT_URI = "http://localhost:8765/oauth2/callback"
PORT = 8765

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/drive.file",
]

# 取るログの種類。login = 認証イベント、token = OAuth の許可と利用
APPLICATIONS = ("login", "token")


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

    def log_message(self, *args):
        return


def authorize() -> None:
    """管理者アカウントで許可を取り、refresh token を保存する。"""
    from google_auth_oauthlib.flow import Flow

    if not CLIENT_SECRETS.exists():
        raise SystemExit(f"{CLIENT_SECRETS} が無い。先に OAuth クライアントの JSON を置く")

    flow = Flow.from_client_secrets_file(str(CLIENT_SECRETS), scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    url, _ = flow.authorization_url(access_type="offline", prompt="consent")
    print("このURLを開いて、**管理者アカウント**で許可する:")
    print(url)

    server = HTTPServer(("127.0.0.1", PORT), CallbackHandler)
    while CallbackHandler.code is None:
        server.handle_request()
    server.server_close()

    flow.fetch_token(code=CallbackHandler.code)
    CREDENTIALS.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS.write_text(flow.credentials.to_json(), encoding="utf-8")
    print(f"保存した: {CREDENTIALS}")


def _credentials():
    from google.oauth2.credentials import Credentials

    if not CREDENTIALS.exists():
        raise SystemExit(f"{CREDENTIALS} が無い。先に --authorize を実行する")
    return Credentials.from_authorized_user_file(str(CREDENTIALS), scopes=SCOPES)


def fetch_events(credentials, days: int) -> list[dict]:
    """指定した日数ぶんの認証イベントを取ってくる。"""
    from googleapiclient.discovery import build

    reports = build("admin", "reports_v1", credentials=credentials, cache_discovery=False)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    events: list[dict] = []
    for application in APPLICATIONS:
        page_token = None
        while True:
            response = (
                reports.activities()
                .list(
                    userKey="all",
                    applicationName=application,
                    startTime=since,
                    maxResults=1000,
                    pageToken=page_token,
                )
                .execute()
            )
            events.extend(response.get("items", []))
            page_token = response.get("nextPageToken")
            if not page_token:
                break
    return events


def timestamp_over(data: bytes, tsa_url: str) -> bytes:
    """束そのものにタイムスタンプを打つ。

    ⚠これが無いと、後年になって都合よく作った束を出せてしまう。
    タイムスタンプがあれば「この束はその時点で存在した」ところまでは第三者が示せる。
    """
    import asyncio
    import hashlib

    from pyhanko.sign.timestamps import HTTPTimeStamper

    stamper = HTTPTimeStamper(tsa_url)
    # ⚠pyHanko の request_cms は要求を組み立てるだけで送らない。送るのは async の方
    token = asyncio.run(stamper.async_timestamp(hashlib.sha256(data).digest(), "sha256"))
    return token.dump()


def upload(credentials, folder_id: str, name: str, data: bytes, mime: str) -> str:
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaInMemoryUpload

    drive = build("drive", "v3", credentials=credentials, cache_discovery=False)
    created = (
        drive.files()
        .create(
            body={"name": name, "parents": [folder_id]},
            media_body=MediaInMemoryUpload(data, mimetype=mime),
            fields="id",
        )
        .execute()
    )
    return created["id"]


def main() -> int:
    parser = argparse.ArgumentParser(description="認証監査ログを Drive に置く")
    parser.add_argument("--authorize", action="store_true", help="管理者アカウントで許可を取る")
    parser.add_argument("--folder", help="置き先の Drive フォルダ ID")
    parser.add_argument("--days", type=int, default=7, help="さかのぼる日数（既定7日）")
    parser.add_argument("--timestamp", metavar="TSA_URL", help="束にタイムスタンプを打つ")
    args = parser.parse_args()

    if args.authorize:
        authorize()
        return 0
    if not args.folder:
        raise SystemExit("--folder に置き先の Drive フォルダ ID を渡す")

    credentials = _credentials()
    events = fetch_events(credentials, args.days)
    stamped = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # 1行1イベント。後から grep できる形にしておく
    data = "\n".join(json.dumps(event, ensure_ascii=False, sort_keys=True) for event in events)
    data = data.encode("utf-8")

    name = f"auth-log-{stamped}.jsonl"
    file_id = upload(credentials, args.folder, name, data, "application/x-ndjson")
    print(f"{len(events)}件を置いた: {name} ({file_id})")

    if args.timestamp:
        token = timestamp_over(data, args.timestamp)
        token_id = upload(
            credentials, args.folder, f"{name}.tsr", token, "application/timestamp-reply"
        )
        print(f"タイムスタンプ: {name}.tsr ({token_id})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
