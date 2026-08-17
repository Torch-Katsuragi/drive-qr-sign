"""Google Drive を書類の置き場として使う。

アプリはサービスアカウントとして Drive を触る。触れるのは**共有された書類だけ**で、
組織は回覧する書類（またはフォルダ）をそのアカウントに共有することで許可を与える。
つまりアクセス制御は Drive の共有設定そのもので、アプリ側に名簿は要らない。

> [!WARNING] ここが乗っ取られたときの被害範囲
> サービスアカウントに共有されている書類は、読まれるし上書きもされる。
> だから ①共有は回覧期間に限る ②署名鍵は KMS に置いて持ち出せなくする
> ③署名要求をアプリが消せない場所に記録する、の3つで受ける（docs/DESIGN.md）。

書き戻しは**原本の新しい版として上書き**する。別ファイルに逃がすと原本と署名済みが
割れて、QR やリンクが指す原本にいつまでも署名が入らない状態になるため。
消された場合の復元は Google Vault（Business Plus 以上）に委ねる。
"""

from __future__ import annotations

import io
from pathlib import Path

from .documents import DocumentNotFound

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
PDF_MIME = "application/pdf"


def build_service(credentials_file: Path | str):
    """サービスアカウントの鍵ファイルから Drive クライアントを作る。

    本番（Cloud Run）では鍵ファイルを置かず、実行環境に紐づいたサービスアカウントを
    そのまま使う（`google.auth.default()`）。鍵ファイルは開発用の逃げ道。
    """
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    credentials = service_account.Credentials.from_service_account_file(
        str(credentials_file), scopes=[DRIVE_SCOPE]
    )
    return build("drive", "v3", credentials=credentials, cache_discovery=False)


def build_default_service():
    """実行環境のサービスアカウントで Drive クライアントを作る（鍵ファイル無し）。"""
    import google.auth
    from googleapiclient.discovery import build

    credentials, _ = google.auth.default(scopes=[DRIVE_SCOPE])
    return build("drive", "v3", credentials=credentials, cache_discovery=False)


class DriveDocumentStore:
    """DocumentStore の Drive 実装。"""

    def __init__(self, service):
        self._service = service

    def fetch(self, file_id: str) -> bytes:
        try:
            return self._service.files().get_media(fileId=file_id).execute()
        except Exception as exc:
            # 共有されていないファイルも「見つからない」として扱う。
            # 存在の有無を問い合わせ元に教えない
            raise DocumentNotFound(f"取得できない: {file_id}") from exc

    def store_signed(self, file_id: str, data: bytes) -> str:
        """署名済みを原本の新しい版として書き戻す。

        版が積まれるだけで file id は変わらないので、紙に刷った QR も
        Drive のリンクも、そのまま最新の署名済みを指し続ける。
        """
        from googleapiclient.http import MediaIoBaseUpload

        media = MediaIoBaseUpload(io.BytesIO(data), mimetype=PDF_MIME, resumable=False)
        result = (
            self._service.files()
            .update(fileId=file_id, media_body=media, fields="id,version")
            .execute()
        )
        return str(result.get("version") or result.get("id") or file_id)

    def can_read(self, file_id: str, email: str) -> bool:
        """その人が Drive 上でこの書類を見られるか。

        アプリが名簿で判定するのではなく、Drive の共有設定に従う。
        ⚠グループ共有は展開されない（permissions にはグループが1件出るだけで、
        その中の個人までは分からない）。グループを使う組織では、これだけに頼らない。
        """
        try:
            response = (
                self._service.permissions()
                .list(fileId=file_id, fields="permissions(emailAddress,type,role)")
                .execute()
            )
        except Exception as exc:
            raise DocumentNotFound(f"共有設定を読めない: {file_id}") from exc

        wanted = email.strip().lower()
        for permission in response.get("permissions", []):
            # リンクを知っている全員／ドメイン全体に共有されている場合は誰でも読める。
            # それを選んだのは組織なので、アプリは追認する
            if permission.get("type") in {"anyone", "domain"}:
                return True
            if (permission.get("emailAddress") or "").strip().lower() == wanted:
                return True
        return False
