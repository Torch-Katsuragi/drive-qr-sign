"""署名した本人へ、確認のメールを送る。

狙いは通知そのものではなく、**アプリの外に消せない記録を作ること**にある。

Workspace のドメインから送ったメールには、そのドメインの秘密鍵による DKIM 署名が付く。
受信者の手元に残るコピーにもそのヘッダがそのまま残るので、署名者は
「このドメインが確かにこの内容を送った」を、こちらの協力なしに証明できる。
逆に受信者の側では偽造できない（ドメインの秘密鍵が要る）。

送信履歴は組織、受信履歴は本人。**どちらも一方的には両方を消せない**。
アプリが乗っ取られて記録を書き換えられても、署名者の受信箱のコピーは残る。

> [!IMPORTANT] 本文に入れるのは file id ではなく署名済み PDF のハッシュ
> file id はファイルが変わっても同じなので、何も固定しない。
> ハッシュを入れて初めて「このバイト列が、この人の署名で確定した」という
> ドメイン署名付きの宣言になる。

> [!WARNING] メール送信能力はアプリの被害範囲を広げる
> 乗っ取られれば組織のドメインからフィッシングを撒ける。Drive の読み書きより
> 社会的な被害が大きくなりうる。だから送信専用アカウント（`no-reply@`）の
> 資格情報だけを持たせ、ドメイン全体の代理送信権限（domain-wide delegation）は渡さない。
> 要求するスコープも `gmail.send` だけにする。

証明できるのは「通知された」ことまでで、「本人が押した」ことではない。
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"


@dataclass(frozen=True)
class SignatureNotice:
    """1回の署名について、後から突き合わせられるだけの事実。"""

    file_id: str
    signer_email: str
    role: str | None  # None なら押印枠を持たない人のサイレント署名
    digest: str  # 署名済み PDF の SHA-256（16進）
    signed_at: datetime

    @staticmethod
    def create(*, file_id: str, signer_email: str, role: str | None, signed_pdf: bytes):
        return SignatureNotice(
            file_id=file_id,
            signer_email=signer_email,
            role=role,
            digest=hashlib.sha256(signed_pdf).hexdigest(),
            signed_at=datetime.now(timezone.utc),
        )

    @property
    def drive_url(self) -> str:
        return f"https://drive.google.com/file/d/{self.file_id}/view"


def render_notice(notice: SignatureNotice) -> tuple[str, str]:
    """件名と本文。機械で突き合わせられるよう、値は1行1項目で書く。"""
    what = f"{notice.role} 欄に押印" if notice.role else "確認の記録（紙面には出ない署名）"
    subject = f"[署名の記録] {notice.file_id}"
    body = f"""{notice.signer_email} 様

下記の書類に、あなたのアカウントで署名が行われました。

  内容          : {what}
  書類          : {notice.drive_url}
  ファイル ID   : {notice.file_id}
  署名済みPDFのSHA-256: {notice.digest}
  署名時刻(UTC) : {notice.signed_at.isoformat(timespec="seconds")}

このメールは記録として保存してください。
送信ドメインの DKIM 署名が付いているため、このメールを持っていれば、
上記のハッシュを持つ PDF について「この内容の通知が確かに送られた」ことを
後から第三者に示せます。手元の PDF のハッシュと突き合わせて確認できます。

心当たりが無い場合は、書類の管理者に連絡してください。
"""
    return subject, body


class Notifier(Protocol):
    def notify(self, notice: SignatureNotice) -> None:
        """署名の記録を本人へ送る。"""


class NullNotifier:
    """送らない。既定はこれ（メール送信は導入組織が選ぶオプション）。"""

    def notify(self, notice: SignatureNotice) -> None:
        return None


class GmailNotifier:
    """送信専用アカウントの資格情報で Gmail から送る。

    sender を省略すると、差出人は Gmail が資格情報の持ち主で埋める。
    自分の宛先を知るためだけに読み取り権限を足すのは本末転倒なので、既定はこちら
    （`gmail.send` は自分のアドレスを問い合わせることすらできない）。
    """

    def __init__(self, service, sender: str | None = None):
        self._service = service
        self._sender = sender

    def notify(self, notice: SignatureNotice) -> None:
        subject, body = render_notice(notice)
        message = EmailMessage()
        message["To"] = notice.signer_email
        if self._sender:
            message["From"] = self._sender
        message["Subject"] = subject
        message.set_content(body)

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        self._service.users().messages().send(userId="me", body={"raw": raw}).execute()


def build_gmail_service(credentials_file: Path | str):
    """送信専用アカウントの refresh token から Gmail クライアントを作る。

    サービスアカウントの代理送信（domain-wide delegation）は使わない。
    あれはドメイン内の誰にでもなりすませてしまうため。
    """
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    credentials = Credentials.from_authorized_user_file(
        str(credentials_file), scopes=[GMAIL_SEND_SCOPE]
    )
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def notify_quietly(notifier: Notifier | None, notice: SignatureNotice) -> None:
    """通知の失敗で署名を失敗させない。

    署名はもう PDF に埋まって書き戻されている。そのあとメールが出せなかったからといって
    署名者に「失敗しました」と見せるのは、事実と違ううえに再署名を誘発して害になる。
    """
    if notifier is None:
        return
    try:
        notifier.notify(notice)
    except Exception:
        logger.exception("署名の通知メールを送れなかった: %s", notice.file_id)
