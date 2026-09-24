"""署名を「受け付け」と「実行」に分ける。

押した人を待たせるのは、本人の確認と押してよい欄かの判定まで（0.1秒台）。
PDF への署名・タイムスタンプ・Drive への書き戻し（合わせて数秒）は後ろへ回す。
署名に要る本人側の情報は Google で確かめたメールアドレスだけなので、
受け付けた時点で「誰が・どの書類の・どの欄に」を書き留めておけば、後から押せる。

後ろへ回す先は2つ。

- `CloudTasksQueue` … 本番。予約は Google 側に残るので、インスタンスが落ちても
  デプロイの最中でも消えない。失敗すれば間を置いてやり直してくれる。
  キューの同時実行を1件に絞るので、署名どうしが重ならない
- `ThreadQueue` … 開発用サーバ。プロセスの中の1本のスレッドで順に回す。
  プロセスが止まれば予約も消える（本番には使わない）

キューを渡さなければ、今までどおりその場で署名する（Cloud Tasks を用意していない導入先向け）。

> [!WARNING] 「押せたように見えて Drive にはまだ無い」時間ができる
> 以前は、これを作らないために書き戻しを同期にしていた。テンポを優先して方針を変えた
> （2026-09-24、松本判断）。代わりに、最後まで押せなかったときは本人へメールで知らせる。
"""

from __future__ import annotations

import base64
import json
import logging
import queue
import threading
from dataclasses import dataclass
from typing import Callable, Protocol

logger = logging.getLogger(__name__)

# Cloud Tasks がやり直す回数の上限。キューの設定（docs/DEPLOY.md）と揃える。
# 最後の1回でも押せなければ、本人へ「押せなかった」と知らせて打ち切る
MAX_ATTEMPTS = 5
TASK_PATH = "/tasks/sign"


@dataclass(frozen=True)
class SignJob:
    """1件の署名の予約。押した時点で決まることは、全部ここに固めて持ち運ぶ。

    印影は絵そのもので持つ。アカウントのアイコンやアップロードした画像は
    押した人のログイン中にしか取れないので、後から作り直せない。
    """

    file_id: str
    email: str
    role: str | None  # None なら押印枠を持たない人のサイレント署名
    stamp_png: bytes | None
    requested_at: str  # 受け付けた時刻（ISO 8601）。署名の理由欄に残す

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "file_id": self.file_id,
                "email": self.email,
                "role": self.role,
                "stamp_png": base64.b64encode(self.stamp_png).decode("ascii") if self.stamp_png else None,
                "requested_at": self.requested_at,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    @staticmethod
    def from_json(data: bytes) -> "SignJob":
        raw = json.loads(data)
        stamp = raw.get("stamp_png")
        return SignJob(
            file_id=raw["file_id"],
            email=raw["email"],
            role=raw.get("role"),
            stamp_png=base64.b64decode(stamp) if stamp else None,
            requested_at=raw["requested_at"],
        )


class SignQueue(Protocol):
    def enqueue(self, job: SignJob) -> None:
        """署名の予約を積む。戻ってきた時点で、予約は失われない場所にある。"""


class CloudTasksQueue:
    """Cloud Tasks に積む。タスクはこのアプリの `/tasks/sign` を呼び返す。

    呼び返しには OIDC トークンが付く。`/tasks/sign` は誰でも叩ける URL なので、
    アプリ側でトークンを確かめる（`verify_task_token`）。
    """

    def __init__(self, queue_path: str, target_url: str, invoker_email: str, *, service=None):
        self.queue_path = queue_path  # projects/<p>/locations/<l>/queues/<q>
        self.target_url = target_url
        self.invoker_email = invoker_email
        self._fixed = service
        # googleapiclient はスレッドをまたいで共有できない（drive.py と同じ理由）。
        # 一覧からまとめて押すと、受け付けが同時に並ぶ
        self._local = threading.local()

    def _tasks(self):
        service = self._fixed or getattr(self._local, "service", None)
        if service is None:
            from googleapiclient.discovery import build

            service = self._local.service = build("cloudtasks", "v2", cache_discovery=False)
        return service.projects().locations().queues().tasks()

    def enqueue(self, job: SignJob) -> None:
        body = {
            "task": {
                "httpRequest": {
                    "httpMethod": "POST",
                    "url": self.target_url,
                    "headers": {"Content-Type": "application/json"},
                    "body": base64.b64encode(job.to_json()).decode("ascii"),
                    "oidcToken": {
                        "serviceAccountEmail": self.invoker_email,
                        "audience": self.target_url,
                    },
                }
            }
        }
        self._tasks().create(parent=self.queue_path, body=body).execute()


class ThreadQueue:
    """開発用。1本のスレッドで順に回す。プロセスが止まれば予約も消える。"""

    def __init__(self):
        self._jobs: queue.Queue[SignJob] = queue.Queue()
        self._runner: Callable[[SignJob], None] | None = None
        self._worker: threading.Thread | None = None

    def bind(self, runner: Callable[[SignJob], None]) -> None:
        """実際に押す関数を受け取る（create_app が渡す）。"""
        self._runner = runner

    def enqueue(self, job: SignJob) -> None:
        if self._worker is None:
            self._worker = threading.Thread(target=self._loop, daemon=True)
            self._worker.start()
        self._jobs.put(job)

    def join(self) -> None:
        """積まれた分を全部押し終えるまで待つ（テスト用）。"""
        self._jobs.join()

    def _loop(self) -> None:
        while True:
            job = self._jobs.get()
            try:
                self._runner(job)
            except Exception:
                logger.exception("署名の予約を押せなかった: %s", job.file_id)
            finally:
                self._jobs.task_done()


def verify_task_token(authorization: str | None, audience: str, invoker_email: str) -> bool:
    """`/tasks/sign` を呼んだのが、こちらのキューかを確かめる。

    Cloud Tasks は OIDC トークン（Google が署名した ID トークン）を付けて呼ぶ。
    宛先（audience）とサービスアカウントの両方が合うものだけを通す。
    """
    if not authorization or not authorization.startswith("Bearer "):
        return False
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    try:
        claims = id_token.verify_oauth2_token(
            authorization.removeprefix("Bearer ").strip(), google_requests.Request(), audience
        )
    except Exception:
        return False
    return bool(claims.get("email_verified")) and claims.get("email") == invoker_email
