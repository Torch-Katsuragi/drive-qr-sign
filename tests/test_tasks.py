"""押すのを後ろへ回す（受け付け → キュー → 実行）。

キューは偽物（積まれた予約を手元に溜めるだけ）を差して、`/tasks/sign` を
テストから呼び返す。Cloud Tasks が呼び返すのと同じ入口を通る。
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from drive_qr_sign.documents import LocalDocumentStore
from drive_qr_sign.identity import SignerDirectory, SignerEntry, silent_field_name
from drive_qr_sign.qr import make_mac
from drive_qr_sign.signing import list_signature_fields, list_signatures, load_signer
from drive_qr_sign.tasks import (
    MAX_ATTEMPTS,
    TASK_PATH,
    CloudTasksQueue,
    SignJob,
    ThreadQueue,
    verify_task_token,
)
from drive_qr_sign.web import create_app

SECRET = b"test-secret-do-not-use"
FILE_ID = "sample"
TASK_TOKEN = "Bearer from-the-queue"


class FakeIdentity:
    def __init__(self, email=None):
        self.email = email

    def verified_email(self, request):
        return self.email


class KeepingQueue:
    """積まれた予約を溜めるだけ。押すのはテストが `/tasks/sign` を呼んだとき。"""

    def __init__(self):
        self.jobs: list[SignJob] = []

    def enqueue(self, job: SignJob) -> None:
        self.jobs.append(job)


class Recording:
    def __init__(self):
        self.sent = []

    def notify(self, notice):
        self.sent.append(notice)


class Flaky(LocalDocumentStore):
    """指定した回数だけ取得に失敗する倉庫（Drive や TSA が一時的に落ちている状況）。"""

    def __init__(self, root, failures: int = 0):
        super().__init__(root)
        self.failures = failures

    def fetch(self, file_id):
        if self.failures:
            self.failures -= 1
            raise RuntimeError("一時的に落ちている")
        return super().fetch(file_id)


@pytest.fixture
def app_env(fields_pdf: Path, dev_cert, tmp_path: Path):
    (tmp_path / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())
    key, cert = dev_cert
    identity = FakeIdentity("kumiaicho@example.test")
    queue = KeepingQueue()
    notifier = Recording()
    store = Flaky(tmp_path)
    app = create_app(
        document_store=store,
        signer_directory=SignerDirectory(
            {
                "kumiaicho@example.test": SignerEntry(role="組合長", seal_text="松本"),
                "kanji@example.test": None,
            }
        ),
        identity_provider=identity,
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
        notifier=notifier,
        sign_queue=queue,
        task_auth=lambda request: request.headers.get("authorization") == TASK_TOKEN,
    )
    client = TestClient(app)
    client.app_identity = identity
    return client, identity, queue, notifier, store, tmp_path


def _page(client):
    return client.get(f"/s/{FILE_ID}?m={make_mac(SECRET, FILE_ID)}").text


def _press(client, **headers):
    """署名ボタンを押す。CSRF は画面から拾わずに作る（受付済みの画面にはフォームが無い）。"""
    from drive_qr_sign.web import _csrf_token

    email = client.app_identity.email
    csrf = _csrf_token(SECRET, FILE_ID, email)
    return client.post(
        f"/s/{FILE_ID}/sign?m={make_mac(SECRET, FILE_ID)}", data={"csrf": csrf}, headers=headers
    )


def _deliver(client, job: SignJob, *, retried: int = 0, token: str = TASK_TOKEN):
    """Cloud Tasks が呼び返すのと同じ形で `/tasks/sign` を呼ぶ。"""
    return client.post(
        TASK_PATH,
        content=job.to_json(),
        headers={
            "Content-Type": "application/json",
            "Authorization": token,
            "X-CloudTasks-TaskRetryCount": str(retried),
        },
    )


def _signed_fields(root: Path) -> list[str]:
    signed = root / f"{FILE_ID}.signed.pdf"
    return list_signature_fields(signed, filled=True) if signed.exists() else []


def test_pressing_only_takes_the_order(app_env):
    """押したら予約が積まれるだけで、PDF はまだ変わらない。画面は「受付済み」になる。"""
    client, _, queue, _, _, root = app_env

    response = _press(client)

    assert response.status_code == 200
    assert "署名を受け付けました" in response.text
    assert len(queue.jobs) == 1
    assert queue.jobs[0].role == "組合長"
    assert queue.jobs[0].stamp_png  # 印影は押した時点の絵で持っていく
    assert _signed_fields(root) == []


def test_the_inbox_gets_a_short_answer(app_env):
    client, _, queue, _, _, _ = app_env
    response = _press(client, **{"X-Requested-With": "inbox"})
    assert response.status_code == 202
    assert len(queue.jobs) == 1


def test_an_accepted_order_is_not_taken_twice(app_env):
    client, _, queue, _, _, _ = app_env
    _press(client)
    assert _press(client).status_code == 409
    assert len(queue.jobs) == 1


def test_accepted_documents_leave_the_inbox(app_env):
    client, _, _, _, _, _ = app_env
    assert "data-action" in client.get("/").text
    _press(client)
    assert "data-action" not in client.get("/").text


def test_the_queue_signs_and_sends_the_record(app_env):
    client, _, queue, notifier, _, root = app_env
    _press(client)

    assert _deliver(client, queue.jobs[0]).status_code == 200

    assert _signed_fields(root) == ["組合長"]
    [(field, who)] = list_signatures((root / f"{FILE_ID}.signed.pdf").read_bytes())
    assert (field, who) == ("組合長", "kumiaicho@example.test")
    assert [n.failure for n in notifier.sent] == [None]
    assert "署名済み" in _page(client)


def test_the_same_order_delivered_twice_signs_once(app_env):
    """Cloud Tasks は同じ予約を2回届けることがある。2回目は何もしない。"""
    client, _, queue, notifier, _, root = app_env
    _press(client)
    job = queue.jobs[0]

    assert _deliver(client, job).status_code == 200
    assert _deliver(client, job).status_code == 200

    assert len(list_signatures((root / f"{FILE_ID}.signed.pdf").read_bytes())) == 1
    assert len(notifier.sent) == 1


def test_only_the_queue_may_call_back(app_env):
    """`/tasks/sign` は誰でも叩ける URL。キューの印が無ければ押さない。"""
    client, _, queue, _, _, root = app_env
    _press(client)
    assert _deliver(client, queue.jobs[0], token="Bearer someone-else").status_code == 403
    assert _signed_fields(root) == []


def test_a_passing_hiccup_is_retried_by_the_queue(app_env):
    """一時的な失敗には 500 を返し、Cloud Tasks にやり直させる。本人には知らせない。"""
    client, _, queue, notifier, store, root = app_env
    _press(client)
    job = queue.jobs[0]
    store.failures = 1
    # 手元の写しがあると落としに行かないので、中身を変えて取り直させる
    (root / f"{FILE_ID}.pdf").write_bytes((root / f"{FILE_ID}.pdf").read_bytes() + b"\n")

    assert _deliver(client, job, retried=0).status_code == 500
    assert notifier.sent == []
    assert _deliver(client, job, retried=1).status_code == 200
    assert _signed_fields(root) == ["組合長"]


def test_the_signer_is_told_when_the_last_try_fails(app_env):
    client, _, queue, notifier, store, root = app_env
    _press(client)
    job = queue.jobs[0]
    (root / f"{FILE_ID}.pdf").write_bytes((root / f"{FILE_ID}.pdf").read_bytes() + b"\n")
    store.failures = 99

    assert _deliver(client, job, retried=MAX_ATTEMPTS - 1).status_code == 200
    assert _signed_fields(root) == []
    [notice] = notifier.sent
    assert notice.failure
    # 受付済みの表示は外れ、もう一度押せる
    store.failures = 0
    assert "組合長として署名する" in _page(client)


def test_an_order_that_can_never_succeed_is_not_retried(app_env):
    """押せる欄が無くなった等、やり直しても無駄な失敗は、すぐ打ち切って本人へ知らせる。"""
    client, _, _, notifier, _, root = app_env
    job = SignJob(
        file_id=FILE_ID,
        email="kanji@example.test",  # 押印枠を持たない人が、組合長欄の予約を持ってきた
        role="組合長",
        stamp_png=None,
        requested_at="2026-09-24T10:00:00+09:00",
    )
    assert _deliver(client, job).status_code == 200
    assert _signed_fields(root) == []
    [notice] = notifier.sent
    assert "欄が変わりました" in notice.failure


def test_silent_signatures_go_through_the_queue_too(app_env):
    client, identity, queue, _, _, root = app_env
    identity.email = "kanji@example.test"
    _press(client)
    assert queue.jobs[0].role is None and queue.jobs[0].stamp_png is None
    _deliver(client, queue.jobs[0])
    assert _signed_fields(root) == [silent_field_name("kanji@example.test")]


def test_the_order_survives_the_trip_as_json():
    job = SignJob("f", "a@example.test", "担当", b"\x89PNG...", "2026-09-24T10:00:00+09:00")
    assert SignJob.from_json(job.to_json()) == job


def test_cloud_tasks_calls_back_with_a_token_for_this_app():
    created = []

    class Tasks:
        def create(self, parent, body):
            created.append((parent, body))

            class Call:
                def execute(self_inner):
                    return {}

            return Call()

    class Service:
        def projects(self):
            return self

        def locations(self):
            return self

        def queues(self):
            return self

        def tasks(self):
            return Tasks()

    queue = CloudTasksQueue(
        "projects/p/locations/l/queues/q",
        "https://app.example/tasks/sign",
        "app@p.iam.gserviceaccount.com",
        service=Service(),
    )
    job = SignJob("f", "a@example.test", None, None, "2026-09-24T10:00:00+09:00")
    queue.enqueue(job)

    [(parent, body)] = created
    request = body["task"]["httpRequest"]
    assert parent == "projects/p/locations/l/queues/q"
    assert request["url"] == "https://app.example/tasks/sign"
    assert request["oidcToken"] == {
        "serviceAccountEmail": "app@p.iam.gserviceaccount.com",
        "audience": "https://app.example/tasks/sign",
    }
    assert SignJob.from_json(base64.b64decode(request["body"])) == job


def test_a_forged_token_is_refused():
    assert not verify_task_token(None, "https://app.example/tasks/sign", "x@example.test")
    assert not verify_task_token("Bearer not-a-jwt", "https://app.example/tasks/sign", "x@example.test")


def test_the_dev_queue_signs_in_the_background(fields_pdf: Path, dev_cert, tmp_path: Path):
    (tmp_path / f"{FILE_ID}.pdf").write_bytes(fields_pdf.read_bytes())
    key, cert = dev_cert
    queue = ThreadQueue()
    app = create_app(
        document_store=LocalDocumentStore(tmp_path),
        signer_directory=SignerDirectory({"kumiaicho@example.test": "組合長"}),
        identity_provider=FakeIdentity("kumiaicho@example.test"),
        signer=load_signer(key, cert),
        qr_secret=SECRET,
        tsa_url=None,
        sign_queue=queue,
    )
    client = TestClient(app)
    client.app_identity = FakeIdentity("kumiaicho@example.test")
    assert _press(client).status_code == 200
    queue.join()
    assert _signed_fields(tmp_path) == ["組合長"]
    assert "署名済み" in _page(client)
