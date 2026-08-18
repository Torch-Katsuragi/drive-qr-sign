"""Drive を書類の置き場として使う層。

Google には出ない。Drive API の返しを差し替えて、こちら側のふるまいだけを見る。
"""

from __future__ import annotations

import pytest

from drive_qr_sign.documents import DocumentNotFound
from drive_qr_sign.drive import DriveDocumentStore


class FakeRequest:
    def __init__(self, result, error: Exception | None = None):
        self._result = result
        self._error = error

    def execute(self):
        if self._error:
            raise self._error
        return self._result


class FakeFiles:
    def __init__(self, drive: "FakeDrive"):
        self._drive = drive

    def get_media(self, fileId: str):
        if fileId not in self._drive.contents:
            return FakeRequest(None, error=RuntimeError("404"))
        return FakeRequest(self._drive.contents[fileId])

    def update(self, fileId: str, media_body=None, fields=None):
        self._drive.contents[fileId] = media_body.getbytes(0, media_body.size())
        self._drive.versions[fileId] = self._drive.versions.get(fileId, 1) + 1
        return FakeRequest({"id": fileId, "version": str(self._drive.versions[fileId])})


class FakePermissions:
    def __init__(self, drive: "FakeDrive"):
        self._drive = drive

    def list(self, fileId: str, fields=None):
        if fileId not in self._drive.shares:
            return FakeRequest(None, error=RuntimeError("404"))
        return FakeRequest({"permissions": self._drive.shares[fileId]})

    def delete(self, fileId: str, permissionId: str):
        self._drive.shares[fileId] = [
            p for p in self._drive.shares[fileId] if p.get("id") != permissionId
        ]
        return FakeRequest({})


class FakeDrive:
    """googleapiclient の Resource のうち、こちらが使う分だけを真似る。"""

    def __init__(self, contents: dict, shares: dict | None = None):
        self.contents = dict(contents)
        self.shares = dict(shares or {})
        self.versions: dict[str, int] = {}

    def files(self):
        return FakeFiles(self)

    def permissions(self):
        return FakePermissions(self)


@pytest.fixture
def store():
    drive = FakeDrive(
        contents={"doc-1": b"%PDF-1.7 original"},
        shares={
            "doc-1": [
                {"id": "p1", "emailAddress": "Kumiaicho@example.test", "type": "user", "role": "writer"},
                {
                    "id": "p2",
                    "emailAddress": "app@project.iam.gserviceaccount.com",
                    "type": "user",
                    "role": "writer",
                },
            ],
            "link-shared": [{"id": "p3", "type": "anyone", "role": "reader"}],
        },
    )
    return DriveDocumentStore(drive), drive


def test_fetch_returns_the_bytes(store):
    document_store, _ = store
    assert document_store.fetch("doc-1") == b"%PDF-1.7 original"


def test_unshared_file_looks_like_a_missing_file(store):
    """共有されていないことを問い合わせ元に教えない（存在の有無を漏らさない）。"""
    document_store, _ = store
    with pytest.raises(DocumentNotFound):
        document_store.fetch("someone-elses-doc")


def test_store_signed_overwrites_the_original(store):
    """別ファイルに逃がさず、原本の新しい版として上書きする。

    逃がすと QR やリンクが指す原本にいつまでも署名が入らない。
    """
    document_store, drive = store
    document_store.store_signed("doc-1", b"%PDF-1.7 signed")

    assert drive.contents["doc-1"] == b"%PDF-1.7 signed"
    assert document_store.fetch("doc-1") == b"%PDF-1.7 signed"


def test_store_signed_reports_the_new_version(store):
    document_store, _ = store
    first = document_store.store_signed("doc-1", b"a")
    second = document_store.store_signed("doc-1", b"b")
    assert first != second


def test_can_read_follows_the_sharing_settings(store):
    """アプリの名簿ではなく Drive の共有設定で決まる。"""
    document_store, _ = store
    assert document_store.can_read("doc-1", "kumiaicho@example.test")  # 大文字小文字は無視
    assert not document_store.can_read("doc-1", "yoso@example.test")


def test_link_shared_file_is_readable_by_anyone(store):
    """「リンクを知っている全員」を選んだのは組織なので、アプリは追認する。"""
    document_store, _ = store
    assert document_store.can_read("link-shared", "dare@example.test")


APP = "app@project.iam.gserviceaccount.com"


def test_revoking_own_access_ends_the_circulation(store):
    """回覧が終わった書類をアプリから見えなくする。

    乗っ取られたときに読まれる範囲を「いま回覧中のもの」に縮めるための操作。
    """
    document_store, drive = store

    assert document_store.revoke_own_access("doc-1", APP) is True
    assert all(p.get("emailAddress") != APP for p in drive.shares["doc-1"])
    # 外したら自分では読めなくなる（他の共有相手はそのまま）
    assert not document_store.can_read("doc-1", APP)
    assert document_store.can_read("doc-1", "kumiaicho@example.test")


def test_revoking_twice_is_harmless(store):
    document_store, _ = store
    assert document_store.revoke_own_access("doc-1", APP) is True
    assert document_store.revoke_own_access("doc-1", APP) is False
