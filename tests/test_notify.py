"""署名の記録メール。

狙いは通知ではなく、アプリの外（本人の受信箱）に消せない控えを残すこと。
"""

from __future__ import annotations

import base64
import email
import hashlib

import pytest

from drive_qr_sign.notify import (
    GmailNotifier,
    NullNotifier,
    SignatureNotice,
    notify_quietly,
    render_notice,
)

PDF = b"%PDF-1.7 signed bytes"


def make_notice(role: str | None = "組合長") -> SignatureNotice:
    return SignatureNotice.create(
        file_id="1abcDEF", signer_email="signer@example.test", role=role, signed_pdf=PDF
    )


def test_digest_is_of_the_signed_bytes():
    """file id ではなくハッシュを載せる。file id はファイルが変わっても同じで何も固定しない。"""
    assert make_notice().digest == hashlib.sha256(PDF).hexdigest()


def test_body_carries_the_digest_and_the_document():
    subject, body = render_notice(make_notice())
    assert "1abcDEF" in subject
    assert hashlib.sha256(PDF).hexdigest() in body
    assert "https://drive.google.com/file/d/1abcDEF/view" in body
    assert "組合長" in body


def test_silent_signature_is_described_as_a_record():
    _, body = render_notice(make_notice(role=None))
    assert "紙面には出ない署名" in body


class FakeMessages:
    def __init__(self):
        self.sent = []

    def send(self, userId: str, body: dict):
        self.sent.append((userId, body))
        return self

    def execute(self):
        return {"id": "msg-1"}


class FakeGmail:
    def __init__(self):
        self.messages_resource = FakeMessages()

    def users(self):
        return self

    def messages(self):
        return self.messages_resource


def test_gmail_notifier_sends_to_the_signer():
    gmail = FakeGmail()
    GmailNotifier(gmail, sender="no-reply@example.test").notify(make_notice())

    (user_id, body), = gmail.messages_resource.sent
    assert user_id == "me"

    # 日本語を含むので本文は base64 で運ばれる。ヘッダと復号した本文で見る
    message = email.message_from_bytes(base64.urlsafe_b64decode(body["raw"]))
    assert message["To"] == "signer@example.test"
    assert message["From"] == "no-reply@example.test"
    assert hashlib.sha256(PDF).hexdigest() in message.get_payload(decode=True).decode("utf-8")


class BrokenNotifier:
    def notify(self, notice):
        raise RuntimeError("SMTP がこけた")


def test_a_failed_notification_does_not_break_the_signature():
    """署名はもう PDF に埋まって書き戻されている。

    そこでメールが出せなかったからといって失敗を見せると、事実と違ううえに
    再署名を誘発して害になる。
    """
    notify_quietly(BrokenNotifier(), make_notice())  # 例外が外に出ないこと


def test_null_notifier_is_the_default_shape():
    assert NullNotifier().notify(make_notice()) is None
