"""QR に焼く URL のペイロードを HMAC で守る。

QR は紙に印刷されて出回る。誰でも中身を読めるし、書き換えた QR を貼ることもできる。
なので「この URL はこのアプリが発行したものだ」を鍵で示せるようにする。

秘密にするのは鍵だけで、file id は秘密ではない（Drive 側の ACL とアプリ側の突合が
本来のアクセス制御。QR の HMAC はそれとは別の、偽 URL を弾くための層）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import quote

# 鍵を替えたときに古い QR を失効させられるよう、MAC にバージョンを混ぜる
MAC_VERSION = "v1"
MAC_BYTES = 16  # 128bit。紙に載る長さと総当たり耐性の折り合い


class InvalidPayload(Exception):
    """QR の中身が壊れているか、この鍵で発行されたものではない。"""


def _digest(secret: bytes, file_id: str) -> bytes:
    message = f"{MAC_VERSION}:{file_id}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).digest()[:MAC_BYTES]


def make_mac(secret: bytes, file_id: str) -> str:
    """file id に対する MAC を URL に載る形（base64url・パディングなし）で返す。"""
    return base64.urlsafe_b64encode(_digest(secret, file_id)).decode("ascii").rstrip("=")


def verify_mac(secret: bytes, file_id: str, mac: str) -> None:
    """MAC が合わなければ InvalidPayload を投げる。合えば黙って返る。"""
    if not hmac.compare_digest(make_mac(secret, file_id), mac):
        raise InvalidPayload(f"MAC が一致しない: {file_id}")


def sign_url(base_url: str, secret: bytes, file_id: str) -> str:
    """QR に焼く署名ページの URL を組み立てる。

    file id は Drive が採番したもの。`files.generateIds` で先に予約しておけば、
    アップロード前に QR を焼き込める（鶏卵問題の回避）。
    """
    return f"{base_url.rstrip('/')}/s/{quote(file_id, safe='')}?m={make_mac(secret, file_id)}"
