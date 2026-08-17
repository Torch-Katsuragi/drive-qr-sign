"""QR ペイロードの HMAC。"""

from __future__ import annotations

import pytest

from drive_qr_sign.qr import InvalidPayload, make_mac, sign_url, verify_mac

SECRET = b"test-secret-do-not-use"


def test_roundtrip():
    verify_mac(SECRET, "1AbC_dEf", make_mac(SECRET, "1AbC_dEf"))


def test_other_file_id_is_rejected():
    """1つの正規 QR から、別の書類を指す QR を作れないこと。"""
    with pytest.raises(InvalidPayload):
        verify_mac(SECRET, "別の書類", make_mac(SECRET, "1AbC_dEf"))


def test_other_secret_is_rejected():
    with pytest.raises(InvalidPayload):
        verify_mac(SECRET, "1AbC_dEf", make_mac(b"attacker", "1AbC_dEf"))


def test_mac_is_url_safe():
    mac = make_mac(SECRET, "1AbC_dEf")
    assert "=" not in mac and "+" not in mac and "/" not in mac


def test_sign_url_escapes_file_id():
    url = sign_url("https://example.test/", SECRET, "a/b?c")
    assert url.startswith("https://example.test/s/a%2Fb%3Fc?m=")
