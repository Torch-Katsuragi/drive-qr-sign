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


def test_a_stray_newline_in_the_key_does_not_break_anything():
    """鍵の末尾に改行が混ざっても、作る側と確かめる側で食い違わない。

    Secret Manager に `python -c "print(...)" | gcloud ... --data-file=-` で入れると
    末尾に改行が入る。片側だけが取り除くと、署名ページが 403 で開かなくなる。
    """
    from drive_qr_sign.qr import make_mac, verify_mac

    clean, dirty = b"secret-key", b"secret-key" + bytes([13, 10])  # CR LF

    assert make_mac(clean, "doc") == make_mac(dirty, "doc")
    verify_mac(dirty, "doc", make_mac(clean, "doc"))
    verify_mac(clean, "doc", make_mac(dirty, "doc"))


def test_macs_printed_before_the_change_still_open():
    """空白を落とす前の鍵で刷った QR も、そのまま通す。

    落とす扱いに変えた瞬間に、刷ってある QR が一斉に無効になるのを避ける。
    """
    import base64
    import hashlib
    import hmac as hmac_module

    from drive_qr_sign.qr import MAC_BYTES, MAC_VERSION, verify_mac

    dirty = b"secret-key" + bytes([13])  # CR
    raw_digest = hmac_module.new(dirty, f"{MAC_VERSION}:doc".encode(), hashlib.sha256).digest()
    old_mac = base64.urlsafe_b64encode(raw_digest[:MAC_BYTES]).decode("ascii").rstrip("=")

    verify_mac(dirty, "doc", old_mac)  # 刷ってある QR
