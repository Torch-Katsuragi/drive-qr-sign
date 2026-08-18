"""押印枠に押す絵の組み立て。"""

from __future__ import annotations

from drive_qr_sign.seal import CAPTION_BAND, compose_stamp, render_seal


def test_caption_sits_above_the_seal():
    """アドレスは上、印影はその下。アイコンだと紙の上で誰か分からないため。"""
    stamp = compose_stamp(render_seal("松本"), "a@example.test", size=400)
    alpha = stamp.getchannel("A")
    band = int(400 * CAPTION_BAND)

    assert any(alpha.getpixel((x, y)) > 8 for x in range(400) for y in range(band))
    # 印影は帯より下にある
    assert any(alpha.getpixel((x, y)) > 8 for x in range(400) for y in range(band, 400))


def test_long_address_is_wrapped_at_the_at_sign():
    """長いアドレスでも幅に収める。切り捨てない。"""
    short = compose_stamp(render_seal("松"), "a@b.jp", size=400)
    long = compose_stamp(render_seal("松"), "matsumoto.katsuaki.kitayama@example.test", size=400)
    assert short.size == long.size == (400, 400)


def test_stamp_keeps_transparency():
    """押印枠の罫線が透けること。"""
    stamp = compose_stamp(render_seal("松"), "a@example.test", size=200)
    assert stamp.mode == "RGBA"
    assert stamp.getpixel((0, 199))[3] == 0  # 左下の角は空いている
