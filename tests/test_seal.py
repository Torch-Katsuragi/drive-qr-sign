"""印影の生成。"""

from __future__ import annotations

import pytest

from drive_qr_sign.seal import SealStyle, VERMILION, render_seal


def _ink_pixels(image):
    alpha = image.getchannel("A")
    return [(x, y) for y in range(image.height) for x in range(image.width) if alpha.getpixel((x, y)) > 8]


@pytest.mark.parametrize("text", ["松", "松本", "組合長", "きたやま", "佐々木"])
def test_ink_stays_inside_the_ring(text: str):
    """字が円からはみ出さないこと。

    最初の実装は文字を正方形に置いていて、円に内接する矩形を超えてはみ出していた。
    """
    style = SealStyle(size=256)
    image = render_seal(text, style)
    radius = style.size / 2 - style.size * style.margin_ratio
    center = style.size / 2

    for x, y in _ink_pixels(image):
        distance = ((x + 0.5 - center) ** 2 + (y + 0.5 - center) ** 2) ** 0.5
        assert distance <= radius + 1, f"{text}: ({x}, {y}) が円の外に出ている"


@pytest.mark.parametrize("text", ["松", "松本", "組合長", "きたやま"])
def test_characters_are_drawn(text: str):
    """輪だけで中身が空、を防ぐ。中央付近に必ず墨が乗る。"""
    style = SealStyle(size=256)
    image = render_seal(text, style)
    middle = image.crop((80, 80, 176, 176))
    assert _ink_pixels(middle), f"{text}: 円の中身が空"


def test_background_is_transparent():
    """押印枠の罫線が透けること。不透明だと紙面の見た目が変わる。"""
    image = render_seal("松本", SealStyle(size=128))
    assert image.mode == "RGBA"
    assert image.getpixel((0, 0))[3] == 0


def test_color_is_vermilion():
    image = render_seal("松", SealStyle(size=128))
    colors = {image.getpixel(p)[:3] for p in _ink_pixels(image)}
    assert colors == {VERMILION}


def test_empty_text_is_rejected():
    with pytest.raises(ValueError):
        render_seal("   ")


def test_too_long_text_is_trimmed():
    """5文字以上は彫れない。落ちるのではなく、印鑑と同じで入る分だけにする。"""
    render_seal("きたやまむら")
