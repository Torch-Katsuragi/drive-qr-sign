"""本人が用意した印影の登録。"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from drive_qr_sign.seal import MAX_UPLOAD_BYTES, UnusableImage, prepare_uploaded
from drive_qr_sign.seal_store import LocalSealStore


def _png(color=(30, 120, 200, 255), size=(300, 200)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGBA", size, color).save(buffer, format="PNG")
    return buffer.getvalue()


def test_opaque_image_is_cropped_to_a_circle():
    """写真やアイコンを四角いまま貼ると押印枠が塗りつぶされる。"""
    image = prepare_uploaded(_png(), size=100)
    assert image.getpixel((50, 50))[3] == 255  # 中心は残る
    assert image.getpixel((0, 0))[3] == 0  # 角は抜ける


def test_transparent_image_is_left_alone():
    """印影として作られた PNG を勝手に丸く切らない。"""
    source = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    source.paste((200, 0, 0, 255), (0, 0, 20, 20))  # 左上の角にだけ描く
    buffer = io.BytesIO()
    source.save(buffer, format="PNG")

    image = prepare_uploaded(buffer.getvalue(), size=100)
    assert image.getpixel((5, 5))[3] == 255  # 角が残っている＝丸く切られていない


def test_non_square_image_is_centre_cropped():
    image = prepare_uploaded(_png(size=(400, 100)), size=64)
    assert image.size == (64, 64)


def test_garbage_is_rejected():
    with pytest.raises(UnusableImage):
        prepare_uploaded(b"this is not an image")


def test_oversized_upload_is_rejected():
    with pytest.raises(UnusableImage):
        prepare_uploaded(b"\x89PNG" + b"\0" * MAX_UPLOAD_BYTES)


def test_store_roundtrip(tmp_path):
    store = LocalSealStore(tmp_path)
    assert store.get("a@example.test") is None

    store.put("A@example.test", _png())
    assert store.get("a@example.test") is not None  # 大文字小文字は同一人物

    store.delete("a@example.test")
    assert store.get("a@example.test") is None


def test_stored_file_name_does_not_leak_the_address(tmp_path):
    """置き場を覗いただけで署名者の一覧が読めないこと。"""
    store = LocalSealStore(tmp_path)
    store.put("himitsu@example.test", _png())
    names = [p.name for p in tmp_path.iterdir()]
    assert names and all("himitsu" not in name for name in names)
