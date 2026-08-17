"""署名者が自分で用意した印影の置き場。

このアプリは書類を持たない（DocumentStore 参照）が、印影だけは持つ必要がある。
毎回アップロードさせるわけにはいかないため。とはいえ DB は持ちたくないので、
本番では導入組織の Drive の一角に置く前提で、口だけ切っておく。

置くのは印影の絵だけ。誰がいつ何に署名したかはここには残らない（それは PDF が持つ）。
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Protocol

from PIL import Image

from .seal import prepare_uploaded


class SealStore(Protocol):
    def get(self, email: str) -> Image.Image | None:
        """その人が登録した印影。無ければ None。"""

    def put(self, email: str, data: bytes) -> Image.Image:
        """画像を印影として登録し、整えた結果を返す。"""

    def delete(self, email: str) -> None:
        """登録を取り消す（以後は名簿の指定か生成に戻る）。"""


def _key(email: str) -> str:
    """メールアドレスをそのままファイル名にしない。

    印影の置き場を覗いただけで署名者の一覧が読めてしまうのを避ける。
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:32]


class LocalSealStore:
    """ディレクトリに PNG で置く実装。開発用、および小さい導入向け。"""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, email: str) -> Path:
        return self.root / f"{_key(email)}.png"

    def get(self, email: str) -> Image.Image | None:
        path = self._path(email)
        if not path.is_file():
            return None
        image = Image.open(path)
        image.load()
        return image.convert("RGBA")

    def put(self, email: str, data: bytes) -> Image.Image:
        image = prepare_uploaded(data)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        self._path(email).write_bytes(buffer.getvalue())
        return image

    def delete(self, email: str) -> None:
        self._path(email).unlink(missing_ok=True)
