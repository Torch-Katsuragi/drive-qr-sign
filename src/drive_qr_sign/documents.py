"""書類の取得と書き戻し。

Drive 実装はまだ無い。ここを Protocol にしてあるのは、
「書類はユーザーのストレージに住み、アプリは倉庫を持たない」という設計を
型の側から守るため。アプリ内に書類を溜め込む実装が生えたら、この Protocol が邪魔をする。
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class DocumentNotFound(Exception):
    pass


class DocumentStore(Protocol):
    def fetch(self, file_id: str) -> bytes:
        """署名対象の PDF を丸ごと取ってくる。"""

    def store_signed(self, file_id: str, data: bytes) -> str:
        """署名済み PDF を書き戻し、その版を表す文字列を返す。"""

    def version(self, file_id: str) -> str | None:
        """いまの版。中身を落とさずに「変わっていないか」を確かめるためのもの。

        省略可（実装が無ければ、毎回そのまま取りに行くだけ）。
        """

    def web_url(self, file_id: str) -> str | None:
        """人がその書類を開くための URL。省略可（無ければアプリが PDF を配る）。"""


class LocalDocumentStore:
    """ローカルのディレクトリを Drive の代わりに使う開発用の実装。

    書き戻しは別名保存（`<file_id>.signed.pdf`）。
    元ファイルへの増分更新で Drive の版管理に乗せるかは未決事項（docs/DESIGN.md）。
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)

    def _check(self, file_id: str) -> None:
        # file id をそのままパスにすると ../ で外に出られる
        if "/" in file_id or "\\" in file_id or file_id in {"", ".", ".."}:
            raise DocumentNotFound(f"file id が不正: {file_id!r}")

    def fetch(self, file_id: str) -> bytes:
        """署名済みがあればそちらを返す。

        2人目の署名は1人目の署名が入った PDF に対して行う（PAdES の増分更新で
        先の署名は保たれる）。元ファイルを返すと、後から押した人が
        前の人の署名を消してしまう。
        """
        self._check(file_id)
        for path in (self.root / f"{file_id}.signed.pdf", self.root / f"{file_id}.pdf"):
            if path.is_file():
                return path.read_bytes()
        raise DocumentNotFound(f"見つからない: {file_id}")

    def store_signed(self, file_id: str, data: bytes) -> str:
        self._check(file_id)
        out = self.root / f"{file_id}.signed.pdf"
        out.write_bytes(data)
        return self.version(file_id) or out.name

    def version(self, file_id: str) -> str | None:
        self._check(file_id)
        for path in (self.root / f"{file_id}.signed.pdf", self.root / f"{file_id}.pdf"):
            if path.is_file():
                stat = path.stat()
                return f"{path.name}:{stat.st_mtime_ns}:{stat.st_size}"
        return None
