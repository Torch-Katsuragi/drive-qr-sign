"""書類の取得と書き戻し。

Drive 実装はまだ無い。ここを Protocol にしてあるのは、
「書類はユーザーのストレージに住み、アプリは倉庫を持たない」という設計を
型の側から守るため。アプリ内に書類を溜め込む実装が生えたら、この Protocol が邪魔をする。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class DocumentNotFound(Exception):
    pass


@dataclass(frozen=True)
class SharedDocument:
    """一覧に並べる1件。中身は落とさず、名前とハッシュだけを持つ。"""

    file_id: str
    name: str
    content_hash: str | None = None


class DocumentStore(Protocol):
    def fetch(self, file_id: str) -> bytes:
        """署名対象の PDF を丸ごと取ってくる。"""

    def store_signed(self, file_id: str, data: bytes) -> str:
        """署名済み PDF を書き戻し、その版を表す文字列を返す。"""

    def content_hash(self, file_id: str) -> str | None:
        """いまの中身のハッシュ。落とさずに「同じ中身か」を確かめるためのもの。

        省略可（実装が無ければ、毎回そのまま取りに行くだけ）。
        """

    def web_url(self, file_id: str) -> str | None:
        """人がその書類を開くための URL。省略可（無ければアプリが PDF を配る）。"""

    def shared_with(self, email: str) -> list[SharedDocument]:
        """その人が見られる PDF の一覧。省略可（無ければ一覧画面は使えない）。

        ⚠ここが「一覧に出してよいか」の判定そのもの。返したものは、その人に
        見せてよい書類として扱われる。
        """


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
        return out.name

    def shared_with(self, email: str) -> list[SharedDocument]:
        """置いてある書類を全部返す。

        ローカルには共有設定が無いので、誰に対しても全件になる。開発用サーバでは
        名簿に載っている人だけがログインできる前提で、それで足りる。
        """
        found = []
        for path in sorted(self.root.glob("*.pdf")):
            if path.name.endswith(".signed.pdf"):
                continue
            file_id = path.stem
            found.append(SharedDocument(file_id, path.name, self.content_hash(file_id)))
        return found

    def content_hash(self, file_id: str) -> str | None:
        import hashlib

        self._check(file_id)
        for path in (self.root / f"{file_id}.signed.pdf", self.root / f"{file_id}.pdf"):
            if path.is_file():
                return hashlib.md5(path.read_bytes()).hexdigest()
        return None
