"""署名者が誰で、どの欄を押せるのか。

アプリが持つ業務知識はここだけ——署名者名簿という一枚の表。
どの書類にどの欄があるかは PDF 側が知っている（docs/DESIGN.md）。

名簿は「メールアドレス → 役職（省略可）」で、3つの状態を表す。

| 名簿 | 役職 | 押すとどうなるか |
|---|---|---|
| いる | あり | その役職の欄に印影が乗る |
| いる／いない | なし | 不可視署名がサイレントで付く（紙面は変わらない） |

Drive で共有されていない人は、そもそもこの画面まで来られない。

名簿はアクセス制御ではない。「この書類を見てよいか」は Drive の共有設定が決める
（`DriveDocumentStore.can_read`）。名簿が決めるのは、どの押印枠を押せるかだけ。

本人性は Google の OpenID で検証済みのメールアドレスに委ねる。
`email_verified` が false の ID トークンを通さないことは、OIDC 実装側の責任。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class NotSignedIn(Exception):
    pass


class IdentityProvider(Protocol):
    def verified_email(self, request) -> str | None:
        """ログイン済みなら検証済みメールアドレス、未ログインなら None。"""


@dataclass(frozen=True)
class SignerEntry:
    """名簿の1行。

    role が None の人は押印枠を持たず、押すとサイレント署名になる。
    seal_text は印影に彫る文字（通常は姓）。seal_image を置けば生成せずその画像を使う。
    """

    role: str | None = None
    seal_text: str | None = None
    seal_image: Path | str | None = None


class SignerDirectory:
    """署名者名簿。役職だけを書きたいときは文字列、押印枠を持たない人は None でよい。"""

    def __init__(self, mapping: dict[str, SignerEntry | str | None]):
        # メールアドレスの大文字小文字は本人性の判定に使わない
        self._by_email = {
            email.strip().lower(): _as_entry(value) for email, value in mapping.items()
        }

    def knows(self, email: str) -> bool:
        return email.strip().lower() in self._by_email

    def entry_for(self, email: str) -> SignerEntry | None:
        return self._by_email.get(email.strip().lower())

    def role_for(self, email: str) -> str | None:
        entry = self.entry_for(email)
        return entry.role if entry else None

    def seal_image_for(self, email: str):
        """組織が名簿で指定した印影画像。指定が無ければ None。

        生成はここではやらない。生成まで返すと、Google アカウントのアイコンに
        出番が来なくなる（アイコンのほうが既定であってほしい）。
        """
        from .seal import prepare_uploaded

        entry = self.entry_for(email)
        if entry is None or not entry.seal_image:
            return None
        return prepare_uploaded(Path(entry.seal_image).read_bytes())

    def seal_text_for(self, email: str) -> str | None:
        """印影に彫る文字。名簿に無ければ役職で代用する。"""
        entry = self.entry_for(email)
        if entry is None:
            return None
        return entry.seal_text or entry.role

    def emails_for(self, role: str) -> list[str]:
        return [email for email, entry in self._by_email.items() if entry.role == role]

    def __len__(self) -> int:
        return len(self._by_email)


def _as_entry(value: SignerEntry | str | None) -> SignerEntry:
    if isinstance(value, SignerEntry):
        return value
    return SignerEntry(role=value)


# サイレント署名のフィールド名は専用の名前空間に閉じる。
# 役職名と衝突しないので、割当の無い人が「組合長」欄を作って署名する経路が生まれない。
SILENT_FIELD_PREFIX = "silent-"


def silent_field_name(email: str) -> str:
    """その人のサイレント署名フィールド名。

    メールアドレスそのものを PDF に晒さないようハッシュにする（署名の中身には名前が入る）。
    同じ人は同じ名前になるので、二重のサイレント署名は名前の重複として弾ける。
    """
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return f"{SILENT_FIELD_PREFIX}{digest[:16]}"
