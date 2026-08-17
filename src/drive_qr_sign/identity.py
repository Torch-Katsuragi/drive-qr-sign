"""署名者が誰で、どの欄を押せるのか。

アプリが持つ業務知識はここだけ——署名者名簿という一枚の表。
どの書類にどの欄があるかは PDF 側が知っている（docs/DESIGN.md）。

名簿は「メールアドレス → 役職（省略可）」で、3つの状態を表す。

| 名簿 | 役職 | 押すとどうなるか |
|---|---|---|
| いる | あり | その役職の欄に印影が乗る |
| いる | なし | 不可視署名がサイレントで付く（紙面は変わらない） |
| いない | — | 押せない |

名簿を持つ理由は順番の管理ではない。このアプリは Drive を導入組織の管理用アカウントで
読むので、署名者本人の Drive ACL が効かない。名簿がアクセス制御そのものになる。
紙に刷った QR の URL は秘密として扱えないことに注意（docs/DESIGN.md の代償の節）。

本人性は Google の OpenID で検証済みのメールアドレスに委ねる。
`email_verified` が false の ID トークンを通さないことは、OIDC 実装側の責任。
"""

from __future__ import annotations

import hashlib
from typing import Protocol


class NotSignedIn(Exception):
    pass


class IdentityProvider(Protocol):
    def verified_email(self, request) -> str | None:
        """ログイン済みなら検証済みメールアドレス、未ログインなら None。"""


class SignerDirectory:
    """署名者名簿。値が None の人は役職を持たない（サイレント署名のみ）。"""

    def __init__(self, mapping: dict[str, str | None]):
        # メールアドレスの大文字小文字は本人性の判定に使わない
        self._by_email = {email.strip().lower(): role for email, role in mapping.items()}

    def knows(self, email: str) -> bool:
        return email.strip().lower() in self._by_email

    def role_for(self, email: str) -> str | None:
        return self._by_email.get(email.strip().lower())

    def emails_for(self, role: str) -> list[str]:
        return [email for email, r in self._by_email.items() if r == role]

    def __len__(self) -> int:
        return len(self._by_email)


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
