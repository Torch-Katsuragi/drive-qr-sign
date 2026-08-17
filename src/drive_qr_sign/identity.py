"""署名者が誰で、どの欄を押せるのか。

アプリが持つ業務知識はここだけ——「メールアドレス → 役職」の一枚の対応表。
どの書類にどの欄があるかは PDF 側が知っている（docs/DESIGN.md）。

本人性は Google の OpenID で検証済みのメールアドレスに委ねる。
`email_verified` が false の ID トークンを通さないことは、OIDC 実装側の責任。
"""

from __future__ import annotations

from typing import Protocol


class NotSignedIn(Exception):
    pass


class IdentityProvider(Protocol):
    def verified_email(self, request) -> str | None:
        """ログイン済みなら検証済みメールアドレス、未ログインなら None。"""


class RoleDirectory:
    """メールアドレスと役職の対応表。"""

    def __init__(self, mapping: dict[str, str]):
        # メールアドレスの大文字小文字は本人性の判定に使わない
        self._by_email = {email.strip().lower(): role for email, role in mapping.items()}

    def role_for(self, email: str) -> str | None:
        return self._by_email.get(email.strip().lower())

    def emails_for(self, role: str) -> list[str]:
        return [email for email, r in self._by_email.items() if r == role]

    def __len__(self) -> int:
        return len(self._by_email)
