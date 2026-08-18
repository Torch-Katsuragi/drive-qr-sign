"""回覧を終える。

    python tools/close_circulation.py <file_id> [<file_id> ...]

その書類に対するアプリ（サービスアカウント）の共有を外す。以後アプリはその書類を
読めず、署名ページも開けなくなる。書類は組織の Drive にそのまま残るので、
中身を見るときは Drive で普通に開く。

> [!IMPORTANT] なぜ自動でやらないのか
> 「押印枠が全部埋まったら自動で外す」こともできるが、既定にはしていない。
> 押印枠を持たない人のサイレント署名（確認の記録）は枠と無関係にいつでも起きるので、
> 枠が埋まった瞬間に締め出すと、読了記録を残そうとした人が弾かれる。
> 回覧を終えるのは人の判断であって、枠の数で決まる話ではない。

これを回すのを忘れると、共有されたままの書類が溜まる。溜まった分だけ、
アプリが乗っ取られたときに読まれる範囲が広がる（docs/DESIGN.md）。
"""

from __future__ import annotations

import sys
from pathlib import Path

from drive_qr_sign.drive import DriveDocumentStore, build_service, service_account_email

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVICE_ACCOUNT = REPO_ROOT / "secrets" / "service-account.json"


def main(file_ids: list[str]) -> int:
    if not file_ids:
        print(__doc__)
        return 2
    if not SERVICE_ACCOUNT.exists():
        raise SystemExit(f"{SERVICE_ACCOUNT} が無い")

    own_email = service_account_email(SERVICE_ACCOUNT)
    store = DriveDocumentStore(build_service(SERVICE_ACCOUNT))

    for file_id in file_ids:
        removed = store.revoke_own_access(file_id, own_email)
        state = "共有を外した" if removed else "もともと共有されていない"
        print(f"{file_id}: {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
