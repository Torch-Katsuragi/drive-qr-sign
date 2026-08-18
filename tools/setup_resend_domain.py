"""記録メールの差出人ドメインを、Resend と Cloud DNS の両方に用意する。

    python tools/setup_resend_domain.py sleeptree.jp            # 何を足すかを見るだけ
    python tools/setup_resend_domain.py sleeptree.jp --apply    # Cloud DNS に足して検証を頼む

やっていること:

1. Resend にドメインを登録する（もう有れば、その情報を取り直す）
2. 返ってきた DNS レコード（DKIM / SPF / バウンス用 MX）を Cloud DNS に足す
3. Resend に「確認して」と頼む

⚠鍵は `secrets/resend-api-key.txt`（.gitignore 済み）に置く。ドメインを登録するので
「Full access」の鍵が要る。送信するだけなら sending 権限で足りるので、
運用に載せる鍵は分けてよい。

⚠Cloud DNS のゾーン `sleeptree-jp`（プロジェクト nemurigi-kobo）には、
Call-Agent が terraform で管理しているレコードが同居している。ここで足すのは
メール用の別レコードなので衝突しないが、terraform 側の管理外になることは覚えておく。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
API_KEY_FILE = REPO_ROOT / "secrets" / "resend-api-key.txt"
API = "https://api.resend.com"
DNS_PROJECT = "nemurigi-kobo"
DNS_ZONE = "sleeptree-jp"
TTL = 300


def api_key() -> str:
    if not API_KEY_FILE.exists():
        raise SystemExit(
            f"{API_KEY_FILE} が無い。resend.com で作った API キーを1行で置く"
        )
    return API_KEY_FILE.read_text(encoding="utf-8").strip()


def register(domain: str, key: str) -> dict:
    """ドメインを登録する。登録済みなら既存のものを引く。"""
    headers = {"Authorization": f"Bearer {key}"}
    created = requests.post(
        f"{API}/domains", headers=headers, json={"name": domain}, timeout=15
    )
    if created.status_code < 400:
        return created.json()

    listed = requests.get(f"{API}/domains", headers=headers, timeout=15)
    listed.raise_for_status()
    for found in listed.json().get("data", []):
        if found.get("name") == domain:
            detail = requests.get(f"{API}/domains/{found['id']}", headers=headers, timeout=15)
            detail.raise_for_status()
            return detail.json()
    raise SystemExit(f"登録も取得もできない: {created.status_code} {created.text}")


def dns_commands(records: list[dict]) -> list[list[str]]:
    """Resend が要求するレコードを gcloud の引数に直す。"""
    commands = []
    for record in records:
        name = record["name"].rstrip(".")
        if not name.endswith("."):
            name = f"{name}."
        value = record["value"]
        if record["type"] == "MX":
            # Resend は優先度を別フィールドで返す
            data = [f"{record.get('priority', 10)} {value.rstrip('.')}."]
        else:
            # TXT は引用符でくくる。255文字を超える DKIM もそのまま通る
            data = [f'"{value}"']
        commands.append(
            [
                "gcloud", "dns", "record-sets", "create", name,
                "--zone", DNS_ZONE, "--project", DNS_PROJECT,
                "--type", record["type"], "--ttl", str(TTL),
                "--rrdatas", ",".join(data),
            ]
        )
    return commands


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    domain = sys.argv[1]
    apply = "--apply" in sys.argv

    key = api_key()
    info = register(domain, key)
    records = info.get("records", [])
    print(f"ドメイン {domain}（id={info.get('id')} / 状態={info.get('status')}）")
    for record in records:
        print(f"  {record['type']:<4} {record['name']}  {record['value'][:60]}")

    for command in dns_commands(records):
        if not apply:
            print("  $ " + " ".join(command))
            continue
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0 and "already exists" not in result.stderr:
            print(result.stderr, file=sys.stderr)
            raise SystemExit("Cloud DNS への追加に失敗した")
        print(f"  ✓ {command[4]} {command[12]}")

    if apply:
        asked = requests.post(
            f"{API}/domains/{info['id']}/verify",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        print(f"検証を依頼: {asked.status_code} {asked.text.strip()[:120]}")
        print("反映まで数分かかる。状態は resend.com のダッシュボードで見る")


if __name__ == "__main__":
    main()
