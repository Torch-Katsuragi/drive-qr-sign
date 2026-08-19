"""Cloud KMS の鍵に対応する自己署名証明書を作る。

    python tools/make_kms_cert.py <鍵バージョンのリソース名> [--out secrets/kms-cert.pem]

鍵バージョンのリソース名は次の形（末尾の `/cryptoKeyVersions/1` まで要る）:

    projects/<プロジェクト>/locations/<リージョン>/keyRings/<キーリング>/cryptoKeys/<鍵>/cryptoKeyVersions/1

鍵は KMS から出てこないので、証明書の自己署名も KMS に頼む（`build_self_signed_cert`）。
出来上がるのは公開情報なので、そのまま Secret Manager なり環境変数なりに置いてよい。

⚠自己署名なので Acrobat の署名パネルには「信頼されていない」警告が出る。
消すには AATL 掲載の認証局から証明書を取る必要がある（未決事項）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from drive_qr_sign.kms import build_self_signed_cert  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key_version", help="KMS の鍵バージョンのリソース名")
    parser.add_argument("--out", default="secrets/kms-cert.pem", help="出力先")
    # 証明書に載る名前は導入先ごとに違う。既定値を置くと、直し忘れが証明書に焼き付く
    parser.add_argument("--common-name", required=True, help="証明書の CN（例: 〇〇組合 署名）")
    parser.add_argument("--organization", required=True, help="証明書の O（例: 〇〇組合）")
    parser.add_argument("--days", type=int, default=1095, help="有効期間（日）")
    args = parser.parse_args()

    pem_bytes = build_self_signed_cert(
        args.key_version,
        common_name=args.common_name,
        organization=args.organization,
        valid_days=args.days,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pem_bytes)
    print(f"証明書: {out}")
    print("次: Secret Manager に入れて、SIGNING_KEY_KMS と一緒に Cloud Run へ渡す")


if __name__ == "__main__":
    main()
