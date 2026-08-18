"""署名鍵を Cloud KMS に置いたときの署名者。

PEM を環境変数で受け取る形（`load_signer_from_pem`）では、鍵がプロセスのメモリに載る。
アプリを取られたら鍵そのものを持ち出され、こちらの知らないところで無制限に署名を作れる。

KMS に置くと、鍵は Google 側の金庫から出てこない。アプリができるのは
「このハッシュに署名して」と頼むことだけで、

- 鍵の複製ができない（持ち出しても、アプリを動かせる場所でしか使えない）
- 使ったことが Cloud Audit Logs に残る
- 権限を切れば、その瞬間から署名できなくなる

証明書は鍵とは別物で、こちらは公開情報。KMS の鍵に対応する証明書を作って
（`tools/make_kms_cert.py`）、PEM のまま渡す。

> [!NOTE] 差し替えられるのは pyHanko の Signer が抽象になっているから
> 署名の実体は `async_sign_raw` の1メソッドしかない。ここを KMS 呼び出しに
> 差し替えるだけで、PDF の組み立て・タイムスタンプ・印影は何も変わらない。
"""

from __future__ import annotations

import hashlib

from asn1crypto.algos import SignedDigestAlgorithm
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko_certvalidator.registry import SimpleCertificateStore

# KMS が受け取るダイジェストの名前。pyHanko は "sha256" のような小文字で渡してくる
SUPPORTED_DIGESTS = {"sha256", "sha384", "sha512"}

# ⚠KMS の鍵はアルゴリズムが1つに固定されている（例: RSA_SIGN_PKCS1_3072_SHA256）。
# 何も言わないと pyHanko は鍵長からダイジェストを選び、3072bit には SHA-384 を当てて
# 「その鍵では使えないダイジェストだ」と KMS に断られる（実測）。だからこちらから指定する。
DEFAULT_DIGEST = "sha256"


class KmsSigner(Signer):
    """Cloud KMS の鍵で署名する。鍵はこのプロセスに来ない。"""

    def __init__(
        self,
        key_version_name: str,
        signing_cert,
        *,
        chain=(),
        client=None,
        digest_algorithm: str = DEFAULT_DIGEST,
    ):
        if digest_algorithm not in SUPPORTED_DIGESTS:
            raise ValueError(f"KMS で扱えないダイジェスト: {digest_algorithm}")
        self.digest_algorithm = digest_algorithm
        super().__init__(
            signature_mechanism=SignedDigestAlgorithm({"algorithm": f"{digest_algorithm}_rsa"})
        )
        self.key_version_name = key_version_name
        self._signing_cert = signing_cert
        self._cert_registry = SimpleCertificateStore.from_certs(chain)
        self._client = client

    @property
    def signing_cert(self):
        return self._signing_cert

    @property
    def cert_registry(self):
        return self._cert_registry

    def _kms(self):
        if self._client is None:
            from google.cloud import kms

            self._client = kms.KeyManagementServiceClient()
        return self._client

    async def async_sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) -> bytes:
        digest_algorithm = digest_algorithm.lower()
        if digest_algorithm not in SUPPORTED_DIGESTS:
            raise ValueError(f"KMS で扱えないダイジェスト: {digest_algorithm}")

        if dry_run:
            # 場所取りのための空打ち。長さだけ合っていればよい（鍵と同じ長さになる）
            return bytes(self._signature_size())

        digest = hashlib.new(digest_algorithm, data).digest()
        response = self._kms().asymmetric_sign(
            request={
                "name": self.key_version_name,
                "digest": {digest_algorithm: digest},
            }
        )
        return response.signature

    def _signature_size(self) -> int:
        """署名の長さ（バイト）。証明書の公開鍵から決まる。"""
        public_key = self._signing_cert.public_key
        bit_size = public_key.bit_size
        return (bit_size + 7) // 8


def load_kms_signer(
    key_version_name: str,
    cert_pem: bytes,
    *,
    client=None,
    digest_algorithm: str = DEFAULT_DIGEST,
) -> KmsSigner:
    """KMS の鍵バージョンと、それに対応する証明書（PEM）から署名者を作る。

    digest_algorithm は KMS の鍵のアルゴリズムに合わせる
    （`RSA_SIGN_PKCS1_3072_SHA256` なら sha256）。
    """
    from pyhanko import keys

    certs = list(keys.load_certs_from_pemder_data(cert_pem))
    if not certs:
        raise ValueError("証明書を読めなかった")
    return KmsSigner(
        key_version_name,
        certs[0],
        chain=certs[1:],
        client=client,
        digest_algorithm=digest_algorithm,
    )


def public_key_pem(key_version_name: str, *, client=None) -> str:
    """KMS の鍵の公開鍵を PEM で取る。証明書を作るときに使う。"""
    if client is None:
        from google.cloud import kms

        client = kms.KeyManagementServiceClient()
    return client.get_public_key(request={"name": key_version_name}).pem


# --- 証明書づくり ---------------------------------------------------------
#
# 鍵が KMS の中から出てこないので、証明書もふつうのライブラリでは作れない
# （どれも「秘密鍵を渡してくれれば署名する」形になっている）。
# 中身を自分で組み立てて、署名だけ KMS に頼む。

CERT_DIGEST = "sha256"
CERT_SIGNATURE_ALGORITHM = "sha256_rsa"


def build_self_signed_cert(
    key_version_name: str,
    *,
    common_name: str,
    organization: str,
    country: str = "JP",
    valid_days: int = 1095,
    client=None,
    now=None,
) -> bytes:
    """KMS の鍵に対応する自己署名証明書を作って PEM で返す。

    自己署名なので、証明書自身の署名もその鍵で行う——つまりここでも KMS に頼む。

    ⚠自己署名の証明書は Acrobat に信頼されない（署名パネルに警告が出る）。
    警告を消すには AATL 掲載の認証局から証明書を買う必要がある。それは別の判断。
    """
    import hashlib
    from datetime import datetime, timedelta, timezone

    from asn1crypto import core, keys as asn1keys, pem as asn1pem, x509 as asn1x509

    public_pem = public_key_pem(key_version_name, client=client).encode("ascii")
    _, _, public_der = asn1pem.unarmor(public_pem)
    public_key_info = asn1keys.PublicKeyInfo.load(public_der)

    name = asn1x509.Name.build(
        {"country_name": country, "organization_name": organization, "common_name": common_name}
    )
    started = now or datetime.now(timezone.utc)
    tbs = asn1x509.TbsCertificate(
        {
            "version": "v3",
            # 通し番号は推測できない値にする（同じ鍵で作り直したときの取り違えを防ぐ）
            "serial_number": int.from_bytes(hashlib.sha256(
                f"{key_version_name}{started.isoformat()}".encode("utf-8")
            ).digest()[:16], "big") >> 1,
            "signature": {"algorithm": CERT_SIGNATURE_ALGORITHM},
            "issuer": name,
            "validity": {
                # 1日ぶん前から有効にする。署名する側と検証する側の時計のずれで
                # 「まだ有効になっていない証明書」と言われるのを防ぐ
                "not_before": asn1x509.Time({"utc_time": core.UTCTime(started - timedelta(days=1))}),
                "not_after": asn1x509.Time(
                    {"utc_time": core.UTCTime(started + timedelta(days=valid_days))}
                ),
            },
            "subject": name,
            "subject_public_key_info": public_key_info,
            "extensions": [
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": {"ca": False},
                },
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    # PAdES の署名者証明書は non_repudiation を要求される
                    "extn_value": {"digital_signature", "non_repudiation"},
                },
                {
                    "extn_id": "extended_key_usage",
                    "critical": False,
                    "extn_value": ["email_protection"],
                },
                {
                    "extn_id": "key_identifier",
                    "critical": False,
                    "extn_value": public_key_info.sha1,
                },
            ],
        }
    )

    digest = hashlib.new(CERT_DIGEST, tbs.dump()).digest()
    if client is None:
        from google.cloud import kms

        client = kms.KeyManagementServiceClient()
    signature = client.asymmetric_sign(
        request={"name": key_version_name, "digest": {CERT_DIGEST: digest}}
    ).signature

    certificate = asn1x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": CERT_SIGNATURE_ALGORITHM},
            "signature_value": signature,
        }
    )
    return asn1pem.armor("CERTIFICATE", certificate.dump())
