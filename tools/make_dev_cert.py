"""開発用の自己署名証明書を作る。

本番の鍵ではない。Acrobat は自己署名の証明書を信頼しないので署名パネルに警告が出る。
証明書をどうするか（自己署名で通すか AATL 掲載 CA から買うか）は未決事項。

    python tools/make_dev_cert.py [出力ディレクトリ]

既定の出力先は secrets/（.gitignore 済み）。
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_dev_cert(out_dir: Path, common_name: str = "drive-qr-sign development") -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "dev-key.pem"
    cert_path = out_dir / "dev-cert.pem"

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "drive-qr-sign"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                # PAdES の署名者証明書は non_repudiation（content_commitment）を要求される
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("secrets")
    key, cert = make_dev_cert(target)
    print(f"key : {key}")
    print(f"cert: {cert}")
