"""署名鍵を Cloud KMS に置いたときの署名者。

KMS には出ない。手元の鍵で同じ形の応答を返す偽物を差し込んで、
**アプリ側が鍵を触らずに正しい署名を組み立てられること**だけを見る。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from asn1crypto import pem
from asn1crypto import x509 as asn1x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from drive_qr_sign.kms import build_self_signed_cert, load_kms_signer, public_key_pem
from drive_qr_sign.signing import sign_field

KEY_VERSION = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
DIGESTS = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}


class FakeKms:
    """KMS の代わり。鍵はここから外に出ない、という関係だけを再現する。"""

    def __init__(self, private_key):
        self._private_key = private_key
        self.signed = []

    def asymmetric_sign(self, request):
        algorithm, digest = next(iter(request["digest"].items()))
        self.signed.append((request["name"], algorithm))
        signature = self._private_key.sign(
            digest, padding.PKCS1v15(), Prehashed(DIGESTS[algorithm])
        )
        return type("Response", (), {"signature": signature})()

    def get_public_key(self, request):
        pem_text = self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        return type("Response", (), {"pem": pem_text})()


def _fake_kms(key_file: Path) -> FakeKms:
    return FakeKms(serialization.load_pem_private_key(key_file.read_bytes(), password=None))


def _validation_context(cert_file: Path) -> ValidationContext:
    _, _, der = pem.unarmor(cert_file.read_bytes())
    return ValidationContext(
        trust_roots=[asn1x509.Certificate.load(der)],
        allow_fetching=False,
        revocation_mode="soft-fail",
    )


def test_a_document_signed_through_kms_validates(fields_pdf: Path, dev_cert, tmp_path: Path):
    """KMS 越しに署名しても、出来上がる PDF は同じように検証を通ること。"""
    key, cert = dev_cert
    kms = _fake_kms(key)
    signer = load_kms_signer(KEY_VERSION, cert.read_bytes(), client=kms)

    out = tmp_path / "signed.pdf"
    sign_field(fields_pdf, out, field_name="組合長", signer=signer, tsa_url=None)

    with open(out, "rb") as inf:
        embedded = PdfFileReader(inf).embedded_signatures[0]
        status = validate_pdf_signature(embedded, signer_validation_context=_validation_context(cert))
        assert status.intact and status.valid and status.trusted
        assert status.coverage.name == "ENTIRE_FILE"

    # 署名の実体は KMS に頼んでいる（場所取りの空打ちを除いて1回）
    assert kms.signed and all(name == KEY_VERSION for name, _ in kms.signed)


def test_the_key_itself_never_reaches_the_signer(dev_cert):
    """署名者は鍵を持たない。持っているのは鍵の**名前**と証明書だけ。"""
    key, cert = dev_cert
    signer = load_kms_signer(KEY_VERSION, cert.read_bytes(), client=_fake_kms(key))

    secrets = [
        value
        for value in vars(signer).values()
        if isinstance(value, (bytes, str)) and "PRIVATE KEY" in str(value)
    ]
    assert not secrets
    assert signer.key_version_name == KEY_VERSION


def test_the_placeholder_matches_the_real_signature_length(dev_cert):
    """場所取りの空打ちと本物の長さが違うと、署名の埋め込みが壊れる。"""
    key, cert = dev_cert
    signer = load_kms_signer(KEY_VERSION, cert.read_bytes(), client=_fake_kms(key))

    placeholder = asyncio.run(signer.async_sign_raw(b"x", "sha256", dry_run=True))
    real = asyncio.run(signer.async_sign_raw(b"x", "sha256"))
    assert len(placeholder) == len(real)


def test_the_public_key_can_be_read_for_making_a_certificate(dev_cert):
    """証明書を作るために、鍵の公開側だけを取り出せること。"""
    key, cert = dev_cert
    text = public_key_pem(KEY_VERSION, client=_fake_kms(key))
    assert text.startswith("-----BEGIN PUBLIC KEY-----")


def test_the_certificate_for_a_kms_key_is_signed_by_that_key(dev_cert):
    """鍵が KMS から出てこない以上、証明書の自己署名も KMS に頼むしかない。

    出来上がりが「自分の公開鍵で自分の署名を検証できる」証明書になっていること。
    """
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

    key, _ = dev_cert
    pem_bytes = build_self_signed_cert(
        KEY_VERSION,
        common_name="ねむりぎ工房 署名",
        organization="ねむりぎ工房",
        client=_fake_kms(key),
    )

    certificate = crypto_x509.load_pem_x509_certificate(pem_bytes)
    certificate.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        crypto_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    usage = certificate.extensions.get_extension_for_class(crypto_x509.KeyUsage).value
    # PAdES の署名者証明書に要る2つ
    assert usage.digital_signature and usage.content_commitment


def test_a_kms_certificate_can_be_used_to_sign(fields_pdf: Path, dev_cert, tmp_path: Path):
    """作った証明書で、そのまま署名まで通ること（証明書と鍵が食い違っていない）。"""
    key, _ = dev_cert
    kms = _fake_kms(key)
    pem_bytes = build_self_signed_cert(
        KEY_VERSION, common_name="ねむりぎ工房 署名", organization="ねむりぎ工房", client=kms
    )

    out = tmp_path / "signed.pdf"
    sign_field(
        fields_pdf,
        out,
        field_name="組合長",
        signer=load_kms_signer(KEY_VERSION, pem_bytes, client=kms),
        tsa_url=None,
    )

    with open(out, "rb") as inf:
        embedded = PdfFileReader(inf).embedded_signatures[0]
        assert embedded.field_name == "組合長"
