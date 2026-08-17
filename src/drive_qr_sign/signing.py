"""署名コア。

pyHanko の薄いラッパで、このアプリが PDF に対して行う操作はここに閉じる。

- 空の署名フィールドを座標指定で注入する（書類のビルド時に一度だけ）
- 空のフィールドに PAdES 署名とタイムスタンプを埋める（署名者がボタンを押したとき）

TSA の URL と署名鍵はいずれも引数で受け取る。どちらを使うかは未決事項なので、
決まっていない間もこのモジュールは書き換えずに済むようにしてある（docs/DESIGN.md 参照）。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps

# 無料の RFC 3161 TSA。プロトタイプの既定値であって、本番の選定結果ではない。
FREE_TSA_URL = "https://freetsa.org/tsr"


@dataclass(frozen=True)
class FieldPlacement:
    """署名欄ひとつ分の置き場所。

    name はそのまま PDF の署名フィールド名になり、アプリ側では役職名として扱う。
    box は PDF の座標系（左下原点・単位 pt）で (x1, y1, x2, y2)。
    """

    name: str
    page: int  # 0 始まり
    box: tuple[float, float, float, float]


def add_signature_fields(
    src: Path | str, dst: Path | str, placements: Iterable[FieldPlacement]
) -> list[str]:
    """空の署名フィールドを注入した PDF を dst に書く。注入したフィールド名を返す。

    増分更新で書くので、元の PDF の中身とページの見た目は一切変わらない。
    """
    names: list[str] = []
    with open(src, "rb") as inf, open(dst, "wb") as outf:
        writer = IncrementalPdfFileWriter(inf)
        for placement in placements:
            fields.append_signature_field(
                writer,
                fields.SigFieldSpec(
                    sig_field_name=placement.name,
                    on_page=placement.page,
                    box=placement.box,
                ),
            )
            names.append(placement.name)
        writer.write(outf)
    return names


def list_signature_fields(src: Path | str, *, filled: bool | None = None) -> list[str]:
    """PDF が持っている署名フィールド名を返す。

    filled=False で「まだ署名されていない欄」だけを取れる。
    アプリはこれと OpenID の検証済みメールを突合して、押せるボタンを決める。
    """
    with open(src, "rb") as inf:
        reader = PdfFileReader(inf)
        return [item[0] for item in fields.enumerate_sig_fields(reader, filled_status=filled)]


def load_signer(key_file: Path | str, cert_file: Path | str, *, key_passphrase: bytes | None = None):
    """PEM の秘密鍵と証明書から署名者を作る。"""
    return signers.SimpleSigner.load(
        str(key_file), str(cert_file), key_passphrase=key_passphrase
    )


def sign_field(
    src: Path | str,
    dst: Path | str | BinaryIO,
    *,
    field_name: str,
    signer,
    tsa_url: str | None = FREE_TSA_URL,
    reason: str | None = None,
    signer_name: str | None = None,
) -> None:
    """既存の空フィールドに PAdES 署名を埋める。

    existing_fields_only=True にしてあるので、指定した名前の空フィールドが無ければ失敗する。
    「アプリが勝手に署名欄を作って署名する」ことが起きないようにするための安全弁。
    """
    timestamper = timestamps.HTTPTimeStamper(tsa_url) if tsa_url else None
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        subfilter=fields.SigSeedSubFilter.PADES,
        reason=reason,
        name=signer_name,
    )
    pdf_signer = signers.PdfSigner(meta, signer=signer, timestamper=timestamper)

    with open(src, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf)
        if hasattr(dst, "write"):
            pdf_signer.sign_pdf(writer, existing_fields_only=True, output=dst)
        else:
            with open(dst, "wb") as outf:
                pdf_signer.sign_pdf(writer, existing_fields_only=True, output=outf)
