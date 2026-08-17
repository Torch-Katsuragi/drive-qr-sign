"""署名コア。

pyHanko の薄いラッパで、このアプリが PDF に対して行う操作はここに閉じる。

- 空の署名フィールドを座標指定で注入する（書類のビルド時に一度だけ）
- 空のフィールドに PAdES 署名とタイムスタンプを埋める（署名者がボタンを押したとき）

TSA の URL と署名鍵はいずれも引数で受け取る。どちらを使うかは未決事項なので、
決まっていない間もこのモジュールは書き換えずに済むようにしてある（docs/DESIGN.md 参照）。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps

# PDF はパスでもストリームでも受ける。web 層はディスクに落とさず BytesIO で渡す
PdfSource = Path | str | BinaryIO
PdfSink = Path | str | BinaryIO


@contextmanager
def _as_stream(target: PdfSource | PdfSink, mode: str) -> Iterator[BinaryIO]:
    if hasattr(target, "read") or hasattr(target, "write"):
        yield target  # type: ignore[misc]
    else:
        with open(target, mode) as stream:  # type: ignore[arg-type]
            yield stream

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
    src: PdfSource, dst: PdfSink, placements: Iterable[FieldPlacement]
) -> list[str]:
    """空の署名フィールドを注入した PDF を dst に書く。注入したフィールド名を返す。

    増分更新で書くので、元の PDF の中身とページの見た目は一切変わらない。
    """
    names: list[str] = []
    with _as_stream(src, "rb") as inf, _as_stream(dst, "wb") as outf:
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


def list_signature_fields(src: PdfSource, *, filled: bool | None = None) -> list[str]:
    """PDF が持っている署名フィールド名を返す。

    filled=False で「まだ署名されていない欄」だけを取れる。
    アプリはこれと OpenID の検証済みメールを突合して、押せるボタンを決める。
    """
    with _as_stream(src, "rb") as inf:
        reader = PdfFileReader(inf)
        return [item[0] for item in fields.enumerate_sig_fields(reader, filled_status=filled)]


def load_signer(key_file: Path | str, cert_file: Path | str, *, key_passphrase: bytes | None = None):
    """PEM の秘密鍵と証明書から署名者を作る。"""
    return signers.SimpleSigner.load(
        str(key_file), str(cert_file), key_passphrase=key_passphrase
    )


def _seal_style(seal):
    """印影だけを描くスタンプ。文字も枠も出さない。

    pyHanko の既定スタンプは「Digitally signed by ...」という英文と人型のアートを描く。
    紙面を従来と同じ見た目に保つのが設計の柱なので、印影以外は出さない。
    """
    if seal is None:
        return None
    from pyhanko import stamp
    from pyhanko.pdf_utils.images import PdfImage
    from pyhanko.pdf_utils.layout import AxisAlignment, InnerScaling, SimpleBoxLayoutRule

    return stamp.StaticStampStyle(
        background=PdfImage(seal),
        border_width=0,
        # 押印枠の中央に、枠いっぱいまで。既定は左上寄せの原寸なので枠と印影がずれる
        background_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MID,
            y_align=AxisAlignment.ALIGN_MID,
            inner_content_scaling=InnerScaling.STRETCH_TO_FIT,
        ),
    )


def _sign(
    src: PdfSource,
    dst: PdfSink,
    *,
    field_name: str,
    signer,
    tsa_url: str | None,
    reason: str | None,
    signer_name: str | None,
    new_field_spec: "fields.SigFieldSpec | None",
    seal=None,
) -> None:
    timestamper = timestamps.HTTPTimeStamper(tsa_url) if tsa_url else None
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        subfilter=fields.SigSeedSubFilter.PADES,
        reason=reason,
        name=signer_name,
    )
    pdf_signer = signers.PdfSigner(
        meta,
        signer=signer,
        timestamper=timestamper,
        new_field_spec=new_field_spec,
        stamp_style=_seal_style(seal),
    )

    with _as_stream(src, "rb") as inf, _as_stream(dst, "wb") as outf:
        writer = IncrementalPdfFileWriter(inf)
        pdf_signer.sign_pdf(
            writer, existing_fields_only=new_field_spec is None, output=outf
        )


def sign_field(
    src: PdfSource,
    dst: PdfSink,
    *,
    field_name: str,
    signer,
    tsa_url: str | None = FREE_TSA_URL,
    reason: str | None = None,
    signer_name: str | None = None,
    seal=None,
) -> None:
    """既存の空フィールドに PAdES 署名を埋める。

    existing_fields_only=True になるので、指定した名前の空フィールドが無ければ失敗する。
    「アプリが押印枠を勝手に作って署名する」ことが起きないようにするための安全弁。

    seal に PIL 画像を渡すと、押印枠にその印影を描く。渡さなければ pyHanko の既定の
    見た目になる（英文と人型のアート）ので、実運用では必ず渡す。
    """
    _sign(
        src,
        dst,
        field_name=field_name,
        signer=signer,
        tsa_url=tsa_url,
        reason=reason,
        signer_name=signer_name,
        new_field_spec=None,
        seal=seal,
    )


def sign_invisible(
    src: PdfSource,
    dst: PdfSink,
    *,
    field_name: str,
    signer,
    tsa_url: str | None = FREE_TSA_URL,
    reason: str | None = None,
    signer_name: str | None = None,
) -> None:
    """押印枠を持たない人の署名。フィールドをその場で作り、紙面には何も出さない。

    box を渡さないので `/Rect [0 0 0 0]` の不可視フィールドになる。
    署名の中身（証明書・タイムスタンプ・改ざん検知）は可視署名とまったく同じで、
    違うのは appearance が無いことだけ。Acrobat の署名パネルには出る。

    フィールド名は呼び出し側が `identity.silent_field_name()` で決める。
    押印枠の名前空間（役職名）とは重ならない。
    """
    _sign(
        src,
        dst,
        field_name=field_name,
        signer=signer,
        tsa_url=tsa_url,
        reason=reason,
        signer_name=signer_name,
        new_field_spec=fields.SigFieldSpec(sig_field_name=field_name),
    )
