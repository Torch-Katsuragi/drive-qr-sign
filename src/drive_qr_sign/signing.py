"""署名コア。

pyHanko の薄いラッパで、このアプリが PDF に対して行う操作はここに閉じる。

- 空の署名フィールドを座標指定で注入する（書類のビルド時に一度だけ）
- 空のフィールドに PAdES 署名とタイムスタンプを埋める（署名者がボタンを押したとき）

TSA の URL と署名鍵はいずれも引数で受け取る。どちらを使うかは未決事項なので、
決まっていない間もこのモジュールは書き換えずに済むようにしてある（docs/DESIGN.md 参照）。
"""

from __future__ import annotations

import io
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps
from pyhanko_certvalidator.registry import SimpleCertificateStore

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


def load_signer_from_pem(key_pem: bytes, cert_pem: bytes, *, key_passphrase: bytes | None = None):
    """PEM の中身そのものから署名者を作る。

    Cloud Run では鍵をファイルとして置かず、Secret Manager から環境変数で受ける。
    ディスクに書き出す工程を作らないためにこちらを使う。

    ⚠この形でも鍵はプロセスのメモリに載る。鍵を持ち出せなくしたいなら KMS に移す
    （呼び出し側から見た形は同じなので、ここを差し替えるだけで済む）。
    """
    from pyhanko import keys

    certs = list(keys.load_certs_from_pemder_data(cert_pem))
    if not certs:
        raise ValueError("証明書を読めなかった")
    return signers.SimpleSigner(
        signing_cert=certs[0],
        signing_key=keys.load_private_key_from_pemder_data(key_pem, passphrase=key_passphrase),
        cert_registry=SimpleCertificateStore.from_certs(certs[1:]),
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


class NotRevocable(Exception):
    """その署名は取り消せない。"""


def list_signatures(pdf: bytes) -> list[tuple[str, str]]:
    """押されている署名の (フィールド名, 署名者) を、押された順に返す。

    紙面に出る押印だけでなく、不可視の署名もここに出る。
    ⚠**紙を見ても不可視署名は分からない**ので、誰が確認したかを人に見せるには
    この一覧が要る（署名パネルを開かせるわけにはいかない）。
    """
    reader = PdfFileReader(io.BytesIO(pdf))
    found = []
    for embedded in reader.embedded_signatures:
        name = embedded.sig_object.get("/Name")
        found.append((embedded.field_name, str(name) if name else ""))
    return found  # 押された順に返る（増分更新の積み順）


def last_signature(pdf: bytes) -> tuple[str, str] | None:
    """最後に押された署名の (フィールド名, 署名者) を返す。無ければ None。

    「最後」はファイルの終端まで覆っているもの。増分更新は積み重なるので、
    いちばん上に積まれた署名だけがファイル全体を覆う。
    """
    reader = PdfFileReader(io.BytesIO(pdf))
    for embedded in reader.embedded_signatures:
        covered = embedded.byte_range[2] + embedded.byte_range[3]
        if covered >= len(pdf.rstrip()):
            name = embedded.sig_object.get("/Name")
            return embedded.field_name, (str(name) if name else "")
    return None


def revoke_last_signature(pdf: bytes, *, expect_signer: str) -> bytes:
    """最後の署名を取り消した PDF を返す。

    署名は増分更新で積まれているので、その署名が入る直前の版まで切り詰めれば消える。

    > [!IMPORTANT] 外せるのは最後の1つだけ
    > 後から押された署名は、先の署名を含めたファイル全体をハッシュしている。
    > 中間の署名だけを抜くと、後の人の署名が壊れる。だから積んだ順にしか外せない。
    """
    reader = PdfFileReader(io.BytesIO(pdf))
    signatures = list(reader.embedded_signatures)
    if not signatures:
        raise NotRevocable("署名が無い")

    end = len(pdf.rstrip())
    top = None
    for embedded in signatures:
        if embedded.byte_range[2] + embedded.byte_range[3] >= end:
            top = embedded
            break
    if top is None:
        raise NotRevocable("最後の署名を特定できない")

    name = top.sig_object.get("/Name")
    if (str(name) if name else "") != expect_signer:
        raise NotRevocable("最後に押したのは別の人")
    if top.signed_revision < 1:
        raise NotRevocable("元の版が無い")

    start = reader.xrefs.get_startxref_for_revision(top.signed_revision - 1)
    marker = pdf.find(b"%%EOF", start)
    if marker < 0:
        raise NotRevocable("直前の版の終端が見つからない")
    return pdf[: marker + len(b"%%EOF")] + bytes([10])
