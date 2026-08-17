"""署名ページに出す、書類の見た目。

紙で回ってきたものに押すのだから、押す前に中身が見えないと話にならない。
PDF をそのままブラウザに渡す手もあるが、スマホの標準ブラウザは
インラインの PDF を素直に描かない（ダウンロードに落ちる、1ページ目しか出ない等）。
QR から来る人はほぼスマホなので、サーバ側でページ画像に焼いて並べる。

pypdfium2（PDFium）で描くので、署名の appearance——つまり押された印影も、
Acrobat で開いたときと同じように出る。
"""

from __future__ import annotations

import hashlib
import io

DEFAULT_WIDTH = 1100  # 紙の文字が読める程度。回線の細い現場を考えるとこれ以上は上げない


def _digest(pdf: bytes) -> str:
    return hashlib.sha256(pdf).hexdigest()


def page_count(pdf: bytes) -> int:
    import pypdfium2 as pdfium

    document = pdfium.PdfDocument(io.BytesIO(pdf))
    try:
        return len(document)
    finally:
        document.close()


def render_page(pdf: bytes, index: int, width: int = DEFAULT_WIDTH) -> bytes:
    """1ページを PNG にする。同じ PDF の同じページは焼き直さない。"""
    return _render_cached(_digest(pdf), pdf, index, width)


def _render(pdf: bytes, index: int, width: int) -> bytes:
    import pypdfium2 as pdfium

    document = pdfium.PdfDocument(io.BytesIO(pdf))
    try:
        if not 0 <= index < len(document):
            raise IndexError(f"ページが無い: {index}")
        document.init_forms()  # これを呼ばないと署名欄の appearance が描かれない
        page = document[index]
        scale = width / page.get_width()
        image = page.render(scale=scale, draw_annots=True, may_draw_forms=True).to_pil()
    finally:
        document.close()

    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


_CACHE: dict[tuple[str, int, int], bytes] = {}
_CACHE_LIMIT = 64


def _render_cached(digest: str, pdf: bytes, index: int, width: int) -> bytes:
    key = (digest, index, width)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    rendered = _render(pdf, index, width)
    if len(_CACHE) >= _CACHE_LIMIT:
        _CACHE.pop(next(iter(_CACHE)))  # 入った順に捨てる。回覧1件を見るには十分
    _CACHE[key] = rendered
    return rendered
