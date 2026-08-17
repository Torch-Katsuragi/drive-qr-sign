"""印影を作る。

印影に検証力は無い。真正性は証明書とタイムスタンプが持っていて、これはただの絵で、
紙面を従来と同じ見た目に保つためだけに置く（docs/DESIGN.md の二層構成）。

だからこそ実物の印章の図案は持ち込まない。実印と同じ図案の画像が PDF に載って出回ると、
切り出して他の書類に貼る人が出る。紙の押印をやめたいのに押印の画像だけが流通するのは筋が悪い。
ここで作る印影は、このアプリが生成した専用の図案であって、実在の印章とは無関係。

組織が既に電子印影を持っているなら、生成せずその画像を使う口もある（`seal_image` 指定）。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ASSETS = Path(__file__).parent / "assets"

# 同梱フォント。SIL Open Font License 1.1（assets/ShipporiMincho-OFL.txt）
DEFAULT_FONT = ASSETS / "ShipporiMincho-Regular.ttf"

# 朱肉の色
VERMILION = (199, 17, 44)


@dataclass(frozen=True)
class SealStyle:
    size: int = 512  # 一辺の画素数。PDF には座標で置くので解像度の目安でしかない
    color: tuple[int, int, int] = VERMILION
    ring_ratio: float = 0.055  # 外周の太さ（直径比）
    margin_ratio: float = 0.02
    fill_ratio: float = 0.94  # 内接矩形をどこまで使うか。1.0 だと字が輪に触れる
    gutter_ratio: float = 0.06  # 隣の字との間隔（マス比）
    font_path: Path = DEFAULT_FONT


def _cells(count: int) -> list[tuple[int, int, int, int]]:
    """文字を置く格子を (列数, 行数, 列index, 行index) の並びで返す。

    縦書きで右から左へ読む、印鑑の伝統的な配置に合わせる。
    3文字は右列に2文字・左列に1文字（4分割して1マス空ける形にはしない）。
    """
    if count <= 1:
        return [(1, 1, 0, 0)]
    if count == 2:
        return [(1, 2, 0, 0), (1, 2, 0, 1)]
    if count == 3:
        # 右列に1・2文字目、左列に3文字目（左列は中央に置く）
        return [(2, 2, 1, 0), (2, 2, 1, 1), (2, 1, 0, 0)]
    return [(2, 2, 1, 0), (2, 2, 1, 1), (2, 2, 0, 0), (2, 2, 0, 1)][:count]


def render_seal(text: str, style: SealStyle = SealStyle()) -> Image.Image:
    """朱色の丸印を描いて返す。背景は透過なので、押印枠の罫線が透ける。

    text は通常は姓。4文字を超える場合は先頭4文字に切る（印鑑と同じで、収まらないものは彫れない）。
    """
    text = text.strip()[:4]
    if not text:
        raise ValueError("印影に彫る文字が無い")

    size = style.size
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    ring = max(1, round(size * style.ring_ratio))
    margin = round(size * style.margin_ratio)
    box = (margin + ring // 2, margin + ring // 2, size - margin - ring // 2, size - margin - ring // 2)
    draw.ellipse(box, outline=style.color + (255,), width=ring)

    cells = _cells(len(text))
    grid_cols = max(c for c, _, _, _ in cells)
    grid_rows = max(r for _, r, _, _ in cells)

    # 円に内接する最大の矩形を、字組みの縦横比で取る（w:h = 列数:行数、w²+h² = 直径²）
    diameter = size - 2 * margin - 2 * ring
    diagonal = (grid_cols**2 + grid_rows**2) ** 0.5
    block_w = diameter * grid_cols / diagonal * style.fill_ratio
    block_h = diameter * grid_rows / diagonal * style.fill_ratio
    left = (size - block_w) / 2
    top = (size - block_h) / 2

    for char, (cols, rows, col, row) in zip(text, cells):
        # 列数・行数はマスごとに違う（3文字のとき左列は1行ぶんの高さを使う）
        cell_w = block_w / cols
        cell_h = block_h / rows
        gutter_w = cell_w * style.gutter_ratio
        gutter_h = cell_h * style.gutter_ratio
        glyph = _stretched_glyph(
            char,
            style.font_path,
            round(cell_w - gutter_w),
            round(cell_h - gutter_h),
        )
        image.paste(
            style.color + (255,),
            (round(left + cell_w * col + gutter_w / 2), round(top + cell_h * row + gutter_h / 2)),
            glyph,
        )

    return image


def _stretched_glyph(char: str, font_path: Path, width: int, height: int) -> Image.Image:
    """字をマスいっぱいに引き伸ばしたマスク画像を作る。

    等倍で置くと字ごとに大きさが揃わず、円の中に隙間が残る。実際の印鑑も字を
    長方形に変形して詰めているので、それに倣ってマスに合わせて伸縮させる。
    """
    canvas = 512
    mask = Image.new("L", (canvas, canvas), 0)
    ImageDraw.Draw(mask).text(
        (canvas / 2, canvas / 2),
        char,
        font=ImageFont.truetype(str(font_path), int(canvas * 0.8)),
        fill=255,
        anchor="mm",
    )
    ink = mask.getbbox()  # 実際に墨が乗った範囲だけを取る（字の余白は無視する）
    if ink:
        mask = mask.crop(ink)
    return mask.resize((max(1, width), max(1, height)), Image.LANCZOS)


def seal_for(seal_text: str | None, seal_image: Path | str | None = None) -> Image.Image | None:
    """名簿の1行から印影を作る。画像が指定されていればそちらを優先する。"""
    if seal_image:
        return Image.open(seal_image).convert("RGBA")
    if seal_text:
        return render_seal(seal_text)
    return None
