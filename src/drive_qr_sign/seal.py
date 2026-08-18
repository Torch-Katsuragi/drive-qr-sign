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
        return prepare_uploaded(Path(seal_image).read_bytes())
    if seal_text:
        return render_seal(seal_text)
    return None


# 受け取る画像の上限。押印枠に収まる絵でしかないので、大きい必要がない
MAX_UPLOAD_BYTES = 4 * 1024 * 1024


class UnusableImage(Exception):
    pass


def prepare_uploaded(data: bytes, size: int = 512) -> Image.Image:
    """人が持ち込んだ画像を印影として使える形に整える。

    受け取ったバイト列をそのまま PDF に流さず、必ず開いて描き直す。
    素性の分からない画像を PDF に埋め込むことになるので、ここが実質の検疫になる
    （EXIF や余計なチャンクは再エンコードで落ちる）。

    - 正方形に中央切り抜きしてから縮小する。押印枠は正方形なので、比率を崩すと絵が歪む
    - 透過を持たない画像（Google アカウントのアイコンや写真）は円形に切り抜く。
      四角いまま貼ると枠が塗りつぶされ、紙面の見た目が変わってしまう
    - 元から透過を持つ画像（印影として作られた PNG など）はそのまま。勝手に丸く切らない
    """
    import io

    if len(data) > MAX_UPLOAD_BYTES:
        raise UnusableImage("画像が大きすぎます")
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except Exception as exc:  # PIL は画像形式ごとに別の例外を投げる
        raise UnusableImage("画像として読めません") from exc

    from PIL import ImageOps

    image = ImageOps.exif_transpose(image).convert("RGBA")
    has_alpha = image.getchannel("A").getextrema()[0] < 250

    side = min(image.size)
    left = (image.width - side) // 2
    top = (image.height - side) // 2
    image = image.crop((left, top, left + side, top + side)).resize((size, size), Image.LANCZOS)

    if not has_alpha:
        mask = Image.new("L", (size, size), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
        image.putalpha(mask)
    return image


# 押印枠の上部に置くメールアドレスの帯。押印枠は正方形なので、その割合で切る
CAPTION_BAND = 0.16
# 中立な灰色にする。青みを入れると「紙面に青は出ない」という不変条件が崩れ、
# 既定スタンプ（紫のアート）が混ざっていないことを色で判定できなくなる
CAPTION_COLOR = (85, 85, 85)


def compose_stamp(seal: Image.Image, caption: str, size: int = 512) -> Image.Image:
    """押印枠に入れる絵を組み立てる。上に小さくメールアドレス、その下に印影。

    アカウントのアイコンをそのまま押すと、紙の上では誰の印か分からない。
    印影が生成した丸印なら姓が読めるが、写真では読めない。
    だから誰のものかを紙の上で言えるように、アドレスを添える。

    > [!NOTE] 紙面は従来と同じ、という柱からの小さな逸脱
    > 押印枠の中に文字が1行増える。それでも入れるのは、
    > 「誰が押したか」が紙を見て分かることのほうが実務上効くため。
    """
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    band = int(size * CAPTION_BAND)
    _draw_caption(canvas, caption, band)

    # 残りに印影を収める。正方形を保ったまま中央へ
    room = size - band
    fitted = seal.resize((room, room), Image.LANCZOS)
    canvas.paste(fitted, ((size - room) // 2, band), fitted)
    return canvas


def _draw_caption(canvas: Image.Image, caption: str, band: int) -> None:
    """帯にアドレスを描く。入り切らなければ @ で折って2行にする。"""
    draw = ImageDraw.Draw(canvas)
    width = canvas.width
    lines = [caption]
    if _text_width(caption, band) > width:
        local, _, domain = caption.partition("@")
        if domain:
            lines = [local + "@", domain]

    line_height = band / len(lines)
    for index, line in enumerate(lines):
        font = _caption_font(line, width * 0.96, line_height * 0.92)
        draw.text(
            (width / 2, line_height * (index + 0.5)),
            line,
            font=font,
            fill=CAPTION_COLOR + (255,),
            anchor="mm",
        )


def _text_width(text: str, height: float) -> float:
    font = ImageFont.truetype(str(DEFAULT_FONT), max(4, int(height)))
    left, _, right, _ = font.getbbox(text)
    return right - left


def _caption_font(text: str, max_width: float, max_height: float) -> ImageFont.FreeTypeFont:
    """幅にも高さにも収まる最大の字面。アドレスは長いので、たいてい幅で決まる。"""
    size = max(4, int(max_height))
    font = ImageFont.truetype(str(DEFAULT_FONT), size)
    left, _, right, _ = font.getbbox(text)
    actual = right - left
    if actual > max_width:
        size = max(3, int(size * max_width / actual))
        font = ImageFont.truetype(str(DEFAULT_FONT), size)
    return font
