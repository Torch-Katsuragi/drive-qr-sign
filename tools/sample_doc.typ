// 署名欄つき書類のサンプル。
// アプリ本体は Typst に依存しない。これは「PDF が署名欄を自己記述する」仕組みの検証用。

#set page(paper: "a4", margin: 20mm)
#set text(font: ("Yu Gothic", "Meiryo", "Noto Sans CJK JP"), size: 10.5pt, lang: "ja")

// 押印枠。枠を描くと同時に、その位置を metadata として PDF に埋める。
// role をラベル名ではなく metadata の中身に持たせているのがポイント。
// ラベル名に役職を埋める（<sig-組合長>）と、typst query 側が役職名を先に知っていないと引けない。
#let sig-anchor(role, w: 24mm, h: 24mm) = box(width: w, height: h, stroke: 0.5pt + gray)[
  #context [
    #let p = here().position()
    #metadata((
      role: role,
      page: p.page,
      x: p.x.pt(),
      y: p.y.pt(),
      w: w.pt(),
      h: h.pt(),
    )) <sig-anchor>
  ]
  // 枠の外に役職名を置く。枠の中は印影のためにまるごと空けておく
  #place(bottom + center, dy: 4.5mm, text(size: 7pt, fill: gray, role))
]

// QR は署名ページの入口。読むと、その書類の署名ページが開く
#let qr-path = sys.inputs.at("qr", default: none)
#let qr-block(w: 22mm) = box(width: w, height: w)[
  #if qr-path != none { image(qr-path, width: w, height: w) }
]

// 押印枠は右上にあるので、QR は左上へ。重なると読めないし押せない
#place(top + left, qr-block())

#align(center, text(size: 16pt, weight: "bold")[支出調書（サンプル）])

// QR の高さぶん本文を下げる。place は流し込みの外なので、自分で場所を空ける
#v(14mm)

#grid(
  columns: (1fr, auto),
  align: (left + top, right + top),
  [
    起案日: 2026年8月17日 \
    件名: 電子署名ワークフローの動作確認 \
    金額: 金 1,000 円也
  ],
  grid(
    columns: 3,
    column-gutter: 4mm,
    sig-anchor("組合長"),
    sig-anchor("参事"),
    sig-anchor("担当"),
  ),
)

#v(10mm)

これはサンプル書類である。上の枠は押印枠で、同じ座標に空の署名フィールドが注入される。
紙に印刷して回覧し、読了後に QR を読むと、この枠に印影が入る。

#v(40mm)

#align(right, text(size: 8pt, fill: gray)[drive-qr-sign sample])
