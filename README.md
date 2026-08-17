# drive-qr-sign

紙で回覧した書類の「押印」だけを電子署名に置き換える。書類は Google Drive に置いたまま動かさない。
印刷した QR をスマホで読むと署名ページが開き、Google ログイン後ワンタップで PAdES 署名と
タイムスタンプが PDF に埋まる。

一行で言うと「LibreSign の Google Drive 版」。

```
書類PDFをDriveに配置 → QR付きで印刷して紙で回覧 → 読了後にQRをスマホで読む
  → 署名ページ（Googleログイン）→ アプリがDrive APIでPDF取得 → 内容確認して署名（PAdES + TSA）
```

紙の回覧文化はそのまま残す。ペーパーレスを強制しない。
証跡は PDF 自体に埋まるので、将来このアプリを廃止しても署名済み PDF 単体で検証できる。

## 現状

開発初期。Google ログインと Drive をまだ差していないが、その2つを除けば一周している。

| | 状態 |
|---|---|
| PAdES 署名 + RFC 3161 タイムスタンプ | 動く |
| Typst の押印枠 → 空署名フィールドの自動注入 | 動く |
| QR ペイロードの HMAC | 動く |
| 署名ページ（QR を開く → 自分の欄 → 署名 → 書き戻し） | 動く |
| 複数人が順に署名しても前の署名が残る | 動く |
| 印影の生成（朱色の丸印） | 動く |
| 押印枠を持たない人の不可視署名 | 動く |
| Google ログイン（OIDC） | 未着手（`IdentityProvider` の口だけある） |
| Drive 連携 | 未着手（`DocumentStore` の口だけある） |

設計の詳細は [docs/DESIGN.md](docs/DESIGN.md)。

## 仕組みのかなめ

### PDF が署名欄を自己記述する

署名欄の位置をアプリが持つと、書類の種類が増えるたびにアプリを直すことになる。
そうならないよう、位置は書類側（Typst）に持たせる。

```typst
#let sig-anchor(role, w: 24mm, h: 24mm) = box(width: w, height: h, stroke: 0.5pt + gray)[
  #context [
    #let p = here().position()
    #metadata((role: role, page: p.page, x: p.x.pt(), y: p.y.pt(), w: w.pt(), h: h.pt())) <sig-anchor>
  ]
]
```

役職はラベル名（`<sig-組合長>`）ではなく metadata の中身に入れる。
ラベル名に埋めると、引く側が役職名を先に知っていないと `typst query` できないため。

ビルド時に `typst query` で座標を取り、その位置へ pyHanko で空の署名フィールドを注入する。
フィールド名はそのまま役職名になる。サイドカーファイルは不要で、Acrobat からも標準の署名欄として見える。

アプリが持つのは「メールアドレス → 役職」の対応表だけ。アプリは書類の種類を知らない。

### 印影は生成する。実物の印章は持ち込まない

印影に検証力は無い。真正性は証明書とタイムスタンプが持っていて、印影はただの絵であり、
紙面を従来と同じ見た目に保つためだけに置く。

だから実物の印章の図案は使わない。実印と同じ図案の画像が PDF に載って出回ると、
切り出して他の書類に貼る人が出る。紙の押印をやめたいのに押印の画像だけが流通するのは筋が悪い。

名簿に彫る文字（通常は姓）を書いておくと、朱色の丸印をその場で生成する。
外部サービスには一切問い合わせない。組織が既に電子印影を持っているなら、画像を指定して差し替えられる。

同梱フォントは Shippori Mincho（SIL Open Font License 1.1、
`src/drive_qr_sign/assets/ShipporiMincho-OFL.txt`）。

### 署名者に Drive スコープを要求しない

署名者の OAuth スコープは `openid` + `email` のみ。無料の Gmail アカウントでも、
未審査アプリの警告画面を踏まずに署名できる。

> [!IMPORTANT]
> その代償として、Drive アクセス用の refresh token を導入組織の管理用アカウントから
> 一つ預かる。完全なステートレスではなく、アクセス制御の根拠が
> 「署名者本人の Drive ACL」から「アプリによる突合」に移る。
> 導入前にこの点を理解すること。

## 開発

```powershell
py -3.10 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest
```

サンプル書類をビルドして署名欄を注入する:

```powershell
.venv\Scripts\python.exe tools\build_sample.py
```

署名ページを立てる（Google ログインも Drive も無しで一周できる）:

```powershell
.venv\Scripts\python.exe tools\run_dev.py
```

起動時に署名用の URL を印字する。本人確認は `?as=<メールアドレス>` で偽装する開発専用の実装で、
`tools/` の中にしか無い（偽の認証がライブラリ側に混ざらないようにするため）。

`secrets/` と `out/` は `.gitignore` 済み。
TSA に接続するテストは既定で除外してある（`pytest -m network` で実行）。

## ライセンス

Apache License 2.0（[LICENSE](LICENSE)）。
