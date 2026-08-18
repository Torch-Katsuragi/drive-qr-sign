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

開発初期。QR から署名して Drive に書き戻すところまで、実物の Drive で通っている。

| | 状態 |
|---|---|
| PAdES 署名 + RFC 3161 タイムスタンプ | 動く |
| Typst の押印枠 → 空署名フィールドの自動注入 | 動く |
| QR ペイロードの HMAC | 動く |
| 署名ページ（QR を開く → 自分の欄 → 署名 → 書き戻し） | 動く |
| 複数人が順に署名しても前の署名が残る | 動く |
| 印影（画像の登録・生成） | 動く |
| 押印枠を持たない人の不可視署名 | 動く |
| Google ログイン（OIDC・PKCE つき） | 動く |
| Drive 連携（取得・書き戻し・共有設定での閲覧判定） | 動く |
| 署名の記録メール（オプション） | 動く（送信アカウントの用意は導入時） |

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

### 印影は本人が選ぶ。生成はいちばん後ろ

印影に検証力は無い。真正性は証明書とタイムスタンプが持っていて、印影はただの絵であり、
紙面を従来と同じ見た目に保つためだけに置く。

押印枠に何を出すかは、この順で決まる。

1. 本人が `/seal` で登録した画像（手元の画像のアップロード、または Google アカウントのアイコン）
2. 名簿に組織が指定した画像
3. 名簿の文字から生成した丸印（文字が無ければ役職から）

生成は「何も用意しなかった人」のための最後の受け皿。本人が用意した絵があるなら、そちらが本人らしい。

持ち込まれた画像はそのまま PDF に流さず、必ず開いて描き直す。素性の分からない画像を
PDF に埋め込むことになるので、ここが検疫にあたる。透過を持たない画像（写真・アイコン）は
丸く切り抜く。四角いまま貼ると押印枠が塗りつぶされ、紙面の見た目が変わってしまうため。

なお実物の印章をスキャンした画像は勧めない。実印と同じ図案が PDF に載って出回ると、
切り出して他の書類に貼る人が出る。紙の押印をやめたいのに押印の画像だけが流通するのは筋が悪い。

生成に使う同梱フォントは Shippori Mincho（SIL Open Font License 1.1、
`src/drive_qr_sign/assets/ShipporiMincho-OFL.txt`）。

### アクセス制御は Drive の共有設定に任せる

「この人は書類を見てよいか」をアプリの名簿で決めない。**サービスアカウントに共有された書類だけ**を
アプリが触れ、**誰が見られるか**は Drive の共有設定（`permissions.list`）に従う。
名簿が持つのは「メールアドレス → 役職」だけで、これは決裁の割り当てであってアクセス制御ではない。

署名済みは**原本の新しい版として書き戻す**。別ファイルに逃がすと原本と署名済みが割れて、
QR やリンクが指す原本にいつまでも署名が入らない。

> [!WARNING] サービスアカウントが乗っ取られたときの被害範囲
> 共有されている書類は読まれるし上書きもされる。これは署名をサーバでやる以上避けられない。
> 狭めるのは ①共有を回覧期間に限る ②署名鍵は KMS に置いて持ち出せなくする
> ③署名要求をアプリが消せない場所に記録する、の3つ。消された場合の復元は Google Vault に委ねる。

回覧が終わったら、その書類への共有を外す。

```powershell
.venv\Scripts\python.exe tools\close_circulation.py <file_id>
```

「押印枠が全部埋まったら自動で外す」ことはしていない。押印枠を持たない人の確認記録は
枠と無関係にいつでも起きるので、枠が埋まった瞬間に締め出すと読了記録を残せなくなる。
回覧を終えるのは人の判断であって、枠の数で決まる話ではない。

### 署名の記録は、アプリの外にも残す

署名のあと、本人へ確認のメールを送れる（オプション）。狙いは通知ではなく、
**アプリが消せない場所に控えを作ること**にある。

Workspace のドメインから送ったメールには DKIM 署名が付き、受信者の手元のコピーにも残る。
署名者は「このドメインが確かにこの内容を送った」を、こちらの協力なしに証明できる。
送信履歴は組織、受信履歴は本人。どちらも一方的には両方を消せない。

本文に載せるのは file id ではなく**署名済み PDF の SHA-256** にする。
file id はファイルが変わっても同じで何も固定しないが、ハッシュなら
「このバイト列がこの人の署名で確定した」というドメイン署名付きの宣言になる。

> [!WARNING] メール送信能力はアプリの被害範囲を広げる
> 乗っ取られれば組織のドメインからフィッシングを撒ける。送信専用アカウント（`no-reply@`）の
> 資格情報だけを持たせ、スコープは `gmail.send` に限る。
> サービスアカウントの代理送信（domain-wide delegation）は使わない——
> ドメイン内の誰にでもなりすませてしまうため。

証明できるのは「通知された」ことまでで、「本人が押した」ことではない。

### 署名者に Drive スコープを要求しない

署名者の OAuth スコープは `openid` + `email` のみ。無料の Gmail アカウントでも、
未審査アプリの警告画面を踏まずに署名できる。

署名者が Drive の権限をアプリに渡さないので、アプリが署名者の代わりに Drive を触ることはない。
アプリが持つのは自分のサービスアカウントだけで、そこに何が見えるかは組織の共有設定が決める。

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

起動時に署名用の URL を印字する。

### Google ログインを繋ぐ

`secrets/oauth-client.json` があれば本物の Google ログインになり、無ければ
`?as=<メールアドレス>` で名乗れる開発専用の身元確認になる（この偽の実装は `tools/` の中にしか無い）。

1. Google Cloud コンソールで OAuth クライアント（ウェブ アプリケーション）を作る
2. 承認済みリダイレクト URI に `http://localhost:8765/oauth2/callback` を入れる。
   Google はループバックだけを特別扱いするので、手元では http のままで通る
3. クライアントの詳細から JSON をダウンロードし、`secrets/oauth-client.json` に置く

同意画面のスコープは `openid` と `email` だけでよい。
Google アカウントのアイコンを印影に使いたい場合のみ `profile` を足す。

### Drive を繋ぐ

`secrets/service-account.json` と `secrets/dev-drive.json` の両方があれば本物の Drive を使い、
無ければローカルのディレクトリを倉庫にする。

```powershell
gcloud iam service-accounts create drive-qr-sign --project <PROJECT>
gcloud iam service-accounts keys create secrets\service-account.json `
  --iam-account drive-qr-sign@<PROJECT>.iam.gserviceaccount.com
```

そのうえで、署名させたい PDF を Drive でそのサービスアカウントに**編集者として共有**し、
file id を `secrets/dev-drive.json` に書く。

```json
{ "file_id": "1jsEW..." }
```

本番（Cloud Run）では鍵ファイルを置かず、実行環境に紐づいたサービスアカウントをそのまま使う
（`build_default_service()`）。鍵ファイルは開発用の逃げ道。

`secrets/` と `out/` は `.gitignore` 済み。
TSA に接続するテストは既定で除外してある（`pytest -m network` で実行）。

## ライセンス

Apache License 2.0（[LICENSE](LICENSE)）。
