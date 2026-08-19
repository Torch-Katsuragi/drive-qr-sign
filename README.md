# drive-qr-sign

紙の回覧はそのままに、押印だけを電子署名に置き換える。
書類は Google Drive に置いたまま、署名者はいま使っている Google アカウントで押す。

> **In English** — Keep circulating the paper; replace only the seal. Approvers scan the QR printed
> on the page, sign in with the Google account they already have, and tap once. A PAdES signature
> and an RFC 3161 timestamp go into the PDF, and the original in Google Drive is updated in place.
> No new accounts, no per-seat subscription, no moving documents elsewhere.
> Docs and code comments are in Japanese.

```
書類PDFをDriveに置く → QR付きで印刷して紙で回覧 → 読んだ人がQRを読む
  → Googleでログイン → 中身を確認してワンタップ → PAdES署名＋タイムスタンプ
  → Driveの原本が新しい版として更新される
```

証跡は PDF に埋まる。このアプリを捨てても、署名済み PDF 単体で検証できる。

## 既存の電子契約サービスとの違い

|  | 電子契約サービス | drive-qr-sign |
|---|---|---|
| 署名者のアカウント | 新規登録 | いまの Google アカウント |
| 署名者に求める権限 | サービスの利用同意 | メールアドレスの確認だけ |
| 書類の置き場 | サービス側へ移す | Drive のまま。file id も変わらない |
| 閲覧できる人 | サービス内で招待 | Drive の共有設定 |
| 費用 | 席数 × 月額 | 実費のみ。人数で増えない |
| 証跡 | サービスの管理画面 | PDF 自体（PAdES + RFC 3161） |
| 紙の回覧 | やめる前提 | 続けられる |

費用の実費は、Cloud Run が回覧程度なら無料枠、Cloud KMS の鍵が月に数セント、
タイムスタンプは freeTSA なら 0 円。認定タイムスタンプ局と AATL 証明書を使う場合だけ別。

## 何をしないか

- **書類の用意**。QR を紙面に載せることと、印影を出す位置に押印枠を置くこと。
  枠が無ければ、署名は紙面に出ない記録として残る
- **ワークフロー管理**（未押印者の一覧・催促・期限）は持たない

## 現状

動くものが本番に載っているが、まだ実運用の回覧は1件も回していない。

- 証明書は自己署名。Acrobat の署名パネルに警告が出る（組織内なら1回信頼登録すれば消える）
- `--max-instances=1` での運用が前提（同時に押されたときの上書きを防ぐため）
- 押してから画面に反映されるまで約5.5秒
- 署名者名簿の更新にデプロイが要る

設計は [docs/DESIGN.md](docs/DESIGN.md)、導入手順は [docs/DEPLOY.md](docs/DEPLOY.md)。

## 開発

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest
```

> [!NOTE] Windows on ARM では x64 の Python を使う
> ネイティブ ARM64 の Python だと `cryptography` / `grpcio` / `httptools` の
> ホイールが無く、ソースからのビルドに Visual Studio を要求されて止まる。
> x64 版（エミュレーション）の Python なら、そのまま入る。

署名ページを立てる（Google ログインも Drive も無しで一周できる）:

```powershell
.venv\Scripts\python.exe tools\build_sample.py
.venv\Scripts\python.exe tools\run_dev.py
```

起動時に署名用の URL を印字する。`secrets/oauth-client.json` を置けば本物の Google ログイン、
`secrets/service-account.json` と `secrets/dev-drive.json` を置けば本物の Drive になる
（どちらも無ければ `?as=<メールアドレス>` の偽ログインとローカルディレクトリ）。

`secrets/` と `out/` は `.gitignore` 済み。
TSA に出るテストは既定で除外してある（`pytest -m network` で実行）。

## ライセンス

Apache License 2.0（[LICENSE](LICENSE)）。
