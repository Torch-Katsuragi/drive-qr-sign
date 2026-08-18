# 導入手順

自分の組織の GCP プロジェクトに一式を置くまでの手順。上から順に実行すれば動く。
実際にこの通りに構築した記録から起こしてある（踏んだ落とし穴も各所に書いた）。

かかる費用: Cloud Run は使った時間だけ（回覧程度なら無料枠に収まる）。
Cloud KMS の鍵が月に数セント。記録メールを使うなら送信サービスの無料枠。
⚠**認定タイムスタンプ局と AATL 証明書を使う場合だけ**、別途費用がかかる。

前提: `gcloud` がインストール済み・課金が有効な GCP プロジェクト・Python 3.11 以上。

以下、`<プロジェクト>` `<リージョン>` は自分のものに読み替える（例: `asia-northeast1`）。

## 1. API を有効にする

```powershell
gcloud services enable `
  run.googleapis.com drive.googleapis.com secretmanager.googleapis.com `
  cloudkms.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com `
  --project <プロジェクト>
```

## 2. アプリが名乗るサービスアカウントを作る

```powershell
gcloud iam service-accounts create drive-qr-sign --project <プロジェクト> `
  --display-name "drive-qr-sign"
```

このアカウントは**鍵ファイルを持たない**。Cloud Run の実行 ID として紐づけるだけで、
Drive にはこのアドレスを書類ごとに共有して届かせる（→ 6章）。

## 3. Google ログイン（OAuth クライアント）

コンソールでの手作業。API では作れない。

1. 「API とサービス」→「OAuth 同意画面」を設定（外部・本番環境）
   - スコープは `openid` `email` `profile` だけ。⚠**Drive のスコープを足さない**。
     足すと署名者に「確認されていないアプリ」の警告が出て、導入できる組織が激減する
2. 「認証情報」→「OAuth クライアント ID」→ 種類=ウェブアプリ
3. リダイレクト URI は、いまは `http://localhost:8765/oauth2/callback` だけ入れる
   （本番の URL は 5章のデプロイまで分からない）
4. JSON をダウンロードして `secrets/oauth-client.json` に置く

## 4. 署名鍵（Cloud KMS）と証明書

```powershell
gcloud kms keyrings create drive-qr-sign --location <リージョン> --project <プロジェクト>
gcloud kms keys create signing --location <リージョン> --keyring drive-qr-sign `
  --purpose asymmetric-signing --default-algorithm rsa-sign-pkcs1-3072-sha256 `
  --project <プロジェクト>
gcloud kms keys add-iam-policy-binding signing --keyring drive-qr-sign --location <リージョン> `
  --member "serviceAccount:drive-qr-sign@<プロジェクト>.iam.gserviceaccount.com" `
  --role roles/cloudkms.signerVerifier --project <プロジェクト>

python tools\make_kms_cert.py `
  projects/<プロジェクト>/locations/<リージョン>/keyRings/drive-qr-sign/cryptoKeys/signing/cryptoKeyVersions/1 `
  --out secrets\kms-cert.pem --common-name "〇〇組合 署名" --organization "〇〇組合"
```

⚠鍵は KMS から出てこないので、**証明書の自己署名も KMS に頼んでいる**。
⚠自己署名なので Acrobat の署名パネルには「信頼されていない」警告が出る。
消すには AATL 掲載の認証局の証明書が要るが、**AATL は鍵を FIPS ハードウェアに置くことを
要求する**ので、その場合は KMS ではなく CA のクラウド署名サービスに預ける形になる
（`kms.py` を差し替える。署名の実体は `async_sign_raw` の1メソッドしかない）。

## 5. 設定を Secret Manager に入れてデプロイ

署名者名簿を書く（メールアドレス → 役職。役職 null の人はサイレント署名）:

```json
{ "kumiaicho@example.com": "組合長", "sanji@example.com": "参事", "kanji@example.com": null }
```

```powershell
# 秘密の値（QR の署名鍵とセッションの鍵）は推測できない値を作る
python -c "import secrets;print(secrets.token_urlsafe(32))" | gcloud secrets create drive-qr-sign-qr-secret --data-file=- --project <プロジェクト>
python -c "import secrets;print(secrets.token_urlsafe(32))" | gcloud secrets create drive-qr-sign-session-secret --data-file=- --project <プロジェクト>
gcloud secrets create drive-qr-sign-signers --data-file=signers.json --project <プロジェクト>
gcloud secrets create drive-qr-sign-oauth-client --data-file=secrets\oauth-client.json --project <プロジェクト>
gcloud secrets create drive-qr-sign-signing-cert --data-file=secrets\kms-cert.pem --project <プロジェクト>

# 実行サービスアカウントに読み取りを許す（5つとも）
foreach ($s in "qr-secret","session-secret","signers","oauth-client","signing-cert") {
  gcloud secrets add-iam-policy-binding drive-qr-sign-$s --project <プロジェクト> `
    --member "serviceAccount:drive-qr-sign@<プロジェクト>.iam.gserviceaccount.com" `
    --role roles/secretmanager.secretAccessor
}

gcloud run deploy drive-qr-sign --source . --project <プロジェクト> --region <リージョン> `
  --service-account drive-qr-sign@<プロジェクト>.iam.gserviceaccount.com `
  --allow-unauthenticated --max-instances=1 `
  --set-secrets "QR_SECRET=drive-qr-sign-qr-secret:latest,SESSION_SECRET=drive-qr-sign-session-secret:latest,SIGNERS_JSON=drive-qr-sign-signers:latest,OAUTH_CLIENT_JSON=drive-qr-sign-oauth-client:latest,SIGNING_CERT_PEM=drive-qr-sign-signing-cert:latest" `
  --set-env-vars "SIGNING_KEY_KMS=projects/<プロジェクト>/locations/<リージョン>/keyRings/drive-qr-sign/cryptoKeys/signing/cryptoKeyVersions/1,PUBLIC_ORIGIN=https://<デプロイ後のURL>,TSA_URL=https://freetsa.org/tsr"
```

⚠**`--max-instances=1` を外さない**。読んで→署名して→書き戻す、のあいだに別の人の
署名が入ると上書きしてしまうため、書類ごとの鍵で1人ずつ通している。この鍵は
プロセス内でしか効かない（→ README の「同時に押されたときの上書き」）。

⚠**`--allow-unauthenticated` が要る**。署名者は Google でログインするが、それはアプリ側の
仕組みであって Cloud Run の IAM ではない。ここを閉じると誰も署名ページに来られない。

デプロイの出力に本番 URL が出る。⚠**この URL は推測できない**
（`https://<サービス>-<プロジェクト番号>.<リージョン>.run.app` ではなく
`https://drive-qr-sign-4rt5qtts2q-an.a.run.app` のような形）。出てきた値で:

1. `PUBLIC_ORIGIN` を入れ直してもう一度デプロイ
2. 3章の OAuth クライアントに `https://<本番URL>/oauth2/callback` を足す

## 6. 書類を用意して回覧する

```powershell
python tools\build_document.py <書類.typ> --out out\document.pdf
```

Typst の書類に押印枠のアンカーを置いておくと、その座標に空の署名フィールドが入り、
QR も焼き込まれる（書き方は README「PDF が署名欄を自己記述する」）。

できた PDF を Drive に置き、**「回覧中」フォルダを作って、そのフォルダを
サービスアカウント（`drive-qr-sign@...`）と署名者に共有する**。
回覧が終わったら書類をフォルダから出す。それが共有の解除になる。

⚠Drive の「アクセスの有効期限」では代替できない。期限を付けられるのは
reader / commenter だけで、書き戻しに writer が要るこのアプリの共有には付かない。

## 7. 記録メール（任意）

署名した本人へ、署名済み PDF のハッシュ入りの控えを送る。狙いは通知ではなく、
**アプリの外に、こちらが消せない記録を作ること**（→ README「署名の記録は、アプリの外にも残す」）。

送信サービス（Resend）を使う場合:

```powershell
python tools\setup_resend_domain.py <ドメイン> --zone <Cloud DNSのゾーン> --dns-project <プロジェクト> --apply
gcloud secrets create drive-qr-sign-resend-key --data-file=secrets\resend-api-key.txt --project <プロジェクト>
# デプロイに足す
#   --update-secrets "RESEND_API_KEY=drive-qr-sign-resend-key:latest"
#   --update-env-vars "NOTICE_SENDER=〇〇組合 <no-reply@example.com>"
```

⚠API キーは**送信権限だけ**のものにする。漏れてもできるのはメールを出すことだけで、
Drive にも受信箱にも届かない。

## 動かないときに見るところ

| 症状 | 原因 |
|---|---|
| ヘルスチェックが 404 | `/healthz` は Cloud Run のフロントエンドが横取りする。このアプリは `/status` |
| 起動直後にコンテナが落ちる | 静的ファイルが配布物に入っていない。`pyproject.toml` の `package-data` を見る |
| ログに何も出ない | uvicorn は自前のロガーしか設定しない。アプリ側は `basicConfig` が要る（`main.py` で実施済み） |
| KMS が「そのダイジェストは使えない」 | 鍵のアルゴリズムと署名のダイジェストの不一致。`load_kms_signer(digest_algorithm=...)` を鍵に合わせる |
| ログインで「Token used too early」 | 端末の時計のずれ。許容幅は実装済み（30秒） |
| 署名が 409「ほかの人の署名と重なりました」 | 同時に押された。押し直せばよい（先の署名は消えていない） |
