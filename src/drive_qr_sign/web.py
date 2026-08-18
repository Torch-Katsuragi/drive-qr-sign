"""署名ページ。

QR から来た人が見る唯一の画面。やることは3つしかない。

1. QR の URL が本物か（HMAC）
2. 押しているのが誰か（OpenID の検証済みメール）と、その人がこの書類を見られるか
3. 押されたら署名して書き戻す。押印枠を持つ人は枠に印影、持たない人は不可視署名

判定の出どころは2つに分かれている。**見られるか**は Drive の共有設定、
**押印枠に押せるか**は名簿の役職。前者はアクセス制御、後者は決裁の割り当てで、
守っているものが違うため一緒にしない。

Drive も身元確認も Protocol 越しに受け取るので、実装が差し替わってもこのファイルは変わらない。
"""

from __future__ import annotations

import hashlib
import hmac
import io
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .documents import DocumentNotFound, DocumentStore
from .identity import IdentityProvider, SignerDirectory, silent_field_name
from .notify import Notifier, SignatureNotice, notify_quietly
from .qr import InvalidPayload, verify_mac
from .seal import MAX_UPLOAD_BYTES, UnusableImage
from .seal_store import SealStore
from .signing import FREE_TSA_URL, list_signature_fields, sign_field, sign_invisible

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"

# 画面の状態。テンプレートの分岐と POST の可否がこの1つで決まる
MODE_LOGIN = "login"  # 未ログイン
MODE_STRANGER = "stranger"  # この書類を見る権限が無い
MODE_ROLE_READY = "role_ready"  # 押印枠が空いている
MODE_ROLE_DONE = "role_done"  # 自分の枠は署名済み
MODE_SILENT_READY = "silent_ready"  # 枠は無い。不可視署名を付けられる
MODE_SILENT_DONE = "silent_done"  # 不可視署名は記録済み

SIGNABLE = {MODE_ROLE_READY, MODE_SILENT_READY}


def _csrf_token(secret: bytes, file_id: str, email: str) -> str:
    """この画面を実際に開いた本人だけが持てる値。

    他所のサイトに置かれたフォームから署名 POST を撃たれるのを防ぐ
    （画面の中身は同一生成元でないと読めないため）。
    """
    message = f"csrf:{file_id}:{email}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def create_app(
    *,
    document_store: DocumentStore,
    signer_directory: SignerDirectory,
    identity_provider: IdentityProvider,
    signer,
    qr_secret: bytes,
    tsa_url: str | None = FREE_TSA_URL,
    seal_store: SealStore | None = None,
    can_read=None,
    notifier: Notifier | None = None,
) -> FastAPI:
    app = FastAPI(title="drive-qr-sign")

    # 「この人はこの書類を見てよいか」の判定。本番は Drive の共有設定に従う
    # （DriveDocumentStore.can_read）。渡されなければ名簿で代用する——
    # Drive の無い開発用サーバのための逃げ道で、本番の姿ではない
    _can_read = can_read or (lambda file_id, email: signer_directory.knows(email))

    # pdf.js とビューアの読み込み口。外部 CDN は使わない
    # （導入先がネットワークを絞っていても動くこと、依存先が消えないことを優先する）
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ログイン経路を持つ IdentityProvider（Google OIDC など）はここで生える。
    # 偽の身元確認を差した開発用サーバでは router が無いので、何も生えない
    login_routes = getattr(identity_provider, "router", None)
    if login_routes is not None:
        app.include_router(login_routes)

    def _seal_for(email: str):
        """印影をどこから取るか。

        1. 本人が登録した画像（アップロード、または Google のアイコン）
        2. 名簿に組織が指定した画像
        3. 名簿の文字から生成（無ければ役職から生成）

        生成はいちばん後ろ。本人が用意した絵があるなら、そちらが本人らしい。
        """
        if seal_store is not None:
            own = seal_store.get(email)
            if own is not None:
                return own
        return signer_directory.seal_for(email)

    def _google_picture(request: Request) -> str | None:
        """ログインしている Google アカウントのアイコン URL。

        取れるかどうかは IdentityProvider 次第（OIDC の picture クレームは
        profile スコープが要る）。取れない実装なら、この導線は画面に出ない。
        """
        source = getattr(identity_provider, "picture_url", None)
        return source(request) if source else None

    def _load(file_id: str, mac: str) -> bytes:
        try:
            verify_mac(qr_secret, file_id, mac)
        except InvalidPayload:
            # 偽造 QR。どこが違うかは教えない
            raise HTTPException(status_code=403, detail="この URL は無効です")
        try:
            return document_store.fetch(file_id)
        except DocumentNotFound:
            raise HTTPException(status_code=404, detail="書類が見つかりません")

    def _situation(
        pdf: bytes, email: str | None, file_id: str
    ) -> tuple[str, str | None, list[str]]:
        """誰が何をできる状態かを1か所で判定する。GET も POST もここだけを見る。

        見られるかどうかは Drive の共有設定、押印枠に押せるかは名簿の役職。
        判定の出どころが2つに分かれているのは、それぞれ守っているものが違うため。
        """
        empty_fields = list_signature_fields(io.BytesIO(pdf), filled=False)
        if not email:
            return MODE_LOGIN, None, empty_fields
        if not _can_read(file_id, email):
            return MODE_STRANGER, None, empty_fields

        role = signer_directory.role_for(email)
        if role:
            mode = MODE_ROLE_READY if role in empty_fields else MODE_ROLE_DONE
            return mode, role, empty_fields

        # 押印枠を持たない人。書類を見られる人なら確認の記録は残せる。
        # 同じ名前のフィールドは2度作れないので、それが二重署名の判定になる
        already = silent_field_name(email) in list_signature_fields(io.BytesIO(pdf))
        return (MODE_SILENT_DONE if already else MODE_SILENT_READY), None, empty_fields

    def _reader(request: Request, file_id: str, mac: str) -> bytes:
        """書類の中身を見せてよい相手にだけ PDF を返す。

        QR は紙に刷られて回覧されるので、URL を知っていることは何の資格でもない。
        見せてよいかは Drive の共有設定に従う（アプリの名簿では決めない）。
        """
        pdf = _load(file_id, mac)
        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        if not _can_read(file_id, email):
            raise HTTPException(status_code=403, detail="この書類を見られるアカウントではありません")
        return pdf

    # ⚠`/healthz` は使えない。Cloud Run のフロントエンドが横取りして、
    # リクエストがコンテナまで届かない（実測: アクセスログに一切残らず Google の404が返る）
    @app.get("/status")
    def status() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/s/{file_id}/document.pdf")
    def document_file(request: Request, file_id: str, m: str = "") -> Response:
        """PDF そのもの。手元のビューアで開きたい人向け。"""
        pdf = _reader(request, file_id, m)
        return Response(
            pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": "inline", "Cache-Control": "no-store"},
        )

    @app.get("/s/{file_id}", response_class=HTMLResponse)
    def sign_page(request: Request, file_id: str, m: str = "") -> HTMLResponse:
        pdf = _load(file_id, m)
        email = identity_provider.verified_email(request)
        mode, role, empty_fields = _situation(pdf, email, file_id)

        return TEMPLATES.TemplateResponse(
            request=request,
            name="sign.html",
            context={
                "file_id": file_id,
                "mac": m,
                "email": email,
                "role": role,
                "mode": mode,
                "empty_fields": empty_fields,
                "csrf": _csrf_token(qr_secret, file_id, email) if email else "",
                # ログイン経路が無い（開発用の偽の身元確認）ときはボタンを出さない
                "can_log_in": login_routes is not None,
                # 中身を見せてよい相手か。未ログイン・共有されていない人にはビューアごと出さない
                "can_read": mode not in {MODE_LOGIN, MODE_STRANGER},
            },
        )

    @app.post("/s/{file_id}/sign", response_class=HTMLResponse)
    def do_sign(request: Request, file_id: str, m: str = "", csrf: str = Form("")) -> HTMLResponse:
        pdf = _load(file_id, m)

        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        if not hmac.compare_digest(_csrf_token(qr_secret, file_id, email), csrf):
            raise HTTPException(status_code=403, detail="フォームの有効期限が切れています")

        mode, role, _ = _situation(pdf, email, file_id)
        if mode == MODE_STRANGER:
            raise HTTPException(status_code=403, detail="この書類に署名できるアカウントではありません")
        if mode not in SIGNABLE:
            raise HTTPException(status_code=409, detail="この書類にはもう署名しています")

        signed = io.BytesIO()
        if mode == MODE_ROLE_READY:
            sign_field(
                io.BytesIO(pdf),
                signed,
                field_name=role,
                signer=signer,
                tsa_url=tsa_url,
                signer_name=email,
                reason=f"{role}として承認",
                seal=_seal_for(email),
            )
        else:
            sign_invisible(
                io.BytesIO(pdf),
                signed,
                field_name=silent_field_name(email),
                signer=signer,
                tsa_url=tsa_url,
                signer_name=email,
                reason="確認",
            )
        signed_pdf = signed.getvalue()
        stored_as = document_store.store_signed(file_id, signed_pdf)

        # 署名の記録を本人へ送る。アプリの外（本人の受信箱）に、こちらが消せない
        # 控えを残すのが目的。送れなくても署名は成立しているので、握りつぶして進む
        notify_quietly(
            notifier,
            SignatureNotice.create(
                file_id=file_id,
                signer_email=email,
                role=role if mode == MODE_ROLE_READY else None,
                signed_pdf=signed_pdf,
            ),
        )

        return TEMPLATES.TemplateResponse(
            request=request,
            name="done.html",
            context={
                "file_id": file_id,
                "role": role,
                "email": email,
                "mode": mode,
                "stored_as": stored_as,
            },
        )

    # --- 印影の登録 ---------------------------------------------------------
    # 押印枠に何を出すかは本人が選べる。生成した丸印はあくまで、何も用意しなかった人向け。

    def _require_signer(request: Request) -> str:
        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        return email

    def _check_seal_csrf(email: str, csrf: str) -> None:
        if not hmac.compare_digest(_csrf_token(qr_secret, "seal", email), csrf):
            raise HTTPException(status_code=403, detail="フォームの有効期限が切れています")
        if seal_store is None:
            raise HTTPException(status_code=404, detail="印影の登録は使えません")

    @app.get("/seal", response_class=HTMLResponse)
    def seal_page(request: Request) -> HTMLResponse:
        email = _require_signer(request)
        return TEMPLATES.TemplateResponse(
            request=request,
            name="seal.html",
            context={
                "email": email,
                "can_register": seal_store is not None,
                "registered": seal_store is not None and seal_store.get(email) is not None,
                "google_picture": _google_picture(request),
                "csrf": _csrf_token(qr_secret, "seal", email),
            },
        )

    @app.get("/seal/preview.png")
    def seal_preview(request: Request) -> Response:
        """いま押されることになる印影。登録・生成のどちらであっても同じ絵が出る。"""
        email = _require_signer(request)
        seal = _seal_for(email)
        if seal is None:
            raise HTTPException(status_code=404, detail="印影がありません")
        buffer = io.BytesIO()
        seal.save(buffer, format="PNG")
        return Response(buffer.getvalue(), media_type="image/png")

    @app.post("/seal")
    async def upload_seal(
        request: Request, csrf: str = Form(""), image: UploadFile = File(...)
    ) -> RedirectResponse:
        email = _require_signer(request)
        _check_seal_csrf(email, csrf)
        try:
            seal_store.put(email, await image.read())
        except UnusableImage as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return RedirectResponse("/seal", status_code=303)

    @app.post("/seal/google")
    def use_google_picture(request: Request, csrf: str = Form("")) -> RedirectResponse:
        email = _require_signer(request)
        _check_seal_csrf(email, csrf)
        url = _google_picture(request)
        if not url:
            raise HTTPException(status_code=400, detail="アイコンを取得できません")
        seal_store.put(email, _fetch_picture(url))
        return RedirectResponse("/seal", status_code=303)

    @app.post("/seal/delete")
    def delete_seal(request: Request, csrf: str = Form("")) -> RedirectResponse:
        email = _require_signer(request)
        _check_seal_csrf(email, csrf)
        seal_store.delete(email)
        return RedirectResponse("/seal", status_code=303)

    return app


def _fetch_picture(url: str) -> bytes:
    """Google アカウントのアイコンを取ってくる。

    URL は ID トークン由来だが、アプリからの外向き通信になるので行き先を絞る。
    ここを緩めると、細工したトークンでアプリに任意の URL を叩かせられる。
    """
    from urllib.parse import urlparse

    import requests

    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(
        ".googleusercontent.com"
    ):
        raise HTTPException(status_code=400, detail="アイコンの取得先が不正です")

    response = requests.get(url, timeout=5, stream=True)
    response.raise_for_status()
    return response.raw.read(MAX_UPLOAD_BYTES + 1, decode_content=True)
