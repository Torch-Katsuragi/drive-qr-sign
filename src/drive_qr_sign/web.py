"""署名ページ。

QR から来た人が見る唯一の画面。やることは3つしかない。

1. QR の URL が本物か（HMAC）
2. 押しているのが誰か（OpenID の検証済みメール）と、その人の欄がこの PDF に空で存在するか
3. 押されたらその欄にだけ PAdES 署名を埋めて書き戻す

Google ログインと Drive はまだ差し込まれていない。どちらも Protocol 越しに受け取るので、
本物が来てもこのファイルは変わらない。
"""

from __future__ import annotations

import hashlib
import hmac
import io
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .documents import DocumentNotFound, DocumentStore
from .identity import IdentityProvider, RoleDirectory
from .qr import InvalidPayload, verify_mac
from .signing import FREE_TSA_URL, list_signature_fields, sign_field

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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
    role_directory: RoleDirectory,
    identity_provider: IdentityProvider,
    signer,
    qr_secret: bytes,
    tsa_url: str | None = FREE_TSA_URL,
) -> FastAPI:
    app = FastAPI(title="drive-qr-sign")

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

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/s/{file_id}", response_class=HTMLResponse)
    def sign_page(request: Request, file_id: str, m: str = "") -> HTMLResponse:
        pdf = _load(file_id, m)
        empty_fields = list_signature_fields(io.BytesIO(pdf), filled=False)
        email = identity_provider.verified_email(request)
        role = role_directory.role_for(email) if email else None

        return TEMPLATES.TemplateResponse(
            request=request,
            name="sign.html",
            context={
                "file_id": file_id,
                "mac": m,
                "email": email,
                "role": role,
                "empty_fields": empty_fields,
                "can_sign": bool(role) and role in empty_fields,
                "already_signed": bool(role) and role not in empty_fields,
                "csrf": _csrf_token(qr_secret, file_id, email) if email else "",
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

        role = role_directory.role_for(email)
        if not role:
            raise HTTPException(status_code=403, detail="このアカウントに署名欄が割り当てられていません")
        # 「空の欄がある」ことが署名の許可そのもの。二重署名もここで止まる
        if role not in list_signature_fields(io.BytesIO(pdf), filled=False):
            raise HTTPException(status_code=409, detail=f"{role} の欄は署名できません")

        signed = io.BytesIO()
        sign_field(
            io.BytesIO(pdf),
            signed,
            field_name=role,
            signer=signer,
            tsa_url=tsa_url,
            signer_name=email,
            reason=f"{role}として承認",
        )
        stored_as = document_store.store_signed(file_id, signed.getvalue())

        return TEMPLATES.TemplateResponse(
            request=request,
            name="done.html",
            context={"file_id": file_id, "role": role, "email": email, "stored_as": stored_as},
        )

    return app
