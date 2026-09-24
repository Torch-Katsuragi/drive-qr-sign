"""署名ページと、署名待ちの一覧。

QR から来た人が見るのは署名ページ。やることは3つしかない。

1. QR の URL が本物か（HMAC）
2. 押しているのが誰か（OpenID の検証済みメール）と、その人がこの書類を見られるか
3. 押されたら署名して書き戻す。押印枠を持つ人は枠に印影、持たない人は不可視署名

判定の出どころは2つに分かれている。**見られるか**は Drive の共有設定、
**押印枠に押せるか**は名簿の役職。前者はアクセス制御、後者は決裁の割り当てで、
守っているものが違うため一緒にしない。

押すのは「受け付け」と「実行」に分かれている（tasks.py）。POST が返すまでにやるのは
本人と欄の確認だけで、署名・タイムスタンプ・書き戻しはキュー（Cloud Tasks）から
`/tasks/sign` として呼び返されたときに行う。キューが無ければその場で行う。

一覧（`/`）は QR を読む手間ごと省く入口。ログインした人に共有されている書類のうち、
まだ押していないものを並べる。押すのは一覧から署名ページの POST を1件ずつ呼ぶだけで、
署名の経路は QR から来たときと同じものを通る。

Drive も身元確認も Protocol 越しに受け取るので、実装が差し替わってもこのファイルは変わらない。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
import threading
import io
import time
import logging
from pathlib import Path

from fastapi import BackgroundTasks, Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .documents import DocumentNotFound, DocumentStore
from .identity import (
    SILENT_FIELD_PREFIX,
    IdentityProvider,
    SignerDirectory,
    silent_field_name,
)
from .notify import Notifier, SignatureNotice, notify_quietly
from .cache import TimedCache
from .qr import InvalidPayload, make_mac, verify_mac
from .tasks import MAX_ATTEMPTS, TASK_PATH, SignJob, SignQueue
from .seal import MAX_UPLOAD_BYTES, UnusableImage, compose_stamp, prepare_uploaded, render_seal
from .signing import (
    list_signatures,
    FREE_TSA_URL,
    NotRevocable,
    last_signature,
    list_signature_fields,
    revoke_last_signature,
    sign_field,
    sign_invisible,
)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"


def _static_version() -> str:
    """static/ の中身から決まる版。中身が変われば URL が変わる。"""
    digest = hashlib.md5()
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(STATIC_DIR).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


# ⚠静的ファイルは版つきの URL で配る。版なしだとブラウザが前の版を期限の推測で
# 使い回し、module の import が新旧で食い違って動かなくなる（2026-09-24 に Pixel で
# 一括署名が止まった）。module 内の import は相対なので、入口の URL だけ変えれば足りる
STATIC_PREFIX = f"/static/{_static_version()}"
TEMPLATES.env.globals["static"] = STATIC_PREFIX

logger = logging.getLogger(__name__)

# 画面の状態。テンプレートの分岐と POST の可否がこの1つで決まる
# 覚え書きの寿命。
# ⚠書類の中身を短命にしても意味がなかった（当初10秒）。人は画面を開いて書類を読んでから
# 押すので、押す頃には毎回消えている。**長く持ったうえで、使う前に版番号で確かめる**のが正しい。
# 版番号の問い合わせは数百バイトで、本体（1MB級）を落とし直すのとは桁が違う。
DOCUMENT_TTL = 600.0  # 書類の中身。使う前に必ず版番号で確かめるので、古いものを見せることはない
VERIFIED_TTL = 10.0   # 版番号を確かめたばかり、とみなす時間（画面1枚ぶんの連続した要求をまとめる）
ACCESS_TTL = 30.0     # Drive の共有設定
PICTURE_TTL = 600.0   # Google アカウントのアイコン（そう変わらない）
# 一覧に出す判定（どの欄が空いているか）。中身のハッシュを鍵にするので、
# 中身が変われば別の鍵になり、古い判定を見せることはない。長く持ってよい
FIELDS_TTL = 6 * 3600.0
# 受け付けたがまだ押していない署名。押し終えれば消すので、これは
# 「キューが止まったまま」になったときに、いつまでも受付済みと言い続けないための上限
PENDING_TTL = 15 * 60.0
# 書き戻す直前に他の人の署名と重なったとき、取り直して押し直す回数
CONFLICT_RETRIES = 3
JST = timezone(timedelta(hours=9))

# 印影の種類。画面の選択肢と `_seal_source` の分岐で同じ名前を使う
SEAL_REGISTERED = "registered"  # 名簿に組織が指定した画像
SEAL_ICON = "icon"              # Google アカウントのアイコン
SEAL_GENERATED = "generated"    # 名簿の文字から生成した丸印

MODE_LOGIN = "login"  # 未ログイン
MODE_STRANGER = "stranger"  # この書類を見る権限が無い
MODE_ROLE_READY = "role_ready"  # 押印枠が空いている
MODE_ROLE_DONE = "role_done"  # 自分の枠は署名済み
MODE_SILENT_READY = "silent_ready"  # 枠は無い。不可視署名を付けられる
MODE_SILENT_DONE = "silent_done"  # 不可視署名は記録済み
MODE_PENDING = "pending"  # 押したのは受け付けた。PDF にはまだ入っていない

SIGNABLE = {MODE_ROLE_READY, MODE_SILENT_READY}


def _csrf_token(secret: bytes, file_id: str, email: str) -> str:
    """この画面を実際に開いた本人だけが持てる値。

    他所のサイトに置かれたフォームから署名 POST を撃たれるのを防ぐ
    （画面の中身は同一生成元でないと読めないため）。
    """
    message = f"csrf:{file_id}:{email}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


class JobRejected(Exception):
    """やり直しても押せない（共有を外された、欄が無くなった等）。"""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class _Conflict(Exception):
    """書き戻す直前に、土台にした中身が入れ替わっていた。"""


def create_app(
    *,
    document_store: DocumentStore,
    signer_directory: SignerDirectory,
    identity_provider: IdentityProvider,
    signer,
    qr_secret: bytes,
    tsa_url: str | None = FREE_TSA_URL,
    can_read=None,
    notifier: Notifier | None = None,
    sign_queue: SignQueue | None = None,
    task_auth=None,
) -> FastAPI:
    app = FastAPI(title="drive-qr-sign")

    # 1回の画面表示のあいだ、同じ問い合わせを繰り返さないための覚え書き（cache.py）
    documents = TimedCache(DOCUMENT_TTL)
    # 書類ごとの鍵。読んで→署名して→書き戻す、のあいだに割り込ませない
    writes: dict[str, threading.Lock] = {}
    writes_guard = threading.Lock()
    verified = TimedCache(VERIFIED_TTL)
    access = TimedCache(ACCESS_TTL)
    pictures = TimedCache(PICTURE_TTL)
    fields_by_hash = TimedCache(FIELDS_TTL)
    # 受け付けてまだ押していない (file_id, email)。画面で「受付済み」と出すのに使う。
    # ⚠`--max-instances=1` なのでプロセスの中に持てば足りる。消えても、あとから来た
    # 予約が「もう押してある」を見て何もせず終わるだけ
    pending = TimedCache(PENDING_TTL)

    # 「この人はこの書類を見てよいか」の判定。本番は Drive の共有設定に従う
    # （DriveDocumentStore.can_read）。渡されなければ名簿で代用する——
    # Drive の無い開発用サーバのための逃げ道で、本番の姿ではない
    _can_read = can_read or (lambda file_id, email: signer_directory.knows(email))

    # pdf.js とビューアの読み込み口。外部 CDN は使わない
    # （導入先がネットワークを絞っていても動くこと、依存先が消えないことを優先する）
    app.mount(STATIC_PREFIX, StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ログイン経路を持つ IdentityProvider（Google OIDC など）はここで生える。
    # 偽の身元確認を差した開発用サーバでは router が無いので、何も生えない
    login_routes = getattr(identity_provider, "router", None)
    if login_routes is not None:
        app.include_router(login_routes)

    def _account_icon(request: Request, email: str):
        """Google アカウントのアイコン。取れなければ None。"""
        picture = _google_picture(request)
        if not picture:
            return None
        try:
            raw = pictures.get(picture) or pictures.put(picture, _fetch_picture(picture))
            return prepare_uploaded(raw)
        except Exception:
            logger.exception("アイコンを取れなかった: %s", email)
            return None

    def _seal_choices(request: Request, email: str) -> list[str]:
        """この人が選べる印影の種類。並び順がそのまま既定の優先順になる。"""
        choices = []
        if signer_directory.seal_image_for(email) is not None:
            choices.append(SEAL_REGISTERED)
        choices.append(SEAL_GENERATED)
        if _google_picture(request):
            choices.append(SEAL_ICON)
        return choices

    def _seal_source(request: Request, email: str, uploaded: bytes | None, choice: str = ""):
        """印影の元になる絵を決める。

        選ばれたものがあればそれを使い、無ければ上から順に落ちる。

        1. その場でアップロードされた画像（この署名かぎり。保管しない）
        2. 名簿に組織が指定した画像
        3. 名簿の文字から生成した丸印（無ければ役職から）

        Google アカウントのアイコンは**選べば使えるが、既定にはしない**。
        押印枠に入るのは印であって顔写真ではないので、何も選ばなかった人の紙面が
        アカウントの設定次第で変わるのは具合が悪い。生成した丸印なら、
        名簿さえ整っていれば誰が押しても同じ体裁になる。

        押印枠に押すときは、この絵の上にメールアドレスを添える（_stamp_for）。
        画面右上のアカウントアイコンには、添えずにそのまま出す。
        """
        seal = None
        if uploaded:
            seal = prepare_uploaded(uploaded)
        # 選ばれたものだけを作る。選ばれていなければ従来どおり上から落ちる
        if seal is None and choice == SEAL_GENERATED:
            pass  # 下の生成に落ちる
        elif seal is None and choice == SEAL_ICON:
            seal = _account_icon(request, email)
        elif seal is None and choice == SEAL_REGISTERED:
            seal = signer_directory.seal_image_for(email)
        elif seal is None:
            seal = signer_directory.seal_image_for(email)
        if seal is None:
            # 既定の落ち先。名簿の文字、無ければアドレスの頭文字で作る
            seal = render_seal(signer_directory.seal_text_for(email) or email.strip()[:1].upper() or "?")
        return seal

    def _stamp_for(request: Request, email: str, uploaded: bytes | None, choice: str = ""):
        """押印枠に押す絵。元の絵の上にメールアドレスを添えて返す。

        アイコンや写真は紙の上で誰の印か分からないため（seal.compose_stamp）。
        """
        return compose_stamp(_seal_source(request, email, uploaded, choice), email)

    def _google_picture(request: Request) -> str | None:
        """ログインしている Google アカウントのアイコン URL。

        取れるかどうかは IdentityProvider 次第（OIDC の picture クレームは
        profile スコープが要る）。取れない実装なら、この導線は画面に出ない。
        """
        source = getattr(identity_provider, "picture_url", None)
        return source(request) if source else None

    def _allowed(file_id: str, email: str) -> bool:
        """この人にこの書類を見せてよいか。共有設定の問い合わせは数十秒だけ覚える。

        共有を外してから実際に閉まるまで、最大 ACCESS_TTL のずれが出る。
        回覧を閉じるのは分単位の作業なので、そこは許容する。
        """
        key = (file_id, email.strip().lower())
        remembered = access.get(key)
        if remembered is None:
            remembered = access.put(key, bool(_can_read(file_id, email)))
        return remembered

    def _log_breakdown(what: str, marks: list[tuple[str, float]]) -> None:
        """どこで待っていたかを1行に残す。体感の重さは推測ではなくログで詰める。

        実測（本番・2026-08-18）:
            書類の用意=1737ms 署名（TSA込み）=1685ms 書き戻し=2073ms 合計=5495ms

        いまはこの全部をキュー（Cloud Tasks）の後ろへ回し、押した人は待たせない（tasks.py）。
        当初は「押せたように見えて Drive には無い」状態を嫌って同期にしていたが、
        テンポを優先して方針を変えた（2026-09-24）。直列化はキューの同時実行1で、
        失敗は本人へのメールで受ける。
        """
        parts = [
            f"{label}={(at - before) * 1000:.0f}ms"
            for (label, at), (_, before) in zip(marks[1:], marks)
        ]
        total = (marks[-1][1] - marks[0][1]) * 1000
        logger.info("%s: %s 合計=%.0fms", what, " ".join(parts), total)

    def _web_url(file_id: str) -> str | None:
        """原本を人が開く URL。倉庫が持っていなければ None。"""
        source = getattr(document_store, "web_url", None)
        return source(file_id) if source else None

    def _stored_hash(file_id: str) -> str | None:
        """いま倉庫にある中身のハッシュ。分からない倉庫なら None。"""
        source = getattr(document_store, "content_hash", None)
        return source(file_id) if source else None

    def _hash(pdf: bytes) -> str:
        """手元の中身のハッシュ。倉庫に問い合わせずに出せる（Drive の md5Checksum と同じ）。"""
        return hashlib.md5(pdf).hexdigest()

    def _writing(file_id: str) -> threading.Lock:
        """その書類を書き換えるための鍵。

        ⚠これはこのプロセスの中でしか効かない。Cloud Run のインスタンスが増えると
        別プロセスになるので、`--max-instances=1` と併せて初めて意味を持つ。
        インスタンスが並ぶのはデプロイの入れ替わりの一瞬だけで、そこは書き戻す
        直前の突き合わせ（`_store_if_unchanged`）で受ける。
        """
        with writes_guard:
            return writes.setdefault(file_id, threading.Lock())

    def _store_if_unchanged(file_id: str, pdf: bytes, base_hash: str) -> str:
        """土台が入れ替わっていないことを確かめてから書き戻す。

        ⚠Drive には「この中身のときだけ書き換える」条件付き更新が無い。だから
        **確かめてから書く**しかなく、隙間は完全には消えない。隙間を
        「署名まるごと（数秒）」から「確認から書き戻しまで」に縮めるのが目的。

        ⚠見るのは版番号ではなく**中身**。版番号は「いつ読んだか」との対応が取れず、
        読んだ直後に他の人が書き戻すと、古い中身に新しい版番号が付く（テストで露見）。
        """
        stored = _stored_hash(file_id)
        if stored is not None and stored != base_hash:
            raise _Conflict(file_id)
        return document_store.store_signed(file_id, pdf)

    def _load(file_id: str, mac: str, *, fresh: bool = False) -> bytes:
        """書類の中身。読むだけなら少しのあいだ使い回す。

        ⚠署名・取り消しでは `fresh=True`。古い版を土台に署名すると、あいだに
        押された人の署名ごと消した版を書き戻すことになる。ただし「最新である」ことを
        確かめる方法は2つある——**丸ごと落とし直す**（1MB・1秒前後）か、
        **版番号だけ問い合わせる**（数百バイト）か。手元の版が最新だと分かれば、
        落とし直す必要はない。
        """
        try:
            verify_mac(qr_secret, file_id, mac)
        except InvalidPayload:
            # 偽造 QR。どこが違うかは教えない
            raise HTTPException(status_code=403, detail="この URL は無効です")
        try:
            return _current(file_id, fresh=fresh)
        except DocumentNotFound:
            raise HTTPException(status_code=404, detail="書類が見つかりません")

    def _current(file_id: str, *, fresh: bool = False) -> bytes:
        """書類の中身（MAC は確かめない。確かめるのは呼ぶ側の責任）。"""
        remembered = documents.get(file_id)
        if remembered is not None:
            content_hash, pdf = remembered
            # 画面1枚ぶんの連続した要求（ページ→PDF本体）は、確かめ直さない
            if not fresh and verified.get(file_id):
                return pdf
            if content_hash == _stored_hash(file_id):
                verified.put(file_id, True)
                return pdf  # 手元のものと同じ中身だった

        started = time.perf_counter()
        pdf = document_store.fetch(file_id)
        logger.info("Drive から取得: %s (%.0fms)", file_id, (time.perf_counter() - started) * 1000)
        documents.put(file_id, (_hash(pdf), pdf))
        verified.put(file_id, True)
        return pdf

    def _situation(
        pdf: bytes, email: str | None, file_id: str
    ) -> tuple[str, str | None, list[str]]:
        """誰が何をできる状態かを1か所で判定する。GET も POST もここだけを見る。

        見られるかどうかは Drive の共有設定、押印枠に押せるかは名簿の役職。
        判定の出どころが2つに分かれているのは、それぞれ守っているものが違うため。
        """
        all_fields = list_signature_fields(io.BytesIO(pdf))
        empty_fields = list_signature_fields(io.BytesIO(pdf), filled=False)
        if not email:
            return MODE_LOGIN, None, empty_fields
        if not _allowed(file_id, email):
            return MODE_STRANGER, None, empty_fields
        mode, role = _mode_for(email, all_fields, empty_fields)
        if mode in SIGNABLE and _is_pending(file_id, email):
            return MODE_PENDING, role, empty_fields
        return mode, role, empty_fields

    def _is_pending(file_id: str, email: str) -> bool:
        return bool(pending.get((file_id, email.strip().lower())))

    def _mode_for(email: str, all_fields: list[str], empty_fields: list[str]) -> tuple[str, str | None]:
        """見てよい人について、押せるかどうか。署名ページと一覧で同じ判定を使う。"""
        role = signer_directory.role_for(email)
        if role in empty_fields:
            return MODE_ROLE_READY, role
        if role in all_fields:
            return MODE_ROLE_DONE, role

        # 名簿に役職があっても、この書類にその押印枠が無いことはある
        # （Word など他の道具で作った書類、役職ごとに枠を置かない書類）。
        # ⚠その場合を「署名済み」と言ってはいけない。押す場所が無いだけで、
        # 確認の記録は残せる——押印枠を持たない人と同じ扱いにする
        already = silent_field_name(email) in all_fields
        return (MODE_SILENT_DONE if already else MODE_SILENT_READY), None

    def _fields_of(file_id: str, listed_hash: str | None) -> tuple[list[str], list[str]]:
        """一覧に出すための、その書類の欄（全部・空き）。

        ⚠一覧のたびに全件を落とすと、件数ぶん秒単位で待たせる。Drive の一覧は
        中身のハッシュを追加の問い合わせ無しで返すので、**ハッシュが同じなら前の判定を使う**。
        落とすのは中身が変わった書類だけになる。
        """
        if listed_hash:
            known = fields_by_hash.get((file_id, listed_hash))
            if known is not None:
                return known

        remembered = documents.get(file_id)
        if remembered is not None and listed_hash and remembered[0] == listed_hash:
            pdf = remembered[1]
        else:
            started = time.perf_counter()
            pdf = document_store.fetch(file_id)
            logger.info("一覧のため Drive から取得: %s (%.0fms)", file_id, (time.perf_counter() - started) * 1000)
            # 開いて読むときにもう一度落とさずに済むよう、署名ページと同じ覚え書きに置く
            documents.put(file_id, (_hash(pdf), pdf))

        fields = (
            list_signature_fields(io.BytesIO(pdf)),
            list_signature_fields(io.BytesIO(pdf), filled=False),
        )
        return fields_by_hash.put((file_id, _hash(pdf)), fields)

    def _waiting_for(email: str) -> list[dict]:
        """その人がまだ押していない書類。一覧画面に並べるもの。"""
        started = time.perf_counter()
        waiting = []
        for shared in document_store.shared_with(email):
            # 一覧に出たこと自体が「見てよい」の根拠（shared_with の約束）。
            # 1件ずつ共有設定を問い合わせ直さずに済むよう、ここで覚えておく
            access.put((shared.file_id, email.strip().lower()), True)
            try:
                all_fields, empty_fields = _fields_of(shared.file_id, shared.content_hash)
            except DocumentNotFound:
                continue  # 一覧を取ったあとに消された・共有を外された
            mode, role = _mode_for(email, all_fields, empty_fields)
            if mode not in SIGNABLE or _is_pending(shared.file_id, email):
                continue
            waiting.append(
                {
                    "file_id": shared.file_id,
                    "name": shared.name,
                    "mac": make_mac(qr_secret, shared.file_id),
                    "role": role,
                    "csrf": _csrf_token(qr_secret, shared.file_id, email),
                }
            )
        logger.info("一覧: %s %d件 (%.0fms)", email, len(waiting), (time.perf_counter() - started) * 1000)
        return waiting

    def _signed_by(pdf: bytes) -> list[dict]:
        """この書類に押されている署名の一覧。押印枠のものも、不可視のものも。

        ⚠不可視の署名は紙を見ても分からない。回覧が回りきったかを判断するのは人なので、
        「誰が確認したか」は画面で見えないと使えない。
        """
        signed = []
        for field_name, signer in list_signatures(pdf):
            silent = field_name.startswith(SILENT_FIELD_PREFIX)
            signed.append({"who": signer, "role": None if silent else field_name})
        return signed

    def _revocable_field(pdf: bytes, email: str) -> str | None:
        """その人がいま取り消せる署名の欄名。取り消せなければ None。

        取り消せるのは**自分が最後の押し手**のときだけ。後から誰かが押していたら、
        その人の署名が自分の署名を含めて覆っているので、抜くと相手のものが壊れる。
        積んだ順にしか外せない。
        """
        found = last_signature(pdf)
        if not found:
            return None
        field, signer = found
        return field if signer.strip().lower() == email.strip().lower() else None

    def _back_to_sign_page(file_id: str, mac: str) -> RedirectResponse:
        """押した後・取り消した後は、同じ画面に戻す。

        「署名しました」という専用の画面は作らない。押した結果は書類とボタンの
        状態を見れば分かるので、読む画面が1枚増えるだけになる。
        """
        return RedirectResponse(f"/s/{file_id}?m={mac}", status_code=303)

    def _reader(request: Request, file_id: str, mac: str) -> bytes:
        """書類の中身を見せてよい相手にだけ PDF を返す。

        QR は紙に刷られて回覧されるので、URL を知っていることは何の資格でもない。
        見せてよいかは Drive の共有設定に従う（アプリの名簿では決めない）。
        """
        # ⚠先に相手を確かめる。取ってから断ると、断る相手のために毎回
        # Drive から1MB落とすことになる（実測: 401 を返すのに1.5秒かかっていた）
        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        if not _allowed(file_id, email):
            raise HTTPException(status_code=403, detail="この書類を見られるアカウントではありません")
        return _load(file_id, mac)

    # ⚠`/healthz` は使えない。Cloud Run のフロントエンドが横取りして、
    # リクエストがコンテナまで届かない（実測: アクセスログに一切残らず Google の404が返る）
    @app.get("/status")
    def status() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def inbox(request: Request) -> HTMLResponse:
        """署名待ちの一覧。QR を読まずに、まとめて押すための入口。"""
        email = identity_provider.verified_email(request)
        listing = getattr(document_store, "shared_with", None)
        return TEMPLATES.TemplateResponse(
            request=request,
            name="inbox.html",
            context={
                "email": email,
                "can_log_in": login_routes is not None,
                "can_list": listing is not None,
                "waiting": _waiting_for(email) if email and listing is not None else [],
            },
        )

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
                # 取り消せるのは自分が最後の押し手のときだけ
                "revocable": _revocable_field(pdf, email) if email else None,
                # ログイン経路が無い（開発用の偽の身元確認）ときはボタンを出さない
                "can_log_in": login_routes is not None,
                # 中身を見せてよい相手か。未ログイン・共有されていない人にはビューアごと出さない
                "can_read": mode not in {MODE_LOGIN, MODE_STRANGER},
                # 原本を開く先。Drive にあるならそちらを指す（無ければアプリが配る PDF）
                "document_url": _web_url(file_id),
                # 誰が押したか。紙に出ない署名もここでだけ見える
                "signed_by": _signed_by(pdf) if mode not in {MODE_LOGIN, MODE_STRANGER} else [],
                # 選べる印影。先頭が既定（_seal_source の落ちる順と同じ）
                "seal_choices": _seal_choices(request, email) if email else [],
            },
        )

    def _run_job(job: SignJob) -> SignatureNotice | None:
        """予約された署名を実際に押して書き戻す。押す必要が無ければ None。

        受け付けた時点から中身が変わっていてもよい（間に誰かが押しただけなら、
        その版の上に押せばよい）。変わっていてはいけないのは「その人がその欄を押せること」で、
        それは押す直前にもう一度確かめる。

        ⚠同じ予約が2回来ることがある（Cloud Tasks のやり直し、応答が届かなかった場合など）。
        もう押してあれば何もしない。二重に押さないことを、ここで保証する。
        """
        from PIL import Image

        for _ in range(CONFLICT_RETRIES):
            marks = [("開始", time.perf_counter())]
            with _writing(job.file_id):
                try:
                    pdf = _current(job.file_id, fresh=True)
                except DocumentNotFound:
                    raise JobRejected(404, "書類が見つかりません（削除されたか、共有が外されました）")
                base_hash = _hash(pdf)
                marks.append(("書類の用意", time.perf_counter()))

                if not _allowed(job.file_id, job.email):
                    raise JobRejected(403, "この書類に署名できるアカウントではありません")
                all_fields = list_signature_fields(io.BytesIO(pdf))
                empty_fields = list_signature_fields(io.BytesIO(pdf), filled=False)
                mode, role = _mode_for(job.email, all_fields, empty_fields)
                if mode not in SIGNABLE:
                    return None  # もう押してある
                if (role if mode == MODE_ROLE_READY else None) != job.role:
                    raise JobRejected(409, "押す欄が変わりました。署名ページを開き直してください")

                signed = io.BytesIO()
                received = f"{job.requested_at} 受付"
                if mode == MODE_ROLE_READY:
                    sign_field(
                        io.BytesIO(pdf),
                        signed,
                        field_name=role,
                        signer=signer,
                        tsa_url=tsa_url,
                        signer_name=job.email,
                        reason=f"{role}として承認（{received}）",
                        seal=Image.open(io.BytesIO(job.stamp_png)) if job.stamp_png else None,
                    )
                else:
                    sign_invisible(
                        io.BytesIO(pdf),
                        signed,
                        field_name=silent_field_name(job.email),
                        signer=signer,
                        tsa_url=tsa_url,
                        signer_name=job.email,
                        reason=f"確認（{received}）",
                    )
                signed_pdf = signed.getvalue()
                marks.append(("署名（TSA込み）", time.perf_counter()))

                try:
                    _store_if_unchanged(job.file_id, signed_pdf, base_hash)
                except _Conflict:
                    # 間に誰かが書き戻した。その版を取り直して押し直す
                    logger.info("ほかの署名と重なったので押し直す: %s", job.file_id)
                    continue
                documents.put(job.file_id, (_hash(signed_pdf), signed_pdf))
                verified.put(job.file_id, True)
                marks.append(("書き戻し", time.perf_counter()))

            _log_breakdown("署名", marks)
            return SignatureNotice.create(
                file_id=job.file_id, signer_email=job.email, role=job.role, signed_pdf=signed_pdf
            )
        raise JobRejected(409, "ほかの人の署名と重なり続けました。もう一度押してください")

    def _process(job: SignJob, *, last_attempt: bool) -> bool:
        """キューから来た予約を押す。やり直させたいときだけ False を返す。

        押せたら記録のメール、やり直しても押せないと分かったら「押せなかった」メール。
        ⚠メールは応答を返す前に送る。応答のあとは CPU がほとんど割り当てられない。
        """
        key = (job.file_id, job.email.strip().lower())
        try:
            notice = _run_job(job)
        except JobRejected as exc:
            logger.warning("署名できなかった: %s %s (%s)", job.file_id, job.email, exc.detail)
            pending.forget(key)
            notify_quietly(
                notifier,
                SignatureNotice.failed(
                    file_id=job.file_id, signer_email=job.email, role=job.role, reason=exc.detail
                ),
            )
            return True
        except Exception:
            logger.exception("署名の途中で失敗: %s %s", job.file_id, job.email)
            if not last_attempt:
                return False
            pending.forget(key)
            notify_quietly(
                notifier,
                SignatureNotice.failed(
                    file_id=job.file_id,
                    signer_email=job.email,
                    role=job.role,
                    reason="時間をおいて何度か試しましたが、処理中のエラーが続きました",
                ),
            )
            return True
        pending.forget(key)
        if notice is not None:
            notify_quietly(notifier, notice)
        return True

    if hasattr(sign_queue, "bind"):
        # プロセス内で回すキュー（開発用）。やり直しはしない
        sign_queue.bind(lambda job: _process(job, last_attempt=True))

    @app.post("/s/{file_id}/sign")
    def do_sign(
        request: Request,
        background: BackgroundTasks,
        file_id: str,
        m: str = "",
        csrf: str = Form(""),
        seal_choice: str = Form(""),
        seal_image: UploadFile | None = File(None),
    ):
        """押したのを受け付ける。キューがあれば予約を積んで、すぐに返す。

        ここで確かめるのは本人・CSRF・押してよい欄かまで。判定には手元の写しを使う
        （押す直前に最新でもう一度確かめるので、ここで落とし直す必要はない）。
        """
        # ⚠このエンドポイントを async にしてはいけない。キューが無いときはここで
        # pyHanko が署名し、pyHanko は内部で asyncio.run() を呼ぶ
        pdf = _load(file_id, m)

        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        if not hmac.compare_digest(_csrf_token(qr_secret, file_id, email), csrf):
            raise HTTPException(status_code=403, detail="フォームの有効期限が切れています")

        mode, role, _ = _situation(pdf, email, file_id)
        if mode == MODE_STRANGER:
            raise HTTPException(status_code=403, detail="この書類に署名できるアカウントではありません")
        if mode == MODE_PENDING:
            raise HTTPException(status_code=409, detail="受け付け済みです。書類への反映をお待ちください")
        if mode not in SIGNABLE:
            raise HTTPException(status_code=409, detail="この書類にはもう署名しています")

        uploaded = seal_image.file.read() if seal_image is not None else None
        if uploaded:
            try:
                prepare_uploaded(uploaded)  # 押す前に検疫を通す
            except UnusableImage as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        # 印影は押した人のログイン中にしか作れない（アイコン・アップロード画像）ので、ここで絵にして持たせる
        stamp_png = None
        if mode == MODE_ROLE_READY:
            buffer = io.BytesIO()
            _stamp_for(request, email, uploaded, seal_choice).save(buffer, format="PNG")
            stamp_png = buffer.getvalue()

        job = SignJob(
            file_id=file_id,
            email=email,
            role=role if mode == MODE_ROLE_READY else None,
            stamp_png=stamp_png,
            requested_at=datetime.now(JST).isoformat(timespec="seconds"),
        )
        key = (file_id, email.strip().lower())
        if sign_queue is None:
            try:
                notice = _run_job(job)
            except JobRejected as exc:
                raise HTTPException(status_code=exc.status, detail=exc.detail)
            # 画面を返したあとに送る。応答を待つあいだ、押した人を待たせない
            if notice is not None:
                background.add_task(notify_quietly, notifier, notice)
        else:
            pending.put(key, True)
            try:
                sign_queue.enqueue(job)
            except Exception:
                pending.forget(key)
                logger.exception("署名の予約を積めなかった: %s", file_id)
                raise HTTPException(status_code=503, detail="受け付けられませんでした。もう一度押してください")

        # 一覧からまとめて押すときは、画面を組み立てて返す必要が無い
        if request.headers.get("x-requested-with") == "inbox":
            return JSONResponse({"status": "accepted"}, status_code=202)
        return _back_to_sign_page(file_id, m)

    @app.post(TASK_PATH)
    def run_task(request: Request, payload: dict = Body(...)) -> Response:
        """キュー（Cloud Tasks）から呼び返されて、予約された署名を押す。

        500 を返すと Cloud Tasks が間を置いてやり直す。やり直しても無駄な失敗
        （共有を外された等）と、やり直しの最後の1回では 200 を返して打ち切り、本人へ知らせる。
        """
        if task_auth is None or not task_auth(request):
            raise HTTPException(status_code=403, detail="forbidden")
        job = SignJob.from_json(json.dumps(payload).encode("utf-8"))
        retried = int(request.headers.get("x-cloudtasks-taskretrycount", "0") or 0)
        done = _process(job, last_attempt=retried + 1 >= MAX_ATTEMPTS)
        return Response(status_code=200 if done else 500)

    @app.post("/s/{file_id}/revoke")
    def do_revoke(
        request: Request, background: BackgroundTasks, file_id: str, m: str = "", csrf: str = Form("")
    ) -> RedirectResponse:
        """押し間違えたときに、自分の署名を外す。

        外せるのは自分が最後の押し手のときだけ。後から誰かが押していたら、
        その署名が自分のものを含めて覆っているので、抜くと相手のものが壊れる。
        """
        marks = [("開始", time.perf_counter())]
        with _writing(file_id):
            pdf = _load(file_id, m, fresh=True)
            base_hash = _hash(pdf)
            marks.append(("書類の用意", time.perf_counter()))

            email = identity_provider.verified_email(request)
            if not email:
                raise HTTPException(status_code=401, detail="ログインが必要です")
            if not hmac.compare_digest(_csrf_token(qr_secret, file_id, email), csrf):
                raise HTTPException(status_code=403, detail="フォームの有効期限が切れています")

            field = _revocable_field(pdf, email)
            if field is None:
                raise HTTPException(
                    status_code=409,
                    detail="取り消せません。あなたの後に誰かが署名しているか、署名がありません",
                )

            try:
                reverted = revoke_last_signature(pdf, expect_signer=email)
            except NotRevocable as exc:
                raise HTTPException(status_code=409, detail=str(exc))

            try:
                _store_if_unchanged(file_id, reverted, base_hash)
            except _Conflict:
                raise HTTPException(
                    status_code=409, detail="ほかの人の署名と重なりました。もう一度押してください"
                )
            documents.put(file_id, (_hash(reverted), reverted))
            verified.put(file_id, True)
            marks.append(("書き戻し", time.perf_counter()))

        _log_breakdown("取り消し", marks)

        # 押したときに記録を送っているなら、取り消しも同じ場所に残す。
        # 送ったメールは消せないので、事実の側を揃える
        background.add_task(
            notify_quietly,
            notifier,
            SignatureNotice.create(
                file_id=file_id,
                signer_email=email,
                role=None if field.startswith("silent-") else field,
                signed_pdf=reverted,
                revoked=True,
            ),
        )

        return _back_to_sign_page(file_id, m)

    @app.get("/seal/preview.png")
    def seal_preview(request: Request, choice: str = "") -> Response:
        """いま押されることになる絵。署名ページに出す。

        choice を渡すと、その候補の絵を返す（選ぶ画面に並べるため）。
        """
        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        buffer = io.BytesIO()
        _stamp_for(request, email, None, choice).save(buffer, format="PNG")
        return Response(buffer.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})

    @app.get("/account/icon.png")
    def account_icon(request: Request) -> Response:
        """いまログインしている人の顔。画面右上に出す。

        押印枠に押される絵と同じものを使う。ここに出ている顔と紙に載る印が
        違うと、切り替えの導線としての意味が無い。
        """
        email = identity_provider.verified_email(request)
        if not email:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        buffer = io.BytesIO()
        _seal_source(request, email, None).save(buffer, format="PNG")
        return Response(buffer.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})

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
