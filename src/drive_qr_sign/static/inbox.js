// 書類の一覧。署名待ちはまとめて署名し、署名済みは開いて取り消せる。
//
// 押した瞬間に「署名済み」にする。サーバがやるのは受け付けまでで（本人と欄の確認だけ）、
// PDF への署名と書き戻しはサーバ側のキューが後で行う（tasks.py）。受け付けを断られた行だけ、
// 表示を戻して理由を出す。
//
// ⚠送るのは keepalive 付き。押してすぐ画面を閉じても、受け付けの要求は届く。

import { attachViewer } from "./viewer.js";

// 開いたときに初めて PDF と押した人を読む。開かれなかった書類は落とさない
const opened = new Set();
document.addEventListener(
  "toggle",
  (event) => {
    const details = event.target;
    if (!(details instanceof HTMLDetailsElement) || !details.open) return;
    const item = details.closest(".item");
    if (!item || opened.has(item)) return;
    opened.add(item);
    const viewer = item.querySelector(".viewer");
    if (viewer) attachViewer(viewer)();
    loadDetail(item);
  },
  true // toggle は泡立たないので、捕獲側で拾う
);

/** 押した人の一覧と、署名済みなら取り消しボタン。 */
async function loadDetail(item) {
  const box = item.querySelector(".detail");
  if (!box) return;
  try {
    const response = await fetch(box.dataset.src, { credentials: "same-origin" });
    if (!response.ok) throw new Error(await reason(response));
    renderDetail(item, box, await response.json());
  } catch (error) {
    console.error(error);
    box.replaceChildren(note(`押した人を読めませんでした（${error.message}）`));
  }
}

function renderDetail(item, box, detail) {
  const parts = [];

  // 紙面に出ない署名は、ここでしか見えない
  if (detail.signed_by.length) {
    const list = document.createElement("ul");
    list.className = "signed";
    for (const signature of detail.signed_by) {
      const row = document.createElement("li");
      const who = document.createElement("span");
      who.className = "address";
      who.textContent = signature.who;
      const what = document.createElement(signature.role ? "b" : "i");
      what.textContent = signature.role || "確認";
      row.append(who, what);
      list.append(row);
    }
    parts.push(list);
  } else {
    parts.push(note("まだ誰も署名していません。"));
  }
  parts.push(
    note(
      detail.empty_fields.length
        ? `未署名の押印枠: ${detail.empty_fields.join("、")}`
        : "押印枠はすべて埋まっています。"
    )
  );
  {
    // 原本を開く先。Drive にあるならそちらを指す（無ければアプリが配る PDF）
    const link = document.createElement("a");
    link.href = detail.document_url || item.querySelector(".viewer").dataset.src;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = detail.document_url ? "Google ドライブで開く" : "PDF を開く";
    const line = note("");
    line.append(link);
    parts.push(line);
  }

  if (item.dataset.revoke && !item.classList.contains("revoked")) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "quiet";
    button.textContent = "署名を取り消す";
    if (detail.revocable) {
      button.addEventListener("click", () => revoke(item, button));
      parts.push(button, note("押し間違えたときに使います。あなたが最後の押し手のあいだだけ取り消せます。"));
    } else {
      // 押せない理由が見えるように、ボタンは消さずに灰色のまま残す
      button.disabled = true;
      parts.push(
        button,
        note("あなたの後に誰かが署名しているため、いまは取り消せません。積んだ順にしか外せないので、後の人が取り消すのを待つことになります。")
      );
    }
  }
  box.replaceChildren(...parts);
}

async function revoke(item, button) {
  button.disabled = true;
  button.textContent = "処理中…";
  const body = new FormData();
  body.append("csrf", item.dataset.csrf);
  try {
    const response = await fetch(item.dataset.revoke, {
      method: "POST",
      body,
      credentials: "same-origin",
      headers: { "X-Requested-With": "inbox" },
    });
    if (!response.ok) throw new Error(await reason(response));
    item.classList.add("revoked");
    item.querySelector(".state").textContent = "取り消しました（署名待ちに戻りました）";
    loadDetail(item);
    const viewer = item.querySelector(".viewer");
    if (viewer) attachViewer(viewer)();
  } catch (error) {
    console.error(error);
    button.disabled = false;
    button.textContent = "署名を取り消す";
    button.after(note(error.message || "取り消せませんでした"));
  }
}

// ---- 署名待ち：まとめて署名する ----

const form = document.getElementById("batch");
if (form) setUpBatch(form);

function setUpBatch(form) {
  const button = document.getElementById("batch-sign");
  const selectAll = document.getElementById("select-all");
  const items = () => [...form.querySelectorAll(".item")];
  const pending = () => items().filter((item) => !item.classList.contains("done"));
  const picked = () => pending().filter((item) => item.querySelector(".pick").checked);

  function refresh() {
    const count = picked().length;
    button.disabled = count === 0;
    button.textContent = count ? `選んだ${count}件に署名する` : "選んだ書類に署名する";
    const rest = pending();
    selectAll.checked = rest.length > 0 && count === rest.length;
    selectAll.disabled = rest.length === 0;
  }

  form.addEventListener("change", (event) => {
    if (event.target === selectAll) {
      pending().forEach((item) => {
        item.querySelector(".pick").checked = selectAll.checked;
      });
    }
    if (event.target.classList.contains("pick") || event.target === selectAll) refresh();
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const queue = picked();
    if (!queue.length) return;

    // 印影はまとめて押す全件に同じものを使う
    const choice = form.querySelector('input[name="seal_choice"]:checked')?.value || "";
    const upload = form.querySelector('input[type="file"][name="seal_image"]')?.files?.[0];

    // 先に見た目を済ませる。待たせるのは、押した人ではなくサーバのキュー
    for (const item of queue) {
      settle(item, "done", "署名済み");
      item.querySelector("details").open = false;
    }
    refresh();

    for (const item of queue) {
      const body = new FormData();
      body.append("csrf", item.dataset.csrf);
      body.append("seal_choice", choice);
      if (upload) body.append("seal_image", upload);
      fetch(item.dataset.action, {
        method: "POST",
        body,
        credentials: "same-origin",
        // ⚠keepalive の本文は 64KB まで。アップロードした画像を付けるときは外す
        keepalive: !upload,
        headers: { "X-Requested-With": "inbox" },
      })
        .then(async (response) => {
          if (!response.ok) throw new Error(await reason(response));
        })
        .catch((error) => {
          console.error(error);
          settle(item, "failed", error.message || "受け付けられませんでした");
          refresh();
        });
    }
  });

  /** 行の状態を切り替える。done の行は選べなくなり、failed の行はもう一度選べる。 */
  function settle(item, state, label) {
    item.classList.remove("done", "failed");
    item.classList.add(state);
    item.querySelector(".state").textContent = label;
    const box = item.querySelector(".pick");
    box.checked = false;
    box.disabled = state === "done";
  }

  refresh();
}

// ---- 印影の選択 ----

// 印影の選択は背景を暗くしたポップアップで出す。その場で開くと署名ボタンが
// 押し下げられて、押す場所が動いてしまう。
document.addEventListener("click", (event) => {
  const opener = event.target.closest("[data-opens]");
  if (opener) {
    document.getElementById(opener.dataset.opens)?.showModal();
    return;
  }
  const closer = event.target.closest("[data-closes]");
  if (closer) closer.closest("dialog")?.close();
});

// 印影を選んだら、押される絵の表示をその場で入れ替える。
// 何が押されるのかを、押す前に見て確かめられることが目的。
document.addEventListener("change", (event) => {
  const preview = document.getElementById("seal-preview");
  if (!preview) return;

  const radio = event.target.closest('input[name="seal_choice"]');
  if (radio?.dataset.preview) {
    preview.src = radio.dataset.preview;
    const file = radio.closest(".choices")?.querySelector('input[type="file"]');
    if (file) file.value = ""; // 選び直したらアップロードは使わない
    radio.closest("dialog")?.close(); // 選んだら閉じる。選択そのものが返事になる
    return;
  }

  const file = event.target.closest('input[type="file"][name="seal_image"]');
  if (file?.files?.length) {
    // 検疫（丸く切り抜く等）はサーバ側で通すので、ここで見えるのは元の画像
    preview.src = URL.createObjectURL(file.files[0]);
    file.closest(".choices")?.querySelectorAll('input[name="seal_choice"]').forEach((other) => {
      other.checked = false;
    });
    file.closest("dialog")?.close();
  }
});

// ---- 共通 ----

function note(text) {
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = text;
  return p;
}

/** 断られた理由。サーバが日本語で返すので、そのまま見せる。 */
async function reason(response) {
  try {
    const data = await response.json();
    if (data && typeof data.detail === "string") return data.detail;
  } catch (_) {
    // 本文が JSON でなければ番号だけ
  }
  return `失敗しました（${response.status}）`;
}

document.body.dataset.ready = "1";
