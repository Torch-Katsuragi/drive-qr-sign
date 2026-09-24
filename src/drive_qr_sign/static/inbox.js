// 署名待ちの一覧。選んだ書類をまとめて署名する。
//
// 押した瞬間に「署名済み」にする。サーバがやるのは受け付けまでで（本人と欄の確認だけ）、
// PDF への署名と書き戻しはサーバ側のキューが後で行う（tasks.py）。受け付けを断られた行だけ、
// 表示を戻して理由を出す。
//
// ⚠送るのは keepalive 付き。押してすぐ画面を閉じても、受け付けの要求は届く。
// 押すのは署名ページと同じ POST（/s/<id>/sign）で、QR から来たときと同じ判定を通る。

import { attachViewer } from "./viewer.js";

const form = document.getElementById("batch");
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

// 開いたときに初めて PDF を読む。開かれなかった書類は落とさない
const viewers = new Map();
form.addEventListener(
  "toggle",
  (event) => {
    const details = event.target;
    if (!(details instanceof HTMLDetailsElement) || !details.open) return;
    const box = details.querySelector(".viewer");
    if (!box || viewers.has(box)) return;
    const render = attachViewer(box);
    viewers.set(box, render);
    render();
  },
  true // toggle は泡立たないので、捕獲側で拾う
);

form.addEventListener("change", (event) => {
  if (event.target === selectAll) {
    pending().forEach((item) => {
      item.querySelector(".pick").checked = selectAll.checked;
    });
  }
  refresh();
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const queue = picked();
  if (!queue.length) return;

  // 先に見た目を済ませる。待たせるのは、押した人ではなくサーバのキュー
  for (const item of queue) {
    settle(item, "done", "署名済み");
    item.querySelector("details").open = false;
  }
  refresh();

  for (const item of queue) {
    const body = new FormData();
    body.append("csrf", item.dataset.csrf);
    fetch(item.dataset.action, {
      method: "POST",
      body,
      credentials: "same-origin",
      keepalive: true,
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

button.dataset.ready = "1";
refresh();
