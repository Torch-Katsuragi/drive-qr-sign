// 署名待ちの一覧。選んだ書類を1件ずつ署名する。
//
// 押すのは署名ページと同じ POST（/s/<id>/sign）。まとめて1回で送る口は作らない。
// 1件あたり数秒かかる（署名＋タイムスタンプ＋書き戻し）ので、1回にまとめると
// 何十秒も無言で待たせることになる。1件ずつなら、終わった行から順に印が付く。
// 途中で1件失敗しても、残りはそのまま進める。

import { attachViewer } from "./viewer.js";

const form = document.getElementById("batch");
const button = document.getElementById("batch-sign");
const selectAll = document.getElementById("select-all");
const items = () => [...form.querySelectorAll(".item")];
const pending = () => items().filter((item) => !item.classList.contains("done"));
const picked = () => pending().filter((item) => item.querySelector(".pick").checked);

let running = false;

function refresh() {
  const count = picked().length;
  button.disabled = running || count === 0;
  if (!running) button.textContent = count ? `選んだ${count}件に署名する` : "選んだ書類に署名する";
  const rest = pending();
  selectAll.checked = rest.length > 0 && count === rest.length;
  selectAll.disabled = running || rest.length === 0;
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const queue = picked();
  if (!queue.length) return;

  running = true;
  form.querySelectorAll(".pick").forEach((box) => (box.disabled = true));
  let done = 0;
  let failed = 0;

  for (const item of queue) {
    button.textContent = `署名中… ${done + failed + 1} / ${queue.length}`;
    const state = item.querySelector(".state");
    state.textContent = "署名中…";
    item.classList.add("busy");
    try {
      const body = new FormData();
      body.append("csrf", item.dataset.csrf);
      const response = await fetch(item.dataset.action, {
        method: "POST",
        body,
        credentials: "same-origin",
        headers: { "X-Requested-With": "fetch" },
      });
      if (!response.ok) throw new Error(await reason(response));
      item.classList.add("done");
      item.querySelector(".pick").checked = false;
      state.textContent = "署名済み";
      done += 1;
      // 開いている書類は、押したあとの版で描き直す
      const box = item.querySelector(".viewer");
      if (viewers.has(box) && item.querySelector("details").open) viewers.get(box)();
    } catch (error) {
      console.error(error);
      item.classList.add("failed");
      state.textContent = error.message || "失敗しました";
      failed += 1;
    } finally {
      item.classList.remove("busy");
    }
  }

  running = false;
  items().forEach((item) => {
    item.querySelector(".pick").disabled = item.classList.contains("done");
  });
  refresh();
  if (failed) {
    button.insertAdjacentHTML(
      "afterend",
      `<p class="note">${done}件署名し、${failed}件はできませんでした。理由は各行に出ています。</p>`
    );
  }
});

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
