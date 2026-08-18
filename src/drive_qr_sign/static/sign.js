// 押す・取り消すを、画面を切り替えずにその場で反映する。
//
// 「署名しました」という専用の画面は作らない。押した結果は書類とボタンの状態を
// 見れば分かるので、読むだけの画面が1枚増えるとかえって手間になる。
//
// JS が動かない環境では素のフォーム送信になり、サーバ側の 303 で同じ画面へ戻る。
// どちらの経路でも見えるものは同じで、こちらは読んでいた位置を保てるだけ。

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-inplace]");
  if (!form) return;
  event.preventDefault();

  const button = form.querySelector("button");
  const label = button ? button.textContent : "";
  if (button) {
    button.disabled = true;
    button.textContent = "処理中…";
  }

  try {
    // 303 は fetch が自動で追うので、返るのは更新後の署名ページそのもの
    const response = await fetch(form.action, {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { "X-Requested-With": "fetch" },
    });
    if (!response.ok) throw new Error(`${response.status}`);
    swapAction(await response.text());
    window.reloadDocument?.();
  } catch (error) {
    console.error(error);
    // その場で直せる見込みはないので、素直に読み込み直させる
    if (button) {
      button.disabled = false;
      button.textContent = label;
    }
    form.insertAdjacentHTML(
      "afterend",
      '<p class="note">うまくいきませんでした。画面を再読み込みしてやり直してください。</p>'
    );
  }
});

/** 返ってきたページから、説明とボタンの部分だけを入れ替える。 */
function swapAction(html) {
  const fresh = new DOMParser().parseFromString(html, "text/html").querySelector(".cols");
  const current = document.querySelector(".cols");
  if (fresh && current) current.replaceWith(fresh);
}

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
    radio.closest("dialog")?.close();  // 選んだら閉じる。選択そのものが返事になる
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
