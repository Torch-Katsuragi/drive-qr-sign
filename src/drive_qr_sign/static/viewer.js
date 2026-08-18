// 署名ページに書類を表示する。描画は pdf.js（同梱・Apache-2.0）で、
// サーバは PDF をそのまま渡すだけ。ページ画像に焼く方式と違って
// サーバの CPU を使わず、拡大してもぼけず、文字を選択できる。

import * as pdfjs from "./pdfjs/pdf.min.mjs";

let revision = 0;

const container = document.getElementById("document");
if (container) {
  pdfjs.GlobalWorkerOptions.workerSrc = container.dataset.worker;
  render();
  // 署名・取り消しの直後に、書類だけを描き直すための入口（static/sign.js から呼ぶ）
  window.reloadDocument = render;
}

function render() {
  // 描き直しのあいだ背丈を保つ。空にした瞬間にページが縮むと、
  // ブラウザがスクロール位置を切り詰めて先頭へ飛ぶ
  const height = container.offsetHeight;
  if (height) container.style.minHeight = `${height}px`;
  container.replaceChildren();
  revision += 1;
  show(container)
    .then(() => {
      container.style.minHeight = "";
    })
    .catch((error) => {
      container.style.minHeight = "";
      console.error(error);
      container.insertAdjacentHTML(
        "beforeend",
        '<p class="note">書類を表示できませんでした。「PDF を開く」から確認してください。</p>'
      );
    });
}

async function show(container) {
  const pdf = await pdfjs.getDocument({
    // 押したあとの版を確実に取りに行く（同じ URL のままだと古い版が出る余地がある）
    url: revision > 1 ? `${container.dataset.src}&r=${revision}` : container.dataset.src,
    withCredentials: true, // セッションのクッキーを付ける
  }).promise;

  // 画面が細いほど拡大率を上げる必要はない。実寸の幅に合わせて描く
  const cssWidth = container.clientWidth;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  // 見えたページだけ描く。分厚い書類でも開いた瞬間に全部描かない
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        observer.unobserve(entry.target);
        drawPage(pdf, entry.target, cssWidth, dpr);
      }
    },
    { rootMargin: "600px" }
  );

  const first = await pdf.getPage(1);
  const ratio = first.getViewport({ scale: 1 }).height / first.getViewport({ scale: 1 }).width;

  for (let number = 1; number <= pdf.numPages; number++) {
    const page = document.createElement("div");
    page.className = "page";
    page.dataset.page = String(number);
    // 描く前から場所を取っておく。あとから高さが増えてスクロールが飛ぶのを防ぐ
    page.style.aspectRatio = `1 / ${ratio}`;
    container.appendChild(page);
    observer.observe(page);
  }
}

async function drawPage(pdf, element, cssWidth, dpr) {
  const page = await pdf.getPage(Number(element.dataset.page));
  const base = page.getViewport({ scale: 1 });
  const scale = cssWidth / base.width;
  const viewport = page.getViewport({ scale });

  const canvas = document.createElement("canvas");
  canvas.width = Math.floor(viewport.width * dpr);
  canvas.height = Math.floor(viewport.height * dpr);
  canvas.style.width = "100%";
  canvas.style.height = "auto";

  element.style.aspectRatio = `${viewport.width} / ${viewport.height}`;
  element.replaceChildren(canvas);

  await page.render({
    canvasContext: canvas.getContext("2d"),
    viewport: page.getViewport({ scale: scale * dpr }),
  }).promise;

  await addTextLayer(page, element, viewport, scale);
}

async function addTextLayer(page, element, viewport, scale) {
  if (!pdfjs.TextLayer) return; // 版が変わって無くなっても、絵は出ているので黙って諦める

  const layer = document.createElement("div");
  layer.className = "textLayer";
  // pdf.js は文字の位置をこの変数から計算する
  layer.style.setProperty("--scale-factor", String(scale));
  element.appendChild(layer);

  await new pdfjs.TextLayer({
    textContentSource: page.streamTextContent(),
    container: layer,
    viewport,
  }).render();
}
