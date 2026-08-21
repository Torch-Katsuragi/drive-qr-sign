// 署名ページに書類を表示する。描画は pdf.js（同梱・Apache-2.0）で、
//
// ⚠同梱しているのは **legacy ビルド**。既定の modern ビルドは「最新のブラウザ」前提で、
// 少し古い iPhone の Safari で落ちる。回覧板を回す相手の端末は選べないので、
// 広く動くほうを取る（legacy でも Safari 18+ が pdf.js の言う対応範囲）。
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

  // 見えたページだけ描く。分厚い書類でも開いた瞬間に全部描かない
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        observer.unobserve(entry.target);
        drawPage(pdf, entry.target, cssWidth, sharpness());
      }
    },
    { rootMargin: "600px" }
  );

  currentPdf = pdf;
  watchZoom(container);

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

// ⚠1回描いた画像をピンチで引き伸ばすと、拡大したときに粗い。
// 端末の画素密度に**拡大の余地**を足した解像度で描いておき、拡大されたら描き直す。
const ZOOM_HEADROOM = 2;   // このぶんまでは描き直さずに耐える
const MAX_SHARPNESS = 6;   // これ以上は canvas が重くなるだけ。
// ⚠iOS には canvas の面積・総量の上限がある。描き直すのは**見えているページだけ**に
// しているのはそのため（分厚い書類で全ページを高解像度に持つと落ちる）

function sharpness() {
  const zoom = (window.visualViewport && window.visualViewport.scale) || 1;
  const density = Math.min(window.devicePixelRatio || 1, 2);
  return Math.min(density * ZOOM_HEADROOM * zoom, MAX_SHARPNESS);
}

/** ピンチで拡大されたら、その倍率で描き直す（引き伸ばした画像のままにしない）。 */
function watchZoom(container) {
  if (!window.visualViewport) return;
  let drawnAt = sharpness();
  let pending = null;
  window.visualViewport.addEventListener("resize", () => {
    const wanted = sharpness();
    if (wanted <= drawnAt * 1.2) return;  // 誤差では描き直さない
    clearTimeout(pending);
    // 指を離してから描く。拡大の途中で何度も描くと固まる
    pending = setTimeout(() => {
      drawnAt = wanted;
      container.querySelectorAll(".page").forEach((page) => {
        page.dataset.redraw = "1";
      });
      redrawVisible(container, wanted);
    }, 250);
  });
}

let currentPdf = null;

/** いま見えているページだけ、指定の細かさで描き直す。 */
function redrawVisible(container, wanted) {
  if (!currentPdf) return;
  const view = { top: -200, bottom: window.innerHeight + 200 };
  container.querySelectorAll(".page").forEach((element) => {
    const box = element.getBoundingClientRect();
    if (box.bottom < view.top || box.top > view.bottom) return;
    drawPage(currentPdf, element, container.clientWidth, wanted);
  });
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
