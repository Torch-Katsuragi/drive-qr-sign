// 紙にカメラをかざすと、押印の状況が紙面に重なって見える。
//
// 仕掛けは単純で、QR を基準点として使っている。QR が紙のどこにあるかは PDF に
// 書いてあるので（layout.py）、カメラに写った QR の四隅と突き合わせれば、
// 紙面の座標をカメラ画像の座標へ移す変換（ホモグラフィ）が決まる。
// あとは押印枠の四隅を同じ変換で移して、そこに絵を描くだけ。
//
// 重ねる絵は PDF から切り出す。作り直すのではなく、実際に押された appearance を
// そのまま見せたいため（pdf.js で1ページ描いて、枠の矩形で切る）。

import * as pdfjs from "./pdfjs/pdf.min.mjs";

const root = document.getElementById("ar");
const video = document.getElementById("camera");
const canvas = document.getElementById("overlay");
const status = document.getElementById("ar-status");
const context = canvas.getContext("2d");

const scratch = document.createElement("canvas");
const scratchContext = scratch.getContext("2d", { willReadFrequently: true });

let layout = null;
const stamps = new Map(); // フィールド名 → 切り出した画像

start().catch((error) => {
  console.error(error);
  status.textContent = "カメラを開けませんでした。ブラウザの権限を確認してください。";
});

async function start() {
  pdfjs.GlobalWorkerOptions.workerSrc = root.dataset.worker;

  status.textContent = "書類の情報を読んでいます…";
  layout = await (await fetch(root.dataset.layout, { credentials: "same-origin" })).json();
  if (!layout.qr) {
    status.textContent = "この書類には QR が焼かれていないので、位置を合わせられません。";
    return;
  }

  await cutStamps();

  status.textContent = "カメラを起動しています…";
  video.srcObject = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
    audio: false,
  });
  await video.play();

  status.textContent = "紙の QR にかざしてください";
  requestAnimationFrame(tick);
}

/** 署名済みの枠の見た目を PDF から切り出しておく。 */
async function cutStamps() {
  const pdf = await pdfjs.getDocument({ url: root.dataset.pdf, withCredentials: true }).promise;
  const page = await pdf.getPage(1);
  const scale = 3; // 重ねると拡大されるので、紙面の3倍で焼いておく
  const viewport = page.getViewport({ scale });

  const sheet = document.createElement("canvas");
  sheet.width = Math.ceil(viewport.width);
  sheet.height = Math.ceil(viewport.height);
  await page.render({ canvasContext: sheet.getContext("2d"), viewport }).promise;

  for (const field of layout.fields) {
    if (!field.signed) continue;
    const box = field.box;
    const crop = document.createElement("canvas");
    crop.width = Math.max(1, Math.round((box[2] - box[0]) * scale));
    crop.height = Math.max(1, Math.round((box[3] - box[1]) * scale));
    crop.getContext("2d").drawImage(
      sheet,
      box[0] * scale,
      (layout.page.height - box[3]) * scale, // PDF は左下原点、canvas は左上原点
      crop.width,
      crop.height,
      0, 0, crop.width, crop.height
    );
    stamps.set(field.name, crop);
  }
}

function tick() {
  requestAnimationFrame(tick);
  if (video.readyState !== video.HAVE_ENOUGH_DATA) return;

  fitCanvas();
  const found = detect();
  context.clearRect(0, 0, canvas.width, canvas.height);
  if (!found) {
    status.textContent = "紙の QR にかざしてください";
    return;
  }

  const project = solve(qrCornersInPage(), found);
  if (!project) return;

  status.textContent = "";
  for (const field of layout.fields) drawField(field, project);
}

function fitCanvas() {
  if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
  }
}

/** カメラ画像から QR の四隅を拾う。 */
function detect() {
  const short = 480; // 解析は縮小して行う。等倍だと処理が追いつかない
  const ratio = short / Math.min(video.videoWidth, video.videoHeight);
  scratch.width = Math.round(video.videoWidth * ratio);
  scratch.height = Math.round(video.videoHeight * ratio);
  scratchContext.drawImage(video, 0, 0, scratch.width, scratch.height);

  const pixels = scratchContext.getImageData(0, 0, scratch.width, scratch.height);
  const result = window.jsQR(pixels.data, pixels.width, pixels.height, {
    inversionAttempts: "dontInvert",
  });
  if (!result) return null;

  const back = 1 / ratio;
  const l = result.location;
  return [
    [l.topLeftCorner.x * back, l.topLeftCorner.y * back],
    [l.topRightCorner.x * back, l.topRightCorner.y * back],
    [l.bottomRightCorner.x * back, l.bottomRightCorner.y * back],
    [l.bottomLeftCorner.x * back, l.bottomLeftCorner.y * back],
  ];
}

/** 紙面での QR の四隅。canvas と向きを揃えて左上原点にする。 */
function qrCornersInPage() {
  const box = layout.qr.box;
  const top = layout.page.height - box[3];
  const bottom = layout.page.height - box[1];
  return [[box[0], top], [box[2], top], [box[2], bottom], [box[0], bottom]];
}

/** 紙面座標 → カメラ画像座標 のホモグラフィを4点から解く（DLT）。 */
function solve(from, to) {
  const a = [];
  const b = [];
  for (let i = 0; i < 4; i++) {
    const x = from[i][0];
    const y = from[i][1];
    const u = to[i][0];
    const v = to[i][1];
    a.push([x, y, 1, 0, 0, 0, -u * x, -u * y]);
    a.push([0, 0, 0, x, y, 1, -v * x, -v * y]);
    b.push(u, v);
  }
  const h = gaussian(a, b);
  if (!h) return null;
  h.push(1);
  return (x, y) => {
    const w = h[6] * x + h[7] * y + h[8];
    return [(h[0] * x + h[1] * y + h[2]) / w, (h[3] * x + h[4] * y + h[5]) / w];
  };
}

function gaussian(a, b) {
  const n = b.length;
  const m = a.map((row, i) => row.concat([b[i]]));
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let row = col + 1; row < n; row++) {
      if (Math.abs(m[row][col]) > Math.abs(m[pivot][col])) pivot = row;
    }
    if (Math.abs(m[pivot][col]) < 1e-9) return null; // QR が潰れて見えている
    const swap = m[col];
    m[col] = m[pivot];
    m[pivot] = swap;
    for (let row = 0; row < n; row++) {
      if (row === col) continue;
      const factor = m[row][col] / m[col][col];
      for (let k = col; k <= n; k++) m[row][k] -= factor * m[col][k];
    }
  }
  return m.map((row, i) => row[n] / row[i]);
}

function drawField(field, project) {
  const box = field.box;
  const top = layout.page.height - box[3];
  const bottom = layout.page.height - box[1];
  const corners = [[box[0], top], [box[2], top], [box[2], bottom], [box[0], bottom]].map(
    (point) => project(point[0], point[1])
  );

  const stamp = stamps.get(field.name);
  if (stamp) {
    drawWarped(stamp, corners);
  } else {
    // 未署名の枠は、空いていることが分かればよい
    context.save();
    context.strokeStyle = "rgba(120,120,130,.9)";
    context.setLineDash([8, 6]);
    context.lineWidth = 2;
    outline(corners);
    context.stroke();
    context.restore();
  }
  label(field, corners);
}

/** 四隅に合わせて画像を貼る。三角形2枚に割ってアフィン変換で近似する。 */
function drawWarped(image, corners) {
  const tl = corners[0];
  const tr = corners[1];
  const br = corners[2];
  const bl = corners[3];
  triangle(image, tl, tr, bl, [0, 0], [image.width, 0], [0, image.height]);
  triangle(image, tr, br, bl, [image.width, 0], [image.width, image.height], [0, image.height]);
}

function triangle(image, p0, p1, p2, s0, s1, s2) {
  const denominator = (s1[0] - s0[0]) * (s2[1] - s0[1]) - (s2[0] - s0[0]) * (s1[1] - s0[1]);
  if (!denominator) return;
  const a = ((p1[0] - p0[0]) * (s2[1] - s0[1]) - (p2[0] - p0[0]) * (s1[1] - s0[1])) / denominator;
  const b = ((p2[0] - p0[0]) * (s1[0] - s0[0]) - (p1[0] - p0[0]) * (s2[0] - s0[0])) / denominator;
  const c = ((p1[1] - p0[1]) * (s2[1] - s0[1]) - (p2[1] - p0[1]) * (s1[1] - s0[1])) / denominator;
  const d = ((p2[1] - p0[1]) * (s1[0] - s0[0]) - (p1[1] - p0[1]) * (s2[0] - s0[0])) / denominator;

  context.save();
  context.beginPath();
  context.moveTo(p0[0], p0[1]);
  context.lineTo(p1[0], p1[1]);
  context.lineTo(p2[0], p2[1]);
  context.closePath();
  context.clip();
  context.transform(a, c, b, d, p0[0] - a * s0[0] - b * s0[1], p0[1] - c * s0[0] - d * s0[1]);
  context.drawImage(image, 0, 0);
  context.restore();
}

function outline(corners) {
  context.beginPath();
  corners.forEach((point, i) => (i ? context.lineTo(point[0], point[1]) : context.moveTo(point[0], point[1])));
  context.closePath();
}

function label(field, corners) {
  const anchor = corners[3];
  const text = field.signed ? field.name + ": " + field.signer : field.name + ": 未署名";
  context.save();
  context.font = "16px system-ui, sans-serif";
  const width = context.measureText(text).width + 12;
  context.fillStyle = field.signed ? "rgba(20,120,60,.85)" : "rgba(60,60,70,.75)";
  context.fillRect(anchor[0], anchor[1] + 4, width, 24);
  context.fillStyle = "#fff";
  context.fillText(text, anchor[0] + 6, anchor[1] + 21);
  context.restore();
}
