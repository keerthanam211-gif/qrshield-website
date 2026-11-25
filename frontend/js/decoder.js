// QR decoding: live camera scanning and still-image decoding.
// Uses the native BarcodeDetector when available (fast, handles rotation) and falls back to jsQR.

let nativeDetector; // undefined = not probed, null = unavailable
async function getNativeDetector() {
  if (nativeDetector !== undefined) return nativeDetector;
  nativeDetector = null;
  try {
    if ("BarcodeDetector" in window) {
      const formats = await window.BarcodeDetector.getSupportedFormats();
      if (formats.includes("qr_code")) nativeDetector = new window.BarcodeDetector({ formats: ["qr_code"] });
    }
  } catch { nativeDetector = null; }
  return nativeDetector;
}

function jsqrDecode(ctx, w, h, inversion = "attemptBoth") {
  if (typeof window.jsQR !== "function") throw new Error("QR decoder failed to load. Please reload the page.");
  const img = ctx.getImageData(0, 0, w, h);
  const r = window.jsQR(img.data, w, h, { inversionAttempts: inversion });
  return r && r.data ? r.data : null;
}

// ------------------------------------------------------------------ camera
export class CameraScanner {
  constructor(video, { onDetect, onState }) {
    this.video = video;
    this.onDetect = onDetect;
    this.onState = onState || (() => {});
    this.stream = null;
    this.devices = [];
    this.deviceIndex = -1;
    this.running = false;
    this.torchOn = false;
    this.canvas = document.createElement("canvas");
    this.ctx = this.canvas.getContext("2d", { willReadFrequently: true });
    this.frame = 0;
    this.lastTick = 0;
  }

  static support() {
    if (!window.isSecureContext) return { ok: false, reason: "insecure" };
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return { ok: false, reason: "unsupported" };
    return { ok: true };
  }

  async start(deviceId) {
    const sup = CameraScanner.support();
    if (!sup.ok) throw Object.assign(new Error(sup.reason), { name: sup.reason === "insecure" ? "InsecureContext" : "NotSupportedError" });
    this.stop(false);
    const tries = deviceId
      ? [{ video: { deviceId: { exact: deviceId }, width: { ideal: 1280 }, height: { ideal: 720 } } }]
      : [
          { video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } } },
          { video: { facingMode: "environment" } },
          { video: true },
        ];
    let lastErr;
    for (const c of tries) {
      try {
        this.stream = await navigator.mediaDevices.getUserMedia({ audio: false, ...c });
        break;
      } catch (e) {
        lastErr = e;
        // Permission problems won't be fixed by relaxing constraints.
        if (e.name === "NotAllowedError" || e.name === "SecurityError") throw e;
      }
    }
    if (!this.stream) throw lastErr || new Error("Camera unavailable");

    this.video.srcObject = this.stream;
    this.video.setAttribute("playsinline", "");
    this.video.muted = true;
    await this.video.play().catch(() => {});
    await new Promise((res) => (this.video.readyState >= 2 ? res() : this.video.addEventListener("loadeddata", res, { once: true })));

    try {
      this.devices = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
      const cur = this.stream.getVideoTracks()[0]?.getSettings().deviceId;
      this.deviceIndex = Math.max(0, this.devices.findIndex((d) => d.deviceId === cur));
    } catch { this.devices = []; }

    this.running = true;
    this.torchOn = false;
    this.onState({ running: true, canSwitch: this.devices.length > 1, canTorch: this.torchSupported() });
    this.detector = await getNativeDetector();
    this.loop();
  }

  torchSupported() {
    const track = this.stream?.getVideoTracks()[0];
    try { return !!track?.getCapabilities?.().torch; } catch { return false; }
  }

  async toggleTorch() {
    const track = this.stream?.getVideoTracks()[0];
    if (!track) return false;
    this.torchOn = !this.torchOn;
    try { await track.applyConstraints({ advanced: [{ torch: this.torchOn }] }); } catch { this.torchOn = false; }
    return this.torchOn;
  }

  async switchCamera() {
    if (this.devices.length < 2) return;
    this.deviceIndex = (this.deviceIndex + 1) % this.devices.length;
    await this.start(this.devices[this.deviceIndex].deviceId);
  }

  loop = async (ts = 0) => {
    if (!this.running) return;
    if (ts - this.lastTick > 110 && this.video.readyState >= 2 && this.video.videoWidth) {
      this.lastTick = ts;
      let text = null;
      try {
        text = await this.decodeFrame();
      } catch (e) {
        this.stop();
        this.onState({ running: false, error: e });
        return;
      }
      if (text && this.running) {
        this.stop();
        this.onDetect(text);
        return;
      }
    }
    this.raf = requestAnimationFrame(this.loop);
  };

  async decodeFrame() {
    const v = this.video;
    try {
      if (this.detector) {
        const codes = await this.detector.detect(v);
        const hit = codes.find((c) => c.rawValue);
        if (hit) return hit.rawValue;
        // Some implementations miss inverted codes; fall through to jsQR every 4th frame.
        if (this.frame++ % 4 !== 0) return null;
      }
      const scale = Math.min(1, 720 / Math.max(v.videoWidth, v.videoHeight));
      const w = Math.round(v.videoWidth * scale);
      const h = Math.round(v.videoHeight * scale);
      if (this.canvas.width !== w) this.canvas.width = w;
      if (this.canvas.height !== h) this.canvas.height = h;
      this.ctx.drawImage(v, 0, 0, w, h);
      return jsqrDecode(this.ctx, w, h, this.frame++ % 2 ? "onlyInvert" : "dontInvert");
    } catch (e) {
      if (/failed to load/.test(e.message)) throw e;
      return null;
    }
  }

  stop(notify = true) {
    this.running = false;
    cancelAnimationFrame(this.raf);
    if (this.stream) this.stream.getTracks().forEach((t) => t.stop());
    this.stream = null;
    this.video.srcObject = null;
    if (notify) this.onState({ running: false });
  }
}

/** Human-friendly message for camera errors. Returns { title, body (html-safe text), steps[] }. */
export function cameraErrorMessage(err) {
  const n = err?.name || "";
  const ua = navigator.userAgent;
  const isIOS = /iPhone|iPad|iPod/.test(ua);
  const isAndroid = /Android/.test(ua);
  switch (n) {
    case "NotAllowedError":
    case "PermissionDeniedError":
      return {
        title: "Camera permission was blocked",
        steps: isIOS
          ? ["Open Settings › Safari › Camera and choose Allow (or tap “aA” › Website Settings › Camera).", "Reload this page and tap Start camera again."]
          : isAndroid
          ? ["Tap the lock / tune icon next to the address bar › Permissions › Camera › Allow.", "Reload the page and tap Start camera again."]
          : ["Click the camera or lock icon in the address bar and allow camera access for this site.", "Reload the page and click Start camera again."],
        alt: true,
      };
    case "NotFoundError":
    case "DevicesNotFoundError":
    case "OverconstrainedError":
      return { title: "No camera found", steps: ["Connect a camera, or use Upload image to decode a screenshot or photo of the QR code."], alt: true };
    case "NotReadableError":
    case "TrackStartError":
      return { title: "Camera is busy", steps: ["Another app or browser tab is using the camera. Close it and try again."], alt: true };
    case "InsecureContext":
      return { title: "Camera requires a secure (HTTPS) connection", steps: ["Open this site using https:// to enable the camera."], alt: true };
    case "NotSupportedError":
      return { title: "This browser can't access the camera", steps: ["Use a current version of Chrome, Safari, Edge or Firefox, or use Upload image instead."], alt: true };
    default:
      return { title: "Could not start the camera", steps: [err?.message || "Unknown error. Try again or use Upload image."], alt: true };
  }
}

// ------------------------------------------------------------------ images
function loadImage(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => resolve({ img, url });
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("This image format can't be read by your browser. Try a PNG or JPG screenshot."));
    };
    img.src = url;
  });
}

/** Decode a QR code from an uploaded/pasted image file. Tries several scales, crops and inversions. */
export async function decodeImageFile(file) {
  if (!file || !/^image\//.test(file.type || "image/")) throw new Error("Please choose an image file.");
  if (file.size > 15 * 1024 * 1024) throw new Error("Image is too large (max 15 MB).");
  const { img, url } = await loadImage(file);
  try {
    const det = await getNativeDetector();
    if (det) {
      try {
        const codes = await det.detect(img);
        const hit = codes.find((c) => c.rawValue);
        if (hit) return { text: hit.rawValue, previewUrl: url };
      } catch { /* fall back */ }
    }
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const W = img.naturalWidth, H = img.naturalHeight;
    const maxDims = [1600, 1000, 700, 450];
    // full frame at multiple scales, then centre crop (QR inside a busy photo / screenshot)
    const regions = [[0, 0, W, H], [W * 0.15, H * 0.15, W * 0.7, H * 0.7]];
    for (const [sx, sy, sw, sh] of regions) {
      for (const max of maxDims) {
        const scale = Math.min(1, max / Math.max(sw, sh));
        const w = Math.max(1, Math.round(sw * scale)), h = Math.max(1, Math.round(sh * scale));
        canvas.width = w + 40; canvas.height = h + 40; // quiet zone padding helps tightly-cropped codes
        ctx.fillStyle = "#fff";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.imageSmoothingEnabled = scale < 1;
        ctx.drawImage(img, sx, sy, sw, sh, 20, 20, w, h);
        const text = jsqrDecode(ctx, canvas.width, canvas.height, "attemptBoth");
        if (text) return { text, previewUrl: url };
      }
    }
    return { text: null, previewUrl: url };
  } catch (e) {
    URL.revokeObjectURL(url);
    throw e;
  }
}
