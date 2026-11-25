// QRShield front-end controller: routing, scanning flows, history and reports.
import * as api from "./api.js";
import { CameraScanner, cameraErrorMessage, decodeImageFile } from "./decoder.js";
import { $, $$, esc, renderPending, renderResult, animateGauges, historyRow, emptyList, toast, confirmDialog, copyText, openableUrl, fmtDate, sourceLabel } from "./ui.js";

const LAST_KEY = "qrshield.lastResult";
const state = {
  route: "scan",
  busy: false,
  current: null, // { scan, saved, saveError } shown on the scan page
  reportScan: null,
  history: { verdict: "", q: "", offset: 0, limit: 20, total: 0, items: [] },
};

// =====================================================================
// Router
// =====================================================================
const ROUTES = ["scan", "history", "report", "about"];
function parseHash() {
  const [, name = "scan", id = ""] = (location.hash || "#/scan").match(/^#\/?([^/]*)\/?(.*)$/) || [];
  return { name: ROUTES.includes(name) ? name : "scan", id: decodeURIComponent(id) };
}

function navigate() {
  const { name, id } = parseHash();
  if (name !== "scan") camera.stop();
  state.route = name;
  $$(".view").forEach((v) => (v.hidden = v.dataset.view !== name));
  $$("[data-route]").forEach((a) => a.classList.toggle("active", a.dataset.route === name));
  $$("[data-route]").forEach((a) => (a.dataset.route === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  document.title = { scan: "QRShield — Scan before you trust", history: "History · QRShield", report: "Report · QRShield", about: "How it works · QRShield" }[name];
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
  if (name === "history") loadHistory(true);
  if (name === "report") showReport(id);
  if (name === "about") loadAbout();
}
window.addEventListener("hashchange", navigate);

// =====================================================================
// Scan flow (shared by camera, upload and manual input)
// =====================================================================
const resultBody = $("#resultBody");
const resultEmpty = $("#resultEmpty");

async function runScan(content, source) {
  content = String(content || "").trim();
  if (!content) return;
  if (state.busy) return toast("Still checking the previous code…");
  state.busy = true;
  setFormBusy(true);

  // 1) Show the decoded content immediately.
  const pending = { content, source, contentType: api.guessType(content) };
  resultEmpty.hidden = true;
  resultBody.hidden = false;
  resultBody.innerHTML = renderPending(pending);
  if (matchMedia("(max-width: 920px)").matches) $("#resultCard").scrollIntoView({ behavior: "smooth", block: "start" });

  // 2) Real verification on the backend. No local default verdicts.
  try {
    const res = await api.scan(content, source);
    state.current = { scan: res.scan, saved: res.saved, saveError: res.saveError };
    try { sessionStorage.setItem(LAST_KEY, JSON.stringify(state.current)); } catch { /* quota */ }
    resultBody.innerHTML = renderResult(res.scan, { saved: res.saved, saveError: res.saveError, context: "scan" });
    animateGauges(resultBody);
    if (res.offline) toast("Backend unreachable — result is UNVERIFIED.", "error");
    if (res.scan.verdict === "DANGEROUS" && navigator.vibrate) navigator.vibrate([80, 60, 80, 60, 160]);
  } catch (e) {
    resultBody.innerHTML = `<div class="alert error"><b>Could not check this content.</b><br>${esc(e.message)}</div>`;
  } finally {
    state.busy = false;
    setFormBusy(false);
  }
}

function setFormBusy(b) {
  const btn = $("#manualSubmit");
  btn.disabled = b;
  btn.classList.toggle("loading", b);
}

async function handleResultAction(e, scanGetter, context) {
  const btn = e.target.closest("[data-act]");
  if (!btn) return;
  const scan = scanGetter();
  if (!scan) return;
  const act = btn.dataset.act;
  if (act === "copy") {
    await copyText(scan.content);
    toast("Copied to clipboard");
  } else if (act === "open") {
    const url = openableUrl(scan);
    if (!url || scan.verdict === "DANGEROUS") return;
    if (scan.verdict !== "SAFE") {
      const ok = await confirmDialog(
        scan.verdict === "SUSPICIOUS" ? "This link looks suspicious" : "This link could not be verified",
        `${scan.summary}\n\nOpen ${url} anyway?`,
        "Open anyway",
      );
      if (!ok) return;
    }
    window.open(url, "_blank", "noopener,noreferrer");
  } else if (act === "pdf") {
    btn.classList.add("loading");
    try {
      await api.downloadScanReport(scan);
      toast("Report downloaded");
    } catch (err) {
      toast(`Report failed: ${err.message}`, "error");
    } finally {
      btn.classList.remove("loading");
    }
  } else if (act === "again" && context === "scan") {
    resetResult();
    const tab = $(".tab.active")?.dataset.tab;
    if (tab === "camera") startCamera();
    else if (tab === "manual") $("#manualInput").focus();
    else $("#fileInput").click();
  }
}
resultBody.addEventListener("click", (e) => handleResultAction(e, () => state.current?.scan, "scan"));

function resetResult() {
  resultBody.hidden = true;
  resultBody.innerHTML = "";
  resultEmpty.hidden = false;
}

// =====================================================================
// Tabs
// =====================================================================
function selectTab(name) {
  const tabs = $$(".tab");
  const idx = tabs.findIndex((t) => t.dataset.tab === name);
  tabs.forEach((t) => {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
  });
  $$(".panel").forEach((p) => (p.hidden = p.id !== `panel-${name}`));
  $(".tab-ink").style.transform = `translateX(${idx * 100}%)`;
  if (name !== "camera") camera.stop();
  if (name === "manual") setTimeout(() => $("#manualInput").focus(), 50);
}
$$(".tab").forEach((t) => t.addEventListener("click", () => selectTab(t.dataset.tab)));
$(".tabs").addEventListener("keydown", (e) => {
  if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
  const tabs = $$(".tab");
  const i = tabs.findIndex((t) => t.classList.contains("active"));
  const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
  selectTab(next.dataset.tab);
  next.focus();
});

// =====================================================================
// Camera
// =====================================================================
const vf = $("#viewfinder");
const camError = $("#camError");
const camera = new CameraScanner($("#video"), {
  onDetect: (text) => {
    const flash = $("#vfFlash");
    flash.classList.remove("go");
    void flash.offsetWidth;
    flash.classList.add("go");
    if (navigator.vibrate) navigator.vibrate(60);
    runScan(text, "camera");
  },
  onState: ({ running, canSwitch, canTorch, error }) => {
    vf.classList.toggle("live", !!running);
    $("#camControls").hidden = !running;
    if (running) {
      $("#camSwitch").hidden = !canSwitch;
      $("#camTorch").hidden = !canTorch;
      $("#camTorch").setAttribute("aria-pressed", "false");
    }
    if (error) showCamError(error);
  },
});

function showCamError(err) {
  const m = cameraErrorMessage(err);
  camError.className = "alert error";
  camError.innerHTML = `<b>${esc(m.title)}</b><ul>${m.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>${m.alt ? '<div style="margin-top:8px">You can also <a href="#" data-alt="upload">upload a QR image</a> or <a href="#" data-alt="manual">check a link manually</a>.</div>' : ""}`;
  camError.hidden = false;
}
camError.addEventListener("click", (e) => {
  const a = e.target.closest("[data-alt]");
  if (!a) return;
  e.preventDefault();
  selectTab(a.dataset.alt);
});

async function startCamera() {
  camError.hidden = true;
  const btn = $("#camStart");
  btn.classList.add("loading");
  btn.disabled = true;
  try {
    await camera.start();
  } catch (e) {
    showCamError(e);
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
  }
}
$("#camStart").addEventListener("click", startCamera);
$("#camStop").addEventListener("click", () => camera.stop());
$("#camSwitch").addEventListener("click", async () => {
  try { await camera.switchCamera(); } catch (e) { showCamError(e); }
});
$("#camTorch").addEventListener("click", async () => {
  const on = await camera.toggleTorch();
  $("#camTorch").setAttribute("aria-pressed", String(on));
});
document.addEventListener("visibilitychange", () => { if (document.hidden) camera.stop(); });
window.addEventListener("pagehide", () => camera.stop());

// Reflect a previously-denied permission before the user taps Start.
(async () => {
  const sup = CameraScanner.support();
  if (!sup.ok) return showCamError({ name: sup.reason === "insecure" ? "InsecureContext" : "NotSupportedError" });
  try {
    const p = await navigator.permissions?.query({ name: "camera" });
    if (!p) return;
    const apply = () => { if (p.state === "denied") showCamError({ name: "NotAllowedError" }); else if (camError.textContent.includes("blocked")) camError.hidden = true; };
    apply();
    p.onchange = apply;
  } catch { /* Firefox/Safari may not support the camera permission name */ }
})();

// =====================================================================
// Upload / drag-drop / paste
// =====================================================================
const dropzone = $("#dropzone");
const uploadErr = $("#uploadError");
const preview = $("#uploadPreview");

async function handleImage(file) {
  if (!file) return;
  uploadErr.hidden = true;
  dropzone.classList.add("busy");
  try {
    const { text, previewUrl } = await decodeImageFile(file);
    if (preview.dataset.url) URL.revokeObjectURL(preview.dataset.url);
    preview.src = previewUrl;
    preview.dataset.url = previewUrl;
    preview.hidden = false;
    if (!text) {
      uploadErr.className = "alert";
      uploadErr.innerHTML = "<b>No QR code found in this image.</b><ul><li>Make sure the whole QR code is visible and in focus.</li><li>Crop the screenshot closer to the code, or try a higher-resolution image.</li></ul>";
      uploadErr.hidden = false;
      return;
    }
    runScan(text, "upload");
  } catch (e) {
    uploadErr.className = "alert error";
    uploadErr.textContent = e.message;
    uploadErr.hidden = false;
  } finally {
    dropzone.classList.remove("busy");
    $("#fileInput").value = "";
  }
}
$("#fileInput").addEventListener("change", (e) => handleImage(e.target.files[0]));
dropzone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#fileInput").click(); } });
["dragenter", "dragover"].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); }));
dropzone.addEventListener("drop", (e) => handleImage([...(e.dataTransfer?.files || [])].find((f) => f.type.startsWith("image/"))));
document.addEventListener("paste", (e) => {
  if (state.route !== "scan") return;
  const file = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"))?.getAsFile();
  if (file) {
    e.preventDefault();
    selectTab("upload");
    handleImage(file);
  }
});

// =====================================================================
// Manual check
// =====================================================================
const manualInput = $("#manualInput");
manualInput.addEventListener("input", () => ($("#manualCount").textContent = `${manualInput.value.length} / 4096`));
manualInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#manualForm").requestSubmit(); }
});
$("#manualForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = manualInput.value.trim();
  const err = $("#manualError");
  if (!v) {
    err.className = "alert error";
    err.textContent = "Enter a link, UPI string or QR text to check.";
    err.hidden = false;
    return;
  }
  err.hidden = true;
  runScan(v, "manual");
});

// =====================================================================
// History
// =====================================================================
const list = $("#historyList");
async function loadHistory(reset = false) {
  const h = state.history;
  if (reset) {
    h.offset = 0;
    h.items = [];
    list.innerHTML = Array.from({ length: 4 }, () => '<div class="skeleton" style="height:84px"></div>').join("");
  }
  try {
    const res = await api.history({ verdict: h.verdict, q: h.q, limit: h.limit, offset: h.offset });
    h.total = res.total;
    h.items = reset ? res.items : [...h.items, ...res.items];
    h.offset = h.items.length;
    for (const [k, v] of Object.entries(res.stats || {})) {
      const el = $(`[data-stat="${k}"]`);
      if (el) el.textContent = v;
    }
    if (!h.items.length) {
      list.innerHTML = h.verdict || h.q
        ? emptyList("No matching scans", "Try a different filter or search term.", false)
        : emptyList("No scans yet", "Your scans will appear here with date, time, verdict and risk score.");
    } else {
      list.innerHTML = h.items.map(historyRow).join("");
    }
    $("#loadMore").hidden = h.items.length >= h.total;
  } catch (e) {
    list.innerHTML = `<div class="alert error"><b>Could not load history.</b> ${esc(e.message)} <button class="btn btn-ghost btn-sm" type="button" id="retryHistory">Retry</button></div>`;
    $("#retryHistory")?.addEventListener("click", () => loadHistory(true));
    $("#loadMore").hidden = true;
  }
}
function setFilter(v) {
  state.history.verdict = v;
  $$("#historyFilters .chip").forEach((c) => c.classList.toggle("active", c.dataset.filter === v));
  $$(".stat").forEach((c) => c.classList.toggle("active", !!v && c.dataset.filter === v));
  loadHistory(true);
}
$$("#historyFilters .chip, .stat").forEach((c) => c.addEventListener("click", () => setFilter(c.dataset.filter)));
let searchTimer;
$("#historySearch").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.history.q = e.target.value.trim(); loadHistory(true); }, 300);
});
$("#loadMore").addEventListener("click", () => loadHistory(false));

list.addEventListener("click", async (e) => {
  const item = e.target.closest(".h-item");
  const btn = e.target.closest("[data-act]");
  if (!item || !btn) return;
  const id = item.dataset.id;
  const scan = state.history.items.find((s) => s.id === id);
  if (btn.dataset.act === "view") location.hash = `#/report/${id}`;
  if (btn.dataset.act === "pdf") {
    btn.classList.add("loading");
    try { await api.downloadScanReport(scan); } catch (err) { toast(`Report failed: ${err.message}`, "error"); }
    btn.classList.remove("loading");
  }
  if (btn.dataset.act === "delete") {
    if (!(await confirmDialog("Delete this scan?", scan?.target || scan?.content || "", "Delete"))) return;
    try {
      await api.deleteScan(id);
      toast("Scan deleted");
      loadHistory(true);
    } catch (err) { toast(err.message, "error"); }
  }
});
list.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.matches(".h-main")) location.hash = `#/report/${e.target.closest(".h-item").dataset.id}`;
});

async function withLoading(btn, fn, okMsg) {
  btn.classList.add("loading");
  btn.disabled = true;
  try { await fn(); if (okMsg) toast(okMsg); } catch (e) { toast(e.message, "error"); }
  btn.classList.remove("loading");
  btn.disabled = false;
}
$("#exportCsv").addEventListener("click", (e) => withLoading(e.currentTarget, api.downloadCsv, "CSV exported"));
$("#historyPdf").addEventListener("click", (e) => withLoading(e.currentTarget, api.downloadHistoryReport, "History report downloaded"));
$("#clearHistory").addEventListener("click", async (e) => {
  if (!(await confirmDialog("Clear all history?", "This permanently deletes every scan saved from this browser.", "Clear history"))) return;
  withLoading(e.currentTarget, async () => { const r = await api.clearHistory(); toast(`${r.deleted} scan(s) deleted`); loadHistory(true); });
});

// =====================================================================
// Report
// =====================================================================
const reportBody = $("#reportBody");
async function showReport(id) {
  $("#reportActions").hidden = true;
  state.reportScan = null;
  if (!id) {
    let last = null;
    try { last = JSON.parse(sessionStorage.getItem(LAST_KEY) || "null"); } catch { /* ignore */ }
    if (last?.scan?.id) return (location.hash = `#/report/${last.scan.id}`);
    if (last?.scan) return renderReport(last.scan, true);
    $("#reportTitle").textContent = "Report";
    $("#reportMeta").textContent = "Choose a scan to see its full security report.";
    reportBody.innerHTML = '<div class="skeleton" style="height:120px"></div>';
    try {
      const res = await api.history({ limit: 6 });
      reportBody.innerHTML = res.items.length
        ? `<div class="card"><h3>Recent scans</h3><p class="muted">Select one to open its report.</p><div class="pick-list history-list">${res.items.map(historyRow).join("")}</div></div>`
        : emptyList("No reports yet", "Scan a QR code or check a link — a detailed security report is created for every scan.");
      reportBody.querySelector(".pick-list")?.addEventListener("click", (e) => {
        const item = e.target.closest(".h-item");
        if (!item) return;
        const sc = res.items.find((s) => s.id === item.dataset.id);
        const act = e.target.closest("[data-act]")?.dataset.act;
        if (act === "pdf") return api.downloadScanReport(sc).catch((err) => toast(err.message, "error"));
        if (act === "delete") return api.deleteScan(sc.id).then(() => showReport("")).catch((err) => toast(err.message, "error"));
        location.hash = `#/report/${item.dataset.id}`;
      });
    } catch (e) {
      reportBody.innerHTML = `<div class="alert error"><b>Could not load scans.</b> ${esc(e.message)}</div>`;
    }
    return;
  }
  reportBody.innerHTML = '<div class="skeleton" style="height:420px"></div>';
  try {
    const { scan } = await api.getScan(id);
    renderReport(scan, false);
  } catch (e) {
    $("#reportTitle").textContent = "Report not found";
    $("#reportMeta").textContent = "";
    reportBody.innerHTML = e.status === 404 || e.status === 400
      ? emptyList("Report not found", "This scan doesn't exist or was deleted. Reports are only visible in the browser that created them.")
      : `<div class="alert error"><b>Could not load report.</b> ${esc(e.message)}</div>`;
  }
}

function renderReport(scan, unsaved) {
  state.reportScan = scan;
  $("#reportTitle").innerHTML = `Report · <span class="v-${esc(scan.verdict)}">${esc(scan.verdict)}</span>`;
  $("#reportMeta").textContent = `${fmtDate(scan.createdAt)} · ${sourceLabel(scan.source)}${scan.id ? ` · ID ${scan.id}` : " · not saved to history"}`;
  $("#reportActions").hidden = false;
  reportBody.innerHTML = `
    <div class="report-layout">
      <div class="card">${renderResult(scan, { context: "report" })}</div>
      <aside class="report-side">
        <div class="card">
          <h3>Scan record</h3>
          <div class="kv">
            <div>Date</div><div>${esc(new Date(scan.createdAt).toLocaleDateString())}</div>
            <div>Time</div><div>${esc(new Date(scan.createdAt).toLocaleTimeString())}</div>
            <div>Risk score</div><div>${esc(scan.riskScore ?? "—")} / 100</div>
            <div>Verdict</div><div class="v-${esc(scan.verdict)}"><b>${esc(scan.verdict)}</b></div>
            <div>Method</div><div>${esc(sourceLabel(scan.source))}</div>
            ${scan.target ? `<div>Target</div><div>${esc(scan.target)}</div>` : ""}
            ${scan.finalUrl && scan.finalUrl !== scan.target ? `<div>Destination</div><div>${esc(scan.finalUrl)}</div>` : ""}
          </div>
        </div>
        <div class="card">
          <h3>What to do</h3>
          <p class="muted">${esc({
            SAFE: "No threats were found. Still make sure you trust where this QR code came from before entering personal or payment details.",
            SUSPICIOUS: "Don't enter passwords, OTPs, card details or your UPI PIN. Reach the organisation through its official app or website instead.",
            DANGEROUS: "Do not open or pay. If you already entered details, change passwords and contact your bank now. In India, report at cybercrime.gov.in or call 1930.",
            UNVERIFIED: "The check could not be completed. Treat this QR code as untrusted and try again later.",
          }[scan.verdict] || "")}</p>
          ${unsaved ? '<p class="save-note warn">⚠ This result was not saved to history.</p>' : ""}
        </div>
      </aside>
    </div>`;
  animateGauges(reportBody);
}
reportBody.addEventListener("click", (e) => { if (state.reportScan) handleResultAction(e, () => state.reportScan, "report"); });
$("#reportBack").addEventListener("click", () => (location.hash = "#/history"));
$("#reportPrint").addEventListener("click", () => window.print());
$("#reportPdf").addEventListener("click", (e) => state.reportScan && withLoading(e.currentTarget, () => api.downloadScanReport(state.reportScan), "Report downloaded"));

// =====================================================================
// Intel status + About
// =====================================================================
let healthCache = null;
async function refreshHealth() {
  const pill = $("#intelPill");
  try {
    healthCache = await api.health();
    const feeds = healthCache.intel.feeds.filter((f) => f.loaded).length;
    const gsb = healthCache.intel.googleSafeBrowsing === "configured";
    const n = feeds + (gsb ? 1 : 0);
    pill.className = `intel-pill ${n === 0 ? "down" : gsb ? "ok" : "ok"}`;
    pill.querySelector(".label").textContent = n ? `Threat intel · ${n} source${n === 1 ? "" : "s"} live` : "Threat intel offline";
  } catch {
    healthCache = null;
    pill.className = "intel-pill down";
    pill.querySelector(".label").textContent = "Backend offline";
  }
  return healthCache;
}
$("#intelPill").addEventListener("click", () => (location.hash = "#/about"));

async function loadAbout() {
  const box = $("#sourcesList");
  const h = healthCache || (await refreshHealth());
  if (!h) {
    box.innerHTML = '<div class="alert error">The QRShield backend is unreachable. Scans will be marked UNVERIFIED until it is back.</div>';
    return;
  }
  const gsb = h.intel.googleSafeBrowsing === "configured";
  const items = [
    { name: "Google Safe Browsing", cls: gsb ? "clean" : "error", text: gsb ? "Active — phishing, malware & unwanted software lists." : "Not configured on this deployment (set GOOGLE_SAFE_BROWSING_API_KEY)." },
    ...h.intel.feeds.map((f) => ({ name: f.name, cls: f.loaded ? "clean" : "error", text: f.loaded ? `Active — ${f.entries.toLocaleString()} entries, synced ${new Date(f.syncedAt).toLocaleTimeString()}.` : `Unavailable${f.lastError ? ` (${f.lastError})` : ""}.` })),
    { name: "RDAP domain age", cls: "clean", text: "Active — registration date lookups for every domain." },
    { name: "Redirect tracer", cls: "clean", text: "Active — follows HTTP, meta-refresh and script redirects." },
  ];
  box.innerHTML = items.map((i) => `<div class="intel ${i.cls}"><div class="h"><i></i>${esc(i.name)}</div><p>${esc(i.text)}</p></div>`).join("");
}

// =====================================================================
// Boot
// =====================================================================
(function boot() {
  selectTab("camera");
  try {
    const last = JSON.parse(sessionStorage.getItem(LAST_KEY) || "null");
    if (last?.scan) {
      state.current = last;
      resultEmpty.hidden = true;
      resultBody.hidden = false;
      resultBody.innerHTML = renderResult(last.scan, { saved: last.saved, saveError: last.saveError, context: "scan" });
      animateGauges(resultBody);
    }
  } catch { /* ignore */ }
  if (!location.hash) history.replaceState(null, "", "#/scan");
  navigate();
  refreshHealth();
})();

window.addEventListener("error", (e) => console.error("QRShield error:", e.error || e.message));
window.addEventListener("unhandledrejection", (e) => console.error("QRShield unhandled:", e.reason));
