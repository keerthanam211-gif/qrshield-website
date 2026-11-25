// QRShield API client. All calls go to the Netlify Server backend under /api.
const API = "/api";
const CID_KEY = "qrshield.clientId";
const SCAN_TIMEOUT_MS = 28000;

function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Anonymous per-browser id so each visitor only sees their own history. */
export function clientId() {
  let id = null;
  try { id = localStorage.getItem(CID_KEY); } catch { /* private mode */ }
  if (!id || !/^[0-9a-f-]{36}$/i.test(id)) {
    id = uuid();
    try { localStorage.setItem(CID_KEY, id); } catch { /* ignore */ }
  }
  return id;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = "GET", body, timeout = 15000, raw = false } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  let res;
  try {
    res = await fetch(API + path, {
      method,
      headers: { "X-Client-Id": clientId(), ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new ApiError(e.name === "AbortError" ? "The security service took too long to respond." : "Could not reach the QRShield security service. Check your connection.", 0);
  } finally {
    clearTimeout(t);
  }
  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* not json */ }
    throw new ApiError(msg, res.status);
  }
  if (raw) return res;
  return res.json();
}

/**
 * Analyse content. Never fabricates a verdict: if the backend fails, the result is UNVERIFIED.
 */
export async function scan(content, source) {
  try {
    return await request("/scan", { method: "POST", body: { content, source }, timeout: SCAN_TIMEOUT_MS });
  } catch (e) {
    if (e.status === 400 || e.status === 413 || e.status === 429) throw e;
    return {
      saved: false,
      offline: true,
      saveError: "Not saved — backend unavailable",
      scan: {
        id: null,
        source,
        content,
        contentType: guessType(content),
        target: null,
        finalUrl: null,
        verdict: "UNVERIFIED",
        riskScore: null,
        summary: "Security verification failed — the QRShield backend could not be reached. Treat this QR code as untrusted.",
        reasons: [{ id: "backend", severity: "medium", weight: 0, title: "Verification service unavailable", detail: e.message }],
        details: {},
        createdAt: new Date().toISOString(),
      },
    };
  }
}

export function guessType(c) {
  const s = (c || "").trim();
  if (/^upi:\/\//i.test(s)) return "upi";
  if (/^https?:\/\//i.test(s) || /^www\./i.test(s) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) return "url";
  if (/^WIFI:/i.test(s)) return "wifi";
  if (/^tel:/i.test(s)) return "phone";
  if (/^(smsto|sms|mms):/i.test(s)) return "sms";
  if (/^(mailto:|MATMSG:)/i.test(s)) return "email";
  if (/^(BEGIN:VCARD|MECARD:)/i.test(s)) return "contact";
  if (/^(javascript|vbscript|data|file):/i.test(s)) return "script";
  if (/^[a-z][a-z0-9+.-]+:/i.test(s)) return "app";
  return "text";
}

export const health = () => request("/health", { timeout: 10000 });
export const history = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null));
  return request(`/history?${q}`);
};
export const getScan = (id) => request(`/history/${encodeURIComponent(id)}`);
export const deleteScan = (id) => request(`/history/${encodeURIComponent(id)}`, { method: "DELETE" });
export const clearHistory = () => request("/history", { method: "DELETE" });

async function download(res, fallbackName) {
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const name = cd.match(/filename="?([^";]+)"?/)?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: name, rel: "noopener" });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/** Download a PDF report. Saved scans are rendered from the database; unsaved ones from the result itself. */
export async function downloadScanReport(scanObj) {
  const res = scanObj.id
    ? await request(`/reports/${encodeURIComponent(scanObj.id)}/pdf`, { raw: true, timeout: 20000 })
    : await request("/reports/pdf", { method: "POST", body: scanObj, raw: true, timeout: 20000 });
  await download(res, "qrshield-report.pdf");
}
export async function downloadHistoryReport() {
  await download(await request("/reports/history/pdf", { raw: true, timeout: 25000 }), "qrshield-history-report.pdf");
}
export async function downloadCsv() {
  await download(await request("/history/export/csv", { raw: true, timeout: 20000 }), "qrshield-history.csv");
}
