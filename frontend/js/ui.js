// Rendering helpers for scan results, history rows and toasts. All dynamic text is escaped.
export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const ICON = {
  SAFE: '<svg viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.4 3.4 8.3 8 9 4.6-.7 8-4.6 8-9V6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>',
  SUSPICIOUS: '<svg viewBox="0 0 24 24"><path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/></svg>',
  DANGEROUS: '<svg viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.4 3.4 8.3 8 9 4.6-.7 8-4.6 8-9V6z"/><path d="m9.5 9.5 5 5m0-5-5 5"/></svg>',
  UNVERIFIED: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01"/></svg>',
};
export const SVG = {
  copy: '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a1 1 0 0 1 1-1h10"/></svg>',
  open: '<svg viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9M19 14v6H4V5h6"/></svg>',
  pdf: '<svg viewBox="0 0 24 24"><path d="M12 4v11m0 0-4-4m4 4 4-4M4 19h16"/></svg>',
  report: '<svg viewBox="0 0 24 24"><path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6M9 14h6M9 18h4"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13"/></svg>',
  again: '<svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 1 0 2.3-5.7M4 4v4h4"/></svg>',
  qr: '<svg viewBox="0 0 48 48"><path d="M6 16V6h10M32 6h10v10M42 32v10H32M16 42H6V32"/><path d="M16 16h6v6h-6zM26 16h6v6h-6zM16 26h6v6h-6zM27 27h4v4h-4z"/></svg>',
};

const TYPE_LABEL = { url: "Link", upi: "UPI payment", wifi: "Wi-Fi", phone: "Phone", sms: "SMS", email: "Email", location: "Location", contact: "Contact", event: "Event", app: "App link", crypto: "Crypto", text: "Text", script: "Script" };
const SOURCE_LABEL = { camera: "Camera scan", upload: "Image upload", manual: "Manual check" };
export const typeLabel = (t) => TYPE_LABEL[t] || t;
export const sourceLabel = (s) => SOURCE_LABEL[s] || s;

export function fmtDate(d) {
  const dt = new Date(d);
  if (isNaN(dt)) return "";
  return dt.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function decodedBlock(scan) {
  return `
    <div class="decoded">
      <div class="decoded-head">
        <span class="lbl">Decoded content</span>
        <span class="type-badge">${esc(typeLabel(scan.contentType))}</span>
        <span class="src-badge">${esc(sourceLabel(scan.source))}</span>
      </div>
      <div class="decoded-box">
        <code>${esc(scan.content)}</code>
        <button class="btn btn-ghost btn-sm btn-icon" type="button" data-act="copy" title="Copy content" aria-label="Copy decoded content">${SVG.copy}</button>
      </div>
    </div>`;
}

/** Shown immediately after decoding, while the backend runs real checks. */
export function renderPending(scan) {
  const steps =
    scan.contentType === "upi"
      ? ["Validating UPI payee address", "Checking for refund / KYC / reward scam patterns", "Checking payment fields for tampering"]
      : scan.contentType === "url"
      ? ["Tracing redirects to the real destination", "Querying threat-intelligence sources", "Checking domain age (RDAP)", "Analysing impersonation & phishing patterns"]
      : ["Classifying content", "Extracting and checking embedded links", "Analysing scam patterns"];
  return `
    ${decodedBlock(scan)}
    <div class="analyzing" role="status">
      <div class="spinner-ring" aria-hidden="true"></div>
      <div>
        <h4>Verifying security…</h4>
        <ul>${steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
      </div>
    </div>
    <div class="section"><div class="skeleton" style="height:58px"></div></div>
    <div class="section"><div class="skeleton" style="height:58px"></div></div>`;
}

function verdictBlock(scan) {
  const score = scan.riskScore;
  const pct = score == null ? 0 : Math.max(0, Math.min(100, score));
  const verifiedBy = scan.details?.verifiedBy?.length ? `Checked by ${scan.details.verifiedBy.join(" · ")}` : "";
  return `
    <div class="verdict ${esc(scan.verdict)}">
      <div class="gauge" aria-label="Risk score ${score ?? "unknown"} out of 100">
        <svg viewBox="0 0 104 104"><circle class="track" cx="52" cy="52" r="46"/><circle class="bar" cx="52" cy="52" r="46" data-pct="${pct}"/></svg>
        <div class="num"><b>${score == null ? "—" : score}</b><small>RISK / 100</small></div>
      </div>
      <div>
        <div class="verdict-word">${ICON[scan.verdict] || ""}${esc(scan.verdict)}</div>
        <p class="verdict-summary">${esc(scan.summary)}</p>
        <div class="verdict-sub">${esc(fmtDate(scan.createdAt))}${verifiedBy ? " · " + esc(verifiedBy) : ""}</div>
      </div>
    </div>`;
}

function findingsBlock(reasons) {
  if (!reasons?.length) return "";
  const warn = reasons.filter((r) => r.weight > 0 || ["critical", "high", "medium"].includes(r.severity));
  const info = reasons.filter((r) => !warn.includes(r));
  const row = (r) => `
    <div class="finding">
      <span class="sev sev-${esc(r.severity)}">${esc(r.severity)}</span>
      <div><h5>${esc(r.title)}</h5><p>${esc(r.detail)}</p></div>
      <span class="w">${r.weight > 0 ? "+" + esc(r.weight) : ""}</span>
    </div>`;
  return `
    ${warn.length ? `<div class="section"><h4 class="section-title"><span>Why this verdict</span><span>${warn.length} signal${warn.length === 1 ? "" : "s"}</span></h4><div class="findings">${warn.map(row).join("")}</div></div>` : ""}
    ${info.length ? `<div class="section"><h4 class="section-title"><span>Notes</span></h4><div class="findings">${info.map(row).join("")}</div></div>` : ""}`;
}

function intelBlock(checks, title = "Threat intelligence") {
  if (!checks?.length) return "";
  const label = { clean: "Clean", match: "Threat found", error: "Unavailable", not_configured: "Not configured" };
  return `<div class="section"><h4 class="section-title"><span>${esc(title)}</span></h4><div class="intel-grid">
    ${checks.map((c) => `<div class="intel ${esc(c.status)}"><div class="h"><i></i>${esc(c.source)}</div><p><b>${esc(label[c.status] || c.status)}</b> — ${esc(c.detail)}</p>${(c.matches || []).map((m) => `<p>⚠ ${esc(m.threat)}: ${esc(m.url)}</p>`).join("")}</div>`).join("")}
  </div></div>`;
}

function linkBlocks(link, multi) {
  if (!link) return "";
  let html = intelBlock(link.intel, multi ? `Threat intelligence · ${hostOf(link.original)}` : "Threat intelligence");
  if (link.redirects?.length) {
    html += `<div class="section"><h4 class="section-title"><span>Redirect chain</span><span>${link.redirects.length - 1} redirect${link.redirects.length === 2 ? "" : "s"}</span></h4><ol class="chain">
      ${link.redirects.map((h) => `<li>${esc(h.url)}<span class="meta">${esc(h.via === "start" ? "start" : h.via)} · ${h.status ? "HTTP " + esc(h.status) : esc(h.error || "no response")}</span></li>`).join("")}
    </ol></div>`;
  }
  const age = link.finalDomainAge || link.domainAge;
  const rows = [];
  if (age) rows.push(["Domain", age.domain], ["Registered", age.registeredAt ? `${new Date(age.registeredAt).toLocaleDateString()} (${age.ageDays.toLocaleString()} days ago)` : `Unknown — ${age.error || "not published"}`]);
  if (age?.registrar) rows.push(["Registrar", age.registrar]);
  if (link.page?.title) rows.push(["Page title", link.page.title]);
  if (link.page?.isDownload) rows.push(["Download", link.page.downloadType]);
  if (rows.length) html += `<div class="section"><h4 class="section-title"><span>Destination</span></h4>${kv(rows)}</div>`;
  return html;
}

const hostOf = (u) => { try { return new URL(u).hostname; } catch { return u; } };
const kv = (rows) => `<div class="kv">${rows.filter(([, v]) => v != null && v !== "").map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join("")}</div>`;

function upiBlock(u) {
  if (!u) return "";
  return `<div class="section"><h4 class="section-title"><span>UPI payment request</span></h4>${kv([
    ["Payee UPI ID", u.payeeVpa || "— missing —"],
    ["Payee name", u.payeeName || "Not provided"],
    ["Amount", u.amount ? `₹${Number(u.amount).toLocaleString("en-IN")}` : "Not pre-filled (you enter it)"],
    ["Currency", u.currency || "INR"],
    ["Note", u.note],
    ["Merchant code", u.merchantCode],
    ["Reference", u.transactionRef],
    ["Provider handle", u.handle ? `@${u.handle}${u.handleKnown ? " · known UPI provider" : " · uncommon"}` : null],
  ])}</div>`;
}

function wifiBlock(w) {
  if (!w) return "";
  return `<div class="section"><h4 class="section-title"><span>Wi-Fi network</span></h4>${kv([["Network", w.ssid], ["Security", w.security], ["Hidden", w.hidden ? "Yes" : "No"], ["Password included", w.hasPassword ? "Yes" : "No"]])}</div>`;
}

export function openableUrl(scan) {
  const c = (scan.content || "").trim();
  if (scan.contentType !== "url") return null;
  const u = /^https?:\/\//i.test(c) ? c : `https://${c}`;
  try { return new URL(u).href; } catch { return null; }
}

/** Full result: decoded content + verdict + reasons + intel + details + actions. */
export function renderResult(scan, { saved = true, saveError = null, context = "scan" } = {}) {
  const d = scan.details || {};
  const links = d.link ? [d.link] : d.links || [];
  const url = openableUrl(scan);
  const actions = [
    url ? `<button class="btn ${scan.verdict === "SAFE" ? "btn-primary" : "btn-ghost"}" type="button" data-act="open" ${scan.verdict === "DANGEROUS" ? "disabled title='Blocked: confirmed malicious'" : ""}>${SVG.open}${scan.verdict === "DANGEROUS" ? "Blocked" : "Open link"}</button>` : "",
    `<button class="btn btn-ghost" type="button" data-act="pdf">${SVG.pdf}PDF report</button>`,
    scan.id && context !== "report" ? `<a class="btn btn-ghost" href="#/report/${esc(scan.id)}">${SVG.report}Full report</a>` : "",
    context === "scan" ? `<button class="btn btn-ghost" type="button" data-act="again">${SVG.again}Scan another</button>` : "",
  ].join("");
  const note = saved
    ? `<div class="save-note">✓ Saved to history${scan.id ? ` · ID ${esc(scan.id.slice(0, 8))}` : ""}</div>`
    : `<div class="save-note warn">⚠ ${esc(saveError || "Not saved to history")}</div>`;
  return `
    ${decodedBlock(scan)}
    ${verdictBlock(scan)}
    ${findingsBlock(scan.reasons)}
    ${upiBlock(d.upi)}
    ${wifiBlock(d.wifi)}
    ${links.map((l) => linkBlocks(l, links.length > 1)).join("")}
    ${intelBlock(d.embeddedLinkIntel, "Embedded link intelligence")}
    <div class="actions">${actions}</div>
    ${context === "scan" ? note : ""}`;
}

/** Animate gauges after insertion. */
export function animateGauges(root) {
  requestAnimationFrame(() =>
    $$(".gauge .bar", root).forEach((el) => {
      el.style.strokeDashoffset = String(289 - (289 * Number(el.dataset.pct || 0)) / 100);
    }),
  );
}

export function historyRow(s, i = 0) {
  return `
    <article class="h-item ${esc(s.verdict)}" style="animation-delay:${Math.min(i, 10) * 30}ms" data-id="${esc(s.id)}">
      <span class="bar"></span>
      <div class="h-main" data-act="view" tabindex="0" role="link" aria-label="View report">
        <div class="h-top"><span class="type-badge">${esc(typeLabel(s.contentType))}</span><span class="h-date">${esc(fmtDate(s.createdAt))}</span><span class="src-badge">· ${esc(sourceLabel(s.source))}</span></div>
        <div class="h-content">${esc(s.target || s.content)}</div>
        <div class="h-sum">${esc(s.summary)}</div>
      </div>
      <div class="h-verdict"><b>${esc(s.verdict)}</b><span>risk ${esc(s.riskScore)}/100</span></div>
      <div class="h-actions">
        <button class="btn btn-ghost btn-sm" type="button" data-act="view">${SVG.report}Report</button>
        <button class="btn btn-ghost btn-sm btn-icon" type="button" data-act="pdf" title="Download PDF" aria-label="Download PDF report">${SVG.pdf}</button>
        <button class="btn btn-danger-ghost btn-sm btn-icon" type="button" data-act="delete" title="Delete" aria-label="Delete scan">${SVG.trash}</button>
      </div>
    </article>`;
}

export function emptyList(title, text, cta = true) {
  return `<div class="empty-list"><div class="vf-icon">${SVG.qr}</div><h3>${esc(title)}</h3><p class="muted">${esc(text)}</p>${cta ? '<a class="btn btn-primary" href="#/scan">Scan a QR code</a>' : ""}</div>`;
}

export function toast(msg, type = "info", ms = 3800) {
  const wrap = $("#toasts");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 300); }, ms);
}

export function confirmDialog(title, text, okLabel = "Continue") {
  const dlg = $("#confirmModal");
  $("#confirmTitle").textContent = title;
  $("#confirmText").textContent = text;
  $("#confirmOk").textContent = okLabel;
  if (typeof dlg.showModal !== "function") return Promise.resolve(window.confirm(`${title}\n\n${text}`));
  return new Promise((resolve) => {
    dlg.returnValue = "";
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
    dlg.showModal();
  });
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}
