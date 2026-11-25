/** Downloadable PDF security reports (single scan + full history), styled in QRShield's green/lime palette. */
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage, type RGB } from "pdf-lib";
import type { ScanRow } from "../../../db/schema.ts";

const C = {
  ink: rgb(0.04, 0.1, 0.07),
  deep: rgb(0.02, 0.07, 0.045),
  lime: rgb(0.78, 1, 0.3),
  green: rgb(0.17, 0.84, 0.48),
  text: rgb(0.12, 0.16, 0.14),
  muted: rgb(0.4, 0.47, 0.43),
  line: rgb(0.85, 0.89, 0.86),
  white: rgb(1, 1, 1),
};
const VERDICT_COLOR: Record<string, RGB> = {
  SAFE: rgb(0.13, 0.7, 0.4),
  SUSPICIOUS: rgb(0.93, 0.6, 0.05),
  DANGEROUS: rgb(0.86, 0.18, 0.24),
  UNVERIFIED: rgb(0.42, 0.48, 0.6),
};
const SEV_COLOR: Record<string, RGB> = {
  critical: rgb(0.86, 0.18, 0.24),
  high: rgb(0.9, 0.35, 0.15),
  medium: rgb(0.93, 0.6, 0.05),
  low: rgb(0.45, 0.6, 0.2),
  info: rgb(0.42, 0.48, 0.6),
};

/** Standard PDF fonts only support WinAnsi; map common Unicode to safe equivalents. */
function clean(s: unknown): string {
  return String(s ?? "")
    .replace(/₹/g, "Rs.")
    .replace(/[—–]/g, "-")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/…/g, "...")
    .replace(/[\r\t]/g, " ")
    .replace(/[^\x20-\x7E\n]/g, "?");
}

class Writer {
  doc: PDFDocument;
  page!: PDFPage;
  y = 0;
  font!: PDFFont;
  bold!: PDFFont;
  mono!: PDFFont;
  readonly W = 595.28;
  readonly H = 841.89;
  readonly M = 44;
  pageNo = 0;
  constructor(doc: PDFDocument) {
    this.doc = doc;
  }
  async init() {
    this.font = await this.doc.embedFont(StandardFonts.Helvetica);
    this.bold = await this.doc.embedFont(StandardFonts.HelveticaBold);
    this.mono = await this.doc.embedFont(StandardFonts.Courier);
  }
  newPage(title: string) {
    this.page = this.doc.addPage([this.W, this.H]);
    this.pageNo++;
    this.page.drawRectangle({ x: 0, y: this.H - 70, width: this.W, height: 70, color: C.deep });
    this.page.drawRectangle({ x: 0, y: this.H - 73, width: this.W, height: 3, color: C.lime });
    // shield mark
    this.page.drawRectangle({ x: this.M, y: this.H - 52, width: 26, height: 30, color: C.lime });
    this.page.drawText("QR", { x: this.M + 4.5, y: this.H - 42, size: 11, font: this.bold, color: C.deep });
    this.page.drawText("QRShield", { x: this.M + 36, y: this.H - 38, size: 18, font: this.bold, color: C.white });
    this.page.drawText(clean(title), { x: this.M + 36, y: this.H - 54, size: 9, font: this.font, color: C.lime });
    const gen = `Generated ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC`;
    this.page.drawText(gen, { x: this.W - this.M - this.font.widthOfTextAtSize(gen, 8), y: this.H - 42, size: 8, font: this.font, color: rgb(0.7, 0.8, 0.74) });
    this.page.drawText(`Page ${this.pageNo}`, { x: this.W - this.M - 30, y: 24, size: 8, font: this.font, color: C.muted });
    this.page.drawText("QRShield verdicts combine live threat intelligence with heuristic analysis. Always stay cautious with unknown QR codes.", { x: this.M, y: 24, size: 7, font: this.font, color: C.muted });
    this.y = this.H - 100;
  }
  ensure(h: number, title: string) {
    if (this.y - h < 50) this.newPage(title);
  }
  wrap(text: string, font: PDFFont, size: number, width: number): string[] {
    const out: string[] = [];
    for (const para of clean(text).split("\n")) {
      let line = "";
      for (const word of para.split(/(\s+)/)) {
        const cand = line + word;
        if (font.widthOfTextAtSize(cand, size) <= width) {
          line = cand;
          continue;
        }
        if (line.trim()) out.push(line.trimEnd());
        line = word.trimStart();
        while (font.widthOfTextAtSize(line, size) > width) {
          let i = line.length;
          while (i > 1 && font.widthOfTextAtSize(line.slice(0, i), size) > width) i--;
          out.push(line.slice(0, i));
          line = line.slice(i);
        }
      }
      out.push(line.trimEnd());
    }
    return out;
  }
  para(text: string, opts: { font?: PDFFont; size?: number; color?: RGB; indent?: number; gap?: number; title: string; maxLines?: number }) {
    const font = opts.font ?? this.font;
    const size = opts.size ?? 10;
    const x = this.M + (opts.indent ?? 0);
    let lines = this.wrap(text, font, size, this.W - this.M - x);
    if (opts.maxLines && lines.length > opts.maxLines) lines = [...lines.slice(0, opts.maxLines), "[...truncated]"];
    for (const l of lines) {
      this.ensure(size + 4, opts.title);
      this.page.drawText(l, { x, y: this.y, size, font, color: opts.color ?? C.text });
      this.y -= size + 3.5;
    }
    this.y -= opts.gap ?? 4;
  }
  heading(text: string, title: string) {
    this.ensure(34, title);
    this.y -= 8;
    this.page.drawRectangle({ x: this.M, y: this.y - 2, width: 3, height: 13, color: C.green });
    this.page.drawText(clean(text).toUpperCase(), { x: this.M + 9, y: this.y, size: 10, font: this.bold, color: C.ink });
    this.y -= 8;
    this.page.drawLine({ start: { x: this.M, y: this.y }, end: { x: this.W - this.M, y: this.y }, thickness: 0.6, color: C.line });
    this.y -= 14;
  }
  kv(rows: [string, unknown][], title: string) {
    for (const [k, v] of rows) {
      if (v == null || v === "") continue;
      const lines = this.wrap(String(v), this.font, 9.5, this.W - this.M * 2 - 130);
      this.ensure(lines.length * 13 + 2, title);
      this.page.drawText(clean(k), { x: this.M, y: this.y, size: 9, font: this.bold, color: C.muted });
      for (const l of lines) {
        this.page.drawText(l, { x: this.M + 130, y: this.y, size: 9.5, font: this.font, color: C.text });
        this.y -= 13;
      }
      this.y -= 2;
    }
  }
  pill(x: number, y: number, label: string, color: RGB, size = 8) {
    const w = this.bold.widthOfTextAtSize(label, size) + 12;
    this.page.drawRectangle({ x, y: y - 4, width: w, height: size + 8, color });
    this.page.drawText(label, { x: x + 6, y, size, font: this.bold, color: C.white });
    return w;
  }
}

type Reason = { severity: string; title: string; detail: string; weight: number };
type Check = { source: string; status: string; detail: string };
type LinkDetail = { original: string; final: string; redirects?: { url: string; status: number | null; via: string; error?: string }[]; intel?: Check[]; domainAge?: { domain: string; registeredAt: string | null; ageDays: number | null; registrar: string | null } | null; page?: { title: string | null } | null };

const fmt = (d: Date | string) => new Date(d).toISOString().replace("T", " ").slice(0, 19) + " UTC";

export async function buildScanReport(scan: ScanRow): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle(`QRShield Security Report - ${scan.verdict}`);
  doc.setAuthor("QRShield");
  doc.setCreationDate(new Date());
  const w = new Writer(doc);
  await w.init();
  const T = "Security Report";
  w.newPage(T);

  // Verdict banner
  const vc = VERDICT_COLOR[scan.verdict] ?? C.muted;
  w.page.drawRectangle({ x: w.M, y: w.y - 62, width: w.W - w.M * 2, height: 74, color: rgb(0.96, 0.98, 0.96), borderColor: vc, borderWidth: 1.2 });
  w.page.drawRectangle({ x: w.M, y: w.y - 62, width: 6, height: 74, color: vc });
  w.page.drawText(scan.verdict, { x: w.M + 20, y: w.y - 18, size: 24, font: w.bold, color: vc });
  w.page.drawText(`Risk score ${scan.riskScore}/100`, { x: w.M + 20, y: w.y - 36, size: 10, font: w.bold, color: C.text });
  // score bar
  const bx = w.M + 20, by = w.y - 52, bw = 200;
  w.page.drawRectangle({ x: bx, y: by, width: bw, height: 6, color: C.line });
  w.page.drawRectangle({ x: bx, y: by, width: Math.max(2, (bw * scan.riskScore) / 100), height: 6, color: vc });
  const sl = w.wrap(scan.summary, w.font, 9.5, 230);
  sl.slice(0, 5).forEach((l, i) => w.page.drawText(l, { x: w.M + 260, y: w.y - 14 - i * 12.5, size: 9.5, font: w.font, color: C.text }));
  w.y -= 88;

  w.heading("Scan details", T);
  w.kv([
    ["Report ID", scan.id],
    ["Scanned at", fmt(scan.createdAt)],
    ["Scan method", { camera: "Camera scan", upload: "Image upload", manual: "Manual check" }[scan.source] ?? scan.source],
    ["Content type", scan.contentType.toUpperCase()],
    ["Target", scan.target],
    ["Final destination", scan.finalUrl && scan.finalUrl !== scan.target ? scan.finalUrl : null],
  ], T);

  w.heading("Decoded QR content", T);
  w.para(scan.content, { font: w.mono, size: 8.5, title: T, maxLines: 30 });

  const reasons = (scan.reasons as Reason[]) ?? [];
  w.heading(`Findings (${reasons.length})`, T);
  if (!reasons.length) w.para("No findings.", { title: T, color: C.muted });
  for (const r of reasons) {
    w.ensure(40, T);
    const pw = w.pill(w.M, w.y, r.severity.toUpperCase(), SEV_COLOR[r.severity] ?? C.muted, 7);
    w.page.drawText(clean(r.title).slice(0, 90), { x: w.M + pw + 8, y: w.y, size: 10, font: w.bold, color: C.ink });
    if (r.weight > 0) {
      const t = `+${r.weight}`;
      w.page.drawText(t, { x: w.W - w.M - w.bold.widthOfTextAtSize(t, 9), y: w.y, size: 9, font: w.bold, color: SEV_COLOR[r.severity] ?? C.muted });
    }
    w.y -= 15;
    w.para(r.detail, { size: 9, color: C.muted, indent: 0, gap: 8, title: T });
  }

  const d = (scan.details ?? {}) as Record<string, unknown>;
  const links: LinkDetail[] = [d.link as LinkDetail, ...((d.links as LinkDetail[]) ?? [])].filter(Boolean);
  for (const l of links) {
    w.heading(`Threat intelligence${links.length > 1 ? ` - ${l.original}` : ""}`, T);
    for (const c of l.intel ?? []) {
      w.ensure(18, T);
      const color = c.status === "match" ? SEV_COLOR.critical : c.status === "clean" ? VERDICT_COLOR.SAFE : C.muted;
      const label = { match: "THREAT", clean: "CLEAN", error: "ERROR", not_configured: "OFF" }[c.status] ?? c.status;
      const pw = w.pill(w.M, w.y, label, color, 7);
      w.page.drawText(clean(c.source), { x: w.M + Math.max(pw, 52) + 8, y: w.y, size: 9.5, font: w.bold, color: C.ink });
      w.page.drawText(clean(c.detail).slice(0, 80), { x: w.M + 200, y: w.y, size: 8.5, font: w.font, color: C.muted });
      w.y -= 17;
    }
    if (l.redirects?.length) {
      w.heading("Redirect chain", T);
      l.redirects.forEach((h, i) => {
        const status = h.status ? `HTTP ${h.status}` : h.error ? `ERROR: ${h.error}` : "-";
        w.para(`${i + 1}. [${h.via}] ${h.url}  -> ${status}`, { font: w.mono, size: 8, title: T, gap: 1 });
      });
      w.y -= 4;
    }
    if (l.domainAge) {
      w.heading("Domain registration (RDAP)", T);
      w.kv([
        ["Domain", l.domainAge.domain],
        ["Registered", l.domainAge.registeredAt ? `${l.domainAge.registeredAt.slice(0, 10)} (${l.domainAge.ageDays} days ago)` : "Not available"],
        ["Registrar", l.domainAge.registrar],
        ["Page title", l.page?.title],
      ], T);
    }
  }

  const upi = d.upi as Record<string, unknown> | undefined;
  if (upi) {
    w.heading("UPI payment details", T);
    w.kv([
      ["Payee UPI ID", upi.payeeVpa],
      ["Payee name", upi.payeeName],
      ["Amount", upi.amount ? `Rs. ${upi.amount}` : "Not pre-filled"],
      ["Currency", upi.currency ?? "INR (default)"],
      ["Note", upi.note],
      ["Merchant code", upi.merchantCode],
      ["Transaction ref", upi.transactionRef],
      ["UPI handle", upi.handle ? `@${upi.handle}${upi.handleKnown ? " (known provider)" : " (uncommon)"}` : null],
    ], T);
  }
  const wifi = d.wifi as Record<string, unknown> | undefined;
  if (wifi) {
    w.heading("Wi-Fi network", T);
    w.kv([["Network (SSID)", wifi.ssid], ["Security", wifi.security], ["Hidden", wifi.hidden ? "Yes" : "No"]], T);
  }

  w.heading("Recommendation", T);
  const rec = {
    SAFE: "No threats were detected by the security checks. Still verify you trust the source of the QR code before entering personal or payment details.",
    SUSPICIOUS: "Do not enter passwords, OTPs, card or UPI PIN details. Verify the destination through an official channel (type the official website yourself or use the official app).",
    DANGEROUS: "Do not open this link or make this payment. If you already entered information, change your passwords, contact your bank immediately and report the incident at cybercrime.gov.in (India: call 1930).",
    UNVERIFIED: "The security check could not be completed. Treat this QR code as untrusted and try scanning again later.",
  }[scan.verdict as "SAFE"];
  w.para(rec ?? "", { title: T });

  return doc.save();
}

export async function buildHistoryReport(rows: ScanRow[], stats: Record<string, number>): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle("QRShield Scan History Report");
  const w = new Writer(doc);
  await w.init();
  const T = "Scan History Report";
  w.newPage(T);

  w.heading("Overview", T);
  const keys = ["SAFE", "SUSPICIOUS", "DANGEROUS", "UNVERIFIED"];
  const boxW = (w.W - w.M * 2 - 30) / 4;
  keys.forEach((k, i) => {
    const x = w.M + i * (boxW + 10);
    w.page.drawRectangle({ x, y: w.y - 40, width: boxW, height: 50, color: rgb(0.96, 0.98, 0.96), borderColor: VERDICT_COLOR[k], borderWidth: 1 });
    w.page.drawText(String(stats[k] ?? 0), { x: x + 10, y: w.y - 14, size: 20, font: w.bold, color: VERDICT_COLOR[k] });
    w.page.drawText(k, { x: x + 10, y: w.y - 32, size: 8, font: w.bold, color: C.muted });
  });
  w.y -= 62;
  w.para(`${rows.length} scan(s) included${rows.length ? `, from ${fmt(rows[rows.length - 1].createdAt)} to ${fmt(rows[0].createdAt)}` : ""}.`, { title: T, color: C.muted });

  w.heading("Scans", T);
  const cols = [w.M, w.M + 98, w.M + 150, w.M + 380, w.M + 462];
  const header = () => {
    ["DATE / TIME (UTC)", "TYPE", "CONTENT", "VERDICT", "SCORE"].forEach((h, i) => w.page.drawText(h, { x: cols[i], y: w.y, size: 7.5, font: w.bold, color: C.muted }));
    w.y -= 14;
  };
  header();
  for (const r of rows) {
    if (w.y < 70) {
      w.newPage(T);
      header();
    }
    const target = clean(r.target || r.content).replace(/\n/g, " ");
    const t = w.wrap(target, w.font, 8, 220)[0] + (w.font.widthOfTextAtSize(target, 8) > 220 ? "..." : "");
    w.page.drawText(fmt(r.createdAt).slice(0, 16), { x: cols[0], y: w.y, size: 8, font: w.font, color: C.text });
    w.page.drawText(r.contentType.toUpperCase(), { x: cols[1], y: w.y, size: 7.5, font: w.bold, color: C.muted });
    w.page.drawText(t, { x: cols[2], y: w.y, size: 8, font: w.font, color: C.text });
    w.page.drawText(r.verdict, { x: cols[3], y: w.y, size: 8, font: w.bold, color: VERDICT_COLOR[r.verdict] ?? C.muted });
    w.page.drawText(String(r.riskScore), { x: cols[4], y: w.y, size: 8, font: w.bold, color: C.text });
    w.y -= 6;
    w.page.drawLine({ start: { x: w.M, y: w.y }, end: { x: w.W - w.M, y: w.y }, thickness: 0.4, color: C.line });
    w.y -= 10;
  }
  return doc.save();
}
