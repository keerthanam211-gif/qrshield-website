/**
 * QRShield REST API (Hono). Mounted by netlify/server/index.ts on /api/*.
 */
import { Hono, type Context } from "hono";
import { analyzeContent } from "./analysis/content.ts";
import { intelStatus, warmFeeds } from "./analysis/intel.ts";
import { clearScans, deleteScan, getScan, listScans, saveScan, verdictStats } from "./history.ts";
import { buildHistoryReport, buildScanReport } from "./reports/pdf.ts";
import type { ScanRow } from "../../db/schema.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERDICTS = new Set(["SAFE", "SUSPICIOUS", "DANGEROUS", "UNVERIFIED"]);
const SOURCES = new Set(["camera", "upload", "manual"]);
const MAX_CONTENT = 4096;

export const app = new Hono().basePath("/api");

// ---- helpers ---------------------------------------------------------------
function clientIdOf(c: Context): string | null {
  const id = c.req.header("x-client-id") ?? c.req.query("cid") ?? "";
  return UUID_RE.test(id) ? id.toLowerCase() : null;
}

function requireClient(c: Context) {
  const id = clientIdOf(c);
  if (!id) throw new HttpError(400, "Missing or invalid X-Client-Id header");
  return id;
}

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Per-instance sliding-window rate limit for the expensive scan endpoint.
const hits = new Map<string, number[]>();
function rateLimited(key: string, limit = 30, windowMs = 60_000) {
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some((t) => now - t < windowMs)) hits.delete(k);
  return arr.length > limit;
}

function serialize(r: ScanRow) {
  return {
    id: r.id,
    source: r.source,
    content: r.content,
    contentType: r.contentType,
    target: r.target,
    finalUrl: r.finalUrl,
    verdict: r.verdict,
    riskScore: r.riskScore,
    summary: r.summary,
    reasons: r.reasons,
    details: r.details,
    createdAt: r.createdAt,
  };
}

function csvCell(v: unknown) {
  const s = String(v ?? "");
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s; // neutralise spreadsheet formula injection
  return `"${safe.replace(/"/g, '""')}"`;
}

app.onError((err, c) => {
  if (err instanceof HttpError) return c.json({ error: err.message }, err.status as 400);
  console.error("API error:", err);
  return c.json({ error: "Internal server error" }, 500);
});

// ---- routes ----------------------------------------------------------------
app.get("/health", async (c) => {
  await Promise.race([warmFeeds(), new Promise((r) => setTimeout(r, 4000))]);
  return c.json({ status: "ok", time: new Date().toISOString(), intel: intelStatus() });
});

app.post("/scan", async (c) => {
  const clientId = requireClient(c);
  const ip = c.req.header("x-nf-client-connection-ip") ?? c.req.header("x-forwarded-for") ?? "local";
  if (rateLimited(`${ip}|${clientId}`)) return c.json({ error: "Too many scans. Please wait a minute and try again." }, 429);

  let body: { content?: unknown; source?: unknown };
  try {
    body = await c.req.json();
  } catch {
    throw new HttpError(400, "Body must be JSON");
  }
  const content = typeof body.content === "string" ? body.content.replace(/\u0000/g, "").trim() : "";
  if (!content) throw new HttpError(400, "Nothing to analyse — content is empty");
  if (content.length > MAX_CONTENT) throw new HttpError(413, `Content too long (max ${MAX_CONTENT} characters)`);
  const source = typeof body.source === "string" && SOURCES.has(body.source) ? body.source : "manual";

  const analysis = await analyzeContent(content);

  try {
    const saved = await saveScan({ clientId, source, content, ...analysis, target: analysis.target?.slice(0, 2048) ?? null, finalUrl: analysis.finalUrl?.slice(0, 2048) ?? null });
    return c.json({ saved: true, scan: serialize(saved) });
  } catch (e) {
    console.error("Failed to save scan:", e);
    return c.json({ saved: false, saveError: "Result could not be saved to history", scan: { id: null, source, content, ...analysis, createdAt: new Date().toISOString() } });
  }
});

app.get("/history", async (c) => {
  const clientId = requireClient(c);
  const verdict = (c.req.query("verdict") ?? "").toUpperCase();
  const limit = Math.min(100, Math.max(1, Number(c.req.query("limit")) || 20));
  const offset = Math.max(0, Number(c.req.query("offset")) || 0);
  const q = (c.req.query("q") ?? "").trim().slice(0, 200);
  const { rows, total } = await listScans(clientId, { verdict: VERDICTS.has(verdict) ? verdict : undefined, q: q || undefined, limit, offset });
  const stats = await verdictStats(clientId);
  return c.json({ items: rows.map(serialize), total, limit, offset, stats });
});

app.get("/history/export/csv", async (c) => {
  const clientId = requireClient(c);
  const { rows } = await listScans(clientId, { limit: 5000, offset: 0 });
  const head = ["id", "date", "time_utc", "source", "content_type", "verdict", "risk_score", "target", "final_url", "summary", "content"];
  const lines = rows.map((r) => {
    const iso = new Date(r.createdAt).toISOString();
    return [r.id, iso.slice(0, 10), iso.slice(11, 19), r.source, r.contentType, r.verdict, r.riskScore, r.target, r.finalUrl, r.summary, r.content].map(csvCell).join(",");
  });
  return new Response([head.join(","), ...lines].join("\r\n"), {
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="qrshield-history-${new Date().toISOString().slice(0, 10)}.csv"`, "Cache-Control": "no-store" },
  });
});

app.get("/history/:id", async (c) => {
  const clientId = requireClient(c);
  const id = c.req.param("id");
  if (!UUID_RE.test(id)) throw new HttpError(400, "Invalid scan id");
  const row = await getScan(clientId, id);
  if (!row) return c.json({ error: "Scan not found" }, 404);
  return c.json({ scan: serialize(row) });
});

app.delete("/history/:id", async (c) => {
  const clientId = requireClient(c);
  const id = c.req.param("id");
  if (!UUID_RE.test(id)) throw new HttpError(400, "Invalid scan id");
  const ok = await deleteScan(clientId, id);
  return ok ? c.json({ deleted: true }) : c.json({ error: "Scan not found" }, 404);
});

app.delete("/history", async (c) => {
  const clientId = requireClient(c);
  const n = await clearScans(clientId);
  return c.json({ deleted: n });
});

// Render a report for a result that is not (yet) in history, e.g. when saving failed. Data is re-validated.
app.post("/reports/pdf", async (c) => {
  let b: Record<string, unknown>;
  try {
    b = await c.req.json();
  } catch {
    throw new HttpError(400, "Body must be JSON");
  }
  const str = (v: unknown, max = 4096) => (typeof v === "string" ? v.slice(0, max) : null);
  const verdict = str(b.verdict, 20) ?? "";
  if (!VERDICTS.has(verdict) || !str(b.content)) throw new HttpError(400, "Invalid scan data");
  const row = {
    id: "unsaved",
    clientId: "",
    source: SOURCES.has(str(b.source, 20) ?? "") ? (b.source as string) : "manual",
    content: str(b.content)!,
    contentType: str(b.contentType, 40) ?? "text",
    target: str(b.target, 2048),
    finalUrl: str(b.finalUrl, 2048),
    verdict,
    riskScore: Math.max(0, Math.min(100, Math.round(Number(b.riskScore) || 0))),
    summary: str(b.summary, 1000) ?? "",
    reasons: (Array.isArray(b.reasons) ? b.reasons.slice(0, 60) : []).map((r: Record<string, unknown>) => ({
      severity: ["critical", "high", "medium", "low", "info"].includes(String(r?.severity)) ? String(r.severity) : "info",
      title: String(r?.title ?? "").slice(0, 200),
      detail: String(r?.detail ?? "").slice(0, 1000),
      weight: Math.max(0, Math.min(100, Number(r?.weight) || 0)),
    })),
    details: b.details && typeof b.details === "object" ? b.details : {},
    createdAt: new Date(str(b.createdAt, 40) ?? Date.now()),
  } as ScanRow;
  if (isNaN(row.createdAt.getTime())) row.createdAt = new Date();
  let pdf: Uint8Array;
  try {
    pdf = await buildScanReport(row);
  } catch {
    throw new HttpError(400, "Invalid scan data");
  }
  return new Response(pdf as unknown as BodyInit, {
    headers: { "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="qrshield-report-${verdict.toLowerCase()}.pdf"`, "Cache-Control": "no-store" },
  });
});

app.get("/reports/history/pdf", async (c) => {
  const clientId = requireClient(c);
  const [{ rows }, stats] = await Promise.all([listScans(clientId, { limit: 1000, offset: 0 }), verdictStats(clientId)]);
  const pdf = await buildHistoryReport(rows, stats);
  return new Response(pdf as unknown as BodyInit, {
    headers: { "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="qrshield-history-report-${new Date().toISOString().slice(0, 10)}.pdf"`, "Cache-Control": "no-store" },
  });
});

app.get("/reports/:id/pdf", async (c) => {
  const clientId = requireClient(c);
  const id = c.req.param("id");
  if (!UUID_RE.test(id)) throw new HttpError(400, "Invalid scan id");
  const row = await getScan(clientId, id);
  if (!row) return c.json({ error: "Scan not found" }, 404);
  const pdf = await buildScanReport(row);
  return new Response(pdf as unknown as BodyInit, {
    headers: { "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="qrshield-report-${row.verdict.toLowerCase()}-${id.slice(0, 8)}.pdf"`, "Cache-Control": "no-store" },
  });
});

app.notFound((c) => c.json({ error: "Not found" }, 404));
