/** History queries (filter, search, paging, stats) on top of the Blobs scan store in /db. */
import { allScans, findScan, insertScan, removeAll, removeScan } from "../../db/store.ts";
import type { NewScanRow, ScanRow } from "../../db/schema.ts";

export const saveScan = (row: NewScanRow): Promise<ScanRow> => insertScan(row);
export const getScan = (clientId: string, id: string) => findScan(clientId, id);
export const deleteScan = (clientId: string, id: string) => removeScan(clientId, id);
export const clearScans = (clientId: string) => removeAll(clientId);

export async function listScans(clientId: string, opts: { verdict?: string; q?: string; limit: number; offset: number }) {
  let rows = await allScans(clientId);
  if (opts.verdict) rows = rows.filter((r) => r.verdict === opts.verdict);
  if (opts.q) {
    const q = opts.q.toLowerCase();
    rows = rows.filter((r) => [r.content, r.target, r.summary].some((v) => (v ?? "").toLowerCase().includes(q)));
  }
  return { rows: rows.slice(opts.offset, opts.offset + opts.limit), total: rows.length };
}

export async function verdictStats(clientId: string): Promise<Record<string, number>> {
  const out: Record<string, number> = { SAFE: 0, SUSPICIOUS: 0, DANGEROUS: 0, UNVERIFIED: 0, total: 0 };
  for (const r of await allScans(clientId)) {
    out[r.verdict] = (out[r.verdict] ?? 0) + 1;
    out.total++;
  }
  return out;
}
