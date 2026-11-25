/**
 * Scan-history persistence on Netlify Blobs.
 * Keys: `<clientId>/<reverse-timestamp>_<scanId>` so a prefix listing returns one visitor's scans newest-first.
 */
import { getStore } from "@netlify/blobs";
import type { NewScanRow, ScanRow } from "./schema.ts";

const MAX_PER_CLIENT = 1000;
const store = () => getStore({ name: "qrshield-scans", consistency: "strong" });

const revTs = (d: Date) => String(9_999_999_999_999 - d.getTime()).padStart(13, "0");
const keyOf = (r: { clientId: string; id: string; createdAt: Date }) => `${r.clientId}/${revTs(r.createdAt)}_${r.id}`;

type Stored = Omit<ScanRow, "createdAt"> & { createdAt: string };
const revive = (s: Stored): ScanRow => ({ ...s, createdAt: new Date(s.createdAt) });

async function keysFor(clientId: string): Promise<string[]> {
  const { blobs } = await store().list({ prefix: `${clientId}/` });
  return blobs.map((b) => b.key).sort();
}

export async function insertScan(row: NewScanRow): Promise<ScanRow> {
  const saved: ScanRow = { ...row, id: row.id ?? crypto.randomUUID(), createdAt: row.createdAt ?? new Date() };
  await store().setJSON(keyOf(saved), { ...saved, createdAt: saved.createdAt.toISOString() });
  // Keep each visitor's history bounded.
  const keys = await keysFor(saved.clientId);
  if (keys.length > MAX_PER_CLIENT) await Promise.all(keys.slice(MAX_PER_CLIENT).map((k) => store().delete(k)));
  return saved;
}

/** All scans for a client, newest first. */
export async function allScans(clientId: string): Promise<ScanRow[]> {
  const keys = await keysFor(clientId);
  const rows: ScanRow[] = [];
  for (let i = 0; i < keys.length; i += 25) {
    const batch = await Promise.all(keys.slice(i, i + 25).map((k) => store().get(k, { type: "json" }) as Promise<Stored | null>));
    for (const r of batch) if (r) rows.push(revive(r));
  }
  return rows;
}

async function keyForId(clientId: string, id: string): Promise<string | null> {
  return (await keysFor(clientId)).find((k) => k.endsWith(`_${id}`)) ?? null;
}

export async function findScan(clientId: string, id: string): Promise<ScanRow | null> {
  const key = await keyForId(clientId, id);
  if (!key) return null;
  const r = (await store().get(key, { type: "json" })) as Stored | null;
  return r ? revive(r) : null;
}

export async function removeScan(clientId: string, id: string): Promise<boolean> {
  const key = await keyForId(clientId, id);
  if (!key) return false;
  await store().delete(key);
  return true;
}

export async function removeAll(clientId: string): Promise<number> {
  const keys = await keysFor(clientId);
  await Promise.all(keys.map((k) => store().delete(k)));
  return keys.length;
}
