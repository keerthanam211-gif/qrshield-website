/**
 * Threat-intelligence lookups. All results are real:
 *  - Google Safe Browsing v4 Lookup API (phishing, malware, unwanted software) — needs GOOGLE_SAFE_BROWSING_API_KEY
 *  - OpenPhish community feed (live phishing URLs, refreshed hourly)
 *  - Phishing Army blocklist (aggregated phishing domains from PhishTank, OpenPhish, CERT.PL, urlscan.io, ...)
 * Feeds are cached in memory per server instance and refreshed when stale.
 */
import { getDomain } from "tldts";
import type { SourceCheck } from "./types.ts";

const FEED_TTL_MS = 60 * 60 * 1000;
const FEED_TIMEOUT_MS = 10_000;

interface Feed {
  name: string;
  url: string;
  parse: (text: string) => { urls: Set<string>; hosts: Set<string> };
  data: { urls: Set<string>; hosts: Set<string> } | null;
  loadedAt: number;
  loading: Promise<void> | null;
  lastError: string | null;
}

export function normalizeUrlForMatch(raw: string): string | null {
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    let path = u.pathname.replace(/\/+$/, "");
    if (!path) path = "";
    return `${u.hostname.toLowerCase().replace(/^www\./, "")}${path}${u.search}`;
  } catch {
    return null;
  }
}

/** Hosts where many unrelated users publish content — a feed entry on these must match the exact URL. */
const SHARED_HOSTS = new Set([
  "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
  "firebasestorage.googleapis.com", "dropbox.com", "www.dropbox.com", "onedrive.live.com", "1drv.ms",
  "forms.office.com", "sharepoint.com", "github.com", "raw.githubusercontent.com", "bit.ly", "t.co",
  "tinyurl.com", "linktr.ee", "notion.so", "telegra.ph", "discord.com", "cdn.discordapp.com",
  "ipfs.io", "dweb.link", "jotform.com", "form.jotform.com", "typeform.com", "canva.com", "www.canva.com",
]);

const feeds: Record<string, Feed> = {
  openphish: {
    name: "OpenPhish",
    url: "https://openphish.com/feed.txt",
    parse(text) {
      const urls = new Set<string>();
      const hosts = new Set<string>();
      for (const line of text.split(/\r?\n/)) {
        const n = normalizeUrlForMatch(line);
        if (!n) continue;
        urls.add(n);
        try {
          hosts.add(new URL(line.trim()).hostname.toLowerCase().replace(/^www\./, ""));
        } catch {
          /* skip */
        }
      }
      return { urls, hosts };
    },
    data: null,
    loadedAt: 0,
    loading: null,
    lastError: null,
  },
  phishingArmy: {
    name: "Phishing Army",
    url: "https://phishing.army/download/phishing_army_blocklist.txt",
    parse(text) {
      const hosts = new Set<string>();
      for (const line of text.split(/\r?\n/)) {
        const d = line.trim().toLowerCase();
        if (!d || d.startsWith("#")) continue;
        if (d === "amiprotected.it" || d === "www.amiprotected.it") continue; // feed's harmless test entries
        hosts.add(d.replace(/^www\./, ""));
      }
      return { urls: new Set(), hosts };
    },
    data: null,
    loadedAt: 0,
    loading: null,
    lastError: null,
  },
};

async function refreshFeed(feed: Feed): Promise<void> {
  if (feed.loading) return feed.loading;
  feed.loading = (async () => {
    try {
      const res = await fetch(feed.url, {
        redirect: "follow",
        signal: AbortSignal.timeout(FEED_TIMEOUT_MS),
        headers: { "User-Agent": "QRShield/2.0 (+threat-feed-sync)" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const data = feed.parse(text);
      if (data.urls.size + data.hosts.size === 0) throw new Error("Feed was empty");
      feed.data = data;
      feed.loadedAt = Date.now();
      feed.lastError = null;
    } catch (e) {
      feed.lastError = (e as Error).message;
    } finally {
      feed.loading = null;
    }
  })();
  return feed.loading;
}

async function ensureFeed(feed: Feed): Promise<void> {
  if (!feed.data || Date.now() - feed.loadedAt > FEED_TTL_MS) await refreshFeed(feed);
}

/** Pre-warm feeds (called on first request). */
export function warmFeeds(): Promise<unknown> {
  return Promise.all(Object.values(feeds).map(ensureFeed));
}

function hostCandidates(host: string): string[] {
  const h = host.toLowerCase().replace(/^www\./, "");
  const registered = getDomain(h);
  const out = [h];
  if (!registered) return out;
  const parts = h.split(".");
  for (let i = 1; i < parts.length; i++) {
    const cand = parts.slice(i).join(".");
    out.push(cand);
    if (cand === registered) break;
  }
  return out;
}

function checkFeed(feed: Feed, urls: string[]): SourceCheck {
  if (!feed.data) {
    return { source: feed.name, status: "error", detail: `Feed unavailable${feed.lastError ? `: ${feed.lastError}` : ""}` };
  }
  const matches: { url: string; threat: string }[] = [];
  for (const raw of urls) {
    const n = normalizeUrlForMatch(raw);
    if (!n) continue;
    let host: string;
    try {
      host = new URL(raw).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      continue;
    }
    if (feed.data.urls.has(n)) {
      matches.push({ url: raw, threat: "Listed phishing URL" });
      continue;
    }
    if (SHARED_HOSTS.has(host)) continue;
    const hit = hostCandidates(host).find((c) => feed.data!.hosts.has(c) && !SHARED_HOSTS.has(c));
    if (hit) matches.push({ url: raw, threat: `Listed phishing domain (${hit})` });
  }
  const size = feed.data.urls.size || feed.data.hosts.size;
  if (matches.length) {
    return { source: feed.name, status: "match", detail: `${matches.length} match(es) in ${size.toLocaleString("en-US")} known phishing entries`, matches };
  }
  return { source: feed.name, status: "clean", detail: `Not listed (${size.toLocaleString("en-US")} entries, synced ${Math.round((Date.now() - feed.loadedAt) / 60000)} min ago)` };
}

const GSB_THREAT_LABEL: Record<string, string> = {
  MALWARE: "Malware",
  SOCIAL_ENGINEERING: "Phishing / social engineering",
  UNWANTED_SOFTWARE: "Unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "Potentially harmful application",
};

export function safeBrowsingConfigured(): boolean {
  return !!process.env.GOOGLE_SAFE_BROWSING_API_KEY;
}

async function checkSafeBrowsing(urls: string[]): Promise<SourceCheck> {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!key) {
    return { source: "Google Safe Browsing", status: "not_configured", detail: "API key not configured (set GOOGLE_SAFE_BROWSING_API_KEY)" };
  }
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(6000),
      body: JSON.stringify({
        client: { clientId: "qrshield", clientVersion: "2.0.0" },
        threatInfo: {
          threatTypes: Object.keys(GSB_THREAT_LABEL),
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.slice(0, 50).map((url) => ({ url })),
        },
      }),
    });
    if (!res.ok) {
      return { source: "Google Safe Browsing", status: "error", detail: `API error (HTTP ${res.status})` };
    }
    const json = (await res.json()) as { matches?: { threatType: string; threat: { url: string } }[] };
    const matches = (json.matches ?? []).map((m) => ({ url: m.threat.url, threat: GSB_THREAT_LABEL[m.threatType] ?? m.threatType }));
    if (matches.length) return { source: "Google Safe Browsing", status: "match", detail: `${matches.length} threat match(es)`, matches };
    return { source: "Google Safe Browsing", status: "clean", detail: "No threats found" };
  } catch (e) {
    return { source: "Google Safe Browsing", status: "error", detail: `Request failed: ${(e as Error).message}` };
  }
}

export interface IntelResult {
  checks: SourceCheck[];
  matched: boolean;
  /** At least one source answered and no configured source failed hard. */
  verified: boolean;
}

/** Check every URL in a redirect chain against all sources in parallel. */
export async function checkThreatIntel(urls: string[]): Promise<IntelResult> {
  const unique = [...new Set(urls.filter(Boolean))];
  const [gsb] = await Promise.all([checkSafeBrowsing(unique), warmFeeds()]);
  const checks = [gsb, checkFeed(feeds.openphish, unique), checkFeed(feeds.phishingArmy, unique)];
  const matched = checks.some((c) => c.status === "match");
  const answered = checks.filter((c) => c.status === "clean" || c.status === "match").length;
  const gsbFailed = gsb.status === "error"; // configured but failing => cannot claim verification
  return { checks, matched, verified: answered > 0 && !gsbFailed };
}

export function intelStatus() {
  return {
    googleSafeBrowsing: safeBrowsingConfigured() ? "configured" : "not_configured",
    feeds: Object.values(feeds).map((f) => ({
      name: f.name,
      loaded: !!f.data,
      entries: f.data ? f.data.urls.size || f.data.hosts.size : 0,
      syncedAt: f.loadedAt ? new Date(f.loadedAt).toISOString() : null,
      lastError: f.lastError,
    })),
  };
}
