/**
 * SSRF-safe redirect tracer. Follows HTTP 3xx, <meta refresh> and simple JavaScript redirects
 * for a user-supplied URL, refusing loopback/private/link-local/unique-local targets on every hop
 * (checked at connect time via a custom DNS lookup, so DNS rebinding is covered too).
 * Only derived signals are returned — never the fetched body.
 */
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import ipaddr from "ipaddr.js";

export interface Hop {
  url: string;
  status: number | null;
  via: "start" | "http" | "meta-refresh" | "javascript";
  contentType?: string | null;
  error?: string;
  errorCode?: string;
}

export interface PageSignals {
  title: string | null;
  hasPasswordField: boolean;
  hasForm: boolean;
  isDownload: boolean;
  downloadType: string | null;
}

export interface TraceResult {
  hops: Hop[];
  finalUrl: string;
  completed: boolean; // reached a non-redirect response
  stopReason: string | null;
  nonWebRedirect: string | null; // e.g. intent://, market://
  page: PageSignals | null;
}

const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);
const MAX_BODY = 96 * 1024;
const UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 QRShieldLinkCheck/2.0";

export function isPublicAddress(ip: string): boolean {
  try {
    const addr = ipaddr.process(ip);
    return addr.range() === "unicast";
  } catch {
    return false;
  }
}

class BlockedAddressError extends Error {
  code = "EBLOCKED";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function safeLookup(hostname: string, options: any, callback: any) {
  dns.lookup(hostname, { all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses.length || addresses.some((a) => !isPublicAddress(a.address))) {
      return callback(new BlockedAddressError(`${hostname} resolves to a private or reserved network address`));
    }
    if (options && options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

interface HopResponse {
  status: number;
  location: string | null;
  contentType: string | null;
  contentDisposition: string | null;
  body: string | null;
}

function requestOnce(target: URL, timeoutMs: number): Promise<HopResponse> {
  return new Promise((resolve, reject) => {
    const lib = target.protocol === "https:" ? https : http;
    const req = lib.request(
      target,
      {
        method: "GET",
        lookup: safeLookup,
        agent: false,
        timeout: timeoutMs,
        headers: {
          "User-Agent": UA,
          Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
          "Accept-Encoding": "identity",
          "Accept-Language": "en-IN,en;q=0.9",
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const contentType = (res.headers["content-type"] as string | undefined) ?? null;
        const contentDisposition = (res.headers["content-disposition"] as string | undefined) ?? null;
        const location = (res.headers.location as string | undefined) ?? null;
        const isHtml = !!contentType && /text\/html|application\/xhtml/i.test(contentType);
        if (status >= 300 || !isHtml) {
          res.destroy();
          return resolve({ status, location, contentType, contentDisposition, body: null });
        }
        const chunks: Buffer[] = [];
        let size = 0;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          resolve({ status, location, contentType, contentDisposition, body: Buffer.concat(chunks).toString("utf8") });
        };
        res.on("data", (c: Buffer) => {
          chunks.push(c);
          size += c.length;
          if (size >= MAX_BODY) {
            finish();
            res.destroy();
          }
        });
        res.on("end", finish);
        res.on("error", finish);
        res.on("close", finish);
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" })));
    req.on("error", reject);
    req.end();
  });
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

function findMetaRefresh(html: string): string | null {
  const tag = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i)?.[0];
  if (!tag) return null;
  const content = tag.match(/content\s*=\s*(["'])(.*?)\1/i)?.[2] ?? tag.match(/content\s*=\s*([^\s>]+)/i)?.[1];
  const url = content?.match(/url\s*=\s*['"]?([^'";]+)/i)?.[1];
  return url ? decodeEntities(url.trim()) : null;
}

function findJsRedirect(html: string): string | null {
  // Only consider short pages (real redirect stubs), not full apps that reference location somewhere.
  if (html.length > 20000) return null;
  const m =
    html.match(/(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]/i) ||
    html.match(/location\.(?:replace|assign)\(\s*["'`]([^"'`]+)["'`]\s*\)/i);
  return m ? decodeEntities(m[1]) : null;
}

function pageSignals(html: string): Pick<PageSignals, "title" | "hasPasswordField" | "hasForm"> {
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1];
  return {
    title: title ? decodeEntities(title.replace(/\s+/g, " ").trim()).slice(0, 200) : null,
    hasPasswordField: /<input[^>]+type\s*=\s*["']?password/i.test(html),
    hasForm: /<form[\s>]/i.test(html),
  };
}

const DOWNLOAD_TYPES: Record<string, string> = {
  "application/vnd.android.package-archive": "Android app (APK)",
  "application/x-msdownload": "Windows executable",
  "application/x-msdos-program": "Windows executable",
  "application/x-msi": "Windows installer",
  "application/x-apple-diskimage": "macOS disk image",
  "application/java-archive": "Java archive",
  "application/x-sh": "Shell script",
};

export async function traceRedirects(startUrl: string, opts: { maxHops?: number; budgetMs?: number } = {}): Promise<TraceResult> {
  const maxHops = opts.maxHops ?? 8;
  const deadline = Date.now() + (opts.budgetMs ?? 9000);
  const hops: Hop[] = [];
  const seen = new Set<string>();
  let current = startUrl;
  let via: Hop["via"] = "start";
  let page: PageSignals | null = null;

  for (let i = 0; i <= maxHops; i++) {
    let url: URL;
    try {
      url = new URL(current);
    } catch {
      return { hops, finalUrl: current, completed: false, stopReason: "Invalid redirect target", nonWebRedirect: null, page };
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { hops, finalUrl: current, completed: false, stopReason: `Redirects to non-web link (${url.protocol})`, nonWebRedirect: url.protocol, page };
    }
    if (seen.has(url.href)) {
      return { hops, finalUrl: url.href, completed: false, stopReason: "Redirect loop detected", nonWebRedirect: null, page };
    }
    seen.add(url.href);
    if (!ALLOWED_PORTS.has(url.port)) {
      hops.push({ url: url.href, status: null, via, error: `Port ${url.port} not fetched`, errorCode: "EPORT" });
      return { hops, finalUrl: url.href, completed: false, stopReason: `Non-standard port ${url.port}`, nonWebRedirect: null, page };
    }
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(host) && !isPublicAddress(host)) {
      hops.push({ url: url.href, status: null, via, error: "Private/reserved network address", errorCode: "EBLOCKED" });
      return { hops, finalUrl: url.href, completed: false, stopReason: "Points to a private or local network address", nonWebRedirect: null, page };
    }
    const remaining = deadline - Date.now();
    if (remaining < 500) {
      return { hops, finalUrl: url.href, completed: false, stopReason: "Redirect tracing timed out", nonWebRedirect: null, page };
    }

    let res: HopResponse;
    try {
      res = await requestOnce(url, Math.min(5000, remaining));
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      hops.push({ url: url.href, status: null, via, error: err.message, errorCode: err.code ?? "EFETCH" });
      return { hops, finalUrl: url.href, completed: false, stopReason: err.message, nonWebRedirect: null, page };
    }

    hops.push({ url: url.href, status: res.status, via, contentType: res.contentType });

    if (res.status >= 300 && res.status < 400 && res.location) {
      current = new URL(res.location, url).href;
      via = "http";
      continue;
    }

    const ct = (res.contentType ?? "").split(";")[0].trim().toLowerCase();
    const attachment = /attachment/i.test(res.contentDisposition ?? "");
    const dlType = DOWNLOAD_TYPES[ct] ?? (attachment ? `File download (${ct || "unknown type"})` : null);

    if (res.body) {
      const meta = findMetaRefresh(res.body);
      const js = meta ? null : findJsRedirect(res.body);
      const next = meta ?? js;
      if (next) {
        try {
          current = new URL(next, url).href;
          via = meta ? "meta-refresh" : "javascript";
          continue;
        } catch {
          /* ignore malformed */
        }
      }
      page = { ...pageSignals(res.body), isDownload: false, downloadType: null };
    } else {
      page = { title: null, hasPasswordField: false, hasForm: false, isDownload: !!dlType, downloadType: dlType };
    }
    return { hops, finalUrl: url.href, completed: true, stopReason: null, nonWebRedirect: null, page };
  }
  return { hops, finalUrl: current, completed: false, stopReason: `More than ${maxHops} redirects`, nonWebRedirect: null, page };
}
