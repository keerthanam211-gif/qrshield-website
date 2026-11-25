/**
 * Entry point: classifies decoded QR content and routes it to the right analyser.
 */
import { parse } from "tldts";
import { analyzeUrl, type UrlAnalysis } from "./url.ts";
import { analyzeUpi } from "./upi.ts";
import { analyzeUrlStatic } from "./heuristics.ts";
import { checkThreatIntel } from "./intel.ts";
import { decideVerdict, dedupeFindings, finding, type AnalysisResult, type Finding, type Verdict } from "./types.ts";

const URL_IN_TEXT = /\b((?:https?:\/\/|www\.)[^\s<>"'`]+)/gi;

export function classify(content: string): string {
  const c = content.trim();
  if (/^upi:\/\//i.test(c)) return "upi";
  if (/^https?:\/\//i.test(c)) return "url";
  if (/^(javascript|vbscript|data|file|blob):/i.test(c)) return "script";
  if (/^WIFI:/i.test(c)) return "wifi";
  if (/^tel:/i.test(c)) return "phone";
  if (/^(smsto|sms|mms):/i.test(c)) return "sms";
  if (/^(mailto:|MATMSG:)/i.test(c)) return "email";
  if (/^geo:/i.test(c)) return "location";
  if (/^(BEGIN:VCARD|MECARD:)/i.test(c)) return "contact";
  if (/^BEGIN:VEVENT|^BEGIN:VCALENDAR/i.test(c)) return "event";
  if (/^(intent|market|itms-services|itms-apps):/i.test(c)) return "app";
  if (/^(bitcoin|ethereum|litecoin|dogecoin|bitcoincash|solana|tron|usdt):/i.test(c)) return "crypto";
  if (looksLikeBareDomain(c)) return "url";
  if (/^[a-z][a-z0-9+.-]{1,30}:\/\//i.test(c)) return "app";
  return "text";
}

function looksLikeBareDomain(c: string) {
  if (/\s/.test(c) || c.length > 2000) return false;
  const m = c.match(/^([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:[/?#]\S*)?$/i);
  if (!m) return false;
  const p = parse(m[1]);
  return !!p.domain && (p.isIcann ?? false);
}

export function normalizeUrlInput(c: string): string {
  const t = c.trim();
  if (/^https?:\/\//i.test(t)) return t;
  if (/^www\./i.test(t) || looksLikeBareDomain(t)) return `https://${t}`;
  return t;
}

interface PartialResult {
  findings: Finding[];
  confirmedMalicious: boolean;
  verified: boolean;
  target: string | null;
  finalUrl: string | null;
  details: Record<string, unknown>;
  unverifiedReason?: string | null;
}

function urlDetails(a: UrlAnalysis) {
  return {
    original: a.url,
    final: a.finalUrl,
    redirects: a.trace.hops,
    stopReason: a.trace.stopReason,
    page: a.trace.page ? { title: a.trace.page.title, hasPasswordField: a.trace.page.hasPasswordField, isDownload: a.trace.page.isDownload, downloadType: a.trace.page.downloadType } : null,
    domainAge: a.domainAge,
    finalDomainAge: a.finalDomainAge,
    intel: a.intel.checks,
  };
}

async function analyzeEmbeddedUrls(urls: string[]): Promise<PartialResult | null> {
  const list = [...new Set(urls.map(normalizeUrlInput))].filter((u) => { try { new URL(u); return true; } catch { return false; } }).slice(0, 3);
  if (!list.length) return null;
  const results = await Promise.all(list.map((u) => analyzeUrl(u, { traceBudgetMs: 7000 })));
  return {
    findings: results.flatMap((r, i) => r.findings.map((f) => (list.length > 1 ? { ...f, id: `${i}-${f.id}`, detail: `[${new URL(r.url).hostname}] ${f.detail}` } : f))),
    confirmedMalicious: results.some((r) => r.confirmedMalicious),
    verified: results.every((r) => r.verified),
    unverifiedReason: results.find((r) => r.unverifiedReason)?.unverifiedReason ?? null,
    target: results[0].url,
    finalUrl: results[0].finalUrl,
    details: { links: results.map(urlDetails) },
  };
}

async function analyzeByType(type: string, content: string): Promise<PartialResult> {
  const c = content.trim();
  switch (type) {
    case "url": {
      const a = await analyzeUrl(normalizeUrlInput(c));
      return { findings: a.findings, confirmedMalicious: a.confirmedMalicious, verified: a.verified, unverifiedReason: a.unverifiedReason, target: a.url, finalUrl: a.finalUrl, details: { link: urlDetails(a) } };
    }

    case "upi": {
      const { details, findings } = analyzeUpi(c);
      let confirmed = false;
      let verified = true;
      const extra: Record<string, unknown> = {};
      if (details.url && /^https?:\/\//i.test(details.url)) {
        // A UPI QR can embed a reference link — check it statically + against threat intel (no browsing).
        const intel = await checkThreatIntel([details.url]);
        confirmed = intel.matched;
        verified = intel.verified;
        findings.push(...analyzeUrlStatic(details.url).map((f) => ({ ...f, id: `upi-url-${f.id}`, title: `Embedded link: ${f.title}` })));
        if (intel.matched) findings.push(finding("upi-url-intel", "critical", 60, "Embedded link is a known threat", `The reference link ${details.url} is listed by threat intelligence.`));
        extra.embeddedLinkIntel = intel.checks;
      }
      return { findings, confirmedMalicious: confirmed, verified, target: details.payeeVpa, finalUrl: null, details: { upi: details, ...extra } };
    }

    case "script": {
      const scheme = c.split(":")[0].toLowerCase();
      const isHtmlData = scheme === "data" && /^data:\s*(text\/html|application\/xhtml|image\/svg)/i.test(c);
      if (scheme === "javascript" || scheme === "vbscript" || isHtmlData) {
        return {
          findings: [finding("script-payload", "critical", 90, scheme === "data" ? "Embedded web page / script (data: URL)" : `Executable ${scheme}: code`, "This QR contains code that runs directly in your browser instead of a normal link. Legitimate QR codes never do this — it is used to steal sessions and show fake login pages.")],
          confirmedMalicious: true, verified: true, target: c.slice(0, 200), finalUrl: null, details: { scheme },
        };
      }
      return { findings: [finding("local-scheme", "high", 40, `Unusual ${scheme}: link`, `"${scheme}:" links access local files or embedded data rather than a website.`)], confirmedMalicious: false, verified: true, target: c.slice(0, 200), finalUrl: null, details: { scheme } };
    }

    case "wifi": {
      const get = (k: string) => c.match(new RegExp(`(?:^WIFI:|;)${k}:((?:\\\\.|[^;])*)`, "i"))?.[1]?.replace(/\\(.)/g, "$1") ?? null;
      const ssid = get("S");
      const auth = (get("T") ?? "nopass").toUpperCase();
      const hidden = /^true$/i.test(get("H") ?? "");
      const f: Finding[] = [];
      if (!ssid) f.push(finding("wifi-nossid", "medium", 20, "Wi-Fi QR without a network name", "The Wi-Fi configuration is incomplete."));
      if (auth === "NOPASS" || auth === "") f.push(finding("wifi-open", "low", 15, "Open network (no password)", "Traffic on open Wi-Fi can be watched by anyone nearby. Avoid banking or logins on it."));
      else if (auth === "WEP") f.push(finding("wifi-wep", "low", 15, "Outdated WEP encryption", "WEP can be cracked in minutes."));
      if (hidden) f.push(finding("wifi-hidden", "info", 0, "Hidden network", "The network does not broadcast its name."));
      if (ssid && /free|public|guest|airport|station|hotel/i.test(ssid) && (auth === "NOPASS" || auth === "")) {
        f.push(finding("wifi-evil-twin", "medium", 15, "Generic 'free Wi-Fi' name", "Fake hotspots ('evil twins') use generic names like Free WiFi to intercept traffic."));
      }
      return { findings: f, confirmedMalicious: false, verified: true, target: ssid, finalUrl: null, details: { wifi: { ssid, security: auth === "NOPASS" ? "None" : auth, hidden, hasPassword: !!get("P") } } };
    }

    case "phone": {
      const num = decodeURIComponent(c.replace(/^tel:/i, "")).trim();
      const f: Finding[] = [];
      if (/[*#]/.test(num)) {
        f.push(finding("ussd", "high", 45, "USSD / call-forwarding code", `"${num}" is a network command, not a phone number. Codes like *21*, *401* or **67* silently forward your calls and OTPs to a scammer.`));
      } else if (!/^\+?[\d\s()-]{3,20}$/.test(num)) {
        f.push(finding("bad-number", "low", 15, "Malformed phone number", `"${num}" is not a normal phone number.`));
      }
      return { findings: f, confirmedMalicious: false, verified: true, target: num, finalUrl: null, details: { phone: num } };
    }

    case "sms": {
      const m = c.match(/^(?:smsto|sms|mms):([^:?]*)[:?]?(?:body=)?(.*)$/i);
      const num = decodeSafe(m?.[1] ?? "");
      const body = decodeSafe(m?.[2] ?? "");
      const f: Finding[] = [];
      if (/\b(otp|kyc|verify|refund|prize|lottery|password|pin|start|activate|register)\b/i.test(body)) {
        f.push(finding("sms-bait", "medium", 25, "Pre-written message with sensitive wording", `Sending "${body.slice(0, 80)}" may subscribe you to a premium service or share sensitive information.`));
      }
      if (/[*#]/.test(num)) f.push(finding("ussd", "high", 40, "SMS to a network code", `"${num}" is not a normal number.`));
      const embedded = await analyzeEmbeddedUrls(body.match(URL_IN_TEXT) ?? []);
      return merge({ findings: f, confirmedMalicious: false, verified: true, target: num, finalUrl: null, details: { sms: { number: num, body } } }, embedded);
    }

    case "email": {
      const urls = c.match(URL_IN_TEXT) ?? [];
      const f: Finding[] = [];
      if (/\b(password|otp|kyc|verify|bank details|account number)\b/i.test(c)) f.push(finding("email-bait", "low", 15, "Pre-written email asks for sensitive details", "Do not send passwords, OTPs or bank details by email."));
      const embedded = await analyzeEmbeddedUrls(urls);
      const to = c.match(/^mailto:([^?]*)/i)?.[1] ?? c.match(/TO:([^;]*)/i)?.[1] ?? null;
      return merge({ findings: f, confirmedMalicious: false, verified: true, target: to ? decodeSafe(to) : null, finalUrl: null, details: { email: { to } } }, embedded);
    }

    case "location":
      return { findings: [finding("geo", "info", 0, "Map location", "Opens a location in your maps app.")], confirmedMalicious: false, verified: true, target: c, finalUrl: null, details: {} };

    case "contact":
    case "event": {
      const f: Finding[] = [];
      for (const tel of c.match(/TEL[^:]*:([^\r\n;]+)/gi) ?? []) {
        if (/[*#]/.test(tel.split(":").pop()!)) f.push(finding("ussd", "high", 40, "Contact contains a network code", `${tel.split(":").pop()} is a USSD/call-forwarding code, not a phone number.`));
      }
      const embedded = await analyzeEmbeddedUrls(c.match(URL_IN_TEXT) ?? []);
      const name = c.match(/(?:^|\n)FN:([^\r\n]+)/i)?.[1] ?? c.match(/MECARD:N:([^;]+)/i)?.[1] ?? c.match(/SUMMARY:([^\r\n]+)/i)?.[1] ?? null;
      return merge({ findings: f, confirmedMalicious: false, verified: true, target: name, finalUrl: null, details: {} }, embedded);
    }

    case "app": {
      const scheme = c.split(":")[0].toLowerCase();
      if (scheme === "itms-services") {
        return { findings: [finding("ios-sideload", "high", 45, "Installs an iOS app outside the App Store", "itms-services links install enterprise-signed apps, a method used to push spyware and fake banking apps.")], confirmedMalicious: false, verified: true, target: c.slice(0, 200), finalUrl: null, details: { scheme } };
      }
      if (scheme === "market") {
        const id = c.match(/[?&]id=([\w.]+)/)?.[1] ?? null;
        return { findings: [finding("play-link", "info", 0, "Opens a Google Play listing", `Opens app ${id ?? "(unknown)"} in Google Play. Check the developer name before installing.`)], confirmedMalicious: false, verified: true, target: id, finalUrl: null, details: { package: id } };
      }
      if (scheme === "intent") {
        const fallback = decodeSafe(c.match(/S\.browser_fallback_url=([^;]+)/)?.[1] ?? "");
        const pkg = c.match(/package=([\w.]+)/)?.[1] ?? null;
        const base: PartialResult = { findings: [finding("intent", "low", 10, "Android app intent", `Launches ${pkg ?? "an app"} directly on Android.`)], confirmedMalicious: false, verified: false, unverifiedReason: "Android app intents cannot be fully verified.", target: pkg, finalUrl: null, details: { package: pkg } };
        const embedded = fallback ? await analyzeEmbeddedUrls([fallback]) : null;
        return merge(base, embedded);
      }
      return { findings: [finding("app-link", "low", 10, `App link (${scheme}://)`, "This QR opens an app directly. QRShield cannot inspect what the app will do.")], confirmedMalicious: false, verified: false, unverifiedReason: `"${scheme}" app links cannot be verified by threat intelligence.`, target: c.slice(0, 200), finalUrl: null, details: { scheme } };
    }

    case "crypto": {
      const scheme = c.split(":")[0].toLowerCase();
      const addr = c.split(":")[1]?.split("?")[0] ?? null;
      return { findings: [finding("crypto", "low", 15, `${scheme} payment request`, "Crypto transfers are irreversible and the recipient cannot be verified. Only pay addresses you obtained from a trusted source.")], confirmedMalicious: false, verified: false, unverifiedReason: "Cryptocurrency recipients cannot be verified.", target: addr, finalUrl: null, details: { scheme, address: addr } };
    }

    default: {
      const urls = c.match(URL_IN_TEXT) ?? [];
      const upiInText = c.match(/upi:\/\/pay\?[^\s]+/i)?.[0];
      const f: Finding[] = [];
      if (/\b(kyc|otp|lottery|prize|refund|cashback|account (blocked|suspended)|verify your)\b/i.test(c)) {
        f.push(finding("text-bait", "low", 15, "Scam-style wording", "The text uses language typical of KYC, refund or prize scams."));
      }
      if (upiInText) {
        const sub = await analyzeByType("upi", upiInText);
        return merge({ findings: f, confirmedMalicious: false, verified: true, target: null, finalUrl: null, details: { text: true } }, sub);
      }
      const embedded = await analyzeEmbeddedUrls(urls);
      if (!embedded) f.push(finding("plain-text", "info", 0, "Plain text only", "This QR contains text with no links, payments or actions."));
      return merge({ findings: f, confirmedMalicious: false, verified: true, target: null, finalUrl: null, details: {} }, embedded);
    }
  }
}

function merge(base: PartialResult, extra: PartialResult | null): PartialResult {
  if (!extra) return base;
  return {
    findings: [...base.findings, ...extra.findings],
    confirmedMalicious: base.confirmedMalicious || extra.confirmedMalicious,
    verified: base.verified && extra.verified,
    unverifiedReason: base.unverifiedReason ?? extra.unverifiedReason ?? null,
    target: extra.target ?? base.target,
    finalUrl: extra.finalUrl ?? base.finalUrl,
    details: { ...base.details, ...extra.details },
  };
}

function decodeSafe(s: string) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

const TYPE_LABEL: Record<string, string> = {
  url: "link", upi: "UPI payment", wifi: "Wi-Fi network", phone: "phone number", sms: "SMS", email: "email",
  location: "location", contact: "contact card", event: "calendar event", app: "app link", crypto: "crypto payment",
  text: "text", script: "script",
};

function summarize(verdict: Verdict, type: string, p: PartialResult, findings: Finding[], verifiedBy: string[]): string {
  const top = findings.filter((f) => f.weight > 0);
  switch (verdict) {
    case "DANGEROUS":
      return `Confirmed threat — ${top[0]?.title ?? "listed as malicious"}. Do not open${type === "upi" ? " or pay" : ""}.`;
    case "SUSPICIOUS":
      return `${top.length} warning sign${top.length === 1 ? "" : "s"}: ${top.slice(0, 2).map((f) => f.title).join("; ")}.`;
    case "SAFE":
      if (type === "url" || p.details.links) {
        const host = (() => { try { return new URL(p.finalUrl ?? "").hostname; } catch { return "the destination"; } })();
        return `No threats found${verifiedBy.length ? ` by ${verifiedBy.join(", ")}` : ""}. Opens ${host}.`;
      }
      if (type === "upi") return "Payment request passed all UPI fraud checks. Confirm the payee name in your UPI app before paying.";
      return `No security issues found in this ${TYPE_LABEL[type] ?? type}.`;
    default:
      return p.unverifiedReason ?? "Security verification could not be completed.";
  }
}

export async function analyzeContent(content: string): Promise<AnalysisResult> {
  const type = classify(content);
  const p = await analyzeByType(type, content);
  const findings = dedupeFindings(p.findings);
  const { verdict, riskScore } = decideVerdict({ findings, confirmedMalicious: p.confirmedMalicious, verified: p.verified });
  const intelLists = [p.details.link, ...((p.details.links as unknown[]) ?? [])].filter(Boolean) as { intel: { source: string; status: string }[] }[];
  const verifiedBy = [...new Set(intelLists.flatMap((l) => l.intel.filter((c) => c.status === "clean" || c.status === "match").map((c) => c.source)))];
  if (verdict === "UNVERIFIED" && p.unverifiedReason) {
    findings.unshift(finding("unverified", "medium", 0, "Verification incomplete", p.unverifiedReason));
  }
  return {
    contentType: type,
    target: p.target,
    finalUrl: p.finalUrl,
    verdict,
    riskScore,
    summary: summarize(verdict, type, p, findings, verifiedBy),
    reasons: findings,
    details: { ...p.details, verifiedBy, analyzedAt: new Date().toISOString() },
  };
}
