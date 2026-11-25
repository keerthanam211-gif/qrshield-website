/**
 * Static URL heuristics. Weights are calibrated so that a single weak signal (e.g. a "login" path, a link
 * shortener, plain HTTP) never makes a normal link SUSPICIOUS on its own; strong signals (brand impersonation,
 * typosquatting, raw IPs, APK downloads, credential-harvest patterns) do.
 */
import { parse } from "tldts";
import { domainToUnicode } from "node:url";
import { finding, type Finding } from "./types.ts";

interface Brand {
  name: string;
  tokens: string[]; // tokens that indicate a claim to be this brand
  official: string[]; // registered domains owned by the brand
  officialSuffixes?: string[]; // e.g. brand-owned TLDs (.sbi) or regulated zones (bank.in)
  anyCcTld?: boolean; // google.co.in, amazon.de, ...
  strict?: boolean; // common English word: only count when a sensitive keyword is also present
}

export const BRANDS: Brand[] = [
  { name: "PayPal", tokens: ["paypal"], official: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { name: "Paytm", tokens: ["paytm"], official: ["paytm.com", "paytm.in", "paytmmall.com", "paytmbank.com", "paytmmoney.com", "paytmpayments.com"] },
  { name: "PhonePe", tokens: ["phonepe"], official: ["phonepe.com"] },
  { name: "Google Pay", tokens: ["gpay", "googlepay", "tez"], official: ["google.com", "g.co", "goo.gl"] },
  { name: "Google", tokens: ["google", "gmail"], official: ["google.com", "gmail.com", "goo.gl", "g.co", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "withgoogle.com", "google"], anyCcTld: true },
  { name: "Amazon", tokens: ["amazon", "amzn"], official: ["amazon.com", "amazon.in", "amzn.to", "amzn.in", "a.co", "amazonaws.com", "media-amazon.com", "amazonpay.in"], anyCcTld: true },
  { name: "Flipkart", tokens: ["flipkart"], official: ["flipkart.com", "fkrt.it", "flipkart.net"] },
  { name: "State Bank of India", tokens: ["sbi", "onlinesbi", "yonosbi", "yono"], official: ["sbi.co.in", "onlinesbi.com", "sbicard.com", "sbilife.co.in", "sbimf.com"], officialSuffixes: ["sbi", "bank.in"] },
  { name: "HDFC Bank", tokens: ["hdfc", "hdfcbank"], official: ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcbank.net"], officialSuffixes: ["bank.in"] },
  { name: "ICICI Bank", tokens: ["icici", "icicibank"], official: ["icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com"], officialSuffixes: ["bank.in"] },
  { name: "Axis Bank", tokens: ["axisbank", "axis"], official: ["axisbank.com", "axisbank.co.in"], officialSuffixes: ["bank.in"], strict: true },
  { name: "Kotak", tokens: ["kotak", "kotak811"], official: ["kotak.com", "kotakbank.com", "kotak811.com", "kotaksecurities.com"], officialSuffixes: ["bank.in"] },
  { name: "Punjab National Bank", tokens: ["pnb", "pnbindia"], official: ["pnbindia.in", "netpnb.com"], officialSuffixes: ["bank.in"], strict: true },
  { name: "Apple", tokens: ["apple", "icloud", "appleid"], official: ["apple.com", "icloud.com", "apple.co", "me.com"], strict: true },
  { name: "Microsoft", tokens: ["microsoft", "office365", "onedrive", "sharepoint", "msonline"], official: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com", "sharepoint.com", "onedrive.com", "1drv.ms", "aka.ms", "windows.net", "azure.com", "bing.com", "msn.com", "microsoft365.com", "cloud.microsoft"] },
  { name: "Netflix", tokens: ["netflix"], official: ["netflix.com", "nflxext.com", "netflix.net"] },
  { name: "Facebook", tokens: ["facebook", "fb"], official: ["facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com", "fbcdn.net"], strict: true },
  { name: "Instagram", tokens: ["instagram"], official: ["instagram.com", "instagr.am", "cdninstagram.com"] },
  { name: "WhatsApp", tokens: ["whatsapp"], official: ["whatsapp.com", "whatsapp.net", "wa.me"] },
  { name: "IRCTC", tokens: ["irctc"], official: ["irctc.co.in", "irctc.com"] },
  { name: "UIDAI / Aadhaar", tokens: ["aadhaar", "aadhar", "uidai"], official: ["uidai.gov.in", "myaadhaar.uidai.gov.in"] },
  { name: "Income Tax Dept", tokens: ["incometax", "incometaxindia", "itrefund"], official: ["incometax.gov.in", "incometaxindia.gov.in"] },
  { name: "EPFO", tokens: ["epfo", "epfindia"], official: ["epfindia.gov.in"] },
  { name: "India Post", tokens: ["indiapost"], official: ["indiapost.gov.in"] },
  { name: "DHL", tokens: ["dhl"], official: ["dhl.com", "dhl.de", "dhl.co.in"], anyCcTld: true, strict: true },
  { name: "FedEx", tokens: ["fedex"], official: ["fedex.com"] },
  { name: "USPS", tokens: ["usps"], official: ["usps.com"] },
  { name: "Chase", tokens: ["chase"], official: ["chase.com", "jpmorganchase.com"], strict: true },
  { name: "Wells Fargo", tokens: ["wellsfargo"], official: ["wellsfargo.com"] },
  { name: "Bank of America", tokens: ["bankofamerica", "bofa"], official: ["bankofamerica.com", "bofa.com"] },
  { name: "HSBC", tokens: ["hsbc"], official: ["hsbc.com", "hsbc.co.in", "hsbc.co.uk", "hsbc.com.au", "hsbc.com.hk"], anyCcTld: true },
  { name: "LinkedIn", tokens: ["linkedin"], official: ["linkedin.com", "lnkd.in"] },
  { name: "Binance", tokens: ["binance"], official: ["binance.com", "binance.us"] },
  { name: "Coinbase", tokens: ["coinbase"], official: ["coinbase.com"] },
  { name: "MetaMask", tokens: ["metamask"], official: ["metamask.io"] },
  { name: "Steam", tokens: ["steamcommunity", "steampowered"], official: ["steamcommunity.com", "steampowered.com"] },
  { name: "Telegram", tokens: ["telegram"], official: ["telegram.org", "t.me", "telegram.me"] },
];

/** Registered-domain labels for typosquat comparison (>= 5 chars to avoid noise). */
const TYPO_TARGETS: { label: string; brand: string }[] = [
  ["paypal", "PayPal"], ["paytm", "Paytm"], ["phonepe", "PhonePe"], ["google", "Google"], ["amazon", "Amazon"],
  ["flipkart", "Flipkart"], ["netflix", "Netflix"], ["microsoft", "Microsoft"], ["instagram", "Instagram"],
  ["facebook", "Facebook"], ["whatsapp", "WhatsApp"], ["icicibank", "ICICI Bank"], ["hdfcbank", "HDFC Bank"],
  ["axisbank", "Axis Bank"], ["onlinesbi", "State Bank of India"], ["linkedin", "LinkedIn"], ["coinbase", "Coinbase"],
  ["binance", "Binance"], ["metamask", "MetaMask"], ["outlook", "Microsoft"], ["icloud", "Apple"], ["apple", "Apple"],
  ["wellsfargo", "Wells Fargo"], ["irctc", "IRCTC"], ["dropbox", "Dropbox"], ["github", "GitHub"],
].map(([label, brand]) => ({ label, brand }));

const SENSITIVE_KEYWORDS = [
  "login", "log-in", "signin", "sign-in", "verify", "verification", "validate", "update", "secure", "security",
  "account", "kyc", "wallet", "password", "passwd", "otp", "unlock", "suspend", "suspended", "confirm", "billing",
  "refund", "reward", "prize", "claim", "lottery", "bonus", "gift", "invoice", "recover", "authenticate", "auth",
  "banking", "netbanking", "credential", "webscr", "seed", "airdrop", "redeem", "blocked", "expire", "pan-card",
];

export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly", "tiny.cc", "shorturl.at",
  "rebrand.ly", "s.id", "v.gd", "t.ly", "bl.ink", "short.io", "tiny.one", "shorte.st", "adf.ly", "bitly.com",
  "lnkd.in", "qrco.de", "qr.link", "tinyurl.is", "clck.ru", "u.to", "urlz.fr", "bit.do", "surl.li", "shorturl.asia",
]);

const RISKY_TLDS = new Set([
  "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "rest", "loan", "men",
  "cam", "sbs", "cfd", "icu", "buzz", "monster", "quest", "bond", "cyou", "lol", "mom", "beauty", "hair", "skin",
  "makeup", "autos", "boats", "yachts", "support", "help", "live", "fit", "gdn", "win", "bid", "review", "date",
  "download", "racing", "stream", "trade", "party", "science", "accountant", "faith", "cricket", "su", "cc", "ws",
  "pw", "rest", "today", "vip", "lat", "best", "cyou", "info", "online", "site", "website", "space", "fun", "store",
]);
// The most abused ones carry more weight than "cheap but common" ones like .online/.site/.store/.info.
const HIGH_ABUSE_TLDS = new Set(["zip", "mov", "tk", "ml", "ga", "cf", "gq", "sbs", "cfd", "icu", "cyou", "bond", "buzz", "monster", "quest", "lat", "gdn", "su", "top", "xyz"]);

const TUNNEL_HOSTS = ["ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "zapto.org", "sytes.net", "freeddns.org", "localtunnel.me", "pagekite.me", "serveousercontent.com"];
const FREE_HOSTS = ["000webhostapp.com", "weebly.com", "wixsite.com", "glitch.me", "repl.co", "replit.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "vercel.app", "netlify.app", "github.io", "blogspot.com", "godaddysites.com", "square.site", "webflow.io", "framer.app", "gitbook.io", "herokuapp.com", "onrender.com", "r2.dev", "ipfs.io", "surge.sh", "wordpress.com", "carrd.co", "mystrikingly.com", "yolasite.com", "jimdosite.com", "sitey.me", "ukit.me"];

const EXEC_EXT = /\.(apk|xapk|apks|aab|exe|msi|scr|bat|cmd|pif|jar|vbs|vbe|jse|wsf|ps1|hta|dmg|pkg|ipa|deb|lnk)$/i;

function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}

function deHomoglyph(s: string): string {
  return s
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/0/g, "o")
    .replace(/[1!|]/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b")
    .replace(/\$/g, "s");
}

function endsWithDomain(host: string, domain: string) {
  return host === domain || host.endsWith("." + domain);
}

export function isOfficialBrandDomain(host: string): Brand | null {
  const p = parse(host);
  for (const b of BRANDS) {
    if (b.official.some((d) => endsWithDomain(host, d))) return b;
    if (b.officialSuffixes?.some((s) => p.publicSuffix === s || endsWithDomain(host, s))) {
      // e.g. *.sbi or <bank>.bank.in — regulated / brand-owned zones
      if (p.publicSuffix === "bank.in" || host.endsWith(".bank.in")) {
        if (b.tokens.some((t) => (p.domainWithoutSuffix ?? "").includes(t))) return b;
        continue;
      }
      return b;
    }
    if (b.anyCcTld && p.domainWithoutSuffix && b.tokens.includes(p.domainWithoutSuffix) && (p.publicSuffix?.length ?? 9) <= 6 && /^(co\.|com\.)?[a-z]{2}$|^com$/.test(p.publicSuffix ?? "")) return b;
  }
  return null;
}

/** Any well-known brand / big platform the host belongs to (used to suppress weak signals). */
export function trustedPlatform(host: string): string | null {
  const b = isOfficialBrandDomain(host);
  return b ? b.name : null;
}

export function tokenize(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function keywordHits(text: string): string[] {
  const t = text.toLowerCase();
  return SENSITIVE_KEYWORDS.filter((k) => new RegExp(`(^|[^a-z])${k.replace(/-/g, "\\-")}`, "i").test(t));
}

/** Detects which brands a piece of text (host, path, page title) claims to be. `whole` = exact token match. */
export function claimedBrands(text: string, opts: { allowSubstring: boolean; keywordPresent: boolean }): { brand: Brand; whole: boolean }[] {
  const toks = tokenize(text);
  const joined = toks.join(" ");
  const out: { brand: Brand; whole: boolean }[] = [];
  for (const b of BRANDS) {
    if (b.strict && !opts.keywordPresent) continue;
    if (b.tokens.some((t) => toks.includes(t))) out.push({ brand: b, whole: true });
    else if (opts.allowSubstring && b.tokens.some((t) => t.length >= 5 && joined.includes(t))) out.push({ brand: b, whole: false });
  }
  return out;
}

export function analyzeUrlStatic(raw: string, role: "original" | "final" = "original"): Finding[] {
  const out: Finding[] = [];
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return [finding("malformed-url", "medium", 20, "Malformed link", "The link could not be parsed as a valid URL.")];
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const p = parse(host);
  const registered = p.domain ?? host;
  const label = p.domainWithoutSuffix ?? "";
  const subdomain = p.subdomain ?? "";
  const official = isOfficialBrandDomain(host);
  const pathAndQuery = decodeURIComponentSafe(url.pathname + url.search);
  const kw = keywordHits(`${subdomain} ${label} ${pathAndQuery}`);
  const tag = role === "final" ? " (destination)" : "";

  if (p.isIp) {
    out.push(finding("ip-host", "high", 30, `Uses a raw IP address${tag}`, `The link points to ${host} instead of a domain name. Legitimate services almost never ask you to visit a bare IP address.`));
  } else if (!p.isIcann && !p.publicSuffix) {
    out.push(finding("unknown-tld", "medium", 20, "Unrecognised domain ending", `"${host}" does not use a recognised public domain extension.`));
  }

  if (url.username || url.password) {
    out.push(finding("userinfo", "high", 30, "Hidden real destination (@ trick)", `Text before "@" in the address is ignored by browsers. This link actually opens ${host}.`));
  }

  if (/(^|\.)xn--/.test(host)) {
    const uni = domainToUnicode(host);
    const inRegistered = /(^|\.)xn--/.test(registered);
    out.push(finding("punycode", "high", inRegistered ? 30 : 15, "Look-alike characters (punycode domain)", `The domain renders as "${uni}" but is really "${host}". Attackers use foreign characters that look like Latin letters to imitate trusted sites.`));
  }

  // Brand impersonation: brand name appears in host but domain is not the brand's.
  if (!official && !p.isIp) {
    const claims = claimedBrands(`${subdomain}.${label}`, { allowSubstring: true, keywordPresent: kw.length > 0 });
    if (claims.length) {
      const names = [...new Set(claims.map((c) => c.brand.name))].join(", ");
      const strong = claims.some((c) => c.whole) || kw.length > 0;
      out.push(
        finding(
          "brand-impersonation",
          strong ? "high" : "medium",
          strong ? 40 : 20,
          `${strong ? "Impersonates" : "Mentions"} ${names}${tag}`,
          `The address contains "${names}" but the site is ${registered}, which is not an official ${names} domain.${strong ? " This is the most common phishing pattern." : ""}`,
        ),
      );
    } else {
      // typosquat on the registered label
      const flat = label.replace(/-/g, "");
      const ascii = deHomoglyph(flat);
      for (const t of TYPO_TARGETS) {
        if (flat === t.label) continue; // exact label on a different TLD handled by official check / brand claim above
        if (ascii === t.label || (t.label.length >= 5 && flat.length >= 5 && levenshtein(flat, t.label) === 1)) {
          out.push(finding("typosquat", "high", 40, `Look-alike of ${t.brand}${tag}`, `"${registered}" is one character away from ${t.brand}'s real domain — a typosquatting trick.`));
          break;
        }
      }
      // brand name in path combined with credential keywords
      const pathClaims = claimedBrands(pathAndQuery, { allowSubstring: false, keywordPresent: kw.length > 0 });
      if (pathClaims.length && kw.length) {
        const bn = pathClaims[0].brand.name;
        out.push(finding("brand-in-path", "medium", 20, `Mentions ${bn} on an unrelated site`, `The page path references ${bn} together with "${kw[0]}", but it is hosted on ${registered}.`));
      }
    }
  }

  if (p.publicSuffix && RISKY_TLDS.has(p.publicSuffix.split(".").pop()!) && !official) {
    const tld = p.publicSuffix.split(".").pop()!;
    const high = HIGH_ABUSE_TLDS.has(tld);
    out.push(finding("risky-tld", high ? "medium" : "low", high ? 15 : 5, `High-abuse domain extension (.${tld})`, `.${tld} domains are cheap and disproportionately used for phishing and scams.`));
  }

  if (SHORTENERS.has(registered) || SHORTENERS.has(host)) {
    out.push(finding("shortener", "low", 5, "Shortened link", `${host} is a URL shortener that hides the real destination. QRShield followed it to check where it really goes.`));
  }

  if (TUNNEL_HOSTS.some((d) => endsWithDomain(host, d))) {
    out.push(finding("tunnel-host", "high", 25, "Temporary tunnel / dynamic DNS host", `${registered} provides throw-away public URLs for any computer. Scam pages often use them to avoid takedowns.`));
  } else if (FREE_HOSTS.some((d) => endsWithDomain(host, d)) && kw.length) {
    out.push(finding("free-host", "low", 10, "Free hosting with sensitive wording", `Hosted on a free site builder (${registered}) and uses words like "${kw[0]}".`));
  }

  if (!official && kw.length) {
    const w = Math.min(15, kw.length * 5);
    out.push(finding("keywords", w >= 10 ? "low" : "info", w, "Credential / urgency wording", `The address contains ${kw.slice(0, 4).map((k) => `"${k}"`).join(", ")} — wording typical of fake login, KYC and reward pages.`));
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    out.push(finding("odd-port", "low", 10, `Unusual port :${url.port}`, "Normal websites use the default web ports. Custom ports are common on improvised scam servers."));
  }

  if (subdomain.split(".").filter(Boolean).length >= 4) {
    out.push(finding("deep-subdomains", "low", 10, "Excessive subdomains", `"${host}" stacks many subdomains, often to push a trusted-looking name to the front.`));
  }
  if (host.length > 50) out.push(finding("long-host", "low", 5, "Very long hostname", `The hostname is ${host.length} characters long.`));
  const hyphens = (label.match(/-/g) ?? []).length;
  if (hyphens >= 3 && !official) out.push(finding("hyphens", "low", 10, "Many hyphens in domain", `"${registered}" uses ${hyphens} hyphens, typical of generated scam domains like secure-login-verify-account.`));

  const fileName = url.pathname.split("/").pop() ?? "";
  if (EXEC_EXT.test(fileName)) {
    const ext = fileName.split(".").pop()!.toLowerCase();
    const isApk = /^(apk|xapk|apks|aab)$/.test(ext);
    out.push(finding("exec-download", "high", isApk ? 45 : 40, isApk ? "Downloads an Android app (APK)" : `Downloads an executable file (.${ext})`, isApk ? "Installing APKs from QR codes is a leading cause of banking-trojan and remote-access fraud. Only install apps from the Play Store." : "Executable files from QR codes can install malware on your device."));
  }

  const emailInQuery = /[?&][^=]*=([^&]*%40|[^&]*@)[^&]+\.[a-z]{2,}/i.test(url.search);
  const b64Email = (() => {
    const frag = url.hash.slice(1);
    if (frag.length < 8 || !/^[A-Za-z0-9+/=_-]+$/.test(frag)) return false;
    try {
      return /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(Buffer.from(frag, "base64").toString("utf8"));
    } catch {
      return false;
    }
  })();
  if ((emailInQuery || b64Email) && !official) {
    out.push(finding("prefilled-email", "medium", 15, "Pre-filled email address", "The link carries an email address, a hallmark of targeted credential-phishing pages that pre-fill the victim's login."));
  }

  if ((url.pathname.match(/%[0-9a-f]{2}/gi) ?? []).length > 12) {
    out.push(finding("encoded-path", "low", 10, "Heavily encoded address", "Large amounts of percent-encoding are used to hide what a link really contains."));
  }
  if (raw.length > 300) out.push(finding("long-url", "info", 0, "Very long link", `The link is ${raw.length} characters long.`));

  return out;
}

function decodeURIComponentSafe(s: string) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
