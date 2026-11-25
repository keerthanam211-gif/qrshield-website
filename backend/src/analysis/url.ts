import { parse } from "tldts";
import { analyzeUrlStatic, claimedBrands, isOfficialBrandDomain, SHORTENERS } from "./heuristics.ts";
import { checkThreatIntel, type IntelResult } from "./intel.ts";
import { lookupDomainAge, type DomainAge } from "./rdap.ts";
import { traceRedirects, type TraceResult } from "./safe-fetch.ts";
import { dedupeFindings, finding, type Finding } from "./types.ts";

export interface UrlAnalysis {
  url: string;
  finalUrl: string;
  findings: Finding[];
  confirmedMalicious: boolean;
  verified: boolean;
  unverifiedReason: string | null;
  intel: IntelResult;
  trace: TraceResult;
  domainAge: DomainAge | null;
  finalDomainAge: DomainAge | null;
}

const TLS_ERROR = /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|HOSTNAME/i;

function regDomain(u: string): string | null {
  try {
    const h = new URL(u).hostname;
    const p = parse(h);
    return p.isIp ? h : p.domain ?? h;
  } catch {
    return null;
  }
}

function ageFindings(age: DomainAge | null, host: string): Finding[] {
  if (!age || age.ageDays == null || isOfficialBrandDomain(host)) return [];
  const d = age.ageDays;
  const when = age.registeredAt ? new Date(age.registeredAt).toISOString().slice(0, 10) : "recently";
  if (d <= 14) return [finding("new-domain", "high", 40, `Domain registered ${d} day${d === 1 ? "" : "s"} ago`, `${age.domain} was registered on ${when}. Most phishing domains are used within days of registration.`)];
  if (d <= 60) return [finding("new-domain", "medium", 25, `Domain is only ${d} days old`, `${age.domain} was registered on ${when}. Very new domains deserve extra caution.`)];
  if (d <= 180) return [finding("new-domain", "low", 10, `Domain is ${Math.round(d / 30)} months old`, `${age.domain} was registered on ${when}.`)];
  return [];
}

export async function analyzeUrl(input: string, opts: { traceBudgetMs?: number } = {}): Promise<UrlAnalysis> {
  const url = new URL(input).href;
  const host = new URL(url).hostname.toLowerCase();
  const p = parse(host);
  const findings: Finding[] = analyzeUrlStatic(url, "original");

  const [trace, domainAge] = await Promise.all([
    traceRedirects(url, { budgetMs: opts.traceBudgetMs ?? 9000 }),
    p.domain && !p.isIp ? lookupDomainAge(p.domain) : Promise.resolve(null),
  ]);

  const chain = [url, ...trace.hops.map((h) => h.url), trace.finalUrl].filter((u) => /^https?:/i.test(u));
  const finalUrl = trace.finalUrl;
  let finalHost = host;
  try {
    finalHost = new URL(finalUrl).hostname.toLowerCase();
  } catch {
    /* keep */
  }
  const origReg = regDomain(url);
  const finalReg = regDomain(finalUrl);
  const crossDomain = !!finalReg && finalReg !== origReg;
  const finalParse = parse(finalHost);

  const [intel, finalDomainAge] = await Promise.all([
    checkThreatIntel(chain),
    crossDomain && finalParse.domain && !finalParse.isIp ? lookupDomainAge(finalParse.domain) : Promise.resolve(null),
  ]);

  // Threat-intel matches => confirmed malicious
  for (const c of intel.checks) {
    if (c.status !== "match") continue;
    for (const m of c.matches ?? []) {
      const isDest = m.url !== url;
      findings.push(finding(`intel-${c.source}-${m.url}`, "critical", 60, `${c.source}: ${m.threat}`, `${isDest ? "A redirect destination" : "This link"} (${m.url}) is flagged by ${c.source} — ${m.threat.toLowerCase()}.`));
    }
  }

  if (crossDomain) findings.push(...analyzeUrlStatic(finalUrl, "final").map((f) => ({ ...f, id: `final-${f.id}` })));

  // Redirect behaviour
  const redirects = trace.hops.length - 1;
  const origIsShortener = !!origReg && (SHORTENERS.has(origReg) || SHORTENERS.has(host));
  const finalOfficial = isOfficialBrandDomain(finalHost);
  if (redirects >= 4) findings.push(finding("long-chain", "medium", 15, `${redirects} redirects before the destination`, "Long redirect chains are used to launder malicious destinations through innocent-looking links."));
  if (crossDomain && redirects > 0) {
    if (origIsShortener || finalOfficial || isOfficialBrandDomain(host)) {
      findings.push(finding("redirect-dest", "info", 0, `Opens ${finalReg}`, `The link redirects to ${finalHost}.`));
    } else {
      findings.push(finding("cross-redirect", "low", 10, "Redirects to a different website", `The link starts at ${origReg} but sends you to ${finalReg}.`));
    }
  }
  if (trace.hops.some((h) => h.via === "meta-refresh" || h.via === "javascript")) {
    findings.push(finding("client-redirect", "medium", 10, "Hidden in-page redirect", "The page silently forwards you using a meta-refresh or script — a technique used to evade link scanners."));
  }
  if (trace.nonWebRedirect) {
    findings.push(finding("app-redirect", "medium", 20, `Redirects into an app link (${trace.nonWebRedirect})`, "After loading, the link tries to open an app or install handler directly."));
  }
  if (trace.stopReason === "Redirect loop detected" || /More than \d+ redirects/.test(trace.stopReason ?? "")) {
    findings.push(finding("redirect-loop", "medium", 15, "Abnormal redirect behaviour", trace.stopReason!));
  }

  const lastHop = trace.hops[trace.hops.length - 1];
  let unverifiedReason: string | null = null;
  if (lastHop?.errorCode === "EBLOCKED") {
    findings.push(finding("private-target", "high", 30, "Points to a private / local network", "The link targets an internal network address (router, intranet or localhost). Public QR codes have no reason to do this."));
  } else if (lastHop?.errorCode === "ENOTFOUND") {
    findings.push(finding("dns-fail", "medium", 20, "Domain does not resolve", `${new URL(lastHop.url).hostname} has no DNS record — it may be a taken-down scam domain or a typo.`));
  } else if (lastHop?.error && TLS_ERROR.test(`${lastHop.errorCode} ${lastHop.error}`)) {
    findings.push(finding("tls-error", "high", 25, "Invalid HTTPS certificate", `The site's security certificate is not valid (${lastHop.errorCode}). Your connection to it cannot be trusted.`));
  } else if (lastHop?.error && lastHop.errorCode !== "EPORT") {
    findings.push(finding("unreachable", "info", 0, "Site could not be loaded", `QRShield could not reach ${lastHop.url} (${lastHop.error}). Threat-intelligence checks still ran on the address.`));
    if (redirects > 0 || origIsShortener) unverifiedReason = "The final destination of the redirect chain could not be reached, so it could not be fully verified.";
  } else if (!trace.completed && trace.stopReason?.includes("timed out")) {
    unverifiedReason = "Redirect tracing timed out before reaching the final destination.";
  }

  // Destination page signals
  if (trace.completed) {
    const fu = new URL(finalUrl);
    if (fu.protocol === "http:") findings.push(finding("no-tls", "low", 10, "Not encrypted (HTTP)", "The destination does not use HTTPS, so anything you type can be intercepted."));
    const page = trace.page;
    if (page?.isDownload) {
      const apk = /APK/.test(page.downloadType ?? "");
      findings.push(finding("exec-download", "high", apk ? 45 : 35, `Starts a download: ${page.downloadType}`, apk ? "The link downloads an Android app outside the Play Store — the #1 delivery method for banking trojans in QR scams." : "The link immediately downloads a file instead of opening a web page."));
    }
    if (page?.hasPasswordField && fu.protocol === "http:") {
      findings.push(finding("password-http", "high", 25, "Asks for a password over HTTP", "The page has a password field but no encryption."));
    }
    if (page?.title && !finalOfficial) {
      const kwInTitle = /login|log in|sign in|verify|account|kyc|bank|wallet|password|secure|update|otp/i.test(page.title);
      const claims = claimedBrands(page.title, { allowSubstring: false, keywordPresent: kwInTitle || page.hasPasswordField });
      if (claims.length) {
        const bn = claims[0].brand.name;
        const strong = page.hasPasswordField || kwInTitle;
        findings.push(finding("page-brand", strong ? "high" : "low", strong ? 35 : 5, strong ? `Page poses as ${bn}` : `Page mentions ${bn}`, `The page title is "${page.title}" but it is hosted on ${finalReg}, not an official ${bn} domain.${page.hasPasswordField ? " It also asks for a password." : ""}`));
      }
    }
    if (page?.hasPasswordField && !finalOfficial) {
      findings.push(finding("password-field", "info", 0, "Page contains a login form", "Never enter passwords or OTPs on a page opened from a QR code unless you are sure of the site."));
    }
  }

  findings.push(...ageFindings(domainAge, host));
  if (crossDomain) findings.push(...ageFindings(finalDomainAge, finalHost).map((f) => ({ ...f, id: `final-${f.id}` })));

  if (!intel.verified) unverifiedReason = "Threat-intelligence services could not be reached, so this link could not be verified.";

  return {
    url,
    finalUrl,
    findings: dedupeFindings(findings),
    confirmedMalicious: intel.matched,
    verified: intel.verified && !unverifiedReason,
    unverifiedReason,
    intel,
    trace,
    domainAge,
    finalDomainAge,
  };
}
