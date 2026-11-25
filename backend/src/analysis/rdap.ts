/** Domain registration age via RDAP (the IANA-standard successor to WHOIS), using the rdap.org bootstrap. */
const cache = new Map<string, { at: number; value: DomainAge }>();
const TTL = 12 * 60 * 60 * 1000;

export interface DomainAge {
  domain: string;
  registeredAt: string | null;
  ageDays: number | null;
  registrar: string | null;
  error: string | null;
}

export async function lookupDomainAge(domain: string): Promise<DomainAge> {
  const hit = cache.get(domain);
  if (hit && Date.now() - hit.at < TTL) return hit.value;
  let value: DomainAge;
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      redirect: "follow",
      signal: AbortSignal.timeout(4500),
      headers: { Accept: "application/rdap+json, application/json", "User-Agent": "QRShield/2.0 (+domain-age-check)" },
    });
    if (!res.ok) throw new Error(res.status === 404 ? "No RDAP record for this domain/TLD" : `RDAP HTTP ${res.status}`);
    const json = (await res.json()) as {
      events?: { eventAction: string; eventDate: string }[];
      entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, string][]] }[];
    };
    const reg = json.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null;
    const registrarEntity = json.entities?.find((e) => e.roles?.includes("registrar"));
    const registrar = registrarEntity?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] ?? null;
    const ageDays = reg ? Math.floor((Date.now() - new Date(reg).getTime()) / 86_400_000) : null;
    value = { domain, registeredAt: reg, ageDays, registrar: typeof registrar === "string" ? registrar : null, error: reg ? null : "Registration date not published" };
  } catch (e) {
    value = { domain, registeredAt: null, ageDays: null, registrar: null, error: (e as Error).message };
  }
  cache.set(domain, { at: Date.now(), value });
  return value;
}
