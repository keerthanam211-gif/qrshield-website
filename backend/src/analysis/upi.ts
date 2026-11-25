/**
 * UPI payment-QR fraud analysis (NPCI "upi://pay" deep-link spec).
 * Designed to avoid false alarms: a normal merchant or person-to-person QR (valid VPA, INR, sensible note)
 * produces no warnings. Only real scam patterns raise the score.
 */
import { finding, type Finding } from "./types.ts";

/** PSP / bank handles issued under NPCI UPI (not exhaustive; unknown handles only add an informational note). */
const KNOWN_HANDLES = new Set(
  (
    "okaxis okhdfcbank okicici oksbi ybl ibl axl paytm ptyes ptaxis pthdfc ptsbi upi apl yapl rapl abfspay axisbank axisb " +
    "icici icicibank hdfcbank hdfcbankjd sbi kotak kbl kmbl mahb barodampay pnb boi cnrb idfcbank idfcfirst indus federal fbl " +
    "fifederal aubank yesbank yesbankltd yesb jio jiopay freecharge mobikwik ikwik airtel airtelpay mairtel naviaxis superyes " +
    "sliceaxis fam waaxis wahdfcbank wasbi waicici dbs hsbc sc citi citigold rbl uco unionbank uboi unionbankofindia centralbank cbin " +
    "indianbank indbank iob psb equitas esaf ujjivan dlb kvb kaypay tjsb postbank ippb razorpay rzp pinelabs eazypay bandhan " +
    "goaxb axisbiz timecosmos pingpay oneyes tapicici yescred amazonpay kbl ikwik cub dcb jkb jsb nsdl saraswat svc karnatakabank " +
    "csbpay csb idbi aubankltd bob barodapay ezeepay hsbcbank jupiteraxis okbizaxis paytmbank pockets purz shriramhdfcbank " +
    "tmb utbi vijb ratn imobile icicipay mypsb kotak811 fbpe nsdlbank gpay apb airtelpaymentsbank"
  ).split(/\s+/),
);

const RECEIVE_SCAM = /\b(refund|cash ?back|prize|lotter(y|ies)|lucky ?draw|reward|winner|winning|you (have )?won|claim|jackpot|bonus|receive|recieve|credited to you|get money|money back|kbc|scratch ?card)\b/i;
const IMPERSONATION_SCAM = /\b(kyc|re-?kyc|otp|verification|verify|customer ?care|help ?line|support team|account (block|suspend)|electricity (bill|disconnect)|pan ?card|aadhaar update|income ?tax refund|cyber ?cell|challan penalty)\b/i;
const VPA_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,255}@[a-zA-Z][a-zA-Z0-9.]{1,63}$/;
const VPA_SCAM_WORDS = /(refund|cashback|reward|lottery|prize|kyc|helpline|customercare|custcare|support|claim|bonus|winner|gift)/i;

const MCC_NOTES: Record<string, { w: number; label: string }> = {
  "7995": { w: 15, label: "betting / gambling" },
  "7800": { w: 10, label: "government lottery" },
  "7801": { w: 10, label: "online gambling" },
  "7802": { w: 10, label: "horse/dog racing" },
  "6051": { w: 10, label: "quasi-cash / crypto" },
  "6540": { w: 10, label: "stored-value / wallet load" },
  "4829": { w: 10, label: "money transfer" },
};

export interface UpiDetails {
  scheme: string;
  payeeVpa: string | null;
  payeeName: string | null;
  amount: string | null;
  currency: string | null;
  note: string | null;
  merchantCode: string | null;
  transactionRef: string | null;
  handle: string | null;
  handleKnown: boolean | null;
  isMerchant: boolean;
  url: string | null;
  params: Record<string, string>;
}

export function parseUpi(raw: string): { details: UpiDetails; duplicates: string[] } {
  const m = raw.trim().match(/^upi:\/\/([a-z]+)\/?\??(.*)$/i);
  const scheme = (m?.[1] ?? "").toLowerCase();
  const query = m?.[2] ?? "";
  const params: Record<string, string> = {};
  const counts: Record<string, number> = {};
  for (const part of query.split("&")) {
    if (!part) continue;
    const idx = part.indexOf("=");
    const k = decodeSafe(idx === -1 ? part : part.slice(0, idx)).toLowerCase();
    const v = idx === -1 ? "" : decodeSafe(part.slice(idx + 1).replace(/\+/g, " "));
    counts[k] = (counts[k] ?? 0) + 1;
    if (!(k in params)) params[k] = v.trim();
  }
  const pa = params.pa || null;
  const handle = pa?.includes("@") ? pa.split("@").pop()!.toLowerCase() : null;
  return {
    details: {
      scheme,
      payeeVpa: pa,
      payeeName: params.pn || null,
      amount: params.am || null,
      currency: params.cu || null,
      note: params.tn || null,
      merchantCode: params.mc || null,
      transactionRef: params.tr || null,
      handle,
      handleKnown: handle ? KNOWN_HANDLES.has(handle) : null,
      isMerchant: !!params.mc && params.mc !== "0000",
      url: params.url || null,
      params,
    },
    duplicates: Object.keys(counts).filter((k) => counts[k] > 1 && ["pa", "pn", "am", "cu", "url"].includes(k)),
  };
}

function decodeSafe(s: string) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function analyzeUpi(raw: string): { details: UpiDetails; findings: Finding[] } {
  const { details: d, duplicates } = parseUpi(raw);
  const f: Finding[] = [];

  if (d.scheme === "mandate") {
    f.push(finding("upi-mandate", "medium", 15, "AutoPay mandate, not a one-time payment", "This QR sets up recurring automatic debits from your account. Only approve if you knowingly signed up for a subscription with this payee."));
  } else if (d.scheme !== "pay") {
    f.push(finding("upi-scheme", "medium", 20, `Unusual UPI action "${d.scheme || "none"}"`, "Standard payment QR codes use upi://pay. Other actions are rarely used legitimately in printed QR codes."));
  }

  if (!d.payeeVpa) {
    f.push(finding("upi-no-pa", "high", 45, "Missing payee UPI ID", "The payment QR has no payee address (pa=). It is malformed or tampered with."));
  } else if (!VPA_RE.test(d.payeeVpa)) {
    f.push(finding("upi-bad-vpa", "high", 40, "Invalid payee UPI ID", `"${d.payeeVpa}" is not a valid UPI address format.`));
  } else {
    const user = d.payeeVpa.split("@")[0];
    if (VPA_SCAM_WORDS.test(user)) {
      f.push(finding("upi-vpa-bait", "high", 35, "Payee UPI ID uses bait wording", `The UPI ID "${d.payeeVpa}" contains words like "${user.match(VPA_SCAM_WORDS)![0]}". Banks, apps and support desks never collect refunds or rewards through personal UPI IDs.`));
    }
    if (d.handleKnown === false) {
      f.push(finding("upi-handle", "info", 5, `Uncommon UPI handle "@${d.handle}"`, "This bank/app handle is not in QRShield's list of common UPI providers. It may be legitimate but less common — check the payee name your UPI app shows."));
    }
  }

  if (duplicates.length) {
    f.push(finding("upi-dup", "high", 35, "Conflicting payment fields", `The QR repeats ${duplicates.map((k) => `"${k}"`).join(", ")}. Different apps may read different values — a known trick to redirect payments.`));
  }

  const text = `${d.note ?? ""} ${d.payeeName ?? ""}`;
  const rm = text.match(RECEIVE_SCAM);
  if (rm) {
    f.push(finding("upi-receive-scam", "high", 40, `"${rm[0]}" — scanning never RECEIVES money`, "Scanning a UPI QR and entering your PIN always sends money OUT of your account. QR codes promising refunds, cashback, prizes or rewards are a top UPI scam."));
  }
  const im = text.match(IMPERSONATION_SCAM);
  if (im) {
    f.push(finding("upi-impersonation", "high", 35, `Mentions "${im[0]}"`, "Banks, KYC desks, customer care, police and utility companies never ask you to pay by scanning a QR code."));
  }

  if (d.currency && d.currency.toUpperCase() !== "INR") {
    f.push(finding("upi-currency", "high", 30, `Non-INR currency (${d.currency})`, "UPI payments are made in Indian Rupees. A different currency code indicates a malformed or manipulated QR."));
  }

  if (d.amount != null) {
    const amt = Number(d.amount);
    if (!/^\d+(\.\d{1,2})?$/.test(d.amount) || !Number.isFinite(amt) || amt <= 0) {
      f.push(finding("upi-bad-amount", "medium", 30, "Invalid amount", `The pre-filled amount "${d.amount}" is not a valid rupee amount.`));
    } else if (amt >= 100000) {
      f.push(finding("upi-high-amount", "low", 10, `High pre-filled amount (₹${amt.toLocaleString("en-IN")})`, "Double-check this amount before entering your PIN."));
    } else {
      f.push(finding("upi-amount", "info", 0, `Pre-filled amount ₹${amt.toLocaleString("en-IN")}`, "Confirm the amount matches what you expect to pay."));
    }
  }

  if (d.merchantCode && MCC_NOTES[d.merchantCode]) {
    const n = MCC_NOTES[d.merchantCode];
    f.push(finding("upi-mcc", "low", n.w, `Merchant category: ${n.label}`, `Merchant code ${d.merchantCode} is registered as ${n.label}.`));
  }

  if (!d.payeeName) {
    f.push(finding("upi-no-name", "info", 0, "No payee name in QR", "Your UPI app will show the registered name of the payee — make sure it is who you intend to pay."));
  } else {
    f.push(finding("upi-check-name", "info", 0, "Confirm the payee name in your app", `The QR says "${d.payeeName}". Your UPI app shows the bank-registered name before you pay — they should match.`));
  }

  return { details: d, findings: f };
}
