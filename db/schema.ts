/**
 * Scan record shape. Each record is one QR / link check performed by QRShield.
 * `clientId` is an anonymous per-browser identifier so each visitor sees only their own history.
 */
export interface ScanRow {
  id: string;
  clientId: string;
  source: string; // camera | upload | manual
  content: string; // raw decoded QR payload / user input
  contentType: string; // url | upi | wifi | text | tel | sms | email | ...
  target: string | null; // primary URL / VPA that was analysed
  finalUrl: string | null; // where redirects ended
  verdict: string; // SAFE | SUSPICIOUS | DANGEROUS | UNVERIFIED
  riskScore: number;
  summary: string;
  reasons: unknown;
  details: unknown;
  createdAt: Date;
}

export type NewScanRow = Omit<ScanRow, "id" | "createdAt"> & { id?: string; createdAt?: Date };
