/**
 * Mail transport security and brand records: MTA-STS (RFC 8461), SMTP TLS
 * Reporting (RFC 8460) and BIMI (the brand-indicators draft). Parsing and
 * checks are pure; report.ts does the lookups.
 */
import { issue, type Issue } from "./issue.js";

/** Tag=value pairs of a TXT record such as "v=STSv1; id=abc". */
export function tags(record: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    if (key !== "" && !(key in out)) out[key] = part.slice(eq + 1).trim();
  }
  return out;
}

export interface MtaStsRecord {
  raw: string;
  id?: string;
}

/** The `_mta-sts` TXT record (RFC 8461, section 3.1). */
export function evaluateMtaStsTxt(txt: string[]): { record?: MtaStsRecord; issues: Issue[] } {
  const records = txt.filter((t) => /^v=STSv1(\s*;|$)/.test(t.trim()));
  if (records.length === 0) return { issues: [] };
  const issues: Issue[] = [];
  if (records.length > 1) {
    issues.push(issue("error", "mta-sts", `${records.length} _mta-sts records published; senders must ignore them all (RFC 8461 3.1)`));
  }
  const raw = records[0]!;
  const id = tags(raw).id;
  if (!id) issues.push(issue("error", "mta-sts", "the _mta-sts record has no id= (senders cannot tell when the policy changes)"));
  else if (!/^[A-Za-z0-9]{1,32}$/.test(id)) issues.push(issue("error", "mta-sts", `id "${id}" must be 1-32 letters and digits (RFC 8461 3.1)`));
  return { record: { raw, ...(id ? { id } : {}) }, issues };
}

export interface MtaStsPolicy {
  mode?: string;
  mx: string[];
  maxAge?: number;
}

/** Parse the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt (RFC 8461, 3.2). */
export function parseMtaStsPolicy(text: string): { policy: MtaStsPolicy; issues: Issue[] } {
  const issues: Issue[] = [];
  const policy: MtaStsPolicy = { mx: [] };
  let version: string | undefined;
  for (const line of text.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "version") version = value;
    else if (key === "mode") policy.mode = value;
    else if (key === "mx") policy.mx.push(value.toLowerCase());
    else if (key === "max_age") policy.maxAge = /^\d{1,10}$/.test(value) ? Number(value) : NaN;
  }
  if (version !== "STSv1") issues.push(issue("error", "mta-sts", 'the policy has no "version: STSv1"'));
  if (!["enforce", "testing", "none"].includes(policy.mode ?? "")) {
    issues.push(issue("error", "mta-sts", `policy mode must be enforce, testing or none (got "${policy.mode ?? ""}")`));
  } else if (policy.mode === "testing") {
    issues.push(issue("info", "mta-sts", "policy mode is testing: failures are reported (TLS-RPT) but mail is still delivered"));
  } else if (policy.mode === "none") {
    issues.push(issue("warning", "mta-sts", "policy mode is none: MTA-STS is switched off for this domain"));
  }
  if (policy.maxAge === undefined || !Number.isFinite(policy.maxAge)) {
    issues.push(issue("error", "mta-sts", "the policy needs max_age (seconds)"));
  } else if (policy.maxAge > 31557600) {
    issues.push(issue("error", "mta-sts", `max_age ${policy.maxAge} is above the maximum 31557600 (RFC 8461 3.2)`));
  } else if (policy.maxAge < 86400) {
    issues.push(issue("info", "mta-sts", `max_age ${policy.maxAge} is under a day; RFC 8461 suggests weeks or more`));
  }
  if (policy.mode !== "none" && policy.mx.length === 0) {
    issues.push(issue("error", "mta-sts", "the policy lists no mx: patterns"));
  }
  return { policy, issues };
}

/** Whether an MX host matches a policy pattern (an exact name or a "*." wildcard for one label). */
export function mxMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const p = pattern.toLowerCase().replace(/\.$/, "");
  if (p.startsWith("*.")) {
    const rest = p.slice(2);
    return h.endsWith(`.${rest}`) && !h.slice(0, -rest.length - 1).includes(".");
  }
  return h === p;
}

/** MX hosts the policy does not cover: in enforce mode, mail to them would fail. */
export function uncoveredMx(mxHosts: string[], policy: MtaStsPolicy): string[] {
  return mxHosts.filter((h) => !policy.mx.some((p) => mxMatches(h, p)));
}

export interface TlsRptRecord {
  raw: string;
  rua: string[];
}

/** The `_smtp._tls` TXT record (RFC 8460, section 3). */
export function evaluateTlsRpt(txt: string[]): { record?: TlsRptRecord; issues: Issue[] } {
  const records = txt.filter((t) => /^v=TLSRPTv1(\s*;|$)/.test(t.trim()));
  if (records.length === 0) return { issues: [] };
  const issues: Issue[] = [];
  if (records.length > 1) issues.push(issue("error", "tls-rpt", `${records.length} _smtp._tls records published; only one is allowed`));
  const raw = records[0]!;
  const rua = (tags(raw).rua ?? "").split(",").map((r) => r.trim()).filter((r) => r !== "");
  if (rua.length === 0) issues.push(issue("error", "tls-rpt", "the TLS-RPT record has no rua= (where reports go)"));
  for (const r of rua) {
    if (!/^(mailto:\S+@\S+|https:\/\/\S+)$/i.test(r)) {
      issues.push(issue("error", "tls-rpt", `rua "${r}" must be a mailto: or https: URI`));
    }
  }
  return { record: { raw, rua }, issues };
}

export interface BimiRecord {
  raw: string;
  logo?: string;
  authority?: string;
}

/**
 * The `default._bimi` TXT record (draft-brand-indicators-for-message-
 * identification): a logo URL (l=, an SVG over HTTPS) and optionally a mark
 * certificate (a=). Mailbox providers show the logo only for mail that
 * passes DMARC under an enforcing policy, so the DMARC policy is checked too.
 */
export function evaluateBimi(
  txt: string[],
  dmarc: { policy?: string; pct?: string } | undefined,
): { record?: BimiRecord; issues: Issue[] } {
  const records = txt.filter((t) => /^v=BIMI1(\s*;|$)/i.test(t.trim()));
  if (records.length === 0) return { issues: [] };
  const issues: Issue[] = [];
  const raw = records[0]!;
  const t = tags(raw);
  const logo = t.l || undefined;
  const authority = t.a || undefined;
  if (logo !== undefined && !/^https:\/\/\S+\.svg(\?\S*)?$/i.test(logo)) {
    issues.push(issue("warning", "bimi", `l= "${logo}" should be an https:// URL of an SVG logo`));
  }
  if (logo === undefined && authority === undefined) {
    issues.push(issue("info", "bimi", "the BIMI record has neither l= nor a=: it declines BIMI for this domain"));
  }
  if (authority === undefined && logo !== undefined) {
    issues.push(issue("info", "bimi", "no a= mark certificate; some mailbox providers show a logo only with one (a VMC or CMC)"));
  }
  const policy = dmarc?.policy?.toLowerCase();
  const pct = dmarc?.pct === undefined ? 100 : Number(dmarc.pct);
  if (policy !== "quarantine" && policy !== "reject") {
    issues.push(issue("error", "bimi", "BIMI needs DMARC at p=quarantine or p=reject; with p=none the logo is not shown"));
  } else if (pct < 100) {
    issues.push(issue("warning", "bimi", `DMARC pct=${pct}: BIMI expects the policy to apply to all mail (pct=100)`));
  }
  return { record: { raw, ...(logo ? { logo } : {}), ...(authority ? { authority } : {}) }, issues };
}
