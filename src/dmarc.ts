/** DMARC (RFC 7489) record parsing and linting. Pure. */
import { issue, type Issue } from "./issue.js";

export interface DmarcRecord {
  raw: string;
  /** Parsed tag=value pairs, lowercased tag names. */
  tags: Record<string, string>;
  policy?: string;
  subdomainPolicy?: string;
  issues: Issue[];
}

/** Pick DMARC records out of the _dmarc TXT records. */
export function findDmarcRecords(txtRecords: string[]): string[] {
  return txtRecords.filter((t) => /^v=DMARC1(\s*;|$)/i.test(t.trim()));
}

/** Parse and lint one DMARC record. */
export function parseDmarc(raw: string): DmarcRecord {
  const issues: Issue[] = [];
  const tags: Record<string, string> = {};

  for (const part of raw.split(";")) {
    const kv = part.trim();
    if (kv === "") continue;
    const eq = kv.indexOf("=");
    if (eq === -1) {
      issues.push(issue("warning", "dmarc", `malformed tag "${kv}"`));
      continue;
    }
    tags[kv.slice(0, eq).trim().toLowerCase()] = kv.slice(eq + 1).trim();
  }

  if ((tags.v ?? "").toUpperCase() !== "DMARC1") {
    issues.push(issue("error", "dmarc", 'record must start with "v=DMARC1"'));
  }

  const policy = tags.p?.toLowerCase();
  if (!policy) {
    issues.push(issue("error", "dmarc", 'missing required policy tag "p=" (none | quarantine | reject)'));
  } else if (!["none", "quarantine", "reject"].includes(policy)) {
    issues.push(issue("error", "dmarc", `invalid policy "p=${policy}"`));
  } else if (policy === "none") {
    issues.push(issue("warning", "dmarc", "p=none only monitors: forged mail is still delivered"));
  }

  const sp = tags.sp?.toLowerCase();
  if (sp && !["none", "quarantine", "reject"].includes(sp)) {
    issues.push(issue("error", "dmarc", `invalid subdomain policy "sp=${sp}"`));
  }
  const rank: Record<string, number> = { none: 0, quarantine: 1, reject: 2 };
  if (policy && sp && rank[sp]! < rank[policy]!) {
    issues.push(issue("warning", "dmarc", `subdomains are weaker (sp=${sp}) than the domain (p=${policy})`));
  }

  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      issues.push(issue("error", "dmarc", `invalid pct=${tags.pct}`));
    } else if (pct < 100 && policy !== "none") {
      issues.push(issue("warning", "dmarc", `pct=${pct}: only ${pct}% of failing mail gets the policy`));
    }
  }

  if (!tags.rua) {
    issues.push(issue("warning", "dmarc", 'no "rua=" address: you receive no aggregate reports'));
  } else if (!/^mailto:/i.test(tags.rua)) {
    issues.push(issue("warning", "dmarc", 'rua should be a mailto: URI'));
  }

  for (const align of ["adkim", "aspf"] as const) {
    const v = tags[align]?.toLowerCase();
    if (v && v !== "r" && v !== "s") {
      issues.push(issue("error", "dmarc", `invalid ${align}=${tags[align]} (r or s)`));
    }
  }

  return { raw: raw.trim(), tags, policy, subdomainPolicy: sp, issues };
}

/** Interpret the presence/absence of DMARC records for a domain. */
export function evaluateDmarc(txtRecords: string[] | undefined): { record?: DmarcRecord; issues: Issue[] } {
  if (!txtRecords || txtRecords.length === 0) {
    return { issues: [issue("error", "dmarc", "no DMARC record at _dmarc.<domain>: receivers cannot verify forged mail")] };
  }
  const records = findDmarcRecords(txtRecords);
  if (records.length === 0) {
    return { issues: [issue("error", "dmarc", "_dmarc TXT exists but none starts with v=DMARC1")] };
  }
  const issues: Issue[] = [];
  if (records.length > 1) {
    issues.push(issue("error", "dmarc", `${records.length} DMARC records published (receivers ignore them all)`));
  }
  const record = parseDmarc(records[0]!);
  return { record, issues: [...issues, ...record.issues] };
}

/**
 * Well-known second-level public suffixes, so the fallback walk does not
 * treat e.g. "co.jp" itself as an organizational domain. A pragmatic inline
 * list instead of shipping the full Public Suffix List (zero-dependency).
 */
const SECOND_LEVEL_SUFFIXES = new Set([
  "co.jp",
  "ne.jp",
  "or.jp",
  "ac.jp",
  "go.jp",
  "ad.jp",
  "ed.jp",
  "gr.jp",
  "lg.jp",
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "co.kr",
  "com.cn",
  "com.tw",
]);

/**
 * Parent domains of `domain`, nearest parent first, excluding the domain
 * itself and stopping before the public suffix. The LAST element is the
 * heuristic organizational domain — the only name RFC 7489 receivers query
 * for the DMARC fallback (intermediate parents are never consulted). Without
 * a PSL, the heuristic is: an organizational domain has at least 2 labels,
 * or 3 when it ends in a known second-level suffix such as co.jp or co.uk.
 * Pure.
 */
export function dmarcFallbackDomains(domain: string): string[] {
  const labels = domain.toLowerCase().replace(/\.$/, "").split(".");
  const minLabels = SECOND_LEVEL_SUFFIXES.has(labels.slice(-2).join(".")) ? 3 : 2;
  const parents: string[] = [];
  for (let i = 1; labels.length - i >= minLabels; i++) {
    parents.push(labels.slice(i).join("."));
  }
  return parents;
}
