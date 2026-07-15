/** Assemble the full domain report from DNS answers and the pure analyzers. */
import { dmarcFallbackDomains, evaluateDmarc, findDmarcRecords, type DmarcRecord } from "./dmarc.js";
import { parseDkim, COMMON_SELECTORS, type DkimRecord } from "./dkim.js";
import { findSpfRecords, parseSpf, resolveSpfTree, type SpfRecord, type SpfTree } from "./spf.js";
import { issue, type Issue } from "./issue.js";
import type { DnsClient } from "./dns.js";

export interface Report {
  domain: string;
  spf?: { record: SpfRecord; tree: SpfTree };
  dmarc?: DmarcRecord;
  /**
   * Set when the applied DMARC record was not published at the domain itself
   * but inherited from this parent (RFC 7489 organizational-domain fallback).
   */
  dmarcInheritedFrom?: string;
  dkim: DkimRecord[];
  /** Selectors that were queried (found or not). */
  probedSelectors: string[];
  records: {
    a: string[];
    aaaa: string[];
    mx: { exchange: string; priority: number }[];
    ns: string[];
    caa: string[];
  };
  issues: Issue[];
}

export interface ReportOptions {
  /** DKIM selectors to check; defaults to a common-provider probe list. */
  selectors?: string[];
}

/** Query everything about a domain and run the analyzers. */
export async function buildReport(domain: string, dns: DnsClient, opts: ReportOptions = {}): Promise<Report> {
  const issues: Issue[] = [];

  const [txt, a, aaaa, mx, ns, caa, dmarcTxt] = await Promise.all([
    dns.txt(domain),
    dns.a(domain),
    dns.aaaa(domain),
    dns.mx(domain),
    dns.ns(domain),
    dns.caa(domain),
    dns.txt(`_dmarc.${domain}`),
  ]);

  if (a.length === 0 && aaaa.length === 0 && ns.length === 0 && mx.length === 0 && txt.length === 0) {
    issues.push(issue("error", "dns", `"${domain}" does not resolve (no A/AAAA/MX/NS/TXT records)`));
  }

  // SPF: parse the record, then walk includes to count lookups.
  let spf: Report["spf"];
  const spfRecords = findSpfRecords(txt);
  if (spfRecords.length === 0) {
    if (mx.length > 0) {
      issues.push(issue("error", "spf", "no SPF record: anyone can send mail claiming to be this domain"));
    } else {
      issues.push(issue("warning", "spf", 'no SPF record (fine only if the domain never sends mail; then publish "v=spf1 -all")'));
    }
  } else {
    if (spfRecords.length > 1) {
      issues.push(issue("error", "spf", `${spfRecords.length} SPF records published (receivers treat this as permerror)`));
    }
    const tree = await resolveSpfTree(domain, dns.txt);
    spf = { record: tree.root.record ?? parseSpf(spfRecords[0]!), tree };
    issues.push(...tree.issues);
  }

  // DMARC: use the domain's own record, or walk parent domains toward the
  // organizational domain (RFC 7489 fallback) when the domain has none.
  let dmarcResult = evaluateDmarc(dmarcTxt);
  let dmarcInheritedFrom: string | undefined;
  if (findDmarcRecords(dmarcTxt).length === 0) {
    for (const parent of dmarcFallbackDomains(domain)) {
      const parentTxt = await dns.txt(`_dmarc.${parent}`).catch(() => []);
      if (findDmarcRecords(parentTxt).length === 0) continue;
      dmarcResult = evaluateDmarc(parentTxt);
      dmarcInheritedFrom = parent;
      dmarcResult.issues.push(
        issue("info", "dmarc", `no record at _dmarc.${domain}; policy inherited from "${parent}" (RFC 7489 organizational-domain fallback)`),
      );
      break;
    }
  }
  issues.push(...dmarcResult.issues);

  // DKIM: query each selector's _domainkey TXT.
  const selectors = opts.selectors && opts.selectors.length > 0 ? opts.selectors : COMMON_SELECTORS;
  const dkim: DkimRecord[] = [];
  const dkimTxt = await Promise.all(selectors.map((s) => dns.txt(`${s}._domainkey.${domain}`).catch(() => [])));
  selectors.forEach((selector, i) => {
    const record = dkimTxt[i]!.find((t) => /(^|;)\s*p=/.test(t) || /^v=DKIM1/i.test(t.trim()));
    if (record !== undefined) {
      const parsed = parseDkim(selector, record);
      dkim.push(parsed);
      issues.push(...parsed.issues);
    }
  });
  if (dkim.length === 0 && opts.selectors && opts.selectors.length > 0) {
    issues.push(issue("error", "dkim", `no DKIM key at the given selector(s): ${opts.selectors.join(", ")}`));
  } else if (dkim.length === 0 && mx.length > 0) {
    issues.push(
      issue(
        "info",
        "dkim",
        "no DKIM key found among common selectors (the domain may use a selector this probe does not know)",
      ),
    );
  }

  return {
    domain,
    spf,
    dmarc: dmarcResult.record,
    dmarcInheritedFrom,
    dkim,
    probedSelectors: selectors,
    records: { a, aaaa, mx, ns, caa },
    issues,
  };
}
