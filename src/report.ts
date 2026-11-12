/** Assemble the full domain report from DNS answers and the pure analyzers. */
import { dmarcFallbackDomains, evaluateDmarc, findDmarcRecords, type DmarcRecord } from "./dmarc.js";
import {
  evaluateBimi,
  evaluateMtaStsTxt,
  evaluateTlsRpt,
  parseMtaStsPolicy,
  uncoveredMx,
  type BimiRecord,
  type MtaStsPolicy,
  type MtaStsRecord,
  type TlsRptRecord,
} from "./transport.js";
import type { DnssecStatus } from "./dnssec.js";
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
  /** MTA-STS (RFC 8461): the TXT record, and the policy when fetched. */
  mtaSts?: { record: MtaStsRecord; policy?: MtaStsPolicy };
  /** SMTP TLS Reporting (RFC 8460). */
  tlsRpt?: TlsRptRecord;
  /** BIMI (default selector). */
  bimi?: BimiRecord;
  /** DNSSEC as the resolver sees it. */
  dnssec?: DnssecStatus;
  issues: Issue[];
}

export interface ReportOptions {
  /** DKIM selectors to check; defaults to a common-provider probe list. */
  selectors?: string[];
  /** Fetch a URL's text (for the MTA-STS policy); without it the policy is not fetched. */
  fetchText?: (url: string) => Promise<string>;
  /** Check DNSSEC through this probe; without it DNSSEC is not checked. */
  dnssec?: (domain: string) => Promise<DnssecStatus>;
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

  // DMARC: use the domain's own record, or fall back to the organizational
  // domain. RFC 7489 receivers query only the organizational domain — never
  // intermediate parents — so a record at e.g. b.example.com does not apply
  // to a.b.example.com, and adopting it here would misreport the policy that
  // receivers actually enforce.
  let dmarcResult = evaluateDmarc(dmarcTxt);
  let dmarcInheritedFrom: string | undefined;
  if (findDmarcRecords(dmarcTxt).length === 0) {
    const orgDomain = dmarcFallbackDomains(domain).at(-1);
    if (orgDomain !== undefined) {
      const orgTxt = await dns.txt(`_dmarc.${orgDomain}`).catch(() => []);
      if (findDmarcRecords(orgTxt).length > 0) {
        dmarcResult = evaluateDmarc(orgTxt);
        dmarcInheritedFrom = orgDomain;
        dmarcResult.issues.push(
          issue("info", "dmarc", `no record at _dmarc.${domain}; policy inherited from "${orgDomain}" (RFC 7489 organizational-domain fallback)`),
        );
      }
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

  // Transport security and brand records.
  const [stsTxt, rptTxt, bimiTxt] = await Promise.all([
    dns.txt(`_mta-sts.${domain}`).catch(() => []),
    dns.txt(`_smtp._tls.${domain}`).catch(() => []),
    dns.txt(`default._bimi.${domain}`).catch(() => []),
  ]);
  let mtaSts: Report["mtaSts"];
  const sts = evaluateMtaStsTxt(stsTxt);
  issues.push(...sts.issues);
  if (sts.record) {
    mtaSts = { record: sts.record };
    if (opts.fetchText) {
      const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
      try {
        const parsed = parseMtaStsPolicy(await opts.fetchText(url));
        mtaSts.policy = parsed.policy;
        issues.push(...parsed.issues);
        const missing = uncoveredMx(mx.map((m) => m.exchange), parsed.policy);
        if (missing.length > 0 && parsed.policy.mode !== "none") {
          issues.push(
            issue(
              parsed.policy.mode === "enforce" ? "error" : "warning",
              "mta-sts",
              `MX host(s) not covered by the policy's mx: patterns: ${missing.join(", ")}${parsed.policy.mode === "enforce" ? " (mail to them will fail)" : ""}`,
            ),
          );
        }
      } catch (err) {
        issues.push(issue("error", "mta-sts", `cannot fetch the policy at ${url}: ${(err as Error).message}`));
      }
    }
  } else if (mx.length > 0) {
    issues.push(issue("info", "mta-sts", "no MTA-STS record: senders cannot require TLS for mail to this domain"));
  }
  const rpt = evaluateTlsRpt(rptTxt);
  issues.push(...rpt.issues);
  if (!rpt.record && sts.record) {
    issues.push(issue("info", "tls-rpt", "MTA-STS without TLS-RPT: you will not hear about delivery TLS failures"));
  }
  const bimi = evaluateBimi(bimiTxt, dmarcResult.record ? { policy: dmarcResult.record.policy, pct: dmarcResult.record.tags.pct } : undefined);
  issues.push(...bimi.issues);

  let dnssec: DnssecStatus | undefined;
  if (opts.dnssec) {
    try {
      dnssec = await opts.dnssec(domain);
      if (dnssec.servfail) {
        issues.push(issue("error", "dnssec", `${dnssec.resolver} answered SERVFAIL; a validating resolver does that when DNSSEC validation fails`));
      } else if (!dnssec.signed) {
        issues.push(issue("info", "dnssec", "not signed with DNSSEC (no DS record at the parent)"));
      } else if (!dnssec.validated) {
        issues.push(issue("warning", "dnssec", `signed (DS at the parent), but ${dnssec.resolver} did not mark the answers validated; it may not validate DNSSEC (try --server 1.1.1.1)`));
      }
    } catch (err) {
      issues.push(issue("info", "dnssec", `DNSSEC not checked: ${(err as Error).message}`));
    }
  }

  return {
    domain,
    ...(mtaSts ? { mtaSts } : {}),
    ...(rpt.record ? { tlsRpt: rpt.record } : {}),
    ...(bimi.record ? { bimi: bimi.record } : {}),
    ...(dnssec ? { dnssec } : {}),
    spf,
    dmarc: dmarcResult.record,
    dmarcInheritedFrom,
    dkim,
    probedSelectors: selectors,
    records: { a, aaaa, mx, ns, caa },
    issues,
  };
}
