/**
 * Public API for dnspeek.
 *
 * dnspeek diagnoses a domain's email authentication (SPF / DKIM / DMARC) and
 * key DNS records in plain language. Parsing and linting are pure functions;
 * the SPF include walk takes an injected TXT fetcher, so everything is
 * unit-testable offline. The only IO is DNS queries in the CLI's DnsClient.
 */

export type { Issue, Severity } from "./issue.js";
export { issue, hasErrors } from "./issue.js";

export {
  findSpfRecords,
  parseSpf,
  resolveSpfTree,
  LOOKUP_LIMIT,
} from "./spf.js";
export type { SpfRecord, SpfTerm, SpfTree, SpfNode, TxtFetcher, Qualifier } from "./spf.js";

export { findDmarcRecords, parseDmarc, evaluateDmarc, dmarcFallbackDomains } from "./dmarc.js";
export type { DmarcRecord } from "./dmarc.js";

export { parseDkim, COMMON_SELECTORS } from "./dkim.js";
export type { DkimRecord } from "./dkim.js";

export { makeDnsClient } from "./dns.js";
export type { DnsClient } from "./dns.js";

export { buildReport } from "./report.js";
export type { Report, ReportOptions } from "./report.js";

export { normalizeDomain } from "./domain.js";
export { renderText, renderJson } from "./render.js";
