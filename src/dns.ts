/** The only IO in dnspeek: DNS queries via node:dns. */
import { Resolver } from "node:dns/promises";

export interface DnsClient {
  /** TXT records with their chunks joined ("" on NXDOMAIN / no data). */
  txt(domain: string): Promise<string[]>;
  a(domain: string): Promise<string[]>;
  aaaa(domain: string): Promise<string[]>;
  mx(domain: string): Promise<{ exchange: string; priority: number }[]>;
  ns(domain: string): Promise<string[]>;
  caa(domain: string): Promise<string[]>;
}

const EMPTY_CODES = new Set(["ENOTFOUND", "ENODATA"]);

function emptyOnMissing<T>(p: Promise<T[]>): Promise<T[]> {
  return p.catch((err: NodeJS.ErrnoException) => {
    if (err.code && EMPTY_CODES.has(err.code)) return [];
    throw err;
  });
}

/** Build a DNS client with the given timeout (ms) and optional server override. */
export function makeDnsClient(timeoutMs = 5000, server?: string): DnsClient {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  if (server) resolver.setServers([server]);

  return {
    txt: (d) =>
      emptyOnMissing(resolver.resolveTxt(d)).then((rows) => rows.map((chunks) => chunks.join(""))),
    a: (d) => emptyOnMissing(resolver.resolve4(d)),
    aaaa: (d) => emptyOnMissing(resolver.resolve6(d)),
    mx: (d) => emptyOnMissing(resolver.resolveMx(d)),
    ns: (d) => emptyOnMissing(resolver.resolveNs(d)),
    caa: (d) =>
      emptyOnMissing(resolver.resolveCaa(d)).then((rows) =>
        rows.map((r) => {
          const record = r as { critical: number; issue?: string; issuewild?: string; iodef?: string };
          if (record.issue) return `${record.critical} issue "${record.issue}"`;
          if (record.issuewild) return `${record.critical} issuewild "${record.issuewild}"`;
          if (record.iodef) return `${record.critical} iodef "${record.iodef}"`;
          return JSON.stringify(record);
        }),
      ),
  };
}
