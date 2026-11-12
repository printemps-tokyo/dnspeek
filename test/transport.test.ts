import { describe, expect, it } from "vitest";
import { buildReport } from "../src/report.js";
import type { DnsClient } from "../src/dns.js";
import {
  buildQuery,
  dnssecStatus,
  evaluateBimi,
  evaluateMtaStsTxt,
  evaluateTlsRpt,
  mxMatches,
  parseAnswer,
  parseMtaStsPolicy,
  uncoveredMx,
  type DnsAnswer,
} from "../src/index.js";

describe("MTA-STS", () => {
  it("reads the TXT id and the policy file", () => {
    expect(evaluateMtaStsTxt(["v=STSv1; id=20260101T000000"]).record?.id).toBe("20260101T000000");
    expect(evaluateMtaStsTxt(["v=STSv1;"]).issues[0]?.message).toMatch(/no id=/);
    expect(evaluateMtaStsTxt(["v=STSv1; id=a", "v=STSv1; id=b"]).issues[0]?.severity).toBe("error");
    const { policy, issues } = parseMtaStsPolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.backup.example.net\r\nmax_age: 604800\r\n");
    expect(policy).toEqual({ mode: "enforce", mx: ["mail.example.com", "*.backup.example.net"], maxAge: 604800 });
    expect(issues).toEqual([]);
    expect(parseMtaStsPolicy("version: STSv1\nmode: enforce\nmx: a\nmax_age: 99999999\n").issues[0]?.message).toMatch(/31557600/);
  });

  it("matches a wildcard against one leftmost label only (RFC 8461 3.2)", () => {
    expect(mxMatches("mx1.backup.example.net", "*.backup.example.net")).toBe(true);
    expect(mxMatches("a.mx1.backup.example.net", "*.backup.example.net")).toBe(false);
    expect(mxMatches("Mail.Example.com.", "mail.example.com")).toBe(true);
    expect(uncoveredMx(["mail.example.com", "other.example.org"], { mx: ["mail.example.com"] })).toEqual(["other.example.org"]);
  });
});

describe("TLS-RPT and BIMI", () => {
  it("checks the report addresses", () => {
    expect(evaluateTlsRpt(["v=TLSRPTv1; rua=mailto:tls@example.com,https://r.example.com/v1"]).record?.rua).toHaveLength(2);
    expect(evaluateTlsRpt(["v=TLSRPTv1; rua=tls@example.com"]).issues[0]?.message).toMatch(/mailto: or https:/);
  });

  it("needs an enforcing DMARC policy", () => {
    const rec = ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"];
    expect(evaluateBimi(rec, { policy: "reject" }).issues).toEqual([]);
    expect(evaluateBimi(rec, { policy: "none" }).issues[0]?.severity).toBe("error");
    expect(evaluateBimi(rec, { policy: "quarantine", pct: "50" }).issues[0]?.message).toMatch(/pct=50/);
    expect(evaluateBimi(["v=BIMI1; l=http://example.com/logo.png"], { policy: "reject" }).issues[0]?.message).toMatch(/https/);
  });
});

/** A DNS response for a query, with `answers` records of `type` and the AD bit. */
function response(query: Buffer, opts: { ad: boolean; rcode?: number; answers: number; type: number }): Buffer {
  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8180 | (opts.ad ? 0x20 : 0) | (opts.rcode ?? 0), 2);
  header.writeUInt16BE(opts.answers, 6);
  header.writeUInt16BE(0, 10);
  const question = query.subarray(12, query.length - 11);
  const rr = Buffer.alloc(12 + 4);
  rr.writeUInt16BE(0xc00c, 0); // name: pointer to the question
  rr.writeUInt16BE(opts.type, 2);
  rr.writeUInt16BE(1, 4);
  rr.writeUInt32BE(300, 6);
  rr.writeUInt16BE(4, 10);
  return Buffer.concat([header, question, ...Array.from({ length: opts.answers }, () => rr)]);
}

describe("DNSSEC probe", () => {
  it("builds a query with RD, AD and the DO bit", () => {
    const q = buildQuery(0x1234, "example.com", 43);
    expect(q.readUInt16BE(0)).toBe(0x1234);
    expect(q.readUInt16BE(2)).toBe(0x0120);
    expect(q.subarray(12, 25).toString("latin1")).toBe("\x07example\x03com\x00");
    // OPT: type 41, payload 1232, DO bit set.
    expect([...q.subarray(-11)]).toEqual([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
    expect(() => buildQuery(1, `${"a".repeat(64)}.com`, 1)).toThrow(/63/);
  });

  it("reads AD, the rcode and the answer types", () => {
    const q = buildQuery(7, "example.com", 43);
    const a = parseAnswer(response(q, { ad: true, answers: 2, type: 43 }));
    expect(a).toEqual({ id: 7, rcode: 0, ad: true, truncated: false, answerTypes: [43, 43] });
  });

  it("calls a domain signed and validated only with DS and AD on both answers", async () => {
    const fake = (ds: Partial<DnsAnswer>, soa: Partial<DnsAnswer>) => (_s: string, _n: string, type: number) =>
      Promise.resolve({ id: 1, rcode: 0, ad: false, truncated: false, answerTypes: [], ...(type === 43 ? ds : soa) } as DnsAnswer);
    expect(await dnssecStatus("x.example", "r", 1000, fake({ ad: true, answerTypes: [43] }, { ad: true, answerTypes: [6] }))).toMatchObject({ signed: true, validated: true });
    expect(await dnssecStatus("x.example", "r", 1000, fake({ ad: false, answerTypes: [43] }, { ad: false }))).toMatchObject({ signed: true, validated: false });
    expect(await dnssecStatus("x.example", "r", 1000, fake({ ad: true }, { ad: true }))).toMatchObject({ signed: false, validated: false });
    expect(await dnssecStatus("x.example", "r", 1000, fake({ rcode: 2 }, { rcode: 2 }))).toMatchObject({ servfail: true });
  });
});

describe("report", () => {
  const dns: DnsClient = {
    txt: (d) =>
      Promise.resolve(
        ({
          "example.com": ["v=spf1 -all"],
          "_dmarc.example.com": ["v=DMARC1; p=reject"],
          "_mta-sts.example.com": ["v=STSv1; id=1"],
          "default._bimi.example.com": ["v=BIMI1; l=https://example.com/l.svg"],
        } as Record<string, string[]>)[d] ?? [],
      ),
    a: () => Promise.resolve([]),
    aaaa: () => Promise.resolve([]),
    mx: () => Promise.resolve([{ exchange: "mail.example.com", priority: 10 }, { exchange: "old.example.org", priority: 20 }]),
    ns: () => Promise.resolve(["ns.example.net"]),
    caa: () => Promise.resolve([]),
  };

  it("fetches the policy only when asked, and flags uncovered MX hosts", async () => {
    const plain = await buildReport("example.com", dns, { selectors: ["s"] });
    expect(plain.mtaSts?.policy).toBeUndefined();
    const fetched: string[] = [];
    const r = await buildReport("example.com", dns, {
      selectors: ["s"],
      fetchText: (url) => {
        fetched.push(url);
        return Promise.resolve("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n");
      },
    });
    expect(fetched).toEqual(["https://mta-sts.example.com/.well-known/mta-sts.txt"]);
    expect(r.issues.find((i) => i.area === "mta-sts" && i.severity === "error")?.message).toMatch(/old\.example\.org.*will fail/);
    expect(r.issues.some((i) => i.area === "tls-rpt")).toBe(true);
    expect(r.bimi?.logo).toBe("https://example.com/l.svg");
  });
});
