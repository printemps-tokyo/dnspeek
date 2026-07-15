import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { buildReport } from "../src/report.js";
import { renderText, renderJson } from "../src/render.js";
import { hasErrors } from "../src/issue.js";
import type { DnsClient } from "../src/dns.js";

const DKIM_KEY = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .publicKey.export({ type: "spki", format: "der" })
  .toString("base64");

function mockDns(zones: {
  txt?: Record<string, string[]>;
  mx?: { exchange: string; priority: number }[];
}): DnsClient {
  return {
    txt: (d) => Promise.resolve(zones.txt?.[d] ?? []),
    a: () => Promise.resolve(["192.0.2.10"]),
    aaaa: () => Promise.resolve([]),
    mx: () => Promise.resolve(zones.mx ?? []),
    ns: () => Promise.resolve(["ns1.example.net", "ns2.example.net"]),
    caa: () => Promise.resolve(['0 issue "letsencrypt.org"']),
  };
}

const GOOD = {
  txt: {
    "example.com": ["v=spf1 include:_spf.example.net -all", "other=1"],
    "_spf.example.net": ["v=spf1 ip4:192.0.2.0/24 -all"],
    "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:agg@example.com"],
    "s1._domainkey.example.com": [`v=DKIM1; k=rsa; p=${DKIM_KEY}`],
  },
  mx: [{ exchange: "mx.example.com", priority: 10 }],
};

describe("buildReport", () => {
  it("assembles a clean report for a well-configured domain", async () => {
    const report = await buildReport("example.com", mockDns(GOOD), { selectors: ["s1"] });
    expect(report.spf?.tree.totalLookups).toBe(1);
    expect(report.dmarc?.policy).toBe("reject");
    expect(report.dkim).toHaveLength(1);
    expect(hasErrors(report.issues)).toBe(false);
  });

  it("errors when a mail-receiving domain has no SPF and no DMARC", async () => {
    const report = await buildReport(
      "example.com",
      mockDns({ txt: {}, mx: [{ exchange: "mx.example.com", priority: 10 }] }),
    );
    expect(report.issues.some((i) => i.area === "spf" && i.severity === "error")).toBe(true);
    expect(report.issues.some((i) => i.area === "dmarc" && i.severity === "error")).toBe(true);
  });

  it("only warns about missing SPF when the domain has no MX", async () => {
    const report = await buildReport("example.com", mockDns({ txt: {}, mx: [] }));
    const spf = report.issues.filter((i) => i.area === "spf");
    expect(spf).toHaveLength(1);
    expect(spf[0]!.severity).toBe("warning");
  });

  it("falls back to the organizational domain's DMARC record for a subdomain", async () => {
    const report = await buildReport(
      "mail.example.com",
      mockDns({
        txt: {
          "mail.example.com": ["v=spf1 -all"],
          "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:agg@example.com"],
        },
        mx: [{ exchange: "mx.example.com", priority: 10 }],
      }),
    );
    expect(report.dmarc?.policy).toBe("reject");
    expect(report.dmarcInheritedFrom).toBe("example.com");
    expect(report.issues.filter((i) => i.area === "dmarc" && i.severity === "error")).toEqual([]);
    expect(report.issues.some((i) => i.area === "dmarc" && /inherited from "example.com"/.test(i.message))).toBe(true);
    const out = renderText(report, false);
    expect(out).toContain("(inherited from example.com)");
  });

  it("skips an intermediate parent's DMARC and applies the organizational domain's", async () => {
    // RFC 7489 receivers query only the organizational domain, so the
    // p=none at b.example.com must not shadow the p=reject at example.com.
    const report = await buildReport(
      "a.b.example.com",
      mockDns({
        txt: {
          "a.b.example.com": ["v=spf1 -all"],
          "_dmarc.b.example.com": ["v=DMARC1; p=none; rua=mailto:agg@example.com"],
          "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:agg@example.com"],
        },
        mx: [{ exchange: "mx.example.com", priority: 10 }],
      }),
    );
    expect(report.dmarc?.policy).toBe("reject");
    expect(report.dmarcInheritedFrom).toBe("example.com");
    expect(report.issues.some((i) => i.area === "dmarc" && /inherited from "example.com"/.test(i.message))).toBe(true);
  });

  it("reports no DMARC when a record exists only at an intermediate parent", async () => {
    // Receivers never consult intermediate parents, so this domain has no
    // effective DMARC at all despite the record at b.example.com.
    const report = await buildReport(
      "a.b.example.com",
      mockDns({
        txt: {
          "a.b.example.com": ["v=spf1 -all"],
          "_dmarc.b.example.com": ["v=DMARC1; p=reject; rua=mailto:agg@example.com"],
        },
        mx: [{ exchange: "mx.example.com", priority: 10 }],
      }),
    );
    expect(report.dmarc).toBeUndefined();
    expect(report.dmarcInheritedFrom).toBeUndefined();
    expect(report.issues.some((i) => i.area === "dmarc" && i.severity === "error")).toBe(true);
  });

  it("still errors when neither the domain nor any parent has DMARC", async () => {
    const report = await buildReport(
      "mail.example.com",
      mockDns({ txt: { "mail.example.com": ["v=spf1 -all"] }, mx: [{ exchange: "mx.example.com", priority: 10 }] }),
    );
    expect(report.dmarc).toBeUndefined();
    expect(report.dmarcInheritedFrom).toBeUndefined();
    expect(report.issues.some((i) => i.area === "dmarc" && i.severity === "error")).toBe(true);
  });

  it("errors when an explicitly requested selector has no key", async () => {
    const report = await buildReport("example.com", mockDns(GOOD), { selectors: ["nope"] });
    expect(report.issues.some((i) => i.area === "dkim" && i.severity === "error")).toBe(true);
  });
});

describe("render", () => {
  it("renders the text summary with verdicts", async () => {
    const report = await buildReport("example.com", mockDns(GOOD), { selectors: ["s1"] });
    const out = renderText(report, false);
    expect(out).toContain("SPF:    v=spf1 include:_spf.example.net -all");
    expect(out).toContain("lookups: 1/10  [OK]");
    expect(out).toContain("policy: reject");
    expect(out).toContain("s1._domainkey  rsa 2048-bit  [OK]");
    expect(out).toContain("MX:   10 mx.example.com");
    expect(out).not.toContain("\x1b[");
  });

  it("renders JSON with the same fields", async () => {
    const report = await buildReport("example.com", mockDns(GOOD), { selectors: ["s1"] });
    const parsed = JSON.parse(renderJson(report));
    expect(parsed.domain).toBe("example.com");
    expect(parsed.dmarc.policy).toBe("reject");
  });
});
