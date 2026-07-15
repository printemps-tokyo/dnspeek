import { describe, expect, it } from "vitest";
import { findSpfRecords, parseSpf, resolveSpfTree, type TxtFetcher } from "../src/spf.js";

describe("findSpfRecords", () => {
  it("picks only v=spf1 records", () => {
    const txt = ["v=spf1 -all", "google-site-verification=abc", "V=SPF1 mx ~all", "v=spf10 x"];
    expect(findSpfRecords(txt)).toEqual(["v=spf1 -all", "V=SPF1 mx ~all"]);
  });
});

describe("parseSpf", () => {
  it("parses qualifiers, values, and cidrs", () => {
    const r = parseSpf("v=spf1 ip4:192.0.2.0/24 include:_spf.example.com a:mail.example.com/28 mx -all");
    expect(r.terms.map((t) => t.name)).toEqual(["ip4", "include", "a", "mx", "all"]);
    expect(r.terms[0]).toMatchObject({ value: "192.0.2.0", cidr: "24", qualifier: "+" });
    expect(r.terms[2]).toMatchObject({ value: "mail.example.com", cidr: "28" });
    expect(r.terms[4]!.qualifier).toBe("-");
    expect(r.issues).toEqual([]);
  });

  it("flags +all as an error and ?all / ptr / missing all as warnings", () => {
    expect(parseSpf("v=spf1 +all").issues.some((i) => i.severity === "error")).toBe(true);
    expect(parseSpf("v=spf1 mx ?all").issues.some((i) => i.severity === "warning")).toBe(true);
    expect(parseSpf("v=spf1 ptr -all").issues.some((i) => /ptr/.test(i.message))).toBe(true);
    expect(parseSpf("v=spf1 mx").issues.some((i) => /no "all"/.test(i.message))).toBe(true);
  });

  it("flags unknown mechanisms and terms after all", () => {
    expect(parseSpf("v=spf1 bogus -all").issues.some((i) => /unknown mechanism/.test(i.message))).toBe(true);
    expect(parseSpf("v=spf1 -all mx").issues.some((i) => /never evaluated/.test(i.message))).toBe(true);
  });

  it("treats redirect as a modifier and warns when combined with all", () => {
    const r = parseSpf("v=spf1 redirect=_spf.example.com");
    expect(r.terms[0]).toMatchObject({ kind: "modifier", name: "redirect", value: "_spf.example.com" });
    expect(parseSpf("v=spf1 -all redirect=x.com").issues.some((i) => /redirect.*ignored/.test(i.message))).toBe(
      true,
    );
  });
});

function mockTxt(zones: Record<string, string[]>): TxtFetcher {
  return (domain) => Promise.resolve(zones[domain] ?? []);
}

describe("resolveSpfTree", () => {
  it("counts a/mx/include/exists lookups recursively", async () => {
    const fetchTxt = mockTxt({
      "example.com": ["v=spf1 mx include:one.example -all"],
      "one.example": ["v=spf1 a exists:%{i}.chk.example include:two.example ~all"],
      "two.example": ["v=spf1 ip4:192.0.2.1 -all"],
    });
    const tree = await resolveSpfTree("example.com", fetchTxt);
    // mx(1) + include one.example(1) + a(1) + exists(1) + include two.example(1) = 5
    expect(tree.totalLookups).toBe(5);
    expect(tree.issues.filter((i) => i.severity === "error")).toEqual([]);
  });

  it("errors past 10 lookups", async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.example`).join(" ");
    const zones: Record<string, string[]> = { "example.com": [`v=spf1 ${includes} -all`] };
    for (let i = 0; i < 11; i++) zones[`i${i}.example`] = ["v=spf1 -all"];
    const tree = await resolveSpfTree("example.com", mockTxt(zones));
    expect(tree.totalLookups).toBe(11);
    expect(tree.issues.some((i) => i.severity === "error" && /exceed/.test(i.message))).toBe(true);
  });

  it("detects include loops and void include targets", async () => {
    const loop = await resolveSpfTree(
      "a.example",
      mockTxt({
        "a.example": ["v=spf1 include:b.example -all"],
        "b.example": ["v=spf1 include:a.example -all"],
      }),
    );
    expect(loop.issues.some((i) => /loop/.test(i.message))).toBe(true);

    const missing = await resolveSpfTree(
      "a.example",
      mockTxt({ "a.example": ["v=spf1 include:gone.example -all"] }),
    );
    expect(missing.issues.some((i) => /void/.test(i.message))).toBe(true);
  });

  it("treats a shared include on sibling branches as a duplicate, not a loop", async () => {
    const tree = await resolveSpfTree(
      "example.com",
      mockTxt({
        "example.com": ["v=spf1 include:crm.example include:shop.example -all"],
        "crm.example": ["v=spf1 include:shared.vendor.example -all"],
        "shop.example": ["v=spf1 include:shared.vendor.example -all"],
        "shared.vendor.example": ["v=spf1 ip4:192.0.2.0/24 -all"],
      }),
    );
    expect(tree.issues.some((i) => /loop/.test(i.message))).toBe(false);
    expect(tree.issues.filter((i) => i.severity === "error")).toEqual([]);
    const dup = tree.issues.find((i) => /duplicate include/.test(i.message));
    expect(dup?.severity).toBe("warning");
    // Both include lookups are still charged against the RFC 7208 budget:
    // crm(1) + shop(1) + shared(1) + shared again(1) = 4.
    expect(tree.totalLookups).toBe(4);
  });

  it("still reports a self-include and a deeper ancestor loop as errors", async () => {
    const self = await resolveSpfTree(
      "a.example",
      mockTxt({ "a.example": ["v=spf1 include:a.example -all"] }),
    );
    expect(self.issues.some((i) => i.severity === "error" && /loop/.test(i.message))).toBe(true);

    const deep = await resolveSpfTree(
      "a.example",
      mockTxt({
        "a.example": ["v=spf1 include:b.example -all"],
        "b.example": ["v=spf1 include:c.example -all"],
        "c.example": ["v=spf1 include:b.example -all"],
      }),
    );
    expect(deep.issues.some((i) => i.severity === "error" && /loop/.test(i.message))).toBe(true);
  });

  it("follows redirect= targets", async () => {
    const tree = await resolveSpfTree(
      "example.com",
      mockTxt({
        "example.com": ["v=spf1 redirect=_spf.example.com"],
        "_spf.example.com": ["v=spf1 mx -all"],
      }),
    );
    // redirect(1) + mx(1)
    expect(tree.totalLookups).toBe(2);
    expect(tree.root.children[0]?.domain).toBe("_spf.example.com");
  });
});

describe("normalizeDomain", () => {
  it("accepts domains, URLs, emails, and trailing dots", async () => {
    const { normalizeDomain } = await import("../src/domain.js");
    expect(normalizeDomain("Example.COM")).toBe("example.com");
    expect(normalizeDomain("https://example.com:8443/path")).toBe("example.com");
    expect(normalizeDomain("user@mail.example.com")).toBe("mail.example.com");
    expect(normalizeDomain("example.com.")).toBe("example.com");
    expect(() => normalizeDomain("not a domain")).toThrow(/does not look like/);
    expect(() => normalizeDomain("localhost")).toThrow();
  });
});
