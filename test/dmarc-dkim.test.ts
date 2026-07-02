import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { evaluateDmarc, parseDmarc } from "../src/dmarc.js";
import { parseDkim } from "../src/dkim.js";

describe("parseDmarc", () => {
  it("parses tags and accepts a solid policy", () => {
    const r = parseDmarc("v=DMARC1; p=reject; rua=mailto:agg@example.com; adkim=s");
    expect(r.policy).toBe("reject");
    expect(r.tags.rua).toBe("mailto:agg@example.com");
    expect(r.issues.filter((i) => i.severity === "error")).toEqual([]);
  });

  it("warns on p=none, pct<100, weak sp, and missing rua", () => {
    const none = parseDmarc("v=DMARC1; p=none; rua=mailto:a@b.c");
    expect(none.issues.some((i) => /p=none/.test(i.message))).toBe(true);

    const pct = parseDmarc("v=DMARC1; p=reject; pct=50; rua=mailto:a@b.c");
    expect(pct.issues.some((i) => /pct=50/.test(i.message))).toBe(true);

    const sp = parseDmarc("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c");
    expect(sp.issues.some((i) => /subdomains are weaker/.test(i.message))).toBe(true);

    const noRua = parseDmarc("v=DMARC1; p=reject");
    expect(noRua.issues.some((i) => /rua/.test(i.message))).toBe(true);
  });

  it("errors on a missing/invalid policy or bad version", () => {
    expect(parseDmarc("v=DMARC1; rua=mailto:a@b.c").issues.some((i) => i.severity === "error")).toBe(true);
    expect(parseDmarc("v=DMARC1; p=block").issues.some((i) => i.severity === "error")).toBe(true);
    expect(parseDmarc("p=reject").issues.some((i) => /DMARC1/.test(i.message))).toBe(true);
  });
});

describe("evaluateDmarc", () => {
  it("errors when the record is absent or not DMARC", () => {
    expect(evaluateDmarc([]).issues.some((i) => i.severity === "error")).toBe(true);
    expect(evaluateDmarc(["not-dmarc"]).issues.some((i) => i.severity === "error")).toBe(true);
  });

  it("errors on multiple DMARC records", () => {
    const r = evaluateDmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"]);
    expect(r.issues.some((i) => /2 DMARC records/.test(i.message))).toBe(true);
  });
});

function rsaKeyB64(bits: number): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

describe("parseDkim", () => {
  it("reads the key type and RSA size", () => {
    const r = parseDkim("s1", `v=DKIM1; k=rsa; p=${rsaKeyB64(2048)}`);
    expect(r.keyType).toBe("rsa");
    expect(r.keyBits).toBe(2048);
    expect(r.revoked).toBe(false);
    expect(r.issues).toEqual([]);
  });

  it("warns on 1024-bit keys and flags revoked / test-mode keys", () => {
    const weak = parseDkim("s1", `v=DKIM1; p=${rsaKeyB64(1024)}`);
    expect(weak.issues.some((i) => i.severity === "warning" && /1024/.test(i.message))).toBe(true);

    const revoked = parseDkim("s1", "v=DKIM1; p=");
    expect(revoked.revoked).toBe(true);
    expect(revoked.issues.some((i) => /revoked/.test(i.message))).toBe(true);

    const test = parseDkim("s1", `v=DKIM1; t=y; p=${rsaKeyB64(2048)}`);
    expect(test.testMode).toBe(true);
  });

  it("errors on an undecodable key or missing p tag", () => {
    expect(parseDkim("s1", "v=DKIM1; p=!!!notbase64key!!!").issues.some((i) => i.severity === "error")).toBe(
      true,
    );
    expect(parseDkim("s1", "v=DKIM1; k=rsa").issues.some((i) => /missing required/.test(i.message))).toBe(true);
  });
});
