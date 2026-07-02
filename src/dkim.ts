/** DKIM (RFC 6376) key record parsing and linting. */
import { createPublicKey } from "node:crypto";
import { issue, type Issue } from "./issue.js";

export interface DkimRecord {
  selector: string;
  raw: string;
  keyType: string;
  /** RSA modulus bits, when the key parses. */
  keyBits?: number;
  revoked: boolean;
  testMode: boolean;
  issues: Issue[];
}

/** Selectors worth probing when none are given (common providers). */
export const COMMON_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "s1",
  "s2",
  "mail",
  "dkim",
  "fm1",
  "pm",
  "mandrill",
  "zoho",
];

/** Parse and lint one DKIM key record (the TXT at <selector>._domainkey.<domain>). */
export function parseDkim(selector: string, raw: string): DkimRecord {
  const issues: Issue[] = [];
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const kv = part.trim();
    if (kv === "") continue;
    const eq = kv.indexOf("=");
    if (eq !== -1) tags[kv.slice(0, eq).trim().toLowerCase()] = kv.slice(eq + 1).trim();
  }

  if (tags.v !== undefined && tags.v.toUpperCase() !== "DKIM1") {
    issues.push(issue("error", "dkim", `${selector}: invalid version "${tags.v}"`));
  }

  const keyType = (tags.k ?? "rsa").toLowerCase();
  const p = (tags.p ?? "").replace(/\s+/g, "");
  const revoked = p === "";
  if (tags.p === undefined) {
    issues.push(issue("error", "dkim", `${selector}: missing required public key tag "p="`));
  } else if (revoked) {
    issues.push(issue("warning", "dkim", `${selector}: empty p= means the key is revoked`));
  }

  let keyBits: number | undefined;
  if (!revoked && p !== "" && keyType === "rsa") {
    try {
      const der = Buffer.from(p, "base64");
      const key = createPublicKey({ key: der, format: "der", type: "spki" });
      keyBits = key.asymmetricKeyDetails?.modulusLength;
      if (keyBits !== undefined) {
        if (keyBits < 1024) {
          issues.push(issue("error", "dkim", `${selector}: ${keyBits}-bit RSA key is trivially breakable`));
        } else if (keyBits < 2048) {
          issues.push(issue("warning", "dkim", `${selector}: ${keyBits}-bit RSA key is weak; use 2048`));
        }
      }
    } catch {
      issues.push(issue("error", "dkim", `${selector}: p= does not decode as a public key`));
    }
  }

  const testMode = /(^|:)y(:|$)/.test(tags.t ?? "");
  if (testMode) {
    issues.push(issue("info", "dkim", `${selector}: t=y test mode (verifiers may ignore signatures)`));
  }

  return { selector, raw: raw.trim(), keyType, keyBits, revoked, testMode, issues };
}
