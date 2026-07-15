/** Normalize user input (domain, URL, or email address) to a bare domain. Pure. */
import { domainToASCII } from "node:url";

export function normalizeDomain(input: string): string {
  let s = input.trim();
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  s = s.split("/")[0]!.split(":")[0]!;
  s = s.replace(/\.$/, "").toLowerCase();
  // Internationalized domain names: convert to the punycode (A-label) form
  // with the WHATWG IDNA converter built into node:url, so DNS queries and
  // output use the ASCII form (e.g. xn--wgv71a119e.jp).
  if (/[^\x20-\x7e]/.test(s)) {
    const ascii = domainToASCII(s);
    if (ascii === "") {
      throw new Error(`"${input}" does not look like a domain`);
    }
    s = ascii;
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(s)) {
    throw new Error(`"${input}" does not look like a domain`);
  }
  return s;
}
