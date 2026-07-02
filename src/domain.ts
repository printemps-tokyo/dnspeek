/** Normalize user input (domain, URL, or email address) to a bare domain. Pure. */

export function normalizeDomain(input: string): string {
  let s = input.trim();
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  s = s.split("/")[0]!.split(":")[0]!;
  s = s.replace(/\.$/, "").toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(s)) {
    throw new Error(`"${input}" does not look like a domain`);
  }
  return s;
}
