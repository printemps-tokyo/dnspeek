#!/usr/bin/env node
import { parseArgs } from "node:util";
import { normalizeDomain } from "./domain.js";
import { makeDnsClient } from "./dns.js";
import { buildReport } from "./report.js";
import { renderJson, renderText } from "./render.js";
import { hasErrors } from "./issue.js";

const HELP = `dnspeek - diagnose a domain's email authentication and key DNS records

Usage:
  dnspeek <domain>              Check SPF, DMARC, DKIM, and core records
  dnspeek <domain> --selector s1,s2   Check specific DKIM selectors

A URL or email address is accepted and normalized to its domain, and
internationalized domain names are converted to punycode.

Explains, in plain language, whether a domain's mail can be spoofed: the SPF
record and its RFC 7208 lookup count (includes are followed recursively), the
DMARC policy (falling back to the organizational domain's record for
subdomains, as receivers do), and DKIM keys (probing common selectors when
none are given).
Also shows MX, NS, A/AAAA, and CAA. The only network traffic is DNS queries
for the domain you name.

Options:
  --selector <s1,s2>  DKIM selectors to check (default: probe common ones)
  --server <ip>       Use this DNS server instead of the system resolver
  --timeout <ms>      DNS query timeout (default: 5000)
  --json              Output JSON instead of text
  --no-color          Disable ANSI colors
  -h, --help          Show this help
  -v, --version       Show version

Exit code: 1 when a problem is found (no/broken SPF, too many lookups, missing
or invalid DMARC, revoked/weak DKIM key), so it fits CI and monitoring.

Examples:
  dnspeek example.com
  dnspeek example.com --selector google
  dnspeek example.com --json
`;

async function readVersion(): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  try {
    const raw = await readFile(join(here, "..", "package.json"), "utf8");
    return (JSON.parse(raw) as { version: string }).version;
  } catch {
    return "0.0.0";
  }
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes("-h") || argv.includes("--help") || argv.length === 0) {
    process.stdout.write(HELP);
    return argv.length === 0 ? 1 : 0;
  }
  if (argv.includes("-v") || argv.includes("--version")) {
    process.stdout.write((await readVersion()) + "\n");
    return 0;
  }

  let values;
  let positionals;
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        selector: { type: "string" },
        server: { type: "string" },
        timeout: { type: "string" },
        json: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
      },
    });
    values = parsed.values;
    positionals = parsed.positionals;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    process.stderr.write("run 'dnspeek --help' for usage.\n");
    return 1;
  }

  if (positionals.length !== 1) {
    process.stderr.write("error: give exactly one domain\n\n" + HELP);
    return 1;
  }

  let report;
  try {
    const domain = normalizeDomain(positionals[0]!);
    const dns = makeDnsClient(values.timeout ? Number(values.timeout) : undefined, values.server);
    const selectors = values.selector
      ? values.selector.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;
    report = await buildReport(domain, dns, { selectors });
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  const color = !values["no-color"] && !process.env.NO_COLOR && process.stdout.isTTY === true;
  process.stdout.write(values.json ? renderJson(report) : renderText(report, color));

  return hasErrors(report.issues) ? 1 : 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    process.exitCode = 1;
  });
