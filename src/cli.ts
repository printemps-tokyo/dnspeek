#!/usr/bin/env node
import { parseArgs } from "node:util";
import { getServers } from "node:dns";
import { dnssecStatus } from "./dnssec.js";
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
Also checks MTA-STS, TLS-RPT, BIMI and DNSSEC, and shows MX, NS, A/AAAA, and
CAA. The only network traffic is DNS queries for the domain you name (and,
with --http, its MTA-STS policy file).

Options:
  --selector <s1,s2>  DKIM selectors to check (default: probe common ones)
  --server <ip>       Use this DNS server instead of the system resolver
  --timeout <ms>      DNS query timeout (default: 5000)
  --http              Also fetch the MTA-STS policy over HTTPS and check it
                      against the MX hosts (the only non-DNS traffic)
  --no-dnssec         Skip the DNSSEC check (a DS and SOA query with the
                      DNSSEC OK bit, sent to the resolver)
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
        http: { type: "boolean", default: false },
        "no-dnssec": { type: "boolean", default: false },
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
    const timeoutMs = values.timeout ? Number(values.timeout) : 5000;
    const resolver = values.server ?? getServers()[0];
    report = await buildReport(domain, dns, {
      selectors,
      ...(values.http ? { fetchText: (url: string) => fetchPolicy(url, timeoutMs) } : {}),
      ...(!values["no-dnssec"] && resolver ? { dnssec: (d: string) => dnssecStatus(d, resolver, timeoutMs) } : {}),
    });
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

/** GET a small text file over HTTPS (the MTA-STS policy), refusing redirects as RFC 8461 3.3 requires. */
async function fetchPolicy(url: string, timeoutMs: number): Promise<string> {
  const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(Math.max(timeoutMs, 10_000)) });
  if (res.status >= 300 && res.status < 400) throw new Error(`HTTP ${res.status} redirect (MTA-STS policies must not redirect)`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > 64 * 1024) throw new Error("the policy is larger than 64 KiB");
  return text;
}
