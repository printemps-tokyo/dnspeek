# dnspeek

> Diagnose a domain's email authentication (SPF / DKIM / DMARC) and key DNS records in plain language. Zero-dependency CLI.

[![CI](https://github.com/printemps-tokyo/dnspeek/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/dnspeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`dig` shows you a domain's records; `dnspeek` tells you what they mean. One
command answers the question every mail admin eventually asks: can other
people spoof mail from this domain, and will my own mail get delivered?

```console
$ dnspeek github.com
Domain: github.com

Email authentication
  SPF:    v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ...
          lookups: 10/10  [OK]
  DMARC:  v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ...
          policy: quarantine (subdomains: reject)  [OK]
  DKIM:   google._domainkey  rsa 2048-bit  [OK]
  DKIM:   selector1._domainkey  rsa 1024-bit  [OK]

Records
  MX:   0 github-com.mail.protection.outlook.com
  NS:   dns1.p08.nsone.net, ...
  CAA:  0 issue "digicert.com", ...

Findings
  warn  spf: 10/10 DNS lookups: one more include may break SPF
  warn  dkim: selector1: 1024-bit RSA key is weak; use 2048
```

The only network traffic is DNS queries for the domain you name. Analysis is
local and dependency-free.

## Requirements

- Node.js >= 22

## Install

Not published to npm yet — install from source:

```bash
git clone https://github.com/printemps-tokyo/dnspeek
cd dnspeek
npm install && npm run build
npm link   # optional: puts the `dnspeek` command on your PATH
```

Then run `dnspeek …` (after `npm link`), or `node dist/cli.js …` from the clone.

## Usage

```bash
dnspeek example.com                    # full email-auth diagnosis
dnspeek user@example.com               # a URL or email works too
dnspeek 日本語.jp                       # IDN input is converted to punycode
dnspeek example.com --selector s1,s2   # check specific DKIM selectors
dnspeek example.com --json             # machine-readable
```

| Option | Description |
| --- | --- |
| `<domain>` | Domain to check (a URL or email address is normalized; internationalized domain names are converted to their punycode form, which is what the output shows) |
| `--selector <s1,s2>` | DKIM selectors to check (default: probe 14 common ones) |
| `--server <ip>` | Use this DNS server instead of the system resolver |
| `--timeout <ms>` | DNS query timeout (default: 5000) |
| `--json` | Output JSON instead of text |
| `--no-color` | Disable ANSI colors |

The exit code is `1` when a problem is found — no or multiple SPF records, an
unknown mechanism, more than 10 DNS lookups, a missing or invalid DMARC record,
a revoked or trivially weak DKIM key — so it fits CI and monitoring crons.

## What it checks

SPF (RFC 7208):

- Finds the `v=spf1` record and parses every mechanism and modifier; unknown
  mechanisms (a common typo like `ipv4:` for `ip4:`) are flagged as the
  permerror they cause.
- Follows `include:` and `redirect=` targets recursively and counts every
  DNS-querying term against the RFC limit of 10 — the failure mode that
  silently breaks SPF as a domain accumulates SaaS senders.
- Flags `+all` (anyone may send), `?all`, deprecated `ptr`, terms after `all`,
  missing terminal `all`, multiple SPF records, and void include targets.
- Distinguishes real include loops (a domain including one of its ancestors,
  an error) from the same vendor include appearing on two branches, which is
  legal and only reported as a warning because it wastes lookups.

DMARC (RFC 7489):

- Parses the `_dmarc` record and explains the policy for the domain and its
  subdomains.
- When a subdomain publishes no record of its own, walks parent domains
  toward the organizational domain (the RFC 7489 fallback receivers apply)
  and labels the result `inherited from <domain>`. Without shipping the
  Public Suffix List, the walk stops at 2 labels (3 for well-known
  second-level suffixes such as co.jp or co.uk).
- Flags a missing record, `p=none` (monitoring only), `pct<100`, subdomain
  policies weaker than the domain's, invalid tags, and a missing `rua=`
  (you would receive no reports).

DKIM (RFC 6376):

- Looks up the key records for your selectors, or probes 14 common provider
  selectors (google, selector1/2, k1, s1/s2, ...) when none are given.
- Reads the key type and RSA size, and flags revoked (`p=`), weak (<2048 bit),
  and test-mode (`t=y`) keys.

Plus the core records in one view: MX (sorted by priority), NS, A/AAAA, and
CAA (with a note when any CA may issue certificates).

## Programmatic API

```ts
import { makeDnsClient, buildReport, hasErrors } from "@printemps-tokyo/dnspeek";

const report = await buildReport("example.com", makeDnsClient());
console.log(report.spf?.tree.totalLookups, report.dmarc?.policy, hasErrors(report.issues));
```

Parsing and linting (`parseSpf`, `parseDmarc`, `parseDkim`) are pure functions,
and `resolveSpfTree` takes an injected TXT fetcher, so everything is testable
offline.

## License

[MIT](./LICENSE) (c) printemps.tokyo
