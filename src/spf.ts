/**
 * SPF (RFC 7208) parsing, linting, and DNS-lookup counting.
 *
 * Parsing and linting are pure. Counting the DNS lookups an SPF record costs
 * requires following include: and redirect= targets, so the resolver walk
 * takes an injected `fetchTxt` function — tests pass a mock, the CLI passes a
 * real DNS client.
 */
import { issue, type Issue } from "./issue.js";

export type Qualifier = "+" | "-" | "~" | "?";

export interface SpfTerm {
  kind: "mechanism" | "modifier";
  /** Mechanism or modifier name, lowercased (all, include, redirect, ...). */
  name: string;
  /** The :value / =value part (domain, ip, ...), if any. */
  value?: string;
  /** The /cidr suffix on a, mx, ip4, ip6, if any. */
  cidr?: string;
  qualifier: Qualifier;
}

export interface SpfRecord {
  raw: string;
  terms: SpfTerm[];
  issues: Issue[];
}

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
/** Mechanisms / modifiers that cost a DNS lookup (RFC 7208 section 4.6.4). */
const COUNTED = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);
/** RFC 7208 limit on DNS-querying terms per check_host() evaluation. */
export const LOOKUP_LIMIT = 10;

/** Pick the SPF records out of a domain's TXT records. */
export function findSpfRecords(txtRecords: string[]): string[] {
  return txtRecords.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
}

/** Parse one SPF record string into terms plus syntax/lint issues. */
export function parseSpf(raw: string): SpfRecord {
  const issues: Issue[] = [];
  const terms: SpfTerm[] = [];
  const parts = raw.trim().split(/\s+/);

  for (const part of parts.slice(1)) {
    // Modifier: name=value
    const mod = /^([A-Za-z][A-Za-z0-9._-]*)=(.*)$/.exec(part);
    if (mod) {
      const name = mod[1]!.toLowerCase();
      terms.push({ kind: "modifier", name, value: mod[2], qualifier: "+" });
      if (name !== "redirect" && name !== "exp") {
        issues.push(issue("info", "spf", `unknown modifier "${name}=" is ignored by receivers`));
      }
      continue;
    }

    // Mechanism: [qualifier]name[:value][/cidr]
    const m = /^([+\-~?]?)([A-Za-z][A-Za-z0-9]*)((?::[^/]*)?)((?:\/.*)?)$/.exec(part);
    if (!m) {
      issues.push(issue("error", "spf", `unparsable term "${part}"`));
      continue;
    }
    const qualifier = (m[1] === "" ? "+" : m[1]) as Qualifier;
    const name = m[2]!.toLowerCase();
    const value = m[3] ? m[3].slice(1) : undefined;
    const cidr = m[4] ? m[4].slice(1) : undefined;

    if (!MECHANISMS.has(name)) {
      issues.push(issue("error", "spf", `unknown mechanism "${name}" (receivers treat this as permerror)`));
      continue;
    }
    if ((name === "include" || name === "exists") && !value) {
      issues.push(issue("error", "spf", `"${name}" needs a domain (${name}:example.com)`));
      continue;
    }
    terms.push({ kind: "mechanism", name, value, cidr, qualifier });
  }

  lintSpf(terms, issues);
  return { raw: raw.trim(), terms, issues };
}

function lintSpf(terms: SpfTerm[], issues: Issue[]): void {
  const all = terms.find((t) => t.kind === "mechanism" && t.name === "all");
  const redirect = terms.find((t) => t.kind === "modifier" && t.name === "redirect");

  if (all) {
    if (all.qualifier === "+") {
      issues.push(issue("error", "spf", '"+all" authorizes the whole internet to send as this domain'));
    } else if (all.qualifier === "?") {
      issues.push(issue("warning", "spf", '"?all" is neutral: SPF then asserts nothing about forged mail'));
    }
    const allIndex = terms.indexOf(all);
    const after = terms.slice(allIndex + 1).filter((t) => t.kind === "mechanism" || t.name === "redirect");
    if (after.length > 0) {
      issues.push(issue("warning", "spf", `terms after "all" are never evaluated`));
    }
  } else if (!redirect) {
    issues.push(issue("warning", "spf", 'no "all" or "redirect=" at the end: unmatched senders get a neutral result'));
  }
  if (all && redirect) {
    issues.push(issue("warning", "spf", '"redirect=" is ignored because "all" is present'));
  }
  if (terms.some((t) => t.kind === "mechanism" && t.name === "ptr")) {
    issues.push(issue("warning", "spf", '"ptr" is slow and unreliable; RFC 7208 says do not use it'));
  }
}

/** One resolved node in the include / redirect tree. */
export interface SpfNode {
  domain: string;
  record?: SpfRecord;
  /** Lookups charged for reaching and evaluating this node's own terms. */
  lookups: number;
  children: SpfNode[];
  issues: Issue[];
}

export interface SpfTree {
  root: SpfNode;
  /** Total RFC 7208 counted lookups across the whole evaluation. */
  totalLookups: number;
  issues: Issue[];
}

export type TxtFetcher = (domain: string) => Promise<string[]>;

/**
 * Resolve a domain's SPF record and walk its include:/redirect= targets,
 * counting every DNS-querying term against the RFC 7208 limit of 10. The
 * `fetchTxt` dependency is injected so the walk is unit-testable offline.
 */
export async function resolveSpfTree(domain: string, fetchTxt: TxtFetcher): Promise<SpfTree> {
  const issues: Issue[] = [];
  /** Every domain resolved anywhere in the tree, for duplicate detection. */
  const visited = new Set<string>();
  let total = 0;

  const walk = async (name: string, viaLookup: boolean, path: readonly string[]): Promise<SpfNode> => {
    const node: SpfNode = { domain: name, lookups: 0, children: [], issues: [] };
    if (viaLookup) total += 1;

    const key = name.toLowerCase();
    // A real loop is a domain including one of its own ancestors. A domain
    // reached again on a sibling branch (e.g. a shared vendor include) is
    // legal; it just spends another lookup, so flag it without recursing.
    if (path.includes(key)) {
      node.issues.push(issue("error", "spf", `include loop: "${name}" includes itself via ${path.join(" -> ")}`));
      return node;
    }
    if (visited.has(key)) {
      node.issues.push(issue("warning", "spf", `duplicate include of "${name}" wastes lookups`));
      return node;
    }
    visited.add(key);
    if (path.length > 10) {
      node.issues.push(issue("error", "spf", `include chain deeper than 10 at "${name}"`));
      return node;
    }

    let txt: string[];
    try {
      txt = await fetchTxt(name);
    } catch {
      node.issues.push(issue("warning", "spf", `could not resolve TXT for "${name}"`));
      return node;
    }
    const records = findSpfRecords(txt);
    if (records.length === 0) {
      if (viaLookup) {
        node.issues.push(issue("error", "spf", `"${name}" has no SPF record (include/redirect target is void)`));
      }
      return node;
    }
    if (records.length > 1) {
      node.issues.push(issue("error", "spf", `"${name}" publishes ${records.length} SPF records (receivers treat this as permerror)`));
    }
    node.record = parseSpf(records[0]!);
    node.issues.push(...node.record.issues);

    for (const term of node.record.terms) {
      if (!COUNTED.has(term.name)) continue;
      if (term.name === "include" || term.name === "redirect") {
        node.children.push(await walk(term.value ?? "", true, [...path, key]));
      } else {
        total += 1; // a, mx, ptr, exists cost a lookup but are not followed.
        node.lookups += 1;
      }
    }
    return node;
  };

  const root = await walk(domain, false, []);
  if (total > LOOKUP_LIMIT) {
    issues.push(
      issue(
        "error",
        "spf",
        `${total} DNS lookups exceed the RFC 7208 limit of ${LOOKUP_LIMIT} (receivers return permerror)`,
      ),
    );
  } else if (total >= LOOKUP_LIMIT - 1) {
    issues.push(issue("warning", "spf", `${total}/${LOOKUP_LIMIT} DNS lookups: one more include may break SPF`));
  }

  const collect = (n: SpfNode): Issue[] => [...n.issues, ...n.children.flatMap(collect)];
  return { root, totalLookups: total, issues: [...collect(root), ...issues] };
}
