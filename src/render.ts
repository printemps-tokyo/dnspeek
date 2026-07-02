/** Render a Report as human-readable text or JSON. Pure. */
import { LOOKUP_LIMIT } from "./spf.js";
import { hasErrors, type Issue } from "./issue.js";
import type { Report } from "./report.js";

function paint(text: string, code: string, color: boolean): string {
  return color ? `\x1b[${code}m${text}\x1b[0m` : text;
}

function verdict(ok: boolean, color: boolean, okText = "OK", badText = "PROBLEM"): string {
  return ok ? paint(`[${okText}]`, "32", color) : paint(`[${badText}]`, "31", color);
}

function severityTag(s: Issue["severity"], color: boolean): string {
  if (s === "error") return paint("error", "31", color);
  if (s === "warning") return paint("warn ", "33", color);
  return paint("info ", "36", color);
}

/** Render the report as text. */
export function renderText(report: Report, color: boolean): string {
  const lines: string[] = [];
  const head = (t: string): void => {
    lines.push(paint(t, "1", color));
  };

  lines.push(`${paint("Domain:", "36", color)} ${report.domain}`);
  lines.push("");

  head("Email authentication");
  const areaIssues = (area: string): Issue[] => report.issues.filter((i) => i.area === area);

  if (report.spf) {
    const spfOk = !hasErrors(areaIssues("spf"));
    lines.push(`  SPF:    ${report.spf.record.raw}`);
    lines.push(
      `          lookups: ${report.spf.tree.totalLookups}/${LOOKUP_LIMIT}  ${verdict(spfOk, color)}`,
    );
  } else {
    lines.push(`  SPF:    none  ${verdict(false, color, "OK", "MISSING")}`);
  }

  if (report.dmarc) {
    const dmarcOk = !hasErrors(areaIssues("dmarc"));
    lines.push(`  DMARC:  ${report.dmarc.raw}`);
    const sp = report.dmarc.subdomainPolicy ?? "inherit";
    lines.push(`          policy: ${report.dmarc.policy ?? "?"} (subdomains: ${sp})  ${verdict(dmarcOk, color)}`);
  } else {
    lines.push(`  DMARC:  none  ${verdict(false, color, "OK", "MISSING")}`);
  }

  if (report.dkim.length > 0) {
    for (const k of report.dkim) {
      const bits = k.keyBits !== undefined ? ` ${k.keyBits}-bit` : "";
      const flags = [k.revoked ? "revoked" : "", k.testMode ? "test mode" : ""].filter(Boolean).join(", ");
      const ok = !k.revoked && !k.issues.some((i) => i.severity === "error");
      lines.push(`  DKIM:   ${k.selector}._domainkey  ${k.keyType}${bits}${flags ? `  (${flags})` : ""}  ${verdict(ok, color)}`);
    }
  } else {
    lines.push(`  DKIM:   no key found (probed ${report.probedSelectors.length} selectors)`);
  }

  lines.push("");
  head("Records");
  const { a, aaaa, mx, ns, caa } = report.records;
  if (mx.length > 0) {
    const hosts = [...mx].sort((x, y) => x.priority - y.priority).map((m) => `${m.priority} ${m.exchange}`);
    lines.push(`  MX:   ${hosts.join(", ")}`);
  } else {
    lines.push("  MX:   none (domain does not receive mail)");
  }
  if (ns.length > 0) lines.push(`  NS:   ${[...ns].sort().join(", ")}`);
  if (a.length > 0) lines.push(`  A:    ${a.join(", ")}`);
  if (aaaa.length > 0) lines.push(`  AAAA: ${aaaa.join(", ")}`);
  lines.push(caa.length > 0 ? `  CAA:  ${caa.join(", ")}` : "  CAA:  none (any CA may issue certificates)");

  const shown = report.issues.filter((i) => i.severity !== "info" || report.dkim.length === 0);
  if (shown.length > 0) {
    lines.push("");
    head("Findings");
    const order = { error: 0, warning: 1, info: 2 } as const;
    for (const i of [...shown].sort((x, y) => order[x.severity] - order[y.severity])) {
      lines.push(`  ${severityTag(i.severity, color)} ${i.area}: ${i.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

/** Render the report as JSON. */
export function renderJson(report: Report): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
