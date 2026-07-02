/** A diagnostic finding shared by all analyzers. */

export type Severity = "error" | "warning" | "info";

export interface Issue {
  severity: Severity;
  /** Which subsystem raised it: spf | dmarc | dkim | dns. */
  area: string;
  message: string;
}

export function issue(severity: Severity, area: string, message: string): Issue {
  return { severity, area, message };
}

/** True when any issue is an error (drives the exit code). */
export function hasErrors(issues: Issue[]): boolean {
  return issues.some((i) => i.severity === "error");
}
