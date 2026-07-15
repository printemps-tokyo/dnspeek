/**
 * End-to-end check of the argument-parsing error path.
 *
 * When parseArgs rejects an unknown/invalid option, the CLI should print a
 * clean `error:` line and a hint pointing at `--help`, then exit 1 - rather
 * than surfacing a bare parser stack trace.
 *
 * Runs the built CLI (dist/cli.js); the test self-builds if dist is missing.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const pexecFile = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const cliPath = join(root, "dist", "cli.js");

beforeAll(async () => {
  if (!existsSync(cliPath)) {
    await pexecFile("npm", ["run", "build"], { cwd: root });
  }
});

describe("cli argument parsing", () => {
  it("rejects an unknown flag with an error and a --help hint, exit 1", async () => {
    const err = (await pexecFile("node", [cliPath, "--definitely-not-a-real-flag"]).catch(
      (e: unknown) => e,
    )) as { code?: number; stderr?: string };
    expect(err.code).toBe(1);
    expect(err.stderr ?? "").toContain("error:");
    expect(err.stderr ?? "").toContain("--help");
  });
});
