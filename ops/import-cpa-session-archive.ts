#!/usr/bin/env node
/** Validated dry-run-by-default wrapper for the Rust session archive importer. */

import { spawn } from "node:child_process";
import { accessSync, constants as fsConstants, statSync } from "node:fs";

class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 2) {
    super(message);
    this.exitCode = exitCode;
  }
}

function fail(message: string): never {
  throw new CliError(message);
}

function booleanSetting(name: string, fallback: boolean): boolean {
  const raw = process.env[name] ?? String(fallback);
  if (raw !== "true" && raw !== "false") fail(`${name} must be true or false`);
  return raw === "true";
}

function unsignedSetting(name: string, fallback: string): string {
  const raw = process.env[name] ?? fallback;
  if (!/^\d+$/.test(raw)) fail("archive import numeric settings must be unsigned integers");
  return raw;
}

async function main(): Promise<void> {
  const input = process.env.CPA_SESSION_ARCHIVE_INPUT;
  if (!input) fail("CPA_SESSION_ARCHIVE_INPUT is required");
  try {
    const metadata = statSync(input);
    accessSync(input, fsConstants.R_OK);
    if (!metadata.isFile()) throw new Error("not regular");
  } catch {
    fail("CPA_SESSION_ARCHIVE_INPUT must be a readable regular file");
  }

  const tenant = process.env.IMPORT_TENANT_EXTERNAL_ID ?? "cpa-dogfood-import";
  const cpampSource = process.env.CPAMP_IMPORT_SOURCE ?? "cpamp-usage-events-v1";
  const archiveSource = process.env.SESSION_ARCHIVE_IMPORT_SOURCE ?? "cpa-session-archive-v2";
  const overlap = unsignedSetting("SESSION_ARCHIVE_OVERLAP_MS", "86400000");
  const tolerance = unsignedSetting("SESSION_ARCHIVE_TIME_TOLERANCE_MS", "300000");
  const maxLineBytes = unsignedSetting("SESSION_ARCHIVE_MAX_LINE_BYTES", "16777216");
  const maxPlanBytes = unsignedSetting("SESSION_ARCHIVE_MAX_PLAN_BYTES", "1073741824");
  if (BigInt(maxLineBytes) > 16_777_216n) fail("SESSION_ARCHIVE_MAX_LINE_BYTES must not exceed the 16 MiB importer hard limit");
  const planDirectory = process.env.SESSION_ARCHIVE_PLAN_DIRECTORY ?? "/tmp";
  try {
    if (!statSync(planDirectory).isDirectory()) throw new Error("not directory");
    accessSync(planDirectory, fsConstants.W_OK);
  } catch {
    fail("SESSION_ARCHIVE_PLAN_DIRECTORY must be a writable directory");
  }
  const allowUnmapped = booleanSetting("SESSION_ARCHIVE_ALLOW_UNMAPPED", false);
  const apply = booleanSetting("SESSION_ARCHIVE_APPLY", false);
  const binary = process.env.MTC_SESSION_ARCHIVE_IMPORT_BIN ?? "import-cpa-session-archive";
  if (!binary || binary.includes("\0")) fail("session archive importer binary is unavailable");

  const args = [
    "--input", input,
    "--plan-directory", planDirectory,
    "--tenant-external-id", tenant,
    "--cpamp-source", cpampSource,
    "--archive-source", archiveSource,
    "--overlap-ms", overlap,
    "--time-tolerance-ms", tolerance,
    "--max-line-bytes", maxLineBytes,
    "--max-plan-bytes", maxPlanBytes,
    "--allow-unmapped", String(allowUnmapped),
    ...(apply ? ["--apply"] : []),
  ];
  const status = await new Promise<number>((resolve, reject) => {
    const child = spawn(binary, args, { env: process.env, shell: false, stdio: "inherit" });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve(code ?? (signal ? 128 : 1)));
  }).catch((error: unknown) => {
    fail(error instanceof Error && "code" in error && error.code === "ENOENT" ? "session archive importer binary is unavailable" : `session archive importer failed: ${error instanceof Error ? error.message : "unknown error"}`);
  });
  process.exitCode = status;
}

try {
  await main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "session archive import failed"}\n`);
  process.exitCode = error instanceof CliError ? error.exitCode : 1;
}
