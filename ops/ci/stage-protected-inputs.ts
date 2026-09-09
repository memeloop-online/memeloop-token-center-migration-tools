#!/usr/bin/env node
/**
 * Stage mounted migration inputs without a shell or a writable secret path.
 *
 * The init container normally runs this command as root so that the resulting
 * files can be owned by the non-root migration process.  A non-root test or
 * same-identity invocation may preserve its current ownership. Inputs are
 * copied through an O_NOFOLLOW descriptor, never overwritten, and re-checked after the copy.
 * A checkpoint is only chmod/chowned in place after its inode and link count
 * have been checked; it is never created by this helper.
 */

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  chownSync,
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fchownSync,
  fsyncSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { BigIntStats } from "node:fs";
import { dirname, extname, isAbsolute, join } from "node:path";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";

const DEFAULT_UID = 10001;
const DEFAULT_GID = 10001;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const PRIVATE_MODE = 0o600n;
const SOURCE_MODE_MASK = 0o077n;

type BigFileStat = BigIntStats;

type CopyRequest = Readonly<{ source: string; target: string }>;
type AuthDirectoryRequest = Readonly<{ source: string; target: string }>;

type Arguments = Readonly<{
  copies: readonly CopyRequest[];
  authDirectories: readonly AuthDirectoryRequest[];
  excludedAuthSubdirectories: readonly string[];
  checkpoint?: string;
  checkpointRequired: boolean;
  uid: number;
  gid: number;
  maxBytes: number;
}>;

class StageError extends Error {}

function fail(message: string): never {
  throw new StageError(message);
}

function usage(): string {
  return [
    "usage: stage-protected-inputs [options]",
    "",
    "  --copy SOURCE TARGET       copy one owner-only input (repeatable)",
    "  --copy-auth-dir SOURCE TARGET",
    "                             recursively copy only 0600 JSON auth files",
    "  --exclude-auth-subdir PATH  skip one exact reviewed auth subdirectory (repeatable)",
    "  --checkpoint PATH          fence an existing checkpoint, if present",
    "  --checkpoint-required      fail when PATH does not exist",
    "  --target-uid UID           destination owner (default: 10001)",
    "  --target-gid GID           destination group (default: 10001)",
    "  --max-bytes BYTES          per-input copy limit (default: 67108864)",
    "  --help                     print this message",
  ].join("\n");
}

function unsigned(value: string, label: string, maximum: number): number {
  if (!/^\d+$/.test(value)) fail(`${label} must be an unsigned decimal integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) fail(`${label} is out of range`);
  return parsed;
}

function pathValue(value: string, label: string): string {
  if (value.includes("\0") || !isAbsolute(value)) fail(`${label} must be an absolute path`);
  return value;
}

function preserveCurrentOwnership(uid: number, gid: number): boolean {
  const currentUid = process.getuid?.();
  const currentGid = process.getgid?.();
  return currentUid !== undefined && currentGid !== undefined && currentUid === uid && currentGid === gid;
}

function fchownRequested(fd: number, uid: number, gid: number): void {
  if (!preserveCurrentOwnership(uid, gid)) fchownSync(fd, uid, gid);
}

function chownRequested(path: string, uid: number, gid: number): void {
  if (!preserveCurrentOwnership(uid, gid)) chownSync(path, uid, gid);
}

function nextValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("--")) fail(`${option} requires a value`);
  return value;
}

function parseCopy(argv: readonly string[], index: number, option: string): { request: CopyRequest; next: number } {
  const source = pathValue(nextValue(argv, index, option), "copy source");
  const target = pathValue(nextValue(argv, index + 1, option), "copy target");
  return { request: { source, target }, next: index + 3 };
}

export function parseArguments(argv: readonly string[]): Arguments {
  const copies: CopyRequest[] = [];
  const authDirectories: AuthDirectoryRequest[] = [];
  const excludedAuthSubdirectories: string[] = [];
  let checkpoint: string | undefined;
  let checkpointRequired = false;
  let uid = DEFAULT_UID;
  let gid = DEFAULT_GID;
  let maxBytes = DEFAULT_MAX_BYTES;

  for (let index = 0; index < argv.length;) {
    const argument = argv[index]!;
    if (argument === "--help" || argument === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (argument === "--copy" || argument === "--input") {
      const parsed = parseCopy(argv, index, argument);
      copies.push(parsed.request);
      index = parsed.next;
      continue;
    }
    if (argument === "--copy-auth-dir" || argument === "--auth-dir") {
      const source = pathValue(nextValue(argv, index, argument), "auth source directory");
      const target = pathValue(nextValue(argv, index + 1, argument), "auth target directory");
      authDirectories.push({ source, target });
      index += 3;
      continue;
    }
    if (argument.startsWith("--copy-auth-dir=") || argument.startsWith("--auth-dir=")) {
      const value = argument.slice(argument.indexOf("=") + 1);
      const separator = value.indexOf("=");
      if (separator <= 0 || separator === value.length - 1) fail(`${argument.slice(0, argument.indexOf("="))} requires SOURCE=TARGET`);
      authDirectories.push({
        source: pathValue(value.slice(0, separator), "auth source directory"),
        target: pathValue(value.slice(separator + 1), "auth target directory"),
      });
      index += 1;
      continue;
    }
    if (argument.startsWith("--copy=") || argument.startsWith("--input=")) {
      const value = argument.slice(argument.indexOf("=") + 1);
      const separator = value.indexOf("=");
      if (separator <= 0 || separator === value.length - 1) fail(`${argument.slice(0, argument.indexOf("="))} requires SOURCE=TARGET`);
      copies.push({
        source: pathValue(value.slice(0, separator), "copy source"),
        target: pathValue(value.slice(separator + 1), "copy target"),
      });
      index += 1;
      continue;
    }
    if (argument === "--exclude-auth-subdir") {
      excludedAuthSubdirectories.push(relativeDirectory(nextValue(argv, index, argument)));
      index += 2;
      continue;
    }
    if (argument.startsWith("--exclude-auth-subdir=")) {
      excludedAuthSubdirectories.push(relativeDirectory(argument.slice("--exclude-auth-subdir=".length)));
      index += 1;
      continue;
    }
    if (argument === "--checkpoint") {
      checkpoint = pathValue(nextValue(argv, index, argument), "checkpoint");
      index += 2;
      continue;
    }
    if (argument.startsWith("--checkpoint=")) {
      checkpoint = pathValue(argument.slice("--checkpoint=".length), "checkpoint");
      index += 1;
      continue;
    }
    if (argument === "--checkpoint-required") {
      checkpointRequired = true;
      index += 1;
      continue;
    }
    if (argument === "--target-uid" || argument === "--target-gid" || argument === "--max-bytes") {
      const value = nextValue(argv, index, argument);
      const parsed = argument === "--max-bytes"
        ? unsigned(value, argument, Number.MAX_SAFE_INTEGER)
        : unsigned(value, argument, 0xffff_ffff);
      if (argument === "--target-uid") uid = parsed;
      else if (argument === "--target-gid") gid = parsed;
      else maxBytes = parsed;
      index += 2;
      continue;
    }
    if (argument.startsWith("--target-uid=") || argument.startsWith("--target-gid=") || argument.startsWith("--max-bytes=")) {
      const separator = argument.indexOf("=");
      const option = argument.slice(0, separator);
      const value = argument.slice(separator + 1);
      const parsed = option === "--max-bytes"
        ? unsigned(value, option, Number.MAX_SAFE_INTEGER)
        : unsigned(value, option, 0xffff_ffff);
      if (option === "--target-uid") uid = parsed;
      else if (option === "--target-gid") gid = parsed;
      else maxBytes = parsed;
      index += 1;
      continue;
    }
    fail(`unknown argument: ${argument}`);
  }

  if (copies.length === 0 && authDirectories.length === 0 && checkpoint === undefined) fail("at least one --copy, --copy-auth-dir, or --checkpoint is required");
  if (excludedAuthSubdirectories.length > 0 && authDirectories.length === 0) fail("--exclude-auth-subdir requires --copy-auth-dir");
  if (new Set(excludedAuthSubdirectories).size !== excludedAuthSubdirectories.length) fail("duplicate --exclude-auth-subdir is not allowed");
  const destinations = new Set<string>();
  for (const copy of copies) {
    if (destinations.has(copy.target)) fail(`duplicate destination: ${copy.target}`);
    destinations.add(copy.target);
  }
  for (const directory of authDirectories) {
    if (destinations.has(directory.target)) fail(`duplicate destination: ${directory.target}`);
    destinations.add(directory.target);
  }
  return { copies, authDirectories, excludedAuthSubdirectories, checkpoint, checkpointRequired, uid, gid, maxBytes };
}

function relativeDirectory(value: string): string {
  if (value.length === 0 || value.includes("\0") || value.includes("\\") || value.includes("*")) fail("excluded auth subdirectory must be a normalized relative path");
  const parts = value.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === ".." || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(part))) {
    fail("excluded auth subdirectory must be a normalized relative path");
  }
  return parts.join("/");
}

function asBigFileStat(path: string, label: string): BigFileStat {
  try {
    return lstatSync(path, { bigint: true }) as BigFileStat;
  } catch {
    fail(`${label} is unavailable`);
  }
}

function privateRegular(stat: BigFileStat, label: string): void {
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (stat.nlink !== 1n) fail(`${label} must have exactly one hard link`);
  if ((stat.mode & SOURCE_MODE_MASK) !== 0n) fail(`${label} must not be group/other accessible`);
}

function sameFile(left: BigFileStat, right: BigFileStat): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink;
}

function descriptorStat(fd: number, label: string): BigFileStat {
  try {
    return fstatSync(fd, { bigint: true }) as BigFileStat;
  } catch {
    fail(`${label} could not be inspected`);
  }
}

function safeSystemErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,31}$/.test(code) ? code : undefined;
}

function failSystemStage(error: unknown): never {
  const code = safeSystemErrorCode(error);
  fail(code === undefined ? "protected input staging failed" : `protected input staging failed (${code})`);
}

function openSource(path: string): { fd: number; stat: BigFileStat } {
  const listed = asBigFileStat(path, "source input");
  privateRegular(listed, "source input");
  let fd = -1;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = descriptorStat(fd, "source input");
    privateRegular(opened, "source input");
    if (!sameFile(listed, opened)) fail("source input changed while opening");
    return { fd, stat: opened };
  } catch (error) {
    if (fd >= 0) closeSync(fd);
    if (error instanceof StageError) throw error;
    fail("source input could not be opened safely");
  }
}

function assertParent(path: string, label: string): void {
  const parent = dirname(path);
  const stat = asBigFileStat(parent, `${label} parent`);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} parent must be a regular directory`);
}

function assertDestination(path: string, uid: number, gid: number, label: string): BigFileStat {
  const stat = asBigFileStat(path, label);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (stat.nlink !== 1n) fail(`${label} must have exactly one hard link`);
  if ((stat.mode & 0o777n) !== PRIVATE_MODE) fail(`${label} must have mode 0600`);
  if (stat.uid !== BigInt(uid) || stat.gid !== BigInt(gid)) fail(`${label} has an unexpected owner`);
  return stat;
}

function copyProtectedFile(request: CopyRequest, uid: number, gid: number, maxBytes: number): void {
  assertParent(request.target, "copy target");
  try {
    const existing = lstatSync(request.target, { bigint: true });
    if (existing) fail(`refusing to overwrite copy target: ${request.target}`);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }

  const source = openSource(request.source);
  let targetFd = -1;
  const temporary = `${request.target}.stage-${process.pid}-${randomBytes(12).toString("hex")}`;
  try {
    targetFd = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    fchmodSync(targetFd, 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (true) {
      const length = readSync(source.fd, buffer, 0, buffer.length, null);
      if (length === 0) break;
      total += length;
      if (total > maxBytes) fail(`source input exceeds the ${maxBytes}-byte copy limit`);
      let offset = 0;
      while (offset < length) offset += writeSync(targetFd, buffer, offset, length - offset);
    }
    fchmodSync(targetFd, 0o600);
    fsyncSync(targetFd);
    const copied = descriptorStat(targetFd, "staged input");
    if (!copied.isFile() || copied.nlink !== 1n || (copied.mode & 0o777n) !== PRIVATE_MODE) {
      fail("staged input could not be fenced");
    }
    const sourceAfter = descriptorStat(source.fd, "source input");
    if (!sameFile(source.stat, sourceAfter)) fail("source input changed while copying");

    // link+unlink gives a no-overwrite publish: rename would replace a path
    // created by a concurrent actor, while link fails atomically with EEXIST.
    // Keep the temporary file owned by the root staging process until the
    // link exists. On Linux with protected_hardlinks=1, a root process limited
    // to CAP_CHOWN cannot link a 0600 file after it has been chowned to the
    // non-root consumer. The retained descriptor then fences the published
    // inode's final ownership without adding CAP_FOWNER or CAP_DAC_OVERRIDE.
    linkSync(temporary, request.target);
    fchownRequested(targetFd, uid, gid);
    fsyncSync(targetFd);
    unlinkSync(temporary);
    const published = descriptorStat(targetFd, "staged input");
    if (!published.isFile() || published.nlink !== 1n || (published.mode & 0o777n) !== PRIVATE_MODE || published.uid !== BigInt(uid) || published.gid !== BigInt(gid)) {
      fail("staged input could not be fenced");
    }
    const publishedPath = assertDestination(request.target, uid, gid, "staged input");
    if (!sameFile(published, publishedPath)) fail("staged input changed after publication");
    closeSync(targetFd);
    targetFd = -1;
  } catch (error) {
    if (error instanceof StageError) throw error;
    failSystemStage(error);
  } finally {
    if (targetFd >= 0) closeSync(targetFd);
    try { unlinkSync(temporary); } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    }
    closeSync(source.fd);
  }
}

function privateDirectory(path: string, label: string): BigFileStat {
  const stat = asBigFileStat(path, label);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink directory`);
  if ((stat.mode & 0o777n) !== 0o700n) fail(`${label} must have mode 0700`);
  return stat;
}

function createPrivateDirectory(path: string, label: string): void {
  assertParent(path, label);
  try {
    const existing = lstatSync(path, { bigint: true });
    if (existing) fail(`refusing to overwrite ${label}: ${path}`);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  mkdirSync(path, { mode: 0o700 });
  privateDirectory(path, label);
}

function fencePrivateDirectory(path: string, uid: number, gid: number, label: string): void {
  try {
    chownRequested(path, uid, gid);
    const stat = privateDirectory(path, label);
    if (stat.uid !== BigInt(uid) || stat.gid !== BigInt(gid)) fail(`${label} has an unexpected owner`);
  } catch (error) {
    if (error instanceof StageError) throw error;
    failSystemStage(error);
  }
}

type AuthTreeResult = Readonly<{
  copiedFiles: number;
  excludedDirectories: number;
  matchedExclusions: ReadonlySet<string>;
}>;

function copyAuthTree(
  source: string,
  target: string,
  uid: number,
  gid: number,
  maxBytes: number,
  label: string,
  relativePath: string,
  exclusions: ReadonlySet<string>,
): AuthTreeResult {
  privateDirectory(source, `${label} source`);
  // Keep a newly created 0700 directory owned by the root staging process
  // until every child is published. With only CAP_CHOWN, root cannot search or
  // create in a directory already handed to the non-root consumer. Recursion
  // therefore fences each directory post-order, without adding DAC/FOWNER.
  createPrivateDirectory(target, label);
  let copiedFiles = 0;
  let excludedDirectories = 0;
  const matchedExclusions = new Set<string>();
  for (const entry of readdirSync(source, { withFileTypes: true })) {
    const sourcePath = join(source, entry.name);
    const targetPath = join(target, entry.name);
    const childRelativePath = relativePath.length === 0 ? entry.name : `${relativePath}/${entry.name}`;
    const stat = asBigFileStat(sourcePath, `${label} entry`);
    if (stat.isSymbolicLink()) fail(`${label} contains a symbolic link`);
    if (stat.isDirectory()) {
      if (exclusions.has(childRelativePath)) {
        privateDirectory(sourcePath, `${label}/${entry.name} excluded source`);
        excludedDirectories += 1;
        matchedExclusions.add(childRelativePath);
        continue;
      }
      const result = copyAuthTree(sourcePath, targetPath, uid, gid, maxBytes, `${label}/${entry.name}`, childRelativePath, exclusions);
      copiedFiles += result.copiedFiles;
      excludedDirectories += result.excludedDirectories;
      for (const matched of result.matchedExclusions) matchedExclusions.add(matched);
      continue;
    }
    if (!stat.isFile() || extname(entry.name).toLowerCase() !== ".json") fail(`${label} contains a non-JSON entry`);
    if ((stat.mode & 0o777n) !== PRIVATE_MODE || stat.nlink !== 1n) fail(`${label} JSON entries must be mode 0600 regular files with one link`);
    copyProtectedFile({ source: sourcePath, target: targetPath }, uid, gid, maxBytes);
    copiedFiles += 1;
  }
  fencePrivateDirectory(target, uid, gid, label);
  return { copiedFiles, excludedDirectories, matchedExclusions };
}

function fenceCheckpoint(path: string, uid: number, gid: number, required: boolean): boolean {
  let before: BigFileStat;
  try {
    before = lstatSync(path, { bigint: true }) as BigFileStat;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      if (required) fail("required checkpoint is unavailable");
      return false;
    }
    fail("checkpoint could not be inspected");
  }
  if (!before.isFile() || before.isSymbolicLink()) fail("checkpoint must be a regular non-symlink file");
  if (before.nlink !== 1n) fail("checkpoint must have exactly one hard link");
  chmodSync(path, 0o600);
  chownRequested(path, uid, gid);
  let descriptor = -1;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const after = descriptorStat(descriptor, "checkpoint");
    if (after.dev !== before.dev || after.ino !== before.ino || after.nlink !== 1n) fail("checkpoint changed while being fenced");
    if ((after.mode & 0o777n) !== PRIVATE_MODE || after.uid !== BigInt(uid) || after.gid !== BigInt(gid)) fail("checkpoint owner/mode fence failed");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
  return true;
}

export function main(argv = process.argv.slice(2)): number {
  const args = parseArguments(argv);
  const currentUid = process.getuid?.();
  const currentGid = process.getgid?.();
  if (currentUid !== undefined && currentUid !== 0 && (args.uid !== currentUid || (currentGid !== undefined && args.gid !== currentGid))) {
    fail("stage-protected-inputs must run as root when changing ownership");
  }
  for (const copy of args.copies) copyProtectedFile(copy, args.uid, args.gid, args.maxBytes);
  let authFileCount = 0;
  let excludedDirectoryCount = 0;
  const matchedExclusions = new Set<string>();
  const exclusions = new Set(args.excludedAuthSubdirectories);
  for (const directory of args.authDirectories) {
    const result = copyAuthTree(directory.source, directory.target, args.uid, args.gid, args.maxBytes, "auth directory", "", exclusions);
    authFileCount += result.copiedFiles;
    excludedDirectoryCount += result.excludedDirectories;
    for (const matched of result.matchedExclusions) matchedExclusions.add(matched);
  }
  for (const exclusion of exclusions) if (!matchedExclusions.has(exclusion)) fail("requested auth exclusion directory was not found");
  const checkpointPresent = args.checkpoint === undefined ? false : fenceCheckpoint(args.checkpoint, args.uid, args.gid, args.checkpointRequired);
  process.stdout.write(`${JSON.stringify({ auth_file_count: authFileCount, checkpoint_present: checkpointPresent, copied_count: args.copies.length, excluded_directory_count: excludedDirectoryCount, target_gid: args.gid, target_uid: args.uid })}\n`);
  return 0;
}

if (invokedAsEntrypoint("stage-protected-inputs", import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof StageError ? error.message : "protected-input staging failed"}\n`);
    process.exitCode = 2;
  }
}
