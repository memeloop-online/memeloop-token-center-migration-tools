import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
export { invokedAsEntrypoint } from "../../ops/lib/invoked-as-entrypoint.ts";
export { parseStrictJson } from "../../ops/lib/strict-json.ts";

type JsonObject = Record<string, unknown>;
export type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;

const MAX_COLLECTION_ITEMS = 10_000;
const MAX_IDENTITY_KEY_BYTES = 64 * 1024;
const SOURCE_IDENTITY_KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const SOURCE_IDENTITY_KEY_BYTES = 32;

export class SealedSourceIOFailure extends Error {
  constructor() { super("sealed source I/O validation failed"); }
}

function fail(): never { throw new SealedSourceIOFailure(); }

function readBoundedDescriptor(descriptor: number, limit: number): Buffer {
  const buffer = Buffer.allocUnsafe(limit + 1);
  let offset = 0;
  try {
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset > limit) fail();
    return Buffer.from(buffer.subarray(0, offset));
  } finally {
    buffer.fill(0);
  }
}

export function readOwnerOnly(path: string, _label: string, limit: number): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600
      || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())
      || stat.nlink !== 1) fail();
    return readBoundedDescriptor(descriptor, limit);
  } catch (error) {
    if (error instanceof SealedSourceIOFailure) throw error;
    fail();
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function authFiles(root: string): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  const visit = (directory: string): void => {
    try {
      const stat = lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700
        || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) fail();
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name);
        const child = lstatSync(path);
        if (child.isSymbolicLink()) fail();
        if (child.isDirectory()) visit(path);
        else if (child.isFile()) {
          if (!entry.name.toLowerCase().endsWith(".json")) fail();
          found.push([relative(root, path).split(sep).join("/"), path]);
        } else fail();
      }
    } catch (error) {
      if (error instanceof SealedSourceIOFailure) throw error;
      fail();
    }
  };
  visit(root);
  found.sort(([left], [right]) => left.localeCompare(right, "en"));
  if (found.length > MAX_COLLECTION_ITEMS) fail();
  return found;
}

function object(value: unknown): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") fail();
  return value as JsonObject;
}

export function canonicalJson(value: unknown, _label: string, depth = 0): string {
  if (depth > 32) fail();
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_COLLECTION_ITEMS) fail();
    return `[${value.map((item) => canonicalJson(item, "value", depth + 1)).join(",")}]`;
  }
  const record = object(value);
  const keys = Object.keys(record).sort((left, right) => left.localeCompare(right, "en"));
  if (keys.length > MAX_COLLECTION_ITEMS) fail();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], "value", depth + 1)}`).join(",")}}`;
}

export function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) fail();
  const directory = resolve(dirname(path));
  const filesystemRoot = parse(directory).root;
  let current = filesystemRoot;
  for (const part of relative(filesystemRoot, directory).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { fail(); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail();
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()
      || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid())
      || (metadata.mode & 0o022) !== 0) fail();
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try {
      lstatSync(target);
      fail();
    } catch (error) {
      if (error instanceof SealedSourceIOFailure) throw error;
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) fail();
    }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof SealedSourceIOFailure) throw error;
    fail();
  }
}

export function writeBindingReceipt(output: OutputTarget, receipt: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < receipt.length;) {
      const written = writeSync(descriptor, receipt, offset, receipt.length - offset);
      if (written <= 0) fail();
      offset += written;
    }
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, output.target);
    unlinkSync(temporary);
    const metadata = lstatSync(output.target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
      || (metadata.mode & 0o777) !== 0o600) fail();
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch { /* best-effort cleanup */ }
    if (error instanceof SealedSourceIOFailure) throw error;
    fail();
  }
}

export function readSourceIdentityKey(path: string): Buffer {
  if (!isAbsolute(path)) fail();
  const value = readOwnerOnly(path, "source identity key", MAX_IDENTITY_KEY_BYTES);
  try {
    if (value.length !== SOURCE_IDENTITY_KEY_PREFIX.length + SOURCE_IDENTITY_KEY_BYTES
      || !timingSafeEqual(value.subarray(0, SOURCE_IDENTITY_KEY_PREFIX.length), SOURCE_IDENTITY_KEY_PREFIX)) fail();
    const payload = Buffer.from(value.subarray(SOURCE_IDENTITY_KEY_PREFIX.length));
    if (payload.every((byte) => byte === payload[0])) {
      payload.fill(0);
      fail();
    }
    return payload;
  } finally {
    value.fill(0);
  }
}
