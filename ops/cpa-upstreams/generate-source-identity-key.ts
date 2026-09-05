#!/usr/bin/env node
/** Create a versioned source-identity key without exposing key material. */

import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, parse, resolve, sep } from "node:path";
import { randomBytes } from "node:crypto";

const KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const KEY_PAYLOAD_BYTES = 32;
const TEMP_NAME_ATTEMPTS = 16;

class GenerationFailure extends Error {}

function openSafeParent(target: string): number {
  if (!isAbsolute(target) || target === parse(target).root || resolve(target) !== target) {
    throw new GenerationFailure("target key file path must be absolute and normalized");
  }
  const parent = dirname(target);
  const root = parse(parent).root;
  let current = root;
  let descriptor: number | undefined;
  try {
    for (const component of parent.slice(root.length).split(sep).filter(Boolean)) {
      current = resolve(current, component);
      const metadata = lstatSync(current);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new Error("unsafe directory");
      }
    }
    descriptor = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    const effectiveUid = process.geteuid?.();
    if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
        (effectiveUid !== undefined && metadata.uid !== effectiveUid) ||
        (metadata.mode & 0o022) !== 0) {
      closeSync(descriptor); descriptor = undefined; throw new Error("unsafe directory");
    }
    return descriptor;
  } catch {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* fail closed below */ }
    throw new GenerationFailure("target parent directory is not safe");
  }
}

export function generate(pathValue: string): void {
  const parentDescriptor = openSafeParent(pathValue);
  const anchoredParent = `/proc/self/fd/${parentDescriptor}`;
  const target = `${anchoredParent}/${basename(pathValue)}`;
  let document = Buffer.alloc(0);
  let temporary: string | undefined;
  let descriptor: number | undefined;
  try {
    try { document = Buffer.concat([KEY_PREFIX, randomBytes(KEY_PAYLOAD_BYTES)]); }
    catch { throw new GenerationFailure("cryptographic random generation is unavailable"); }
    for (let attempt = 0; attempt < TEMP_NAME_ATTEMPTS; attempt += 1) {
      const candidate = `${anchoredParent}/.mtc-source-identity-key-${randomBytes(16).toString("hex")}.tmp`;
      try {
        descriptor = openSync(
          candidate,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
        temporary = candidate;
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new GenerationFailure("target key file could not be created safely");
        }
      }
    }
    if (descriptor === undefined || temporary === undefined) {
      throw new GenerationFailure("target key file could not be created safely");
    }
    let offset = 0;
    while (offset < document.length) {
      const written = writeSync(descriptor, document, offset);
      if (written <= 0) throw new Error("short write");
      offset += written;
    }
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, target);
    unlinkSync(temporary);
    temporary = undefined;
    fsyncSync(parentDescriptor);
  } catch (error) {
    if (error instanceof GenerationFailure) throw error;
    throw new GenerationFailure("target key file could not be created safely");
  } finally {
    document.fill(0);
    let cleanupFailure: GenerationFailure | undefined;
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { cleanupFailure = new GenerationFailure("temporary key file could not be closed safely"); }
    }
    if (temporary !== undefined) {
      try { unlinkSync(temporary); fsyncSync(parentDescriptor); } catch { cleanupFailure = new GenerationFailure("temporary key file could not be removed safely"); }
    }
    try { closeSync(parentDescriptor); } catch { cleanupFailure ??= new GenerationFailure("target parent directory could not be closed safely"); }
    if (cleanupFailure) throw cleanupFailure;
  }
}

function usage(): never {
  process.stdout.write(
    "usage: generate-source-identity-key <output>\n\n" +
    "Generate a protected CPA migration source-identity key.\n\n" +
    "positional arguments:\n  output  New absolute output path in a current-user-owned safe directory.\n",
  );
  process.exit(0);
}

function main(argv: string[]): void {
  if (argv.includes("--help") || argv.includes("-h")) usage();
  if (argv.length !== 1) {
    process.stderr.write("usage: generate-source-identity-key <output>\n");
    process.exitCode = 2;
    return;
  }
  try {
    generate(argv[0]!);
  } catch (error) {
    const message = error instanceof GenerationFailure ? error.message : "cryptographic random generation is unavailable";
    process.stderr.write(`Source identity key generation stopped: ${message}\n`);
    process.exitCode = 2;
  }
}

if (basename(process.argv[1] ?? "").replace(/\.(?:ts|[cm]?js)$/, "") === "generate-source-identity-key") main(process.argv.slice(2));
