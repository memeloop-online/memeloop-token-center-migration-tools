/** Canonical tools-owned patch; never modify the product repository or schema. */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { archiveRuntimePin, fileDigest } from "../lib/session-archive-runtime.ts";
const source = resolve(process.argv[2] ?? ".runtime-source");
const patch = resolve("ops/runtime-patches/large-record-v1.patch");
const git = (...args: string[]): string => execFileSync("git", args, { cwd: source, encoding: "utf8" }).trim();
if (git("rev-parse", "HEAD") !== archiveRuntimePin.revision
    || fileDigest(resolve(source, "Cargo.lock")) !== archiveRuntimePin.cargo_lock_sha256
    || fileDigest(patch) !== archiveRuntimePin.source_patch_sha256) throw new Error("archive runtime patch provenance mismatch");
if (process.argv[3] !== "--verify") {
  if (git("status", "--porcelain") !== "") throw new Error("archive runtime source must be clean before patching");
  git("apply", "--check", patch);
  git("apply", patch);
}
const expected = JSON.parse(readFileSync("ops/runtime-patches/large-record-v1-files.json", "utf8")) as Record<string, string>;
if (git("diff", "HEAD", "--name-only").split("\n").sort().join("\n") !== Object.keys(expected).sort().join("\n")
    || Object.entries(expected).some(([file, digest]) => fileDigest(resolve(source, file)) !== digest)
    || git("ls-files", "--others", "--exclude-standard") !== "") throw new Error("archive runtime patched source mismatch");
