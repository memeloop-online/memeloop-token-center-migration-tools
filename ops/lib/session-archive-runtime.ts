import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";

export const archiveRuntimePin = {
  repository: "memeloop-online/memeloop-token-center",
  revision: "a65097f952e174ac482abe6ff719966fa9d330cb",
  cargo_lock_sha256: "2134ac15927c1beaceed75d52e48312b6bb93db072c43df4c557cad7de23e029",
  rust_version: "1.95.0",
  target: "x86_64-unknown-linux-gnu",
} as const;

export function fileDigest(path: string): string {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("runtime file must be regular");
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** No PATH fallback, network fetch, build, or execution before manifest validation. */
export function verifiedArchiveRuntime(binary: string): string {
  try {
    if (!isAbsolute(binary) || lstatSync(binary).isSymbolicLink()) throw new Error("runtime path must be absolute and regular");
    // Resolve directory aliases before both validation and execution. Callers
    // must spawn this return value, never the original user-supplied spelling.
    binary = realpathSync(binary);
    const manifestPath = join(dirname(binary), "compatibility.json");
    const stat = lstatSync(manifestPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16384) throw new Error("manifest invalid");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    if (basename(binary) !== "import-cpa-session-archive"
      || manifest.format_version !== 1 || manifest.binary !== "import-cpa-session-archive"
      || manifest.source_archive !== "source.tar" || manifest.cli_contract !== "session-archive-import-v1"
      || manifest.build_os !== "ubuntu-24.04" || manifest.minimum_glibc !== "2.39"
      || manifest.schema_policy !== "engine-read-only-schema-precondition"
      || manifest.source_closure_extracted !== false
      || JSON.stringify(manifest.archive_schema_versions) !== "[1,2]"
      || Object.entries(archiveRuntimePin).some(([key, value]) => manifest[key] !== value)
      || !/^[0-9a-f]{64}$/.test(String(manifest.binary_sha256))
      || !/^[0-9a-f]{64}$/.test(String(manifest.source_archive_sha256))
      || fileDigest(binary) !== manifest.binary_sha256
      || fileDigest(join(dirname(binary), "source.tar")) !== manifest.source_archive_sha256
      || (lstatSync(binary).mode & 0o111) === 0) throw new Error("runtime identity invalid");
    return binary;
  } catch {
    // Do not include paths, manifest contents, child environment or raw errors.
    throw new Error("session archive runtime verification failed");
  }
}
