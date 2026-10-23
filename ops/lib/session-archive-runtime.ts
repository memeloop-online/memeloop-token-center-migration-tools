import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";

export const archiveRuntimePin = {
  repository: "memeloop-online/memeloop-token-center",
  revision: "072769105392e7d24a12dc4780fa16ab6a01d1e7",
  cargo_lock_sha256: "8bf18924e7cead74d2532d3d9674bc72101fa89fdda48d7da1b7205b2507ee30",
  source_closure_sha256: "ab933bf9921a0ff458333ec16f40680a32d9ff16cf6a49a8e35fbf6de8d57459",
  target_schema_version: 132,
  test_fixture_repository: "memeloop-online/memeloop-token-center-example-plugins",
  test_fixture_revision: "21489f4fee6266de99fe7e258349468ce77af8bd",
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
      || manifest.source_closure_extracted !== true
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

/** Resolve only the packaged, executable SQLite backup runtime. */
export function verifiedSessionArchiveBackupRuntime(binary: string): string {
  try {
    if (!isAbsolute(binary)) throw new Error("runtime path must be absolute");
    const stat = lstatSync(binary);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
      throw new Error("runtime must be a regular executable file");
    }
    binary = realpathSync(binary);
    if (basename(binary) !== "cpa-session-archive-backup") throw new Error("runtime name invalid");
    const resolved = lstatSync(binary);
    if (!resolved.isFile() || resolved.isSymbolicLink() || (resolved.mode & 0o111) === 0) {
      throw new Error("resolved runtime must be a regular executable file");
    }
    return binary;
  } catch {
    throw new Error("session archive backup runtime verification failed");
  }
}
