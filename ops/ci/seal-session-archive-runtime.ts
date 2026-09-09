/** CI-only packaging: consume a locked, already built product checkout. */
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { archiveRuntimePin, fileDigest, verifiedArchiveRuntime } from "../lib/session-archive-runtime.ts";

const source = resolve(process.argv[2] ?? ".runtime-source");
const output = resolve("dist/release/commands/runtime");
const revision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
if (revision !== archiveRuntimePin.revision
  || fileDigest(resolve(source, "Cargo.lock")) !== archiveRuntimePin.cargo_lock_sha256
  || execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: source, encoding: "utf8" }).trim() !== ""
  || !execFileSync("rustc", ["--version"], { encoding: "utf8" }).startsWith(`rustc ${archiveRuntimePin.rust_version} `)) {
  throw new Error("archive runtime build provenance mismatch");
}
mkdirSync(output, { recursive: true });
const binary = resolve(output, "import-cpa-session-archive");
copyFileSync(resolve(source, "target/release/import-cpa-session-archive"), binary);
chmodSync(binary, 0o755);
execFileSync("git", ["archive", "--format=tar", `--output=${resolve(output, "source.tar")}`, revision], { cwd: source });
writeFileSync(resolve(output, "compatibility.json"), `${JSON.stringify({
  format_version: 1,
  ...archiveRuntimePin,
  binary: "import-cpa-session-archive",
  binary_sha256: fileDigest(binary),
  source_archive: "source.tar",
  source_archive_sha256: fileDigest(resolve(output, "source.tar")),
  cli_contract: "session-archive-import-v1",
  build_os: "ubuntu-24.04",
  minimum_glibc: "2.39",
  schema_policy: "engine-read-only-schema-precondition",
  archive_schema_versions: [1, 2],
  source_closure_extracted: false,
}, null, 2)}\n`, { mode: 0o644, flag: "wx" });
const verifiedBinary = verifiedArchiveRuntime(binary);
const help = execFileSync(verifiedBinary, ["--help"], { encoding: "utf8", timeout: 10000 });
for (const flag of ["--input", "--plan-directory", "--apply", "--max-plan-bytes", "--archive-source", "--cpamp-source"]) {
  if (!help.includes(flag)) throw new Error("archive runtime CLI contract mismatch");
}
