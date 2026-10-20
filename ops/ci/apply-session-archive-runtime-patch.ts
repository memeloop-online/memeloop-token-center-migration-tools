import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { archiveRuntimePin, fileDigest } from "../lib/session-archive-runtime.ts";

const source = resolve(process.argv[2] ?? ".runtime-source");
if (process.env.GITHUB_ACTIONS !== "true") throw new Error("archive source assembly is CI-only");
const closure = resolve("ops/runtime-engine");
const manifestPath = resolve("ops/runtime-patches/schema130-files.json");
const git = (...args: string[]): string => execFileSync("git", args, { cwd: source, encoding: "utf8" }).trim();
if (git("rev-parse", "HEAD") !== archiveRuntimePin.revision
  || fileDigest(resolve(source, "Cargo.lock")) !== archiveRuntimePin.cargo_lock_sha256
  || fileDigest(manifestPath) !== archiveRuntimePin.source_closure_sha256) {
  throw new Error("archive runtime source provenance mismatch");
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
  base_files: Record<string, string>;
  files: Record<string, string>;
};
const walk = (directory: string, prefix = ""): string[] => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
  const path = `${prefix}${entry.name}`;
  if (entry.isDirectory()) return walk(resolve(directory, entry.name), `${path}/`);
  if (!entry.isFile()) throw new Error("archive closure must contain regular files only");
  return [path];
});
const closureFiles = walk(closure);
if ([...Object.keys(manifest.base_files), ...Object.keys(manifest.files)].some(path => !/^(?:src|tests)\/[a-zA-Z0-9_./-]+\.rs$/u.test(path) || path.includes(".."))
  || closureFiles.some(path => !(path in manifest.files) || fileDigest(resolve(closure, path)) !== manifest.files[path])
  || Object.keys(manifest.files).filter(path => !(path in manifest.base_files)).some(path => !closureFiles.includes(path))) {
  throw new Error("archive runtime closure integrity mismatch");
}
if (process.argv[3] !== "--verify") {
  if (git("status", "--porcelain") !== ""
    || Object.entries(manifest.base_files).some(([path, digest]) => fileDigest(resolve(source, path)) !== digest)) {
    throw new Error("archive runtime base must be clean and exact");
  }
  for (const path of closureFiles) {
    const destination = resolve(source, path);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(resolve(closure, path), destination);
  }
  const append = (path: string, text: string): void => {
    writeFileSync(resolve(source, path), `${readFileSync(resolve(source, path), "utf8")}\n${text}\n`);
  };
  append("src/lib.rs", "pub mod session_archive_import;");
  append("src/db/requests/mod.rs", `mod session_archive;
mod session_archive_commit;
mod session_archive_quarantine;
pub(crate) use session_archive::valid_archive_identifier;
pub use session_archive::*;
pub use session_archive_commit::*;
pub use session_archive_quarantine::*;`);
  append("src/db/mod.rs", `mod session_archive_projection;
pub(crate) use requests::valid_archive_identifier;
pub(crate) use session_archive_projection::add_archive_record_to_session_projection_in_transaction;
pub use requests::{
    SessionArchiveCommitInput, SessionArchiveCorrelation, SessionArchiveImportLock,
    SessionArchiveImportMatch, SessionArchiveImportMatchInput, SessionArchiveLegacyCheckpointInput,
    SessionArchiveMatchInput, SessionArchivePresentSummaryInput,
    SessionArchiveQuarantineBatchInput, SessionArchiveQuarantineCommitInput,
    SessionArchiveQuarantineFilter, SessionArchiveQuarantineRecordView,
    SessionArchiveQuarantineResolutionInput, SessionArchiveQuarantineResolutionView,
    SessionArchiveQuarantineTarget, SessionArchiveSnapshotApplyInput,
    SessionArchiveSnapshotApplyResult, SessionArchiveSnapshotChainInput, SessionArchiveTarget,
    SessionArchiveTombstoneInput, SessionArchiveUnlinkedCommitInput,
    SessionArchiveUnlinkedMetadata, SessionArchiveUnlinkedTarget,
};`);
}
const changed = [...git("diff", "HEAD", "--name-only").split("\n"), ...git("ls-files", "--others", "--exclude-standard").split("\n")].filter(Boolean).sort();
if (changed.join("\n") !== Object.keys(manifest.files).sort().join("\n")
  || Object.entries(manifest.files).some(([path, digest]) => fileDigest(resolve(source, path)) !== digest)) {
  throw new Error("archive runtime assembled source mismatch");
}
