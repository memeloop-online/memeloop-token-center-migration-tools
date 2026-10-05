import assert from "node:assert/strict";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { parse } from "yaml";

const manifest = parse(readFileSync(new URL("../../ops/inspection/cpa-recovery-copy-20261005.yaml", import.meta.url), "utf8"));
const script: string = manifest.spec.template.spec.initContainers[0].args[0];

function run(directory: string) {
  const program = script.replace("'/destination/recovery-20261005'", JSON.stringify(directory))
    .replace("const targetUid = 10001;", `const targetUid = ${process.getuid!()};`)
    .replace("const targetGid = 10001;", `const targetGid = ${process.getgid!()};`);
  return spawnSync(process.execPath, ["--input-type=module", "-e", program], { encoding: "utf8" });
}

test("copy directory init accepts a previously initialized private directory without changing it", () => {
  const root = mkdtempSync(join(tmpdir(), "copy-directory-"));
  const directory = join(root, "destination");
  try {
    assert.equal(run(directory).status, 0);
    const before = lstatSync(directory, { bigint: true });
    assert.equal(run(directory).status, 0);
    const after = lstatSync(directory, { bigint: true });
    assert.equal(after.ino, before.ino);
    assert.equal(after.ctimeNs, before.ctimeNs);
    assert.equal(after.mode & 0o7777n, 0o700n);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("copy directory init refuses a symlink, a file, wrong owner, or non-private mode without repairs", () => {
  const root = mkdtempSync(join(tmpdir(), "copy-directory-"));
  try {
    const target = join(root, "target");
    mkdirSync(target, { mode: 0o700 });
    const link = join(root, "link");
    symlinkSync(target, link);
    assert.equal(run(link).status, 1);
    assert.ok(lstatSync(link).isSymbolicLink());
    const file = join(root, "file");
    writeFileSync(file, "retained", { mode: 0o600 });
    assert.equal(run(file).status, 1);
    assert.equal(readFileSync(file, "utf8"), "retained");
    chmodSync(target, 0o750);
    assert.equal(run(target).status, 1);
    assert.equal(lstatSync(target).mode & 0o7777, 0o750);
    chmodSync(target, 0o700);
    const wrongOwnerProgram = script.replace("'/destination/recovery-20261005'", JSON.stringify(target))
      .replace("const targetUid = 10001;", `const targetUid = ${process.getuid!() + 1};`);
    const before = lstatSync(target, { bigint: true });
    assert.equal(spawnSync(process.execPath, ["--input-type=module", "-e", wrongOwnerProgram]).status, 1);
    assert.equal(lstatSync(target, { bigint: true }).ctimeNs, before.ctimeNs);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
