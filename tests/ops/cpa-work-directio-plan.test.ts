import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { chownSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, lstatSync, symlinkSync, linkSync, renameSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAllDocuments } from "yaml";
import { PROBE_BUDGET, probeBudget, type ProbeObservation } from "../../ops/inspection/cpa-work-probe-budget.ts";
import "./cpa-work-probe-operator.test.ts";
import { DIRECTIO_FILESYSTEM } from "../../ops/inspection/cpa-work-directio-filesystem.ts";

test("independent startup and execution budgets, fresh observations and total-priority clocks", () => {
  const identity = { jobUid: "job-uid", podUid: "pod-uid", pvcUid: "pvc-uid" };
  const start = Date.parse("2026-10-09T09:00:00Z");
  const at = (seconds: number) => new Date(start + seconds * 1000).toISOString();
  const pending: ProbeObservation = { ...identity, jobResourceVersion: "1", podResourceVersion: "2", pvcResourceVersion: "3", ownerUid: identity.jobUid, claimName: "mtc-cpa-recovery-work-20261005", attemptStartedAt: at(0), collectionStartedAt: at(0), observedAt: at(0), initFailed: false, jobFailed: false, podPhase: "Pending", state: null, writeStarted: false, complete: false };
  const evaluate = (o: ProbeObservation, seconds: number) => probeBudget({ ...o, collectionStartedAt: at(seconds), observedAt: at(seconds) }, identity, start + seconds * 1000);
  const late = evaluate(pending, 300);
  assert.equal(late.status, "STARTUP_DEADLINE");
  assert.equal(late.bytes, null);
  assert.equal(late.execElapsedMs, null);
  assert.equal(late.execDeadline, null);
  assert.equal(late.stopRequired, true);
  assert.deepEqual(late.cleanupIdentity, identity);
  assert.equal(evaluate({ ...pending, initFailed: true }, 10).status, "STARTUP_FAILED");
  assert.equal(evaluate({ ...pending, podPhase: "Failed" }, 10).status, "STARTUP_FAILED");
  assert.equal(evaluate(pending, 299.999).status, "STARTING");
  assert.equal(probeBudget({ ...pending, podUid: null, podResourceVersion: null, ownerUid: null }, { ...identity, podUid: null }, start).status, "STARTING");
  const running = { ...pending, podPhase: "Running", state: { running: { startedAt: at(180) } } };
  const begun = evaluate(running, 181);
  assert.equal(begun.status, "EXECUTING");
  assert.equal(begun.execElapsedMs, 1000);
  assert.equal(begun.execDeadline, start + 180_000 + PROBE_BUDGET.execMs);
  assert.equal(evaluate(running, 344.999).status, "EXECUTING");
  assert.equal(evaluate(running, 345).status, "EXEC_DEADLINE");
  for (const observation of [pending, running, { ...pending, initFailed: true }, { ...running, state: { running: { startedAt: at(301) } } }]) assert.equal(evaluate(observation, 480).status, "TOTAL_DEADLINE");
  assert.equal(evaluate({ ...running, state: { running: { startedAt: at(300) } } }, 300).status, "STARTUP_DEADLINE");
  assert.equal(evaluate({ ...running, state: { running: { startedAt: at(0) } } }, 165).status, "EXEC_DEADLINE");
  const done = { ...running, podPhase: "Succeeded", writeStarted: true, complete: true, state: { terminated: { startedAt: at(180), finishedAt: at(344), exitCode: 0 } } };
  assert.equal(evaluate(done, 344).status, "COMPLETE");
  assert.equal(evaluate(done, 344).bytes, 1024 ** 3);
  assert.equal(evaluate({ ...done, complete: false, state: { terminated: { startedAt: at(180), finishedAt: at(344), exitCode: 1 } } }, 344).status, "EXEC_FAILED");
  assert.throws(() => evaluate({ ...done, writeStarted: false }, 344), /MISSING_WRITE_START/);
  assert.throws(() => probeBudget(running, identity, start + 181_000), /STALE_OBSERVATION/);
  assert.throws(() => evaluate({ ...pending, state: { terminated: { finishedAt: at(-1), exitCode: 1 } } }, 10), /INVALID_EXEC_END/);
  assert.throws(() => evaluate({ ...done, state: { terminated: { startedAt: at(180), finishedAt: at(179), exitCode: 0 } } }, 344), /INVALID_EXEC_END/);
  assert.throws(() => evaluate({ ...done, state: { terminated: { startedAt: at(180), finishedAt: at(345), exitCode: 0 } } }, 344), /INVALID_EXEC_END/);
  assert.throws(() => evaluate({ ...pending, attemptStartedAt: "invalid" }, 10), /INVALID_TIMESTAMP/);
  assert.throws(() => probeBudget(pending, { ...identity, podUid: "replacement" }, start + 1000), /IDENTITY_MISMATCH/);
  assert.throws(() => probeBudget({ ...pending, ownerUid: "other-job" }, identity, start + 1000), /RESOURCE_IDENTITY_MISSING/);
  assert.throws(() => probeBudget({ ...pending, claimName: "frozen-original" }, identity, start + 1000), /TARGET_MISMATCH/);
});

test("review-only target probe uses pinned dd direct I/O under 128Mi/250m, never another file", { timeout: 210000 }, () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.getuid!(), 0);
  const [policy, job] = parseAllDocuments(readFileSync("ops/inspection/cpa-work-directio-20261006a.yaml", "utf8")).map((document) => document.toJSON());
  assert.deepEqual(policy.spec.ingress, []);
  assert.deepEqual(policy.spec.egress, []);
  assert.equal(job.spec.suspend, true);
  assert.equal(job.spec.backoffLimit, 0);
  assert.equal(job.spec.activeDeadlineSeconds + job.spec.template.spec.terminationGracePeriodSeconds, 485);
  assert.equal(Number(job.metadata.annotations["memeloop.io/startup-budget-seconds"]) * 1000, PROBE_BUDGET.startupMs);
  assert.equal(Number(job.metadata.annotations["memeloop.io/exec-budget-seconds"]) * 1000, PROBE_BUDGET.execMs);
  assert.equal(job.spec.activeDeadlineSeconds * 1000, PROBE_BUDGET.totalMs);
  assert.ok(PROBE_BUDGET.totalMs >= PROBE_BUDGET.startupMs + PROBE_BUDGET.execMs + PROBE_BUDGET.freshnessMs + PROBE_BUDGET.pollMs);
  assert.equal(job.spec.template.spec.activeDeadlineSeconds, job.spec.activeDeadlineSeconds);
  const pod = job.spec.template.spec;
  assert.equal(pod.nodeSelector["kubernetes.io/hostname"], "sansheng-hv");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(pod.volumes, [{ name: "destination", persistentVolumeClaim: { claimName: "mtc-cpa-recovery-work-20261005" } }]);
  const runtime = pod.containers[0];
  assert.deepEqual(runtime.resources.limits, { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" });
  assert.ok(runtime.args[0].includes("oflag=direct") && runtime.args[0].includes("conv=notrunc,fsync"));
  assert.ok(runtime.args[0].includes("iflag=direct"));
  const root = mkdtempSync(join(tmpdir(), "cpa-directio-gha-"));
  chmodSync(root, 0o755);
  const directory = join(root, "perf-directio-20261006a");
  const name = `cpa-directio-${process.pid}-${Date.now()}`;
  const retained = join(root, "old.partial");
  const init = pod.initContainers[0];
  const initialization = spawnSync("docker", ["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges", "--user", "0:0", "--volume", `${root}:/destination:rw`, "--entrypoint", init.command[0], init.image, ...init.command.slice(1), ...init.args], { encoding: "utf8", timeout: 10000 });
  assert.equal(initialization.status, 0, initialization.stderr);
  assert.ok(initialization.stdout.includes("DIRECTORY_READY"));
  const reuse = spawnSync("docker", ["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges", "--user", "0:0", "--volume", `${root}:/destination:rw`, "--entrypoint", init.command[0], init.image, ...init.command.slice(1), ...init.args], { encoding: "utf8", timeout: 10000 });
  assert.equal(reuse.status, 0, reuse.stderr);
  writeFileSync(retained, "preserve old partial", { flag: "wx" });
  let passed = false;
  try {
    const result = spawnSync("docker", ["run", "--name", name, "--network", "none", "--read-only", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--volume", `${root}:/destination:rw`, "--entrypoint", runtime.command[0], runtime.image, ...runtime.command.slice(1), ...runtime.args], { encoding: "utf8", timeout: 180000 });
    const inspection = spawnSync("docker", ["inspect", name], { encoding: "utf8" });
    assert.equal(inspection.status, 0, inspection.stderr);
    const state = JSON.parse(inspection.stdout)[0];
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(state.State.OOMKilled, false);
    assert.equal(state.HostConfig.Memory, 128 * 1024 ** 2);
    assert.equal(state.HostConfig.MemorySwap, 128 * 1024 ** 2);
    assert.equal(state.HostConfig.NanoCpus, 250000000);
    assert.ok(result.stdout.includes("DIRECTIO_COMPLETE"));
    assert.equal(existsSync(join(directory, "probe.bin")), false);
    assert.equal(readFileSync(retained, "utf8"), "preserve old partial");
    passed = true;
    console.log(JSON.stringify({ passed, image: runtime.image, testedCommit: process.env.GITHUB_SHA, bytes: 1024 ** 3, stdout: result.stdout, stderr: result.stderr }));
  } finally {
    spawnSync("docker", ["rm", "--force", name], { stdio: "ignore" });
    if (process.env.RUNNER_TEMP) writeFileSync(join(process.env.RUNNER_TEMP, "cpa-work-directio-command-result.json"), JSON.stringify({ passed, image: runtime.image, testedCommit: process.env.GITHUB_SHA, bytes: 1024 ** 3 }) + "\n");
    rmSync(root, { recursive: true });
  }
});


test("reusable original directory handles absence, empty and owned 0644 leftover, rejects malicious entries and replacement", () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.getuid!(), 0);
  const helper = DIRECTIO_FILESYSTEM;
  const [, job] = parseAllDocuments(readFileSync("ops/inspection/cpa-work-directio-20261006a.yaml", "utf8")).map((doc) => doc.toJSON());
  for (const role of ["initContainers", "containers"]) assert.ok(job.spec.template.spec[role][0].args[0].startsWith(helper));
  for (const mode of ["missing", "empty", "leftover", "symlink-dir", "symlink-file", "hardlink", "foreign", "unrelated", "dir-replacement", "file-replacement"]) {
    const root = mkdtempSync(join(tmpdir(), "cpa-init-fixture-"));
    const directory = join(root, "perf-directio-20261006a"), file = join(directory, "probe.bin"), retained = join(root, "old.partial");
    writeFileSync(retained, "retained", {flag:"wx"});
    try {
      if (mode === "symlink-dir") symlinkSync(root, directory);
      else if (mode !== "missing") { mkdirSync(directory, {mode:0o700}); chownSync(directory,10001,10001); }
      if (["leftover", "hardlink", "foreign", "file-replacement"].includes(mode)) { writeFileSync(file,"synthetic",{mode:0o644}); if (mode !== "foreign") chownSync(file,10001,10001); }
      if (mode === "symlink-file") symlinkSync(retained,file);
      if (mode === "hardlink") linkSync(file,join(root,"alias"));
      if (mode === "unrelated") writeFileSync(join(directory,"old.partial"),"real data");
      const injection = mode === "dir-replacement" ? `const h = openDirectory(${JSON.stringify(root)}, false); renameSync(${JSON.stringify(directory)},${JSON.stringify(directory + "-held")}); mkdirSync(${JSON.stringify(directory)}, {mode:0o700}); h.check();`
        : mode === "file-replacement" ? `const h = openDirectory(${JSON.stringify(root)}, false); const original = lstatSync(h.file); renameSync(h.file,${JSON.stringify(join(directory,"saved"))}); writeFileSync(h.file,'unrelated'); chownSync(h.file,10001,10001); removeKnown(h, original);`
        : `initialize(${JSON.stringify(root)});`;
      const result = spawnSync(process.execPath,["--input-type=module","-e", helper + "\nimport {renameSync, writeFileSync, chownSync} from 'node:fs';\n" + injection],{encoding:"utf8",timeout:5000});
      const valid = ["missing","empty","leftover"].includes(mode);
      assert.equal(result.status === 0, valid, mode + result.stderr);
      assert.equal(readFileSync(retained,"utf8"),"retained");
      if (valid) { assert.equal(lstatSync(directory).uid,10001); assert.deepEqual(readdirSync(directory),[]); assert.ok(result.stdout.includes("SYNTHETIC_ABSENT")); }
      if (mode === "leftover") assert.ok(result.stdout.includes("SYNTHETIC_REMOVED"));
      if (mode === "file-replacement") assert.equal(readFileSync(file,"utf8"),"unrelated");
      if (mode === "hardlink") assert.equal(readFileSync(join(root,"alias"),"utf8"),"synthetic");
      if (mode === "unrelated") assert.equal(readFileSync(join(directory,"old.partial"),"utf8"),"real data");
    } finally { rmSync(root,{recursive:true,force:true}); }
  }
});
