import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { chownSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAllDocuments } from "yaml";

test("review-only target probe uses pinned dd direct I/O under 128Mi/250m, never another file", { timeout: 210000 }, () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.getuid!(), 0);
  const [policy, job] = parseAllDocuments(readFileSync("ops/inspection/cpa-work-directio-20261006a.yaml", "utf8")).map((document) => document.toJSON());
  assert.deepEqual(policy.spec.ingress, []);
  assert.deepEqual(policy.spec.egress, []);
  assert.equal(job.spec.suspend, true);
  assert.equal(job.spec.backoffLimit, 0);
  assert.equal(job.spec.activeDeadlineSeconds + job.spec.template.spec.terminationGracePeriodSeconds, 180);
  const pod = job.spec.template.spec;
  assert.equal(pod.nodeSelector["kubernetes.io/hostname"], "sansheng-hv");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(pod.volumes, [{ name: "destination", persistentVolumeClaim: { claimName: "mtc-cpa-recovery-work-20261005" } }]);
  const runtime = pod.containers[0];
  assert.deepEqual(runtime.resources.limits, { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" });
  assert.ok(runtime.args[0].includes("oflag=direct conv=notrunc,fsync"));
  assert.ok(runtime.args[0].includes("iflag=direct"));
  const root = mkdtempSync(join(tmpdir(), "cpa-directio-gha-"));
  chmodSync(root, 0o755);
  const directory = join(root, "perf-directio-20261006a");
  const name = `cpa-directio-${process.pid}-${Date.now()}`;
  const retained = join(root, "old.partial");
  mkdirSync(directory, { mode: 0o700 });
  chownSync(directory, 10001, 10001);
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
