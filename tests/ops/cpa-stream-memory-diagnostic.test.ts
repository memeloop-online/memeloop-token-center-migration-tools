import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { chownSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { MEMORY_DIAGNOSTIC } from "../../ops/lib/cpa-stream.ts";
import { job, policies } from "../../ops/cpa-stream-resources.ts";

test("diagnostic resources have only private RAM and unchanged role-selector networking", () => {
  for (const role of ["reader", "receiver"] as const) {
    const rendered = JSON.parse(JSON.stringify(job(role, role === "reader" ? "10.42.3.2" : undefined, "diagnostic")));
    const pod = rendered.spec.template.spec;
    assert.equal(rendered.spec.suspend, true);
    assert.equal(rendered.spec.backoffLimit, 0);
    assert.equal(rendered.spec.activeDeadlineSeconds, 1800);
    assert.equal(pod.automountServiceAccountToken, false);
    assert.ok(pod.volumes.every((volume: { emptyDir?: { medium: string }; configMap?: unknown }) => volume.emptyDir?.medium === "Memory" || volume.configMap));
    assert.deepEqual(pod.containers[0].command, ["node", "/tool/cpa-frozen-stream-copy.ts", `diagnostic-${role}`]);
    assert.equal(pod.containers[0].resources.limits.memory, "128Mi");
    assert.equal(pod.containers[0].resources.limits.cpu, "250m");
    assert.equal(JSON.stringify(rendered).includes("persistentVolumeClaim"), false);
    assert.equal(JSON.stringify(rendered).includes("hostPath"), false);
    assert.equal(JSON.stringify(rendered).includes("secretName"), false);
  }
  const diagnosticPolicies = JSON.stringify(policies("diagnostic")).replaceAll("diagnostic-", "").replaceAll("20261006a", "20261005a");
  assert.equal(diagnosticPolicies, JSON.stringify(policies()));
});

test("real staged diagnostic CLI transfers RAM payload with each role capped at 128Mi and 250m", { timeout: 180000 }, () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.getuid!(), 0);
  const image = "ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126";
  const prefix = `cpa-memory-${process.pid}-${Date.now()}`;
  const directory = mkdtempSync("/dev/shm/cpa-memory-gha-");
  const identityDirectory = `/dev/shm/${MEMORY_DIAGNOSTIC.run}`;
  const containers: string[] = [];
  let ownIdentity = false;
  let ownNetwork = false;
  const docker = (args: string[], input?: string) => {
    const result = spawnSync("docker", args, { encoding: "utf8", input, timeout: 90000 });
    assert.equal(result.status, 0, result.stderr);
    return (args[0] === "logs" ? result.stdout + result.stderr : result.stdout).trim();
  };
  try {
    const generated = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", "create-diagnostic"], { encoding: "utf8" });
    assert.equal(generated.status, 0, generated.stderr);
    ownIdentity = true;
    mkdirSync(`${directory}/source`, { mode: 0o755 });
    mkdirSync(`${directory}/destination`, { mode: 0o755 });
    const destination = `${directory}/destination/recovery-diagnostic-20261006a`;
    mkdirSync(destination, { mode: 0o700 });
    chownSync(destination, 10001, 10001);
    const source = `${directory}/source/archive.sqlite`;
    writeFileSync(source, Buffer.alloc(MEMORY_DIAGNOSTIC.size, 71), { flag: "wx", mode: 0o400 });
    chownSync(source, 10001, 10001);
    docker(["network", "create", "--internal", "--subnet", "10.42.3.0/24", prefix]);
    ownNetwork = true;
    for (const role of ["receiver", "reader"] as const) {
      const termination = `${directory}/${role}-termination.json`;
      writeFileSync(termination, "", { flag: "wx", mode: 0o600 });
      chownSync(termination, 10001, 10001);
      chmodSync(termination, 0o600);
      const name = `${prefix}-${role}`;
      const address = role === "receiver" ? "10.42.3.2" : "10.42.3.3";
      containers.push(name);
      docker(["run", "--detach", "--name", name, "--network", prefix, "--ip", address,
        "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/identity:rw,noexec,nosuid,size=4m,uid=10001,gid=10001,mode=0700",
        "--volume", `${resolve("ops")}:/tool:ro`, "--volume", `${termination}:/dev/termination-log:rw`,
        "--volume", role === "receiver" ? `${directory}/destination:/destination:rw` : `${directory}/source:/source:ro`,
        "--env", `NODE_NAME=${role === "receiver" ? "westlake" : "sansheng-hv"}`,
        "--env", `POD_NAME=mtc-cpa-stream-diagnostic-${role}-20261006a-gha`, "--env", `POD_IP=${address}`,
        "--env", "CPA_RECEIVER_IP=10.42.3.2", "--entrypoint", "node", image, "/tool/cpa-frozen-stream-copy.ts", `diagnostic-${role}`]);
      docker(["exec", "--interactive", name, "node", "/tool/cpa-frozen-stream-copy.ts", `stage-diagnostic-${role}`], readFileSync(`${identityDirectory}/${role}.json`, "utf8"));
    }
    const receipts = [];
    for (const role of ["reader", "receiver"] as const) {
      const name = `${prefix}-${role}`;
      const exitCode = docker(["wait", name]);
      assert.equal(exitCode, "0", docker(["logs", name]));
      const inspected = JSON.parse(docker(["inspect", name]))[0];
      assert.equal(inspected.State.OOMKilled, false);
      assert.equal(inspected.HostConfig.Memory, 128 * 1024 ** 2);
      assert.equal(inspected.HostConfig.MemorySwap, 128 * 1024 ** 2);
      assert.equal(inspected.HostConfig.NanoCpus, 250000000);
      const { role: receiptRole, ...receipt } = JSON.parse(readFileSync(`${directory}/${role}-termination.json`, "utf8"));
      assert.equal(receiptRole, role);
      assert.equal(receipt.passed, true);
      assert.equal(receipt.bytes, MEMORY_DIAGNOSTIC.size);
      assert.equal(receipt.sha256, MEMORY_DIAGNOSTIC.sha256);
      receipts.push(receipt);
    }
    assert.deepEqual(receipts[0], receipts[1]);
    assert.deepEqual(JSON.parse(readFileSync(`${destination}/copy-receipt.json`, "utf8")), receipts[0]);
  } finally {
    for (const container of containers) spawnSync("docker", ["rm", "--force", container], { stdio: "ignore" });
    if (ownNetwork) spawnSync("docker", ["network", "rm", prefix], { stdio: "ignore" });
    if (ownIdentity) rmSync(identityDirectory, { recursive: true });
    rmSync(directory, { recursive: true });
  }
});
