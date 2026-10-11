import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { chownSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { MEMORY_DIAGNOSTIC, SEGMENTED_DIAGNOSTIC, STREAM_PROFILES, streamResourceName } from "../../ops/lib/cpa-stream.ts";
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

test("segmented generator fixes RAM-only 4x4MiB, original resource limits and exact SNAT ingress", () => {
  assert.equal(SEGMENTED_DIAGNOSTIC.size, 4 * 4 * 1024 ** 2);
  assert.equal(SEGMENTED_DIAGNOSTIC.chunk, 4 * 1024 ** 2);
  assert.equal(SEGMENTED_DIAGNOSTIC.rate, 64 * 1024 ** 2);
  assert.equal(SEGMENTED_DIAGNOSTIC.totalMs, 120000);
  for (const role of ["reader", "receiver"] as const) {
    const rendered = JSON.parse(JSON.stringify(job(role, "10.42.8.2", "segmented")));
    const pod = rendered.spec.template.spec;
    assert.equal(rendered.spec.activeDeadlineSeconds, 120);
    assert.equal(rendered.spec.backoffLimit, 0);
    assert.equal(rendered.spec.suspend, true);
    assert.equal(pod.nodeSelector["kubernetes.io/hostname"], role === "reader" ? "sansheng-hv" : "versetensor-hv");
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.hostNetwork, undefined);
    assert.deepEqual(pod.containers[0].resources.limits, { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" });
    assert.ok(pod.volumes.every((volume: any) => volume.emptyDir?.medium === "Memory" || volume.configMap));
    assert.equal(pod.volumes.find((volume: any) => volume.name === (role === "reader" ? "source" : "destination")).emptyDir.sizeLimit, "32Mi");
    for (const forbidden of ["persistentVolumeClaim", "hostPath", "secretName", "mtc-session-archive", "mtc-cpa-recovery-work"]) assert.equal(JSON.stringify(rendered).includes(forbidden), false);
    assert.deepEqual(pod.containers[0].command, ["node", "/tool/cpa-frozen-stream-copy.ts", `segmented-${role}`]);
    if (role === "reader") assert.equal(pod.containers[0].volumeMounts.find((mount: any) => mount.name === "source").readOnly, true);
  }
  const expected = JSON.stringify(policies("versetensor")).replaceAll("versetensor-20261011b", "segmented-20261011a").replaceAll("versetensor-reader", "segmented-reader").replaceAll("versetensor-receiver", "segmented-receiver").replaceAll("20261011b", "20261011a");
  assert.equal(JSON.stringify(policies("segmented")), expected);
});

for (const profile of ["diagnostic", "segmented"] as const) test(`real staged ${profile} CLI transfers RAM payload with each role capped at 128Mi and 250m`, { timeout: 180000 }, () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.getuid!(), 0);
  const image = "ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126";
  const prefix = `cpa-memory-${process.pid}-${Date.now()}`;
  const directory = mkdtempSync("/dev/shm/cpa-memory-gha-");
  const selected = STREAM_PROFILES[profile];
  const plan = selected.plan;
  const identityDirectory = `/dev/shm/${plan.run}`;
  const containers: string[] = [];
  let ownIdentity = false;
  let ownNetwork = false;
  const docker = (args: string[], input?: string) => {
    const result = spawnSync("docker", args, { encoding: "utf8", input, timeout: 90000 });
    assert.equal(result.status, 0, result.stderr);
    return (args[0] === "logs" ? result.stdout + result.stderr : result.stdout).trim();
  };
  try {
    const generated = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", `create-${profile}`], { encoding: "utf8", timeout: 60000 });
    assert.equal(generated.status, 0, generated.stderr);
    ownIdentity = true;
    mkdirSync(`${directory}/source`, { mode: 0o755 });
    mkdirSync(`${directory}/destination`, { mode: 0o755 });
    const destination = `${directory}${plan.destination}`;
    mkdirSync(destination, { mode: 0o700 });
    chownSync(destination, 10001, 10001);
    const source = `${directory}/source/archive.sqlite`;
    writeFileSync(source, Buffer.alloc(plan.size, 71), { flag: "wx", mode: 0o400 });
    chownSync(source, 10001, 10001);
    docker(["network", "create", "--internal", "--subnet", `${selected.receiverSubnet}.0/24`, prefix]);
    ownNetwork = true;
    for (const role of ["receiver", "reader"] as const) {
      const termination = `${directory}/${role}-termination.json`;
      writeFileSync(termination, "", { flag: "wx", mode: 0o600 });
      chownSync(termination, 10001, 10001);
      chmodSync(termination, 0o600);
      const name = `${prefix}-${role}`;
      const address = `${selected.receiverSubnet}.${role === "receiver" ? 2 : 3}`;
      containers.push(name);
      docker(["run", "--detach", "--name", name, "--network", prefix, "--ip", address,
        "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/identity:rw,noexec,nosuid,size=4m,uid=10001,gid=10001,mode=0700",
        "--volume", `${resolve("ops")}:/tool:ro`, "--volume", `${termination}:/dev/termination-log:rw`,
        "--volume", role === "receiver" ? `${directory}/destination:/destination:rw` : `${directory}/source:/source:ro`,
        "--env", `NODE_NAME=${role === "receiver" ? selected.receiverNode : "sansheng-hv"}`,
        "--env", `POD_NAME=${streamResourceName(role, profile)}-gha`, "--env", `POD_IP=${address}`,
        "--env", `CPA_RECEIVER_IP=${selected.receiverSubnet}.2`, "--entrypoint", "node", image, "/tool/cpa-frozen-stream-copy.ts", `${profile}-${role}`]);
      docker(["exec", "--interactive", name, "node", "/tool/cpa-frozen-stream-copy.ts", `stage-${profile}-${role}`], readFileSync(`${identityDirectory}/${role}.json`, "utf8"));
    }
    const receipts = [];
    const traces: unknown[] = [];
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
      assert.equal(receipt.bytes, plan.size);
      assert.equal(receipt.sha256, plan.sha256);
      const lines = docker(["logs", name]).split("\n").filter(Boolean).map((line) => JSON.parse(line));
      const trace = lines.filter((line) => line.stage === "segment-trace");
      assert.equal(trace.length, profile === "segmented" ? 22 : 0);
      if (profile === "segmented") {
        for (const event of trace) {
          assert.deepEqual(Object.keys(event).sort(), ["durationMs", "elapsedMs", "phase", "role", "run", "segment", "stage"]);
          assert.equal(event.run, plan.run);
          assert.equal(event.role, role);
          assert.ok(Number.isFinite(event.durationMs) && event.durationMs >= 0);
          assert.ok(Number.isFinite(event.elapsedMs) && event.elapsedMs >= 0 && event.elapsedMs < 120000);
          assert.ok(Buffer.byteLength(JSON.stringify(event)) < 512);
        }
        const phases = role === "reader" ? ["frame-start", "read-hash", "throttle", "frame-write", "ack-read"] : ["frame-start", "frame-read", "write-hash", "throttle", "ack-write"];
        for (let segment = 1; segment <= 4; segment++) assert.deepEqual(trace.filter((event) => event.segment === segment).map((event) => event.phase), phases);
        assert.equal(lines.filter((line) => line.listening === true).length, role === "receiver" ? 1 : 0);
        traces.push(...trace);
      }
      receipts.push(receipt);
    }
    assert.deepEqual(receipts[0], receipts[1]);
    assert.deepEqual(JSON.parse(readFileSync(`${destination}/copy-receipt.json`, "utf8")), receipts[0]);
    if (profile === "segmented" && process.env.RUNNER_TEMP) writeFileSync(`${process.env.RUNNER_TEMP}/cpa-stream-segmented-trace-result.json`, JSON.stringify({ revision: process.env.GITHUB_SHA, synthetic: true, pvc: false, bytes: plan.size, trace: traces, receipts }, null, 2));
  } finally {
    for (const container of containers) spawnSync("docker", ["rm", "--force", container], { stdio: "ignore", timeout: 15000 });
    if (ownNetwork) spawnSync("docker", ["network", "rm", prefix], { stdio: "ignore", timeout: 15000 });
    if (ownIdentity) rmSync(identityDirectory, { recursive: true });
    rmSync(directory, { recursive: true });
  }
});
