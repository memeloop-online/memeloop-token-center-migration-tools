import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chownSync, chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { setTimeout as pause } from "node:timers/promises";
import { COPY, SAME_NODE_COPY, streamResourceName } from "../../ops/lib/cpa-stream.ts";

const image = "ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126";
const maximumMemory = 128 * 1024 ** 2;
type Result = {
  kind: string; role: string; memoryLimit: number; swapLimit: number; cpu: number; memoryPeak: number; maxRSS: number;
  receipt: { run: string; passed: boolean; bytes: number; sha256: string };
  samples: { at: number; position: number; rss: number }[];
};

async function command(binary: string, args: string[], timeout = 30000): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const child = spawn(binary, args, { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let bytes = 0;
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("fixture command deadline")); }, timeout);
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 2 * 1024 ** 2) { child.kill("SIGKILL"); reject(new Error("fixture output limit")); }
      output += chunk.toString("utf8");
    });
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => { clearTimeout(timer); code === 0 ? resolve(output) : reject(new Error(`fixture command failed (${code})`)); });
  });
}

for (const profile of ["original", "same-node"] as const) test(`${profile}: two isolated 128Mi/no-swap containers stream 256Mi with bounded read-ahead under receiver backpressure`, { timeout: 480000 }, async () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true", "GHA only; do not run this test locally");
  assert.equal(process.getuid!(), 0, "GHA fixture ownership setup requires root, not privileged role containers");
  const sameNode = profile === "same-node";
  const selected = sameNode ? SAME_NODE_COPY : COPY;
  const identityDirectory = `/dev/shm/${selected.run}`;
  const root = mkdtempSync(join(tmpdir(), "cpa-bounded-fixture-"));
  const network = `cpa-fixture-${process.pid}-${Date.now()}`;
  const receiverName = `${network}-receiver`;
  const readerName = `${network}-reader`;
  const names: string[] = [];
  let ownNetwork = false;
  let ownIdentity = false;
  const report: Record<string, unknown> = { passed: false, profile, run: selected.run, testedCommit: process.env.GITHUB_SHA, bytes: 256 * 1024 ** 2 };
  try {
    await command("docker", ["pull", image], 120000);
    await command(process.execPath, ["ops/cpa-stream-identity.ts", sameNode ? "create-same-node" : "create"]);
    ownIdentity = true;
    for (const role of ["reader", "receiver"]) chownSync(`${identityDirectory}/${role}.json`, 10001, 10001);
    const sourceRoot = join(root, "source");
    const workRoot = join(root, "work");
    const destination = join(workRoot, selected.destination.split("/").at(-1)!);
    mkdirSync(sourceRoot, { mode: 0o755 });
    mkdirSync(workRoot, { mode: 0o700 });
    mkdirSync(destination, { mode: 0o700 });
    chownSync(workRoot, 10001, 10001);
    chownSync(destination, 10001, 10001);
    const fixturePath = join(sourceRoot, "archive.sqlite");
    const descriptor = openSync(fixturePath, "wx", 0o600);
    const chunk = Buffer.alloc(1024 ** 2, 71);
    const digest = createHash("sha256");
    try {
      for (let index = 0; index < 256; index++) {
        let offset = 0;
        while (offset < chunk.length) offset += writeSync(descriptor, chunk, offset, chunk.length - offset);
        digest.update(chunk);
      }
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
    chownSync(fixturePath, 10001, 10001);
    chmodSync(fixturePath, 0o400);
    const before = lstatSync(fixturePath, { bigint: true });
    const expected = { size: 256 * 1024 ** 2, sha256: digest.digest("hex") };
    const metadata = join(root, "fixture.json");
    writeFileSync(metadata, JSON.stringify(expected), { flag: "wx", mode: 0o644 });
    await command("docker", ["network", "create", "--internal", ...(sameNode ? ["--subnet", "10.42.2.0/24"] : []), network]);
    ownNetwork = true;
    const launch = async (role: "reader" | "receiver", name: string) => {
      names.push(name);
      await command("docker", [
        "run", "--detach", "--name", name, "--network", network, "--network-alias", role,
        ...(sameNode ? ["--ip", role === "receiver" ? "10.42.2.2" : "10.42.2.3", "--env", "CPA_GHA_PROFILE=same-node", "--env", "NODE_NAME=sansheng-hv", "--env", `POD_NAME=${streamResourceName(role, profile)}-gha`, "--env", `POD_IP=${role === "receiver" ? "10.42.2.2" : "10.42.2.3"}`, "--env", "CPA_RECEIVER_IP=10.42.2.2", "--tmpfs", "/identity:rw,noexec,nosuid,size=4m,uid=10001,gid=10001,mode=0700"] : []),
        "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001",
        "--env", "CPA_GHA_FIXTURE=1", "--entrypoint", sameNode ? "sh" : "node",
        "--mount", `type=bind,source=${resolve("ops")},target=/tool/ops,readonly`,
        "--mount", `type=bind,source=${resolve("tests/ops/cpa-stream-bounded-role.ts")},target=/tool/tests/ops/cpa-stream-bounded-role.ts,readonly`,
        "--mount", `type=bind,source=${metadata},target=/fixture.json,readonly`,
        "--mount", `type=bind,source=${identityDirectory}/${role}.json,target=/identity.json,readonly`,
        "--mount", role === "reader" ? `type=bind,source=${sourceRoot},target=/source,readonly` : `type=bind,source=${workRoot},target=/destination`,
        image, ...(sameNode ? ["-ec", `node /tool/ops/cpa-frozen-stream-copy.ts stage-same-node-${role} < /identity.json; exec node /tool/tests/ops/cpa-stream-bounded-role.ts ${role}`] : ["/tool/tests/ops/cpa-stream-bounded-role.ts", role]),
      ]);
    };
    await launch("receiver", receiverName);
    const waiting = Date.now();
    while (!(await command("docker", ["logs", receiverName])).includes('"kind":"fixture-listening"')) {
      assert.ok(Date.now() - waiting < 20000, "fixture receiver readiness deadline");
      const state = JSON.parse(await command("docker", ["inspect", receiverName]));
      assert.equal(state[0].State.Running, true, "fixture receiver exited before listen");
      await pause(250);
    }
    await launch("reader", readerName);
    const exits = await Promise.all([receiverName, readerName].map((name) => command("docker", ["wait", name], 330000)));
    const results: Result[] = [];
    const states: unknown[] = [];
    for (const name of [receiverName, readerName]) {
      const inspection = JSON.parse(await command("docker", ["inspect", name]))[0];
      states.push({ name, state: inspection.State, memory: inspection.HostConfig.Memory, swap: inspection.HostConfig.MemorySwap, nanoCpus: inspection.HostConfig.NanoCpus });
      const records = (await command("docker", ["logs", name])).trim().split("\n").filter((line) => line.startsWith("{")).map((line) => JSON.parse(line) as Result);
      const result = records.find((record) => record.kind === "bounded-result");
      if (result) results.push(result);
      report.states = states;
      report.results = results;
      assert.equal(inspection.HostConfig.Memory, maximumMemory);
      assert.equal(inspection.HostConfig.MemorySwap, maximumMemory);
      assert.equal(inspection.HostConfig.NanoCpus, 250000000);
      assert.equal(inspection.State.OOMKilled, false, "bounded role must not be OOM-killed");
      assert.equal(inspection.State.ExitCode, 0, "bounded role must exit successfully");
      assert.ok(result, "bounded result missing");
      assert.equal(result.memoryLimit, maximumMemory);
      assert.equal(result.swapLimit, 0);
      assert.equal(result.cpu, 0.25);
      assert.ok(result.maxRSS < maximumMemory);
      assert.equal(result.receipt.passed, true);
      assert.equal(result.receipt.run, selected.run);
      assert.equal(result.receipt.bytes, expected.size);
      assert.equal(result.receipt.sha256, expected.sha256);
    }
    assert.ok(exits.every((code) => code.trim() === "0"));
    const receiver = results.find((result) => result.role === "receiver")!;
    const reader = results.find((result) => result.role === "reader")!;
    const reads = reader.samples.filter((sample) => sample.position > 0);
    assert.ok(reads.length >= 10, "stream must be sampled while backpressured");
    const nearEnd = reads.find((sample) => sample.position >= expected.size - COPY.chunk);
    assert.ok(nearEnd, "source read position must approach EOF during sampling");
    const readSpan = nearEnd.at - reads[0]!.at;
    assert.ok(readSpan >= 25000, "source must follow the intentionally slower 8MiB/s receiver, not preload input");
    const maxReadAhead = Math.max(...reads.map((sample) => {
      const stored = receiver.samples.find((snapshot) => snapshot.at >= sample.at) ?? receiver.samples.at(-1)!;
      assert.ok(Math.abs(stored.at - sample.at) <= 2000, "backpressure samples must overlap in time");
      return Math.max(0, sample.position - stored.position);
    }));
    assert.ok(maxReadAhead <= 3 * COPY.chunk, `source read-ahead exceeded three frame buffers: ${maxReadAhead}`);
    const after = lstatSync(fixturePath, { bigint: true });
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(after.ctimeNs, before.ctimeNs);
    const receipt = JSON.parse(readFileSync(join(destination, "copy-receipt.json"), "utf8"));
    assert.deepEqual(receiver.receipt, reader.receipt);
    assert.deepEqual(receipt, receiver.receipt);
    assert.equal(receipt.sha256, expected.sha256);
    assert.equal(lstatSync(join(destination, "archive.sqlite")).size, expected.size);
    assert.equal(lstatSync(join(destination, "archive.sqlite.partial")).ino, lstatSync(join(destination, "archive.sqlite")).ino);
    report.passed = true;
    report.readSpanMs = readSpan;
    report.maxReadAhead = maxReadAhead;
    console.log(JSON.stringify({ passed: true, bytes: expected.size, readSpanMs: readSpan, maxReadAhead, roles: results.map(({ role, maxRSS, memoryPeak }) => ({ role, maxRSS, memoryPeak })) }));
  } finally {
    if (process.env.RUNNER_TEMP) writeFileSync(join(process.env.RUNNER_TEMP, sameNode ? "cpa-stream-same-node-bounded-result.json" : "cpa-stream-bounded-result.json"), JSON.stringify(report) + "\n", { mode: 0o644 });
    for (const name of names) await command("docker", ["rm", "--force", name]).catch(() => {});
    if (ownNetwork) await command("docker", ["network", "rm", network]).catch(() => {});
    if (ownIdentity) rmSync(identityDirectory, { recursive: true });
    rmSync(root, { recursive: true, force: true });
  }
});
