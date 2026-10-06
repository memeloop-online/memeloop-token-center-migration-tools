import { readFileSync, readdirSync, readlinkSync, lstatSync } from "node:fs";
import { COPY, SAME_NODE_COPY, loadIdentity, requireCopy, requirePlacement, requireReadOnlyMount, runReader, safeFailure, startReceiver, validateEndpoint, type CopyPlan, type Identity } from "../../ops/lib/cpa-stream.ts";

async function main(): Promise<void> {
  requireCopy(process.env.CPA_GHA_FIXTURE === "1", "GHA_FIXTURE_ONLY");
  const role = process.argv[2];
  requireCopy(process.argv.length === 3 && (role === "reader" || role === "receiver"), "FIXTURE_ROLE");
  const fixture = JSON.parse(readFileSync("/fixture.json", "utf8")) as { size: number; sha256: string };
  requireCopy(fixture.size === 256 * 1024 ** 2 && /^[a-f0-9]{64}$/.test(fixture.sha256), "FIXTURE_METADATA");
  const sameNode = process.env.CPA_GHA_PROFILE === "same-node";
  const selected = sameNode ? SAME_NODE_COPY : COPY;
  const identity = sameNode ? await loadIdentity(role, selected.run) : JSON.parse(readFileSync("/identity.json", "utf8")) as Identity;
  if (sameNode) requirePlacement(role, "same-node", process.env.NODE_NAME, process.env.POD_NAME);
  const endpoint = sameNode ? validateEndpoint("10.42.2.2", "same-node") : role === "reader" ? "receiver" : "0.0.0.0";
  const plan: CopyPlan = { ...selected, ...fixture, totalMs: 300000, verifyMs: 120000, reserveBytes: 0, rate: role === "receiver" ? 8 * 1024 ** 2 : COPY.rate };
  const memoryLimit = Number(readFileSync("/sys/fs/cgroup/memory.max", "utf8").trim());
  const swapLimit = Number(readFileSync("/sys/fs/cgroup/memory.swap.max", "utf8").trim());
  const quota = readFileSync("/sys/fs/cgroup/cpu.max", "utf8").trim().split(/\s+/).map(Number);
  requireCopy(memoryLimit === 128 * 1024 ** 2 && swapLimit === 0 && quota[0]! / quota[1]! === 0.25, "FIXTURE_CGROUP_BUDGET");
  const samples: { at: number; position: number; rss: number }[] = [];
  let position = 0;
  const sample = () => {
    if (role === "reader") {
      for (const descriptor of readdirSync("/proc/self/fd")) {
        try {
          if (readlinkSync(`/proc/self/fd/${descriptor}`) !== COPY.source) continue;
          const offset = /^pos:\s+(\d+)/m.exec(readFileSync(`/proc/self/fdinfo/${descriptor}`, "utf8"));
          if (offset) position = Number(offset[1]);
        } catch {}
      }
    } else {
      try { position = lstatSync(`${plan.destination}/archive.sqlite.partial`).size; } catch {}
    }
    if (samples.length < 4000) samples.push({ at: Date.now(), position, rss: process.memoryUsage().rss });
  };
  sample();
  const sampler = setInterval(sample, 100);
  try {
    let receipt;
    if (role === "reader") {
      requireReadOnlyMount(readFileSync("/proc/self/mountinfo", "utf8"));
      receipt = await runReader(plan, identity, endpoint);
    } else {
      const receiver = startReceiver(plan, identity, endpoint);
      try {
        await receiver.listening;
        console.log(JSON.stringify({ kind: "fixture-listening" }));
        receipt = await receiver.completion;
      } finally { receiver.close(); }
    }
    sample();
    console.log(JSON.stringify({ kind: "bounded-result", role, receipt, memoryLimit, swapLimit, cpu: quota[0]! / quota[1]!, memoryPeak: Number(readFileSync("/sys/fs/cgroup/memory.peak", "utf8").trim()), maxRSS: process.resourceUsage().maxRSS * 1024, samples }));
  } finally { clearInterval(sampler); }
}

void main().catch((error: unknown) => { console.error(JSON.stringify({ kind: "bounded-failure", failure: safeFailure(error) })); process.exitCode = 1; });
