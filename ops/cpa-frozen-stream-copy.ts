import { readFile, writeFile, open, statfs } from "node:fs/promises";
import { setTimeout as pause } from "node:timers/promises";
import { COPY, STREAM_PROFILES, loadIdentity, profileCommand, requireCopy, requirePlacement, requireReadOnlyMount, runReader, safeFailure, startReceiver, validateEndpoint, validateIdentity, type Identity } from "./lib/cpa-stream.ts";

let phase = "preflight";
let run: string = COPY.run;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("cpa-frozen-stream-copy [stage-][same-node-|diagnostic-]reader|receiver; fixed profiles/paths, RAM-only diagnostic, one-use mTLS, no path/URL overrides");
    return;
  }
  requireCopy(args.length === 1, "ARGUMENTS");
  const staging = args[0]!.startsWith("stage-");
  const { profile, command: role } = profileCommand(staging ? args[0]!.slice(6) : args[0]!);
  requireCopy(role === "reader" || role === "receiver", "ARGUMENTS");
  const diagnostic = profile === "diagnostic";
  const plan = STREAM_PROFILES[profile].plan;
  run = plan.run;
  requirePlacement(role, profile, process.env.NODE_NAME, process.env.POD_NAME);
  const endpoint = validateEndpoint((role === "reader" ? process.env.CPA_RECEIVER_IP : process.env.POD_IP) ?? "", profile);
  requireCopy(process.getuid?.() === COPY.uid && process.getgid?.() === COPY.gid, "PROCESS_IDENTITY");
  requireCopy((await statfs("/identity")).type === 0x01021994, "IDENTITY_NOT_RAM");
  if (diagnostic) requireCopy((await statfs(role === "reader" ? "/source" : "/destination")).type === 0x01021994, "DIAGNOSTIC_NOT_RAM");
  if (staging) {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      length += chunk.length;
      requireCopy(length <= 32768, "IDENTITY_TOO_LARGE");
      chunks.push(chunk);
    }
    const identity = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Identity;
    validateIdentity(identity, role, plan.run);
    const file = await open("/identity/bundle.staging.json", "wx", 0o600);
    try { await file.writeFile(JSON.stringify(identity)); await file.sync(); } finally { await file.close(); }
    const { link } = await import("node:fs/promises");
    await link("/identity/bundle.staging.json", "/identity/bundle.json");
    console.log(JSON.stringify({ role, staged: true }));
    return;
  }
  const deadline = setTimeout(() => { console.error("TOTAL_DEADLINE"); process.exit(1); }, plan.totalMs);
  try {
    phase = "identity-wait";
    let identity: Identity | undefined;
    const waiting = Date.now();
    while (!identity) {
      try { identity = await loadIdentity(role, plan.run); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        requireCopy(Date.now() - waiting < 120000, "IDENTITY_DEADLINE");
        await pause(500);
      }
    }
    console.log(JSON.stringify({ role, stage: "identity-ready" }));
    if (role === "reader") {
      phase = "readonly-mount";
      requireReadOnlyMount(await readFile("/proc/self/mountinfo", "utf8"));
      phase = "reader-transport";
      const receipt = await runReader(plan, identity, endpoint);
      await writeFile("/dev/termination-log", JSON.stringify({ role, ...receipt }));
      console.log(JSON.stringify({ role, ...receipt }));
    } else {
      phase = "receiver-transport";
      const receiver = startReceiver(plan, identity, endpoint);
      try {
        await receiver.listening;
        console.log(JSON.stringify({ role, listening: true, port: COPY.port }));
        const receipt = await receiver.completion;
        await writeFile("/dev/termination-log", JSON.stringify({ role, ...receipt }));
        console.log(JSON.stringify({ role, ...receipt }));
      } finally { receiver.close(); }
    }
  } finally { clearTimeout(deadline); }
}

void main().catch(async (error: unknown) => {
  const result = JSON.stringify({ run, passed: false, phase, failure: safeFailure(error) });
  if (!process.argv[2]?.startsWith("stage-")) await writeFile("/dev/termination-log", result).catch(() => {});
  console.error(result);
  process.exitCode = 1;
});
