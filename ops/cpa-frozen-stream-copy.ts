import { readFile, writeFile, open, statfs } from "node:fs/promises";
import { setTimeout as pause } from "node:timers/promises";
import { COPY, loadIdentity, requireCopy, requireReadOnlyMount, runReader, safeFailure, startReceiver, validateEndpoint, validateIdentity, type Identity } from "./lib/cpa-stream.ts";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("cpa-frozen-stream-copy reader|receiver|stage-reader|stage-receiver; fixed CPA frozen source, one-use mTLS, no path/URL overrides");
    return;
  }
  requireCopy(args.length === 1 && ["reader", "receiver", "stage-reader", "stage-receiver"].includes(args[0]!), "ARGUMENTS");
  const role = args[0]!.endsWith("reader") ? "reader" : "receiver";
  requireCopy(process.env.NODE_NAME === (role === "reader" ? "sansheng-hv" : "westlake"), "NODE_PLACEMENT");
  requireCopy(process.env.POD_NAME?.startsWith(`mtc-cpa-stream-${role}-20261005a-`), "POD_IDENTITY");
  requireCopy(process.getuid?.() === COPY.uid && process.getgid?.() === COPY.gid, "PROCESS_IDENTITY");
  requireCopy((await statfs("/identity")).type === 0x01021994, "IDENTITY_NOT_RAM");
  if (args[0]!.startsWith("stage-")) {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      length += chunk.length;
      requireCopy(length <= 32768, "IDENTITY_TOO_LARGE");
      chunks.push(chunk);
    }
    const identity = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Identity;
    validateIdentity(identity, role, COPY.run);
    const file = await open("/identity/bundle.staging.json", "wx", 0o600);
    try { await file.writeFile(JSON.stringify(identity)); await file.sync(); } finally { await file.close(); }
    const { link } = await import("node:fs/promises");
    await link("/identity/bundle.staging.json", "/identity/bundle.json");
    console.log(JSON.stringify({ role, staged: true }));
    return;
  }
  const deadline = setTimeout(() => { console.error("TOTAL_DEADLINE"); process.exit(1); }, COPY.totalMs);
  try {
    let identity: Identity | undefined;
    const waiting = Date.now();
    while (!identity) {
      try { identity = await loadIdentity(role); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        requireCopy(Date.now() - waiting < 120000, "IDENTITY_DEADLINE");
        await pause(500);
      }
    }
    if (role === "reader") {
      requireReadOnlyMount(await readFile("/proc/self/mountinfo", "utf8"));
      const receipt = await runReader(COPY, identity, validateEndpoint(process.env.CPA_RECEIVER_IP ?? ""));
      await writeFile("/dev/termination-log", JSON.stringify({ role, ...receipt }));
      console.log(JSON.stringify({ role, ...receipt }));
    } else {
      const receiver = startReceiver(COPY, identity, validateEndpoint(process.env.POD_IP ?? ""));
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
  const result = JSON.stringify({ run: COPY.run, passed: false, failure: safeFailure(error) });
  if (!process.argv[2]?.startsWith("stage-")) await writeFile("/dev/termination-log", result).catch(() => {});
  console.error(result);
  process.exitCode = 1;
});
