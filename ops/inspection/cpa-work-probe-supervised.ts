import { spawn } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseAllDocuments } from "yaml";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { observeProbeProcess, superviseProbe, type LifecycleReceipt, type ProbeExit } from "./cpa-work-probe-lifecycle.ts";
import { cleanupProbe, configValid, readProbeJournal, unixApi, type ProbeApi, type ProbeConfig, type ProbeJournal, type Resource } from "./cpa-work-probe-operator.ts";

const OPERATOR_PATH = fileURLToPath(new URL("./cpa-work-probe-operator.ts", import.meta.url));

// Only module-resolution flags propagate to the operator child; runner or
// inspector flags of a supervising process must never leak into the launch.
const loaderFlags = (): string[] => {
  const flags: string[] = [];
  for (let index = 0; index < process.execArgv.length; index++) {
    const flag = process.execArgv[index]!;
    if (flag === "--import" && process.execArgv[index + 1]) flags.push(flag, process.execArgv[++index]!);
    else if (flag.startsWith("--import=")) flags.push(flag);
  }
  return flags;
};

export async function cleanupOwnedProbe(api: ProbeApi, config: ProbeConfig, deadline: number, signal: AbortSignal, journal?: ProbeJournal, plan?: Resource, now: () => number = Date.now): Promise<boolean> {
  try {
    configValid(config);
    if (!journal || signal.aborted || now() >= deadline) return false;
    const reviewed = plan ?? parseAllDocuments(readFileSync(new URL("./cpa-work-directio-20261006a.yaml", import.meta.url), "utf8"))[1]?.toJSON() as Resource;
    if (!reviewed) return false;
    const clock = { now, cancelled: () => signal.aborted, sleep: (ms: number) => new Promise<void>((resolveSleep) => setTimeout(resolveSleep, ms)) };
    const limit = Math.min(deadline, journal.state.cleanup.deadline ?? deadline);
    return await cleanupProbe(config, api, reviewed, journal, clock, limit);
  } catch { return false; }
}

export interface SupervisedResult {
  status: string;
  passed: boolean;
  operator: LifecycleReceipt | null;
  exit: ProbeExit | null;
  forcedStop: boolean;
  cleanupComplete: boolean;
  cleanupDeadline: number;
  outerDeadline: number;
}

// Launches the reviewed operator exactly once with the caller's unchanged argv
// and supervises it through the tracked lifecycle module. All signalling,
// deadline and cleanup-boundary semantics live in cpa-work-probe-lifecycle.ts.
export async function runSupervised(argv: string[], now: () => number = Date.now): Promise<SupervisedResult> {
  const [authorization, configPath, socketOption, suppliedSocket] = argv;
  if (authorization !== "--execute-authorized-target-only" || !configPath || socketOption !== "--api-socket" || !suppliedSocket || argv.length > 4) throw new Error("RUNTIME_AUTHORIZATION_REQUIRED");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as ProbeConfig;
  configValid(config);
  const socket = lstatSync(suppliedSocket);
  const parent = lstatSync(dirname(suppliedSocket));
  if (!socket.isSocket() || socket.uid !== process.getuid?.() || !parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) throw new Error("UNSAFE_API_SOCKET");
  const directory = mkdtempSync(join(tmpdir(), "cpa-supervised-attempt-"));
  const journalPath = join(directory, "attempt.json");
  let stdoutTail = "";
  const readReceipt = (): LifecycleReceipt | null => {
    const lines = stdoutTail.trim().split("\n");
    for (let index = lines.length - 1; index >= 0; index--) {
      try {
        const parsed = JSON.parse(lines[index]!) as LifecycleReceipt | null;
        if (parsed && typeof parsed === "object" && "cleanup" in parsed) return parsed;
      } catch { /* earlier non-receipt output */ }
    }
    try { return { cleanup: readProbeJournal(config, journalPath).state.cleanup }; } catch { return null; }
  };
  const controller = new AbortController();
  const cancel = (): void => controller.abort();
  process.once("SIGTERM", cancel); process.once("SIGINT", cancel);
  try {
    // The original launch clock starts here, immediately before the spawn.
    const startedAt = now();
    const child = spawn(process.execPath, [...loaderFlags(), OPERATOR_PATH, ...argv], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CPA_PROBE_ATTEMPT_JOURNAL: journalPath } });
    child.stdout?.on("data", (chunk) => { stdoutTail = (stdoutTail + String(chunk)).slice(-65536); });
    child.stderr?.on("data", (chunk) => process.stderr.write(chunk));
    const probe = observeProbeProcess(child, readReceipt, now);
    const api = unixApi(suppliedSocket);
    const result = await superviseProbe(probe, async (deadline, signal) => {
      try { return await cleanupOwnedProbe(api, config, deadline, signal, readProbeJournal(config, journalPath), undefined, now); }
      catch { return false; }
    }, now, startedAt, controller.signal);
    const operator = result.exit?.receipt ?? null;
    const passed = !result.forcedStop && result.cleanupComplete && (operator as { passed?: unknown } | null)?.passed === true;
    return { status: passed ? "SUPERVISED_COMPLETE" : "SUPERVISED_FAILED", passed, operator, exit: result.exit, forcedStop: result.forcedStop, cleanupComplete: result.cleanupComplete, cleanupDeadline: result.cleanupDeadline, outerDeadline: result.outerDeadline };
  } finally {
    process.removeListener("SIGTERM", cancel); process.removeListener("SIGINT", cancel);
    rmSync(directory, { recursive: true, force: true });
  }
}

if (invokedAsEntrypoint("cpa-work-probe-supervised", import.meta.url)) {
  runSupervised(process.argv.slice(2))
    .then((result) => { console.log(JSON.stringify(result)); process.exitCode = result.passed ? 0 : 1; })
    .catch(() => { console.log(JSON.stringify({ status: "SUPERVISOR_REJECTED", passed: false, operator: null, exit: null, forcedStop: false, cleanupComplete: false })); process.exitCode = 1; });
}
