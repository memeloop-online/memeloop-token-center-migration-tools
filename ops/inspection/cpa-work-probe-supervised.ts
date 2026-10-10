import { spawn } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { PROBE_BUDGET } from "./cpa-work-probe-budget.ts";
import { observeProbeProcess, superviseProbe, type LifecycleReceipt, type ProbeExit } from "./cpa-work-probe-lifecycle.ts";
import { ApiFailure, unixApi, type ProbeApi, type ProbeConfig, type Resource } from "./cpa-work-probe-operator.ts";

// Fixed authorized target contract, identical to the operator module and the
// reviewed manifest; only own-UID Job/Pod paths are ever derived from it.
const NS = "cliproxyapi";
const CORE = `/api/v1/namespaces/${NS}`;
const JOBS = `/apis/batch/v1/namespaces/${NS}/jobs`;
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

type List = { items?: unknown };
const listItems = (value: unknown): Resource[] => {
  const items = (value as List | null)?.items;
  if (!Array.isArray(items)) throw new Error("LIST_MALFORMED");
  return items as Resource[];
};

// Caller-side cleanup of resources this run owns. It adopts only the exact
// configured Job UID and Pods controller-owned by it; any identity mismatch,
// transport failure or expiry fails closed with false and deletes nothing more.
// No retry of mutations, per the probe budget contract.
export async function cleanupOwnedProbe(api: ProbeApi, config: ProbeConfig, deadline: number, signal: AbortSignal): Promise<boolean> {
  const jobPath = `${JOBS}/${config.jobName}`;
  const podsPath = `${CORE}/pods?labelSelector=${encodeURIComponent(`batch.kubernetes.io/controller-uid=${config.jobUid}`)}`;
  const call = (method: "GET" | "DELETE", path: string, body?: unknown): Promise<unknown> => {
    const remaining = deadline - Date.now();
    if (signal.aborted || remaining <= 0) throw new Error("CLEANUP_DEADLINE");
    return api.call(method, path, Math.min(PROBE_BUDGET.apiMs, remaining), body);
  };
  const gone404 = (error: unknown): boolean => error instanceof ApiFailure && error.statusCode === 404;
  try {
    let jobGone = false;
    try {
      const job = (await call("GET", jobPath)) as Resource;
      if (job.metadata.name !== config.jobName || job.metadata.uid !== config.jobUid) return false;
      await call("DELETE", jobPath, { apiVersion: "v1", kind: "DeleteOptions", propagationPolicy: "Orphan", gracePeriodSeconds: 5, preconditions: { uid: config.jobUid, resourceVersion: job.metadata.resourceVersion } });
    } catch (error) { if (gone404(error)) jobGone = true; else return false; }
    if (!jobGone) {
      // Pods are removed only after their owning Job is confirmed stopping.
      for (const pod of listItems(await call("GET", podsPath))) {
        const controllers = pod.metadata.ownerReferences?.filter((owner) => owner.controller) ?? [];
        if (!controllers.some((owner) => owner.uid === config.jobUid)) return false;
        try { await call("DELETE", `${CORE}/pods/${pod.metadata.name}`, { apiVersion: "v1", kind: "DeleteOptions", gracePeriodSeconds: 5, preconditions: { uid: pod.metadata.uid, resourceVersion: pod.metadata.resourceVersion } }); }
        catch (error) { if (!gone404(error)) return false; }
      }
    }
    for (;;) {
      const remaining = deadline - Date.now();
      if (signal.aborted) return false;
      if (remaining <= 0) return false;
      let gone = true;
      try { await call("GET", jobPath); gone = false; } catch (error) { if (!gone404(error)) return false; }
      if (gone && listItems(await call("GET", podsPath)).length) gone = false;
      if (gone) return true;
      await new Promise((resolve) => setTimeout(resolve, Math.min(PROBE_BUDGET.pollMs, Math.max(1, remaining))));
    }
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
  // Presence gate only; the operator child re-runs the full reviewed validation.
  if (!config || typeof config.jobName !== "string" || !config.jobName || typeof config.jobUid !== "string" || !config.jobUid) throw new Error("SUPERVISOR_CONFIG_REJECTED");
  const socket = lstatSync(suppliedSocket);
  const parent = lstatSync(dirname(suppliedSocket));
  if (!socket.isSocket() || socket.uid !== process.getuid?.() || !parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) throw new Error("UNSAFE_API_SOCKET");
  let stdoutTail = "";
  const readReceipt = (): LifecycleReceipt | null => {
    const lines = stdoutTail.trim().split("\n");
    for (let index = lines.length - 1; index >= 0; index--) {
      try {
        const parsed = JSON.parse(lines[index]!) as LifecycleReceipt | null;
        if (parsed && typeof parsed === "object" && "cleanup" in parsed) return parsed;
      } catch { /* earlier non-receipt output */ }
    }
    return null;
  };
  const controller = new AbortController();
  const cancel = (): void => controller.abort();
  process.once("SIGTERM", cancel); process.once("SIGINT", cancel);
  try {
    // The original launch clock starts here, immediately before the spawn.
    const startedAt = now();
    const child = spawn(process.execPath, [...loaderFlags(), OPERATOR_PATH, ...argv], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout?.on("data", (chunk) => { stdoutTail = (stdoutTail + String(chunk)).slice(-65536); });
    child.stderr?.on("data", (chunk) => process.stderr.write(chunk));
    const probe = observeProbeProcess(child, readReceipt, now);
    const api = unixApi(suppliedSocket);
    const result = await superviseProbe(probe, (deadline, signal) => cleanupOwnedProbe(api, config, deadline, signal), now, startedAt, controller.signal);
    const operator = result.exit?.receipt ?? null;
    const passed = !result.forcedStop && result.cleanupComplete && (operator as { passed?: unknown } | null)?.passed === true;
    return { status: passed ? "SUPERVISED_COMPLETE" : "SUPERVISED_FAILED", passed, operator, exit: result.exit, forcedStop: result.forcedStop, cleanupComplete: result.cleanupComplete, cleanupDeadline: result.cleanupDeadline, outerDeadline: result.outerDeadline };
  } finally {
    process.removeListener("SIGTERM", cancel); process.removeListener("SIGINT", cancel);
  }
}

if (invokedAsEntrypoint("cpa-work-probe-supervised", import.meta.url)) {
  runSupervised(process.argv.slice(2))
    .then((result) => { console.log(JSON.stringify(result)); process.exitCode = result.passed ? 0 : 1; })
    .catch(() => { console.log(JSON.stringify({ status: "SUPERVISOR_REJECTED", passed: false, operator: null, exit: null, forcedStop: false, cleanupComplete: false })); process.exitCode = 1; });
}
