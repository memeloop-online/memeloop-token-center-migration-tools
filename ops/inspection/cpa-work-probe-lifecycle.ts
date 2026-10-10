import type { ChildProcess } from "node:child_process";
import { PROBE_BUDGET, cleanupDeadline } from "./cpa-work-probe-budget.ts";

export interface LifecycleReceipt { cleanup?: { startedAt?: string | null } }
export interface ProbeExit { finishedAt: number; receipt: LifecycleReceipt | null }
export interface ProbeProcess {
  // null means the deadline (or cancellation) arrived before process exit.
  waitUntil(deadline: number, signal?: AbortSignal): Promise<ProbeExit | null>;
  signal(signal: "SIGTERM" | "SIGKILL"): void;
}

// Adapter for an already launched operator; no create, launch or cluster action.
export function observeProbeProcess(child: ChildProcess, readReceipt: () => LifecycleReceipt | null, now: () => number): ProbeProcess {
  let exit: ProbeExit | null = null;
  const completion = new Promise<ProbeExit>((resolve) => {
    const finish = () => {
      if (exit) return;
      let receipt: LifecycleReceipt | null = null;
      try { receipt = readReceipt(); } catch { /* finally cleanup still runs */ }
      exit = { finishedAt: now(), receipt }; resolve(exit);
    };
    // Failed spawn emits error asynchronously; never let it bypass caller finally.
    child.on("error", finish);
    if (child.exitCode !== null || child.signalCode !== null) finish();
    else child.once("close", finish);
  });
  return {
    signal: (signal) => { child.kill(signal); },
    waitUntil: async (deadline, signal) => {
      if (exit) return exit;
      if (signal?.aborted || now() >= deadline) return null;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let cancel = () => {};
      try {
        return await Promise.race([completion, new Promise<null>((resolve) => {
          cancel = () => resolve(null);
          timer = setTimeout(cancel, Math.max(0, deadline - now()));
          signal?.addEventListener("abort", cancel, { once: true });
        })]);
      } finally { clearTimeout(timer); signal?.removeEventListener("abort", cancel); }
    },
  };
}

// Callers use this tracked lifecycle instead of inferring cleanup from Pod status.
// now must use the same monotonic epoch clock as the process adapter.
export async function superviseProbe(process: ProbeProcess, cleanup: (deadline: number, signal: AbortSignal) => Promise<boolean>, now: () => number, startedAt: number, signal?: AbortSignal) {
  if (!Number.isFinite(startedAt) || startedAt > now()) throw new Error("INVALID_OPERATOR_START");
  const start = startedAt;
  const executionDeadline = start + PROBE_BUDGET.totalMs;
  const outerDeadline = executionDeadline + PROBE_BUDGET.cleanupMs + 5_000;
  let exit: ProbeExit | null = null, forcedStop = false, cleanupComplete = false;
  let deadline = outerDeadline;
  try {
    exit = await process.waitUntil(executionDeadline, signal);
  } finally {
    // Also runs when the wait fails: signal first, allow finally cleanup, then kill.
    try {
      if (!exit) {
        process.signal("SIGTERM");
        exit = await process.waitUntil(outerDeadline);
        if (!exit) { process.signal("SIGKILL"); forcedStop = true; }
      }
    } finally {
      const entry = now();
      // Explicit operator cleanup entry wins; older receipts use operator end.
      deadline = cleanupDeadline(entry, exit?.receipt?.cleanup?.startedAt, exit?.finishedAt, outerDeadline);
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        if (deadline > now()) {
          cleanupComplete = await Promise.race([cleanup(deadline, controller.signal), new Promise<boolean>((resolve) => {
            timer = setTimeout(() => { controller.abort(); resolve(false); }, Math.max(0, deadline - now()));
          })]);
        }
      } finally { clearTimeout(timer); controller.abort(); }
    }
  }
  return { exit, forcedStop, cleanupComplete, cleanupDeadline: deadline, outerDeadline };
}
