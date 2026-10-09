export const PROBE_BUDGET = Object.freeze({ startupMs: 300_000, execMs: 165_000, totalMs: 480_000, cleanupMs: 30_000, apiMs: 2_000, freshnessMs: 10_000, pollMs: 1_000 });
export type ProbeBudgets = { [K in keyof typeof PROBE_BUDGET]: number };
export type ContainerState = { running?: { startedAt: string }; terminated?: { startedAt?: string; finishedAt: string; exitCode: number }; waiting?: { reason?: string } };
export interface ProbeObservation {
  jobUid: string; jobResourceVersion: string;
  podUid: string | null; podResourceVersion: string | null;
  ownerUid: string | null; pvcUid: string; pvcResourceVersion: string;
  claimName: string; attemptStartedAt: string;
  collectionStartedAt: string; observedAt: string;
  initFailed: boolean; jobFailed: boolean; podPhase: string | null;
  state: ContainerState | null; writeStarted: boolean; complete: boolean;
}
export interface ProbeIdentity { jobUid: string; podUid: string | null; pvcUid: string }

export function validateBudgets(b: ProbeBudgets): void {
  if (Object.keys(b).length !== Object.keys(PROBE_BUDGET).length || Object.values(b).some((value) => !Number.isSafeInteger(value) || value <= 0)) throw new Error("INVALID_BUDGET");
  for (const key of Object.keys(PROBE_BUDGET) as (keyof ProbeBudgets)[]) {
    if (b[key] !== PROBE_BUDGET[key]) throw new Error("UNREVIEWED_BUDGET");
  }
  if (b.totalMs < b.startupMs + b.execMs + b.freshnessMs + b.pollMs) throw new Error("OVERLAPPING_BUDGETS");
}

export function timestamp(value: string): number {
  const parsed = typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed)) throw new Error("INVALID_TIMESTAMP");
  return parsed;
}

export function probeBudget(o: ProbeObservation, identity: ProbeIdentity, now: number, b: ProbeBudgets = PROBE_BUDGET) {
  validateBudgets(b);
  for (const field of ["initFailed", "jobFailed", "writeStarted", "complete"] as const) {
    if (typeof o[field] !== "boolean") throw new Error("INVALID_OBSERVATION");
  }
  if (o.jobUid !== identity.jobUid || !identity.jobUid || o.pvcUid !== identity.pvcUid || !identity.pvcUid || o.podUid !== identity.podUid) throw new Error("IDENTITY_MISMATCH");
  if (!o.jobResourceVersion || !o.pvcResourceVersion || o.podUid !== null && (!o.podResourceVersion || o.ownerUid !== identity.jobUid)) throw new Error("RESOURCE_IDENTITY_MISSING");
  if (o.claimName !== "mtc-cpa-recovery-work-20261005") throw new Error("TARGET_MISMATCH");
  const start = timestamp(o.attemptStartedAt);
  const collection = timestamp(o.collectionStartedAt);
  const observed = timestamp(o.observedAt);
  if (!Number.isFinite(now) || now < start || collection < start || observed < collection || observed > now || now - collection > b.freshnessMs) throw new Error("STALE_OBSERVATION");
  if (o.state && Number(Boolean(o.state.running)) + Number(Boolean(o.state.terminated)) + Number(Boolean(o.state.waiting)) !== 1) throw new Error("INVALID_CONTAINER_STATE");
  const startedAt = o.state?.running?.startedAt ?? o.state?.terminated?.startedAt;
  const execStart = startedAt ? timestamp(startedAt) : null;
  if (execStart !== null && (execStart < start || execStart > observed)) throw new Error("INVALID_EXEC_START");
  if ((o.writeStarted || o.complete) && execStart === null) throw new Error("MISSING_EXEC_START");
  if (o.complete && !o.writeStarted) throw new Error("MISSING_WRITE_START");
  const end = o.state?.terminated;
  if (end && (!Number.isInteger(end.exitCode) || end.exitCode < 0)) throw new Error("INVALID_EXIT_CODE");
  const finished = end ? timestamp(end.finishedAt) : null;
  if (finished !== null && (finished < start || finished > observed || execStart !== null && finished < execStart)) throw new Error("INVALID_EXEC_END");
  const startupDeadline = start + b.startupMs;
  const totalDeadline = start + b.totalMs;
  const execDeadline = execStart === null ? null : execStart + b.execMs;
  const terminalCause = o.initFailed || o.podPhase === "Failed" && execStart === null || o.jobFailed && execStart === null || end && execStart === null ? "STARTUP_FAILED" : end && end.exitCode !== 0 || o.jobFailed || o.podPhase === "Failed" ? "EXEC_FAILED" : null;
  let status: string;
  if (now >= totalDeadline) status = "TOTAL_DEADLINE";
  else if (terminalCause) status = terminalCause;
  else if ((execStart ?? now) >= startupDeadline) status = "STARTUP_DEADLINE";
  else if (execDeadline !== null && (finished ?? now) >= execDeadline) status = "EXEC_DEADLINE";
  else if (end) status = end.exitCode === 0 && o.complete && o.podPhase === "Succeeded" ? "COMPLETE" : "EXEC_FAILED";
  else status = execStart === null ? "STARTING" : "EXECUTING";
  return { status, terminalCause, startupDeadline, execDeadline, totalDeadline,
    execElapsedMs: execStart === null ? null : (finished ?? now) - execStart,
    bytes: status === "COMPLETE" ? 1_073_741_824 : null,
    stopRequired: !["STARTING", "EXECUTING"].includes(status), cleanupIdentity: identity };
}
