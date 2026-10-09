import { readFileSync } from "node:fs";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";

// Target-only observation contract. Never applies resources or deletes by name.
export const PROBE_BUDGET = Object.freeze({ startupMs: 60_000, execMs: 165_000, totalMs: 175_000 });
type ContainerState = { running?: { startedAt: string }; terminated?: { startedAt?: string; finishedAt: string; exitCode: number }; waiting?: { reason?: string } };
export interface ProbeObservation {
  jobUid: string;
  podUid: string;
  ownerUid: string;
  pvcUid: string;
  claimName: string;
  jobStartedAt: string;
  initFailed: boolean;
  state: ContainerState;
  writeStarted: boolean;
  complete: boolean;
}
export interface ProbeIdentity { jobUid: string; podUid: string; pvcUid: string }

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error("INVALID_TIMESTAMP");
  return parsed;
}

export function probeBudget(observation: ProbeObservation, identity: ProbeIdentity, now: number) {
  if ([observation.initFailed, observation.writeStarted, observation.complete].some((value) => typeof value !== "boolean")) throw new Error("INVALID_OBSERVATION");
  if (!observation.state || Number(Boolean(observation.state.running)) + Number(Boolean(observation.state.terminated)) + Number(Boolean(observation.state.waiting)) !== 1) throw new Error("INVALID_CONTAINER_STATE");
  if (observation.complete && !observation.writeStarted) throw new Error("MISSING_WRITE_START");
  for (const field of ["jobUid", "podUid", "pvcUid"] as const) {
    if (!identity[field] || observation[field] !== identity[field]) throw new Error("IDENTITY_MISMATCH");
  }
  if (observation.ownerUid !== identity.jobUid || observation.claimName !== "mtc-cpa-recovery-work-20261005") throw new Error("TARGET_MISMATCH");
  const jobStart = timestamp(observation.jobStartedAt);
  if (!Number.isFinite(now) || now < jobStart) throw new Error("INVALID_CLOCK");
  const startedAt = observation.state.running?.startedAt ?? observation.state.terminated?.startedAt;
  const execStart = startedAt ? timestamp(startedAt) : null;
  if (execStart !== null && (execStart < jobStart || execStart > now)) throw new Error("INVALID_EXEC_START");
  if ((observation.writeStarted || observation.complete) && execStart === null) throw new Error("MISSING_EXEC_START");
  const startupDeadline = jobStart + PROBE_BUDGET.startupMs;
  const totalDeadline = jobStart + PROBE_BUDGET.totalMs;
  const execDeadline = execStart === null ? null : execStart + PROBE_BUDGET.execMs;
  const end = observation.state.terminated;
  if (end && (!Number.isInteger(end.exitCode) || end.exitCode < 0)) throw new Error("INVALID_EXIT_CODE");
  const finished = end ? timestamp(end.finishedAt) : null;
  if (finished !== null && (finished > now || execStart !== null && finished < execStart)) throw new Error("INVALID_EXEC_END");
  const evaluatedAt = finished ?? now;
  let status: string;
  if (observation.initFailed || end && execStart === null) status = "STARTUP_FAILED";
  else if ((execStart ?? evaluatedAt) >= startupDeadline) status = "STARTUP_DEADLINE";
  else if (evaluatedAt >= totalDeadline) status = "TOTAL_DEADLINE";
  else if (execDeadline !== null && evaluatedAt >= execDeadline) status = "EXEC_DEADLINE";
  else if (end) status = end.exitCode === 0 && observation.complete ? "COMPLETE" : "EXEC_FAILED";
  else status = execStart === null ? "STARTING" : "EXECUTING";
  return {
    status, startupDeadline, execDeadline, totalDeadline,
    execElapsedMs: execStart === null ? null : evaluatedAt - execStart,
    // No throughput result exists without successful write/read completion.
    bytes: status === "COMPLETE" ? 1_073_741_824 : null,
    writeStarted: observation.writeStarted,
    stopRequired: !["STARTING", "EXECUTING", "COMPLETE"].includes(status),
    cleanupIdentity: identity,
  };
}

if (invokedAsEntrypoint("cpa-work-probe-budget", import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 4) throw new Error("USAGE: observation.json exact-job-uid exact-pod-uid exact-pvc-uid");
    const [path, jobUid, podUid, pvcUid] = args as [string, string, string, string];
    const result = probeBudget(JSON.parse(readFileSync(path, "utf8")) as ProbeObservation, { jobUid, podUid, pvcUid }, Date.now());
    console.log(JSON.stringify(result));
    if (result.stopRequired) process.exitCode = 1;
  } catch {
    console.error("PROBE_OBSERVATION_REJECTED");
    process.exitCode = 1;
  }
}
