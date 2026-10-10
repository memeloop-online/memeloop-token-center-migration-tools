import { request } from "node:http";
import { spawn } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { parseAllDocuments } from "yaml";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { PROBE_BUDGET, cleanupDeadline, probeBudget, timestamp, validateBudgets, type ContainerState, type ProbeBudgets, type ProbeObservation } from "./cpa-work-probe-budget.ts";

const NS = "cliproxyapi";
const CLAIM = "mtc-cpa-recovery-work-20261005";
const PVC_UID = "a5045b54-0f10-4f60-b1f5-18167620ba31";
const CORE = `/api/v1/namespaces/${NS}`;
const JOBS = `/apis/batch/v1/namespaces/${NS}/jobs`;
const POLICY = `/apis/networking.k8s.io/v1/namespaces/${NS}/networkpolicies/mtc-cpa-work-directio-20261006a`;
type Metadata = { name: string; namespace: string; uid: string; resourceVersion: string; generation?: number; labels?: Record<string, string>; deletionTimestamp?: string; ownerReferences?: { uid: string; kind: string; controller?: boolean }[] };
type ContainerStatus = { name: string; restartCount: number; state: ContainerState };
export interface Resource {
  metadata: Metadata;
  spec: Record<string, unknown>;
  status?: { startTime?: string; completionTime?: string; completedIndexes?: string; failedIndexes?: string; phase?: string; active?: number; failed?: number; succeeded?: number; ready?: number; terminating?: number; uncountedTerminatedPods?: { succeeded?: string[]; failed?: string[] }; conditions?: { type: string; status: string; reason?: string; message?: string; lastProbeTime?: string; lastTransitionTime?: string }[]; containerStatuses?: ContainerStatus[]; initContainerStatuses?: ContainerStatus[]; ephemeralContainerStatuses?: ContainerStatus[] };
}
export interface ProbeConfig {
  jobName: string; jobUid: string; jobResourceVersion: string;
  pvcUid: string; pvcResourceVersion: string; budgets: ProbeBudgets;
}
export interface ProbeApi { call(method: "GET" | "PATCH" | "DELETE", path: string, timeoutMs: number, body?: unknown): Promise<unknown>; lastResponseStatus?(): number | null }
export interface ProbeClock { now(): number; sleep(ms: number): Promise<void>; cancelled(): boolean }
const realClock = (): ProbeClock => {
  const wall = Date.now(), mono = performance.now();
  let cancelled = false;
  const cancel = () => { cancelled = true; };
  process.once("SIGTERM", cancel); process.once("SIGINT", cancel);
  return { now: () => wall + Math.ceil(performance.now() - mono) + 1, sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)), cancelled: () => cancelled };
};
export class ApiFailure extends Error {
  readonly statusCode: number;
  constructor(statusCode: number) { super(statusCode === 404 ? "NOT_FOUND" : "API_FAILED"); this.statusCode = statusCode; }
}

type TransportCategory = "REQUEST_DEADLINE" | "RESPONSE_LIMIT" | "RESPONSE_ABORTED" | "SOCKET_RESET" | "SOCKET_REFUSED" | "SOCKET_MISSING" | "SOCKET_PIPE" | "SOCKET_TIMEOUT" | "SOCKET_DENIED" | "REQUEST_ERROR_OTHER" | "RESPONSE_ERROR_OTHER" | "JSON_INVALID";
export class ApiTransportFailure extends Error {
  readonly category: TransportCategory;
  readonly statusCode: number | null;
  constructor(message: "API_TRANSPORT_FAILED" | "API_READ_FAILED" | "API_JSON_INVALID", category: TransportCategory, statusCode: number | null) { super(message); this.category = category; this.statusCode = statusCode; }
}
function transportCategory(error: unknown, fallback: "REQUEST_ERROR_OTHER" | "RESPONSE_ERROR_OTHER"): TransportCategory {
  const code = (error as { code?: unknown } | null)?.code;
  const categories: Record<string, TransportCategory> = { ECONNRESET: "SOCKET_RESET", ECONNREFUSED: "SOCKET_REFUSED", ENOENT: "SOCKET_MISSING", EPIPE: "SOCKET_PIPE", ETIMEDOUT: "SOCKET_TIMEOUT", EACCES: "SOCKET_DENIED" };
  return typeof code === "string" && Object.hasOwn(categories, code) ? categories[code]! : fallback;
}
type ApiStage = "PREFLIGHT" | "UNSUSPEND" | "OBSERVATION" | "CLEANUP_CAPTURE" | "CLEANUP_JOB" | "CLEANUP_POD" | "CLEANUP_ABSENCE";
type ApiResource = "JOB" | "PVC" | "DENY_POLICY" | "PVC_CONSUMER_LIST" | "OWNED_POD_LIST" | "OWNED_POD" | "DIRECTIO_LOG" | "UNRECOGNIZED";
type ApiCallDiagnostic = { method: "GET" | "PATCH" | "DELETE"; resource: ApiResource; stage: ApiStage; httpStatus: number | null; startedAt: string; finishedAt: string; timeoutMs: number; requestIssued: boolean; acknowledgement: "NOT_APPLICABLE" | "NOT_ISSUED" | "REJECTED_4XX" | "RESPONSE_RECEIVED" | "UNKNOWN" };

// Transport exposes only the local Unix socket, never TCP or a credential read.
export function unixApi(socketPath: string): ProbeApi {
  let responseStatus: number | null = null;
  return { lastResponseStatus: () => responseStatus, call: (method, path, timeoutMs, body) => new Promise((resolve, reject) => {
    responseStatus = null;
    let deadlineExpired = false, responseLimit = false, responseAborted = false;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = request({ socketPath, path, method, headers: payload === undefined ? {} : { "Content-Type": method === "PATCH" ? "application/json-patch+json" : "application/json", "Content-Length": Buffer.byteLength(payload) } }, (res) => {
      responseStatus = res.statusCode ?? null;
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) { responseLimit = true; req.destroy(new Error("API_RESPONSE_LIMIT")); } else chunks.push(chunk); });
      res.on("aborted", () => { responseAborted = true; });
      const category = (error: unknown, fallback: "REQUEST_ERROR_OTHER" | "RESPONSE_ERROR_OTHER") => deadlineExpired ? "REQUEST_DEADLINE" : responseLimit ? "RESPONSE_LIMIT" : responseAborted ? "RESPONSE_ABORTED" : transportCategory(error, fallback);
      res.on("error", (error) => reject(new ApiTransportFailure("API_READ_FAILED", category(error, "RESPONSE_ERROR_OTHER"), responseStatus)));
      res.on("end", () => {
        if ((res.statusCode ?? 500) >= 300) { reject(new ApiFailure(res.statusCode ?? 500)); return; }
        const text = Buffer.concat(chunks).toString("utf8");
        try { resolve(path.includes("/log?") ? text : JSON.parse(text)); } catch { reject(new ApiTransportFailure("API_JSON_INVALID", "JSON_INVALID", responseStatus)); }
      });
    });
    const timer = setTimeout(() => { deadlineExpired = true; req.destroy(new Error("API_DEADLINE")); }, Math.max(1, timeoutMs));
    req.on("close", () => clearTimeout(timer));
    req.on("error", (error) => reject(new ApiTransportFailure("API_TRANSPORT_FAILED", deadlineExpired ? "REQUEST_DEADLINE" : responseLimit ? "RESPONSE_LIMIT" : responseAborted ? "RESPONSE_ABORTED" : transportCategory(error, "REQUEST_ERROR_OTHER"), responseStatus)));
    req.end(payload);
  }) };
}

function identity(resource: Resource, name: string, uid: string, rv?: string): void {
  if (!resource?.metadata || typeof name !== "string" || !/^[a-z0-9][a-z0-9.-]*$/.test(name) || typeof uid !== "string" || !uid || resource.metadata.name !== name || resource.metadata.namespace !== NS || resource.metadata.uid !== uid || typeof resource.metadata.resourceVersion !== "string" || !/^\d+$/.test(resource.metadata.resourceVersion) || rv !== undefined && resource.metadata.resourceVersion !== rv) throw new Error("IDENTITY_MISMATCH");
}
function owned(pod: Resource, jobUid: string): boolean {
  const controllers = pod.metadata.ownerReferences?.filter((owner) => owner.controller) ?? [];
  return controllers.length === 1 && controllers[0]!.kind === "Job" && controllers[0]!.uid === jobUid;
}
function subset(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((value, i) => subset(actual[i], value));
  if (expected !== null && typeof expected === "object") return actual !== null && typeof actual === "object" && Object.entries(expected).every(([key, value]) => subset((actual as Record<string, unknown>)[key], value));
  return isDeepStrictEqual(actual, expected);
}
function reviewedDefaults(actual: Record<string, unknown>, expected: Record<string, unknown>, defaults: Record<string, unknown>): boolean {
  const normalized = structuredClone(actual);
  for (const [key, value] of Object.entries(defaults)) {
    if (!(key in expected) && isDeepStrictEqual(normalized[key], value)) delete normalized[key];
  }
  return isDeepStrictEqual(normalized, expected);
}
function denyPolicyMatches(actual: Record<string, unknown>, expected: Record<string, unknown>): boolean {
  for (const spec of [actual, expected]) {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) return false;
    for (const key of ["ingress", "egress"]) {
      const rules = spec[key];
      if (Object.hasOwn(spec, key) && (!Array.isArray(rules) || rules.length !== 0)) return false;
    }
  }
  return isDeepStrictEqual({ ...actual, ingress: [], egress: [] }, { ...expected, ingress: [], egress: [] });
}
function securityContext(actual: unknown, expected: unknown, defaults: Record<string, unknown>): boolean {
  if (!actual || typeof actual !== "object" || Array.isArray(actual) || !expected || typeof expected !== "object" || Array.isArray(expected)) return false;
  const normalized = structuredClone(actual) as Record<string, unknown>;
  const reviewed = expected as Record<string, unknown>;
  const caps = normalized.capabilities as Record<string, unknown> | undefined;
  const reviewedCaps = reviewed.capabilities as Record<string, unknown> | undefined;
  // An explicit empty add list grants nothing; every nonempty addition stays exact.
  if (caps && reviewedCaps && reviewedCaps.add === undefined && isDeepStrictEqual(caps.add, [])) delete caps.add;
  return reviewedDefaults(normalized, reviewed, defaults);
}
function validateJobControls(spec: Record<string, unknown>, jobUid: string, reviewed: Record<string, unknown>): void {
  const defaults = { parallelism: 1, completions: 1, manualSelector: false, completionMode: "NonIndexed", podReplacementPolicy: "TerminatingOrFailed", managedBy: "kubernetes.io/job-controller" };
  const allowed = new Set([...Object.keys(reviewed), ...Object.keys(defaults), "selector"]);
  if (Object.keys(spec).some((key) => !allowed.has(key)) || Object.entries(defaults).some(([key, value]) => spec[key] !== undefined && !isDeepStrictEqual(spec[key], value))) throw new Error("UNSAFE_JOB_CONTROL");
  if (spec.selector !== undefined && ![
    { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } },
    { matchLabels: { "controller-uid": jobUid } },
    { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid, "controller-uid": jobUid } },
  ].some((selector) => isDeepStrictEqual(spec.selector, selector))) throw new Error("UNSAFE_JOB_CONTROL");
}
function validatePodSpec(actual: Record<string, unknown>, expected: Record<string, unknown>): void {
  if (!subset(actual, expected) || ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"].some((key) => actual[key] === true)) throw new Error("UNSAFE_POD_SPEC");
  for (const [key, safeDefault] of Object.entries({ hostNetwork: false, hostPID: false, hostIPC: false, shareProcessNamespace: false, hostUsers: true, imagePullSecrets: [], resourceClaims: [], hostAliases: [] })) {
    if (!(key in expected) && actual[key] !== undefined && !isDeepStrictEqual(actual[key], safeDefault)) throw new Error("UNSAFE_POD_SPEC");
  }
  if (actual.runtimeClassName !== undefined) throw new Error("UNSAFE_POD_SPEC");
  if (!isDeepStrictEqual(actual.volumes, expected.volumes)) throw new Error("UNSAFE_VOLUMES");
  if (!securityContext(actual.securityContext, expected.securityContext, { supplementalGroups: [], sysctls: [], fsGroupChangePolicy: "Always" })) throw new Error("UNSAFE_SECURITY_CONTEXT");
  const inherited = expected.securityContext as Record<string, unknown>;
  const containerDefaults = { privileged: false, procMount: "Default", runAsUser: inherited.runAsUser, runAsGroup: inherited.runAsGroup, runAsNonRoot: inherited.runAsNonRoot, seccompProfile: inherited.seccompProfile };
  for (const key of ["containers", "initContainers"]) {
    const containers = actual[key] as Record<string, unknown>[];
    const reviewed = expected[key] as Record<string, unknown>[];
    for (let i = 0; i < containers.length; i++) {
      const container = containers[i]!;
      const allowed = new Set([...Object.keys(reviewed[i]!), "imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy"]);
      if (Object.keys(container).some((field) => !allowed.has(field)) || !isDeepStrictEqual(container.volumeMounts, reviewed[i]!.volumeMounts) || !securityContext(container.securityContext, reviewed[i]!.securityContext, containerDefaults) || !isDeepStrictEqual(container.resources, reviewed[i]!.resources)) throw new Error("UNSAFE_CONTAINER_SPEC");
      for (const [field, value] of Object.entries({ imagePullPolicy: "IfNotPresent", terminationMessagePath: "/dev/termination-log", terminationMessagePolicy: "File" })) {
        if (!(field in reviewed[i]!) && container[field] !== undefined && !isDeepStrictEqual(container[field], value)) throw new Error("UNSAFE_CONTAINER_SPEC");
      }
    }
  }
  if (actual.ephemeralContainers !== undefined && !isDeepStrictEqual(actual.ephemeralContainers, [])) throw new Error("UNSAFE_CONTAINER_SPEC");
}
function listItems(value: unknown): Resource[] {
  const items = (value as { items?: Resource[] })?.items;
  if (!Array.isArray(items)) throw new Error("INVALID_POD_LIST");
  return items;
}
function activePvcConsumer(pod: Resource): boolean {
  const status = pod.status;
  if (status?.phase !== "Succeeded" && status?.phase !== "Failed") return true;
  // Kubernetes terminal phases mean all containers stopped and will not restart.
  // A failed init may leave never-started containers waiting in a terminal Pod.
  // Optional lists need not exist; running or unknown states still conflict.
  return [status.containerStatuses, status.initContainerStatuses, status.ephemeralContainerStatuses].some((statuses) =>
    statuses !== undefined && (!Array.isArray(statuses) || statuses.some((container) => {
      const state = container?.state;
      return !state || Object.keys(state).length !== 1 || !Object.entries(state).every(([key, value]) =>
        (key === "terminated" || key === "waiting") && value !== null && typeof value === "object" && !Array.isArray(value));
    })));
}
export function configValid(config: ProbeConfig): void {
  if (!config || typeof config !== "object" || [config.jobName, config.jobUid, config.jobResourceVersion, config.pvcUid, config.pvcResourceVersion].some((value) => typeof value !== "string")) throw new Error("INVALID_CONFIG_IDENTITY");
  validateBudgets(config.budgets);
  if (!/^mtc-cpa-work-directio-[a-z0-9-]+$/.test(config.jobName) || !/^[a-f0-9-]{36}$/.test(config.jobUid) || !/^\d+$/.test(config.jobResourceVersion) || config.pvcUid !== PVC_UID || !/^\d+$/.test(config.pvcResourceVersion)) throw new Error("INVALID_CONFIG_IDENTITY");
}

type ProbeCleanup = { complete: boolean; jobDeleted: boolean; podDeleted: boolean; startedAt: string | null; deadline: number | null; errors: string[] };
export interface ProbeAttempt {
  config: ProbeConfig;
  attempted: boolean;
  pod: Resource | null;
  cleanup: ProbeCleanup;
  deletes: { path: string; acknowledged: boolean }[];
}
export interface ProbeJournal { state: ProbeAttempt; save(): void }
export function probeJournal(config: ProbeConfig, path?: string): ProbeJournal {
  const state: ProbeAttempt = { config, attempted: false, pod: null, cleanup: { complete: false, jobDeleted: false, podDeleted: false, startedAt: null, deadline: null, errors: [] }, deletes: [] };
  return { state, save: () => {
    if (!path) return;
    writeFileSync(`${path}.next`, JSON.stringify(state), { mode: 0o600 });
    renameSync(`${path}.next`, path);
  } };
}
export function readProbeJournal(config: ProbeConfig, path: string): ProbeJournal {
  const file = lstatSync(path);
  if (!file.isFile() || file.uid !== process.getuid?.() || (file.mode & 0o077) !== 0 || file.size > 1024 * 1024) throw new Error("JOURNAL_REJECTED");
  const state = JSON.parse(readFileSync(path, "utf8")) as ProbeAttempt;
  if (!state || !isDeepStrictEqual(state.config, config) || typeof state.attempted !== "boolean" || !state.cleanup) throw new Error("JOURNAL_REJECTED");
  if ([state.cleanup.complete, state.cleanup.jobDeleted, state.cleanup.podDeleted].some((value) => typeof value !== "boolean") || !Array.isArray(state.cleanup.errors) || state.cleanup.errors.some((value) => typeof value !== "string")) throw new Error("JOURNAL_REJECTED");
  if (state.cleanup.startedAt !== null && (typeof state.cleanup.startedAt !== "string" || !Number.isFinite(Date.parse(state.cleanup.startedAt))) || state.cleanup.deadline !== null && (typeof state.cleanup.deadline !== "number" || !Number.isFinite(state.cleanup.deadline))) throw new Error("JOURNAL_REJECTED");
  if (state.pod !== null && (!state.pod || typeof state.pod !== "object") || !Array.isArray(state.deletes) || state.deletes.some((entry) => !entry || typeof entry.path !== "string" || typeof entry.acknowledged !== "boolean")) throw new Error("JOURNAL_REJECTED");
  const journal = probeJournal(config, path);
  Object.assign(journal.state, state);
  return journal;
}
type ProbeCall = (method: "GET" | "PATCH" | "DELETE", path: string, deadline: number, body?: unknown) => Promise<unknown>;
async function retryProbeRead(callOnce: ProbeCall, clock: ProbeClock, budgets: ProbeBudgets, method: "GET" | "PATCH" | "DELETE", path: string, deadline: number, body?: unknown): Promise<unknown> {
  for (let attempt = 1; ; attempt++) {
    try { return await callOnce(method, path, deadline, body); }
    catch (error) {
      const transient = error instanceof ApiFailure ? [502, 503, 504].includes(error.statusCode)
        : error instanceof ApiTransportFailure && ["SOCKET_RESET", "REQUEST_DEADLINE", "SOCKET_TIMEOUT", "RESPONSE_ABORTED"].includes(error.category);
      if (method !== "GET" || !transient || attempt >= 3 || clock.cancelled() || deadline - clock.now() <= budgets.pollMs) throw error;
      await clock.sleep(budgets.pollMs);
    }
  }
}
async function captureProbePod(config: ProbeConfig, plan: Resource, pod: Resource | null, call: ProbeCall, deadline: number): Promise<Resource | null> {
  const items = listItems(await call("GET", `${CORE}/pods?labelSelector=${encodeURIComponent(`batch.kubernetes.io/controller-uid=${config.jobUid}`)}`, deadline));
  for (const item of items) identity(item, item?.metadata?.name, item?.metadata?.uid);
  if (items.length > 1 || items.some((item) => !owned(item, config.jobUid))) throw new Error("POD_OWNERSHIP_REJECTED");
  const found = items[0];
  if (!found) { if (pod) throw new Error("POD_LOST"); return null; }
  if (pod && (pod.metadata.uid !== found.metadata.uid || pod.metadata.name !== found.metadata.name)) throw new Error("POD_REPLACED");
  identity(found, found.metadata.name, pod?.metadata.uid ?? found.metadata.uid);
  const template = plan.spec.template as { metadata: { labels: Record<string, string> }; spec: Record<string, unknown> };
  if (!subset(found.metadata.labels, template.metadata.labels)) throw new Error("NETWORK_LABEL_MISMATCH");
  validatePodSpec(found.spec, template.spec);
  return found;
}
export async function cleanupProbe(config: ProbeConfig, api: ProbeApi, plan: Resource, journal: ProbeJournal, clock: ProbeClock, deadline: number, operatorCall?: ProbeCall, setStage: (stage: ApiStage) => void = () => {}): Promise<boolean> {
  configValid(config);
  const state = journal.state, cleanup = state.cleanup, b = config.budgets;
  if (!isDeepStrictEqual(state.config, config) || !state.attempted || clock.cancelled() || clock.now() >= deadline) return false;
  if (cleanup.complete) return true;
  if (cleanup.errors.length || state.deletes.some((entry) => !entry.acknowledged)) return false;
  if (state.pod) identity(state.pod, state.pod.metadata?.name, state.pod.metadata?.uid);
  const jobPath = `${JOBS}/${config.jobName}`;
  const podsPath = `${CORE}/pods?labelSelector=${encodeURIComponent(`batch.kubernetes.io/controller-uid=${config.jobUid}`)}`;
  const expectedPod = (plan.spec.template as { spec: Record<string, unknown> }).spec;
  const callOnce: ProbeCall = async (method, path, limit, body) => {
    const remaining = limit - clock.now();
    if (clock.cancelled() || remaining <= 0) throw new Error("READ_DEADLINE");
    const value = await api.call(method, path, Math.min(b.apiMs, remaining), body);
    if (clock.cancelled() || clock.now() > limit) throw new Error("READ_DEADLINE");
    return value;
  };
  const call: ProbeCall = async (method, path, limit, body) => {
    if (clock.cancelled() || clock.now() >= limit) throw new Error("READ_DEADLINE");
    return operatorCall ? operatorCall(method, path, limit, body) : retryProbeRead(callOnce, clock, b, method, path, limit, body);
  };
  const resource = async (path: string) => await call("GET", path, deadline) as Resource;
  const remove = async (path: string, body: unknown) => {
    if (state.deletes.some((entry) => entry.path === path)) return;
    if (clock.cancelled() || clock.now() >= deadline) throw new Error("READ_DEADLINE");
    const entry = { path, acknowledged: false };
    state.deletes.push(entry); journal.save();
    await call("DELETE", path, deadline, body);
    entry.acknowledged = true; journal.save();
  };
  if (cleanup.startedAt === null) cleanup.startedAt = new Date(clock.now()).toISOString();
  cleanup.deadline = deadline; journal.save();
  setStage("CLEANUP_CAPTURE");
  if (!state.pod) {
    try { state.pod = await captureProbePod(config, plan, null, call, deadline); journal.save(); }
    catch { cleanup.errors.push("POD_CAPTURE_UNCONFIRMED"); journal.save(); return false; }
  }
  setStage("CLEANUP_JOB");
  try {
    const job = await resource(jobPath); identity(job, config.jobName, config.jobUid);
    validateJobControls(job.spec, config.jobUid, plan.spec);
    if (job.spec.activeDeadlineSeconds !== b.totalMs / 1000 || job.spec.backoffLimit !== 0) throw new Error("JOB_CHANGED");
    validatePodSpec((job.spec.template as { spec: Record<string, unknown> }).spec, expectedPod);
    await remove(jobPath, { apiVersion: "v1", kind: "DeleteOptions", propagationPolicy: "Orphan", gracePeriodSeconds: 5, preconditions: { uid: config.jobUid, resourceVersion: job.metadata.resourceVersion } });
    cleanup.jobDeleted = true;
  } catch (error) { if (error instanceof ApiFailure && error.statusCode === 404) cleanup.jobDeleted = true; else cleanup.errors.push("JOB_STOP_UNCONFIRMED"); }
  const originalPod = state.pod;
  if (originalPod && cleanup.jobDeleted) {
    setStage("CLEANUP_POD");
    try {
      identity(originalPod, originalPod.metadata.name, originalPod.metadata.uid);
      const exact = await resource(`${CORE}/pods/${originalPod.metadata.name}`);
      identity(exact, originalPod.metadata.name, originalPod.metadata.uid);
      const controllers = exact.metadata.ownerReferences?.filter((owner) => owner.controller) ?? [];
      if (controllers.length && !owned(exact, config.jobUid)) throw new Error("POD_OWNER_CHANGED");
      validatePodSpec(exact.spec, expectedPod);
      await remove(`${CORE}/pods/${originalPod.metadata.name}`, { apiVersion: "v1", kind: "DeleteOptions", gracePeriodSeconds: 5, preconditions: { uid: originalPod.metadata.uid, resourceVersion: exact.metadata.resourceVersion } });
      cleanup.podDeleted = true;
    } catch (error) { if (error instanceof ApiFailure && error.statusCode === 404) cleanup.podDeleted = true; else cleanup.errors.push("POD_STOP_UNCONFIRMED"); }
  } else if (originalPod) cleanup.errors.push("POD_STOP_SKIPPED_JOB_UNCONFIRMED");
  else cleanup.podDeleted = cleanup.errors.length === 0;
  if (cleanup.jobDeleted && cleanup.podDeleted && !cleanup.errors.length) {
    setStage("CLEANUP_ABSENCE");
    try {
      for (;;) {
        let gone = true;
        for (const path of [jobPath, ...(originalPod ? [`${CORE}/pods/${originalPod.metadata.name}`] : [])]) {
          try { await resource(path); gone = false; } catch (error) { if (!(error instanceof ApiFailure && error.statusCode === 404)) throw error; }
        }
        if (listItems(await call("GET", podsPath, deadline)).length) gone = false;
        if (gone) { cleanup.complete = true; break; }
        await clock.sleep(Math.min(b.pollMs, Math.max(0, deadline - clock.now())));
      }
    } catch { cleanup.errors.push("CLEANUP_DEADLINE_OR_UNCONFIRMED"); }
  }
  journal.save();
  return cleanup.complete;
}

function initiallySuspendedUnused(job: Resource): boolean {
  const status = job.status;
  if (job.metadata.generation !== 1 || job.spec.suspend !== true || job.metadata.deletionTimestamp) return false;
  if (!status) return true;
  if (status.startTime !== undefined || status.completionTime !== undefined || status.completedIndexes !== undefined || status.failedIndexes !== undefined) return false;
  if ([status.active, status.failed, status.succeeded, status.ready, status.terminating].some((count) => count !== undefined && count !== 0)) return false;
  const uncounted = status.uncountedTerminatedPods;
  if (uncounted !== undefined && (!uncounted || Object.keys(uncounted).some((key) => key !== "succeeded" && key !== "failed") || [uncounted.succeeded, uncounted.failed].some((uids) => uids !== undefined && (!Array.isArray(uids) || uids.length !== 0)))) return false;
  const conditions = status.conditions;
  if (conditions === undefined) return true;
  if (!Array.isArray(conditions)) return false;
  if (conditions.length === 0) return true;
  if (conditions.length !== 1) return false;
  const initial = conditions[0];
  return initial?.type === "Suspended" && initial.status === "True" && initial.reason === "JobSuspended" && initial.message === "Job suspended";
}

export async function runProbe(config: ProbeConfig, api: ProbeApi, plan: Resource, policy: Resource, clock: ProbeClock = realClock(), journal: ProbeJournal = probeJournal(config)) {
  configValid(config);
  const b = config.budgets;
  const jobPath = `${JOBS}/${config.jobName}`;
  const pvcPath = `${CORE}/persistentvolumeclaims/${CLAIM}`;
  const podsPath = `${CORE}/pods?labelSelector=${encodeURIComponent(`batch.kubernetes.io/controller-uid=${config.jobUid}`)}`;
  const consumersPath = `${CORE}/pods`;
  const expectedPod = (plan.spec.template as { spec: Record<string, unknown> }).spec;
  const expectedLabels = (plan.spec.template as { metadata: { labels: Record<string, string> } }).metadata.labels;
  if (plan.spec.activeDeadlineSeconds !== b.totalMs / 1000 || plan.spec.backoffLimit !== 0 || expectedPod.activeDeadlineSeconds !== b.totalMs / 1000) throw new Error("PLAN_BUDGET_MISMATCH");
  let attempted = false, pod: Resource | null = null;
  let attemptStart = clock.now(), phaseDeadline = attemptStart + b.totalMs;
  let result: ReturnType<typeof probeBudget> | null = null;
  let status = "PREFLIGHT_REJECTED";
  let execStartedAt: string | null = null;
  const cleanup = journal.state.cleanup;
  let stage: ApiStage = "PREFLIGHT";
  const apiDiagnostics = { lastSuccessfulCall: null as ApiCallDiagnostic | null, failures: [] as (ApiCallDiagnostic & { category: string; previousSuccessfulCall: ApiCallDiagnostic | null })[] };
  const resourceKind = (path: string): ApiResource => path === jobPath ? "JOB" : path === pvcPath ? "PVC" : path === POLICY ? "DENY_POLICY" : path === consumersPath ? "PVC_CONSUMER_LIST" : path === podsPath ? "OWNED_POD_LIST" : pod && path === `${CORE}/pods/${pod.metadata.name}` ? "OWNED_POD" : pod && path === `${CORE}/pods/${pod.metadata.name}/log?container=directio&limitBytes=4096&tailLines=100` ? "DIRECTIO_LOG" : "UNRECOGNIZED";
  const callOnce = async (method: "GET" | "PATCH" | "DELETE", path: string, deadline: number, body?: unknown) => {
    const started = clock.now(), remaining = deadline - started;
    const timeoutMs = Math.min(b.apiMs, Math.max(0, remaining));
    let issued = false, responded = false;
    const diagnostic = (error?: unknown): ApiCallDiagnostic => ({ method, resource: resourceKind(path), stage,
      httpStatus: error instanceof ApiFailure || error instanceof ApiTransportFailure ? error.statusCode : responded ? api.lastResponseStatus?.() ?? null : null,
      startedAt: new Date(started).toISOString(), finishedAt: new Date(clock.now()).toISOString(), timeoutMs, requestIssued: issued,
      acknowledgement: method === "GET" ? "NOT_APPLICABLE" : !issued ? "NOT_ISSUED" : responded ? "RESPONSE_RECEIVED" : error instanceof ApiFailure && error.statusCode >= 400 && error.statusCode < 500 ? "REJECTED_4XX" : "UNKNOWN" });
    try {
      if (remaining <= 0) throw new Error("READ_DEADLINE");
      if (method === "PATCH") { journal.state.attempted = true; journal.save(); }
      issued = true; // Transport invoked; this does not prove delivery to the API server.
      const value = await api.call(method, path, timeoutMs, body);
      responded = true;
      if (clock.now() > deadline) throw new Error("READ_DEADLINE");
      apiDiagnostics.lastSuccessfulCall = diagnostic();
      return value;
    } catch (error) {
      if (apiDiagnostics.failures.length < 8) apiDiagnostics.failures.push({ ...diagnostic(error), category: error instanceof ApiTransportFailure ? error.category : error instanceof ApiFailure ? "HTTP_STATUS" : error instanceof Error && error.message === "READ_DEADLINE" ? !issued ? "BEFORE_REQUEST_DEADLINE" : "AFTER_RESPONSE_DEADLINE" : "UNCLASSIFIED", previousSuccessfulCall: apiDiagnostics.lastSuccessfulCall });
      throw error;
    }
  };
  const call = async (method: "GET" | "PATCH" | "DELETE", path: string, deadline: number, body?: unknown) => {
    return retryProbeRead(callOnce, clock, b, method, path, deadline, body);
  };
  const resource = async (path: string, deadline: number) => await call("GET", path, deadline) as Resource;
  const capture = async (deadline: number) => {
    pod = await captureProbePod(config, plan, pod, call, deadline);
    journal.state.pod = pod; journal.save();
  };
  const exclusiveConsumers = async (deadline: number) => {
    const consumers = listItems(await call("GET", consumersPath, deadline)).filter((item) =>
      (item.spec.volumes as { persistentVolumeClaim?: { claimName?: string } }[] | undefined)?.some((volume) => volume.persistentVolumeClaim?.claimName === CLAIM) && activePvcConsumer(item));
    if (consumers.some((item) => !owned(item, config.jobUid) || item.metadata.deletionTimestamp) || consumers.length > 1) throw new Error("PVC_CONSUMER_CONFLICT");
  };
  try {
    const preflightDeadline = clock.now() + b.freshnessMs;
    const job = await resource(jobPath, preflightDeadline);
    identity(job, config.jobName, config.jobUid, config.jobResourceVersion);
    validateJobControls(job.spec, config.jobUid, plan.spec);
    if (!initiallySuspendedUnused(job)) throw new Error("ATTEMPT_ALREADY_USED");
    if (job.spec.backoffLimit !== 0 || job.spec.activeDeadlineSeconds !== b.totalMs / 1000 || (job.spec.parallelism ?? 1) !== 1 || (job.spec.completions ?? 1) !== 1 || !subset((job.spec.template as { metadata: unknown }).metadata, (plan.spec.template as { metadata: unknown }).metadata)) throw new Error("JOB_BUDGET_MISMATCH");
    validatePodSpec((job.spec.template as { spec: Record<string, unknown> }).spec, expectedPod);
    const pvc = await resource(pvcPath, preflightDeadline);
    identity(pvc, CLAIM, config.pvcUid, config.pvcResourceVersion);
    if (pvc.metadata.deletionTimestamp || pvc.status?.phase !== "Bound" || pvc.spec.volumeName !== `pvc-${PVC_UID}`) throw new Error("PVC_NOT_BOUND");
    const deny = await resource(POLICY, preflightDeadline);
    if (!denyPolicyMatches(deny.spec, policy.spec)) throw new Error("NETWORK_DENY_MISMATCH");
    await exclusiveConsumers(preflightDeadline);
    await capture(preflightDeadline);
    if (pod) throw new Error("ATTEMPT_ALREADY_USED");
    if (clock.cancelled()) throw new Error("CANCELLED");
    attemptStart = Math.floor(clock.now() / 1000) * 1000; phaseDeadline = attemptStart + b.startupMs;
    attempted = true; // Ambiguous PATCH completion still requires guarded cleanup.
    stage = "UNSUSPEND";
    try {
      await call("PATCH", jobPath, Math.min(phaseDeadline, attemptStart + b.apiMs), [
        { op: "test", path: "/metadata/uid", value: config.jobUid },
        { op: "test", path: "/metadata/resourceVersion", value: config.jobResourceVersion },
        { op: "test", path: "/spec/suspend", value: true },
        { op: "replace", path: "/spec/suspend", value: false },
      ]);
    } catch (error) {
      // A definitive rejected PATCH acquires no attempt. Never stop another
      // actor's conflicting mutation. Transport/5xx ambiguity still cleans up.
      if (!journal.state.attempted || error instanceof ApiFailure && error.statusCode >= 400 && error.statusCode < 500) {
        attempted = false; journal.state.attempted = false; journal.save();
      }
      throw error;
    }
    for (;;) {
      stage = "OBSERVATION";
      if (clock.cancelled()) throw new Error("CANCELLED");
      if (clock.now() >= phaseDeadline) { status = clock.now() >= attemptStart + b.totalMs ? "TOTAL_DEADLINE" : pod?.status?.containerStatuses?.some((s) => s.name === "directio" && (s.state.running || s.state.terminated?.startedAt)) ? "EXEC_DEADLINE" : "STARTUP_DEADLINE"; break; }
      const collection = clock.now();
      const readDeadline = Math.min(phaseDeadline, collection + b.freshnessMs);
      const currentJob = await resource(jobPath, readDeadline);
      identity(currentJob, config.jobName, config.jobUid);
      validateJobControls(currentJob.spec, config.jobUid, plan.spec);
      if (currentJob.spec.suspend !== false || currentJob.spec.activeDeadlineSeconds !== b.totalMs / 1000 || currentJob.spec.backoffLimit !== 0 || (currentJob.spec.parallelism ?? 1) !== 1 || (currentJob.spec.completions ?? 1) !== 1) throw new Error("JOB_CHANGED");
      validatePodSpec((currentJob.spec.template as { spec: Record<string, unknown> }).spec, expectedPod);
      const currentPvc = await resource(pvcPath, readDeadline);
      identity(currentPvc, CLAIM, config.pvcUid);
      if (currentPvc.metadata.deletionTimestamp || currentPvc.status?.phase !== "Bound" || currentPvc.spec.volumeName !== `pvc-${PVC_UID}`) throw new Error("PVC_CHANGED");
      await exclusiveConsumers(readDeadline);
      await capture(readDeadline);
      if (pod) {
        const captured: Resource = pod;
        const exact = await resource(`${CORE}/pods/${captured.metadata.name}`, readDeadline);
        identity(exact, captured.metadata.name, captured.metadata.uid);
        if (!owned(exact, config.jobUid)) throw new Error("POD_OWNERSHIP_REJECTED");
        validatePodSpec(exact.spec, expectedPod); pod = exact;
      }
      const currentPod = pod as Resource | null;
      if ((currentPod?.status?.containerStatuses?.filter((s) => s.name === "directio").length ?? 0) > 1) throw new Error("INVALID_CONTAINER_STATUS");
      const runtime = currentPod?.status?.containerStatuses?.find((s) => s.name === "directio");
      const init = currentPod?.status?.initContainerStatuses ?? [];
      if (runtime && runtime.restartCount !== 0 || init.some((s) => s.restartCount !== 0)) throw new Error("RETRY_REJECTED");
      for (const item of init) {
        if (item.state.terminated) {
          if (!Number.isInteger(item.state.terminated.exitCode) || item.state.terminated.exitCode < 0) throw new Error("INVALID_INIT_EXIT");
          const end = timestamp(item.state.terminated.finishedAt);
          const begin = item.state.terminated.startedAt ? timestamp(item.state.terminated.startedAt) : attemptStart;
          if (begin < attemptStart || end < begin || end > clock.now()) throw new Error("INVALID_INIT_END");
        }
      }
      const state = runtime?.state ?? null;
      const startedAt = state?.running?.startedAt ?? state?.terminated?.startedAt ?? null;
      if (execStartedAt !== null && startedAt !== execStartedAt) throw new Error("EXEC_START_CHANGED");
      if (startedAt) execStartedAt = startedAt;
      let logs = "";
      if (state?.running?.startedAt || state?.terminated?.startedAt) {
        const data = await call("GET", `${CORE}/pods/${currentPod!.metadata.name}/log?container=directio&limitBytes=4096&tailLines=100`, readDeadline);
        if (typeof data !== "string") throw new Error("INVALID_LOG_RESPONSE");
        logs = data;
        const afterLogs = await resource(`${CORE}/pods/${currentPod!.metadata.name}`, readDeadline);
        // Status writes legitimately change RV between the log GET and this GET.
        // RV is a mutation precondition, not the identity of a running Pod.
        identity(afterLogs, currentPod!.metadata.name, currentPod!.metadata.uid);
        if (!owned(afterLogs, config.jobUid)) throw new Error("POD_OWNERSHIP_REJECTED");
        validatePodSpec(afterLogs.spec, expectedPod);
        if (!subset(afterLogs.metadata.labels, expectedLabels)) throw new Error("NETWORK_LABEL_MISMATCH");
      }
      const observation: ProbeObservation = {
        jobUid: currentJob.metadata.uid, jobResourceVersion: currentJob.metadata.resourceVersion,
        pvcUid: currentPvc.metadata.uid, pvcResourceVersion: currentPvc.metadata.resourceVersion, claimName: CLAIM,
        podUid: currentPod?.metadata.uid ?? null, podResourceVersion: currentPod?.metadata.resourceVersion ?? null, ownerUid: currentPod ? config.jobUid : null,
        attemptStartedAt: new Date(attemptStart).toISOString(), collectionStartedAt: new Date(collection).toISOString(), observedAt: new Date(clock.now()).toISOString(),
        initFailed: init.some((s) => s.state.terminated && s.state.terminated.exitCode !== 0),
        jobFailed: Boolean(currentJob.status?.failed) || Boolean(currentJob.status?.conditions?.some((c) => c.type === "Failed" && c.status === "True")),
        podPhase: currentPod?.status?.phase ?? null, state,
        writeStarted: /^WRITE_START /m.test(logs), complete: /^DIRECTIO_COMPLETE /m.test(logs),
      };
      result = probeBudget(observation, { jobUid: config.jobUid, pvcUid: config.pvcUid, podUid: currentPod?.metadata.uid ?? null }, clock.now(), b);
      status = result.status;
      if (result.stopRequired) break;
      phaseDeadline = Math.min(result.totalDeadline, result.execDeadline ?? result.startupDeadline);
      await clock.sleep(Math.min(b.pollMs, Math.max(0, phaseDeadline - clock.now())));
    }
  } catch (error) {
    status = attempted && clock.now() >= attemptStart + b.totalMs ? "TOTAL_DEADLINE" : attempted && clock.now() >= phaseDeadline ? phaseDeadline === attemptStart + b.startupMs ? "STARTUP_DEADLINE" : "EXEC_DEADLINE" : error instanceof Error && /^[A-Z_]+$/.test(error.message) ? error.message : "OBSERVATION_REJECTED";
  } finally {
    if (attempted) {
      const entry = clock.now();
      cleanup.startedAt = new Date(entry).toISOString();
      const deadline = cleanupDeadline(entry);
      cleanup.deadline = deadline;
      journal.state.pod = pod; journal.save();
      await cleanupProbe(config, api, plan, journal, { ...clock, cancelled: () => false }, deadline, call, (value) => { stage = value; });
      pod = journal.state.pod;
    }
  }
  return { status, passed: status === "COMPLETE" && cleanup.complete, bytes: status === "COMPLETE" ? result?.bytes ?? null : null, budgets: b, attemptStartedAt: attempted ? new Date(attemptStart).toISOString() : null,
    jobUid: config.jobUid, podUid: (pod as Resource | null)?.metadata.uid ?? null, pvcUid: config.pvcUid, decision: result, cleanup, apiDiagnostics };
}

if (invokedAsEntrypoint("cpa-work-probe-operator", import.meta.url)) {
  let directory: string | undefined;
  let proxy: ReturnType<typeof spawn> | undefined;
  try {
    const [authorization, configPath, socketOption, suppliedSocket] = process.argv.slice(2);
    if (authorization !== "--execute-authorized-target-only" || !configPath || socketOption !== undefined && (socketOption !== "--api-socket" || !suppliedSocket) || process.argv.length > 6) throw new Error("RUNTIME_AUTHORIZATION_REQUIRED");
    const config = JSON.parse(readFileSync(configPath, "utf8")) as ProbeConfig;
    configValid(config);
    const [policy, plan] = parseAllDocuments(readFileSync(new URL("./cpa-work-directio-20261006a.yaml", import.meta.url), "utf8")).map((doc) => doc.toJSON() as Resource);
    if (!policy || !plan) throw new Error("PLAN_MISSING");
    let socketPath = suppliedSocket;
    if (!socketPath) {
      directory = mkdtempSync(join(tmpdir(), "cpa-probe-api-")); socketPath = join(directory, "api.sock");
      proxy = spawn("kubectl", ["proxy", `--unix-socket=${socketPath}`, "--accept-paths=^/(api/v1|apis/(batch/v1|networking.k8s.io/v1))/namespaces/cliproxyapi/"], { stdio: "ignore" });
      let failed = false; proxy.on("error", () => { failed = true; });
      const deadline = Date.now() + config.budgets.freshnessMs;
      for (;;) {
        if (failed || proxy.exitCode !== null || Date.now() >= deadline) throw new Error("API_PROXY_STARTUP_FAILED");
        try { if (lstatSync(socketPath).isSocket()) break; } catch { /* bounded socket startup */ }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    const socket = lstatSync(socketPath);
    const parent = lstatSync(dirname(socketPath));
    if (!socket.isSocket() || socket.uid !== process.getuid?.() || !parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) throw new Error("UNSAFE_API_SOCKET");
    const journalPath = process.env.CPA_PROBE_ATTEMPT_JOURNAL;
    if (journalPath) {
      const parent = lstatSync(dirname(journalPath));
      if (!parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) throw new Error("JOURNAL_REJECTED");
    }
    const receipt = await runProbe(config, unixApi(socketPath), plan, policy, undefined, probeJournal(config, journalPath));
    console.log(JSON.stringify(receipt)); process.exitCode = receipt.passed ? 0 : 1;
  } catch { console.log(JSON.stringify({ status: "OPERATOR_REJECTED", passed: false, bytes: null, cleanup: { complete: false } })); process.exitCode = 1; }
  finally {
    if (proxy) {
      proxy.kill("SIGTERM");
      await Promise.race([new Promise<void>((resolve) => { if (proxy!.exitCode !== null) resolve(); else proxy!.once("exit", () => resolve()); }), new Promise<void>((resolve) => setTimeout(() => { proxy!.kill("SIGKILL"); resolve(); }, 1000))]);
    }
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
}
