import { STREAM_PROFILES, requireCopy, validateEndpoint } from "./cpa-stream.ts";
import { readFileSync } from "node:fs";

export type ObservedPod = {
  metadata: { uid: string; ownerReferences?: { uid: string }[] };
  spec: { nodeName?: string };
  status?: {
    phase?: string;
    podIP?: string;
    initContainerStatuses?: { name: string; state?: { terminated?: { exitCode: number } } }[];
    containerStatuses?: { name: string; state?: { running?: unknown; terminated?: { exitCode: number } } }[];
  };
};

export function selectSegmentedPod(items: ObservedPod[], jobUid: string, role: "reader" | "receiver", elapsedMs: number): { state: "wait" } | { state: "ready"; uid: string; ip: string } {
  requireCopy(Number.isFinite(elapsedMs) && elapsedMs >= 0 && elapsedMs < 120000, "BUSINESS_DEADLINE");
  requireCopy(items.length <= 1, "POD_COUNT");
  const pod = items[0];
  if (!pod) return { state: "wait" };
  requireCopy(pod.metadata.ownerReferences?.some((owner) => owner.uid === jobUid), "POD_OWNER");
  requireCopy(!["Failed", "Succeeded"].includes(pod.status?.phase ?? ""), "POD_TERMINAL");
  const init = pod.status?.initContainerStatuses ?? [];
  const containers = pod.status?.containerStatuses ?? [];
  for (const container of [...init, ...containers]) requireCopy(!container.state?.terminated || container.state.terminated.exitCode === 0, "POD_TERMINATED");
  if (pod.status?.phase !== "Running" || !pod.status.podIP || !init.length || !init.every((container) => container.state?.terminated?.exitCode === 0) || !containers.some((container) => container.name === role && container.state?.running)) return { state: "wait" };
  requireCopy(pod.spec.nodeName === (role === "reader" ? "sansheng-hv" : STREAM_PROFILES.segmented.receiverNode), "NODE_PLACEMENT");
  if (role === "receiver") validateEndpoint(pod.status.podIP, "segmented");
  else requireCopy(/^10\.42\.2\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(pod.status.podIP), "READER_IP_SCOPE");
  return { state: "ready", uid: pod.metadata.uid, ip: pod.status.podIP };
}

export function confirmedSegmentedBytes(events: { confirmedBytes?: unknown; phase?: unknown; segment?: unknown }[], previous: number): number {
  requireCopy(Number.isSafeInteger(previous) && previous >= 0 && previous <= 16777216, "PROGRESS_RANGE");
  let confirmed = previous;
  for (const event of events) {
    if (event.confirmedBytes !== undefined) {
      requireCopy(Number.isSafeInteger(event.confirmedBytes) && typeof event.confirmedBytes === "number" && event.confirmedBytes >= 0 && event.confirmedBytes <= 16777216, "PROGRESS_RANGE");
      confirmed = Math.max(confirmed, event.confirmedBytes);
    }
    if (event.phase === "ack-read") {
      requireCopy(Number.isSafeInteger(event.segment) && typeof event.segment === "number" && event.segment >= 1 && event.segment <= 4, "PROGRESS_SEGMENT");
      confirmed = Math.max(confirmed, event.segment * 4194304);
    }
  }
  return confirmed;
}

if (process.argv[1]?.endsWith("cpa-stream-observation.ts")) {
  const input = readFileSync(0, "utf8");
  requireCopy(Buffer.byteLength(input) <= 131072, "OBSERVATION_SIZE");
  const request = JSON.parse(input) as { operation: string; items: ObservedPod[]; jobUid: string; role: "reader" | "receiver"; elapsedMs: number; events: Parameters<typeof confirmedSegmentedBytes>[0]; previous: number };
  requireCopy(process.argv.length === 2, "ARGUMENTS");
  if (request.operation === "pod") {
    requireCopy(request.role === "reader" || request.role === "receiver", "ARGUMENTS");
    console.log(JSON.stringify(selectSegmentedPod(request.items, request.jobUid, request.role, request.elapsedMs)));
  } else {
    requireCopy(request.operation === "progress", "ARGUMENTS");
    console.log(JSON.stringify({ confirmedBytes: confirmedSegmentedBytes(request.events, request.previous) }));
  }
}
