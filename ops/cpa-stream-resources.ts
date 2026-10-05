import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { stringify } from "yaml";
import { COPY, requireCopy, safeFailure, validateEndpoint } from "./lib/cpa-stream.ts";

const namespace = "cliproxyapi";
const codeName = "mtc-cpa-stream-code-20261005a";
const image = "ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126";
const sources = {
  "cpa-frozen-stream-copy.ts": readFileSync(new URL("./cpa-frozen-stream-copy.ts", import.meta.url), "utf8"),
  "cpa-stream.ts": readFileSync(new URL("./lib/cpa-stream.ts", import.meta.url), "utf8"),
};
const codeHash = createHash("sha256").update(JSON.stringify(sources)).digest("hex");
const labels = (role: string) => ({ "memeloop.io/cpa-stream-run": COPY.run, "app.kubernetes.io/name": `cpa-stream-${role}` });

export function job(role: "reader" | "receiver", receiverIp?: string): unknown {
  if (role === "reader") validateEndpoint(receiverIp ?? "");
  const receiver = role === "receiver";
  const destination = receiver ? [{ name: "destination", mountPath: "/destination" }] : [];
  const privateDirectory = receiver ? `mkdirSync('${COPY.destination}', {mode:0o700}); chownSync('${COPY.destination}',10001,10001);` : "";
  return {
    apiVersion: "batch/v1", kind: "Job",
    metadata: { name: `mtc-cpa-stream-${role}-20261005a`, namespace, labels: labels(role), annotations: { "memeloop.io/tool-sha256": codeHash } },
    spec: {
      suspend: true, backoffLimit: 0, activeDeadlineSeconds: 1800,
      template: { metadata: { labels: labels(role) }, spec: {
        restartPolicy: "Never", terminationGracePeriodSeconds: 10, automountServiceAccountToken: false, enableServiceLinks: false,
        nodeSelector: { "kubernetes.io/hostname": receiver ? "westlake" : "sansheng-hv" },
        securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: { type: "RuntimeDefault" } },
        initContainers: [{
          name: "private-new-directories", image, command: ["node", "--input-type=module", "-e"],
          args: [`import {mkdirSync,chownSync,chmodSync} from 'node:fs'; chmodSync('/identity',0o700); chownSync('/identity',10001,10001); ${privateDirectory}`],
          resources: { requests: { cpu: "10m", memory: "16Mi" }, limits: { cpu: "100m", memory: "64Mi" } },
          securityContext: { runAsNonRoot: false, runAsUser: 0, runAsGroup: 0, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"], add: ["CHOWN"] } },
          volumeMounts: [{ name: "identity", mountPath: "/identity" }, ...destination],
        }],
        containers: [{
          name: role, image, command: ["node", "/tool/cpa-frozen-stream-copy.ts", role],
          env: [
            { name: "NODE_NAME", valueFrom: { fieldRef: { fieldPath: "spec.nodeName" } } },
            { name: "POD_NAME", valueFrom: { fieldRef: { fieldPath: "metadata.name" } } },
            { name: "POD_IP", valueFrom: { fieldRef: { fieldPath: "status.podIP" } } },
            ...(receiver ? [] : [{ name: "CPA_RECEIVER_IP", value: receiverIp }]),
          ],
          resources: { requests: { cpu: "50m", memory: "48Mi", "ephemeral-storage": "16Mi" }, limits: { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" } },
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } },
          volumeMounts: [{ name: "identity", mountPath: "/identity" }, { name: "code", mountPath: "/tool", readOnly: true }, ...(receiver ? destination : [{ name: "source", mountPath: "/source", readOnly: true }])],
        }],
        volumes: [
          { name: "identity", emptyDir: { medium: "Memory", sizeLimit: "4Mi" } },
          { name: "code", configMap: { name: codeName, defaultMode: 0o444, items: [{ key: "cpa-frozen-stream-copy.ts", path: "cpa-frozen-stream-copy.ts" }, { key: "cpa-stream.ts", path: "lib/cpa-stream.ts" }] } },
          receiver ? { name: "destination", persistentVolumeClaim: { claimName: "mtc-cpa-recovery-work-20261005" } } : { name: "source", persistentVolumeClaim: { claimName: "mtc-session-archive-v08-live-clone-20260919a", readOnly: true } },
        ],
      } },
    },
  };
}

export function policies(): unknown[] {
  return (["reader", "receiver"] as const).map((role) => ({
    apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
    metadata: { name: `mtc-cpa-stream-${role}-20261005a`, namespace },
    spec: {
      podSelector: { matchLabels: labels(role) }, policyTypes: ["Ingress", "Egress"],
      ingress: role === "reader" ? [] : [{ from: [{ podSelector: { matchLabels: labels("reader") } }], ports: [{ protocol: "TCP", port: COPY.port }] }],
      egress: role === "receiver" ? [] : [{ to: [{ podSelector: { matchLabels: labels("receiver") } }], ports: [{ protocol: "TCP", port: COPY.port }] }],
    },
  }));
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") { console.log("cpa-stream-resources code|policies|reader|receiver; renders only, fixed resources, reader requires CPA_RECEIVER_IP"); return; }
  requireCopy(args.length === 1, "ARGUMENTS");
  let documents: unknown[];
  switch (args[0]) {
    case "code": documents = [{ apiVersion: "v1", kind: "ConfigMap", metadata: { name: codeName, namespace, annotations: { "memeloop.io/tool-sha256": codeHash } }, immutable: true, data: sources }]; break;
    case "policies": documents = policies(); break;
    case "reader": documents = [job("reader", process.env.CPA_RECEIVER_IP)]; break;
    case "receiver": documents = [job("receiver")]; break;
    default: throw new Error("ARGUMENTS");
  }
  console.log(documents.map((document) => stringify(document)).join("---\n"));
}

if (process.argv[1]?.endsWith("cpa-stream-resources.ts")) {
  try { main(); } catch (error) { console.error(safeFailure(error)); process.exitCode = 1; }
}
