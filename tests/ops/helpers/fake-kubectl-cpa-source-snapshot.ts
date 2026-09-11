#!/usr/bin/env node
/** Synthetic read-only CPA Pod used only by the local source-capture test. */

import { createServer } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { pack } from "tar-stream";

const arguments_ = process.argv.slice(2);
const counterPath = process.env.FAKE_CPA_COUNTER_PATH;
const configCounterPath = process.env.FAKE_CPA_CONFIG_COUNTER_PATH;
const uid = "10000000-0000-4000-8000-000000000001";
const metadata = {
  metadata: { namespace: "fixture-cpa", uid: process.env.FAKE_CPA_POD_DRIFT === "uid" ? "20000000-0000-4000-8000-000000000002" : uid, labels: { "app.kubernetes.io/name": "source-adapter" } },
  spec: {
    containers: [{ name: "source-adapter", volumeMounts: [
      { name: "auth", mountPath: "/fixture/source-state" },
      { name: "auth", mountPath: "/fixture/config/config.yaml", subPath: "config.yaml" },
    ], ports: [{ containerPort: 18443, protocol: "TCP" }] }],
    volumes: [{ name: "auth", persistentVolumeClaim: { claimName: process.env.FAKE_CPA_POD_DRIFT === "pvc" ? "unexpected-pvc" : "source-state" } }],
  },
};
const config = [
  'auth-dir: "/fixture/source-state/auth"',
  "plugins:",
  "  configs:",
  "    cpa-key-policy:",
  "      mode: native-access",
  '      native_state_file: "/fixture/source-state/cpa-key-access-policy-state.json"',
  "",
].join("\n");

function sourceConfig(): string {
  if (process.env.FAKE_CPA_CONFIG_DRIFT !== "1") return config;
  if (!configCounterPath) process.exit(95);
  const previous = existsSync(configCounterPath) ? Number(readFileSync(configCounterPath, "utf8")) : 0;
  const revision = previous + 1;
  writeFileSync(configCounterPath, String(revision), { mode: 0o600 });
  return revision === 1 ? config : config.replace('auth-dir: "/fixture/source-state/auth"', 'auth-dir: "/fixture/source-state/auth-after-layout"');
}

function nextRevision(): number {
  if (!counterPath) process.exit(91);
  const previous = existsSync(counterPath) ? Number(readFileSync(counterPath, "utf8")) : 0;
  const revision = previous + 1;
  writeFileSync(counterPath, String(revision), { mode: 0o600 });
  return revision;
}
async function archive(entries: readonly Readonly<{ name: string; content?: string; type?: "directory" | "symlink"; linkname?: string }>[]): Promise<void> {
  const output = pack(); output.pipe(process.stdout);
  for (const entry of entries) {
    await new Promise<void>((resolve, reject) => {
      const done = (error?: Error | null): void => { if (error) reject(error); else resolve(); };
      if (entry.content === undefined) {
        const header = entry.type === undefined
          ? { name: entry.name, type: "directory" as const }
          : { name: entry.name, type: entry.type, ...(entry.linkname === undefined ? {} : { linkname: entry.linkname }) };
        output.entry(header, done);
      } else {
        output.entry({ name: entry.name, ...(entry.type === undefined ? {} : { type: entry.type }), ...(entry.linkname === undefined ? {} : { linkname: entry.linkname }) }, entry.content, done);
      }
    });
  }
  output.finalize();
}
async function servePortForward(): Promise<void> {
  const server = createServer((request, response) => {
    if (request.headers.authorization !== "Bearer fixture-management-token") { response.writeHead(401); response.end(); return; }
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (requestUrl.pathname === "/v0/management/auth-files") { response.end(JSON.stringify({ files: [{ id: "fixture-account.json", type: "codex", provider: "codex", disabled: false, status: "active" }] })); return; }
    if (requestUrl.pathname === "/v0/management/auth-files/models" && requestUrl.searchParams.get("name") === "fixture-account.json") { response.end(JSON.stringify({ models: [{ id: "codex-alpha/gpt-5.6-terra" }] })); return; }
    response.writeHead(404); response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") process.exit(92);
  process.stdout.write(`Forwarding from 127.0.0.1:${address.port} -> 18443\n`);
  const close = (): void => { server.close(() => process.exit(0)); };
  process.once("SIGTERM", close); process.once("SIGINT", close);
}

if (arguments_.includes("get") && arguments_.includes("pod")) {
  process.stdout.write(JSON.stringify(metadata));
} else if (arguments_.includes("exec")) {
  const separator = arguments_.lastIndexOf("--"), tarArguments = separator < 0 ? [] : arguments_.slice(separator + 1);
  const fullCapture = tarArguments.includes("auth");
  if (!fullCapture) await archive([{ name: "config.yaml", content: sourceConfig() }]);
  else {
    const requiredExclusions = ["--exclude=auth/logs", "--exclude=auth/*.json.bak", "--exclude=auth/*.json.bak-*", "--exclude=auth/*.json.bak.*"];
    if (!requiredExclusions.every((entry) => tarArguments.includes(entry))) process.exit(93);
    const revision = nextRevision(), prefix = process.env.FAKE_CPA_UNSTABLE_ROUTE === "1" && revision > 1 ? "codex-other" : "codex-alpha";
    await archive([
      { name: "config.yaml", content: sourceConfig() },
      { name: "auth/" },
      { name: "auth/fixture-account.json", content: JSON.stringify({ type: "codex", prefix, refresh_token: `fixture-refresh-${revision}` }) },
      { name: "cpa-key-access-policy-state.json", content: JSON.stringify({ fixture: true }) },
      ...(process.env.FAKE_CPA_AUTH_ENTRY === "backup" ? [
        { name: "auth/fixture-account.json.bak", content: "fixture-backup" },
        { name: "auth/fixture-account.json.bak-20260909", content: "fixture-backup" },
        { name: "auth/fixture-account.json.bak.20260909", content: "fixture-backup" },
      ] : []),
      ...(process.env.FAKE_CPA_AUTH_ENTRY === "non-json" ? [{ name: "auth/unapproved.txt", content: "fixture-unapproved" }] : []),
      ...(process.env.FAKE_CPA_UNSAFE_ARCHIVE === "traversal" ? [{ name: "../escape.json", content: "{}" }] : []),
      ...(process.env.FAKE_CPA_UNSAFE_ARCHIVE === "symlink" ? [{ name: "auth/escape.json", type: "symlink" as const, linkname: "/outside" }] : []),
    ]);
  }
} else if (arguments_.includes("port-forward")) {
  await servePortForward();
} else {
  process.exit(94);
}
