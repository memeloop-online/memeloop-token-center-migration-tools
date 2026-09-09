import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { approvedIdentities, runSourceRecovery } from "../../src/source-credential-recovery-apply.ts";

const keys = Array.from({ length: 10 }, (_, index) => `fixture-only-source-original-key-${index}`);
const ids = keys.map((_, index) => `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`);
const token = "fixture-only-existing-authorized-token";
const digest = (raw: Buffer) => createHash("sha256").update(raw).digest("hex");
const source = Buffer.from(JSON.stringify({ "api-keys": keys }));
const capture = Buffer.from(JSON.stringify({ source_config_sha256: digest(source) }));
const approval = {
  version: 1, mode: "credential-recovery-preflight", tenant_external_id: "default",
  source_config_sha256: digest(source), source_receipt_sha256: digest(capture), verified_count: 10,
  identities: ids.map((key_id, source_index) => ({ key_id, source_index, credential_generation: 0, recovery_available: false })),
};

test("source apply rejects altered approval order, duplicate IDs, generations, count and scope", () => {
  assert.equal(approvedIdentities(Buffer.from(JSON.stringify(approval)), source, capture, "default").length, 10);
  for (const bad of [
    { ...approval, tenant_external_id: "other" },
    { ...approval, verified_count: 9 },
    { ...approval, source_config_sha256: "0".repeat(64) },
    { ...approval, identities: [...approval.identities].reverse() },
    { ...approval, identities: approval.identities.map(identity => ({ ...identity, key_id: ids[0] })) },
    { ...approval, identities: approval.identities.map(identity => ({ ...identity, credential_generation: "0" })) },
    { ...approval, identities: approval.identities.map(identity => ({ ...identity, recovery_available: true })) },
  ]) assert.throws(() => approvedIdentities(Buffer.from(JSON.stringify(bad)), source, capture, "default"));
});

test("mutually exclusive modes and explicit expected count are mandatory", async () => {
  await assert.rejects(runSourceRecovery(["--apply", "--verify-only"]));
  await assert.rejects(runSourceRecovery(["--expected-count", "9"]));
  await assert.rejects(runSourceRecovery(["--retry"]));
});

for (const scenario of ["dry-run", "apply", "verify-only", "batch_generation_changed", "tenant_changed", "redirect",
  "put_rejected", "copy_wrong", "copy_generation", "source_changed", "protected_approval", "approval_count", "output_exists"] as const) {
  test(`source-bound recovery ${scenario}: exact fixed operations and no plaintext leakage`, { timeout: 20_000 }, async () => {
    const directory = mkdtempSync(join(tmpdir(), "source-recovery-mock-"));
    chmodSync(directory, 0o700);
    const privateFile = (name: string, raw: Buffer | string) => {
      const path = join(directory, name); writeFileSync(path, raw, { mode: 0o600 }); return path;
    };
    const sourcePath = privateFile("source.yaml", source);
    const capturePath = privateFile("capture.json", capture);
    const approvalPath = privateFile("approved.json", JSON.stringify(scenario === "approval_count" ? { ...approval, verified_count: 9 } : approval));
    const tokenPath = privateFile("service.token", token);
    const output = join(directory, "result.json");
    if (scenario === "protected_approval") chmodSync(approvalPath, 0o644);
    if (scenario === "output_exists") privateFile("result.json", "existing receipt");
    let selfCount = 0, controlCount = 0, putCount = 0, copyCount = 0, unexpected = 0;
    const available = new Set(scenario === "verify-only" ? ids : []);
    const server = createServer(async (req, res) => {
      res.setHeader("Content-Type", "application/json");
      const url = new URL(req.url!, "http://localhost");
      if (url.pathname === "/self/v1/key" && req.method === "GET") {
        selfCount++;
        const index = keys.indexOf((req.headers.authorization ?? "").replace(/^Bearer /, ""));
        assert.ok(index >= 0);
        if (scenario === "redirect") { res.statusCode = 302; res.setHeader("Location", "/leak"); res.end(keys[0]); return; }
        if (scenario === "source_changed" && selfCount === 20) writeFileSync(sourcePath, Buffer.concat([source, Buffer.from("\n")]), { mode: 0o600 });
        res.end(JSON.stringify({ key_id: ids[index], credential_generation: scenario === "batch_generation_changed" && selfCount === 20 ? 1 : 0 }));
        return;
      }
      assert.equal(req.headers.authorization, `Bearer ${token}`);
      if (url.pathname === "/internal/v1/keys" && req.method === "GET") {
        controlCount++;
        assert.equal(url.searchParams.get("tenant_external_id"), "default");
        assert.equal(url.searchParams.get("limit"), "2");
        const id = url.searchParams.get("key_id")!;
        assert.ok(ids.includes(id));
        res.end(JSON.stringify([{ key_id: id, credential_generation: 0, status: "active",
          tenant_external_id: scenario === "tenant_changed" && controlCount === 20 ? "other" : "default",
          credential_recovery_available: available.has(id) }]));
        return;
      }
      const match = /^\/internal\/v1\/keys\/([^/]+)\/credential-recovery(\/copy)?$/.exec(url.pathname);
      if (match && ids.includes(match[1]!)) {
        const id = match[1]!;
        assert.equal(url.search, "");
        if (!match[2] && req.method === "PUT") {
          putCount++;
          assert.equal(selfCount >= 21, true, "both full batch identity passes precede the first recovery PUT");
          assert.equal(controlCount >= 21, true);
          const chunks: Buffer[] = [];
          for await (const chunk of req) chunks.push(Buffer.from(chunk));
          assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()), { key: keys[ids.indexOf(id)] });
          if (scenario === "put_rejected" && putCount === 3) { res.statusCode = 503; res.end(`${token} ${keys[0]}`); return; }
          available.add(id); res.statusCode = 204; res.end(); return;
        }
        if (match[2] && req.method === "POST") {
          copyCount++;
          assert.ok(available.has(id));
          res.end(JSON.stringify({ key_id: id, credential_generation: scenario === "copy_generation" ? 1 : 0,
            key: scenario === "copy_wrong" ? "wrong" : keys[ids.indexOf(id)] }));
          return;
        }
      }
      unexpected++; res.statusCode = 500; res.end(keys[0]);
    });
    await new Promise<void>(resolveListening => server.listen(0, "127.0.0.1", resolveListening));
    const address = server.address(); assert.ok(address && typeof address !== "string");
    const url = `http://127.0.0.1:${address.port}`;
    const mode = scenario === "dry-run" ? [] : scenario === "verify-only" ? ["--verify-only"] : ["--apply"];
    const argv = [
      resolve("src/source-credential-recovery-apply.ts"), "--source-config-file", sourcePath, "--source-receipt-file", capturePath,
      "--approved-identity-receipt-file", approvalPath, "--expected-count", "10", "--tenant", "default",
      "--gateway-api-base-url", url, "--control-api-base-url", url, "--service-token-file", tokenPath,
      "--receipt-output", output, "--allow-http-loopback", ...mode,
    ];
    try {
      const child = spawn(process.execPath, argv, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      child.stdout.on("data", chunk => { stdout += chunk; });
      child.stderr.on("data", chunk => { stderr += chunk; });
      const code = await new Promise<number | null>((resolveExit, rejectExit) => { child.on("error", rejectExit); child.on("exit", resolveExit); });
      const success = ["dry-run", "apply", "verify-only"].includes(scenario);
      assert.equal(code, success ? 0 : 2, stderr);
      assert.equal(unexpected, 0);
      const receiptText = existsSync(output) ? readFileSync(output, "utf8") : "";
      for (const secret of [...keys, ...ids, token]) {
        assert.equal(`${stdout}${stderr}${receiptText}`.includes(secret), false, "diagnostics and receipt cannot contain plaintext or identities");
      }
      if (scenario === "output_exists") { assert.equal(receiptText, "existing receipt"); assert.equal(selfCount, 0); }
      else if (existsSync(output)) {
        assert.equal(statSync(output).mode & 0o777, 0o600);
        const receipt = JSON.parse(receiptText);
        assert.equal(receipt.success, success);
        if (scenario === "put_rejected") { assert.equal(receipt.stored_count, 2); assert.equal(receipt.write_outcome_uncertain, true); }
      }
      assert.equal(putCount, scenario === "apply" ? 10 : scenario === "put_rejected" ? 3 : ["copy_wrong", "copy_generation"].includes(scenario) ? 1 : 0);
      assert.equal(copyCount, ["apply", "verify-only"].includes(scenario) ? 20 : scenario === "put_rejected" ? 4 : ["copy_wrong", "copy_generation"].includes(scenario) ? 1 : 0);
      if (scenario === "dry-run") { assert.equal(selfCount, 20); assert.equal(controlCount, 20); }
      if (scenario === "redirect") assert.equal(selfCount, 1, "redirects and retries must not occur");
    } finally {
      server.closeAllConnections(); await new Promise<void>(resolveClosed => server.close(() => resolveClosed()));
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
