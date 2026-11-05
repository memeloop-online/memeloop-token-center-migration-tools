// Dependency-free S3 bucket readiness probe/bootstrap. No object overwrite or deletion.
import { createHash, createHmac } from "node:crypto";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const hmac = (key: string | Buffer, value: string) => createHmac("sha256", key).update(value).digest();

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error("configuration");
  return value;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--create") || args.length > 1) throw new Error("arguments");
  const endpoint = new URL(required("MTC_S3_ENDPOINT"));
  const bucket = required("MTC_S3_BUCKET");
  const region = process.env.MTC_S3_REGION || "us-east-1";
  const access = required("MTC_S3_ACCESS_KEY");
  const secret = required("MTC_S3_SECRET_KEY");
  if (process.env.MTC_OBJECT_MIGRATION_TEST_NAMESPACE !== "memeloop-token-center-test"
      || !bucket || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)
      || !access || !secret || endpoint.username || endpoint.password
      || endpoint.search || endpoint.hash || endpoint.pathname !== "/"
      || !["http:", "https:"].includes(endpoint.protocol)
      || (endpoint.protocol === "http:" && process.env.MTC_S3_ALLOW_HTTP !== "true")) {
    throw new Error("configuration");
  }
  const target = new URL(`/${bucket}`, endpoint);
  async function request(method: "HEAD" | "PUT"): Promise<number> {
    const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const day = date.slice(0, 8);
    const payload = sha256("");
    const scope = `${day}/${region}/s3/aws4_request`;
    const headers = `host:${target.host}\nx-amz-content-sha256:${payload}\nx-amz-date:${date}\n`;
    const signed = "host;x-amz-content-sha256;x-amz-date";
    const canonical = [method, target.pathname, "", headers, signed, payload].join("\n");
    const key = hmac(hmac(hmac(hmac(`AWS4${secret}`, day), region), "s3"), "aws4_request");
    const signature = createHmac("sha256", key)
      .update(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${sha256(canonical)}`).digest("hex");
    const response = await fetch(target, {
      method, redirect: "error", signal: AbortSignal.timeout(20_000),
      headers: { "x-amz-content-sha256": payload, "x-amz-date": date,
        authorization: `AWS4-HMAC-SHA256 Credential=${access}/${scope}, SignedHeaders=${signed}, Signature=${signature}` },
    });
    await response.body?.cancel();
    return response.status;
  }
  const before = await request("HEAD");
  if (before === 200) {
    console.log(JSON.stringify({ target_ready: true, created: false }));
    return;
  }
  if (before !== 404 || !args.includes("--create")) {
    console.error(JSON.stringify({ target_ready: false, bucket_head_status: before }));
    process.exitCode = 1;
    return;
  }
  const created = await request("PUT");
  // A concurrent owner may have created the same bucket. HEAD still has to
  // prove that these credentials can read this exact target before success.
  if (![200, 204, 409].includes(created) || await request("HEAD") !== 200) {
    throw new Error("bucket_not_ready");
  }
  console.log(JSON.stringify({ target_ready: true, created: created !== 409 }));
}

main().catch(() => {
  // Transport/auth errors can embed credential-bearing request information.
  // Emit fixed diagnostics only, never the error, headers or environment.
  console.error(JSON.stringify({ target_ready: false, reason: "target_prepare_failed" }));
  process.exitCode = 1;
});
