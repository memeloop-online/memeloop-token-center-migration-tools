import { createHash, createHmac, randomUUID } from "node:crypto";
import { open, rename, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

type Query = Record<string, string>;
type Get = (query: Query, key?: string) => Promise<{ status: number; xml: string }>;

const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const hmac = (key: string | Buffer, value: string) => createHmac("sha256", key).update(value).digest();
const encode = (value: string) => encodeURIComponent(value).replace(/[!'()*]/gu, (character) =>
  `%${character.charCodeAt(0).toString(16).toUpperCase()}`);

function text(xml: string, tag: string): string | undefined {
  const value = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "u").exec(xml)?.[1];
  return value?.replace(/&(#x[0-9a-f]+|#[0-9]+|amp|lt|gt|quot|apos);/giu, (_, entity: string) => {
    if (entity.startsWith("#x")) return String.fromCodePoint(parseInt(entity.slice(2), 16));
    if (entity.startsWith("#")) return String.fromCodePoint(parseInt(entity.slice(1), 10));
    return ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" } as Record<string, string>)[entity]!;
  });
}

function blocks(xml: string, tag: string): string[] {
  if (/<!DOCTYPE|<!ENTITY/iu.test(xml)) throw new Error("unsupported_xml");
  return [...xml.matchAll(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "gu"))]
    .map((match) => match[1]!);
}

function size(xml: string): bigint {
  const value = text(xml, "Size");
  if (!value || !/^\d+$/u.test(value)) throw new Error("invalid_size");
  return BigInt(value);
}

export function storageClass(key: string): string {
  if (key.startsWith("raw-cache/")) return "cache_candidate_requires_reference_and_retention_proof";
  if (/^tenants\/[^/]+\/(?:cas|raw|conversations)\//u.test(key)) return "protected_training_or_shared_cas";
  if (key.startsWith("staging/") || key.startsWith("conversation-staging/")) return "staging_requires_owner_fence";
  if (key.startsWith("readiness/")) return "readiness_requires_owner_fence";
  return "unclassified_protected";
}

export async function audit(get: Get, maximumPages: number, prefix = "") {
  if (!Number.isSafeInteger(maximumPages) || maximumPages < 1 || maximumPages > 100) {
    throw new Error("invalid_page_budget");
  }
  const report = {
    version: 1,
    started_at: new Date().toISOString(),
    completed_at: "",
    read_only: true,
    source_writers_quiesced: false,
    snapshot_consistent: false,
    deletion_authorized: false,
    proven_reclaimable_bytes: "0",
    prefix,
    policies: {} as Record<string, { status: number; xml?: string; error?: string }>,
    objects: {
      pages: 0, complete: false, count: 0, bytes: "0", error: null as string | null,
      classes: {} as Record<string, { count: number; bytes: string }>,
    },
    multipart: {
      pages: 0, complete: false, error: null as string | null,
      uploads: [] as { key_sha256: string; upload_id_sha256: string; storage_class: string;
        initiated: string | null; listed_parts: number; listed_bytes: string; parts_complete: boolean; error?: string }[],
    },
  };
  for (const policy of ["versioning", "lifecycle"]) {
    try {
      const response = await get({ [policy]: "" });
      report.policies[policy] = { status: response.status, xml: response.xml };
    } catch {
      report.policies[policy] = { status: 0, error: "policy_read_failed" };
    }
  }
  try {
    let token = "";
    const seen = new Set<string>();
    for (let page = 0; page < maximumPages; page++) {
      const response = await get({
        "list-type": "2", prefix, "max-keys": "1000",
        ...(token ? { "continuation-token": token } : {}),
      });
      if (response.status !== 200) throw new Error("list_failed");
      for (const object of blocks(response.xml, "Contents")) {
        const key = text(object, "Key");
        if (key === undefined || !key.startsWith(prefix)) throw new Error("invalid_key");
        const bytes = size(object);
        const group = report.objects.classes[storageClass(key)] ??= { count: 0, bytes: "0" };
        group.count++;
        group.bytes = (BigInt(group.bytes) + bytes).toString();
        report.objects.count++;
        report.objects.bytes = (BigInt(report.objects.bytes) + bytes).toString();
      }
      report.objects.pages++;
      const truncated = text(response.xml, "IsTruncated");
      if (truncated === "false") {
        report.objects.complete = true;
        break;
      }
      token = text(response.xml, "NextContinuationToken") || "";
      if (truncated !== "true" || !token || seen.has(token)) throw new Error("invalid_cursor");
      seen.add(token);
    }
  } catch {
    report.objects.error = "object_inventory_incomplete";
  }
  try {
    let keyMarker = "";
    let uploadMarker = "";
    const seen = new Set<string>();
    for (let page = 0; page < maximumPages; page++) {
      const response = await get({
        uploads: "", prefix, "max-uploads": "10",
        ...(keyMarker ? { "key-marker": keyMarker, "upload-id-marker": uploadMarker } : {}),
      });
      if (response.status !== 200) throw new Error("uploads_failed");
      for (const upload of blocks(response.xml, "Upload")) {
        const key = text(upload, "Key");
        const uploadId = text(upload, "UploadId");
        if (key === undefined || !key.startsWith(prefix) || !uploadId) throw new Error("invalid_upload");
        const receipt = {
          key_sha256: digest(key), upload_id_sha256: digest(uploadId), storage_class: storageClass(key),
          initiated: text(upload, "Initiated") ?? null, listed_parts: 0, listed_bytes: "0",
          parts_complete: false, error: undefined as string | undefined,
        };
        report.multipart.uploads.push(receipt);
        try {
          let marker = "";
          const partCursors = new Set<string>();
          for (let partPage = 0; partPage < maximumPages; partPage++) {
            const parts = await get({ uploadId, "max-parts": "1000", ...(marker ? { "part-number-marker": marker } : {}) }, key);
            if (parts.status !== 200) throw new Error("parts_failed");
            for (const part of blocks(parts.xml, "Part")) {
              receipt.listed_parts++;
              receipt.listed_bytes = (BigInt(receipt.listed_bytes) + size(part)).toString();
            }
            const truncated = text(parts.xml, "IsTruncated");
            if (truncated === "false") {
              receipt.parts_complete = true;
              break;
            }
            marker = text(parts.xml, "NextPartNumberMarker") || "";
            if (truncated !== "true" || !/^\d+$/u.test(marker) || partCursors.has(marker)) throw new Error("invalid_parts_cursor");
            partCursors.add(marker);
          }
        } catch {
          receipt.error = "parts_unknown_or_upload_changed";
        }
      }
      report.multipart.pages++;
      const truncated = text(response.xml, "IsTruncated");
      if (truncated === "false") {
        report.multipart.complete = true;
        break;
      }
      keyMarker = text(response.xml, "NextKeyMarker") || "";
      uploadMarker = text(response.xml, "NextUploadIdMarker") || "";
      const cursor = JSON.stringify([keyMarker, uploadMarker]);
      if (truncated !== "true" || !keyMarker || seen.has(cursor)) throw new Error("invalid_upload_cursor");
      seen.add(cursor);
    }
  } catch {
    report.multipart.error = "multipart_inventory_incomplete";
  }
  report.completed_at = new Date().toISOString();
  return report;
}

function signedGet(): Get {
  const endpoint = new URL(process.env.MTC_S3_ENDPOINT || "");
  const bucket = process.env.MTC_S3_BUCKET || "";
  const access = process.env.MTC_S3_ACCESS_KEY || "";
  const secret = process.env.MTC_S3_SECRET_KEY || "";
  const region = process.env.MTC_S3_REGION || "us-east-1";
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket) || !access || !secret ||
      endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/" ||
      !["http:", "https:"].includes(endpoint.protocol) ||
      (endpoint.protocol === "http:" && process.env.MTC_S3_ALLOW_HTTP !== "true")) throw new Error("configuration");
  return async (params, key) => {
    const path = `/${bucket}${key === undefined ? "" : `/${key.split("/").map(encode).join("/")}`}`;
    const query = Object.entries(params).map(([name, value]) => [encode(name), encode(value)] as const)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([name, value]) => `${name}=${value}`).join("&");
    const date = new Date().toISOString().replace(/[:-]|\.\d{3}/gu, "");
    const day = date.slice(0, 8);
    const payload = digest("");
    const scope = `${day}/${region}/s3/aws4_request`;
    const headers = `host:${endpoint.host}\nx-amz-content-sha256:${payload}\nx-amz-date:${date}\n`;
    const signed = "host;x-amz-content-sha256;x-amz-date";
    const canonical = ["GET", path, query, headers, signed, payload].join("\n");
    const signingKey = hmac(hmac(hmac(hmac(`AWS4${secret}`, day), region), "s3"), "aws4_request");
    const signature = createHmac("sha256", signingKey).update(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${digest(canonical)}`).digest("hex");
    const response = await fetch(new URL(`${path}?${query}`, endpoint), {
      method: "GET", redirect: "error", signal: AbortSignal.timeout(20_000),
      headers: { "x-amz-content-sha256": payload, "x-amz-date": date,
        authorization: `AWS4-HMAC-SHA256 Credential=${access}/${scope}, SignedHeaders=${signed}, Signature=${signature}` },
    });
    if (!response.body) return { status: response.status, xml: "" };
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > 4 * 1024 * 1024) throw new Error("metadata_response_too_large");
      chunks.push(chunk);
    }
    return { status: response.status, xml: Buffer.concat(chunks).toString("utf8") };
  };
}

async function main() {
  const options = new Map<string, string>();
  const args = process.argv.slice(2);
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index]!;
    const value = args[index + 1];
    if (!["--output", "--max-pages", "--prefix"].includes(flag) || value === undefined || options.has(flag)) throw new Error("arguments");
    options.set(flag, value);
  }
  const output = options.get("--output");
  if (!output) throw new Error("output_required");
  const report = await audit(signedGet(), Number(options.get("--max-pages") ?? "1"), options.get("--prefix") ?? "");
  const temporary = `${resolve(output)}.${randomUUID()}.tmp`;
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(JSON.stringify(report, null, 2) + "\n");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, resolve(output));
  } finally {
    await rm(temporary, { force: true });
  }
  console.log(JSON.stringify({ report_written: true, object_inventory_complete: report.objects.complete,
    multipart_list_complete: report.multipart.complete, deletion_authorized: false }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    console.error(JSON.stringify({ report_written: false, reason: "storage_audit_failed" }));
    process.exitCode = 1;
  });
}
