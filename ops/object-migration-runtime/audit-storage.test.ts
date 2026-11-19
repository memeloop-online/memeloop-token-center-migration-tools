import assert from "node:assert/strict";
import test from "node:test";
import { audit, storageClass } from "./audit-storage.ts";

test("cache names never authorize deletion of durable originals or unknown data", () => {
  assert.equal(storageClass("tenants/a/cas/v1/object"), "protected_training_or_shared_cas");
  assert.equal(storageClass("tenants/a/raw/v1/object"), "protected_training_or_shared_cas");
  assert.equal(storageClass("raw-cache-other/object"), "unclassified_protected");
  assert.equal(storageClass("raw-cache/object"), "cache_candidate_requires_reference_and_retention_proof");
});

test("bounded metadata pagination distinguishes partial objects from complete multipart and parts", async () => {
  const report = await audit(async (query, key) => {
    if ("lifecycle" in query) return { status: 404, xml: "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>" };
    if ("versioning" in query) return { status: 200, xml: "<VersioningConfiguration/>" };
    if ("list-type" in query) return { status: 200, xml: "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>tenants/a/cas/v1/object</Key><Size>9007199254740993</Size></Contents></ListBucketResult>" };
    if ("uploads" in query) return { status: 200, xml: "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>staging/a&amp;b</Key><UploadId>fixture-id</UploadId><Initiated>2026-01-01T00:00:00Z</Initiated></Upload></ListMultipartUploadsResult>" };
    assert.equal(key, "staging/a&b");
    assert.equal(query.uploadId, "fixture-id");
    return { status: 200, xml: "<ListPartsResult><IsTruncated>false</IsTruncated><Part><Size>5242880</Size></Part></ListPartsResult>" };
  }, 1);
  assert.equal(report.objects.complete, false);
  assert.equal(report.objects.bytes, "9007199254740993");
  assert.equal(report.multipart.complete, true);
  assert.equal(report.multipart.uploads[0]?.listed_bytes, "5242880");
  assert.equal(report.multipart.uploads[0]?.parts_complete, true);
  assert.equal(report.proven_reclaimable_bytes, "0");
  assert.equal(report.deletion_authorized, false);
  assert(!JSON.stringify(report).includes("fixture-id"));
  assert(!JSON.stringify(report).includes("staging/a&b"));
});

test("timeouts and vanished uploads are unknown, not zero-byte reclamation receipts", async () => {
  const report = await audit(async (query) => {
    if ("uploads" in query) return { status: 200, xml: "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>staging/a</Key><UploadId>id</UploadId></Upload></ListMultipartUploadsResult>" };
    throw new Error("must not publish endpoint or secret");
  }, 1);
  assert.equal(report.objects.complete, false);
  assert.equal(report.multipart.uploads[0]?.parts_complete, false);
  assert.equal(report.multipart.uploads[0]?.error, "parts_unknown_or_upload_changed");
  assert(!JSON.stringify(report).includes("secret"));
});

test("repeated cursors and malformed inventories fail closed", async () => {
  const report = await audit(async (query) => {
    if ("list-type" in query) return { status: 200, xml: "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>" };
    if ("uploads" in query) return { status: 200, xml: "<ListMultipartUploadsResult/>" };
    return { status: 200, xml: "" };
  }, 3);
  assert.equal(report.objects.pages, 2);
  assert.equal(report.objects.error, "object_inventory_incomplete");
  assert.equal(report.multipart.complete, false);
});

test("existing locator receipts classify recoverable candidates without certifying bytes or retirement", async () => {
  const { auditLocatorGaps } = await import("./audit-storage.ts");
  const tenant = "00000000-0000-0000-0000-000000000001";
  const id = "00000000-0000-0000-0000-000000000002";
  const prefix = "migration-receipts/conversation-v1/fixture/locators/";
  const checkpoint = {format_version:1,identity:"fixture",copied_rows:0,gap_rows:1,complete:true,digest:"original"};
  const report = await auditLocatorGaps(async (query,key) => {
    if (!key) return {status:200,xml:`<ListBucketResult><Contents><Key>${prefix}a.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`};
    return {status:200,xml:JSON.stringify({format_version:1,identity:"fixture",cursor:{kind:"response",tenant,identity:id},gap_reason:"source_gap"})};
  }, async (_,key) => {
    assert.equal(key, `tenants/${tenant}/raw/v1/${id}/response.json`);
    return {status:200,xml:JSON.stringify({object_locator:`tenants/${tenant}/cas/v1/object`,blake3_digest:"a".repeat(64),size_bytes:12})};
  },checkpoint,1);
  assert.equal(report.counts_match,true);
  assert.equal(report.gaps[0]?.source_candidate,"raw_root_candidate_unverified");
  assert.equal(report.coverage_state,"enumerated_digest_unverified");
  assert.equal(report.body_bytes_verified,false);
  assert.equal(report.deletion_authorized,false);
  assert.equal(checkpoint.digest,"original");
});

test("receipt page budget stays partial and source denial remains unknown", async () => {
  const { auditLocatorGaps } = await import("./audit-storage.ts");
  const prefix = "migration-receipts/conversation-v1/fixture/locators/";
  const target = async (_query: Record<string,string>,key?:string) => !key
    ? {status:200,xml:`<ListBucketResult><Contents><Key>${prefix}a.json</Key></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken></ListBucketResult>`}
    : {status:200,xml:JSON.stringify({format_version:1,identity:"fixture",cursor:{kind:"request",tenant:"00000000-0000-0000-0000-000000000001",identity:"00000000-0000-0000-0000-000000000002"},gap_reason:"source_gap"})};
  const report = await auditLocatorGaps(target,async()=>({status:403,xml:""}),{format_version:1,identity:"fixture",copied_rows:0,gap_rows:1,complete:true,digest:"original"},1);
  assert.equal(report.receipts,1);
  assert.equal(report.counts_match,false);
  assert.equal(report.pagination_exhausted,false);
  assert.equal(report.coverage_state,"partial");
  assert.equal(report.gaps[0]?.source_candidate,"raw_root_access_unknown");
});
