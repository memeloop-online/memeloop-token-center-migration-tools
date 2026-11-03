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
