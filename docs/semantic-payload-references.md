# Online semantic payload references

The `semantic-payload-references` phase consumes committed `.json` receipts from the existing online copy ledgers. It verifies the immutable receipt and streams the target object to validate its original semantic digest, UTF-8 character count, and byte length. It does not copy or delete source objects.

Deploy compatible product readers and migration 153 to every consumer before applying references. Product PR 846 supports format 1 and qualified format 2 references; PR 841 supplies training routing. Configure the exact training endpoint/bucket/region and credentials on readers. The tool derives the identical immutable training binding from its target S3 configuration. Never repoint that binding to a different store.

Use the same source database and target settings as the copy run, and supply all committed receipt directories:

```sh
mtc-object-migration --phase semantic-payload-references \
  --checkpoint /checkpoints/semantic-ref-pass-1.json \
  --receipt-ledger /checkpoints/production-online-shard-0.online-payload-receipts \
  --receipt-ledger /checkpoints/production-online-shard-1.online-payload-receipts \
  --receipt-ledger /checkpoints/production-online-shard-2.online-payload-receipts \
  --receipt-ledger /checkpoints/production-online-shard-3.online-payload-receipts \
  --reference-batch 32
```

The default is read-only eligibility inspection. Applying requires `--apply-references` and a separate checkpoint from a dry run. Repeat the same invocation to advance batches. Batch size is an operational scheduling quantity. The phase shares the existing global source lock with online copy and excludes a second reference applicator. It requires no service outage or writers-quiesced assertion. The pool uses at most two PostgreSQL connections.

Only matching format 1 semantic payloads change. After external verification, a short transaction locks the source row, checks its exact metadata, digest, source MD5 and stored byte length against the previously read version, then replaces the inline string with the qualified reference. Original encoded length, semantic digest and tenant/request/key/principal identity remain unchanged. Outbox, pending financial responsibility, other payload fields and source objects remain intact. Changed or missing source rows are skipped.

Each attempted replacement first fsyncs a prepared audit retaining the original source metadata and immutable copy receipt identity. A confirmed commit writes a final audit. A lost COMMIT response triggers a row reread; an unconfirmed result fails with prepared evidence retained. Replays verify the target again and can recover a missing final audit from the actual qualified row. Existing prepared records are never rebound to a different source version; use a new pass checkpoint for changed versions.

The pass traverses a snapshot of committed receipt filenames in lexical order. Receipts published behind its saved cursor require a new pass checkpoint. Counters describe this pass, not complete migration verification. Copy completion and reference replacement do not authorize deleting old objects or pending rows. PostgreSQL will reuse released TOAST space through normal vacuum; this phase does not run VACUUM FULL or promise immediate filesystem shrinkage.

Validation is the GHA PostgreSQL/RustFS contract: dry-run preservation, original identity/length/digest retention, changed-source skip, unchanged outbox, actual reference apply and committed-row audit recovery. No local build or tests are run.
