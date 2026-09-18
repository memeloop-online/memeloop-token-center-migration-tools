# Retired API2 trial production purge

`purge-retired-api2-trial` is a one-shot, reviewed-manifest cleanup for the
retired API2/CPA bridge trial cohort. It removes product/configuration objects
and neutralizes retained conversation presentation metadata without deleting
traffic, billing, generation or conversation facts.

The public repository contains no production IDs, aliases, labels, receipts or
database coordinates. Build the manifest in the approved evidence system, keep
it and every receipt in a private `0600` file, and retain its SHA-256 beside the
change approval.

## Fixed scope and invariants

The command rejects any manifest that is not exactly:

- 17 `deleted_upstream_account_snapshots` whose reviewed names match
  `legacy-cpa-bridge-*` or `cpa-*`;
- 7 `key_records`, each still `revoked` and archived at its reviewed CAS
  timestamp;
- 16 total credential routing grants plus credential relation revisions;
- a complete, sorted description of every credential, recovery envelope,
  source proof and credential-group membership belonging to those keys.

Each snapshot and key is bound to its tenant and all reviewed lifecycle fields.
Every child relation is compared in both directions: a missing, extra or changed
row aborts the transaction. The command also rejects unreviewed legacy-pattern
snapshot names or credential aliases in the selected tenant.

Before deletion it sets `key_records.issued_key_ciphertext` and
`key_credentials.secret_plaintext` to `NULL`, overwrites every reviewed recovery
`ciphertext`, and clears cached rotation responses. It inventories and removes
matching `legacy_key_credentials` and key-scoped rotation replay rows before
deleting the reviewed recovery/source-proof/membership/routing rows and
credentials. Credential and route groups touched by the cohort are removed only
when no membership, grant, or model-route membership remains.

A principal is deleted only after the selected keys are gone and it has no
remaining key of any status, credit account, conversation cluster, archive
identity, or cloud subscription event. Revoked and archived shared keys retain
their principal exactly like active keys.

Conversation rewrites use exact old `session_name` and `labels_json` values as
CAS inputs. Replacements must use a `retired-*` session name and may not contain
`api2`, `legacy-cpa-bridge`, `cpa-` or `bridge`. After rewriting, the transaction
scans all selected-key observations and fails if any of those markers remain.

The command snapshots row counts for requests, events, request/generation
stats, session rollups/archive rows, ledger entries, reservations, generation
jobs, conversation projections/observations and routing terminals. Any direct
or cascading count change aborts the transaction. In particular, a selected
key with a retained synchronous-generation idempotency row cannot be deleted
silently.

## Reviewed manifest

The JSON document has this shape. Arrays must be sorted by stable ID. Values
below are placeholders, not production examples; the abbreviated arrays make
this intentionally invalid as an executable manifest.

```json
{
  "schema_version": 1,
  "idempotency_key": "owner-approved-operation-key",
  "tenant_external_id": "reviewed-tenant",
  "expected": {
    "deleted_upstream_account_snapshots": 17,
    "key_records": 7,
    "routing_relations": 16
  },
  "snapshots": [
    {
      "upstream_account_id": "00000000-0000-4000-8000-000000000001",
      "name": "cpa-reviewed-placeholder",
      "driver": "reviewed-driver",
      "auth_kind": "api_key",
      "credential_generation": 1,
      "created_at": 1,
      "deleted_at": 2
    }
  ],
  "keys": [
    {
      "key_id": "00000000-0000-4000-8000-000000000101",
      "principal_id": "00000000-0000-4000-8000-000000000201",
      "account_id": "00000000-0000-4000-8000-000000000301",
      "alias": "api2-reviewed-placeholder",
      "currency": "USD",
      "credential_generation": 1,
      "archived_at": 3,
      "created_at": 1,
      "updated_at": 3,
      "issued_ciphertext_present": true,
      "credentials": [
        {
          "credential_id": "00000000-0000-4000-8000-000000000401",
          "generation": 1,
          "fingerprint": "reviewed-fingerprint",
          "created_at": 1,
          "revoked_at": 2,
          "plaintext_present": true
        }
      ],
      "recovery_secrets": [],
      "source_proofs": [],
      "credential_group_memberships": [],
      "routing_grants": [],
      "routing_revision": { "revision": 1 }
    }
  ],
  "conversation_rewrites": [
    {
      "observation_id": "00000000-0000-4000-8000-000000000501",
      "key_id": "00000000-0000-4000-8000-000000000101",
      "session_name": "reviewed old API2 session name",
      "labels_json": "{\"alias\":\"reviewed-old-value\"}",
      "replacement_session_name": "retired-session-00000000-0000-4000-8000-000000000501",
      "replacement_labels_json": "{\"credential\":\"retired-credential-00000000-0000-4000-8000-000000000101\"}"
    }
  ]
}
```

## Dry-run and approval

PostgreSQL uses a private libpq service file so credentials do not appear in
arguments or output:

```text
node ./commands/purge-retired-api2-trial.mjs \
  --manifest /protected/reviewed-purge.json \
  --receipt-output /protected/dry-run-receipt.json \
  --backend postgres \
  --pg-service-file /protected/pg_service.conf \
  --pg-service reviewed_purge
```

SQLite uses the same contract:

```text
node ./commands/purge-retired-api2-trial.mjs \
  --manifest /protected/reviewed-purge.json \
  --receipt-output /protected/dry-run-receipt.json \
  --backend sqlite \
  --sqlite-database /protected/token-center.sqlite
```

Dry-run is the default. It obtains the write lock, performs the complete
mutation and all postconditions inside one transaction, emits a bounded receipt
containing no IDs or legacy strings, and rolls the transaction back. Review the
receipt's `manifest_sha256` and database backup/rollback evidence before apply.

Apply requires the independently approved digest:

```text
node ./commands/purge-retired-api2-trial.mjs \
  --manifest /protected/reviewed-purge.json \
  --receipt-output /protected/apply-receipt.json \
  --backend postgres \
  --pg-service-file /protected/pg_service.conf \
  --pg-service reviewed_purge \
  --apply \
  --approved-manifest-sha256 <64-character-dry-run-digest>
```

The apply transaction records the manifest digest under the manifest's
`idempotency_key` in `migration_tool_operation_receipts`. Replaying the exact
same key and digest returns `outcome: replay` without mutating data. Reusing the
key with a different digest fails closed.

Do not apply a manifest after any reviewed row changes. Regenerate the complete
inventory, repeat dry-run, obtain a new approval, and use a new idempotency key.
