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
- 16 credential routing grants and 7 credential relation revisions;
- 170 conversation observations whose presentation metadata is rewritten by
  exact CAS;
- 24 synchronous image idempotency rows whose replay state is removed by exact
  CAS after their durable request and settlement facts are verified;
- a complete, sorted description of every credential,
  rotation replay, recovery envelope, source proof, membership, and touched
  credential/route group belonging to those keys.

Each snapshot and key is bound to its tenant and all reviewed lifecycle fields.
Every child relation is compared in both directions: a missing, extra or changed
row aborts the transaction. The command also rejects unreviewed legacy-pattern
snapshot names or credential aliases in the selected tenant.

The reviewed credentials, rotation replays, and touched groups are part
of the canonical manifest SHA. Under the database lock, the command compares
their stable IDs and non-secret CAS fields in both directions. Missing, extra,
or changed rows abort both dry-run and apply. Secrets and ciphertext never
appear in the receipt.

Before deletion it sets `key_records.issued_key_ciphertext` and
`key_credentials.secret_plaintext` to `NULL`, overwrites every reviewed recovery
`ciphertext`, and clears cached rotation responses. It removes the reviewed
key-scoped rotation replay rows before deleting the reviewed
recovery/source-proof/membership/routing rows and
credentials. Credential and route groups touched by the cohort are removed only
when no membership, grant, or model-route membership remains.

A principal is deleted only after the selected keys are gone and it has no
remaining key of any status, credit account, conversation cluster, archive
identity, unresolved explicit-parent reference, routing terminal, or cloud
subscription event. Revoked and archived shared keys retain their principal
exactly like active keys.

Conversation rewrites use exact old `session_name` and `labels_json` values as
CAS inputs. `session_name` may be `null`; the manifest keeps that value as
`null` and never invents a title. Each field is checked independently for
retired API2/CPA text. A manifest row must contain a marker in at least one
field. A marked title is replaced with an empty value or `null`, while an
unmarked title must be copied byte-for-byte (including `null`). Marked labels
are replaced with only `{ "state": "retired" }`; unmarked labels must be
copied byte-for-byte. This limits the rewrite to fields that actually contain
retired material and leaves the user-facing tombstone title to the localized
product UI. After rewriting, the transaction scans all selected-key
observations and fails if any legacy markers remain.

The command snapshots row counts for requests, events, request/generation
stats, session rollups/archive rows, ledger entries, reservations, generation
jobs, conversation projections/observations and routing terminals. Any direct
or cascading count change aborts the transaction. In particular, a selected
key with an unreviewed synchronous-generation idempotency row cannot be deleted
silently. Archive import rows are scoped through the current schema's
`target_request_id -> request_records.id -> key_id` relationship.

Synchronous image idempotency rows are operational replay and lease state. The
private manifest binds all 24 rows by key, idempotency key, request hash,
request/reservation IDs, lifecycle fields, response byte count and response
SHA-256. The cleanup requires every linked request to exist under the same key
and be complete, every reservation to exist under the same key and be settled,
and every lease to have expired. A cached successful response is removable only
when the durable request row contains the exact same response bytes. The tool
then deletes the reviewed replay rows explicitly before deleting the archived
keys; the foreign-key cascade has no remaining row to remove. Request records,
reservations, ledger data, archive rows and conversation facts remain covered by
the before/after invariants.

Deletion also fails closed while any selected key has an incomplete request, a
reservation whose status is not `settled`, a non-terminal generation job, or a
terminal generation job whose statistics have not been aggregated. Every
conversation projection outbox row is reviewed by stable ID, identity,
lifecycle fields, payload byte counts and SHA-256 digests. Payload content is
not copied into the manifest or receipt. A row with
`projected_at: null` blocks the purge so the projection worker never loses the
key identity it still needs.

## Reviewed manifest

The JSON document has this shape. Arrays must be sorted by stable ID. Values
below are placeholders, not production examples; the abbreviated arrays make
this intentionally invalid as an executable manifest.

```json
{
  "schema_version": 5,
  "idempotency_key": "owner-approved-operation-key",
  "tenant_external_id": "reviewed-tenant",
  "expected": {
    "deleted_upstream_account_snapshots": 17,
    "key_records": 7,
    "routing_grants": 16,
    "routing_revisions": 7,
    "conversation_observations": 170,
    "synchronous_image_idempotency": 24
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
      "rotation_replays": [
        {
          "idempotency_key": "reviewed-rotation-replay",
          "request_hash": "reviewed-request-hash",
          "expires_at": 3,
          "created_at": 1,
          "response_ciphertext_present": true
        }
      ],
      "credential_group_memberships": [],
      "routing_grants": [],
      "routing_revision": { "revision": 1 }
    }
  ],
  "credential_groups": [],
  "route_groups": [],
  "conversation_projection_outbox": [
    {
      "request_id": "00000000-0000-4000-8000-000000000601",
      "tenant_id": "00000000-0000-4000-8000-000000000701",
      "key_id": "00000000-0000-4000-8000-000000000101",
      "principal_id": "00000000-0000-4000-8000-000000000201",
      "request_json_bytes": 2,
      "hints_json_bytes": 2,
      "request_json_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      "hints_json_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      "client_name": null,
      "upstream_response_id": null,
      "observed_at": 2,
      "lease_owner": null,
      "lease_expires_at": null,
      "attempts": 1,
      "projected_at": 3
    }
  ],
  "conversation_rewrites": [
    {
      "observation_id": "00000000-0000-4000-8000-000000000501",
      "key_id": "00000000-0000-4000-8000-000000000101",
      "session_name": "reviewed old API2 session name",
      "labels_json": "{\"alias\":\"reviewed-old-value\"}",
      "replacement_session_name": null,
      "replacement_labels_json": "{\"alias\":\"reviewed-old-value\"}"
    }
  ],
  "synchronous_image_idempotency": [
    {
      "key_id": "00000000-0000-4000-8000-000000000101",
      "idempotency_key": "reviewed-private-idempotency-key",
      "request_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      "request_id": "00000000-0000-4000-8000-000000000801",
      "reservation_id": "00000000-0000-4000-8000-000000000901",
      "status": "completed",
      "response_status": 200,
      "response_object_present": true,
      "response_object_bytes": 2,
      "response_object_sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      "error_code": null,
      "created_at": 1,
      "lease_expires_at": 2,
      "completed_at": 3
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
