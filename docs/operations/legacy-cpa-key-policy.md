# Legacy CPA key-policy migration

This migration restores the old CPA credential-to-model authorization boundary. It is separate from CPAMP history import, unchanged credential attachment, upstream-account import, and route creation. None of those operations proves that a legacy credential can use a model.

The importer is deliberately fail closed. It never creates a route, chooses a provider alias, grants a route group, grants a provider group, or expands one source provider into a multi-provider target route. Missing Codex, Kimi, Copilot, Cursor, or other routes remain an explicit count-only worklist until an owner adds the routes and reviews a new mapping snapshot.

## Required snapshots

All JSON inputs are strict JSON, reject duplicate object keys, and must be regular one-link files with mode `0600`. The Job stages Kubernetes Secret projections into a memory volume with that ownership and mode before Node reads them. Logs and the checkpoint never contain a plaintext credential, key hash, URL, UUID, or source-stable identifier.

The authoritative native CPA snapshot has numeric `version: 1` and exactly these top-level fields; every other version is rejected:

```json
{
  "version": 1,
  "policies": [
    {
      "key_hash": "REDACTED_64_HEX",
      "enabled": true,
      "grants": [
        {
          "provider": "reviewed-source-provider",
          "model": "reviewed-source-model",
          "group": "reviewed-source-group",
          "upstream_prefix": "reviewed-source-prefix"
        }
      ]
    }
  ],
  "usage": {}
}
```

`usage` must be an object but is not an authorization input. The importer never derives a grant from observed usage. The `policies` array must match the active `cpamp_import_identities` set exactly and one-to-one; a missing, duplicate, extra, inactive, or cross-mapped hash stops the run.

The reviewed route inventory is produced through a separate read-only operator procedure and sealed before review:

```json
{
  "version": 1,
  "routes": [
    {
      "route_id": "REDACTED_UUID",
      "public_model": "reviewed-public-model",
      "upstream_model": "reviewed-upstream-model",
      "protocol": "openai",
      "enabled": true,
      "updated_at": 1,
      "upstream_account_ids": ["REDACTED_UUID"],
      "candidate_upstream_account_ids": ["REDACTED_UUID"],
      "candidate_sources": [
        {
          "upstream_account_id": "REDACTED_UUID",
          "source_stable_id": "reviewed-nonsecret-source-id"
        }
      ]
    }
  ]
}
```

Every effective candidate account must have exactly one source-stable binding, represented as one object rather than two independently sorted arrays. Objects are canonically ordered by account ID; duplicate account IDs, duplicate source-stable IDs, missing pairs, and swapped bindings fail. Explicit accounts may differ from effective candidates when reviewed provider-group inclusion or exclusion is present, but the live effective candidate IDs must still equal the paired reviewed set exactly.

Each native grant may contain any non-empty subset of the four documented fields. Missing and present-with-an-empty-string are different values. The importer neither fills a missing field nor moves a value between fields. Therefore a schema-valid legacy anomaly also remains unmapped until an owner reviews that exact shape.

The owner-reviewed mapping binds both snapshot digests and every exact source pattern:

```json
{
  "version": 1,
  "tenant_external_id": "reviewed-tenant",
  "source_snapshot_sha256": "REVIEWED_SHA256",
  "route_inventory_sha256": "REVIEWED_SHA256",
  "mappings": [
    {
      "source": {
        "provider": "reviewed-source-provider",
        "model": "reviewed-source-model",
        "group": "reviewed-source-group",
        "upstream_prefix": "reviewed-source-prefix"
      },
      "target": {
        "route_id": "REDACTED_UUID",
        "expected_public_model": "reviewed-public-model",
        "expected_upstream_model": "reviewed-upstream-model",
        "expected_protocol": "openai",
        "expected_updated_at": 1,
        "expected_upstream_account_ids": ["REDACTED_UUID"],
        "expected_candidate_upstream_account_ids": ["REDACTED_UUID"],
        "expected_candidate_sources": [
          {
            "upstream_account_id": "REDACTED_UUID",
            "source_stable_id": "reviewed-nonsecret-source-id"
          }
        ]
      }
    }
  ]
}
```

There is no wildcard syntax. An exact source pattern may appear once, and all enabled source grants must resolve. A disabled source policy plans an empty exact-route set.

## Dry-run and approval

Use the immutable importer digest and render [`ops/kubernetes/legacy-key-policy-import-job.yaml`](../../ops/kubernetes/legacy-key-policy-import-job.yaml). Keep the checked-in dry-run form. The target service token needs `routes:read` and `keys:read`; the later apply token additionally needs `keys:write`. It must be a one-purpose tenant-scoped token.

The live dry-run performs these checks without mutation:

1. holds the PostgreSQL advisory lock and reads active CPAMP identities;
2. verifies the raw source, route-inventory, and mapping digest fence;
3. proves exact source-policy-to-target-identity cardinality;
4. verifies every selected live route is enabled and still has the reviewed public model, upstream model, protocol, `updated_at`, explicit accounts, and effective candidate accounts;
5. reads every credential's direct routing and reports counts only.

Approve only the JSON fields `policy_count`, `enabled_policy_count`, `disabled_policy_count`, `grant_count`, `matched_grant_count`, `unmatched_grant_count`, `changed_count`, and `replayed_count`, plus the four non-secret SHA-256 fences. `unmatched_grant_count` must be zero. Compare the count set to the sealed source receipt and retain an immediately restorable database snapshot.

## Apply, interruption, and replay

Add `--apply` only to the exact approved Job render. The importer reads `GET /internal/v1/keys/{key_id}/routing`, then uses its credential `grant_revision` in the CAS `PUT`. The reviewed model-route fence intentionally does not pin the model route's reverse-grant revision, because a successful credential update legitimately changes it. The replacement contains only reviewed direct `route_ids` and an empty `route_group_ids` array. Thus a credential group can never become an authority, and a pre-existing route-group grant cannot silently survive the migration.

After every verified credential, the importer atomically advances a mode-`0600` count-only checkpoint on the dedicated PVC. The checkpoint binds the source, mapping, inventory, and deterministic plan digests. A changed input conflicts. On restart, all checkpointed credentials are read back and must still equal the planned direct routes before work continues. A stale CAS, network failure, response mismatch, or checkpointed-state drift stops the run without advancing the checkpoint.

An exact replay performs no PUTs and reports `changed_count: 0`. Retain the checkpoint and receipts through the production observation window. Delete the one-purpose service token, staged Secrets, Job, and checkpoint PVC only after the rollback window closes.

## Residual boundary

This tool assumes the selected native CPA file uses the documented `version/policies/usage` contract and four grant coordinates. A differently shaped historical policy file needs an explicit, tested adapter; do not rename or shuffle fields to make it pass. It also does not create missing MTC routes or reauthorize OAuth upstreams. Those are prerequisites, not importer side effects.
