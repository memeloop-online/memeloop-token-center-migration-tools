# Existing managed Codex provenance binding

`resolve-cpa-managed-codex-provenance` is a one-shot local TypeScript tool for
constructing the managed half of the version-1 CPA upstream-binding receipt.
It is a read-only proof that an already imported, native OpenAI Codex account
is the target of a particular stable CPA auth-file identity. It is not a
product API client, OAuth importer, credential synchronizer, cluster Job, or
health check.

The tool accepts an explicit mapping between the historical import tenant and
the current route tenant. They may be different. Neither tenant is hard-coded.
The historical value is used only to reproduce the original product lookup;
the current target value is the tenant emitted for the route composer.

## Protected inputs

Every file argument below is an absolute, normalized, owner-owned `0600`
regular file with one link. Input and output directories must not be symlinks;
the output directory must not be group/world writable. Do not put a connection
string, key pepper, auth path, OAuth document, or query output in an argument,
environment variable, CI log, manifest, or this repository.

The owner prepares these files outside the repository:

- `--source-import-tenant-mapping-file` is strict JSON with no auth paths:

  ```json
  {"version":1,"source_import_tenant_external_id":"original-import-tenant","target_tenant_external_id":"current-route-tenant","source_kind":"auth_file","source_type":"codex"}
  ```

`source_import_tenant_external_id` is exactly the historical
`tenant_external_id` string that was included in the original source-key HMAC.
It is not a current database lookup. `target_tenant_external_id` is the
explicitly approved current route tenant and is the only tenant looked up in
PostgreSQL. This permits the historical tenant row to have been merged away
while the durable import provenance row has moved to the current tenant. The
mapping is controlled; no historical tenant name is inferred.

- `--source-config-file` is the same current protected CPA config used to
  generate the managed candidate material.
- `--managed-codex-model-snapshot-file` is the current protected output of
  `export-cpa-managed-codex-model-snapshot`. Its config SHA must match
  `--source-config-file`. The snapshot, rather than a hand-written auth list,
  is the only source of in-memory auth-file relative paths.
- `--source-identity-key-file` is the existing binary CPA source-identity key
  consumed by the route parser. It derives route-only stable IDs; it is not
  the target key pepper.
- `--key-pepper-file` contains the exact raw bytes of the product
  `key_pepper.as_bytes()` value used for the original managed-OAuth import.
  It has no trailing newline or representation conversion. The tool holds it
  only in memory long enough to derive HMACs and zeroes its buffer afterward.
- `--source-inventory-file` is the raw version-2 source inventory, and
  `--provider-candidate-material-file` is the raw combined version-1 provider
  candidate material. Their raw SHA-256 relationship is checked. Only
  `codex`/`openai`/`openai-codex` candidates are selected; every selected
  stable ID must map to exactly one snapshot auth ID.
- `--pg-service-file` is an owner-only libpq service file and `--pg-service`
  is its non-secret service name. The service must point to the approved
  target PostgreSQL endpoint using a role limited to the needed `SELECT`s.
  A referenced passfile, TLS material, or external secret source remains an
  owner-only external secret; this repository never receives it. The command
  passes only `PGSERVICEFILE`/`PGSERVICE` to `psql`, never a connection string.
  Source-key HMAC query values are supplied only through the local `psql`
  standard-input stream, not process arguments or output.

For example, in an approved local migration shell:

```text
node ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts \
  --source-import-tenant-mapping-file /state/input/source-import-tenant.json \
  --source-config-file /state/input/cpa-config.yaml \
  --managed-codex-model-snapshot-file /state/input/managed-codex-model-snapshot.json \
  --source-identity-key-file /state/secrets/cpa-source-identity-key.bin \
  --key-pepper-file /state/secrets/target-key-pepper.bin \
  --source-inventory-file /state/input/source-inventory.json \
  --provider-candidate-material-file /state/input/provider-candidate-material.json \
  --pg-service-file /state/secrets/target-readonly.pg-service \
  --pg-service managed_provenance_readonly \
  --binding-receipt-output /state/receipts/managed-codex-route-bindings.json
```

`--statement-timeout-ms` is optional, defaults to `15000`, and is capped at
`60000`. The tool has no apply flag and no fallback to a network/API request.

## Exact proof and failure boundary

For each selected snapshot auth path the tool derives two different values in
memory:

1. The route stable ID uses the CPA source-identity key and the managed Codex
   route domain.
2. The target provenance key reproduces the product HMAC exactly:
   `HMAC-SHA256(key_pepper, "memeloop:cpa-managed-oauth:source-key:v1\\0" +
   source-import-tenant + "\\0auth_file\\0" + relative-path)`.

One bounded `REPEATABLE READ READ ONLY` PostgreSQL transaction then requires a
unique `upstream_account_imports` record for that HMAC in the explicitly
mapped current target tenant, whose account is in that same tenant. The
historical tenant string is never queried as a current `tenants` row. It
rejects a missing/extra result, a duplicate source or target account, any
driver other than `openai-codex`, inactive status, non-OAuth or non-native
lifecycle, missing current credential generation, or an invalid target CAS
revision.
It snapshots the current credential generation and `updated_at` together so a
later account change cannot be silently treated as the reviewed target.
It selects no account name, email, model configuration, OAuth ciphertext,
access token, refresh token, or credential payload. It never guesses by name,
email, model, or configuration.

The import row's `payload_digest` is intentionally distinct from the stable
source key. It is observed only inside the non-public canonical provenance
record before hashing. A routine OAuth refresh can change that payload revision
without changing the auth-file identity, so it neither creates/quarantines a
route binding nor triggers re-import/update. The receipt therefore proves
route identity binding only; it does not claim that OAuth credentials were
just synchronized or currently usable. Verify refresh and actual route
availability separately through the approved functional migration checks.

## Receipt and composition

The new `0600`, no-overwrite receipt has exactly this top-level shape:

```text
version, tenant_external_id, source_inventory_sha256,
provider_candidate_material_sha256, managed_provenance_evidence_sha256,
bindings, quarantined
```

`quarantined` is always empty: insufficient source/target evidence rejects
without a receipt. Each binding contains only the route HMAC stable ID,
`codex`, target account UUID, `openai-codex`, `active`, and `updated_at`.
The latter is the observed target CAS revision; any later target change needs
a new provenance receipt. `credential_generation`, lifecycle observation,
source-key match state, and observed payload revision contribute only to
`managed_provenance_evidence_sha256`; their raw values are not emitted.

Standard output is one JSON object containing counts and SHA-256 digests only.
The receipt and stdout do not expose auth paths, source-key HMACs, payload
digests, account names, configuration, connection settings, or secret values.
Pass this file unchanged as the composer's
`--managed-binding-receipt-file`; the composer independently verifies its
source/material digests and exact v1 schema before it can form an upstream
inventory. No Job, image, database write, or deployment action is activated by
this tool or this document.
