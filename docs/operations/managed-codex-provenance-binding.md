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

## One-shot PostgreSQL reader authorization

The resolver is not authorized to use the runtime application database
credential. It requires the short-lived, fixed role
`provenance_codex_reader_v1`, whose grants are constrained to the
query below. The role does not receive `SELECT` on a whole table, any write or
sequence privilege, a role membership, a future-default privilege, or a
credential ciphertext column.

| Relation | Permitted columns |
| --- | --- |
| `public.tenants` | `id`, `external_id` |
| `public.upstream_account_imports` | `tenant_id`, `import_kind`, `source_key`, `payload_digest`, `contract_version`, `upstream_account_id` |
| `public.upstream_accounts` | `id`, `tenant_id`, `driver`, `auth_kind`, `status`, `credential_generation`, `oauth_session_id`, `oauth_driver`, `oauth_refresh_url`, `updated_at` |
| `public.upstream_credentials` | `upstream_account_id`, `generation`, `revoked_at` |

The fixed psql templates are:

- [`managed-codex-provenance-reader-preflight.sql`](../../ops/legacy-routes/managed-codex-provenance-reader-preflight.sql)
  checks the exact database, relation inventory, absent role name, and absence
  of any `PUBLIC` relation privilege which would bypass the column boundary.
- [`managed-codex-provenance-reader-prepare.sql`](../../ops/legacy-routes/managed-codex-provenance-reader-prepare.sql)
  has the only grant list. It accepts only `reader_mode=direct|cnpg` and an
  RFC3339 `reader_valid_until` that is later than the transaction clock and at
  most four hours ahead. It is transactional and rejects a same-name role,
  non-default membership, owner objects, administrative attributes, prior
  relation privileges, a different role comment, or a different expiry.
- [`managed-codex-provenance-reader-cleanup.sql`](../../ops/legacy-routes/managed-codex-provenance-reader-cleanup.sql)
  revokes only those grants and drops only that exact role. It never uses
  `CASCADE`, never reassigns/drops objects, and stops rather than touching a
  mismatched, member, or object-owning role.

These are database administration artifacts, not resolver inputs. Do not put
a password, connection string, key pepper, source key, auth path, or receipt
digest in a template, its command line, or its output. Their required operation
inputs are non-secret: `reader_mode` and the short `reader_valid_until`.

### CNPG-managed role path

The current target's CNPG role lifecycle is the preferred path. Before adding
anything to CNPG, run the read-only preflight and retain its success evidence.
That prevents a pre-existing same-name role from being silently adopted. The
owner then adds an inline `spec.managed.roles` entry for the exact role name
with this shape (the timestamp is an approved operation input, not a checked-in
placeholder):

```text
name: provenance_codex_reader_v1
ensure: present
comment: one-shot managed Codex provenance reader v1
login: true
inherit: false
connectionLimit: 1
superuser: false
createdb: false
createrole: false
replication: false
bypassrls: false
inRoles: []
validUntil: APPROVED_RFC3339_WITHIN_FOUR_HOURS
passwordSecret: { name: OWNER_CREATED_BASIC_AUTH_SECRET }
```

The Secret is an owner-created, same-namespace `kubernetes.io/basic-auth`
Secret with a `username` equal to the fixed role name and a separately held
password; it is not a GitOps object and is never copied into this repository.
No login Secret need be created during the initial review: CNPG can first hold
the role with `login: false` and `disablePassword: true`. Only inside the
approved execution window does the owner change it to the above login shape,
provide a short-expiry password Secret, and invoke the prepare template with
`reader_mode=cnpg`. A libpq service/passfile assembled from that owner-only
credential remains local `0600` input to the resolver.

CNPG's inline role declaration manages role attributes and passwords, not the
four column grants. After its role status proves the exact role exists, the
approved DBA principal runs the prepare template through the existing approved
connection. That principal must have both the listed table-grant authority and
the role-administration authority required by the selected lifecycle; the
resolver role itself never has either. If those authorities are split, stop
rather than substituting the application credential, broadening the reader, or
adding a migration Job/image. `pg_read_all_data`, the runtime `database-url`, and
`memeloop-token-center-pg-app` are not substitutes.

For cleanup, first use CNPG to make the role `NOLOGIN` and clear its password,
wait for that status, then remove the role entry so CNPG no longer reconciles
it. Immediately run the cleanup template via an approved principal which can
both revoke the listed grants and `DROP ROLE`. If cleanup fails, the remaining
role is still `NOLOGIN`; investigate rather than
recreating or force-dropping it. Only after the template commits may the owner
delete the password Secret and local passfile. An alternative CNPG
`ensure: absent` is allowed only when the operator itself is intended to drop
the role; do not run the cleanup template against a role that has already been
dropped.

`reader_mode=direct` exists only for a separately approved DBA-owned role
lifecycle. It creates a fresh `NOLOGIN` role with the same fixed expiry and
grants, but never sets a password. A later owner-authorized login credential is
still required before resolver execution. That lifecycle must likewise restore
`NOLOGIN` before it uses the cleanup template. It must not be used where the
target requires CNPG role management.

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
