# Unchanged CPA credential attachment

This procedure makes each currently configured CPA client credential authenticate
as the stable Token Center identity already created from its CPAMP SHA-256. It
does **not** create another identity and does not copy or rewrite request history,
policy, grants, ledger entries or balances. Those records already belong to the
stable `key_id`; the operation adds only an authentication generation alias in
`legacy_key_credentials`.

The importer is fail-closed and dry-run by default. It requires an exact
one-to-one set match:

- every supplied CPA credential SHA-256 must exist in
  `cpamp_import_identities` for the selected tenant;
- every selected CPAMP identity must have exactly one supplied credential;
- source hashes and target `key_id` values must both be unique;
- an existing active legacy mapping may be the same mapping (replay), but may
  not map either side to something else; and
- a revoked mapping touching the selected source or target is a hard stop, so
  the importer can never silently resurrect a credential revoked by rotation.

All validation happens before the first HTTP write. A session-level PostgreSQL
advisory lock is held from identity extraction through the final API response.
The target endpoint is itself idempotent for an identical `(source_hash,
key_id)` pair. Therefore an interrupted apply may be replayed safely; it is not
an excuse to ignore a failed Job, because HTTP calls cannot share one database
transaction.

## Secret boundary

The plaintext CPA credentials may enter the process only through one of these
paths:

1. a mode-restricted, read-only mounted file passed with `--input-file`;
2. stdin by passing `--input-file -`; or
3. the fixed read-only request `GET /v0/management/api-keys`, with the CPA
   management token read from a mounted file.

The accepted CPA response is exactly `{"api-keys":[...]}`. Redirects are not
followed. TLS verification is mandatory unless an operator explicitly approves
`--allow-http-cpa` for a cluster-internal hop. The Token Center URL follows the
same rule and never follows redirects.

Mounted Secret files must be owner-only, or group-readable only by the Job's
private GID 10001. The hardened Job uses `fsGroup: 10001` and mode `0440` so its
non-root UID can read the projected Secret; other-read, group-write and
group-execute permissions are rejected by the importer.

Never put a CPA credential, CPA management token, Token Center service token or
database password in an argument, environment variable, ConfigMap, shell
substitution, here-document, Job annotation, terminal transcript or temporary
file. The candidate client credentials and both HTTP tokens are read into
process memory only. PostgreSQL connection settings use libpq Secret
integration rather than placing the password or URI in argv or the environment.
Kubernetes projects the source Secret as mode `0440` for the pod's private GID.
A non-root, no-capabilities init container copies it into a memory-backed
`emptyDir` as UID/GID 10001 mode `0600`, which is the permission contract
libpq actually accepts. The importer mounts only that prepared file, read-only,
as `PGPASSFILE`. A direct mode-`0440` pgpass projection is invalid.

Normal output is one JSON object containing counts only. It deliberately omits
credentials, hashes, hash prefixes, key UUIDs, fingerprints, URLs and response
bodies. Error handling also refuses to echo input or peer response bodies.

## Build the importer image

Build the existing [importer Dockerfile](../../Dockerfile.importer), scan it,
publish it to the private registry, and record its immutable digest. Its default
entrypoint remains the CPAMP importer; this one-shot Job explicitly selects the
legacy attachment command. The image also contains the Node.js runtime,
`psql` and CA certificates and runs as UID 10001.

```sh
docker build \
  -f Dockerfile.importer \
  -t REGISTRY/memeloop-token-center-importer:REVIEW_SHA \
  .
docker push REGISTRY/memeloop-token-center-importer:REVIEW_SHA
docker inspect --format '{{index .RepoDigests 0}}' \
  REGISTRY/memeloop-token-center-importer:REVIEW_SHA
```

Pin that digest in
[the one-shot Job template](../../ops/kubernetes/legacy-credential-import-job.yaml).
Do not use a mutable tag.

## Preconditions

1. Take and verify a PostgreSQL backup/snapshot.
2. Complete the full CPAMP reconciliation for the intended tenant. The
   `cpamp_import_identities` table is unlogged and is replaced by every CPAMP
   importer run, so do not run another CPAMP import between this dry-run and
   apply.
3. Prove the selected identity count and stable target-key count agree without
   selecting hashes or secrets.
4. Keep CPA unchanged and serving traffic; this operation reads its configured
   client keys but does not mutate CPA.
5. Use a tenant-bound Token Center service credential with only `keys:write`.
   Mount it only in the apply Job. The dry-run Job must not receive it.
6. Route the apply Job only to the private control Service. The public gateway
   must not expose `/internal/v1/*`.
7. Ensure NetworkPolicy permits only CPA management, PostgreSQL, private Token
   Center control and DNS destinations required by this Job.

## Dry-run

The checked-in Job template is intentionally a dry-run. Replace its explicit
placeholders, pin the reviewed image digest and create a uniquely named copy.
The base template mounts the CPA management token but does not mount the target
`keys:write` token.

For an already exported Secret file instead of the CPA endpoint, replace the CPA
URL/token arguments with:

```text
--input-file /secrets/cpa/api-keys.json --input-format cpa-json
```

A successful dry-run prints counts resembling:

```json
{"already_attached_count":0,"attached_verified_count":0,"candidate_count":2,"existing_mapping_count":0,"identity_count":2,"mode":"dry-run","pending_count":2}
```

Approve apply only when `candidate_count == identity_count`, the expected active
CPA key count agrees, and there is no error. A count mismatch is an investigation
gate, not a reason to weaken full coverage.

## Apply and replay

Create a fresh Job manifest from the reviewed dry-run manifest. Add all of the
following together:

- `--apply`;
- `--target-api-base-url` with the private control base URL;
- `--service-token-file /secrets/target/service-token`;
- a read-only `target-service-token` Secret volume and volume mount;
- annotation `memeloop-token-center/import-mode: apply`.

Do not edit or rerun the completed dry-run Job in place. Capture only the
count-only output and Job status. A successful apply has
`attached_verified_count == candidate_count`.

Then create one fresh apply Job with the exact same source snapshot and inputs.
It must succeed again. On this replay, target state must not change,
`already_attached_count` should equal the candidate count, and every idempotent
API response is verified against the expected stable key and source hash.

Finally authenticate through the normal public gateway with each unchanged CPA
credential using a non-billable/read-only probe where possible. For the Linux
Codex credential specifically verify:

- `/self/v1/key` returns the expected stable `key_id`, policy and balance;
- `/self/v1/stats` and `/self/v1/requests` expose the already imported history;
- a denied model remains denied and no administrative endpoint is authorized;
- a controlled billable request changes the same account exactly once.

The automated fixture coverage in
`tests/legacy_credential_continuity.rs` proves attach/replay authentication and
unchanged history, policy and balance against the real API. The operator suite
in `tests/ops/test-legacy-credentials-bulk.ts` proves strict matching,
read-only CPA export, dry-run, apply/replay and absence of credential/hash
material from stdout and stderr. When `MTC_TEST_POSTGRES_URL` is present,
`tests/legacy_credentials_bulk_postgres.rs` also creates and removes an isolated
schema to exercise the real `psql` advisory-lock/query protocol and revoked-row
gate.

## Failure and cleanup

If preflight fails, no target HTTP write has occurred. Resolve the exact source
inventory or rerun the full CPAMP import; do not add an allow-unmatched flag.

If apply is interrupted, keep CPA serving, inspect only count/status evidence,
and replay the same immutable input. The API accepts an identical prior mapping
and rejects cross-key reuse. Do not rotate a key, alter policy/balance or delete
legacy mappings as part of recovery.

After successful replay and dogfooding, delete the one-shot Jobs and remove the
temporary Secret copies. Preserve only the immutable source snapshot reference,
image digest, database backup reference and count-only evidence in the change
record.
