# Imported credential recovery-envelope backfill

`credential-recovery-backfill` stores an encrypted, key-bound recovery envelope
for an already-imported customer credential. It is a one-shot, source-independent
tool: it reads only an owner-approved mapping from the stable target identity to
that identity's original credential. It does not connect to a source database,
infer identities, read a model/route/policy/grant, create a key, rotate a key,
or modify balances or history.

The command calls only this private control-plane endpoint, once per supplied
target identity:

```text
PUT /internal/v1/keys/{target-key-uuid}/credential-recovery
Authorization: Bearer <keys:write token>
Content-Type: application/json

{"key":"the exact original key"}
```

The product endpoint requires `keys:write` and enforces any tenant scope on the
admin token. It verifies that the supplied original key matches the active
authentication hash for that exact key and its current credential generation.
Only then does it store the encrypted envelope. It returns `204`, never returns
the supplied key, and does not rotate the key or alter its generation. A stale,
revoked, cross-tenant, mismatched, or changed credential is a hard stop.

## Protected input contract

The only input is a protected, UTF-8 JSON mapping file. It must be a regular,
single-link file owned by the invoking identity with no group or other access
(normally mode `0600`). The tool opens it with `O_NOFOLLOW`, rejects a symlink,
hard link, unsafe mode, owner mismatch, malformed JSON, duplicate JSON keys,
unknown fields, non-canonical UUID identities, invalid original keys, an empty
mapping, or more than 10,000 mappings.

```json
{
  "format_version": 1,
  "identity_to_original_key": {
    "TARGET_KEY_UUID": "ORIGINAL_KEY_FROM_APPROVED_SECRET_STORE"
  }
}
```

`TARGET_KEY_UUID` is the already-imported stable Token Center key identity, not
a source account, model, route, grant, alias, or a value discovered by this
tool. `ORIGINAL_KEY_FROM_APPROVED_SECRET_STORE` is illustrative only; actual
mapping files, original keys, UUIDs, token values, endpoint URLs, request
bodies, ciphertext and target responses must never be committed, supplied on a
command line, printed, put in an environment variable, or copied into a
receipt. The original key is preserved exactly; the tool never trims or derives
it.

For apply, the admin token is a second owner-private, single-link regular file.
It is passed only with `--admin-token-file`, never as a flag value or an
environment variable. Use a short-lived, one-purpose, tenant-scoped service
token with only `keys:write`; do not use a runtime token, broad operator token,
or a public gateway URL. An optional CA bundle is accepted from a regular
non-symlink file for a private control endpoint. HTTPS and normal certificate
verification are required unless the operator explicitly selects
`--allow-http-target` for an approved isolated test hop.

## Dry-run, apply, and replay

Dry-run is the default and makes no network request. It validates only the
protected input shape and prints one count-only object:

```text
credential-recovery-backfill --mapping-file /protected/recovery/mapping.json
```

```json
{"mode":"dry-run","mapping_count":1,"stored_count":0}
```

Do not treat dry-run as proof that a supplied original key is currently active:
the product endpoint makes that exact check during apply. After owner approval
of the reviewed mapping count and the deployment preconditions below, run the
fixed command from the CI-built, verified JavaScript Release bundle:

```text
sha256sum -c SHA256SUMS
tar -xzf memeloop-token-center-migration-tools-REVIEWED_SHA.tar.gz
node ./commands/credential-recovery-backfill.mjs \
  --mapping-file /protected/recovery/mapping.json \
  --apply \
  --target-api-base-url https://PRIVATE_CONTROL_ENDPOINT \
  --admin-token-file /protected/recovery/keys-write.token
```

The command performs sequential fixed-endpoint `PUT` requests. Each request has
a 30-second timeout and at most two attempts; retry is limited to transport or
5xx failure. A non-retryable response or an exhausted retry stops the batch
immediately. There is no continuation mode, no unbounded concurrency, no
partial-success receipt, and no target-response output. A successful apply is
count-only, for example:

```json
{"mode":"apply","mapping_count":1,"stored_count":1}
```

If an apply process is interrupted or its acknowledgement is lost, do not build
a new mapping or rotate a key. Re-run the exact same reviewed Release command
with the same protected mapping. The endpoint revalidates the current active
credential and replaces only the same key/generation envelope, so state is
idempotent for an unchanged active identity. An error means stop and investigate
outside terminal output; never enumerate credentials, hashes, UUIDs, response
bodies, or ciphertext in a log or receipt.

## Required release and execution gates

The migration owner must complete all of these before apply:

1. Deploy the product revision that includes the durable recovery migration and
   `PUT /internal/v1/keys/{key_id}/credential-recovery` on every private control
   API replica. Verify migration readiness and the endpoint's `keys:write`
   authorization in the target environment without submitting a real original
   credential.
2. Build and verify the immutable JavaScript Release for the exact migration
   tools revision in CI. The approved distribution is the checked Release
   archive and its manifest/checksums, not a container image, mutable tag,
   locally rebuilt checkout, npm package, or registry image.
3. Take the approved target backup/rollback point. Freeze credential rotation
   for the explicitly mapped identities from dry-run approval through successful
   replay, because a generation change correctly invalidates an older recovery
   envelope.
4. Review the mapping outside this repository, verify its count against the
   approved imported-customer identity inventory, and mount the mapping and
   one-purpose admin token as separate owner-private files. Network egress must
   allow only DNS as required and the private control endpoint.
5. Run dry-run, approve its count-only output, run apply, then replay the same
   input once. Preserve only Release revision/tag/checksum, the approved mapping
   reference, backup reference, count-only status, and non-sensitive evidence
   digest in the external change record.

After the successful replay, use the authorized copy operation only through the
normal controlled management workflow to sample the approved identities. Do not
turn this tool into a credential-export utility or add source discovery, key
rotation, model/grant inspection, or plaintext receipt support.
