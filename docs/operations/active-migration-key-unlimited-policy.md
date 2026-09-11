# Active migration-key balance-unrestricted policy transition

This is a one-time, offline migration control. It does not deploy a workload,
write Kubernetes resources, issue, rotate, suspend, or reactivate a credential,
or connect to the public gateway. Its default is a read-only dry-run.

Exact active and revoked key counts belong only in protected migration evidence,
not this repository. The tool never contains a tenant ID, key ID, expected count,
or migration version. At runtime, the target service must select only keys that
are all of:

1. currently `active`;
2. proven by the target's migration-primary relation; and
3. linked to a current, non-revoked credential.

The target is required to exclude every revoked key. A missing proof, an
inactive key, a missing current credential, a duplicate candidate, or an empty
candidate result fails closed. In particular, revoked keys must
not be guessed to be test keys or reactivated.

## Why a maximum balance grant is not this transition

The existing `grant-legacy-max-balances.ts` helper can make a prepaid balance
very large. It cannot make balance exhaustion impossible, and therefore is not
evidence of the required transition. Likewise, the ordinary
`PUT /internal/v1/keys/{key_id}/policy` endpoint is not sufficient: it does
not advertise a balance-unrestricted mode nor a batch transaction/CAS receipt.
Do not use either endpoint as a substitute.

The target may expose `metered_unlimited`, or another formally named current
product equivalent. The name is data returned by the target capability document;
the client accepts it only if the target proves that balance exhaustion is
disabled while key identity, grants, history, balance, and the current credential
are preserved.

## Required target control contract

Before any operator run, the reviewed product release must provide these private
control endpoints behind a one-purpose service credential. The migration tool
does not invent a fallback, issue SQL directly, or retry individual key writes.

`GET /internal/v1/migration-key-policy-unlimited/capabilities` returns strict
JSON containing an API schema number, the private plan/apply paths, and one
transition with all of the following true:

- `atomic_batch_cas`, `idempotent`, `balance_exhaustion_disabled`;
- `key_identity_preserved`, `grants_preserved`, `history_preserved`, and
  `current_credential_preserved`; and
- `revoked_excluded`.

`GET` of the advertised plan path returns a canonically key-ID-sorted candidate
set. Each entry supplies only an in-memory key ID, a positive policy revision,
the active/migration-primary/current-credential/revoked fences, and opaque
SHA-256 digests for the identity, grants, history, balance and credential
snapshots. The tool re-computes the canonical plan digest. IDs and snapshot
digests are never printed.

`POST` of the advertised apply path accepts the approved and newly observed plan
digests plus the deterministic idempotency key. The service must execute one
database transaction: re-evaluate the query, CAS the complete selected set,
change only its formally advertised balance-unrestricted policy, and persist a
replayable receipt. A stale plan aborts before any partial write. An identical
idempotency key returns the prior result; after a lost acknowledgement it may
report the newly observed plan digest alongside the original transaction counts.

The response must prove the candidate count, changed/already-unlimited counts,
each preservation count, revoked exclusion, disabled balance exhaustion, atomic
CAS, and idempotency. The client rejects an incomplete or non-matching receipt.

This deliberately leaves the current release blocked until the product exposes
that control contract. The tool makes the missing product capability explicit;
it does not pretend that a high prepaid balance is unlimited.

## Dry-run, approval, apply, and replay

Use a private control URL and an owner-only (`0600`), regular, single-link file
for the service token. Never put the token, a client credential, database
password, key ID, target URL, or response body in an argument, environment
variable, transcript, ConfigMap, or this repository. HTTPS is required by
default. `--allow-http-target` is only for an approved private in-cluster hop.

Create a new receipt path for dry-run:

```text
node ops/legacy-policy/transition-active-migration-keys-to-unlimited.ts \
  --target-api-base-url https://PRIVATE_CONTROL_ORIGIN \
  --service-token-file /run/secrets/transition/service-token \
  --receipt-file /private-evidence/key-policy-dry-run.json
```

The file is created exclusively with mode `0600`; it is not overwritten. Normal
stdout is count-only and includes the receipt SHA-256, never candidate IDs or
credentials. Approval must check the receipt's candidate/planned-change counts,
transition name, all preservation counts, `revoked_excluded`, and
`balance_exhaustion_disabled`, then retain the receipt in the approved external
audit store.

Apply requires both an explicit flag and that exact immutable dry-run receipt;
write the apply receipt to a different new file:

```text
node ops/legacy-policy/transition-active-migration-keys-to-unlimited.ts \
  --target-api-base-url https://PRIVATE_CONTROL_ORIGIN \
  --service-token-file /run/secrets/transition/service-token \
  --receipt-file /private-evidence/key-policy-apply.json \
  --apply \
  --approved-dry-run-receipt-file /private-evidence/key-policy-dry-run.json
```

If the process loses the apply acknowledgement, reuse the approved dry-run
receipt but choose another new apply-receipt path. The idempotency key is derived
only from the approved dry-run receipt digest, so the target returns its stored
transaction result rather than transitioning a key twice. A new dry-run after a
successful transition should report zero planned changes; applying that new
receipt is a zero-write replay check.

Keep both count/digest receipts, the approved backup reference, and product
release identity through the observation window. They are one required component
of the final per-key/model/day/cache reconciliation; they do not replace the
final archive delta, locators, price provenance, or blue/green acceptance.

## Fixture entry for GitHub Actions

The isolated static fixture contract is:

```text
npm run test:active-migration-key-unlimited
```

It proves dynamic selection rather than a fixed count/ID, dry-run no-write,
formal-equivalent capability acceptance, atomic CAS receipt validation,
idempotent lost-response replay, zero-write replay, preservation fences, revoked
rejection, and receipt/key-material redaction. GitHub Actions is the test
authority; do not use a local run as migration evidence.
