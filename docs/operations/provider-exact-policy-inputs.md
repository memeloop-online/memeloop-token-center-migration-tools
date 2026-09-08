# Provider-exact policy input generation

This is a public, reusable one-shot migration contract, not a runtime policy
service. The examples retain the current CPA/Token Center command and field
names deliberately: active migration consumers depend on them. Generalizing
those names requires a separately versioned compatibility adapter and review;
do not rename the existing CLI or files as part of a documentation-only
reuse effort.

The repository contains only code, documentation, and synthetic fixtures. A
real policy snapshot, source/target inventory, route or policy mapping,
credential, Secret value, checkpoint, receipt, log, or other dynamic evidence
must remain in the approved external input/evidence system. Counts and model
names in this document are schema examples, never production evidence or
activation conditions.

## Immutable execution boundary

Build and test a complete Git revision in CI, then execute the resulting image
by its verified immutable digest with its manifest/SBOM/provenance receipt.
The image's dependency closure is assembled from the lockfile during the
build and its final layer contains only the reviewed TypeScript entrypoints
and required runtime libraries. Do not use a generic `node` image to fetch a
repository, run `npm install`/`npm ci`, or resolve mutable packages at
startup: runtime source/dependency drift would defeat digest reproducibility,
increase network and credential exposure, and bypass the attestation boundary.
The full verification suite is CI-only; local work is limited to
`git diff --check`. Real inputs are injected only by an approved execution
environment.

`export-cpa-target-route-receipt` first closes the target-state observation
step after a successfully replayed native-route plan. It only calls the
existing read-only target route and upstream list APIs; it has no mutation
flags or write requests. It reads all selected files as mode-`0600` protected
inputs, requires the supplied target URL to exactly equal the reviewed
manifest URL, and writes a new mode-`0600` receipt by atomic no-overwrite
publication. HTTPS is required unless the exact reviewed HTTP URL is paired
with `--allow-http-target`.

```text
export-cpa-target-route-receipt --source-inventory-file /state/source/source-inventory.json --upstream-inventory-file /review/upstream-inventory.json --reviewed-route-manifest-file /review/reviewed-route-manifest.json --target-api-base-url https://control.example.test/ --service-token-file /run/secrets/target-read-token --receipt-output /state/source/target-route-receipt.json
```

It binds the raw SHA-256 digests of the source inventory, reviewed upstream
inventory, and reviewed route manifest. It rejects a tenant, response-schema,
route topology, candidate-pool, target-account revision, or retired bridge
mismatch before writing. The strict v1 output contains only the receipt
digests, public route coordinates, target account UUIDs, and reviewed
`source_stable_id` bindings; its stdout is only `route_count` and
`target_route_receipt_sha256`, never the service token or credential data.

`generate-provider-exact-policy-inputs` then closes the handoff between that
receipt and the separate full direct-grant policy importer. It is an offline,
dry-run-only derivation tool: it does not contact or mutate Token Center, CPA,
Kubernetes, or a Secret store.

It accepts six owner-controlled, mode-`0600` regular files with one link:

1. The complete native key-policy snapshot from the read-only source clone.
2. The sealed source inventory from `export-cpa-source-route-inventory`.
3. The owner-reviewed v2 upstream inventory.
4. The owner-reviewed route manifest used by the native route apply/replay.
5. A read-only target route receipt captured after that replay.
6. Two new, non-existent protected output paths.

The target receipt is version 1 and has these exact top-level fields:
`version`, `tenant_external_id`, `source_inventory_sha256`,
`upstream_inventory_sha256`, `reviewed_route_manifest_sha256`, and `routes`.
Each route has exactly `route_id`, `public_model`, `upstream_model`,
`protocol`, `priority`, `enabled`, `updated_at`, `upstream_account_ids`,
`candidate_upstream_account_ids`, and `candidate_sources`. Candidate sources
are `{upstream_account_id,source_stable_id}` pairs. It records only public
route coordinates and HMAC-stable source identities; it contains neither an
API token nor a provider credential.

```text
generate-provider-exact-policy-inputs --policy-snapshot-file /stage/native-key-policy.json --source-inventory-file /state/source/source-inventory.json --upstream-inventory-file /review/upstream-inventory.json --reviewed-route-manifest-file /review/reviewed-route-manifest.json --target-route-receipt-file /review/target-route-receipt.json --route-inventory-output /state/source/route-inventory.candidate.json --reviewed-policy-mapping-output /state/source/reviewed-policy-mapping.candidate.json
```

It refuses a partial policy, missing or ambiguous provider/model/group/prefix
coordinate, stale digest, incomplete candidate pool, non-v2 upstream
inventory, non-native/retired bridge candidate, tenant mismatch, or anything
other than one exact target route for each source coordinate. The output
mapping contains no source key hash; stdout is only count and SHA-256 receipt.
The tool writes each output once with mode `0600`, fsync, no-overwrite hard
link publication, and directory fsync. If the second publication fails, it
removes the first output.

An owner must inspect the count/digest receipt and place exact copies of the
two outputs into the separately owner-managed policy-review input. This step
does not authorize policy apply. The later policy importer independently
revalidates the source-policy, mapping, route-inventory, live target and CAS
fences, then replaces a key's complete direct route set atomically.
