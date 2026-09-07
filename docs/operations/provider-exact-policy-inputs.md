# Provider-exact policy input generation

`generate-provider-exact-policy-inputs` closes the handoff between a
successfully replayed native-route plan and the separate full direct-grant
policy importer. It is an offline, dry-run-only derivation tool: it does not
contact or mutate Token Center, CPA, Kubernetes, or a Secret store.

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
