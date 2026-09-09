# Direct route batch preflight — no apply authorization

This explicit mode prepares and validates complete native `http-json` pools
without waiting for managed-provider capability work. It does **not** deliver
customer authorization, authorize route writes, change a key, or modify policy.
The default full composer and route importer retain their strict full-coverage
behavior, including refusal to quarantine a managed capability gap.

Use only a CI-verified fixed JavaScript release. Supply the original, complete
sealed source inventory and candidate material; never filter the source,
discard anomalies, rewrite source grants, or fabricate an empty managed
receipt. Direct bindings must come from the separate read-only deterministic
resolver and must cover every direct source account without quarantine.

## Offline composition

```text
node /verified-release/commands/compose-cpa-upstream-inventory.mjs \
  --direct-batch-preflight \
  --source-inventory-file /protected/source-inventory.json \
  --provider-candidate-material-file /protected/provider-candidate-material.json \
  --direct-binding-receipt-file /protected/direct-route-bindings.json \
  --upstream-inventory-output /protected/direct-preflight-upstreams.json \
  --batch-receipt-output /protected/direct-preflight-batch.json
```

This selects **all** complete `http-json` pools; arbitrary provider/model/account
subsets are not supported. It preserves equal-weight candidate membership and
the exact source tuples. Missing direct bindings, quarantined direct accounts,
duplicate identities, mixed drivers, stale input hashes, or an empty direct
selection fail closed. Do not supply a managed binding receipt in this mode.

Both outputs are private mode-0600, single-link, no-overwrite files. The batch
receipt includes the original source digest, complete candidate material and
direct binding receipt with their original byte digests, the generated
upstream digest, every deferred mapping, every anomaly and every
reauthorization item. These protected inputs contain opaque account IDs, not
customer credential plaintext or upstream secrets; keep them outside Git and
logs. Standard output contains only counts, digests and the preflight mode.
The full source must remain available alongside the receipt.

## Owner-reviewed live route preflight

Prepare a normal reviewed v2 route manifest covering exactly the generated
direct pools and binding the **original full** source digest plus the generated
upstream digest. `anomaly_quarantine` must be `null`: retained capability gaps
are not waived or quarantined by preflight.

```text
node /verified-release/commands/import-cpa-model-routes.mjs \
  --direct-batch-preflight \
  --batch-receipt-file /protected/direct-preflight-batch.json \
  --source-inventory-file /protected/source-inventory.json \
  --upstream-inventory-file /protected/direct-preflight-upstreams.json \
  --reviewed-manifest-file /protected/reviewed-direct-manifest.json \
  --target-api-base-url https://owner-reviewed-control.example/ \
  --service-token-file /protected/target-read-token \
  --checkpoint-file /protected/direct-preflight-checkpoint.json
```

The importer recomposes the inventory and batch receipt byte-for-byte from
their sealed evidence before target reads. It then checks live tenant/account
revision, exact complete candidate pools, route collisions, CAS expectations
and historical/reference guards. It reads only routes and upstreams; the
existing bounded single-page safety limit remains in force.

The summary explicitly distinguishes matched mappings from deferred mappings,
retained anomalies and retained reauthorizations. A successful preflight does
not mean complete migration, target account import, working customer access,
or successful Responses/SSE acceptance.

`--apply` is rejected before token reads or target access. The execution API
also refuses an apply request for any direct-preflight plan. These outputs
must not be fed to a policy replacement operation. A later route-only apply
requires a separately reviewed contract with full CAS, idempotent replay,
immutable receipts and explicit preservation of every existing key grant;
that operation is deliberately not implemented here.
