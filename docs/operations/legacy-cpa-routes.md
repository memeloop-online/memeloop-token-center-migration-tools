# Legacy CPA provider-exact route convergence

Status: implemented as an owner-reviewed TypeScript planner/importer; checked-in Kubernetes mode is live `dry-run`. This procedure does not grant any credential and does not make the legacy-credential continuity gate pass by itself.

## Why routes stay provider-specific

The old CPA inventory contains 23 provider/model mappings (DeepSeek 8, GLM 6, Qwen 5, Claude 2, other 2) and 61 exact policy grant shapes. MTC currently has fewer routes than those source mappings. A shared public model name is not permission to combine providers: each reviewed route binds exactly one source pattern to either one exact target account or one immutable, provider-exact candidate set. Every candidate repeats its pinned `source_stable_id`. Provider groups, route groups, credential grants, aliases, family inference, and guessed weights are forbidden.

Two old provider/model mappings are an equal round-robin pool of four API keys in every immutable owner snapshot, with no per-key metadata or exclusion model. Selecting one account would change behavior. For those mappings the v2 contract requires the complete four-account set: candidates are deduplicated and ASCII-sorted, every account is active and bound to the same exact source provider and driver, the pool protocol/upstream model matches the route, and the selection is exactly `equal_round_robin`. A subset, superset, cross-provider member, mixed driver, stale member, duplicate, or any selection/weight guess fails closed. MTC's native `upstream_account_ids` array gives every direct association the same fixed scheduling weight; the importer does not synthesize routes or scheduling APIs.

MTC uniquely identifies a route choice by `(tenant, public_model, protocol, priority)`. When two source providers expose the same public model, the owner manifest must assign distinct priorities and explicitly review the selection semantics for credentials that receive both exact routes. The importer never invents the ordering and never combines the two managed Codex accounts.

Image/video generation routes are outside this migration. In particular, Qwen-shaped or otherwise similar old text mappings cannot be redirected to the existing SiliconFlow image/video routes. The live inventory parser accepts unrelated `generation` routes so a full target listing remains readable, while reviewed legacy targets allow only the exact source `openai` or `anthropic` protocol.

## Inputs and pins

All four input files, including the service token, must be regular files with one hard link and mode `0600`:

1. `source-inventory.json`: version 1 exact source mappings plus explicit `reauthorization_required` and `anomalies` worklists.
2. `upstream-inventory.json`: version 1 preserves the original single-candidate contract. Version 2 additionally gives every account its exact `source_provider` and defines one complete `provider_candidate_sets` entry per source mapping. Each set pins source pattern, upstream model, protocol, `equal_round_robin`, and the complete account/stable-source bindings.
3. `reviewed-manifest.json`: version 1 preserves the original single-candidate contract. Version 2 pins the exact candidate array for every route plus the anomaly-quarantine decision described below. Both versions pin the exact target control base URL and the preceding SHA-256 inventories.
4. The private control-plane service bearer token.

Every manifest item repeats the complete source pattern (`provider`, `model`, nullable `group`, nullable `upstream_prefix`, `protocol`) and the exact target candidate bindings, public model, upstream model, protocol, priority, and expected existing state. Target protocol must equal source protocol. For v2, the manifest candidate set must equal the corresponding upstream-inventory set in full; order does not affect the normalized intent digest. Unknown fields, duplicate mappings/candidates, duplicate route choices, stale or disabled upstream bindings, incomplete provider pools, model/protocol mismatch, priority outside `[-1000000,1000000]`, missing source mappings, and provider expansion all fail closed.

The Job template also requires an explicit `REPLACE_TARGET_NAMESPACE`. It must
be the namespace that owns the same database, key pepper and control Service
named by the reviewed manifest. Never infer it from a historical production or
trial name: during the current migration the accepted target is
`memeloop-token-center-api2-trial`, not the older
`memeloop-token-center`/`memeloop-token-center-dev` data planes.

The known malformed legacy shape `{provider: codex, model: classify:csil, group: gpt-5.6-sol}` must remain in `anomalies`; it is never converted into a route. A v2 manifest may proceed only with an explicit `quarantine_unmapped` acknowledgement that pins the normalized anomaly-list SHA-256, exact count, and a separate owner-review evidence SHA-256. An absent acknowledgement, changed reason, new/unknown anomaly, count/digest drift, or any other disposition blocks dry-run and apply. Reports retain both `anomaly_count` and `quarantined_anomaly_count`; quarantine is auditable non-mutation, not silent ignore or permission expansion. Version 1 deliberately has no acknowledgement mechanism and remains blocked by any anomaly.

Copilot and Cursor belong in `reauthorization_required`. That worklist is report-only and does not start OAuth. It does not block creation of otherwise fully reviewed routes, but any nonzero count means end-user continuity is still incomplete and production replacement remains blocked.

## Dry-run, apply, and recovery

Build/run `/usr/local/bin/import-cpa-model-routes` from the immutable importer digest. The checked-in [Job template](../../ops/kubernetes/legacy-route-import-job.yaml) stages every file to memory as owner-only and runs a live dry-run:

```text
import-cpa-model-routes --source-inventory-file /runtime/source-inventory.json --upstream-inventory-file /runtime/upstream-inventory.json --reviewed-manifest-file /runtime/reviewed-manifest.json --target-api-base-url EXACT_REVIEWED_URL --service-token-file /runtime/service-token --checkpoint-file /checkpoint/checkpoint.json
```

The output is count-only plus the three input digests and normalized intent digest; it contains no URL, header, credential, source hash, UUID, account name, or email. Inspect at minimum `source_mapping_count`, `matched_mapping_count`, `unmatched_mapping_count`, `create_count`, `replay_count`, `update_count`, `conflict_count`, `reauthorization_required_count`, `anomaly_count`, and `quarantined_anomaly_count`.

`--apply` is explicit and refuses to run without a persistent owner-only checkpoint. An identical existing route is a zero-write replay. A missing route is created with its complete reviewed direct candidate set, no groups and no credentials, then both `upstream_account_ids` and active `candidate_upstream_account_ids` must match that full set. A lost create response is safe to retry because MTC returns the exact equivalent route; the stable normalized intent digest keeps the checkpoint valid. Resume revalidates every completed ordinal as an exact live replay before skipping it. A dry-run never overwrites an apply checkpoint.

An update needs exact route ID, `updated_at`, `grant_revision`, `history_and_references_reviewed: true`, and a separate owner-reviewed evidence SHA-256. Even then, the importer refuses to update a route with any existing credential grant, route-group relation, or provider-group relation. CAS conflicts and partial failures write only counts/digests to the checkpoint and stop.

HTTPS is mandatory by default. Cluster-internal HTTP requires all three conditions: the exact URL is stored in the digest-pinned owner manifest, the command uses that identical URL, and the operator explicitly adds `--allow-http-target`. This flag does not permit a URL different from the reviewed manifest.

The current implementation deliberately fails if either live routes or upstream accounts reaches the 100-row single-page boundary; it never treats a truncated page as complete. Extend it with tested keyset pagination before using it in a tenant at or above that boundary.

## Release gate

Do not run apply until the 23-entry source inventory, complete provider candidate sets, target upstream inventory, priority choices, digest-bound anomaly quarantine, rollback point, and dry-run counts have an owner approval reference. Route convergence must be followed by the separate exact key-policy import, legacy credential `/v1/models` checks, real text/multimodal requests, and history/charge verification. Copilot/Cursor reauthorization and any missing Claude/Codex/upstream account remain explicit blockers; this tool never claims continuity merely because some routes were created.
