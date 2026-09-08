# CPA source route inventory export

This document describes a public, reusable one-shot exporter while preserving
the current CPA/Token Center names required by the active migration. It does
not authorize access to a CPA volume or any target environment. Real config,
auth files, policy snapshots, source identity keys, inventories, credentials,
logs, checkpoints, receipts and other dynamic evidence stay outside Git and
are supplied through an owner-approved protected-input boundary.

The exporter is executed locally from the CI-built, verified release JS
package. Dependencies are resolved from the lockfile in CI; runtime must not
clone source, download a migration image, or run `npm install`/`npm ci`.
Startup fetches make code and dependency resolution mutable, require
unnecessary network access, and cannot reproduce the release provenance.
Keep the existing command and file names until a separately versioned
compatibility adapter is reviewed.

Run `export-cpa-source-route-inventory` before reviewed legacy-route planning.
It turns one immutable live CPA config/auth snapshot plus the matching native
key-policy snapshot into dynamic, sealed routing inputs. It does not contact or
mutate CPA or Token Center.

```text
export-cpa-source-route-inventory --config /source/config.yaml --auth-dir /source/auth --policy-snapshot-file /source/native-key-policy.json --source-identity-key-file /secrets/migration/source-identity.key --source-inventory-output /sealed/source-inventory.json --provider-candidate-material-output /sealed/provider-candidate-material.json
```

The config, policy snapshot, and source identity key are mode-`0600` regular
files; the config/auth parser applies the same owner-only recursive rules as
the CPA upstream importer. Both destinations are distinct absolute normalized
paths below a current-UID-owned, non-group/other-writable directory. Each is
written mode `0600` with temporary-file fsync, no-replace hard-link publish,
and parent-directory fsync. Existing output is never overwritten.

The exporter shares the upstream importer's strict YAML/auth parser and source
identity logic. It resolves enabled native-policy grant coordinates against the
config's declared `models[].{name,alias,prefix}`, provider and prefix.
`provider` and `model` are mandatory anchors for a route mapping; an absent one
becomes an explicit anomaly and is never inferred. `group` and
`upstream_prefix` are independently optional: an omitted field is preserved as
JSON `null`, then matched as part of the exact source pattern and candidate
pool. Configuration determines the upstream model and protocol. Thus a
source-declared model such as `gpt-6-astra` appears without changing this tool
or relying on historical counts. Unknown config fields, unsupported model
entries, missing aliases, ambiguous model/driver/configuration joins, an
unresolved source grant, or an empty active source pool stop before either
public output is created. A parseable policy shape without provider/model is a
static anomaly and is never guessed or repaired.

## Local read-only source capture

`collect-cpa-source-snapshot` is the only supported way to obtain the source
config, auth tree, native-access policy, and (when applicable) managed Codex
model snapshot from the already-running CPA process. It does not create a Pod,
Job, image pull, Secret read, Kubernetes object, route, grant, or target
account. It deliberately requires an operator to name one existing Pod and
its UID; it never lists Pods or selects a workload.

Prepare an otherwise empty destination name below an existing current-UID
owned `0700` directory, and an already-authorized current-UID `0600` management
token file. The token is needed only if the captured source contains active
Codex OAuth auth files. Do not put either the token or generated directory in
Git, a ticket, chat, command substitution, or a shell trace. The command reads
the fixed Pod and verifies its actual `app.kubernetes.io/name`, container,
state-PVC claim, state/config volume relationship, config `subPath`, and
management port before every sensitive stage. The names and mount paths below
are the reviewed CPA deployment layout; `CONTEXT`, `POD`, and `POD_UID` must be
copied from the operator's read-only approved observation, not guessed.

```text
node /verified-release/operator-scripts/collect-cpa-source-snapshot.mjs \
  --kubectl-binary /usr/bin/kubectl \
  --context CONTEXT \
  --namespace cliproxyapi \
  --pod POD \
  --pod-uid POD_UID \
  --container cliproxyapi \
  --expected-app-name cliproxyapi \
  --expected-pvc cliproxyapi-auth \
  --source-state-root /root/.cli-proxy-api \
  --config-mount-path /CLIProxyAPI/config.yaml \
  --management-port 8317 \
  --management-token-file /protected/cpa-management.token \
  --output-directory /protected/cpa-source-captures/CAPTURE_ID
```

The collector invokes only fixed-argument `kubectl get pod`, `kubectl exec`
with `tar` read mode, and a loopback-only `kubectl port-forward` to that exact
Pod. It has no shell execution and does not change the caller's proxy or
Kubernetes settings. The port-forward is terminated in `finally`, including
on an API, timeout, or consistency error. Its production invocation requires
no `--kubectl-argument`; that repeatable option exists only for an explicitly
approved static local wrapper such as the synthetic CI fixture and never
may be given a Secret value.

The returned protected directory has mode `0700`; every contained dynamic file
has mode `0600` (and nested auth directories mode `0700`):

- `config.yaml`, `auth/`, and `native-key-policy.json` are the exact captured
  source inputs. `auth/logs` is excluded if it exists; its absence is valid.
- `managed-codex-model-snapshot.json` exists only when active Codex OAuth was
  observed. It is collected with the existing read-only management snapshot
  command over the temporary loopback forwarding path.
- `source-capture-receipt.json` is the final completeness sentinel. It carries
  only counts and SHA-256 seals, never config/auth/policy/token values or paths.

The collector captures the source twice. Full config, native policy, and the
route-affecting auth projection (`type`, enabled state, prefix, aliases, and
exclusions) must be identical. A full OAuth document digest is recorded only
as the observed payload revision: a normal token/expiry refresh may change it
without creating a new route identity or a target import. The managed registry
snapshot separately repeats its auth/model reads, so either source projection
or model-list movement fails closed. It also enforces limits on archive size,
entry count, per-entry size, command duration, management response size, and
port-forward output. A failed capture publishes no final receipt; choose a new
destination after investigating a partial directory rather than overwriting it.

## Managed Codex OAuth source evidence

A Codex OAuth auth file makes the management-plane model registry part of the
source proof. The local collector above invokes this read-only release
entrypoint through its temporary loopback path when it observes Codex OAuth.
Use the standalone form only when all its protected local source inputs were
already captured by that collector; it does not import an account, call Token
Center, or print an auth-file ID, token, model list, or credential payload.

```text
node /verified-release/operator-scripts/export-cpa-managed-codex-model-snapshot.mjs --management-api-base-url https://cpa.example/v0/management --management-token-file /secrets/migration/cpa-management.token --source-config-file /source/config.yaml --output /sealed/managed-codex-model-snapshot.json
```

`/secrets/migration/cpa-management.token`, `/source/config.yaml`, and the
snapshot output are current-UID-owned mode-`0600` regular files. The snapshot
output is protected dynamic material: it includes relative auth-file IDs and
model observations and must not be committed, copied to chat, or logged. Its
stdout receipt contains counts and digests only. The capture reads
`GET /v0/management/auth-files`, then each
`GET /v0/management/auth-files/models?name=...`, and repeats both observations.
It also rereads the source config. It rejects any config, list, or per-auth
model change during that window instead of
claiming an atomic CPA view that the API does not provide.

Pass the resulting snapshot to the normal exporter:

```text
node /verified-release/operator-scripts/export-cpa-source-route-inventory.mjs --config /source/config.yaml --auth-dir /source/auth --policy-snapshot-file /source/native-key-policy.json --source-identity-key-file /secrets/migration/source-identity.key --managed-codex-model-snapshot-file /sealed/managed-codex-model-snapshot.json --source-inventory-output /sealed/source-inventory.json --provider-candidate-material-output /sealed/provider-candidate-material.json
```

For managed Codex routes, the exporter evaluates the deployed native-access
`cpa-key-policy` `classify_rules` against the source auth-file identity and
accepts only the exact requested `classify:<group>` members. It applies the
per-auth alias before a global alias, honors exclusions and prefix policy, and
requires the captured per-auth registry to prove the model is actually
available. It therefore does not treat all enabled OAuth accounts as candidates
for every group. Unsupported RE2 rule syntax, source/config drift, missing
registry coverage, a missing candidate, incompatible aliases, or a collision
between a direct and managed pool for the same exact source tuple stops the
export. OAuth refresh fields are not route identity evidence and do not create
new candidates or force a re-import.

`source-inventory.json` is version 2 and can be used directly as
`import-cpa-model-routes --source-inventory-file`. It preserves every exact
source coordinate and reports opaque Copilot/Cursor records only as
`reauthorization_required` objects containing `provider` and a stable,
domain-separated HMAC-SHA256 `source_stable_id`. It never emits auth handles,
logins, labels, emails, paths, credentials, tokens, source key material, or
raw/key hashes. Stdout is a count-and-digest receipt only.

`provider-candidate-material.json` seals one target-independent version 1 candidate set
per source mapping: exact source, upstream model, protocol,
`equal_round_robin`, provider, driver and all HMAC-stable active source-account
candidates. Direct candidates use `http-json`; managed Codex OAuth candidates
use `openai-codex`. Both are serialized once with the same final
`source-inventory.json` digest. It is intentionally not an `upstream-inventory.json` replacement:
after the upstream import, bind each candidate exactly once to a current target
upstream account from a read-only target snapshot, then create reviewed
`upstream-inventory.json` version 2. Do not drop pool members, merge providers
or drivers, select weights, or infer target IDs. The existing route importer
will independently reject an incomplete or cross-provider/driver candidate set.

## Read-only deterministic direct-account binding receipt

If `import-cpa-upstreams --apply` has already replayed the direct API-key
accounts, create the protected binding input for provider-exact review with:

```text
import-cpa-upstreams --resolve-existing-route-bindings --config /source/config.yaml --auth-dir /source/auth --source-identity-key-file /secrets/migration/source-identity.key --provider-candidate-material-file /sealed/provider-candidate-material.json --binding-receipt-output /sealed/direct-route-bindings.json --target-api-base-url https://target-control.example --service-token-file /secrets/migration/target-service-token [--transport-policy-file /sealed/transport-policy.json]
```

This mode makes exactly one target request: a read-only `GET` of the selected
tenant's upstream inventory. It reconstructs the exporter’s domain-separated
direct-account HMAC, deterministic target account name, strict `http-json`
driver, canonical non-secret configuration, and active status. Exactly one
match produces a binding; absent, mismatched, inactive, or duplicate accounts
are recorded as quarantined. The receipt includes only opaque stable IDs,
provider, target UUID, revision, driver, source-inventory digest, candidate
material digest, and quarantine reasons. It never emits source IDs, account
names, configurations, credentials, or service tokens. The output uses the
same protected no-replace publication rules as the source outputs.

When the direct import used a transport policy, supply that same protected
policy file here; otherwise a policy-induced network scope or result-origin
difference correctly quarantines the account.

The mode does not create, update, or rotate target accounts; it does not cover
managed OAuth imports or Copilot/Cursor native reauthorization. Those have
separate provenance/reauthorization evidence and must be strictly composed
with this direct receipt before reviewed `upstream-inventory.json` is made.
