# CPA source route inventory export

This document describes a public, reusable one-shot exporter while preserving
the current CPA/Token Center names required by the active migration. It does
not authorize access to a CPA volume or any target environment. Real config,
auth files, policy snapshots, source identity keys, inventories, credentials,
logs, checkpoints, receipts and other dynamic evidence stay outside Git and
are supplied through an owner-approved protected-input boundary.

The exporter is executed from a CI-built image addressed by its verified
immutable digest. Dependencies are resolved from the lockfile while building
that image; the runtime must not use a generic `node` image to clone source,
download TypeScript, or run `npm install`/`npm ci`. Startup fetches make code
and dependency resolution mutable, require unnecessary network access, and
cannot reproduce the image's SBOM/provenance. Keep the existing command and
file names until a separately versioned compatibility adapter is reviewed.

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

`source-inventory.json` is version 2 and can be used directly as
`import-cpa-model-routes --source-inventory-file`. It preserves every exact
source coordinate and reports opaque Copilot/Cursor records only as
`reauthorization_required` objects containing `provider` and a stable,
domain-separated HMAC-SHA256 `source_stable_id`. It never emits auth handles,
logins, labels, emails, paths, credentials, tokens, source key material, or
raw/key hashes. Stdout is a count-and-digest receipt only.

`provider-candidate-material.json` seals a target-independent v2 candidate set
per source mapping: exact source, upstream model, protocol,
`equal_round_robin`, provider, driver and all HMAC-stable active source-account
candidates. It is intentionally not an `upstream-inventory.json` replacement:
after the upstream import, bind each candidate exactly once to a current target
upstream account from a read-only target snapshot, then create reviewed
`upstream-inventory.json` version 2. Do not drop pool members, merge providers
or drivers, select weights, or infer target IDs. The existing route importer
will independently reject an incomplete or cross-provider/driver candidate set.
