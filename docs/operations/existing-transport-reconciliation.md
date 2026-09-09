# Existing transport reconciliation (read only)

Use the CI-built immutable `reconcile-existing-transport` Release command when
the original reviewed import transport policy is unavailable. It makes only one
authenticated private-control `GET /internal/v1/upstreams` for an explicit tenant.
It never calls an import endpoint, writes a target, accesses a database, creates
permissions, or reads target credential material.

Required protected inputs: `--config`, `--auth-dir`,
`--source-identity-key-file`, `--source-inventory-file`,
`--provider-candidate-material-file`, `--service-token-file`.
Specify `--tenant`, `--target-api-base-url`, and two new absolute output paths:
`--policy-output` and `--receipt-output`. Optional `--ca-file` uses the existing
control CA contract. `--allow-http-loopback` is only for an explicitly approved
temporary loopback port-forward to that same private Service, preserving auth.
It is not evidence of canonical HTTPS or browser acceptance.

Source parsing and domain-separated HMAC identities are shared with the existing
importer. Source inventory must pass the existing version-2 schema parser and
contain at least one mapping. Candidate material must bind the exact supplied
source-inventory SHA, pass the composer schema parser, and cover every mapping
exactly once without missing, extra or duplicate pools. At least one direct
candidate is required; an empty `{}` input or an empty candidate set is not a
successful zero-work reconciliation.
An active source candidate must have exactly one active target with the exact
deterministic name, driver and configuration. Only the existing target's
`network_scope` and `result_origins` may supply policy annotations; these are not
new upstream targets or egress permissions. Every other config field must match.
The output does not modify source proxy settings or the target.

A source proxy without independently available target transport evidence is
always quarantined as `source_proxy_unverifiable`. Do not request target secrets
to make this check pass. The current importer also requires a private SOCKS proxy
for private targets, so private targets cannot be admitted by assuming an absent
source proxy: they receive the same explicit gap. This version therefore emits
no additional private-target allowance. Conflicting or incomplete source-account groups sharing
one base URL cannot produce a broader base-level policy. Missing, ambiguous,
inactive or mismatched target accounts remain explicit gaps. A 100-row response
is rejected as potentially truncated, never treated as a complete inventory.

Outputs are owner-only, no-replace files. The receipt binds source config,
source inventory, candidate material, target snapshot and policy SHA-256 and
includes every direct candidate as either a match or an explicit gap. It contains
no account name, URL, configuration or credential. Stdout is counts only.
Managed OAuth candidates remain owned by their separate provenance workflow.
The receipt additionally preserves source mapping, anomaly, reauthorization and
managed-candidate counts and explicitly scopes coverage to the supplied inventory
and direct candidates. It does not prove complete historical migration or that
the supplied sealed inventory includes every historical source record.

Both policy and receipt must exist and their digest binding must verify before
any later use. Failure during the second publication can leave the first file;
that file alone is not an approved artifact. Preserve it for investigation and
rerun with new output paths, never overwrite it.

This policy is exclusively for read-only reconciliation. It does not authorize
import/apply, route changes or widening private egress. Do not treat a partial
policy as approval of quarantined candidates, or the unchanged existing binding
resolver as proof that an encrypted proxy matched. Carry this receipt's full gap
set into final owner review even if another tool produces a less strict result.
