# Native Kimi sealed import

`native-kimi-import` migrates the exact reviewed two-account Kimi OAuth cohort
from an owner-only `collect-cpa-source-snapshot` directory. It excludes inactive
backup revisions, verifies the capture receipt and every source digest, rejects
disabled or duplicate asserted identities, and never prints source paths,
claims, device identifiers, or tokens.

The default mode is offline and read-only. Supplying a target performs only
bounded control-plane GET requests for `/version`, managed-OAuth capabilities,
provider types, and the redacted upstream-account list. It does not invoke
provider health, model catalog, quota, token refresh, or any Kimi endpoint.
The target revision must match the explicitly reviewed 40-character release
revision.

The protected dry-run receipt contains source and batch hashes, HMAC-based
source/identity deduplication evidence, eight deferred route plans, and target
capability evidence. Route plans retain both OpenAI and Anthropic coverage as a
review requirement; this command deliberately creates no routes, grants, keys,
prices, catalog observations, or reservation bounds.

Apply additionally requires `--apply`, `--expected-count 2`, and the exact
successful target-bound dry-run receipt. Before every submission and after the
batch it reopens and revalidates the sealed source. It calls only the global
`imports:cpa:write` managed-OAuth endpoint. MTC derives server-keyed source
identities for replay, stores credentials in its encrypted generation envelope,
and returns sanitized account bindings. The expected Kimi release uses neutral,
deterministic account names with no CPA/bridge terminology.

```text
native-kimi-import \
  --source-directory /owner-only/sealed-source \
  --source-identity-key-file /owner-only/source-identity.key \
  --receipt /owner-only/receipts/kimi-dry-run.json \
  --target-api-base-url https://control.example/ \
  --service-token-file /owner-only/import-service.token \
  --tenant default \
  --expected-target-revision REVIEWED_RELEASE_SHA
```

After independent receipt review, the one-command apply shape is:

```text
native-kimi-import \
  --source-directory /owner-only/sealed-source \
  --source-identity-key-file /owner-only/source-identity.key \
  --receipt /owner-only/receipts/kimi-apply.json \
  --target-api-base-url https://control.example/ \
  --service-token-file /owner-only/import-service.token \
  --tenant default \
  --expected-target-revision REVIEWED_RELEASE_SHA \
  --approved-dry-run-receipt /owner-only/receipts/kimi-dry-run.json \
  --expected-count 2 \
  --apply
```

Any failure after the sealed source and protected output are admitted produces
a protected terminal receipt. Source/admission failures create no artifact.
`partial-stop-no-retry` and
`uncertain-stop-no-retry` are hard stops: inspect target source-key provenance;
never rerun automatically. Import may make expired active credentials eligible
for the separately deployed worker refresh loop, so production apply also
requires an operator-reviewed refresh/activation window. This repository does
not perform that rollout.
