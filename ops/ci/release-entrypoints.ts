/**
 * Reviewed commands that CI packages as standalone Node.js release scripts.
 *
 * Keep this registry deliberately small and explicit: a TypeScript library is
 * not distributable merely because another command imports it. Both the
 * legacy local launcher and the release bundle consume this list so a command
 * cannot silently exist in one delivery path but not the other.
 */
export const releaseEntrypoints = Object.freeze({
  "api2-target-rollback": "ops/api2-target-rollback.ts",
  "attach-legacy-cpa-credentials": "ops/legacy-credentials/attach-legacy-cpa-credentials.ts",
  "audit-cpa-migration": "ops/audit-cpa-migration.ts",
  "credential-recovery-backfill": "src/credential-recovery-backfill.ts",
  "collect-cpa-source-snapshot": "ops/legacy-routes/collect-cpa-source-snapshot.ts",
  "compose-cpa-upstream-inventory": "ops/legacy-routes/compose-cpa-upstream-inventory.ts",
  "export-cpa-managed-codex-model-snapshot": "ops/legacy-routes/export-cpa-managed-codex-model-snapshot.ts",
  "export-cpa-session-archive-delta": "ops/export-cpa-session-archive-delta.ts",
  "export-cpa-source-route-inventory": "ops/legacy-routes/export-cpa-source-route-inventory.ts",
  "export-cpa-target-route-receipt": "ops/legacy-routes/export-cpa-target-route-receipt.ts",
  "finalize-session-archive-delta": "ops/finalize-session-archive-delta.ts",
  "generate-provider-exact-policy-inputs": "ops/legacy-policy/generate-provider-exact-policy-inputs.ts",
  "generate-source-identity-key": "ops/cpa-upstreams/generate-source-identity-key.ts",
  "import-cpa-key-policy": "ops/legacy-policy/import-cpa-key-policy.ts",
  "import-cpa-model-routes": "ops/legacy-routes/import-cpa-model-routes.ts",
  "import-cpa-session-archive": "ops/import-cpa-session-archive.ts",
  "import-cpa-upstreams": "ops/cpa-upstreams/import-cpa-upstreams.ts",
  "migrate-cpamp": "ops/migrate-cpamp.ts",
  "reconcile-final-price-cache": "ops/reconcile-final-price-cache.ts",
  "reconcile-existing-transport": "ops/cpa-upstreams/reconcile-existing-transport.ts",
  "resolve-cpa-managed-codex-provenance": "ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts",
  "stage-protected-inputs": "ops/ci/stage-protected-inputs.ts",
} as const);

export type ReleaseEntrypoint = keyof typeof releaseEntrypoints;

export const releaseEntrypointNames = Object.freeze(
  Object.keys(releaseEntrypoints) as ReleaseEntrypoint[],
);
