# Backup and restore

This runbook is scoped only to Token Center application recovery: its
PostgreSQL state, S3-compatible archives and generated assets, configuration,
and the key material required to decrypt or authenticate those records. It does
not prescribe cluster-wide, Harbor, Forgejo, Longhorn, node-disk or unrelated
service backups. Those are owned by the infrastructure operating procedures.

Backups are part of the service boundary because PostgreSQL stores identities,
permissions, balances, accounting and archive references while S3 stores the
request and response bodies. Restoring only one side can produce missing archive
objects or database references to a newer object-store state.

## Required policy

Define and review these values before production:

- RPO for PostgreSQL WAL and S3 objects;
- RTO for regional and operator-error recovery;
- base-backup and object-version retention;
- encryption key ownership and recovery;
- a restore environment isolated from production;
- who may initiate, approve and validate a restore.

Kubernetes PVC replicas and snapshots are not independent backups. Backups must
survive loss of the source cluster and its storage control plane.

## PostgreSQL

For CloudNativePG, configure continuous WAL archiving plus scheduled base backups
to a bucket outside the database cluster's failure domain. For managed
PostgreSQL, enable the equivalent PITR facility. Monitor WAL archive failures and
the first/last recoverable timestamp.

At least monthly, restore into an isolated namespace and validate:

1. the operator reports the expected recovery point;
2. schema migrations match the chosen application image;
3. tenant, stable credential identity, grants and ledger totals are consistent;
4. request counts and daily aggregates reconcile;
5. a sample of archive references can be read from restored S3;
6. the gateway can start with migrations disabled and pass a dependency-aware
   readiness check when that endpoint is available.

Never run a restore test against the production write service. Record the image
digest, database recovery timestamp, backup identifiers, duration and validation
results.

## S3-compatible archive

Enable bucket versioning and replication or a provider-native backup to another
failure domain. Apply lifecycle rules deliberately: content-addressed objects can
be shared by multiple request records, so deleting an object merely because one
record aged out can corrupt another record.

Validate restore by listing and reading known objects, checking their hashes and
comparing a database sample of archive references. An empty bucket, a writable
health check, or a successful MinIO PVC snapshot alone is insufficient.

## Recovery sequence

1. Freeze writes or route clients back to the previous gateway.
2. Record the incident recovery target and select mutually compatible database
   and object-store recovery points.
3. Restore PostgreSQL and S3 into new endpoints; do not overwrite the failed
   resources in place.
4. deliver new endpoint credentials through the managed secret controller;
5. run the migration Job only if the selected application image requires it;
6. start control and worker, then a single canary gateway;
7. reconcile ledger/account invariants, aggregate counts and sampled archives;
8. expand gateways and restore traffic gradually;
9. keep the failed environment read-only until the post-incident review.

If S3 recovery is behind PostgreSQL, request detail should report an archive gap
rather than fabricate content. If PostgreSQL is behind S3, unreferenced
content-addressed objects may remain; garbage collection requires a separate,
audited reachability process.
