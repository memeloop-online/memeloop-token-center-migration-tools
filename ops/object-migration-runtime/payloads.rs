use super::*;

#[path = "semantic_payload_refs.rs"]
mod semantic_payload_refs;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SourceField {
    Atom,
    SemanticPayload,
    OutboxRequest,
    SemanticSnapshot,
    PayloadSnapshot,
    KeySnapshot,
    Hints,
}

pub(super) const FIELDS: [SourceField; 6] = [
    SourceField::SemanticPayload,
    SourceField::OutboxRequest,
    SourceField::SemanticSnapshot,
    SourceField::PayloadSnapshot,
    SourceField::KeySnapshot,
    SourceField::Hints,
];

impl SourceField {
    pub(super) fn columns(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Atom => ("semantic_atoms", "content_hash", "content_json"),
            Self::SemanticPayload => (
                "conversation_semantic_payloads",
                "request_id",
                "request_json",
            ),
            Self::OutboxRequest => (
                "conversation_projection_outbox",
                "request_id",
                "request_json",
            ),
            Self::SemanticSnapshot => (
                "conversation_projection_outbox",
                "request_id",
                "semantic_snapshot_json",
            ),
            Self::PayloadSnapshot => (
                "conversation_projection_outbox",
                "request_id",
                "semantic_payload_snapshot_json",
            ),
            Self::KeySnapshot => (
                "conversation_projection_outbox",
                "request_id",
                "key_snapshot_json",
            ),
            Self::Hints => ("conversation_projection_outbox", "request_id", "hints_json"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadReceipt {
    format_version: u32,
    identity: String,
    field: SourceField,
    cursor: Cursor,
    source_md5: String,
    reference: ConversationBodyReference,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PayloadCheckpoint {
    format_version: u32,
    identity: String,
    field_index: usize,
    cursor: Cursor,
    pub(super) rows: u64,
    pub(super) bytes: u64,
    digest: String,
    complete: bool,
    pub(super) verified: bool,
}

// The layout always includes all six fields. Only the primary-key hash is
// partitioned; a row's fields stay on the same worker and retain their original
// per-field repeatable-read snapshots and 64 Ki-character streaming chunks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OnlinePlan {
    pub(super) shards: i32,
    shard: i32,
}

impl OnlinePlan {
    pub(super) fn new(shards: i32, shard: i32) -> Result<Self> {
        if shards < 1 || shard < 0 || shard >= shards {
            return Err("online shard index must be in [0, online-shards)".into());
        }
        Ok(Self { shards, shard })
    }

    async fn owns(self, pool: &PgPool, cursor: &Cursor) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT (('x' || substr(md5($1 || ':' || $2), 1, 8))::bit(32)::bigint % $3)",
        )
        .bind(&cursor.tenant_id)
        .bind(&cursor.content_hash)
        .bind(i64::from(self.shards))
        .fetch_one(pool)
        .await?
            == i64::from(self.shard))
    }
}

// Shared source lock excludes every old serial command and quiesced phase.
// A short coordinator lock serializes layout admission, not body transfers.
// Reserved two-int namespaces encode the exact shard count and index, avoiding
// hashed lock identities. An incompatible active layout is rejected, never mixed.
pub(super) async fn lock_online_shard(
    connection: &mut sqlx::PgConnection,
    plan: OnlinePlan,
    identity: &str,
) -> Result<()> {
    let source: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock_shared(70720261029)")
        .fetch_one(&mut *connection)
        .await?;
    if !source {
        return Err("another conversation migration holds the source lock".into());
    }
    // Admission contains only PostgreSQL lock metadata, never a source read or
    // remote object call. Serialize simultaneous starts without failing shards.
    sqlx::query("SELECT pg_advisory_lock(70720261030)")
        .execute(&mut *connection)
        .await?;
    let incompatible: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = 7072026::oid AND objsubid = 2 AND granted AND objid::bigint <> $1)"
    ).bind(i64::from(plan.shards)).fetch_one(&mut *connection).await?;
    if incompatible {
        return Err("another online shard layout is active".into());
    }
    // Bind the complete source/target identity, not a truncated lock hash.
    // Eight reserved namespaces hold all 256 bits; starts for another target
    // are rejected even when their shard counts happen to match.
    let identity_hash = blake3::hash(identity.as_bytes());
    let words: Vec<i64> = identity_hash
        .as_bytes()
        .chunks_exact(4)
        .map(|word| {
            i64::from(u32::from_be_bytes(
                word.try_into().expect("four-byte identity word"),
            ))
        })
        .collect();
    let other_identity: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid BETWEEN 7072030::oid AND 7072037::oid AND objsubid = 2 AND granted AND objid::bigint <> ($1::bigint[])[classid::int - 7072029])"
    ).bind(&words).fetch_one(&mut *connection).await?;
    if other_identity {
        return Err("another online source/target identity is active".into());
    }
    for (index, word) in words.iter().enumerate() {
        sqlx::query("SELECT pg_advisory_lock_shared($1, $2)")
            .bind(7072030_i32 + index as i32)
            .bind(*word as i32)
            .execute(&mut *connection)
            .await?;
    }
    sqlx::query("SELECT pg_advisory_lock_shared(7072026, $1)")
        .bind(plan.shards)
        .execute(&mut *connection)
        .await?;
    let shard: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(7072027, $1)")
        .bind(plan.shard)
        .fetch_one(&mut *connection)
        .await?;
    sqlx::query("SELECT pg_advisory_unlock(70720261030)")
        .execute(&mut *connection)
        .await?;
    if !shard {
        return Err("another worker owns this online shard".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct OnlineBinding {
    format_version: u32,
    identity: String,
    plan: OnlinePlan,
    fields: Vec<SourceField>,
}

impl Runner {
    // Separate from quiesced checkpoints: every invocation rescans from the
    // beginning, including keys behind the previous cursor. Receipts describe
    // observed row versions, never a complete or consistent source snapshot.
    #[cfg(test)]
    pub(super) async fn copy_payloads_online(&self) -> Result<serde_json::Value> {
        self.copy_payloads_online_partition(OnlinePlan::new(1, 0)?, None)
            .await
    }

    // Keep the complete transfer state on the heap. In particular, callers
    // that retain several online-copy calls in one async state must not embed
    // every source/target streaming future in their own stack frames.
    pub(super) fn copy_payloads_online_partition<'a>(
        &'a self,
        plan: OnlinePlan,
        import: Option<&'a std::path::Path>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        Box::pin(self.copy_payloads_online_partition_inner(plan, import))
    }

    async fn copy_payloads_online_partition_inner(
        &self,
        plan: OnlinePlan,
        import: Option<&std::path::Path>,
    ) -> Result<serde_json::Value> {
        let binding = OnlineBinding {
            format_version: 1,
            identity: self.identity.clone(),
            plan,
            fields: FIELDS.to_vec(),
        };
        let binding_path = self.checkpoint.with_extension("online-layout.json");
        match std::fs::File::open(&binding_path) {
            Ok(file) => {
                if serde_json::from_reader::<_, OnlineBinding>(file)? != binding {
                    return Err(
                        "online checkpoint layout mismatch; use a distinct checkpoint per shard"
                            .into(),
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Legacy ledgers have no layout and belong to the serial plan.
                if plan.shards != 1
                    && self
                        .checkpoint
                        .with_extension("online-payload-receipts")
                        .exists()
                {
                    return Err("legacy ledger must be imported into a new shard checkpoint".into());
                }
                save_checkpoint(&binding_path, &binding)?;
            }
            Err(error) => return Err(error.into()),
        }
        let ledger = self.checkpoint.with_extension("online-payload-receipts");
        std::fs::create_dir_all(&ledger)?;
        // Keep an old writer from reopening the import ledger while workers
        // read it; shared locks allow all shards to reuse the same stopped ledger.
        let _import_lock = if let Some(import) = import {
            if std::fs::canonicalize(import)? == std::fs::canonicalize(&ledger)? {
                return Err("import ledger must be distinct from the destination ledger".into());
            }
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(import.with_extension("lock"))?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockShared)?;
            for entry in std::fs::read_dir(import)? {
                let path = entry?.path();
                let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if extension != "json" && extension != "pending" {
                    continue;
                }
                let (receipt, encoded, digest) = self.read_online_receipt(&path)?;
                if !plan.owns(&self.pool, &receipt.cursor).await? {
                    continue;
                }
                // Validate the exact old object and immutable receipt before
                // committing a local copy. Pending publications are recoverable.
                self.publish_online_payload_receipt(
                    &receipt,
                    &encoded,
                    &digest,
                    extension == "pending",
                )
                .await?;
                let destination = ledger.join(format!("{digest}.json"));
                if !destination.exists() {
                    save_checkpoint(&destination, &receipt)?;
                }
            }
            Some(lock)
        } else {
            None
        };
        let mut historical_versions = 0_u64;
        let mut known =
            std::collections::HashMap::<(String, String, SourceField), Vec<PayloadReceipt>>::new();
        for entry in std::fs::read_dir(&ledger)? {
            let entry = entry?;
            // save_checkpoint may leave a temporary file after process death.
            let path = entry.path();
            let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if extension != "json" && extension != "pending" {
                continue;
            }
            let (receipt, encoded, digest) = self.read_online_receipt(&path)?;
            if !plan.owns(&self.pool, &receipt.cursor).await? {
                return Err("receipt belongs to a different online shard".into());
            }
            if extension == "pending" {
                self.publish_online_payload_receipt(&receipt, &encoded, &digest, true)
                    .await?;
            } else {
                self.verify_committed_payload_receipt(&encoded, &digest)
                    .await?;
            }
            if extension == "pending" {
                std::fs::rename(&path, ledger.join(format!("{digest}.json")))?;
                std::fs::File::open(&ledger)?.sync_all()?;
            }
            known
                .entry((
                    receipt.cursor.tenant_id.clone(),
                    receipt.cursor.content_hash.clone(),
                    receipt.field,
                ))
                .or_default()
                .push(receipt);
            historical_versions += 1;
        }
        let mut reused = 0_u64;
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        let mut disappeared_fields = 0_u64;
        let mut external_semantic_references = 0_u64;
        for field in FIELDS {
            let (table, id, column) = field.columns();
            let source_format = if field == SourceField::SemanticPayload {
                "format_version::bigint"
            } else {
                "1::bigint"
            };
            let mut cursor = Cursor::default();
            loop {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT tenant_id, {id} AS source_id, {source_format} AS source_format FROM {table} WHERE (tenant_id, {id}) > ($1, $2) AND {column} IS NOT NULL AND (('x' || substr(md5(tenant_id || ':' || {id}), 1, 8))::bit(32)::bigint % $3) = $4 ORDER BY tenant_id, {id} LIMIT 1"
                )))
                .bind(&cursor.tenant_id).bind(&cursor.content_hash)
                .bind(i64::from(plan.shards)).bind(i64::from(plan.shard))
                .fetch_optional(&self.pool).await?;
                let Some(row) = row else { break };
                cursor = Cursor {
                    tenant_id: row.try_get("tenant_id")?,
                    content_hash: row.try_get("source_id")?,
                };
                let versions =
                    known.get(&(cursor.tenant_id.clone(), cursor.content_hash.clone(), field));
                let mut observed = if versions.is_some() {
                    // Rehash the current source in a fresh repeatable-read
                    // snapshot. MD5 alone never authorizes reuse of a version.
                    self.source_field_reference_if_present(&cursor, field, false)
                        .await?
                } else {
                    self.source_field_reference_if_present(&cursor, field, true)
                        .await?
                };
                if let Some((reference, md5)) = observed.as_ref() {
                    if let Some(versions) = versions {
                        if versions.iter().any(|old| {
                            old.source_md5 == *md5
                                && old.reference.chars == reference.chars
                                && old.reference.conversation_body_v1.object_locator
                                    == reference.conversation_body_v1.object_locator
                                && old.reference.conversation_body_v1.blake3_digest
                                    == reference.conversation_body_v1.blake3_digest
                                && old.reference.conversation_body_v1.size_bytes
                                    == reference.conversation_body_v1.size_bytes
                        }) {
                            reused += 1;
                        } else {
                            // A changed row is copied under another complete
                            // snapshot; disappearance still retains every old receipt.
                            observed = self
                                .source_field_reference_if_present(&cursor, field, true)
                                .await?;
                        }
                    }
                }
                let Some((reference, source_md5)) = observed else {
                    if field == SourceField::SemanticPayload
                        && row.try_get::<i64, _>("source_format")? == 2
                    {
                        external_semantic_references += 1;
                    } else {
                        disappeared_fields += 1;
                    }
                    continue;
                };
                let receipt = PayloadReceipt {
                    format_version: 1,
                    identity: self.identity.clone(),
                    field,
                    cursor: cursor.clone(),
                    source_md5,
                    reference,
                };
                let encoded = serde_json::to_vec(&receipt)?;
                let digest = blake3::hash(&encoded).to_hex().to_string();
                // Persist the exact version before publishing its receipt. A
                // crash is recovered even if the source changes or disappears.
                let committed = ledger.join(format!("{digest}.json"));
                if committed.exists() {
                    self.verify_committed_payload_receipt(&encoded, &digest)
                        .await?;
                } else {
                    let pending = ledger.join(format!("{digest}.pending"));
                    save_checkpoint(&pending, &receipt)?;
                    self.publish_online_payload_receipt(&receipt, &encoded, &digest, true)
                        .await?;
                    std::fs::rename(pending, committed)?;
                    std::fs::File::open(&ledger)?.sync_all()?;
                }
                rows += 1;
                bytes += receipt.reference.conversation_body_v1.size_bytes;
            }
        }
        Ok(serde_json::json!({
            "mode": "online_copy",
            "scan_finished": true,
            "source_verified": false,
            "source_writers_quiesced": false,
            "rows_observed": rows,
            "versions_reused_without_upload": reused,
            "online_shards": plan.shards,
            "online_shard": plan.shard,
            "bytes_observed": bytes,
            "fields_disappeared_before_snapshot": disappeared_fields,
            "external_semantic_references_retained": external_semantic_references,
            "historical_versions_rechecked": historical_versions,
            "requires_quiesced_final_copy_and_verification": true
        }))
    }

    fn read_online_receipt(
        &self,
        path: &std::path::Path,
    ) -> Result<(PayloadReceipt, Vec<u8>, String)> {
        let receipt: PayloadReceipt = serde_json::from_reader(std::fs::File::open(path)?)?;
        let encoded = serde_json::to_vec(&receipt)?;
        let digest = blake3::hash(&encoded).to_hex().to_string();
        if receipt.format_version != 1
            || receipt.identity != self.identity
            || receipt.field == SourceField::Atom
            || path.file_stem().and_then(|s| s.to_str()) != Some(digest.as_str())
        {
            return Err("online payload receipt identity mismatch".into());
        }
        Ok((receipt, encoded, digest))
    }

    // A committed local record is accepted only against its immutable remote
    // receipt. Its filename digest and target/source identity were checked by
    // read_online_receipt; current source reuse still requires the fresh source
    // snapshot comparison below. Do not download historical bodies on resume.
    async fn verify_committed_payload_receipt(&self, encoded: &[u8], digest: &str) -> Result<()> {
        let key = format!(
            "migration-receipts/conversation-v1/{}/online-payloads/{digest}.json",
            self.identity
        );
        if self.target.get_bounded(&key, 16384).await?.as_ref() != encoded {
            return Err("committed online payload receipt mismatch".into());
        }
        Ok(())
    }

    async fn publish_online_payload_receipt(
        &self,
        receipt: &PayloadReceipt,
        encoded: &[u8],
        digest: &str,
        publish: bool,
    ) -> Result<()> {
        self.target
            .verify_tenant_content(
                Uuid::parse_str(&receipt.cursor.tenant_id)?,
                &receipt.reference.conversation_body_v1,
            )
            .await?;
        // Content-addressed receipts preserve earlier versions. Replaying an
        // interrupted publication writes the identical bytes at the same key.
        let key = format!(
            "migration-receipts/conversation-v1/{}/online-payloads/{digest}.json",
            self.identity
        );
        if publish {
            self.target
                .put(&key, Bytes::copy_from_slice(encoded))
                .await?;
        }
        if self.target.get_bounded(&key, 16384).await?.as_ref() != encoded {
            return Err("online payload receipt mismatch".into());
        }
        Ok(())
    }

    pub(super) async fn transfer_payloads(&self, verify: bool) -> Result<PayloadCheckpoint> {
        let path = self.checkpoint.with_extension("payloads.json");
        let mut checkpoint = match std::fs::File::open(&path) {
            Ok(file) => serde_json::from_reader::<_, PayloadCheckpoint>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PayloadCheckpoint {
                format_version: 1,
                identity: self.identity.clone(),
                ..Default::default()
            },
            Err(error) => return Err(error.into()),
        };
        if checkpoint.format_version != 1
            || checkpoint.identity != self.identity
            || checkpoint.field_index > FIELDS.len()
        {
            return Err("payload checkpoint identity mismatch".into());
        }
        if verify && !checkpoint.complete {
            return Err("payload copy incomplete".into());
        }
        if !verify && checkpoint.complete {
            return Ok(checkpoint);
        }
        if verify {
            checkpoint.verified = false;
            save_checkpoint(&path, &checkpoint)?;
        }
        let mut result = if verify {
            PayloadCheckpoint {
                format_version: 1,
                identity: self.identity.clone(),
                ..Default::default()
            }
        } else {
            checkpoint.clone()
        };
        while let Some(field) = FIELDS.get(result.field_index).copied() {
            let (table, id, column) = field.columns();
            let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT tenant_id, {id} AS source_id FROM {table} WHERE (tenant_id, {id}) > ($1, $2) AND {column} IS NOT NULL ORDER BY tenant_id, {id} LIMIT 1"
            )))
            .bind(&result.cursor.tenant_id).bind(&result.cursor.content_hash)
            .fetch_optional(&self.pool).await?;
            let Some(row) = row else {
                result.field_index += 1;
                result.cursor = Cursor::default();
                if !verify {
                    save_checkpoint(&path, &result)?;
                }
                continue;
            };
            let cursor = Cursor {
                tenant_id: row.try_get("tenant_id")?,
                content_hash: row.try_get("source_id")?,
            };
            let (reference, source_md5) =
                self.source_field_reference(&cursor, field, !verify).await?;
            let receipt = PayloadReceipt {
                format_version: 1,
                identity: self.identity.clone(),
                field,
                cursor: cursor.clone(),
                source_md5,
                reference,
            };
            let key_digest = blake3::hash(&serde_json::to_vec(&(field, &cursor))?)
                .to_hex()
                .to_string();
            let key = format!(
                "migration-receipts/conversation-v1/{}/payloads/{key_digest}.json",
                self.identity
            );
            let encoded = serde_json::to_vec(&receipt)?;
            if !verify {
                self.target.put(&key, Bytes::from(encoded.clone())).await?;
            }
            if self.target.get_bounded(&key, 16384).await?.as_ref() != encoded {
                return Err("payload transfer receipt/source mismatch".into());
            }
            self.target
                .verify_tenant_content(
                    Uuid::parse_str(&cursor.tenant_id)?,
                    &receipt.reference.conversation_body_v1,
                )
                .await?;
            let mut digest = blake3::Hasher::new();
            digest.update(result.digest.as_bytes());
            digest.update(&encoded);
            result.digest = digest.finalize().to_hex().to_string();
            result.rows += 1;
            result.bytes += receipt.reference.conversation_body_v1.size_bytes;
            result.cursor = cursor;
            if !verify {
                save_checkpoint(&path, &result)?;
            }
        }
        if verify {
            if result.rows != checkpoint.rows
                || result.bytes != checkpoint.bytes
                || result.digest != checkpoint.digest
            {
                return Err("payload count/byte/order mismatch".into());
            }
            result.verified = true;
        }
        result.complete = true;
        save_checkpoint(&path, &result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod future_state_tests {
    use super::*;

    // Type-only factories are never called: no fake Runner or unsafe reference
    // is constructed, and measuring state does not connect to PG or an archive.
    fn future_bytes<F: std::future::Future>(_: impl FnOnce(&'static Runner) -> F) -> usize {
        std::mem::size_of::<F>()
    }

    #[test]
    fn online_transfer_retains_large_state_behind_a_heap_boundary() {
        let plan = OnlinePlan::new(4, 0).unwrap();
        let inner = future_bytes(|runner| runner.copy_payloads_online_partition_inner(plan, None));
        let outer = future_bytes(|runner| runner.copy_payloads_online_partition(plan, None));
        // Direct stderr remains visible even if a later contract aborts before
        // libtest can print captured output. These are type sizes, never data.
        writeln!(
            std::io::stderr(),
            "online_copy_future_bytes inner={inner} public={outer}"
        )
        .unwrap();
        assert!(
            outer < inner,
            "public callers must not retain the inline transfer state"
        );
    }
}
