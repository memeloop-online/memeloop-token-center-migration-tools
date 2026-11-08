use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

impl Runner {
    // Separate from quiesced checkpoints: every invocation rescans from the
    // beginning, including keys behind the previous cursor. Receipts describe
    // observed row versions, never a complete or consistent source snapshot.
    pub(super) async fn copy_payloads_online(&self) -> Result<serde_json::Value> {
        let ledger = self.checkpoint.with_extension("online-payload-receipts");
        std::fs::create_dir_all(&ledger)?;
        let mut historical_versions = 0_u64;
        for entry in std::fs::read_dir(&ledger)? {
            let entry = entry?;
            // save_checkpoint may leave a temporary file after process death.
            let path = entry.path();
            let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if extension != "json" && extension != "pending" {
                continue;
            }
            let receipt: PayloadReceipt = serde_json::from_reader(std::fs::File::open(entry.path())?)?;
            let encoded = serde_json::to_vec(&receipt)?;
            let digest = blake3::hash(&encoded).to_hex().to_string();
            if receipt.format_version != 1
                || receipt.identity != self.identity
                || receipt.field == SourceField::Atom
                || entry.file_name().to_str() != Some(format!("{digest}.{extension}").as_str())
            {
                return Err("online payload receipt identity mismatch".into());
            }
            self.publish_online_payload_receipt(&receipt, &encoded, &digest, extension == "pending").await?;
            if extension == "pending" {
                std::fs::rename(&path, ledger.join(format!("{digest}.json")))?;
                std::fs::File::open(&ledger)?.sync_all()?;
            }
            historical_versions += 1;
        }
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        let mut disappeared_fields = 0_u64;
        for field in FIELDS {
            let (table, id, column) = field.columns();
            let mut cursor = Cursor::default();
            loop {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT tenant_id, {id} AS source_id FROM {table} WHERE (tenant_id, {id}) > ($1, $2) AND {column} IS NOT NULL ORDER BY tenant_id, {id} LIMIT 1"
                )))
                .bind(&cursor.tenant_id).bind(&cursor.content_hash)
                .fetch_optional(&self.pool).await?;
                let Some(row) = row else { break };
                cursor = Cursor {
                    tenant_id: row.try_get("tenant_id")?,
                    content_hash: row.try_get("source_id")?,
                };
                let Some((reference, source_md5)) =
                    self.source_field_reference_if_present(&cursor, field, true).await?
                else {
                    disappeared_fields += 1;
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
                    self.publish_online_payload_receipt(&receipt, &encoded, &digest, false).await?;
                } else {
                    let pending = ledger.join(format!("{digest}.pending"));
                    save_checkpoint(&pending, &receipt)?;
                    self.publish_online_payload_receipt(&receipt, &encoded, &digest, true).await?;
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
            "bytes_observed": bytes,
            "fields_disappeared_before_snapshot": disappeared_fields,
            "historical_versions_rechecked": historical_versions,
            "requires_quiesced_final_copy_and_verification": true
        }))
    }

    async fn publish_online_payload_receipt(
        &self,
        receipt: &PayloadReceipt,
        encoded: &[u8],
        digest: &str,
        publish: bool,
    ) -> Result<()> {
        self.target.verify_tenant_content(
            Uuid::parse_str(&receipt.cursor.tenant_id)?,
            &receipt.reference.conversation_body_v1,
        ).await?;
        // Content-addressed receipts preserve earlier versions. Replaying an
        // interrupted publication writes the identical bytes at the same key.
        let key = format!(
            "migration-receipts/conversation-v1/{}/online-payloads/{digest}.json",
            self.identity
        );
        if publish {
            self.target.put(&key, Bytes::copy_from_slice(encoded)).await?;
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
