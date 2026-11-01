use super::*;
use futures_util::StreamExt;
use memeloop_token_center::archive::CasArchiveObject;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocatorCursor {
    kind: String,
    tenant: String,
    identity: String,
}

impl LocatorCursor {
    fn columns(&self) -> Result<(&'static str, &'static str, &'static str)> {
        Ok(match self.kind.as_str() {
            "request" => ("request_records", "id", "request_object"),
            "response" => ("request_records", "id", "response_object"),
            "import_request" => (
                "session_archive_import_records",
                "json_build_array(source, external_request_id)::TEXT",
                "request_object",
            ),
            "import_response" => (
                "session_archive_import_records",
                "json_build_array(source, external_request_id)::TEXT",
                "response_object",
            ),
            "import_previous_request" => (
                "session_archive_import_records",
                "json_build_array(source, external_request_id)::TEXT",
                "previous_request_object",
            ),
            "import_previous_response" => (
                "session_archive_import_records",
                "json_build_array(source, external_request_id)::TEXT",
                "previous_response_object",
            ),
            "unlinked_request" => (
                "session_archive_unlinked_requests",
                "archive_request_id",
                "request_object",
            ),
            "unlinked_response" => (
                "session_archive_unlinked_requests",
                "archive_request_id",
                "response_object",
            ),
            "quarantine_request" => ("session_archive_quarantine_records", "id", "request_object"),
            "quarantine_response" => (
                "session_archive_quarantine_records",
                "id",
                "response_object",
            ),
            "quarantine_version_request" => (
                "session_archive_quarantine_record_versions",
                "id",
                "request_object",
            ),
            "quarantine_version_response" => (
                "session_archive_quarantine_record_versions",
                "id",
                "response_object",
            ),
            "media" => (
                "conversation_media_parts",
                "turn_id || ':' || part_index",
                "object_locator",
            ),
            _ => return Err("unknown locator source kind".into()),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocatorReceipt {
    format_version: u32,
    identity: String,
    cursor: LocatorCursor,
    source_locator_blake3: String,
    #[serde(default)]
    source_locator_md5: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    object: Option<CasArchiveObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gap_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocatorCheckpoint {
    format_version: u32,
    identity: String,
    owner_identity: String,
    cursor: LocatorCursor,
    pub(super) copied_rows: u64,
    pub(super) copied_bytes: u64,
    #[serde(default)]
    pub(super) gap_rows: u64,
    digest: String,
    complete: bool,
    pub(super) verified: bool,
}

struct LocatedObject {
    cursor: LocatorCursor,
    locator: String,
    source_locator_blake3: String,
    source_locator_md5: String,
    expected_digest: Option<String>,
    expected_bytes: Option<u64>,
}

fn receipt_key(identity: &str, cursor: &LocatorCursor) -> Result<String> {
    let digest = blake3::hash(&serde_json::to_vec(cursor)?)
        .to_hex()
        .to_string();
    Ok(format!(
        "migration-receipts/conversation-v1/{identity}/locators/{digest}.json"
    ))
}

pub(super) fn source_config(target: &Config) -> Result<Config> {
    let mut source = target.clone();
    source.s3_endpoint = Some(
        std::env::var("MTC_SOURCE_S3_ENDPOINT").map_err(|_| "explicit source endpoint required")?,
    );
    source.s3_bucket =
        Some(std::env::var("MTC_SOURCE_S3_BUCKET").map_err(|_| "explicit source bucket required")?);
    source.s3_access_key = Some(
        std::env::var("MTC_SOURCE_S3_ACCESS_KEY")
            .map_err(|_| "source access credential environment reference required")?,
    );
    source.s3_secret_key = Some(
        std::env::var("MTC_SOURCE_S3_SECRET_KEY")
            .map_err(|_| "source secret credential environment reference required")?,
    );
    source.s3_region = std::env::var("MTC_SOURCE_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
    source.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
    source.s3_allow_http = source
        .s3_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.starts_with("http://"));
    Ok(source)
}

fn save(path: &std::path::Path, checkpoint: &LocatorCheckpoint) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), checkpoint)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl Runner {
    pub(super) async fn cutover_locators_test(&self) -> Result<serde_json::Value> {
        self.require_test_database().await?;
        let path = self.checkpoint.with_extension("locator-cutover.json");
        let mut result = serde_json::json!({
            "format_version":1, "identity":self.identity,
            "complete":false, "rows":0, "bytes":0,
            "source_objects_deleted":false,
            "complete_training_fidelity_certified":false,
        });
        save_checkpoint(&path, &result)?;
        self.require_reconstruction_receipt()?;
        self.require_all_verification()?;
        let checkpoint: LocatorCheckpoint = serde_json::from_reader(std::fs::File::open(
            self.checkpoint.with_extension("locators.json"),
        )?)?;
        if checkpoint.format_version != 1
            || checkpoint.owner_identity != self.identity
            || !checkpoint.complete
            || !checkpoint.verified
            || checkpoint.gap_rows != 0
        {
            return Err("complete verified locator inventory required for TEST cutover".into());
        }
        // Start from the first identity on every invocation. A committed CAS
        // locator is accepted on resume, but every target is reverified and
        // newly added or changed source rows still revoke completion.
        let mut cursor = LocatorCursor::default();
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        while let Some(located) = self.next_locator(&cursor).await? {
            let encoded = self
                .target
                .get_bounded(&receipt_key(&checkpoint.identity, &located.cursor)?, 16384)
                .await?;
            let receipt: LocatorReceipt = serde_json::from_slice(&encoded)?;
            if receipt.format_version != 1
                || receipt.identity != checkpoint.identity
                || receipt.cursor != located.cursor
                || receipt.gap_reason.is_some()
                || receipt.source_locator_md5.len() != 32
                || !receipt
                    .source_locator_md5
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(
                    "fresh locator receipt with conditional source identity required".into(),
                );
            }
            let object = receipt
                .object
                .ok_or("missing source body cannot authorize cutover")?;
            let tenant = Uuid::parse_str(&located.cursor.tenant)?;
            self.target.verify_tenant_content(tenant, &object).await?;
            if (located.source_locator_md5 != receipt.source_locator_md5
                && located.locator != object.object_locator)
                || located
                    .expected_digest
                    .as_ref()
                    .is_some_and(|digest| *digest != object.blake3_digest)
                || located
                    .expected_bytes
                    .is_some_and(|size| size != object.size_bytes)
            {
                return Err(
                    "locator or media index changed after verification; source retained".into(),
                );
            }
            if matches!(located.cursor.kind.as_str(), "request" | "response") {
                let root = self
                    .target
                    .raw_capture_reference(
                        tenant,
                        Uuid::parse_str(&located.cursor.identity)?,
                        &located.cursor.kind,
                    )
                    .await?
                    .ok_or("verified raw root required before locator cutover")?;
                if serde_json::to_value(root)? != serde_json::to_value(&object)? {
                    return Err("raw root differs from verified locator receipt".into());
                }
            }
            let (table, id, column) = located.cursor.columns()?;
            let media_guard = if located.cursor.kind == "media" {
                " AND content_blake3 = $5 AND byte_length = $6"
            } else {
                ""
            };
            let statement = format!(
                "UPDATE {table} SET {column} = $1 WHERE {id} = $2 AND tenant_id = $3 AND (md5({column}) = $4 OR {column} = $1){media_guard}"
            );
            let mut transaction = self.pool.begin().await?;
            let mut query = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(&object.object_locator)
                .bind(&located.cursor.identity)
                .bind(&located.cursor.tenant)
                .bind(&receipt.source_locator_md5);
            if located.cursor.kind == "media" {
                query = query
                    .bind(&object.blake3_digest)
                    .bind(i64::try_from(object.size_bytes)?);
            }
            if query.execute(&mut *transaction).await?.rows_affected() != 1 {
                transaction.rollback().await?;
                return Err(
                    "locator source identity changed or is ambiguous; source retained".into(),
                );
            }
            transaction.commit().await?;
            rows = rows
                .checked_add(1)
                .ok_or("locator cutover count overflow")?;
            bytes = bytes
                .checked_add(object.size_bytes)
                .ok_or("locator cutover byte overflow")?;
            cursor = located.cursor;
            result["rows"] = rows.into();
            result["bytes"] = bytes.into();
            result["cursor"] = serde_json::to_value(&cursor)?;
            save_checkpoint(&path, &result)?;
        }
        if rows != checkpoint.copied_rows || bytes != checkpoint.copied_bytes {
            return Err("locator cutover source/target count or byte mismatch".into());
        }
        result["complete"] = true.into();
        save_checkpoint(&path, &result)?;
        Ok(result)
    }

    pub(super) async fn verified_locator(
        &self,
        kind: &str,
        tenant: &str,
        identity: &str,
    ) -> Result<CasArchiveObject> {
        let checkpoint: LocatorCheckpoint = serde_json::from_reader(std::fs::File::open(
            self.checkpoint.with_extension("locators.json"),
        )?)?;
        if checkpoint.format_version != 1
            || checkpoint.owner_identity != self.identity
            || !checkpoint.complete
            || !checkpoint.verified
        {
            return Err("verified locator inventory required".into());
        }
        let cursor = LocatorCursor {
            kind: kind.into(),
            tenant: tenant.into(),
            identity: identity.into(),
        };
        let bytes = self
            .target
            .get_bounded(&receipt_key(&checkpoint.identity, &cursor)?, 16384)
            .await?;
        let receipt: LocatorReceipt = serde_json::from_slice(&bytes)?;
        if receipt.format_version != 1
            || receipt.cursor != cursor
            || receipt.identity != checkpoint.identity
        {
            return Err("locator receipt ownership mismatch".into());
        }
        let object = receipt
            .object
            .ok_or("locator receipt records a source gap")?;
        if receipt.gap_reason.is_some() {
            return Err("locator receipt records a source gap".into());
        }
        self.target
            .verify_tenant_content(Uuid::parse_str(tenant)?, &object)
            .await?;
        Ok(object)
    }

    pub(super) async fn transfer_locators(
        &self,
        target_config: &Config,
        verify: bool,
    ) -> Result<LocatorCheckpoint> {
        let source_config = source_config(target_config)?;
        let source = ArchiveStore::from_config(&source_config).await?;
        let identity = blake3::hash(&serde_json::to_vec(&(
            &self.identity,
            &source_config.s3_endpoint,
            &source_config.s3_bucket,
        ))?)
        .to_hex()
        .to_string();
        self.transfer_locators_from(&source, &identity, verify)
            .await
    }

    async fn next_locator(&self, after: &LocatorCursor) -> Result<Option<LocatedObject>> {
        let row = sqlx::query(
            "WITH sources AS (
             SELECT 'request' AS kind, tenant_id AS tenant, id AS identity, request_object AS locator, CAST(NULL AS TEXT) AS expected_digest, CAST(NULL AS BIGINT) AS expected_bytes FROM request_records
             UNION ALL SELECT 'response', tenant_id, id, response_object, NULL, NULL FROM request_records
             UNION ALL SELECT 'media', tenant_id, turn_id || ':' || part_index, object_locator, content_blake3, byte_length FROM conversation_media_parts
             UNION ALL SELECT 'import_request', tenant_id, json_build_array(source, external_request_id)::TEXT, request_object, NULL, NULL FROM session_archive_import_records
             UNION ALL SELECT 'import_response', tenant_id, json_build_array(source, external_request_id)::TEXT, response_object, NULL, NULL FROM session_archive_import_records
             UNION ALL SELECT 'import_previous_request', tenant_id, json_build_array(source, external_request_id)::TEXT, previous_request_object, NULL, NULL FROM session_archive_import_records
             UNION ALL SELECT 'import_previous_response', tenant_id, json_build_array(source, external_request_id)::TEXT, previous_response_object, NULL, NULL FROM session_archive_import_records
             UNION ALL SELECT 'unlinked_request', tenant_id, archive_request_id, request_object, NULL, NULL FROM session_archive_unlinked_requests
             UNION ALL SELECT 'unlinked_response', tenant_id, archive_request_id, response_object, NULL, NULL FROM session_archive_unlinked_requests
             UNION ALL SELECT 'quarantine_request', tenant_id, id, request_object, NULL, NULL FROM session_archive_quarantine_records
             UNION ALL SELECT 'quarantine_response', tenant_id, id, response_object, NULL, NULL FROM session_archive_quarantine_records
             UNION ALL SELECT 'quarantine_version_request', tenant_id, id, request_object, NULL, NULL FROM session_archive_quarantine_record_versions
             UNION ALL SELECT 'quarantine_version_response', tenant_id, id, response_object, NULL, NULL FROM session_archive_quarantine_record_versions
             ) SELECT kind, tenant, identity, left(locator, 4096) AS locator, md5(locator) AS source_locator_md5, expected_digest, expected_bytes FROM sources
             WHERE (kind, tenant, identity) > ($1, $2, $3)
               AND locator IS NOT NULL AND locator <> ''
             ORDER BY kind, tenant, identity LIMIT 1",
        )
        .bind(&after.kind).bind(&after.tenant).bind(&after.identity)
        .fetch_optional(&self.pool).await?;
        let Some(row) = row else { return Ok(None) };
        let cursor = LocatorCursor {
            kind: row.try_get("kind")?,
            tenant: row.try_get("tenant")?,
            identity: row.try_get("identity")?,
        };
        let locator: String = row.try_get("locator")?;
        let source_locator_blake3 = if locator.starts_with("inline-json:") {
            String::new()
        } else {
            if locator.len() >= 4096 {
                return Err("object locator exceeds the source metadata field".into());
            }
            blake3::hash(locator.as_bytes()).to_hex().to_string()
        };
        Ok(Some(LocatedObject {
            cursor,
            locator,
            source_locator_blake3,
            source_locator_md5: row.try_get("source_locator_md5")?,
            expected_digest: row.try_get("expected_digest")?,
            expected_bytes: row
                .try_get::<Option<i64>, _>("expected_bytes")?
                .map(u64::try_from)
                .transpose()?,
        }))
    }

    async fn copy_locator(
        &self,
        source: &ArchiveStore,
        located: &LocatedObject,
        copy: bool,
    ) -> Result<CasArchiveObject> {
        let tenant = Uuid::parse_str(&located.cursor.tenant)?;
        let key = format!(
            "migration-staging/conversation-v1/{}/{}",
            self.identity,
            Uuid::now_v7()
        );
        let compressed = located.locator.ends_with(".mtcz1");
        let mut writer = if !copy {
            None
        } else if compressed {
            Some(self.target.start_compressed_writer(&key).await?)
        } else {
            Some(self.target.start_writer(&key).await?)
        };
        let mut digest = blake3::Hasher::new();
        let mut total = 0_u64;
        if located.locator.starts_with("inline-json:") {
            let mut transaction = self.pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *transaction)
                .await?;
            let (table, id, column) = located.cursor.columns()?;
            let statement = format!(
                "SELECT substring({column} FROM $3 FOR 65536) FROM {table} WHERE {id} = $1 AND tenant_id = $2"
            );
            let mut position = 13_i32;
            loop {
                let text: String = sqlx::query_scalar(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(&located.cursor.identity)
                    .bind(&located.cursor.tenant)
                    .bind(position)
                    .fetch_one(&mut *transaction)
                    .await?;
                if text.is_empty() {
                    break;
                }
                position = position
                    .checked_add(i32::try_from(text.chars().count())?)
                    .ok_or("source text position overflow")?;
                total += text.len() as u64;
                digest.update(text.as_bytes());
                if let Some(writer) = &mut writer {
                    writer.write(Bytes::from(text)).await?;
                }
            }
            transaction.commit().await?;
        } else {
            let download = source.open_stream(&located.locator, None).await?;
            let expected = download.object_size;
            let mut stream = download.stream;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                total = total
                    .checked_add(chunk.len() as u64)
                    .ok_or("object byte count overflow")?;
                digest.update(&chunk);
                if let Some(writer) = &mut writer {
                    writer.write(chunk).await?;
                }
            }
            if total != expected {
                return Err("source object length mismatch".into());
            }
        }
        let digest = digest.finalize().to_hex().to_string();
        if located
            .expected_digest
            .as_ref()
            .is_some_and(|expected| *expected != digest)
            || located
                .expected_bytes
                .is_some_and(|expected| expected != total)
        {
            return Err("media hash or length differs from source index".into());
        }
        if located.locator.starts_with("tenants/") && located.locator.contains("/cas/v1/") {
            // A source CAS name is an integrity claim, not just a readable
            // locator. Reject wrong hash/tenant identity instead of silently
            // turning corrupted source bytes into a different target object.
            source
                .verify_tenant_content(
                    tenant,
                    &CasArchiveObject {
                        object_locator: located.locator.clone(),
                        blake3_digest: digest.clone(),
                        size_bytes: total,
                    },
                )
                .await?;
        }
        if let Some(writer) = writer {
            let staged = writer.finish_staged().await?;
            if staged.blake3_digest != digest || staged.size_bytes != total {
                return Err("destination stream differs from source".into());
            }
            let object = self
                .target
                .promote_staged_text_to_cas(tenant, &staged)
                .await?;
            self.target.delete(&staged.object_locator).await?;
            Ok(object)
        } else {
            Ok(CasArchiveObject {
                object_locator: format!(
                    "tenants/{tenant}/cas/v1/blake3/{}/{digest}{}",
                    &digest[..2],
                    if compressed { ".mtcz1" } else { "" }
                ),
                blake3_digest: digest,
                size_bytes: total,
            })
        }
    }

    pub(super) async fn transfer_locators_from(
        &self,
        source: &ArchiveStore,
        identity: &str,
        verify: bool,
    ) -> Result<LocatorCheckpoint> {
        let checkpoint_path = self.checkpoint.with_extension("locators.json");
        let mut checkpoint = match std::fs::File::open(&checkpoint_path) {
            Ok(file) => serde_json::from_reader::<_, LocatorCheckpoint>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => LocatorCheckpoint {
                format_version: 1,
                identity: identity.into(),
                owner_identity: self.identity.clone(),
                ..Default::default()
            },
            Err(error) => return Err(error.into()),
        };
        if checkpoint.format_version != 1
            || checkpoint.identity != identity
            || checkpoint.owner_identity != self.identity
        {
            return Err("locator checkpoint belongs to another source/target".into());
        }
        if verify && !checkpoint.complete {
            return Err("locator verification requires completed copy".into());
        }
        if !verify && checkpoint.complete {
            return Ok(checkpoint);
        }
        if verify {
            checkpoint.verified = false;
            save(&checkpoint_path, &checkpoint)?;
        }
        let mut result = if verify {
            LocatorCheckpoint {
                format_version: 1,
                identity: identity.into(),
                owner_identity: self.identity.clone(),
                ..Default::default()
            }
        } else {
            checkpoint.clone()
        };
        while let Some(located) = self.next_locator(&result.cursor).await? {
            // Declared historical gaps are evidence, not an instruction to
            // stop copying later readable objects. Never fabricate their body.
            let gap_reason = if located.locator.starts_with("gap://") {
                Some("source_gap")
            } else if located.locator.starts_with("metadata-only-json:") {
                Some("source_metadata_only")
            } else if located.locator.starts_with("provider-reference-json:") {
                Some("source_provider_reference_unresolved")
            } else {
                None
            };
            let object = if gap_reason.is_some() {
                None
            } else {
                Some(self.copy_locator(source, &located, !verify).await?)
            };
            let receipt = LocatorReceipt {
                format_version: 1,
                identity: identity.into(),
                cursor: located.cursor.clone(),
                source_locator_blake3: located.source_locator_blake3,
                source_locator_md5: located.source_locator_md5,
                object,
                gap_reason: gap_reason.map(str::to_owned),
            };
            let key = receipt_key(identity, &located.cursor)?;
            let encoded = serde_json::to_vec(&receipt)?;
            if !verify {
                self.target.put(&key, Bytes::from(encoded.clone())).await?;
            }
            let actual = self.target.get_bounded(&key, 16384).await?;
            let actual: LocatorReceipt = serde_json::from_slice(&actual)?;
            if serde_json::to_vec(&actual)? != encoded {
                return Err("locator receipt/source changed".into());
            }
            if let Some(object) = &receipt.object {
                self.target
                    .verify_tenant_content(Uuid::parse_str(&located.cursor.tenant)?, object)
                    .await?;
                if verify && matches!(located.cursor.kind.as_str(), "request" | "response") {
                    self.target
                        .publish_raw_capture(
                            Uuid::parse_str(&located.cursor.tenant)?,
                            Uuid::parse_str(&located.cursor.identity)?,
                            &located.cursor.kind,
                            object,
                        )
                        .await?;
                }
                result.copied_rows += 1;
                result.copied_bytes += object.size_bytes;
            } else {
                result.gap_rows += 1;
            }
            let mut digest = blake3::Hasher::new();
            digest.update(result.digest.as_bytes());
            digest.update(&encoded);
            result.digest = digest.finalize().to_hex().to_string();
            result.cursor = located.cursor;
            if !verify {
                save(&checkpoint_path, &result)?;
            }
        }
        if verify {
            if result.copied_rows != checkpoint.copied_rows
                || result.copied_bytes != checkpoint.copied_bytes
                || result.digest != checkpoint.digest
                || result.gap_rows != checkpoint.gap_rows
            {
                return Err("locator count/byte/order digest mismatch".into());
            }
            result.verified = result.gap_rows == 0;
        }
        result.complete = true;
        save(&checkpoint_path, &result)?;
        if verify && result.gap_rows != 0 {
            return Err(
                "source gap receipts retained; full locator verification cannot be certified"
                    .into(),
            );
        }
        Ok(result)
    }
}
