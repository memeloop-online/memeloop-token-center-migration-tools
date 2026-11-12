//! Online PG body offload from already committed immutable copy receipts.
//! Object verification happens outside the short source-row transaction.
use super::*;

#[path = "semantic_reference_readback.rs"]
mod readback;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SourceVersion {
    tenant_id: String,
    request_id: String,
    key_id: String,
    principal_id: String,
    format_version: i64,
    encoded_bytes: i64,
    semantic_digest: String,
    stored_md5: String,
    stored_bytes: i64,
    reference: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceAudit {
    format_version: u32,
    source_target_identity: String,
    training_identity: String,
    copy_receipt_digest: String,
    source: SourceVersion,
    new_reference: String,
    status: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceProgress {
    format_version: u32,
    identity: String,
    training_identity: String,
    ledgers: Vec<PathBuf>,
    apply: bool,
    after: Option<PathBuf>,
    visited: u64,
    applied: u64,
    eligible: u64,
    skipped: u64,
    already_referenced: u64,
    original_bytes_referenced: u64,
}

fn training_identity(config: &Config) -> Result<String> {
    if config.archive_backend != memeloop_token_center::config::ArchiveBackend::S3 {
        return Err("semantic references require the actual training S3 target".into());
    }
    let endpoint = config
        .s3_endpoint
        .as_ref()
        .ok_or("training S3 endpoint missing")?;
    let bucket = config
        .s3_bucket
        .as_ref()
        .ok_or("training S3 bucket missing")?;
    Ok(blake3::hash(&serde_json::to_vec(&(
        "mtc-training-s3-v1",
        endpoint,
        bucket,
        &config.s3_region,
    ))?)
    .to_hex()
    .to_string())
}

fn qualified_reference(receipt: &PayloadReceipt, identity: &str) -> Result<String> {
    let mut reference = receipt.reference.clone();
    if !reference
        .conversation_body_v1
        .object_locator
        .starts_with("tenants/")
    {
        return Err("copy receipt must contain the original immutable tenant CAS key".into());
    }
    reference.conversation_body_v1.object_locator = format!(
        "stores/training/{identity}/{}",
        reference.conversation_body_v1.object_locator,
    );
    Ok(serde_json::to_string(&reference)?)
}

async fn source_version<'e, E: sqlx::Executor<'e, Database = sqlx::Postgres>>(
    executor: E,
    cursor: &Cursor,
    lock: bool,
) -> Result<Option<SourceVersion>> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT tenant_id, request_id, key_id, principal_id, format_version, encoded_bytes, digest, md5(request_json) AS stored_md5, octet_length(request_json)::bigint AS stored_bytes, CASE WHEN format_version=2 THEN request_json ELSE NULL END AS reference FROM conversation_semantic_payloads WHERE request_id=$1 AND tenant_id=$2{suffix}"
    );
    // The only SQL fragment is the fixed FOR UPDATE suffix above; all row
    // identities remain bound values. No input is interpolated into SQL.
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(&cursor.content_hash)
        .bind(&cursor.tenant_id)
        .fetch_optional(executor)
        .await?;
    row.map(|row| {
        Ok(SourceVersion {
            tenant_id: row.try_get("tenant_id")?,
            request_id: row.try_get("request_id")?,
            key_id: row.try_get("key_id")?,
            principal_id: row.try_get("principal_id")?,
            format_version: row.try_get("format_version")?,
            encoded_bytes: row.try_get("encoded_bytes")?,
            semantic_digest: row.try_get("digest")?,
            stored_md5: row.try_get("stored_md5")?,
            stored_bytes: row.try_get("stored_bytes")?,
            reference: row.try_get("reference")?,
        })
    })
    .transpose()
}

fn expected_reference(row: &SourceVersion, reference: &str, original: &SourceVersion) -> bool {
    row.format_version == 2
        && row.reference.as_deref() == Some(reference)
        && row.tenant_id == original.tenant_id
        && row.request_id == original.request_id
        && row.key_id == original.key_id
        && row.principal_id == original.principal_id
        && row.encoded_bytes == original.encoded_bytes
        && row.semantic_digest == original.semantic_digest
}

impl Runner {
    pub(crate) fn externalize_semantic_payloads<'a>(
        &'a self,
        config: &'a Config,
        ledgers: &'a [PathBuf],
        batch: usize,
        apply: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        Box::pin(self.externalize_semantic_payloads_inner(config, ledgers, batch, apply))
    }

    async fn externalize_semantic_payloads_inner(
        &self,
        config: &Config,
        ledgers: &[PathBuf],
        batch: usize,
        apply: bool,
    ) -> Result<serde_json::Value> {
        let training = training_identity(config)?;
        let mut ledgers = ledgers
            .iter()
            .map(std::fs::canonicalize)
            .collect::<std::io::Result<Vec<_>>>()?;
        ledgers.sort();
        ledgers.dedup();
        let progress_path = self
            .checkpoint
            .with_extension("semantic-reference-progress.json");
        let mut progress = match std::fs::File::open(&progress_path) {
            Ok(file) => serde_json::from_reader::<_, ReferenceProgress>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ReferenceProgress {
                format_version: 1,
                identity: self.identity.clone(),
                training_identity: training.clone(),
                ledgers: ledgers.clone(),
                apply,
                ..Default::default()
            },
            Err(error) => return Err(error.into()),
        };
        if progress.format_version != 1
            || progress.identity != self.identity
            || progress.training_identity != training
            || progress.ledgers != ledgers
            || progress.apply != apply
        {
            return Err("semantic reference checkpoint identity/mode mismatch".into());
        }
        let audits = self.checkpoint.with_extension("semantic-reference-audit");
        if apply {
            std::fs::create_dir_all(&audits)?;
        }
        // Copy writers publish immutable .json receipts by atomic rename. Reading
        // the committed filename snapshot never locks or modifies their ledgers.
        let mut paths = Vec::new();
        for ledger in &ledgers {
            for entry in std::fs::read_dir(ledger)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && progress.after.as_ref().is_none_or(|after| &path > after)
                {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        let snapshot_candidates = paths.len();
        for path in paths.into_iter().take(batch) {
            let (receipt, encoded, receipt_digest) = self.read_online_receipt(&path)?;
            if receipt.field != SourceField::SemanticPayload {
                progress.skipped += 1;
            } else {
                let cursor = &receipt.cursor;
                if Uuid::parse_str(&cursor.content_hash)?.to_string() != cursor.content_hash {
                    return Err("noncanonical semantic request identity".into());
                }
                let reference = qualified_reference(&receipt, &training)?;
                let current = source_version(&self.pool, cursor, false).await?;
                let outcome = if let Some(current) = current {
                    if current.format_version == 2
                        && current.reference.as_deref() == Some(&reference)
                    {
                        // A replay/commit-unknown recovery still validates its immutable archive.
                        self.verify_semantic_archive(&receipt, &encoded, &receipt_digest, &current)
                            .await?;
                        if apply {
                            self.recover_reference_audit(
                                &current,
                                &reference,
                                &receipt_digest,
                                &training,
                                &audits,
                            )?;
                        }
                        "already"
                    } else if current.format_version != 1
                        || current.stored_md5 != receipt.source_md5
                        || current.stored_bytes != current.encoded_bytes
                        || u64::try_from(current.encoded_bytes).ok()
                            != Some(receipt.reference.conversation_body_v1.size_bytes)
                    {
                        "skipped"
                    } else {
                        self.verify_semantic_archive(&receipt, &encoded, &receipt_digest, &current)
                            .await?;
                        if !apply {
                            "eligible"
                        } else {
                            self.apply_semantic_reference(
                                &receipt,
                                &receipt_digest,
                                &training,
                                &current,
                                &reference,
                                &audits,
                            )
                            .await?
                        }
                    }
                } else {
                    "skipped"
                };
                match outcome {
                    "applied" => {
                        progress.applied += 1;
                        progress.original_bytes_referenced +=
                            receipt.reference.conversation_body_v1.size_bytes;
                    }
                    "eligible" => progress.eligible += 1,
                    "already" => progress.already_referenced += 1,
                    _ => progress.skipped += 1,
                }
            }
            progress.visited += 1;
            progress.after = Some(path);
            save_checkpoint(&progress_path, &progress)?;
        }
        Ok(serde_json::json!({
            "phase":"semantic_payload_references", "apply":apply,
            "visited":progress.visited,"eligible":progress.eligible,"applied":progress.applied,
            "skipped":progress.skipped,"already_referenced":progress.already_referenced,
            "original_bytes_referenced":progress.original_bytes_referenced,
            "snapshot_remaining":snapshot_candidates.saturating_sub(batch),
            "source_verified":false,"source_deleted":false,"outbox_changed":false,
            "requires_compatible_reader_deployment":true,
            "new_receipts_behind_cursor_require_new_pass":true,
        }))
    }

    async fn verify_semantic_archive(
        &self,
        receipt: &PayloadReceipt,
        encoded: &[u8],
        receipt_digest: &str,
        source: &SourceVersion,
    ) -> Result<()> {
        let object = &receipt.reference.conversation_body_v1;
        let mut stream = self
            .target
            .open_tenant_content(Uuid::parse_str(&source.tenant_id)?, object)
            .await?
            .stream;
        let mut semantic = blake3::Hasher::new_derive_key("MTC conversation semantic payload v1");
        for value in [
            &source.request_id,
            &source.tenant_id,
            &source.key_id,
            &source.principal_id,
        ] {
            semantic.update(&(value.len() as u64).to_le_bytes());
            semantic.update(value.as_bytes());
        }
        semantic.update(&(source.encoded_bytes as u64).to_le_bytes());
        let mut bytes = 0_u64;
        let mut chars = 0_u64;
        let mut utf8_tail = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or("semantic archive size overflow")?;
            if bytes > object.size_bytes {
                return Err("semantic archive size mismatch".into());
            }
            semantic.update(&chunk);
            for part in chunk.chunks(64 * 1024) {
                utf8_tail.extend_from_slice(part);
                let valid = match std::str::from_utf8(&utf8_tail) {
                    Ok(text) => text.len(),
                    Err(error) if error.error_len().is_none() => error.valid_up_to(),
                    Err(_) => return Err("semantic archive is not UTF-8".into()),
                };
                chars = chars
                    .checked_add(std::str::from_utf8(&utf8_tail[..valid])?.chars().count() as u64)
                    .ok_or("semantic archive character overflow")?;
                utf8_tail.drain(..valid);
            }
        }
        if !utf8_tail.is_empty()
            || chars != receipt.reference.chars
            || u64::try_from(source.encoded_bytes).ok() != Some(object.size_bytes)
            || bytes != object.size_bytes
            || semantic.finalize().to_hex().as_str() != source.semantic_digest
        {
            return Err("semantic archive original digest mismatch".into());
        }
        // Read only the immutable published receipt after full target readback.
        let key = format!(
            "migration-receipts/conversation-v1/{}/online-payloads/{receipt_digest}.json",
            self.identity
        );
        if self.target.get_bounded(&key, 16384).await?.as_ref() != encoded {
            return Err("semantic archive immutable receipt mismatch".into());
        }
        Ok(())
    }

    fn recover_reference_audit(
        &self,
        current: &SourceVersion,
        reference: &str,
        receipt_digest: &str,
        training: &str,
        audits: &std::path::Path,
    ) -> Result<()> {
        let pending = audits.join(format!("{receipt_digest}.pending"));
        match std::fs::File::open(&pending) {
            Ok(file) => {
                let mut audit: ReferenceAudit = serde_json::from_reader(file)?;
                if audit.format_version != 1
                    || audit.source_target_identity != self.identity
                    || audit.training_identity != training
                    || audit.copy_receipt_digest != receipt_digest
                    || audit.new_reference != reference
                    || !expected_reference(current, reference, &audit.source)
                {
                    return Err("semantic prepared audit identity mismatch".into());
                }
                audit.status = "committed_confirmed_by_reread".into();
                save_checkpoint(&audits.join(format!("{receipt_digest}.json")), &audit)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn apply_semantic_reference(
        &self,
        receipt: &PayloadReceipt,
        receipt_digest: &str,
        training: &str,
        source: &SourceVersion,
        reference: &str,
        audits: &std::path::Path,
    ) -> Result<&'static str> {
        let pending = audits.join(format!("{receipt_digest}.pending"));
        let committed = audits.join(format!("{receipt_digest}.json"));
        let mut audit = ReferenceAudit {
            format_version: 1,
            source_target_identity: self.identity.clone(),
            training_identity: training.to_owned(),
            copy_receipt_digest: receipt_digest.to_owned(),
            source: source.clone(),
            new_reference: reference.to_owned(),
            status: "prepared".into(),
        };
        match std::fs::File::open(&pending) {
            Ok(file) => {
                let previous: ReferenceAudit = serde_json::from_reader(file)?;
                if previous.format_version != audit.format_version
                    || previous.source_target_identity != audit.source_target_identity
                    || previous.training_identity != audit.training_identity
                    || previous.copy_receipt_digest != audit.copy_receipt_digest
                    || previous.source != audit.source
                    || previous.new_reference != audit.new_reference
                {
                    return Err("prepared source version changed; retain audit and use a new pass checkpoint".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                save_checkpoint(&pending, &audit)?
            }
            Err(error) => return Err(error.into()),
        }
        let mut tx = self.pool.begin().await?;
        let locked = source_version(&mut *tx, &receipt.cursor, true).await?;
        if locked.as_ref() != Some(source) {
            tx.rollback().await?;
            audit.status = "skipped_source_changed".into();
            save_checkpoint(&committed, &audit)?;
            return Ok("skipped");
        }
        let result = sqlx::query("UPDATE conversation_semantic_payloads SET format_version=2, request_json=$1 WHERE request_id=$2 AND tenant_id=$3 AND format_version=1")
            .bind(reference).bind(&source.request_id).bind(&source.tenant_id).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err("semantic source CAS did not update exactly one row".into());
        }
        if tx.commit().await.is_err() {
            // A transport failure can hide a successful COMMIT. Re-read rather
            // than resubmit, delete original data or manufacture a success.
            let actual = source_version(&self.pool, &receipt.cursor, false).await?;
            if !actual
                .as_ref()
                .is_some_and(|row| expected_reference(row, reference, source))
            {
                return Err("semantic reference commit outcome unknown; audit retained".into());
            }
        }
        audit.status = "committed".into();
        save_checkpoint(&committed, &audit)?;
        // Keep the prepared record as recovery evidence as well as the final receipt.
        Ok("applied")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::{ObjectStoreExt, PutPayload};

    #[tokio::test]
    async fn semantic_reference_apply_preserves_identity_and_skips_changed_sources() {
        let database_url = std::env::var("MTC_TEST_POSTGRES_URL").unwrap();
        let admin = PgPool::connect(&database_url).await.unwrap();
        let name = format!("semantic_refs_{}", Uuid::now_v7().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&database_url).unwrap();
        url.set_path(&name);
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        sqlx::raw_sql("CREATE TABLE conversation_semantic_payloads(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, principal_id TEXT NOT NULL, format_version BIGINT NOT NULL CHECK(format_version IN(1,2)), encoded_bytes BIGINT NOT NULL, digest TEXT NOT NULL, request_json TEXT NOT NULL);
            CREATE TABLE conversation_projection_outbox(request_id TEXT PRIMARY KEY, request_json TEXT NOT NULL);").execute(&pool).await.unwrap();
        let mut config = Config::for_test(url.to_string());
        config.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
        config.s3_endpoint = Some(std::env::var("MTC_RUSTFS_TEST_ENDPOINT").unwrap());
        config.s3_bucket = Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").unwrap());
        config.s3_access_key = Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").unwrap());
        config.s3_secret_key = Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").unwrap());
        config.s3_region = "us-east-1".into();
        config.s3_allow_http = true;
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts");
        std::fs::create_dir(&ledger).unwrap();
        let mut runner = Runner {
            pool: pool.clone(),
            source: None,
            target: ArchiveStore::from_config(&config).await.unwrap(),
            checkpoint: directory.path().join("dry.json"),
            identity: "semantic-reference-contract".into(),
        };
        let tenant = Uuid::now_v7();
        let mut versions = Vec::new();
        for changed in [false, true, false] {
            let request = Uuid::now_v7();
            let key = Uuid::now_v7();
            let principal = Uuid::now_v7();
            let body = serde_json::json!({"messages":[{"role":"user","content":"工具原文🙂".repeat(20000)}],"changed":changed}).to_string();
            let mut digest = blake3::Hasher::new_derive_key("MTC conversation semantic payload v1");
            for part in [
                request.to_string(),
                tenant.to_string(),
                key.to_string(),
                principal.to_string(),
                body.clone(),
            ] {
                digest.update(&(part.len() as u64).to_le_bytes());
                digest.update(part.as_bytes());
            }
            sqlx::query(
                "INSERT INTO conversation_semantic_payloads VALUES($1,$2,$3,$4,1,$5,$6,$7)",
            )
            .bind(request.to_string())
            .bind(tenant.to_string())
            .bind(key.to_string())
            .bind(principal.to_string())
            .bind(body.len() as i64)
            .bind(digest.finalize().to_hex().to_string())
            .bind(&body)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO conversation_projection_outbox VALUES($1,$2)")
                .bind(request.to_string())
                .bind(&body)
                .execute(&pool)
                .await
                .unwrap();
            let cursor = Cursor {
                tenant_id: tenant.to_string(),
                content_hash: request.to_string(),
            };
            let original = source_version(&pool, &cursor, false)
                .await
                .unwrap()
                .unwrap();
            let object = runner
                .target
                .put_tenant_content(tenant, Bytes::from(body.clone()))
                .await
                .unwrap();
            let receipt = PayloadReceipt {
                format_version: 1,
                identity: runner.identity.clone(),
                field: SourceField::SemanticPayload,
                cursor: cursor.clone(),
                source_md5: original.stored_md5.clone(),
                reference: ConversationBodyReference {
                    conversation_body_v1: object,
                    chars: body.chars().count() as u64,
                },
            };
            let encoded = serde_json::to_vec(&receipt).unwrap();
            let receipt_id = blake3::hash(&encoded).to_hex().to_string();
            runner
                .publish_online_payload_receipt(&receipt, &encoded, &receipt_id, true)
                .await
                .unwrap();
            save_checkpoint(&ledger.join(format!("{receipt_id}.json")), &receipt).unwrap();
            if changed {
                sqlx::query("UPDATE conversation_semantic_payloads SET request_json='{}', encoded_bytes=2 WHERE request_id=$1").bind(request.to_string()).execute(&pool).await.unwrap();
            }
            versions.push((receipt, receipt_id, original, body));
        }
        let ledgers = vec![ledger.clone()];
        let dry = runner
            .externalize_semantic_payloads(&config, &ledgers, 32, false)
            .await
            .unwrap();
        assert_eq!(dry["eligible"], 2);
        assert_eq!(dry["skipped"], 1);
        let v1: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conversation_semantic_payloads WHERE format_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(v1, 3);
        runner.checkpoint = directory.path().join("apply.json");
        let applied = runner
            .externalize_semantic_payloads(&config, &ledgers, 32, true)
            .await
            .unwrap();
        assert_eq!(applied["applied"], 2);
        assert_eq!(applied["skipped"], 1);
        let (receipt, id, original, body) = &versions[0];
        let current = source_version(&pool, &receipt.cursor, false)
            .await
            .unwrap()
            .unwrap();
        let reference = qualified_reference(receipt, &training_identity(&config).unwrap()).unwrap();
        assert!(expected_reference(&current, &reference, original));
        let outbox: String = sqlx::query_scalar(
            "SELECT request_json FROM conversation_projection_outbox WHERE request_id=$1",
        )
        .bind(&receipt.cursor.content_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(&outbox, body);
        // Simulate a committed transaction whose final audit/progress fsync was
        // interrupted. Re-read must confirm the row rather than reapply it.
        let audit_dir = runner.checkpoint.with_extension("semantic-reference-audit");
        std::fs::remove_file(audit_dir.join(format!("{id}.json"))).unwrap();
        std::fs::remove_file(
            runner
                .checkpoint
                .with_extension("semantic-reference-progress.json"),
        )
        .unwrap();
        let replay = runner
            .externalize_semantic_payloads(&config, &ledgers, 32, true)
            .await
            .unwrap();
        assert_eq!(replay["already_referenced"], 2);
        assert_eq!(replay["applied"], 0);
        let audit: ReferenceAudit = serde_json::from_reader(
            std::fs::File::open(audit_dir.join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(audit.status, "committed_confirmed_by_reread");
        assert_eq!(std::fs::read_dir(&ledger).unwrap().count(), 3);
        // Two different request identities share one object. One object stream
        // must satisfy both independently framed semantic digests.
        runner.checkpoint = directory.path().join("readback.json");
        let audit_dirs = vec![audit_dir.clone()];
        let readback = runner
            .readback_semantic_references(&config, &ledgers, &audit_dirs, 32)
            .await
            .unwrap();
        assert_eq!(readback["objects_read"], 1);
        assert_eq!(readback["rows_proven"], 2);
        assert_eq!(readback["bytes_read"], body.len() as u64);
        assert_eq!(readback["gc_authorized"], false);
        assert_eq!(readback["source_writers_quiesced"], false);
        let proof_dir = runner.checkpoint.with_extension("semantic-readback-proofs");
        let proof_path = std::fs::read_dir(&proof_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let previous = std::fs::read(&proof_path).unwrap();
        let replay = runner
            .readback_semantic_references(&config, &ledgers, &audit_dirs, 32)
            .await
            .unwrap();
        assert_eq!(replay["objects_read"], 1);
        assert_eq!(
            std::fs::read(&proof_path).unwrap(),
            previous,
            "no cached-proof timestamp refresh"
        );
        let mut wrong = config.clone();
        wrong.s3_region = "different-region".into();
        assert!(
            runner
                .readback_semantic_references(&wrong, &ledgers, &audit_dirs, 32)
                .await
                .is_err()
        );

        // An actual bad object invalidates the whole group and publishes no proof.
        let object = &receipt.reference.conversation_body_v1;
        // Fault injection uses the isolated TEST object store directly. The
        // production ArchiveStore correctly forbids overwriting immutable CAS.
        let fixture_store = object_store::aws::AmazonS3Builder::new()
            .with_endpoint(config.s3_endpoint.as_ref().unwrap())
            .with_bucket_name(config.s3_bucket.as_ref().unwrap())
            .with_region(&config.s3_region)
            .with_access_key_id(config.s3_access_key.as_ref().unwrap())
            .with_secret_access_key(config.s3_secret_key.as_ref().unwrap())
            .with_allow_http(true)
            .build()
            .unwrap();
        let fixture_path = object_store::path::Path::from(object.object_locator.as_str());
        fixture_store
            .put(
                &fixture_path,
                PutPayload::from_bytes(Bytes::from_static(b"corrupt")),
            )
            .await
            .unwrap();
        runner.checkpoint = directory.path().join("corrupt-readback.json");
        assert!(
            runner
                .readback_semantic_references(&config, &ledgers, &audit_dirs, 32)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_dir(runner.checkpoint.with_extension("semantic-readback-proofs"))
                .unwrap()
                .count(),
            0
        );
        fixture_store
            .put(
                &fixture_path,
                PutPayload::from_bytes(Bytes::copy_from_slice(body.as_bytes())),
            )
            .await
            .unwrap();

        // Hold one real source row until readback reaches FOR SHARE, then change
        // its identity. The final locked read must defer this row, not attest it.
        let mut held = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT request_id FROM conversation_semantic_payloads WHERE request_id=$1 FOR UPDATE",
        )
        .bind(&receipt.cursor.content_hash)
        .fetch_one(&mut *held)
        .await
        .unwrap();
        runner.checkpoint = directory.path().join("race-readback.json");
        let verify =
            Box::pin(runner.readback_semantic_references(&config, &ledgers, &audit_dirs, 32));
        let change = Box::pin(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE '%FOR SHARE%')")
                        .bind(&name).fetch_one(&pool).await.unwrap();
                    if blocked { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.unwrap();
            sqlx::query("UPDATE conversation_semantic_payloads SET key_id=$1 WHERE request_id=$2")
                .bind(Uuid::now_v7().to_string())
                .bind(&receipt.cursor.content_hash)
                .execute(&mut *held)
                .await
                .unwrap();
            held.commit().await.unwrap();
        });
        let (result, ()) = tokio::join!(verify, change);
        let result = result.unwrap();
        assert_eq!(result["objects_read"], 1);
        assert_eq!(result["rows_proven"], 1);
        assert_eq!(result["rows_deferred"], 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM conversation_semantic_payloads WHERE format_version=2"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );
        // A source changed between readback and row locking is never replaced.
        let audits = directory.path().join("race-audits");
        std::fs::create_dir(&audits).unwrap();
        let (changed, id, old, _) = &versions[1];
        assert_eq!(
            runner
                .apply_semantic_reference(
                    changed,
                    id,
                    &training_identity(&config).unwrap(),
                    old,
                    &qualified_reference(changed, &training_identity(&config).unwrap()).unwrap(),
                    &audits
                )
                .await
                .unwrap(),
            "skipped"
        );
        // Priority copying must not read the outbox at all (this fixture's
        // outbox intentionally lacks the other all-fields source columns).
        let (valid_receipt, _, valid_source, valid_body) = &versions[1];
        sqlx::query("UPDATE conversation_semantic_payloads SET request_json=$1, encoded_bytes=$2, digest=$3 WHERE request_id=$4")
            .bind(valid_body).bind(valid_source.encoded_bytes).bind(&valid_source.semantic_digest)
            .bind(&valid_receipt.cursor.content_hash).execute(&pool).await.unwrap();
        let mut ignored = versions[0].0.clone();
        ignored.field = SourceField::OutboxRequest;
        let ignored_bytes = serde_json::to_vec(&ignored).unwrap();
        let ignored_digest = blake3::hash(&ignored_bytes).to_hex().to_string();
        // No remote receipt is published: this out-of-scope record must never
        // be imported, verified remotely or counted as migrated.
        save_checkpoint(&ledger.join(format!("{ignored_digest}.json")), &ignored).unwrap();
        runner.checkpoint = directory.path().join("priority-semantic.json");
        let plan = OnlinePlan::new(1, 0).unwrap();
        let priority = runner
            .copy_payloads_online_partition_filtered(plan, Some(&ledger), true)
            .await
            .unwrap();
        assert_eq!(priority["rows_observed"], 1);
        assert_eq!(priority["versions_reused_without_upload"], 1);
        assert_eq!(priority["external_semantic_references_retained"], 2);
        assert_eq!(priority["fields"], serde_json::json!(["semantic_payload"]));
        assert_eq!(priority["source_verified"], false);
        assert_eq!(priority["source_writers_quiesced"], false);
        let layout: serde_json::Value = serde_json::from_reader(
            std::fs::File::open(runner.checkpoint.with_extension("online-layout.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(layout["fields"], serde_json::json!(["semantic_payload"]));
        let scoped = runner.checkpoint.with_extension("online-payload-receipts");
        assert_eq!(std::fs::read_dir(&scoped).unwrap().count(), 3);
        // Same source/target and partition do not permit reinterpreting the
        // priority checkpoint as all-fields, or mixing a foreign field in it.
        let mismatch = runner
            .copy_payloads_online_partition(plan, None)
            .await
            .unwrap_err();
        assert!(mismatch.to_string().contains("layout mismatch"));
        save_checkpoint(&scoped.join(format!("{ignored_digest}.json")), &ignored).unwrap();
        let mismatch = runner
            .copy_payloads_online_partition_filtered(plan, None, true)
            .await
            .unwrap_err();
        assert!(mismatch.to_string().contains("bound online scope"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM conversation_semantic_payloads WHERE format_version=2"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
