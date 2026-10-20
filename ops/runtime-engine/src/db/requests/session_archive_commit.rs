use super::super::*;

pub struct SessionArchiveUnlinkedMetadata<'a> {
    pub source_completed_at: Option<i64>,
    pub protocol: &'a str,
    pub model: &'a str,
    pub status_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub error_code: Option<&'a str>,
}

pub struct SessionArchiveCommitInput<'a> {
    pub tenant_external_id: &'a str,
    pub archive_source: &'a str,
    pub external_request_id: &'a str,
    pub source_session_id: &'a str,
    pub target: &'a SessionArchiveTarget,
    pub record_digest: &'a str,
    pub request_digest: Option<&'a str>,
    pub response_digest: Option<&'a str>,
    pub request_object: Option<&'a str>,
    pub response_object: Option<&'a str>,
    pub request_json: Option<&'a serde_json::Value>,
    pub conversation_hints: &'a ConversationHints,
    pub client_name: Option<&'a str>,
    pub source_started_at: i64,
    /// The source completion time. `None` is accepted only for legacy/direct
    /// callers and makes the checkpoint cursor fall back to `source_started_at`.
    pub source_completed_at: Option<i64>,
    pub identity_proof_kind: &'a str,
    pub identity_proof_digest: &'a str,
    pub correlation_proof_digest: &'a str,
    pub defer_checkpoint: bool,
}

pub struct SessionArchiveUnlinkedCommitInput<'a> {
    pub tenant_external_id: &'a str,
    pub archive_source: &'a str,
    pub external_request_id: &'a str,
    pub source_session_id: &'a str,
    pub target: &'a SessionArchiveUnlinkedTarget,
    pub record_digest: &'a str,
    pub request_digest: Option<&'a str>,
    pub response_digest: Option<&'a str>,
    pub request_object: Option<&'a str>,
    pub response_object: Option<&'a str>,
    pub request_json: Option<&'a serde_json::Value>,
    pub conversation_hints: &'a ConversationHints,
    pub client_name: Option<&'a str>,
    pub source_started_at: i64,
    pub metadata: SessionArchiveUnlinkedMetadata<'a>,
    pub defer_checkpoint: bool,
}

#[derive(Clone, Debug)]
pub struct SessionArchiveTombstoneInput {
    pub source_session_id: String,
    pub deleted_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct SessionArchivePresentSummaryInput {
    pub source_session_id: String,
    pub requests: i64,
    pub first_at_ms: i64,
    pub last_at_ms: i64,
    pub records_sha256: String,
}

pub struct SessionArchiveSnapshotApplyInput<'a> {
    pub tenant_external_id: &'a str,
    pub archive_source: &'a str,
    pub source_fingerprint: &'a str,
    pub sequence: i64,
    pub offline_full_snapshot: bool,
    pub output_sha256: &'a str,
    pub prior_output_sha256: Option<&'a str>,
    pub prior_source_ingest_fence: Option<i64>,
    pub snapshot_schema_version: i64,
    pub ingest_fence: i64,
    pub tombstone_safe_after_ingest_fence: Option<i64>,
    pub session_set_sha256: &'a str,
    pub session_count: i64,
    pub request_count: i64,
    pub deleted_session_count: i64,
    pub legacy_checkpoint: Option<SessionArchiveLegacyCheckpointInput<'a>>,
    pub staged_batch_id: Option<&'a str>,
    pub present_summaries: &'a [SessionArchivePresentSummaryInput],
    pub tombstones: &'a [SessionArchiveTombstoneInput],
}

pub struct SessionArchiveLegacyCheckpointInput<'a> {
    pub watermark_ms: i64,
    pub watermark_request_id: &'a str,
    pub imported_records: i64,
}

pub struct SessionArchiveSnapshotChainInput<'a> {
    pub tenant_external_id: &'a str,
    pub archive_source: &'a str,
    pub source_fingerprint: &'a str,
    pub sequence: i64,
    pub offline_full_snapshot: bool,
    pub output_sha256: &'a str,
    pub prior_output_sha256: Option<&'a str>,
    pub prior_source_ingest_fence: Option<i64>,
    pub snapshot_schema_version: i64,
    pub ingest_fence: i64,
    pub tombstone_safe_after_ingest_fence: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct SessionArchiveSnapshotApplyResult {
    pub replayed: bool,
    pub tombstones_applied: u64,
    pub tombstones_replayed: u64,
    pub deleted_records: u64,
}

impl Database {
    pub(crate) async fn reconcile_staged_session_archive_projection_in_transaction(
        &self,
        tx: &mut Transaction<'_, Any>,
        tenant_external_id: &str,
        archive_source: &str,
        batch_id: &str,
    ) -> Result<u64, AppError> {
        let tenant_id: String = sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
            .bind(tenant_external_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AppError::NotFound)?;
        let mut retired = 0_u64;
        loop {
            let rows = sqlx::query("SELECT imported.external_request_id,imported.target_request_id,imported.request_object,imported.response_object,imported.previous_request_object,imported.previous_response_object,imported.previous_conversation_cluster_id,imported.conversation_observation_created,target.request_object AS current_request_object,target.response_object AS current_response_object FROM session_archive_import_records imported LEFT JOIN request_records target ON target.id=imported.target_request_id AND target.tenant_id=imported.tenant_id WHERE imported.tenant_id=$1 AND imported.source=$2 AND (EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$3 AND sessions.tenant_id=$1 AND sessions.source=$2 AND sessions.source_session_id=imported.source_session_id AND (sessions.deleted=1 OR NOT EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=imported.external_request_id AND staged.source_session_id=imported.source_session_id AND staged.record_digest=imported.record_digest AND staged.disposition='exact'))) OR EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=imported.external_request_id AND (staged.source_session_id<>imported.source_session_id OR staged.record_digest<>imported.record_digest OR staged.disposition<>'exact'))) LIMIT 128")
                .bind(&tenant_id).bind(archive_source).bind(batch_id).fetch_all(&mut **tx).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let external_request_id: String = row.try_get("external_request_id")?;
                let source_session_id: String = sqlx::query_scalar("SELECT source_session_id FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).fetch_one(&mut **tx).await?;
                let target_request_id: String = row.try_get("target_request_id")?;
                let current_request: Option<String> = row.try_get("current_request_object")?;
                let current_response: Option<String> = row.try_get("current_response_object")?;
                let imported_request: Option<String> = row.try_get("request_object")?;
                let imported_response: Option<String> = row.try_get("response_object")?;
                let previous_request: Option<String> = row.try_get("previous_request_object")?;
                let previous_response: Option<String> = row.try_get("previous_response_object")?;
                let expected_request = imported_request
                    .as_ref()
                    .or(previous_request.as_ref())
                    .ok_or_else(|| {
                        AppError::Conflict(
                            "legacy exact archive row lacks reversible locator provenance".into(),
                        )
                    })?;
                let expected_response = imported_response.as_ref().or(previous_response.as_ref());
                if current_request.as_deref() != Some(expected_request.as_str())
                    || current_response.as_deref() != expected_response.map(String::as_str)
                {
                    return Err(AppError::Conflict(
                        "archive target changed before stable reconciliation".into(),
                    ));
                }
                let updated = sqlx::query("UPDATE request_records SET request_object=$1,response_object=$2,conversation_cluster_id=$3 WHERE id=$4 AND tenant_id=$5 AND request_object=$6 AND ((response_object IS NULL AND $7 IS NULL) OR response_object=$7)")
                    .bind(previous_request.as_deref().ok_or_else(|| AppError::Conflict("legacy exact archive row lacks reversible locator provenance".into()))?).bind(previous_response.as_deref())
                    .bind(row.try_get::<Option<String>,_>("previous_conversation_cluster_id")?).bind(&target_request_id).bind(&tenant_id)
                    .bind(expected_request).bind(expected_response.map(String::as_str)).execute(&mut **tx).await?;
                if updated.rows_affected() != 1 {
                    return Err(AppError::Conflict(
                        "archive target changed during stable reconciliation".into(),
                    ));
                }
                if row.try_get::<i64, _>("conversation_observation_created")? != 0 {
                    retire_archive_observation_in_transaction(tx, &target_request_id).await?;
                }
                sqlx::query("DELETE FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).execute(&mut **tx).await?;
                sqlx::query("DELETE FROM session_archive_correlations WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).execute(&mut **tx).await?;
                sqlx::query("UPDATE session_archive_snapshot_stage_sessions SET deleted_records=deleted_records+1 WHERE batch_id=$1 AND tenant_id=$2 AND source=$3 AND source_session_id=$4 AND deleted=1")
                    .bind(batch_id).bind(&tenant_id).bind(archive_source).bind(&source_session_id).execute(&mut **tx).await?;
                retired += 1;
            }
        }
        loop {
            let rows = sqlx::query("SELECT imported.external_request_id,imported.archive_request_id,imported.key_id,imported.conversation_cluster_id FROM session_archive_unlinked_requests imported WHERE imported.tenant_id=$1 AND imported.source=$2 AND (EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$3 AND sessions.tenant_id=$1 AND sessions.source=$2 AND sessions.source_session_id=imported.source_session_id AND (sessions.deleted=1 OR NOT EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=imported.external_request_id AND staged.source_session_id=imported.source_session_id AND staged.record_digest=(SELECT record_digest FROM session_archive_correlations WHERE tenant_id=$1 AND source=$2 AND external_request_id=imported.external_request_id) AND staged.disposition='unlinked'))) OR EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=imported.external_request_id AND (staged.source_session_id<>imported.source_session_id OR staged.record_digest<>(SELECT record_digest FROM session_archive_correlations WHERE tenant_id=$1 AND source=$2 AND external_request_id=imported.external_request_id) OR staged.disposition<>'unlinked'))) LIMIT 128")
                .bind(&tenant_id).bind(archive_source).bind(batch_id).fetch_all(&mut **tx).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let external_request_id: String = row.try_get("external_request_id")?;
                let source_session_id: String = sqlx::query_scalar("SELECT source_session_id FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).fetch_one(&mut **tx).await?;
                let archive_request_id: String = row.try_get("archive_request_id")?;
                let key_id: String = row.try_get("key_id")?;
                let cluster_id: Option<String> = row.try_get("conversation_cluster_id")?;
                retire_archive_observation_in_transaction(tx, &archive_request_id).await?;
                sqlx::query("DELETE FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).execute(&mut **tx).await?;
                sqlx::query("DELETE FROM session_archive_correlations WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(&tenant_id).bind(archive_source).bind(&external_request_id).execute(&mut **tx).await?;
                if let Some(cluster_id) = cluster_id {
                    rebuild_archive_session_total_in_transaction(
                        tx,
                        &tenant_id,
                        &key_id,
                        &cluster_id,
                    )
                    .await?;
                }
                sqlx::query("UPDATE session_archive_snapshot_stage_sessions SET deleted_records=deleted_records+1 WHERE batch_id=$1 AND tenant_id=$2 AND source=$3 AND source_session_id=$4 AND deleted=1")
                    .bind(batch_id).bind(&tenant_id).bind(archive_source).bind(&source_session_id).execute(&mut **tx).await?;
                retired += 1;
            }
        }
        sqlx::query("DELETE FROM session_archive_quarantine_record_heads WHERE tenant_id=$1 AND source=$2 AND (EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$3 AND sessions.tenant_id=$1 AND sessions.source=$2 AND sessions.source_session_id=session_archive_quarantine_record_heads.source_session_id AND (sessions.deleted=1 OR NOT EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=session_archive_quarantine_record_heads.external_request_id AND staged.source_session_id=session_archive_quarantine_record_heads.source_session_id AND staged.record_digest=session_archive_quarantine_record_heads.record_digest AND staged.disposition='quarantine'))) OR EXISTS (SELECT 1 FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$3 AND staged.tenant_id=$1 AND staged.source=$2 AND staged.external_request_id=session_archive_quarantine_record_heads.external_request_id AND (staged.source_session_id<>session_archive_quarantine_record_heads.source_session_id OR staged.record_digest<>session_archive_quarantine_record_heads.record_digest OR staged.disposition<>'quarantine')))")
            .bind(&tenant_id).bind(archive_source).bind(batch_id).execute(&mut **tx).await?;
        Ok(retired)
    }

    pub(crate) async fn preflight_session_archive_replacement_locator(
        &self,
        tenant_external_id: &str,
        archive_source: &str,
        external_request_id: &str,
        target_request_id: Uuid,
    ) -> Result<bool, AppError> {
        let row = sqlx::query("SELECT imported.target_request_id,imported.request_object,imported.response_object,target.request_object AS current_request_object,target.response_object AS current_response_object FROM session_archive_import_records imported JOIN tenants tenant ON tenant.id=imported.tenant_id LEFT JOIN request_records target ON target.id=imported.target_request_id AND target.tenant_id=imported.tenant_id WHERE tenant.external_id=$1 AND imported.source=$2 AND imported.external_request_id=$3")
            .bind(tenant_external_id).bind(archive_source).bind(external_request_id).fetch_optional(&self.pool).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let stored_target: String = row.try_get("target_request_id")?;
        let expected_request: Option<String> = row.try_get("request_object")?;
        let expected_response: Option<String> = row.try_get("response_object")?;
        let current_request: Option<String> = row.try_get("current_request_object")?;
        let current_response: Option<String> = row.try_get("current_response_object")?;
        if stored_target != target_request_id.to_string()
            || current_request.is_none()
            || expected_request
                .as_deref()
                .is_some_and(|expected| current_request.as_deref() != Some(expected))
            || expected_response
                .as_deref()
                .is_some_and(|expected| current_response.as_deref() != Some(expected))
        {
            return Err(AppError::Conflict(
                "archive target changed before stable replacement".into(),
            ));
        }
        Ok(true)
    }

    pub(crate) async fn preflight_session_archive_snapshot_chain(
        &self,
        input: SessionArchiveSnapshotChainInput<'_>,
    ) -> Result<(), AppError> {
        if !valid_archive_identifier(input.archive_source, 256)
            || !is_sha256_hex(input.source_fingerprint)
            || !is_sha256_hex(input.output_sha256)
            || input
                .prior_output_sha256
                .is_some_and(|value| !is_sha256_hex(value))
            || input.sequence <= 0
            || !matches!(input.snapshot_schema_version, 1 | 2)
            || input.ingest_fence < 0
            || input
                .tombstone_safe_after_ingest_fence
                .is_some_and(|value| value < 0 || value > input.ingest_fence)
            || (input.snapshot_schema_version == 1
                && input.tombstone_safe_after_ingest_fence.is_some())
            || (input.snapshot_schema_version == 2
                && input.tombstone_safe_after_ingest_fence.is_none())
        {
            return Err(AppError::BadRequest(
                "stable archive snapshot chain metadata is invalid".into(),
            ));
        }
        let tenant_id = self
            .session_archive_tenant_id(input.tenant_external_id)
            .await?;
        if input.snapshot_schema_version == 2 {
            let incomplete: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2 AND previous_request_object IS NULL")
                .bind(&tenant_id).bind(input.archive_source).fetch_one(&self.pool).await?;
            if incomplete != 0 {
                return Err(AppError::Conflict(format!(
                    "{incomplete} legacy exact archive rows lack reversible locator provenance; schema-v2 apply is blocked"
                )));
            }
        }
        let existing = sqlx::query("SELECT source_fingerprint,sequence,offline_full_snapshot,output_sha256,prior_output_sha256,prior_source_ingest_fence,snapshot_schema_version,ingest_fence,tombstone_safe_after_ingest_fence FROM session_archive_snapshot_checkpoints WHERE tenant_id=$1 AND source=$2")
            .bind(&tenant_id).bind(input.archive_source).fetch_optional(&self.pool).await?;
        let Some(existing) = existing else {
            return if input.offline_full_snapshot
                && input.sequence == 1
                && input.prior_output_sha256.is_none()
                && input.prior_source_ingest_fence.is_none()
            {
                Ok(())
            } else {
                Err(AppError::Conflict(
                    "stable archive snapshot chain has no valid baseline".into(),
                ))
            };
        };
        let previous_fingerprint: String = existing.try_get("source_fingerprint")?;
        let previous_sequence: i64 = existing.try_get("sequence")?;
        let previous_offline: i64 = existing.try_get("offline_full_snapshot")?;
        let previous_output: String = existing.try_get("output_sha256")?;
        let previous_prior_output: Option<String> = existing.try_get("prior_output_sha256")?;
        let previous_prior_fence: Option<i64> = existing.try_get("prior_source_ingest_fence")?;
        let previous_schema: i64 = existing.try_get("snapshot_schema_version")?;
        let previous_fence: i64 = existing.try_get("ingest_fence")?;
        let previous_safe: Option<i64> = existing.try_get("tombstone_safe_after_ingest_fence")?;
        let exact_replay = input.source_fingerprint == previous_fingerprint
            && input.sequence == previous_sequence
            && i64::from(input.offline_full_snapshot) == previous_offline
            && input.output_sha256 == previous_output
            && input.prior_output_sha256 == previous_prior_output.as_deref()
            && input.prior_source_ingest_fence == previous_prior_fence
            && input.snapshot_schema_version == previous_schema
            && input.ingest_fence == previous_fence
            && input.tombstone_safe_after_ingest_fence == previous_safe;
        if exact_replay {
            return Ok(());
        }
        let valid_next = !input.offline_full_snapshot
            && input.source_fingerprint == previous_fingerprint
            && input.sequence == previous_sequence + 1
            && input.prior_output_sha256 == Some(previous_output.as_str())
            && input.prior_source_ingest_fence == Some(previous_fence)
            && input.ingest_fence >= previous_fence
            && !(previous_schema == 2 && input.snapshot_schema_version != 2)
            && !(previous_schema == 2 && input.tombstone_safe_after_ingest_fence != previous_safe)
            && !(previous_schema == 1
                && input.snapshot_schema_version == 2
                && input
                    .prior_source_ingest_fence
                    .zip(input.tombstone_safe_after_ingest_fence)
                    .is_none_or(|(prior, safe)| prior < safe));
        if valid_next {
            Ok(())
        } else {
            Err(AppError::Conflict(
                "stable archive snapshot fence or digest changed on replay".into(),
            ))
        }
    }

    pub(crate) async fn session_archive_tenant_id(
        &self,
        tenant_external_id: &str,
    ) -> Result<String, AppError> {
        sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
            .bind(tenant_external_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub(crate) async fn preflight_session_archive_tombstones_batch(
        &self,
        tenant_id: &str,
        archive_source: &str,
        session_ids: &[String],
    ) -> Result<(), AppError> {
        if session_ids.is_empty() {
            return Ok(());
        }
        if !valid_archive_identifier(archive_source, 256)
            || session_ids
                .iter()
                .any(|session_id| !valid_archive_identifier(session_id, 512))
        {
            return Err(AppError::BadRequest(
                "stable archive tombstone is invalid".into(),
            ));
        }
        let mut query = sqlx::QueryBuilder::<Any>::new(
            "SELECT COUNT(*) FROM session_archive_import_records imported LEFT JOIN request_records target ON target.id=imported.target_request_id AND target.tenant_id=imported.tenant_id WHERE imported.tenant_id=",
        );
        query
            .push_bind(tenant_id)
            .push(" AND imported.source=")
            .push_bind(archive_source)
            .push(" AND imported.source_session_id IN (");
        let mut separated = query.separated(",");
        for session_id in session_ids {
            separated.push_bind(session_id);
        }
        separated.push_unseparated(") AND (target.id IS NULL OR (imported.request_object IS NOT NULL AND target.request_object<>imported.request_object) OR (imported.response_object IS NOT NULL AND (target.response_object IS NULL OR target.response_object<>imported.response_object)))");
        let drifted: i64 = query.build_query_scalar().fetch_one(&self.pool).await?;
        if drifted != 0 {
            return Err(AppError::Conflict(
                "archive target changed before tombstone apply".into(),
            ));
        }
        Ok(())
    }

    pub async fn preflight_session_archive_tombstone(
        &self,
        tenant_external_id: &str,
        archive_source: &str,
        tombstone: &SessionArchiveTombstoneInput,
    ) -> Result<(), AppError> {
        if !valid_archive_identifier(archive_source, 256)
            || !valid_archive_identifier(&tombstone.source_session_id, 512)
            || tombstone.deleted_at_ms < 0
        {
            return Err(AppError::BadRequest(
                "stable archive tombstone is invalid".into(),
            ));
        }
        let tenant_id = self.session_archive_tenant_id(tenant_external_id).await?;
        self.preflight_session_archive_tombstones_batch(
            &tenant_id,
            archive_source,
            std::slice::from_ref(&tombstone.source_session_id),
        )
        .await
    }

    pub async fn apply_session_archive_snapshot(
        &self,
        input: SessionArchiveSnapshotApplyInput<'_>,
    ) -> Result<SessionArchiveSnapshotApplyResult, AppError> {
        let mut tx = self.begin_write_transaction().await?;
        let result = self
            .apply_session_archive_snapshot_in_transaction(&mut tx, input)
            .await;
        match result {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    pub(crate) async fn apply_session_archive_snapshot_in_transaction(
        &self,
        tx: &mut Transaction<'_, Any>,
        input: SessionArchiveSnapshotApplyInput<'_>,
    ) -> Result<SessionArchiveSnapshotApplyResult, AppError> {
        if !matches!(input.snapshot_schema_version, 1 | 2)
            || input.sequence <= 0
            || !is_sha256_hex(input.source_fingerprint)
            || !is_sha256_hex(input.output_sha256)
            || input
                .prior_output_sha256
                .is_some_and(|digest| !is_sha256_hex(digest))
            || input.ingest_fence < 0
            || input
                .tombstone_safe_after_ingest_fence
                .is_some_and(|fence| fence < 0 || fence > input.ingest_fence)
            || !is_sha256_hex(input.session_set_sha256)
            || input.session_count < 0
            || input.request_count < 0
            || input.deleted_session_count < 0
            || input.legacy_checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint.watermark_ms < 0
                    || checkpoint.imported_records < 0
                    || !valid_archive_identifier(checkpoint.watermark_request_id, 512)
            })
            || (input.snapshot_schema_version == 2
                && input.request_count > 0
                && input.legacy_checkpoint.is_none())
            || input
                .staged_batch_id
                .is_some_and(|batch| !is_sha256_hex(batch))
            || (input.staged_batch_id.is_none()
                && input.deleted_session_count
                    != i64::try_from(input.tombstones.len())
                        .map_err(|_| AppError::BadRequest("too many archive tombstones".into()))?)
            || (input.snapshot_schema_version == 2
                && input.staged_batch_id.is_none()
                && i64::try_from(input.present_summaries.len())
                    .map_err(|_| AppError::BadRequest("too many archive summaries".into()))?
                    .saturating_add(input.deleted_session_count)
                    != input.session_count)
            || (input.snapshot_schema_version == 1
                && (input.staged_batch_id.is_some()
                    || !input.present_summaries.is_empty()
                    || !input.tombstones.is_empty()
                    || input.deleted_session_count != 0
                    || input.tombstone_safe_after_ingest_fence.is_some()))
            || !valid_archive_identifier(input.archive_source, 256)
            || input.tombstones.iter().any(|tombstone| {
                tombstone.deleted_at_ms < 0
                    || !valid_archive_identifier(&tombstone.source_session_id, 512)
            })
            || input.present_summaries.iter().any(|summary| {
                summary.requests <= 0
                    || summary.first_at_ms < 0
                    || summary.last_at_ms < summary.first_at_ms
                    || !is_sha256_hex(&summary.records_sha256)
                    || !valid_archive_identifier(&summary.source_session_id, 512)
            })
        {
            return Err(AppError::BadRequest(
                "stable archive snapshot metadata is invalid".into(),
            ));
        }
        let tenant_id: String = sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
            .bind(input.tenant_external_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AppError::NotFound)?;
        let now = unix_millis();
        if let Some(existing) = sqlx::query("SELECT source_fingerprint,sequence,offline_full_snapshot,output_sha256,prior_output_sha256,prior_source_ingest_fence,snapshot_schema_version,ingest_fence,tombstone_safe_after_ingest_fence,session_set_sha256,session_count,request_count,deleted_session_count,applied_tombstones,deleted_records FROM session_archive_snapshot_checkpoints WHERE tenant_id=$1 AND source=$2")
            .bind(&tenant_id).bind(input.archive_source).fetch_optional(&mut **tx).await? {
            let same = existing.try_get::<String,_>("source_fingerprint")? == input.source_fingerprint
                && existing.try_get::<i64,_>("sequence")? == input.sequence
                && existing.try_get::<i64,_>("offline_full_snapshot")? == i64::from(input.offline_full_snapshot)
                && existing.try_get::<String,_>("output_sha256")? == input.output_sha256
                && existing.try_get::<Option<String>,_>("prior_output_sha256")?.as_deref() == input.prior_output_sha256
                && existing.try_get::<Option<i64>,_>("prior_source_ingest_fence")? == input.prior_source_ingest_fence
                && existing.try_get::<i64,_>("snapshot_schema_version")? == input.snapshot_schema_version
                && existing.try_get::<i64,_>("ingest_fence")? == input.ingest_fence
                && existing.try_get::<Option<i64>,_>("tombstone_safe_after_ingest_fence")? == input.tombstone_safe_after_ingest_fence
                && existing.try_get::<String,_>("session_set_sha256")? == input.session_set_sha256
                && existing.try_get::<i64,_>("session_count")? == input.session_count
                && existing.try_get::<i64,_>("request_count")? == input.request_count
                && existing.try_get::<i64,_>("deleted_session_count")? == input.deleted_session_count;
            if same {
                if let Some(batch_id) = input.staged_batch_id {
                    cleanup_staged_snapshot_in_transaction(tx, batch_id, &tenant_id, input.archive_source).await?;
                }
                return Ok(SessionArchiveSnapshotApplyResult { replayed: true, tombstones_applied: 0, tombstones_replayed: input.deleted_session_count.max(0) as u64, deleted_records: existing.try_get::<i64,_>("deleted_records")?.max(0) as u64 });
            }
            let previous_fingerprint: String = existing.try_get("source_fingerprint")?;
            let previous_sequence: i64 = existing.try_get("sequence")?;
            let previous_output_sha256: String = existing.try_get("output_sha256")?;
            let previous_ingest_fence: i64 = existing.try_get("ingest_fence")?;
            let previous_schema_version: i64 = existing.try_get("snapshot_schema_version")?;
            let previous_tombstone_safe_fence: Option<i64> = existing.try_get("tombstone_safe_after_ingest_fence")?;
            if input.offline_full_snapshot
                || input.source_fingerprint != previous_fingerprint
                || input.sequence != previous_sequence + 1
                || input.prior_output_sha256 != Some(previous_output_sha256.as_str())
                || input.prior_source_ingest_fence != Some(previous_ingest_fence)
                || input.ingest_fence < previous_ingest_fence
                || (previous_schema_version == 2 && input.snapshot_schema_version != 2)
                || (previous_schema_version == 2 && input.tombstone_safe_after_ingest_fence != previous_tombstone_safe_fence)
                || (previous_schema_version == 1 && input.snapshot_schema_version == 2 && input.prior_source_ingest_fence.zip(input.tombstone_safe_after_ingest_fence).is_none_or(|(prior, safe)| prior < safe))
            {
                return Err(AppError::Conflict("stable archive snapshot fence or digest changed on replay".into()));
            }
        } else if !input.offline_full_snapshot || input.sequence != 1 || input.prior_output_sha256.is_some() || input.prior_source_ingest_fence.is_some() {
            return Err(AppError::Conflict("stable archive snapshot chain has no valid baseline".into()));
        }

        let mut result = SessionArchiveSnapshotApplyResult::default();
        if let Some(batch_id) = input.staged_batch_id {
            result = finalize_staged_snapshot_in_transaction(tx, batch_id, &tenant_id, &input, now)
                .await?;
        } else {
            for summary in input.present_summaries {
                // A later present generation explicitly retires the prior deletion.
                // This permits delete -> recreate -> delete while exact snapshot
                // replay still returns above before changing the generation ledger.
                sqlx::query("DELETE FROM session_archive_applied_tombstones WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&summary.source_session_id).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO session_archive_source_sessions (tenant_id,source,source_session_id,requests,first_at_ms,last_at_ms,records_sha256,ingest_fence,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,source,source_session_id) DO UPDATE SET requests=excluded.requests,first_at_ms=excluded.first_at_ms,last_at_ms=excluded.last_at_ms,records_sha256=excluded.records_sha256,ingest_fence=excluded.ingest_fence,updated_at=excluded.updated_at")
                .bind(&tenant_id).bind(input.archive_source).bind(&summary.source_session_id).bind(summary.requests).bind(summary.first_at_ms).bind(summary.last_at_ms).bind(&summary.records_sha256).bind(input.ingest_fence).bind(now).execute(&mut **tx).await?;
            }
            for tombstone in input.tombstones {
                if let Some(existing) = sqlx::query("SELECT deleted_at_ms FROM session_archive_applied_tombstones WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).fetch_optional(&mut **tx).await? {
                if existing.try_get::<i64,_>("deleted_at_ms")? != tombstone.deleted_at_ms {
                    return Err(AppError::Conflict("stable archive tombstone changed after apply".into()));
                }
                result.tombstones_replayed += 1;
                continue;
            }

                let exact_rows = sqlx::query("SELECT target_request_id,external_event_hash,request_object,response_object FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).fetch_all(&mut **tx).await?;
                for row in &exact_rows {
                    let target: String = row.try_get("target_request_id")?;
                    let event_hash: String = row.try_get("external_event_hash")?;
                    let request_object: Option<String> = row.try_get("request_object")?;
                    let response_object: Option<String> = row.try_get("response_object")?;
                    let current = sqlx::query("SELECT request_object,response_object FROM request_records WHERE id=$1 AND tenant_id=$2")
                    .bind(&target).bind(&tenant_id).fetch_one(&mut **tx).await?;
                    if request_object.as_deref().is_some_and(|expected| {
                        current
                            .try_get::<String, _>("request_object")
                            .is_ok_and(|value| value != expected)
                    }) || response_object.as_deref().is_some_and(|expected| {
                        current
                            .try_get::<Option<String>, _>("response_object")
                            .is_ok_and(|value| value.as_deref() != Some(expected))
                    }) {
                        return Err(AppError::Conflict(
                            "archive target changed before tombstone apply".into(),
                        ));
                    }
                    sqlx::query("UPDATE request_records SET request_object=$1,response_object=CASE WHEN $2 IS NULL THEN response_object ELSE $2 END WHERE id=$3 AND tenant_id=$4")
                    .bind(format!("gap://cpamp/{event_hash}/request"))
                    .bind(response_object.as_ref().map(|_| format!("gap://cpamp/{event_hash}")))
                    .bind(&target).bind(&tenant_id).execute(&mut **tx).await?;
                }

                let unlinked = sqlx::query("SELECT archive_request_id,key_id,conversation_cluster_id FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).fetch_all(&mut **tx).await?;
                for row in &unlinked {
                    let request_id: String = row.try_get("archive_request_id")?;
                    sqlx::query("DELETE FROM conversation_edges WHERE from_observation_id IN (SELECT id FROM conversation_observations WHERE request_id=$1) OR to_observation_id IN (SELECT id FROM conversation_observations WHERE request_id=$1)")
                    .bind(&request_id).execute(&mut **tx).await?;
                    sqlx::query("DELETE FROM conversation_observations WHERE request_id=$1")
                        .bind(&request_id)
                        .execute(&mut **tx)
                        .await?;
                }
                // Quarantine batches, records, memberships, and append-only operator
                // resolutions are immutable audit evidence. A source tombstone
                // retires active exact/unlinked projections but never tears holes in
                // that evidence graph.
                let unlinked_deleted = sqlx::query("DELETE FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).execute(&mut **tx).await?.rows_affected();
                let exact_deleted = sqlx::query("DELETE FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).execute(&mut **tx).await?.rows_affected();
                sqlx::query("DELETE FROM session_archive_correlations WHERE tenant_id=$1 AND source=$2 AND external_request_id NOT IN (SELECT external_request_id FROM session_archive_import_records WHERE tenant_id=$1 AND source=$2) AND external_request_id NOT IN (SELECT external_request_id FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND source=$2)")
                .bind(&tenant_id).bind(input.archive_source).execute(&mut **tx).await?;
                for row in &unlinked {
                    let key_id: String = row.try_get("key_id")?;
                    let cluster_id: Option<String> = row.try_get("conversation_cluster_id")?;
                    if let Some(cluster_id) = cluster_id {
                        sqlx::query("DELETE FROM session_archive_totals WHERE tenant_id=$1 AND key_id=$2 AND session_id=$3").bind(&tenant_id).bind(&key_id).bind(&cluster_id).execute(&mut **tx).await?;
                        sqlx::query("INSERT INTO session_archive_totals (tenant_id,key_id,session_id,last_activity_at,requests,errors,input_tokens,output_tokens,duration_count,duration_sum_ms) SELECT tenant_id,key_id,conversation_cluster_id,MAX(source_started_at),COUNT(*),SUM(CASE WHEN status_code IS NOT NULL AND (status_code<200 OR status_code>=400) THEN 1 ELSE 0 END),SUM(input_tokens),SUM(output_tokens),SUM(CASE WHEN duration_ms IS NULL THEN 0 ELSE 1 END),SUM(COALESCE(duration_ms,0)) FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND key_id=$2 AND conversation_cluster_id=$3 GROUP BY tenant_id,key_id,conversation_cluster_id")
                        .bind(&tenant_id).bind(&key_id).bind(&cluster_id).execute(&mut **tx).await?;
                        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conversation_observations WHERE key_id=$1 AND cluster_id=$2").bind(&key_id).bind(&cluster_id).fetch_one(&mut **tx).await?;
                        if remaining == 0 {
                            sqlx::query("DELETE FROM conversation_key_clusters WHERE key_id=$1 AND cluster_id=$2").bind(&key_id).bind(&cluster_id).execute(&mut **tx).await?;
                        } else {
                            sqlx::query("UPDATE conversation_key_clusters SET request_count=$1,updated_at=(SELECT MAX(created_at) FROM conversation_observations WHERE key_id=$2 AND cluster_id=$3) WHERE key_id=$2 AND cluster_id=$3").bind(remaining).bind(&key_id).bind(&cluster_id).execute(&mut **tx).await?;
                        }
                    }
                }
                let deleted = exact_deleted.saturating_add(unlinked_deleted);
                sqlx::query("DELETE FROM session_archive_source_sessions WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO session_archive_applied_tombstones (tenant_id,source,source_session_id,deleted_at_ms,ingest_fence,deleted_records,applied_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                .bind(&tenant_id).bind(input.archive_source).bind(&tombstone.source_session_id).bind(tombstone.deleted_at_ms).bind(input.ingest_fence).bind(i64::try_from(deleted).map_err(|_| AppError::Internal)?).bind(now).execute(&mut **tx).await?;
                result.tombstones_applied += 1;
                result.deleted_records = result.deleted_records.saturating_add(deleted);
            }
        }
        if let Some(checkpoint) = input.legacy_checkpoint {
            sqlx::query("INSERT INTO session_archive_import_checkpoints (tenant_id,source,watermark_ms,watermark_request_id,imported_records,updated_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,source) DO UPDATE SET watermark_ms=CASE WHEN excluded.watermark_ms>session_archive_import_checkpoints.watermark_ms THEN excluded.watermark_ms ELSE session_archive_import_checkpoints.watermark_ms END,watermark_request_id=CASE WHEN excluded.watermark_ms>session_archive_import_checkpoints.watermark_ms OR (excluded.watermark_ms=session_archive_import_checkpoints.watermark_ms AND excluded.watermark_request_id>session_archive_import_checkpoints.watermark_request_id) THEN excluded.watermark_request_id ELSE session_archive_import_checkpoints.watermark_request_id END,imported_records=session_archive_import_checkpoints.imported_records+excluded.imported_records,updated_at=excluded.updated_at")
                .bind(&tenant_id).bind(input.archive_source).bind(checkpoint.watermark_ms).bind(checkpoint.watermark_request_id).bind(checkpoint.imported_records).bind(now).execute(&mut **tx).await?;
        }
        sqlx::query("INSERT INTO session_archive_snapshot_checkpoints (tenant_id,source,source_fingerprint,sequence,offline_full_snapshot,output_sha256,prior_output_sha256,prior_source_ingest_fence,snapshot_schema_version,ingest_fence,tombstone_safe_after_ingest_fence,session_set_sha256,session_count,request_count,deleted_session_count,applied_tombstones,deleted_records,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT(tenant_id,source) DO UPDATE SET source_fingerprint=excluded.source_fingerprint,sequence=excluded.sequence,offline_full_snapshot=excluded.offline_full_snapshot,output_sha256=excluded.output_sha256,prior_output_sha256=excluded.prior_output_sha256,prior_source_ingest_fence=excluded.prior_source_ingest_fence,snapshot_schema_version=excluded.snapshot_schema_version,ingest_fence=excluded.ingest_fence,tombstone_safe_after_ingest_fence=excluded.tombstone_safe_after_ingest_fence,session_set_sha256=excluded.session_set_sha256,session_count=excluded.session_count,request_count=excluded.request_count,deleted_session_count=excluded.deleted_session_count,applied_tombstones=excluded.applied_tombstones,deleted_records=excluded.deleted_records,updated_at=excluded.updated_at")
            .bind(&tenant_id).bind(input.archive_source).bind(input.source_fingerprint).bind(input.sequence).bind(i64::from(input.offline_full_snapshot)).bind(input.output_sha256).bind(input.prior_output_sha256).bind(input.prior_source_ingest_fence).bind(input.snapshot_schema_version).bind(input.ingest_fence).bind(input.tombstone_safe_after_ingest_fence).bind(input.session_set_sha256).bind(input.session_count).bind(input.request_count).bind(input.deleted_session_count).bind(i64::try_from(result.tombstones_applied).map_err(|_| AppError::Internal)?).bind(i64::try_from(result.deleted_records).map_err(|_| AppError::Internal)?).bind(now).execute(&mut **tx).await?;
        if let Some(batch_id) = input.staged_batch_id {
            cleanup_staged_snapshot_in_transaction(tx, batch_id, &tenant_id, input.archive_source)
                .await?;
        }
        Ok(result)
    }

    pub async fn commit_session_archive_request(
        &self,
        input: SessionArchiveCommitInput<'_>,
    ) -> Result<bool, AppError> {
        let mut tx = self.begin_write_transaction().await?;
        let result = self
            .commit_session_archive_request_in_transaction(&mut tx, input)
            .await;
        match result {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    pub(crate) async fn commit_session_archive_request_in_transaction(
        &self,
        tx: &mut Transaction<'_, Any>,
        input: SessionArchiveCommitInput<'_>,
    ) -> Result<bool, AppError> {
        let checkpoint_ms =
            session_archive_checkpoint_ms(input.source_started_at, input.source_completed_at)?;
        if input.target.tenant_id != input.target.key.tenant_id
            || !is_sha256_hex(input.record_digest)
            || !is_sha256_hex(input.identity_proof_digest)
            || !is_sha256_hex(input.correlation_proof_digest)
            || !valid_archive_identifier(input.archive_source, 256)
            || !valid_archive_identifier(input.external_request_id, 512)
            || !valid_archive_identifier(input.source_session_id, 512)
            || !valid_archive_identifier(input.identity_proof_kind, 128)
            || input
                .request_digest
                .is_some_and(|digest| !is_sha256_hex(digest))
            || input
                .response_digest
                .is_some_and(|digest| !is_sha256_hex(digest))
        {
            return Err(AppError::BadRequest(
                "exact archive correlation proof is invalid".into(),
            ));
        }
        let tenant_matches: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE id = $1 AND external_id = $2")
                .bind(input.target.tenant_id.to_string())
                .bind(input.tenant_external_id)
                .fetch_one(&mut **tx)
                .await?;
        if tenant_matches != 1 {
            return Err(AppError::NotFound);
        }

        // Refuse protected targets before creating semantic atoms or conversation
        // projections. The transactional check below is repeated to close the race.
        let protected = sqlx::query(
            "SELECT request_object, response_object, conversation_cluster_id FROM request_records WHERE id = $1 AND created_at = $2 AND tenant_id = $3",
        )
        .bind(input.target.target_request_id.to_string())
        .bind(input.target.request_created_at)
        .bind(input.target.tenant_id.to_string())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::NotFound)?;
        let protected_request: String = protected.try_get("request_object")?;
        let protected_response: Option<String> = protected.try_get("response_object")?;
        replacement_for_gap(&protected_request, input.request_object)?;
        if let Some(current) = protected_response.as_deref() {
            replacement_for_gap(current, input.response_object)?;
        }

        let now = unix_millis();
        let current = sqlx::query(
            "SELECT request_object, response_object, conversation_cluster_id FROM request_records WHERE id = $1 AND created_at = $2 AND tenant_id = $3",
        )
        .bind(input.target.target_request_id.to_string())
        .bind(input.target.request_created_at)
        .bind(input.target.tenant_id.to_string())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::NotFound)?;
        let current_request: String = current.try_get("request_object")?;
        let current_response: Option<String> = current.try_get("response_object")?;
        let previous_conversation_cluster_id: Option<String> =
            current.try_get("conversation_cluster_id")?;
        let next_request = replacement_for_gap(&current_request, input.request_object)?;
        let next_response = match (current_response.as_deref(), input.response_object) {
            (Some(current), replacement) => replacement_for_gap(current, replacement)?,
            (None, Some(replacement)) => Some(replacement.to_owned()),
            (None, None) => None,
        };

        let correlation_inserted = sqlx::query(
            "INSERT INTO session_archive_correlations (tenant_id, source, external_request_id, disposition, key_id, principal_id, target_request_id, target_request_created_at, external_event_hash, record_digest, proof_digest, identity_proof_kind, identity_proof_digest, source_model, source_started_at, correlated_at) VALUES ($1, $2, $3, 'exact', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT(tenant_id, source, external_request_id) DO NOTHING",
        )
        .bind(input.target.tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .bind(input.target.key.key_id.to_string())
        .bind(input.target.key.principal_id.to_string())
        .bind(input.target.target_request_id.to_string())
        .bind(input.target.request_created_at)
        .bind(&input.target.external_event_hash)
        .bind(input.record_digest)
        .bind(input.correlation_proof_digest)
        .bind(input.identity_proof_kind)
        .bind(input.identity_proof_digest)
        .bind(&input.target.source_model)
        .bind(input.source_started_at)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        if correlation_inserted.rows_affected() == 0 {
            let existing = sqlx::query(
                "SELECT disposition, key_id, principal_id, target_request_id, target_request_created_at, external_event_hash, record_digest, proof_digest, identity_proof_kind, identity_proof_digest, source_model, source_started_at FROM session_archive_correlations WHERE tenant_id = $1 AND source = $2 AND external_request_id = $3",
            )
            .bind(input.target.tenant_id.to_string())
            .bind(input.archive_source)
            .bind(input.external_request_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AppError::Internal)?;
            let expected_target_request_id = input.target.target_request_id.to_string();
            let compatible = existing.try_get::<String, _>("disposition")? == "exact"
                && existing.try_get::<String, _>("key_id")? == input.target.key.key_id.to_string()
                && existing.try_get::<String, _>("principal_id")?
                    == input.target.key.principal_id.to_string()
                && existing
                    .try_get::<Option<String>, _>("target_request_id")?
                    .as_deref()
                    == Some(expected_target_request_id.as_str())
                && existing.try_get::<Option<i64>, _>("target_request_created_at")?
                    == Some(input.target.request_created_at)
                && existing
                    .try_get::<Option<String>, _>("external_event_hash")?
                    .as_deref()
                    == Some(input.target.external_event_hash.as_str())
                && existing.try_get::<String, _>("record_digest")? == input.record_digest
                && existing.try_get::<String, _>("proof_digest")? == input.correlation_proof_digest
                && existing.try_get::<String, _>("identity_proof_kind")?
                    == input.identity_proof_kind
                && existing.try_get::<String, _>("identity_proof_digest")?
                    == input.identity_proof_digest
                && existing.try_get::<String, _>("source_model")? == input.target.source_model
                && existing.try_get::<i64, _>("source_started_at")? == input.source_started_at;
            if !compatible {
                return Err(AppError::BadRequest(
                    "archive correlation changed while it was being imported".into(),
                ));
            }
        }

        let inserted = sqlx::query(
            "INSERT INTO session_archive_import_records (tenant_id, source, external_request_id, target_request_id, external_event_hash, record_digest, request_digest, response_digest, request_object, response_object, source_started_at, imported_at, source_session_id,previous_request_object,previous_response_object,previous_conversation_cluster_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,$14,$15,$16) ON CONFLICT(tenant_id, source, external_request_id) DO NOTHING",
        )
        .bind(input.target.tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .bind(input.target.target_request_id.to_string())
        .bind(&input.target.external_event_hash)
        .bind(input.record_digest)
        .bind(input.request_digest)
        .bind(input.response_digest)
        .bind(input.request_object)
        .bind(input.response_object)
        .bind(input.source_started_at)
        .bind(now)
        .bind(input.source_session_id)
        .bind(&current_request)
        .bind(current_response.as_deref())
        .bind(previous_conversation_cluster_id.as_deref())
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing = sqlx::query(
                "SELECT target_request_id, external_event_hash, record_digest, request_digest, response_digest, request_object, response_object, source_started_at, source_session_id FROM session_archive_import_records WHERE tenant_id = $1 AND source = $2 AND external_request_id = $3",
            )
            .bind(input.target.tenant_id.to_string())
            .bind(input.archive_source)
            .bind(input.external_request_id)
            .fetch_optional(&mut **tx)
            .await?;
            let compatible_replay = existing
                .map(|row| {
                    Ok::<_, AppError>(
                        row.try_get::<String, _>("target_request_id")?
                            == input.target.target_request_id.to_string()
                            && row.try_get::<String, _>("external_event_hash")?
                                == input.target.external_event_hash
                            && row.try_get::<String, _>("record_digest")? == input.record_digest
                            && row
                                .try_get::<Option<String>, _>("request_digest")?
                                .as_deref()
                                == input.request_digest
                            && row
                                .try_get::<Option<String>, _>("response_digest")?
                                .as_deref()
                                == input.response_digest
                            && row
                                .try_get::<Option<String>, _>("request_object")?
                                .as_deref()
                                == input.request_object
                            && row
                                .try_get::<Option<String>, _>("response_object")?
                                .as_deref()
                                == input.response_object
                            && row.try_get::<i64, _>("source_started_at")?
                                == input.source_started_at
                            && ["", input.source_session_id]
                                .contains(&row.try_get::<String, _>("source_session_id")?.as_str()),
                    )
                })
                .transpose()?
                .unwrap_or(false);
            return if compatible_replay {
                sqlx::query("UPDATE session_archive_import_records SET source_session_id = $4 WHERE tenant_id = $1 AND source = $2 AND external_request_id = $3 AND source_session_id = ''")
                    .bind(input.target.tenant_id.to_string()).bind(input.archive_source).bind(input.external_request_id).bind(input.source_session_id)
                    .execute(&mut **tx).await?;
                if !input.defer_checkpoint {
                    advance_session_archive_checkpoint(
                        tx,
                        input.target.tenant_id,
                        input.archive_source,
                        checkpoint_ms,
                        input.external_request_id,
                        false,
                        now,
                    )
                    .await?;
                }
                Ok(false)
            } else {
                Err(AppError::BadRequest(
                    "archive request changed while it was being imported".into(),
                ))
            };
        }

        if let Some(request_json) = input.request_json {
            let existing = sqlx::query(
                "SELECT cluster_id FROM conversation_observations WHERE request_id = $1",
            )
            .bind(input.target.target_request_id.to_string())
            .fetch_optional(&mut **tx)
            .await?;
            if existing.is_none() {
                self.record_conversation_observation_in_transaction(
                    tx,
                    ConversationObservationInput {
                        key: &input.target.key,
                        request_id: input.target.target_request_id,
                        request_json,
                        hints: input.conversation_hints,
                        client_name: input.client_name,
                        upstream_response_id: None,
                        observed_at: input.source_started_at,
                        attach_request_record: true,
                        content_materialized: false,
                    },
                )
                .await?;
                sqlx::query("UPDATE session_archive_import_records SET conversation_observation_created=1 WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3")
                    .bind(input.target.tenant_id.to_string()).bind(input.archive_source).bind(input.external_request_id).execute(&mut **tx).await?;
            }
        }

        let updated = sqlx::query(
            "UPDATE request_records SET request_object = $1, response_object = $2 WHERE id = $3 AND created_at = $4 AND tenant_id = $5 AND request_object = $6 AND ((response_object IS NULL AND $7 IS NULL) OR response_object = $7)",
        )
        .bind(next_request.unwrap_or_else(|| current_request.clone()))
        .bind(next_response)
        .bind(input.target.target_request_id.to_string())
        .bind(input.target.request_created_at)
        .bind(input.target.tenant_id.to_string())
        .bind(&current_request)
        .bind(current_response.as_deref())
        .execute(&mut **tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(AppError::BadRequest(
                "archive target changed after preflight".into(),
            ));
        }
        if !input.defer_checkpoint {
            advance_session_archive_checkpoint(
                tx,
                input.target.tenant_id,
                input.archive_source,
                checkpoint_ms,
                input.external_request_id,
                true,
                now,
            )
            .await?;
        }
        Ok(true)
    }

    pub async fn commit_session_archive_unlinked_request(
        &self,
        input: SessionArchiveUnlinkedCommitInput<'_>,
    ) -> Result<bool, AppError> {
        let mut tx = self.begin_write_transaction().await?;
        let result = self
            .commit_session_archive_unlinked_request_in_transaction(&mut tx, input)
            .await;
        match result {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    pub(crate) async fn commit_session_archive_unlinked_request_in_transaction(
        &self,
        tx: &mut Transaction<'_, Any>,
        input: SessionArchiveUnlinkedCommitInput<'_>,
    ) -> Result<bool, AppError> {
        let checkpoint_ms = session_archive_checkpoint_ms(
            input.source_started_at,
            input.metadata.source_completed_at,
        )?;
        if input.target.tenant_id != input.target.key.tenant_id
            || !is_sha256_hex(input.record_digest)
            || !is_sha256_hex(&input.target.identity_proof_digest)
            || !is_sha256_hex(&input.target.correlation_proof_digest)
            || !valid_archive_identifier(input.archive_source, 256)
            || !valid_archive_identifier(input.external_request_id, 512)
            || !valid_archive_identifier(input.source_session_id, 512)
            || !valid_archive_identifier(&input.target.identity_proof_kind, 128)
            || input
                .request_digest
                .is_some_and(|digest| !is_sha256_hex(digest))
            || input
                .response_digest
                .is_some_and(|digest| !is_sha256_hex(digest))
            || input.metadata.protocol.trim().is_empty()
            || input.metadata.model.trim().is_empty()
            || input.metadata.protocol.len() > 256
            || input.metadata.model.len() > 512
            || input.metadata.input_tokens < 0
            || input.metadata.output_tokens < 0
        {
            return Err(AppError::BadRequest(
                "archive-only request metadata or proof is invalid".into(),
            ));
        }
        let tenant_matches: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE id = $1 AND external_id = $2")
                .bind(input.target.tenant_id.to_string())
                .bind(input.tenant_external_id)
                .fetch_one(&mut **tx)
                .await?;
        if tenant_matches != 1 {
            return Err(AppError::NotFound);
        }

        let now = unix_millis();
        let inserted = sqlx::query(
            "INSERT INTO session_archive_correlations (tenant_id, source, external_request_id, disposition, key_id, principal_id, target_request_id, target_request_created_at, external_event_hash, record_digest, proof_digest, identity_proof_kind, identity_proof_digest, source_model, source_started_at, correlated_at) VALUES ($1, $2, $3, 'unlinked', $4, $5, NULL, NULL, NULL, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT(tenant_id, source, external_request_id) DO NOTHING",
        )
        .bind(input.target.tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .bind(input.target.key.key_id.to_string())
        .bind(input.target.key.principal_id.to_string())
        .bind(input.record_digest)
        .bind(&input.target.correlation_proof_digest)
        .bind(&input.target.identity_proof_kind)
        .bind(&input.target.identity_proof_digest)
        .bind(input.metadata.model)
        .bind(input.source_started_at)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing = sqlx::query(
                "SELECT c.disposition, c.key_id, c.principal_id, c.record_digest, c.proof_digest, c.identity_proof_kind, c.identity_proof_digest, c.source_model, c.source_started_at, u.archive_request_id, u.source_completed_at, u.protocol, u.model, u.status_code, u.duration_ms, u.input_tokens, u.output_tokens, u.error_code, u.request_digest, u.response_digest, u.request_object, u.response_object, u.source_session_id FROM session_archive_correlations c LEFT JOIN session_archive_unlinked_requests u ON u.tenant_id = c.tenant_id AND u.source = c.source AND u.external_request_id = c.external_request_id WHERE c.tenant_id = $1 AND c.source = $2 AND c.external_request_id = $3",
            )
            .bind(input.target.tenant_id.to_string())
            .bind(input.archive_source)
            .bind(input.external_request_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AppError::Internal)?;
            let expected_archive_request_id = input.target.archive_request_id.to_string();
            let compatible = existing.try_get::<String, _>("disposition")? == "unlinked"
                && existing.try_get::<String, _>("key_id")? == input.target.key.key_id.to_string()
                && existing.try_get::<String, _>("principal_id")?
                    == input.target.key.principal_id.to_string()
                && existing.try_get::<String, _>("record_digest")? == input.record_digest
                && existing.try_get::<String, _>("proof_digest")?
                    == input.target.correlation_proof_digest
                && existing.try_get::<String, _>("identity_proof_kind")?
                    == input.target.identity_proof_kind
                && existing.try_get::<String, _>("identity_proof_digest")?
                    == input.target.identity_proof_digest
                && existing.try_get::<String, _>("source_model")? == input.metadata.model
                && existing.try_get::<i64, _>("source_started_at")? == input.source_started_at
                && existing
                    .try_get::<Option<String>, _>("archive_request_id")?
                    .as_deref()
                    == Some(expected_archive_request_id.as_str())
                && existing.try_get::<Option<i64>, _>("source_completed_at")?
                    == input.metadata.source_completed_at
                && existing
                    .try_get::<Option<String>, _>("protocol")?
                    .as_deref()
                    == Some(input.metadata.protocol)
                && existing.try_get::<Option<String>, _>("model")?.as_deref()
                    == Some(input.metadata.model)
                && existing.try_get::<Option<i64>, _>("status_code")? == input.metadata.status_code
                && existing.try_get::<Option<i64>, _>("duration_ms")? == input.metadata.duration_ms
                && existing.try_get::<Option<i64>, _>("input_tokens")?
                    == Some(input.metadata.input_tokens)
                && existing.try_get::<Option<i64>, _>("output_tokens")?
                    == Some(input.metadata.output_tokens)
                && existing
                    .try_get::<Option<String>, _>("error_code")?
                    .as_deref()
                    == input.metadata.error_code
                && existing
                    .try_get::<Option<String>, _>("request_digest")?
                    .as_deref()
                    == input.request_digest
                && existing
                    .try_get::<Option<String>, _>("response_digest")?
                    .as_deref()
                    == input.response_digest
                && existing
                    .try_get::<Option<String>, _>("request_object")?
                    .as_deref()
                    == input.request_object
                && existing
                    .try_get::<Option<String>, _>("response_object")?
                    .as_deref()
                    == input.response_object
                && existing
                    .try_get::<Option<String>, _>("source_session_id")?
                    .as_deref()
                    .is_some_and(|value| value.is_empty() || value == input.source_session_id);
            if compatible {
                sqlx::query("UPDATE session_archive_unlinked_requests SET source_session_id = $4 WHERE tenant_id = $1 AND source = $2 AND external_request_id = $3 AND source_session_id = ''")
                    .bind(input.target.tenant_id.to_string()).bind(input.archive_source).bind(input.external_request_id).bind(input.source_session_id)
                    .execute(&mut **tx).await?;
                if !input.defer_checkpoint {
                    advance_session_archive_checkpoint(
                        tx,
                        input.target.tenant_id,
                        input.archive_source,
                        checkpoint_ms,
                        input.external_request_id,
                        false,
                        now,
                    )
                    .await?;
                }
                return Ok(false);
            }
            return Err(AppError::BadRequest(
                "archive-only request changed while it was being imported".into(),
            ));
        }

        sqlx::query(
            "INSERT INTO session_archive_unlinked_requests (tenant_id, source, external_request_id, archive_request_id, key_id, principal_id, conversation_cluster_id, source_started_at, source_completed_at, protocol, model, status_code, duration_ms, input_tokens, output_tokens, error_code, request_digest, response_digest, request_object, response_object, imported_at, source_session_id) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)",
        )
        .bind(input.target.tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .bind(input.target.archive_request_id.to_string())
        .bind(input.target.key.key_id.to_string())
        .bind(input.target.key.principal_id.to_string())
        .bind(input.source_started_at)
        .bind(input.metadata.source_completed_at)
        .bind(input.metadata.protocol)
        .bind(input.metadata.model)
        .bind(input.metadata.status_code)
        .bind(input.metadata.duration_ms)
        .bind(input.metadata.input_tokens)
        .bind(input.metadata.output_tokens)
        .bind(input.metadata.error_code)
        .bind(input.request_digest)
        .bind(input.response_digest)
        .bind(input.request_object)
        .bind(input.response_object)
        .bind(now)
        .bind(input.source_session_id)
        .execute(&mut **tx)
        .await?;

        let empty_request = serde_json::Value::Null;
        let cluster_id = self
            .record_conversation_observation_in_transaction(
                tx,
                ConversationObservationInput {
                    key: &input.target.key,
                    request_id: input.target.archive_request_id,
                    request_json: input.request_json.unwrap_or(&empty_request),
                    hints: input.conversation_hints,
                    client_name: input.client_name,
                    upstream_response_id: None,
                    observed_at: input.source_started_at,
                    attach_request_record: false,
                    content_materialized: false,
                },
            )
            .await?;
        let attached = sqlx::query(
            "UPDATE session_archive_unlinked_requests SET conversation_cluster_id = $1 WHERE tenant_id = $2 AND source = $3 AND external_request_id = $4 AND conversation_cluster_id IS NULL",
        )
        .bind(cluster_id.to_string())
        .bind(input.target.tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .execute(&mut **tx)
        .await?;
        if attached.rows_affected() != 1 {
            return Err(AppError::Internal);
        }
        add_archive_record_to_session_projection_in_transaction(
            tx,
            input.target.tenant_id,
            input.target.key.key_id,
            input.archive_source,
            input.external_request_id,
        )
        .await?;

        if !input.defer_checkpoint {
            advance_session_archive_checkpoint(
                tx,
                input.target.tenant_id,
                input.archive_source,
                checkpoint_ms,
                input.external_request_id,
                true,
                now,
            )
            .await?;
        }
        Ok(true)
    }
}

fn replacement_for_gap(
    current: &str,
    replacement: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(replacement) = replacement else {
        return Ok(Some(current.to_owned()));
    };
    if current.starts_with("gap://") || current == replacement {
        return Ok(Some(replacement.to_owned()));
    }
    Err(AppError::BadRequest(
        "archive import refused to overwrite an existing object".into(),
    ))
}

async fn retire_archive_observation_in_transaction(
    tx: &mut Transaction<'_, Any>,
    request_id: &str,
) -> Result<(), AppError> {
    let observation =
        sqlx::query("SELECT key_id,cluster_id FROM conversation_observations WHERE request_id=$1")
            .bind(request_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(observation) = observation else {
        return Ok(());
    };
    let key_id: String = observation.try_get("key_id")?;
    let cluster_id: String = observation.try_get("cluster_id")?;
    sqlx::query("DELETE FROM conversation_edges WHERE from_observation_id IN (SELECT id FROM conversation_observations WHERE request_id=$1) OR to_observation_id IN (SELECT id FROM conversation_observations WHERE request_id=$1)")
        .bind(request_id).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM conversation_observations WHERE request_id=$1")
        .bind(request_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM conversation_key_clusters WHERE key_id=$1 AND cluster_id=$2")
        .bind(&key_id)
        .bind(&cluster_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO conversation_key_clusters (key_id,cluster_id,explicit_session_id,updated_at,request_count,candidate_edge_count) SELECT $1,$2,MIN(observations.explicit_session_id),MAX(observations.created_at),COUNT(*),(SELECT COUNT(*) FROM conversation_edges edges JOIN conversation_observations targets ON targets.id=edges.to_observation_id JOIN conversation_observations sources ON sources.id=edges.from_observation_id AND sources.key_id=targets.key_id WHERE edges.cluster_id=$2 AND edges.relation_kind='candidate' AND targets.key_id=$1) FROM conversation_observations observations WHERE observations.key_id=$1 AND observations.cluster_id=$2 HAVING COUNT(*)>0")
        .bind(&key_id).bind(&cluster_id).execute(&mut **tx).await?;
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM conversation_observations WHERE cluster_id=$1")
            .bind(&cluster_id)
            .fetch_one(&mut **tx)
            .await?;
    if remaining == 0 {
        sqlx::query("DELETE FROM conversation_clusters WHERE id=$1")
            .bind(&cluster_id)
            .execute(&mut **tx)
            .await?;
    } else {
        sqlx::query("UPDATE conversation_clusters SET created_at=(SELECT MIN(created_at) FROM conversation_observations WHERE cluster_id=$1),updated_at=(SELECT MAX(created_at) FROM conversation_observations WHERE cluster_id=$1),explicit_session_id=(SELECT MIN(explicit_session_id) FROM conversation_observations WHERE cluster_id=$1) WHERE id=$1")
            .bind(&cluster_id).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn rebuild_archive_session_total_in_transaction(
    tx: &mut Transaction<'_, Any>,
    tenant_id: &str,
    key_id: &str,
    cluster_id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM session_archive_totals WHERE tenant_id=$1 AND key_id=$2 AND session_id=$3",
    )
    .bind(tenant_id)
    .bind(key_id)
    .bind(cluster_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO session_archive_totals (tenant_id,key_id,session_id,last_activity_at,requests,errors,input_tokens,output_tokens,duration_count,duration_sum_ms) SELECT tenant_id,key_id,conversation_cluster_id,MAX(source_started_at),COUNT(*),SUM(CASE WHEN status_code IS NOT NULL AND (status_code<200 OR status_code>=400) THEN 1 ELSE 0 END),SUM(input_tokens),SUM(output_tokens),SUM(CASE WHEN duration_ms IS NULL THEN 0 ELSE 1 END),SUM(COALESCE(duration_ms,0)) FROM session_archive_unlinked_requests WHERE tenant_id=$1 AND key_id=$2 AND conversation_cluster_id=$3 GROUP BY tenant_id,key_id,conversation_cluster_id")
        .bind(tenant_id).bind(key_id).bind(cluster_id).execute(&mut **tx).await?;
    Ok(())
}

async fn finalize_staged_snapshot_in_transaction(
    tx: &mut Transaction<'_, Any>,
    batch_id: &str,
    tenant_id: &str,
    input: &SessionArchiveSnapshotApplyInput<'_>,
    now: i64,
) -> Result<SessionArchiveSnapshotApplyResult, AppError> {
    let archive_source = input.archive_source;
    let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_stage_sessions WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(batch_id).bind(tenant_id).bind(archive_source).fetch_one(&mut **tx).await?;
    let deleted_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_stage_sessions WHERE batch_id=$1 AND tenant_id=$2 AND source=$3 AND deleted=1")
        .bind(batch_id).bind(tenant_id).bind(archive_source).fetch_one(&mut **tx).await?;
    let request_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_stage_records WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(batch_id).bind(tenant_id).bind(archive_source).fetch_one(&mut **tx).await?;
    if (session_count, request_count, deleted_count)
        != (
            input.session_count,
            input.request_count,
            input.deleted_session_count,
        )
    {
        return Err(AppError::Conflict(
            "staged stable snapshot counts changed before apply".into(),
        ));
    }
    let unmatched: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_stage_records staged WHERE staged.batch_id=$1 AND staged.tenant_id=$2 AND staged.source=$3 AND ((staged.disposition='exact' AND NOT EXISTS (SELECT 1 FROM session_archive_import_records imported WHERE imported.tenant_id=$2 AND imported.source=$3 AND imported.external_request_id=staged.external_request_id AND imported.source_session_id=staged.source_session_id AND imported.record_digest=staged.record_digest)) OR (staged.disposition='unlinked' AND NOT EXISTS (SELECT 1 FROM session_archive_unlinked_requests imported JOIN session_archive_correlations correlation ON correlation.tenant_id=imported.tenant_id AND correlation.source=imported.source AND correlation.external_request_id=imported.external_request_id WHERE imported.tenant_id=$2 AND imported.source=$3 AND imported.external_request_id=staged.external_request_id AND imported.source_session_id=staged.source_session_id AND correlation.record_digest=staged.record_digest)) OR (staged.disposition='quarantine' AND NOT EXISTS (SELECT 1 FROM session_archive_quarantine_record_heads head WHERE head.tenant_id=$2 AND head.source=$3 AND head.external_request_id=staged.external_request_id AND head.source_session_id=staged.source_session_id AND head.record_digest=staged.record_digest)))")
        .bind(batch_id).bind(tenant_id).bind(archive_source).fetch_one(&mut **tx).await?;
    let tombstone_active: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM session_archive_import_records imported WHERE imported.tenant_id=$2 AND imported.source=$3 AND EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$1 AND sessions.tenant_id=$2 AND sessions.source=$3 AND sessions.deleted=1 AND sessions.source_session_id=imported.source_session_id)) + (SELECT COUNT(*) FROM session_archive_unlinked_requests imported WHERE imported.tenant_id=$2 AND imported.source=$3 AND EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$1 AND sessions.tenant_id=$2 AND sessions.source=$3 AND sessions.deleted=1 AND sessions.source_session_id=imported.source_session_id)) + (SELECT COUNT(*) FROM session_archive_quarantine_record_heads head WHERE head.tenant_id=$2 AND head.source=$3 AND EXISTS (SELECT 1 FROM session_archive_snapshot_stage_sessions sessions WHERE sessions.batch_id=$1 AND sessions.tenant_id=$2 AND sessions.source=$3 AND sessions.deleted=1 AND sessions.source_session_id=head.source_session_id))")
        .bind(batch_id).bind(tenant_id).bind(archive_source).fetch_one(&mut **tx).await?;
    if unmatched != 0 || tombstone_active != 0 {
        return Err(AppError::Conflict(
            "target projection does not match its sealed stable snapshot".into(),
        ));
    }

    let mut result = SessionArchiveSnapshotApplyResult::default();
    let mut after = String::new();
    loop {
        let rows = sqlx::query("SELECT source_session_id,deleted,requests,first_at_ms,last_at_ms,records_sha256,deleted_at_ms,deleted_records FROM session_archive_snapshot_stage_sessions WHERE batch_id=$1 AND tenant_id=$2 AND source=$3 AND source_session_id>$4 ORDER BY source_session_id LIMIT 256")
            .bind(batch_id).bind(tenant_id).bind(archive_source).bind(&after).fetch_all(&mut **tx).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let source_session_id: String = row.try_get("source_session_id")?;
            after = source_session_id.clone();
            if row.try_get::<i64, _>("deleted")? == 0 {
                sqlx::query("DELETE FROM session_archive_applied_tombstones WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                    .bind(tenant_id).bind(archive_source).bind(&source_session_id).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO session_archive_source_sessions (tenant_id,source,source_session_id,requests,first_at_ms,last_at_ms,records_sha256,ingest_fence,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,source,source_session_id) DO UPDATE SET requests=excluded.requests,first_at_ms=excluded.first_at_ms,last_at_ms=excluded.last_at_ms,records_sha256=excluded.records_sha256,ingest_fence=excluded.ingest_fence,updated_at=excluded.updated_at")
                    .bind(tenant_id).bind(archive_source).bind(&source_session_id).bind(row.try_get::<i64,_>("requests")?)
                    .bind(row.try_get::<Option<i64>,_>("first_at_ms")?.ok_or(AppError::Internal)?).bind(row.try_get::<i64,_>("last_at_ms")?)
                    .bind(row.try_get::<Option<String>,_>("records_sha256")?.ok_or(AppError::Internal)?).bind(input.ingest_fence).bind(now).execute(&mut **tx).await?;
            } else {
                let deleted_at_ms: i64 = row
                    .try_get::<Option<i64>, _>("deleted_at_ms")?
                    .ok_or(AppError::Internal)?;
                let deleted_records: i64 = row.try_get("deleted_records")?;
                if let Some(existing) = sqlx::query_scalar::<_, i64>("SELECT deleted_at_ms FROM session_archive_applied_tombstones WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                    .bind(tenant_id).bind(archive_source).bind(&source_session_id).fetch_optional(&mut **tx).await? {
                    if existing != deleted_at_ms { return Err(AppError::Conflict("stable archive tombstone changed after apply".into())); }
                    result.tombstones_replayed += 1;
                } else {
                    sqlx::query("INSERT INTO session_archive_applied_tombstones (tenant_id,source,source_session_id,deleted_at_ms,ingest_fence,deleted_records,applied_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                        .bind(tenant_id).bind(archive_source).bind(&source_session_id).bind(deleted_at_ms).bind(input.ingest_fence).bind(deleted_records).bind(now).execute(&mut **tx).await?;
                    result.tombstones_applied += 1;
                    result.deleted_records = result.deleted_records.saturating_add(u64::try_from(deleted_records).map_err(|_| AppError::Internal)?);
                }
                sqlx::query("DELETE FROM session_archive_source_sessions WHERE tenant_id=$1 AND source=$2 AND source_session_id=$3")
                    .bind(tenant_id).bind(archive_source).bind(&source_session_id).execute(&mut **tx).await?;
            }
        }
    }
    Ok(result)
}

async fn cleanup_staged_snapshot_in_transaction(
    tx: &mut Transaction<'_, Any>,
    batch_id: &str,
    tenant_id: &str,
    archive_source: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM session_archive_snapshot_stage_records WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(batch_id).bind(tenant_id).bind(archive_source).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM session_archive_snapshot_stage_sessions WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(batch_id).bind(tenant_id).bind(archive_source).execute(&mut **tx).await?;
    Ok(())
}

pub(super) fn session_archive_checkpoint_ms(
    source_started_at: i64,
    source_completed_at: Option<i64>,
) -> Result<i64, AppError> {
    if source_started_at < 0
        || source_completed_at.is_some_and(|completed_at| completed_at < source_started_at)
    {
        return Err(AppError::BadRequest(
            "archive request time range is invalid".into(),
        ));
    }
    // A CPA archive record always carries completed_at. None remains a narrowly
    // defined compatibility path for legacy/direct callers and advances by start.
    Ok(source_completed_at.unwrap_or(source_started_at))
}

pub(super) async fn advance_session_archive_checkpoint(
    tx: &mut Transaction<'_, Any>,
    tenant_id: Uuid,
    archive_source: &str,
    checkpoint_ms: i64,
    external_request_id: &str,
    imported: bool,
    now: i64,
) -> Result<(), AppError> {
    if imported {
        sqlx::query(
            "INSERT INTO session_archive_import_checkpoints (tenant_id, source, watermark_ms, watermark_request_id, imported_records, updated_at) VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT(tenant_id, source) DO UPDATE SET watermark_ms = CASE WHEN excluded.watermark_ms > session_archive_import_checkpoints.watermark_ms THEN excluded.watermark_ms ELSE session_archive_import_checkpoints.watermark_ms END, watermark_request_id = CASE WHEN excluded.watermark_ms > session_archive_import_checkpoints.watermark_ms OR (excluded.watermark_ms = session_archive_import_checkpoints.watermark_ms AND excluded.watermark_request_id > session_archive_import_checkpoints.watermark_request_id) THEN excluded.watermark_request_id ELSE session_archive_import_checkpoints.watermark_request_id END, imported_records = session_archive_import_checkpoints.imported_records + 1, updated_at = excluded.updated_at",
        )
        .bind(tenant_id.to_string())
        .bind(archive_source)
        .bind(checkpoint_ms)
        .bind(external_request_id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        return Ok(());
    }

    // A replay must never change imported_records. It may only upgrade a legacy
    // start-based checkpoint to the completed-at cursor already bound by the
    // immutable record digest. A missing checkpoint is corrupt importer state.
    let updated = sqlx::query(
        "UPDATE session_archive_import_checkpoints SET watermark_ms = CASE WHEN $3 > watermark_ms THEN $3 ELSE watermark_ms END, watermark_request_id = CASE WHEN $3 > watermark_ms OR ($3 = watermark_ms AND $4 > watermark_request_id) THEN $4 ELSE watermark_request_id END, updated_at = $5 WHERE tenant_id = $1 AND source = $2",
    )
    .bind(tenant_id.to_string())
    .bind(archive_source)
    .bind(checkpoint_ms)
    .bind(external_request_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Internal);
    }
    Ok(())
}
