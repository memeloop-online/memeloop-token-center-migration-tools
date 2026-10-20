use super::*;

pub(super) async fn stage_validated_snapshot_projection(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    options: &SessionArchiveImportOptions<'_>,
    plan: &mut ValidatedImportPlan,
    manifest: &StableDeltaManifest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if manifest.snapshot_schema_version != 2 {
        return Ok(());
    }
    let tenant_id: String = sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
        .bind(options.tenant_external_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::NotFound)?;
    sqlx::query("DELETE FROM session_archive_snapshot_stage_records WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(&manifest.expected_output_sha256).bind(&tenant_id).bind(options.archive_source).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM session_archive_snapshot_stage_sessions WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(&manifest.expected_output_sha256).bind(&tenant_id).bind(options.archive_source).execute(&mut **tx).await?;
    let mut summary_rows = sqlx::query("SELECT session_id,requests,first_at_ms,last_at_ms,records_sha256,deleted,deleted_at_ms FROM import_plan_summaries ORDER BY session_id COLLATE BINARY")
        .fetch(&mut plan.connection);
    let mut summary_count = 0_i64;
    while let Some(row) = summary_rows.try_next().await? {
        summary_count += 1;
        sqlx::query("INSERT INTO session_archive_snapshot_stage_sessions (batch_id,tenant_id,source,source_session_id,deleted,requests,first_at_ms,last_at_ms,records_sha256,deleted_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&manifest.expected_output_sha256).bind(&tenant_id).bind(options.archive_source)
            .bind(row.try_get::<String,_>("session_id")?).bind(row.try_get::<i64,_>("deleted")?)
            .bind(row.try_get::<i64,_>("requests")?).bind(row.try_get::<Option<i64>,_>("first_at_ms")?)
            .bind(row.try_get::<i64,_>("last_at_ms")?).bind(row.try_get::<Option<String>,_>("records_sha256")?)
            .bind(row.try_get::<Option<i64>,_>("deleted_at_ms")?).execute(&mut **tx).await?;
    }
    drop(summary_rows);
    if summary_count != manifest.session_count {
        return Err(plan_changed_error().into());
    }

    let mut record_rows =
        sqlx::query("SELECT sequence,record_json FROM import_plan_records ORDER BY sequence")
            .fetch(&mut plan.connection);
    let mut record_count = 0_i64;
    while let Some(row) = record_rows.try_next().await? {
        record_count += 1;
        if row.try_get::<i64, _>("sequence")? != record_count {
            return Err(plan_changed_error().into());
        }
        let encoded: Vec<u8> = row.try_get("record_json")?;
        let record: ImportPlanRecord = serde_json::from_slice(&encoded)?;
        validate_plan_record(&record)?;
        let disposition = match record.correlation {
            ImportPlanCorrelation::Exact { .. } => "exact",
            ImportPlanCorrelation::Unlinked { .. } => "unlinked",
            ImportPlanCorrelation::Quarantined { .. } => "quarantine",
        };
        sqlx::query("INSERT INTO session_archive_snapshot_stage_records (batch_id,tenant_id,source,source_session_id,external_request_id,record_digest,disposition) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(&manifest.expected_output_sha256).bind(&tenant_id).bind(options.archive_source)
            .bind(&record.source_session_id).bind(&record.external_request_id).bind(&record.record_digest)
            .bind(disposition)
            .execute(&mut **tx).await?;
    }
    if record_count != manifest.record_count {
        return Err(plan_changed_error().into());
    }
    let staged_requests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_stage_records WHERE batch_id=$1 AND tenant_id=$2 AND source=$3")
        .bind(&manifest.expected_output_sha256).bind(&tenant_id).bind(options.archive_source).fetch_one(&mut **tx).await?;
    if staged_requests != manifest.request_count {
        return Err(plan_changed_error().into());
    }
    Ok(())
}

pub(super) async fn preflight_validated_snapshot_tombstones(
    db: &Database,
    options: &SessionArchiveImportOptions<'_>,
    plan: &mut ValidatedImportPlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const PREFLIGHT_BATCH: usize = 256;
    let tenant_id = db
        .session_archive_tenant_id(options.tenant_external_id)
        .await?;
    let mut rows = sqlx::query(
        "SELECT sequence,session_id,deleted_at_ms FROM import_plan_tombstones ORDER BY sequence",
    )
    .fetch(&mut plan.connection);
    let mut expected = 0_i64;
    let mut session_ids = Vec::with_capacity(PREFLIGHT_BATCH);
    while let Some(row) = rows.try_next().await? {
        expected += 1;
        if row.try_get::<i64, _>("sequence")? != expected {
            return Err(plan_changed_error().into());
        }
        let deleted_at_ms: i64 = row.try_get("deleted_at_ms")?;
        if deleted_at_ms < 0 {
            return Err(plan_changed_error().into());
        }
        session_ids.push(row.try_get("session_id")?);
        if session_ids.len() == PREFLIGHT_BATCH {
            db.preflight_session_archive_tombstones_batch(
                &tenant_id,
                options.archive_source,
                &session_ids,
            )
            .await?;
            session_ids.clear();
        }
    }
    db.preflight_session_archive_tombstones_batch(&tenant_id, options.archive_source, &session_ids)
        .await?;
    if expected != i64::try_from(plan.header.tombstone_count)? {
        return Err(plan_changed_error().into());
    }
    Ok(())
}

pub(super) async fn apply_validated_plan(
    db: &Database,
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    archive: &ArchiveStore,
    options: &SessionArchiveImportOptions<'_>,
    plan: &mut ValidatedImportPlan,
) -> Result<ApplyStats, Box<dyn std::error::Error + Send + Sync>> {
    let mut applied = ApplyStats::default();
    let mut seen = 0_u64;
    let mut rows = sqlx::query(
        "SELECT sequence, source_started_at, source_checkpoint_ms, external_request_id, record_json FROM import_plan_records ORDER BY source_checkpoint_ms ASC, external_request_id ASC, sequence ASC",
    )
    .fetch(&mut plan.connection);
    while let Some(row) = rows.try_next().await? {
        seen += 1;
        let encoded: Vec<u8> = row.try_get("record_json")?;
        let record: ImportPlanRecord = serde_json::from_slice(&encoded)?;
        validate_plan_record(&record)?;
        if row.try_get::<i64, _>("source_started_at")? != record.source_started_at
            || row.try_get::<i64, _>("source_checkpoint_ms")? != record.source_checkpoint_ms
            || row.try_get::<String, _>("external_request_id")? != record.external_request_id
        {
            return Err(plan_changed_error().into());
        }
        let request_json = load_structured_plan_request(archive, options, &record).await?;
        let committed = match &record.correlation {
            ImportPlanCorrelation::Exact {
                target,
                identity_proof_kind,
                identity_proof_digest,
                correlation_proof_digest,
            } => {
                let target: SessionArchiveTarget = target.clone().into();
                db.commit_session_archive_request_in_transaction(
                    tx,
                    SessionArchiveCommitInput {
                        tenant_external_id: options.tenant_external_id,
                        archive_source: options.archive_source,
                        external_request_id: &record.external_request_id,
                        source_session_id: &record.source_session_id,
                        target: &target,
                        record_digest: &record.record_digest,
                        request_digest: record.request_digest.as_deref(),
                        response_digest: record.response_digest.as_deref(),
                        request_object: record.request_object.as_deref(),
                        response_object: record.response_object.as_deref(),
                        request_json: request_json.as_ref(),
                        conversation_hints: &record.conversation_hints,
                        client_name: record.client_name.as_deref(),
                        source_started_at: record.source_started_at,
                        source_completed_at: record.source_completed_at,
                        identity_proof_kind,
                        identity_proof_digest,
                        correlation_proof_digest,
                        defer_checkpoint: plan
                            .header
                            .stable_snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.snapshot_schema_version == 2),
                    },
                )
                .await?
            }
            ImportPlanCorrelation::Unlinked { target } => {
                let target: SessionArchiveUnlinkedTarget = target.clone().into();
                db.commit_session_archive_unlinked_request_in_transaction(
                    tx,
                    SessionArchiveUnlinkedCommitInput {
                        tenant_external_id: options.tenant_external_id,
                        archive_source: options.archive_source,
                        external_request_id: &record.external_request_id,
                        source_session_id: &record.source_session_id,
                        target: &target,
                        record_digest: &record.record_digest,
                        request_digest: record.request_digest.as_deref(),
                        response_digest: record.response_digest.as_deref(),
                        request_object: record.request_object.as_deref(),
                        response_object: record.response_object.as_deref(),
                        request_json: request_json.as_ref(),
                        conversation_hints: &record.conversation_hints,
                        client_name: record.client_name.as_deref(),
                        source_started_at: record.source_started_at,
                        metadata: SessionArchiveUnlinkedMetadata {
                            source_completed_at: record.source_completed_at,
                            protocol: &record.protocol,
                            model: &record.model,
                            status_code: record.status_code,
                            duration_ms: record.duration_ms,
                            input_tokens: record.input_tokens,
                            output_tokens: record.output_tokens,
                            error_code: record.error_code.as_deref(),
                        },
                        defer_checkpoint: plan
                            .header
                            .stable_snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.snapshot_schema_version == 2),
                    },
                )
                .await?
            }
            ImportPlanCorrelation::Quarantined { target } => {
                let target: SessionArchiveQuarantineTarget = target.clone().into();
                let header = &plan.header;
                let batch_id = header.quarantine_batch_id.ok_or_else(plan_changed_error)?;
                let source_size_bytes = i64::try_from(header.source_size_bytes)?;
                let eligible_records = i64::try_from(header.record_count)?;
                let quarantine_records = i64::try_from(header.quarantine_records)?;
                let sequence: i64 = row.try_get("sequence")?;
                let committed = db
                    .commit_session_archive_quarantine_in_transaction(
                        tx,
                        SessionArchiveQuarantineCommitInput {
                            batch: SessionArchiveQuarantineBatchInput {
                                batch_id,
                                tenant_external_id: options.tenant_external_id,
                                archive_source: options.archive_source,
                                cpamp_source: options.cpamp_source,
                                source_digest: &header.source_blake3,
                                source_size_bytes,
                                eligible_records,
                                quarantine_records,
                                tenant_binding_kind: header
                                    .tenant_binding_kind
                                    .as_deref()
                                    .ok_or_else(plan_changed_error)?,
                                tenant_binding_proof: header
                                    .tenant_binding_proof
                                    .as_deref()
                                    .ok_or_else(plan_changed_error)?,
                                approved_by_service_id: header.approved_by_service_id,
                            },
                            sequence,
                            target: &target,
                            external_request_id: &record.external_request_id,
                            source_session_id: &record.source_session_id,
                            record_digest: &record.record_digest,
                            source_started_at: record.source_started_at,
                            source_completed_at: record.source_completed_at,
                            protocol: &record.protocol,
                            model: &record.model,
                            status_code: record.status_code,
                            duration_ms: record.duration_ms,
                            input_tokens: record.input_tokens,
                            output_tokens: record.output_tokens,
                            error_code: record.error_code.as_deref(),
                            request_digest: record.request_digest.as_deref(),
                            response_digest: record.response_digest.as_deref(),
                            request_object: record.request_object.as_deref(),
                            response_object: record.response_object.as_deref(),
                            defer_checkpoint: plan
                                .header
                                .stable_snapshot
                                .as_ref()
                                .is_some_and(|snapshot| snapshot.snapshot_schema_version == 2),
                        },
                    )
                    .await?;
                applied.quarantine_imported += u64::from(committed);
                applied.quarantine_replayed += u64::from(!committed);
                applied.legacy_imported_records = applied
                    .legacy_imported_records
                    .saturating_add(u64::from(committed));
                false
            }
        };
        applied.imported += u64::from(committed);
        applied.legacy_imported_records = applied
            .legacy_imported_records
            .saturating_add(u64::from(committed));
        applied.last_checkpoint = Some((
            record.source_checkpoint_ms,
            record.external_request_id.clone(),
        ));
    }
    if seen != plan.record_count {
        return Err(plan_changed_error().into());
    }
    Ok(applied)
}

pub(super) async fn apply_validated_snapshot_tombstones(
    db: &Database,
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    options: &SessionArchiveImportOptions<'_>,
    plan: &mut ValidatedImportPlan,
    manifest: &StableDeltaManifest,
    applied: &ApplyStats,
) -> Result<crate::db::SessionArchiveSnapshotApplyResult, Box<dyn std::error::Error + Send + Sync>>
{
    if !matches!(manifest.snapshot_schema_version, 1 | 2) {
        return Err("unsupported stable snapshot schema".into());
    }
    let expected = ImportPlanStableSnapshot {
        source_fingerprint: manifest.source_fingerprint.clone(),
        sequence: manifest.sequence,
        offline_full_snapshot: manifest.offline_full_snapshot,
        output_sha256: manifest.expected_output_sha256.clone(),
        prior_output_sha256: manifest.prior_output_sha256.clone(),
        prior_source_ingest_fence: manifest.prior_source_ingest_fence,
        snapshot_schema_version: manifest.snapshot_schema_version,
        ingest_fence: manifest.ingest_fence,
        tombstone_safe_after_ingest_fence: manifest.tombstone_safe_after_ingest_fence,
        session_set_sha256: manifest.session_set_sha256.clone(),
        session_count: manifest.session_count,
        request_count: manifest.request_count,
        deleted_session_count: manifest.deleted_session_count,
    };
    if plan.header.stable_snapshot.as_ref() != Some(&expected) {
        return Err(plan_changed_error().into());
    }
    // Schema v2 is already fully sealed into bounded target staging. Keeping
    // million-session projections out of process memory is part of the import
    // contract; legacy v1 has neither summary controls nor tombstones.
    let tombstones: Vec<SessionArchiveTombstoneInput> = Vec::new();
    let present_summaries: Vec<SessionArchivePresentSummaryInput> = Vec::new();
    let legacy_imported_records = i64::try_from(applied.legacy_imported_records)?;
    let legacy_checkpoint = if manifest.snapshot_schema_version == 2 {
        applied
            .last_checkpoint
            .as_ref()
            .map(
                |(watermark_ms, watermark_request_id)| SessionArchiveLegacyCheckpointInput {
                    watermark_ms: *watermark_ms,
                    watermark_request_id,
                    imported_records: legacy_imported_records,
                },
            )
    } else {
        None
    };
    Ok(db
        .apply_session_archive_snapshot_in_transaction(
            tx,
            SessionArchiveSnapshotApplyInput {
                tenant_external_id: options.tenant_external_id,
                archive_source: options.archive_source,
                source_fingerprint: &manifest.source_fingerprint,
                sequence: manifest.sequence,
                offline_full_snapshot: manifest.offline_full_snapshot,
                output_sha256: &manifest.expected_output_sha256,
                prior_output_sha256: manifest.prior_output_sha256.as_deref(),
                prior_source_ingest_fence: manifest.prior_source_ingest_fence,
                snapshot_schema_version: manifest.snapshot_schema_version,
                ingest_fence: manifest.ingest_fence,
                tombstone_safe_after_ingest_fence: manifest.tombstone_safe_after_ingest_fence,
                session_set_sha256: &manifest.session_set_sha256,
                session_count: manifest.session_count,
                request_count: manifest.request_count,
                deleted_session_count: manifest.deleted_session_count,
                legacy_checkpoint,
                staged_batch_id: (manifest.snapshot_schema_version == 2)
                    .then_some(manifest.expected_output_sha256.as_str()),
                present_summaries: &present_summaries,
                tombstones: &tombstones,
            },
        )
        .await?)
}

#[derive(Default)]
pub(super) struct ApplyStats {
    pub(super) imported: u64,
    pub(super) quarantine_imported: u64,
    pub(super) quarantine_replayed: u64,
    pub(super) legacy_imported_records: u64,
    pub(super) last_checkpoint: Option<(i64, String)>,
}

pub(super) async fn load_structured_plan_request(
    archive: &ArchiveStore,
    options: &SessionArchiveImportOptions<'_>,
    record: &ImportPlanRecord,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    if !record.request_is_structured {
        return Ok(None);
    }
    let location = record
        .request_object
        .as_deref()
        .ok_or_else(plan_changed_error)?;
    let expected_digest = record
        .request_digest
        .as_deref()
        .ok_or_else(plan_changed_error)?;
    let body = archive
        .get_bounded(location, options.max_line_bytes)
        .await?;
    if digest(&body) != expected_digest {
        return Err("planned request CAS object failed its content digest".into());
    }
    let value: Value = serde_json::from_slice(&body)?;
    if !matches!(value, Value::Array(_) | Value::Object(_)) {
        return Err(plan_changed_error().into());
    }
    Ok(Some(value))
}
