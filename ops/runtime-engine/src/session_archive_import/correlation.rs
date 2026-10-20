use super::*;

pub(super) async fn preflight_pass(
    db: &Database,
    options: &SessionArchiveImportOptions<'_>,
    lower_bound: i64,
    input: &mut ReadOnlyInput,
    stable_manifest: Option<&StableDeltaManifest>,
    expected_output_sha256: Option<&str>,
) -> Result<(SessionArchiveImportStats, blake3::Hash), Box<dyn std::error::Error + Send + Sync>> {
    const TOMBSTONE_PREFLIGHT_BATCH: usize = 256;
    let mut stats = SessionArchiveImportStats::default();
    let mut hasher = blake3::Hasher::new();
    let mut output_sha256 = Sha256::new();
    let mut projection = stable_manifest
        .filter(|manifest| manifest.snapshot_schema_version == 2)
        .map(StableProjectionValidator::new)
        .transpose()?;
    let tenant_id = if projection.is_some() {
        Some(
            db.session_archive_tenant_id(options.tenant_external_id)
                .await?,
        )
    } else {
        None
    };
    let mut tombstone_sessions = Vec::with_capacity(TOMBSTONE_PREFLIGHT_BATCH);
    while let Some(line) = read_bounded_line(&mut input.reader, options.max_line_bytes).await? {
        hasher.update(&line);
        output_sha256.update(&line);
        let Some(parsed) = parse_archive_line(&line)? else {
            continue;
        };
        let (record, digest) = match parsed {
            ParsedArchiveLine::Summary(summary) => {
                projection
                    .as_mut()
                    .ok_or("stable session summary is missing its schema-v2 manifest")?
                    .observe_summary(&summary)?;
                stats.tombstones_scanned += u64::from(summary.deleted);
                if summary.deleted {
                    tombstone_sessions.push(summary.session_id.clone());
                    if tombstone_sessions.len() == TOMBSTONE_PREFLIGHT_BATCH {
                        db.preflight_session_archive_tombstones_batch(
                            tenant_id.as_deref().ok_or("missing stable tenant")?,
                            options.archive_source,
                            &tombstone_sessions,
                        )
                        .await?;
                        tombstone_sessions.clear();
                    }
                }
                continue;
            }
            ParsedArchiveLine::Record(record, digest) => {
                if let Some(projection) = projection.as_mut() {
                    projection.observe_record(&record, &line)?;
                }
                (record, digest)
            }
        };
        stats.scanned += 1;
        if !archive_record_inside_overlap(&record, lower_bound) {
            stats.before_overlap += 1;
            continue;
        }
        stats.eligible += 1;
        match match_record(
            db,
            options,
            &record,
            &digest,
            stable_manifest.is_some_and(|manifest| manifest.snapshot_schema_version == 2),
        )
        .await
        {
            Ok(SessionArchiveImportMatch::Correlated(correlation)) => {
                preflight_gap_compatibility(
                    db,
                    options,
                    &record,
                    correlation.as_ref(),
                    stable_manifest.is_some_and(|manifest| manifest.snapshot_schema_version == 2),
                )
                .await?;
                stats.mapped += 1;
                stats.replayed += u64::from(correlation.replay());
            }
            Ok(SessionArchiveImportMatch::Quarantine(_))
                if options.quarantine_unknown_identities =>
            {
                stats.quarantined += 1;
            }
            Ok(SessionArchiveImportMatch::Quarantine(_)) => stats.unmapped += 1,
            Err(AppError::BadRequest(_)) if options.allow_unmapped => stats.unmapped += 1,
            Err(AppError::BadRequest(error)) => return Err(AppError::BadRequest(error).into()),
            Err(error) => return Err(error.into()),
        }
    }
    if !tombstone_sessions.is_empty() {
        db.preflight_session_archive_tombstones_batch(
            tenant_id.as_deref().ok_or("missing stable tenant")?,
            options.archive_source,
            &tombstone_sessions,
        )
        .await?;
    }
    if let Some(projection) = projection {
        projection.finish()?;
    }
    if let Some(expected) = expected_output_sha256
        && format!("{:x}", output_sha256.finalize()) != expected
    {
        return Err("archive input descriptor does not match its delta manifest digest".into());
    }
    if stats.tombstones_scanned > 0
        && stable_manifest.is_none_or(|manifest| {
            manifest.snapshot_schema_version != 2
                || manifest.deleted_session_count
                    != i64::try_from(stats.tombstones_scanned).unwrap_or(-1)
        })
    {
        return Err(
            "session tombstones require a matching stable snapshot schema-v2 manifest".into(),
        );
    }
    if let Some(manifest) = stable_manifest
        && (manifest.record_count != i64::try_from(stats.scanned).unwrap_or(-1)
            || manifest.request_count < manifest.record_count
            || manifest.deleted_session_count
                != i64::try_from(stats.tombstones_scanned).unwrap_or(-1))
    {
        return Err("stable snapshot manifest audit counts disagree with the sealed input".into());
    }
    Ok((stats, hasher.finalize()))
}

pub(super) async fn match_record(
    db: &Database,
    options: &SessionArchiveImportOptions<'_>,
    record: &ArchiveRecord,
    record_digest: &str,
    allow_stable_replacement: bool,
) -> Result<SessionArchiveImportMatch, AppError> {
    let source_key_hash = archived_credential_hash(record)?;
    db.match_session_archive_import(SessionArchiveImportMatchInput {
        tenant_external_id: options.tenant_external_id,
        cpamp_source: options.cpamp_source,
        archive_source: options.archive_source,
        external_request_id: &record.request_id,
        source_session_id: &record.session_id,
        started_at: record.started_at.timestamp_millis(),
        requested_model: nonempty(&record.requested_model),
        resolved_model: nonempty(&record.model),
        source_key_hash: source_key_hash.as_deref(),
        input_tokens: None,
        output_tokens: None,
        record_digest,
        time_tolerance_ms: options.time_tolerance_ms,
        allow_stable_replacement,
    })
    .await
}

pub(super) async fn preflight_gap_compatibility(
    db: &Database,
    options: &SessionArchiveImportOptions<'_>,
    record: &ArchiveRecord,
    correlation: &SessionArchiveCorrelation,
    allow_stable_replacement: bool,
) -> Result<(), AppError> {
    let SessionArchiveCorrelation::Exact { target, .. } = correlation else {
        return Ok(());
    };
    if target.replay {
        return Ok(());
    }

    if allow_stable_replacement
        && db
            .preflight_session_archive_replacement_locator(
                options.tenant_external_id,
                options.archive_source,
                &record.request_id,
                target.target_request_id,
            )
            .await?
    {
        return Ok(());
    }

    let request_object = payload_content_location(&record.request)?;
    let response_object = payload_content_location(&record.response)?;
    let current = db
        .request_archive_refs_for_tenant(options.tenant_external_id, target.target_request_id)
        .await?;
    gap_compatible(&current.request_object, request_object.as_deref())?;
    if let Some(current_response) = current.response_object.as_deref() {
        gap_compatible(current_response, response_object.as_deref())?;
    }
    Ok(())
}

pub(super) fn payload_content_location(value: &Value) -> Result<Option<String>, AppError> {
    payload_bytes(value)
        .map(|body| body.map(|body| content_location(&digest(&body))))
        .map_err(|_| AppError::Internal)
}

pub(super) fn content_location(digest: &str) -> String {
    format!("objects/blake3/{}/{digest}", &digest[..2])
}

pub(super) fn quarantine_batch_id(
    tenant_external_id: &str,
    source: &str,
    source_digest: &str,
) -> Uuid {
    let digest = blake3::hash(
        format!(
            "memeloop-session-archive-quarantine-batch-v1\0{tenant_external_id}\0{source}\0{source_digest}"
        )
        .as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub(super) fn gap_compatible(current: &str, replacement: Option<&str>) -> Result<(), AppError> {
    if replacement.is_none() || current.starts_with("gap://") || Some(current) == replacement {
        return Ok(());
    }
    Err(AppError::BadRequest(
        "archive import refused to overwrite an existing object".into(),
    ))
}
