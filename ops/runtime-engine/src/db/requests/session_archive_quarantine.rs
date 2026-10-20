use super::super::*;
use super::{
    session_archive::{
        archive_proof_digest, deterministic_archive_request_id, normalize_archive_source_key_hash,
    },
    session_archive_commit::{advance_session_archive_checkpoint, session_archive_checkpoint_ms},
};

const QUARANTINE_REASON_MISSING: &str = "missing_credential_hash";
const QUARANTINE_REASON_UNPROVEN: &str = "unproven_identity";

#[derive(Clone, Debug)]
pub struct SessionArchiveImportMatchInput<'a> {
    pub tenant_external_id: &'a str,
    pub cpamp_source: &'a str,
    pub archive_source: &'a str,
    pub external_request_id: &'a str,
    pub source_session_id: &'a str,
    pub started_at: i64,
    pub requested_model: Option<&'a str>,
    pub resolved_model: Option<&'a str>,
    pub source_key_hash: Option<&'a str>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub record_digest: &'a str,
    pub time_tolerance_ms: i64,
    pub allow_stable_replacement: bool,
}

#[derive(Clone, Debug)]
pub struct SessionArchiveQuarantineTarget {
    pub tenant_id: Uuid,
    pub quarantine_id: Uuid,
    pub reason_code: String,
    /// One-way grouping proof. It is persisted for internal reconciliation but
    /// is deliberately absent from every API view.
    pub identity_claim_digest: Option<String>,
    pub proof_digest: String,
}

#[derive(Clone, Debug)]
pub enum SessionArchiveImportMatch {
    Correlated(Box<SessionArchiveCorrelation>),
    Quarantine(SessionArchiveQuarantineTarget),
}

pub struct SessionArchiveQuarantineBatchInput<'a> {
    pub batch_id: Uuid,
    pub tenant_external_id: &'a str,
    pub archive_source: &'a str,
    pub cpamp_source: &'a str,
    pub source_digest: &'a str,
    pub source_size_bytes: i64,
    pub eligible_records: i64,
    pub quarantine_records: i64,
    pub tenant_binding_kind: &'a str,
    pub tenant_binding_proof: &'a str,
    pub approved_by_service_id: Option<Uuid>,
}

pub struct SessionArchiveQuarantineCommitInput<'a> {
    pub batch: SessionArchiveQuarantineBatchInput<'a>,
    pub sequence: i64,
    pub target: &'a SessionArchiveQuarantineTarget,
    pub external_request_id: &'a str,
    pub source_session_id: &'a str,
    pub record_digest: &'a str,
    pub source_started_at: i64,
    pub source_completed_at: Option<i64>,
    pub protocol: &'a str,
    pub model: &'a str,
    pub status_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub error_code: Option<&'a str>,
    pub request_digest: Option<&'a str>,
    pub response_digest: Option<&'a str>,
    pub request_object: Option<&'a str>,
    pub response_object: Option<&'a str>,
    pub defer_checkpoint: bool,
}

#[derive(Clone, Debug)]
pub struct SessionArchiveQuarantineFilter<'a> {
    pub tenant_external_id: &'a str,
    pub state: Option<&'a str>,
    pub limit: i64,
    pub before_started_at: Option<i64>,
    pub before_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionArchiveQuarantineRecordView {
    pub id: Uuid,
    pub tenant_external_id: String,
    pub source: String,
    pub external_request_id: String,
    pub record_digest: String,
    pub reason_code: String,
    pub source_started_at: i64,
    pub source_completed_at: Option<i64>,
    pub protocol: String,
    pub model: String,
    pub status_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub error_code: Option<String>,
    pub state: String,
}

pub struct SessionArchiveQuarantineResolutionInput<'a> {
    pub tenant_external_id: &'a str,
    pub quarantine_id: Uuid,
    pub action: &'a str,
    pub key_id: Option<Uuid>,
    pub expected_record_digest: &'a str,
    pub evidence_digest: &'a str,
    pub note: Option<&'a str>,
    pub idempotency_key: &'a str,
    pub resolved_by_service_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionArchiveQuarantineResolutionView {
    pub id: Uuid,
    pub quarantine_id: Uuid,
    pub action: String,
    pub key_id: Option<Uuid>,
    pub evidence_digest: String,
    pub created_at: i64,
}

impl Database {
    /// Classifies identity absence separately from malformed or ambiguous
    /// evidence. Only the former may enter quarantine; every other proof error
    /// remains fatal for the sealed batch.
    pub async fn match_session_archive_import(
        &self,
        input: SessionArchiveImportMatchInput<'_>,
    ) -> Result<SessionArchiveImportMatch, AppError> {
        if !is_sha256_hex(input.record_digest)
            || !valid_archive_identifier(input.cpamp_source, 256)
            || !valid_archive_identifier(input.archive_source, 256)
            || !valid_archive_identifier(input.external_request_id, 512)
            || !valid_archive_identifier(input.source_session_id, 512)
        {
            return Err(AppError::BadRequest(
                "archive quarantine proof input is invalid".into(),
            ));
        }
        let tenant_id = tenant_id(self, input.tenant_external_id).await?;
        let normalized_hash = match input.source_key_hash.map(str::trim) {
            None | Some("") => None,
            Some(value) => Some(normalize_archive_source_key_hash(value).ok_or_else(|| {
                AppError::BadRequest("archive credential hash is malformed".into())
            })?),
        };

        let reason_code = if normalized_hash.is_some() {
            QUARANTINE_REASON_UNPROVEN
        } else {
            QUARANTINE_REASON_MISSING
        };
        let identity_claim_digest = normalized_hash.as_deref().map(|value| {
            archive_proof_digest(
                "memeloop-session-archive-quarantine-identity-v1",
                &[input.tenant_external_id, input.archive_source, value],
            )
        });
        let proof_digest = archive_proof_digest(
            "memeloop-session-archive-quarantine-v1",
            &[
                input.tenant_external_id,
                input.archive_source,
                input.external_request_id,
                reason_code,
                identity_claim_digest.as_deref().unwrap_or("none"),
                input.record_digest,
            ],
        );

        // Once an external request enters quarantine, later versions remain in
        // quarantine even if a CPAMP mapping appears.  The immutable prior
        // version and its resolution continue to be independently addressable.
        if let Some(existing) = sqlx::query(
            "SELECT version.id,version.record_digest,version.source_session_id,version.identity_claim_digest,version.reason_code,version.proof_digest FROM session_archive_quarantine_record_heads head JOIN session_archive_quarantine_record_versions version ON version.id=head.quarantine_id WHERE head.tenant_id=$1 AND head.source=$2 AND head.external_request_id=$3",
        )
        .bind(tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .fetch_optional(&self.pool)
        .await?
        {
            let same_evidence = existing.try_get::<String, _>("record_digest")?
                == input.record_digest
                && existing.try_get::<String, _>("source_session_id")?
                    == input.source_session_id;
            let historical = if same_evidence {
                None
            } else {
                sqlx::query(
                    "SELECT id,identity_claim_digest,reason_code,proof_digest FROM session_archive_quarantine_record_versions WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3 AND record_digest=$4 AND source_session_id=$5",
                )
                .bind(tenant_id.to_string())
                .bind(input.archive_source)
                .bind(input.external_request_id)
                .bind(input.record_digest)
                .bind(input.source_session_id)
                .fetch_optional(&self.pool)
                .await?
            };
            let replay = if same_evidence {
                Some(&existing)
            } else {
                historical.as_ref()
            };
            if let Some(replay) = replay
                && (replay.try_get::<Option<String>, _>("identity_claim_digest")?
                    != identity_claim_digest
                    || replay.try_get::<String, _>("proof_digest")? != proof_digest
                    || replay.try_get::<String, _>("reason_code")? != reason_code)
            {
                return Err(AppError::Conflict(
                    "quarantined archive record changed on replay".into(),
                ));
            }
            return Ok(SessionArchiveImportMatch::Quarantine(
                SessionArchiveQuarantineTarget {
                    tenant_id,
                    quarantine_id: if same_evidence {
                        parse_uuid(existing.try_get("id")?)?
                    } else if let Some(historical) = historical {
                        parse_uuid(historical.try_get("id")?)?
                    } else {
                        deterministic_quarantine_version_id(
                            input.tenant_external_id,
                            input.archive_source,
                            input.external_request_id,
                            input.record_digest,
                            input.source_session_id,
                        )
                    },
                    reason_code: reason_code.to_owned(),
                    identity_claim_digest,
                    proof_digest,
                },
            ));
        }

        if let Some(source_key_hash) = normalized_hash.as_deref()
            && self
                .resolve_session_archive_identity_optional(
                    input.tenant_external_id,
                    input.cpamp_source,
                    source_key_hash,
                )
                .await?
                .is_some()
        {
            return self
                .correlate_session_archive_request(SessionArchiveMatchInput {
                    tenant_external_id: input.tenant_external_id,
                    cpamp_source: input.cpamp_source,
                    archive_source: input.archive_source,
                    external_request_id: input.external_request_id,
                    started_at: input.started_at,
                    requested_model: input.requested_model,
                    resolved_model: input.resolved_model,
                    source_key_hash,
                    input_tokens: input.input_tokens,
                    output_tokens: input.output_tokens,
                    record_digest: input.record_digest,
                    time_tolerance_ms: input.time_tolerance_ms,
                    allow_stable_replacement: input.allow_stable_replacement,
                })
                .await
                .map(Box::new)
                .map(SessionArchiveImportMatch::Correlated);
        }

        let quarantine_id = deterministic_archive_request_id(
            input.tenant_external_id,
            input.archive_source,
            input.external_request_id,
        );
        Ok(SessionArchiveImportMatch::Quarantine(
            SessionArchiveQuarantineTarget {
                tenant_id,
                quarantine_id,
                reason_code: reason_code.to_owned(),
                identity_claim_digest,
                proof_digest,
            },
        ))
    }

    pub async fn commit_session_archive_quarantine(
        &self,
        input: SessionArchiveQuarantineCommitInput<'_>,
    ) -> Result<bool, AppError> {
        let mut tx = self.begin_write_transaction().await?;
        let result = self
            .commit_session_archive_quarantine_in_transaction(&mut tx, input)
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

    pub(crate) async fn commit_session_archive_quarantine_in_transaction(
        &self,
        tx: &mut Transaction<'_, Any>,
        input: SessionArchiveQuarantineCommitInput<'_>,
    ) -> Result<bool, AppError> {
        validate_quarantine_commit(&input)?;
        let expected_tenant = parse_uuid(
            sqlx::query_scalar::<_, String>("SELECT id FROM tenants WHERE external_id=$1")
                .bind(input.batch.tenant_external_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(AppError::NotFound)?,
        )?;
        if expected_tenant != input.target.tenant_id {
            return Err(AppError::NotFound);
        }
        let checkpoint_ms =
            session_archive_checkpoint_ms(input.source_started_at, input.source_completed_at)?;
        let now = unix_millis();
        let batch_inserted = sqlx::query(
            "INSERT INTO session_archive_quarantine_batches (id, tenant_id, source, cpamp_source, source_digest, source_size_bytes, eligible_records, quarantine_records, tenant_binding_kind, tenant_binding_proof, approved_by_service_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO NOTHING",
        )
        .bind(input.batch.batch_id.to_string())
        .bind(expected_tenant.to_string())
        .bind(input.batch.archive_source)
        .bind(input.batch.cpamp_source)
        .bind(input.batch.source_digest)
        .bind(input.batch.source_size_bytes)
        .bind(input.batch.eligible_records)
        .bind(input.batch.quarantine_records)
        .bind(input.batch.tenant_binding_kind)
        .bind(input.batch.tenant_binding_proof)
        .bind(input.batch.approved_by_service_id.map(|id| id.to_string()))
        .bind(now)
        .execute(&mut **tx)
        .await?;
        if batch_inserted.rows_affected() == 0 {
            let row = sqlx::query("SELECT tenant_id,source,cpamp_source,source_digest,source_size_bytes,eligible_records,quarantine_records,tenant_binding_kind,tenant_binding_proof,approved_by_service_id FROM session_archive_quarantine_batches WHERE id=$1")
                .bind(input.batch.batch_id.to_string())
                .fetch_one(&mut **tx).await?;
            let compatible = row.try_get::<String, _>("tenant_id")? == expected_tenant.to_string()
                && row.try_get::<String, _>("source")? == input.batch.archive_source
                && row.try_get::<String, _>("cpamp_source")? == input.batch.cpamp_source
                && row.try_get::<String, _>("source_digest")? == input.batch.source_digest
                && row.try_get::<i64, _>("source_size_bytes")? == input.batch.source_size_bytes
                && row.try_get::<i64, _>("eligible_records")? == input.batch.eligible_records
                && row.try_get::<i64, _>("quarantine_records")? == input.batch.quarantine_records
                && row.try_get::<String, _>("tenant_binding_kind")?
                    == input.batch.tenant_binding_kind
                && row.try_get::<String, _>("tenant_binding_proof")?
                    == input.batch.tenant_binding_proof
                && row.try_get::<Option<String>, _>("approved_by_service_id")?
                    == input.batch.approved_by_service_id.map(|id| id.to_string());
            if !compatible {
                return Err(AppError::Conflict(
                    "quarantine batch seal changed on replay".into(),
                ));
            }
        }

        let head = sqlx::query(
            "SELECT quarantine_id,record_digest,source_session_id FROM session_archive_quarantine_record_heads WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3",
        )
        .bind(expected_tenant.to_string())
        .bind(input.batch.archive_source)
        .bind(input.external_request_id)
        .fetch_optional(&mut **tx)
        .await?;
        let historical_quarantine_id = sqlx::query_scalar::<_, String>(
            "SELECT id FROM session_archive_quarantine_record_versions WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3 AND record_digest=$4 AND source_session_id=$5",
        )
        .bind(expected_tenant.to_string())
        .bind(input.batch.archive_source)
        .bind(input.external_request_id)
        .bind(input.record_digest)
        .bind(input.source_session_id)
        .fetch_optional(&mut **tx)
        .await?
        .map(parse_uuid)
        .transpose()?;
        let expected_quarantine_id = match head.as_ref() {
            None => deterministic_archive_request_id(
                input.batch.tenant_external_id,
                input.batch.archive_source,
                input.external_request_id,
            ),
            Some(row)
                if row.try_get::<String, _>("record_digest")? == input.record_digest
                    && row.try_get::<String, _>("source_session_id")?
                        == input.source_session_id =>
            {
                parse_uuid(row.try_get("quarantine_id")?)?
            }
            Some(_) if historical_quarantine_id.is_some() => {
                historical_quarantine_id.expect("historical quarantine ID presence was checked")
            }
            Some(_) => deterministic_quarantine_version_id(
                input.batch.tenant_external_id,
                input.batch.archive_source,
                input.external_request_id,
                input.record_digest,
                input.source_session_id,
            ),
        };
        if input.target.quarantine_id != expected_quarantine_id {
            return Err(AppError::Conflict(
                "quarantine head changed after import planning".into(),
            ));
        }

        let inserted = sqlx::query(
            "INSERT INTO session_archive_quarantine_record_versions (id,tenant_id,source,cpamp_source,external_request_id,source_session_id,record_digest,identity_claim_digest,reason_code,proof_digest,source_started_at,source_completed_at,protocol,model,status_code,duration_ms,input_tokens,output_tokens,error_code,request_digest,response_digest,request_object,response_object,quarantined_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) ON CONFLICT(id) DO NOTHING",
        )
        .bind(expected_quarantine_id.to_string())
        .bind(expected_tenant.to_string())
        .bind(input.batch.archive_source)
        .bind(input.batch.cpamp_source)
        .bind(input.external_request_id)
        .bind(input.source_session_id)
        .bind(input.record_digest)
        .bind(input.target.identity_claim_digest.as_deref())
        .bind(&input.target.reason_code)
        .bind(&input.target.proof_digest)
        .bind(input.source_started_at)
        .bind(input.source_completed_at)
        .bind(input.protocol)
        .bind(input.model)
        .bind(input.status_code)
        .bind(input.duration_ms)
        .bind(input.input_tokens)
        .bind(input.output_tokens)
        .bind(input.error_code)
        .bind(input.request_digest)
        .bind(input.response_digest)
        .bind(input.request_object)
        .bind(input.response_object)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            ensure_quarantine_replay(tx, &input).await?;
        }

        // Preserve the v1 canonical row and membership for existing readers,
        // but never mutate them when a corrected version or session move is
        // observed.
        let legacy_quarantine_id = deterministic_archive_request_id(
            input.batch.tenant_external_id,
            input.batch.archive_source,
            input.external_request_id,
        );
        if expected_quarantine_id == legacy_quarantine_id {
            sqlx::query(
                "INSERT INTO session_archive_quarantine_records (id,tenant_id,source,cpamp_source,external_request_id,record_digest,identity_claim_digest,reason_code,proof_digest,source_started_at,source_completed_at,protocol,model,status_code,duration_ms,input_tokens,output_tokens,error_code,request_digest,response_digest,request_object,response_object,quarantined_at,source_session_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) ON CONFLICT(tenant_id,source,external_request_id) DO NOTHING",
            )
            .bind(expected_quarantine_id.to_string())
            .bind(expected_tenant.to_string())
            .bind(input.batch.archive_source)
            .bind(input.batch.cpamp_source)
            .bind(input.external_request_id)
            .bind(input.record_digest)
            .bind(input.target.identity_claim_digest.as_deref())
            .bind(&input.target.reason_code)
            .bind(&input.target.proof_digest)
            .bind(input.source_started_at)
            .bind(input.source_completed_at)
            .bind(input.protocol)
            .bind(input.model)
            .bind(input.status_code)
            .bind(input.duration_ms)
            .bind(input.input_tokens)
            .bind(input.output_tokens)
            .bind(input.error_code)
            .bind(input.request_digest)
            .bind(input.response_digest)
            .bind(input.request_object)
            .bind(input.response_object)
            .bind(now)
            .bind(input.source_session_id)
            .execute(&mut **tx)
            .await?;
            let membership = sqlx::query("INSERT INTO session_archive_quarantine_batch_records (tenant_id,batch_id,quarantine_id,sequence,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(expected_tenant.to_string())
                .bind(input.batch.batch_id.to_string())
                .bind(expected_quarantine_id.to_string())
                .bind(input.sequence)
                .bind(now)
                .execute(&mut **tx).await?;
            if membership.rows_affected() == 0 {
                let row = sqlx::query("SELECT quarantine_id,sequence FROM session_archive_quarantine_batch_records WHERE batch_id=$1 AND sequence=$2")
                    .bind(input.batch.batch_id.to_string())
                    .bind(input.sequence)
                    .fetch_one(&mut **tx).await?;
                if row.try_get::<String, _>("quarantine_id")? != expected_quarantine_id.to_string()
                    || row.try_get::<i64, _>("sequence")? != input.sequence
                {
                    return Err(AppError::Conflict(
                        "quarantine legacy batch membership changed on replay".into(),
                    ));
                }
            }
        }

        let occurrence = sqlx::query("INSERT INTO session_archive_quarantine_occurrences (tenant_id,batch_id,sequence,quarantine_id,record_digest,source_session_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
            .bind(expected_tenant.to_string())
            .bind(input.batch.batch_id.to_string())
            .bind(input.sequence)
            .bind(expected_quarantine_id.to_string())
            .bind(input.record_digest)
            .bind(input.source_session_id)
            .bind(now)
            .execute(&mut **tx).await?;
        if occurrence.rows_affected() == 0 {
            let existing = sqlx::query("SELECT tenant_id,quarantine_id,record_digest,source_session_id FROM session_archive_quarantine_occurrences WHERE batch_id=$1 AND sequence=$2")
                .bind(input.batch.batch_id.to_string())
                .bind(input.sequence)
                .fetch_one(&mut **tx).await?;
            if existing.try_get::<String, _>("tenant_id")? != expected_tenant.to_string()
                || existing.try_get::<String, _>("quarantine_id")?
                    != expected_quarantine_id.to_string()
                || existing.try_get::<String, _>("record_digest")? != input.record_digest
                || existing.try_get::<String, _>("source_session_id")? != input.source_session_id
            {
                return Err(AppError::Conflict(
                    "quarantine batch occurrence changed on replay".into(),
                ));
            }
        } else {
            sqlx::query("INSERT INTO session_archive_quarantine_record_heads (tenant_id,source,external_request_id,quarantine_id,record_digest,source_session_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,source,external_request_id) DO UPDATE SET quarantine_id=excluded.quarantine_id,record_digest=excluded.record_digest,source_session_id=excluded.source_session_id,updated_at=excluded.updated_at")
                .bind(expected_tenant.to_string())
                .bind(input.batch.archive_source)
                .bind(input.external_request_id)
                .bind(expected_quarantine_id.to_string())
                .bind(input.record_digest)
                .bind(input.source_session_id)
                .bind(now)
                .execute(&mut **tx).await?;
        }
        if !input.defer_checkpoint {
            advance_session_archive_checkpoint(
                tx,
                expected_tenant,
                input.batch.archive_source,
                checkpoint_ms,
                input.external_request_id,
                inserted.rows_affected() == 1,
                now,
            )
            .await?;
        }
        Ok(inserted.rows_affected() == 1)
    }

    pub async fn list_session_archive_quarantine(
        &self,
        filter: SessionArchiveQuarantineFilter<'_>,
    ) -> Result<Vec<SessionArchiveQuarantineRecordView>, AppError> {
        if filter
            .state
            .is_some_and(|state| !matches!(state, "pending" | "resolved" | "dismissed"))
        {
            return Err(AppError::BadRequest("invalid quarantine state".into()));
        }
        let before_started_at = filter.before_started_at.unwrap_or(i64::MAX);
        let before_id = filter.before_id.unwrap_or(Uuid::max()).to_string();
        let rows = sqlx::query(
            "SELECT q.id,t.external_id AS tenant_external_id,q.source,q.external_request_id,q.record_digest,q.reason_code,q.source_started_at,q.source_completed_at,q.protocol,q.model,q.status_code,q.duration_ms,q.input_tokens,q.output_tokens,q.error_code,CASE WHEN r.action='dismiss' THEN 'dismissed' WHEN r.id IS NOT NULL THEN 'resolved' ELSE 'pending' END AS state FROM session_archive_quarantine_record_heads h JOIN session_archive_quarantine_record_versions q ON q.id=h.quarantine_id JOIN tenants t ON t.id=q.tenant_id LEFT JOIN session_archive_quarantine_resolutions r ON r.quarantine_id=q.id WHERE t.external_id=$1 AND ($2='' OR CASE WHEN r.action='dismiss' THEN 'dismissed' WHEN r.id IS NOT NULL THEN 'resolved' ELSE 'pending' END=$2) AND (q.source_started_at<$3 OR (q.source_started_at=$3 AND q.id<$4)) ORDER BY q.source_started_at DESC,q.id DESC LIMIT $5",
        )
        .bind(filter.tenant_external_id)
        .bind(filter.state.unwrap_or_default())
        .bind(before_started_at)
        .bind(before_id)
        .bind(filter.limit.clamp(1, 100) + 1)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .take(filter.limit.clamp(1, 100) as usize)
            .map(quarantine_view)
            .collect()
    }

    pub async fn get_session_archive_quarantine(
        &self,
        tenant_external_id: &str,
        quarantine_id: Uuid,
    ) -> Result<SessionArchiveQuarantineRecordView, AppError> {
        let row = sqlx::query(
            "SELECT q.id,t.external_id AS tenant_external_id,q.source,q.external_request_id,q.record_digest,q.reason_code,q.source_started_at,q.source_completed_at,q.protocol,q.model,q.status_code,q.duration_ms,q.input_tokens,q.output_tokens,q.error_code,CASE WHEN r.action='dismiss' THEN 'dismissed' WHEN r.id IS NOT NULL THEN 'resolved' ELSE 'pending' END AS state FROM session_archive_quarantine_record_versions q JOIN tenants t ON t.id=q.tenant_id LEFT JOIN session_archive_quarantine_resolutions r ON r.quarantine_id=q.id WHERE t.external_id=$1 AND q.id=$2",
        )
        .bind(tenant_external_id)
        .bind(quarantine_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::NotFound)?;
        quarantine_view(row)
    }

    pub async fn resolve_session_archive_quarantine(
        &self,
        input: SessionArchiveQuarantineResolutionInput<'_>,
    ) -> Result<SessionArchiveQuarantineResolutionView, AppError> {
        validate_resolution(&input)?;
        let tenant_id = tenant_id(self, input.tenant_external_id).await?;
        let now = unix_millis();
        let mut tx = self.begin_write_transaction().await?;
        let quarantine = sqlx::query("SELECT source,external_request_id,source_session_id,record_digest,proof_digest,source_started_at,source_completed_at,protocol,model,status_code,duration_ms,input_tokens,output_tokens,error_code,request_digest,response_digest,request_object,response_object FROM session_archive_quarantine_record_versions WHERE id=$1 AND tenant_id=$2")
            .bind(input.quarantine_id.to_string()).bind(tenant_id.to_string())
            .fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
        if quarantine.try_get::<String, _>("record_digest")? != input.expected_record_digest {
            return Err(AppError::Conflict(
                "quarantine record changed before resolution".into(),
            ));
        }
        let (key_id, principal_id) = match (input.action, input.key_id) {
            ("associate", Some(key_id)) => {
                let row = sqlx::query(
                    "SELECT principal_id FROM key_records WHERE id=$1 AND tenant_id=$2",
                )
                .bind(key_id.to_string())
                .bind(tenant_id.to_string())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AppError::NotFound)?;
                (
                    Some(key_id),
                    Some(parse_uuid(row.try_get("principal_id")?)?),
                )
            }
            ("dismiss", None) => (None, None),
            _ => return Err(AppError::BadRequest("invalid quarantine resolution".into())),
        };
        let resolution_id = deterministic_resolution_id(input.quarantine_id, input.idempotency_key);
        let request_digest = resolution_request_digest(&input, key_id);
        let inserted = sqlx::query("INSERT INTO session_archive_quarantine_resolutions (id,tenant_id,quarantine_id,action,key_id,evidence_digest,note,idempotency_key,request_digest,resolved_by_service_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(quarantine_id) DO NOTHING")
            .bind(resolution_id.to_string()).bind(tenant_id.to_string())
            .bind(input.quarantine_id.to_string()).bind(input.action)
            .bind(key_id.map(|id| id.to_string())).bind(input.evidence_digest)
            .bind(input.note).bind(input.idempotency_key).bind(&request_digest)
            .bind(input.resolved_by_service_id.to_string()).bind(now)
            .execute(&mut *tx).await?;
        if inserted.rows_affected() == 0 {
            let existing =
                ensure_resolution_replay(&mut tx, &input, resolution_id, key_id, &request_digest)
                    .await?;
            tx.commit().await?;
            return Ok(existing);
        }
        if let (Some(key_id), Some(principal_id)) = (key_id, principal_id) {
            let source: String = quarantine.try_get("source")?;
            let external_request_id: String = quarantine.try_get("external_request_id")?;
            let record_digest: String = quarantine.try_get("record_digest")?;
            let source_started_at: i64 = quarantine.try_get("source_started_at")?;
            let model: String = quarantine.try_get("model")?;
            let identity_proof_digest = archive_proof_digest(
                "memeloop-session-archive-operator-resolution-v1",
                &[
                    input.tenant_external_id,
                    &input.quarantine_id.to_string(),
                    input.evidence_digest,
                    &key_id.to_string(),
                    &principal_id.to_string(),
                ],
            );
            let correlation_proof_digest = archive_proof_digest(
                "memeloop-session-archive-correlation-v1",
                &[
                    input.tenant_external_id,
                    &source,
                    &external_request_id,
                    "unlinked",
                    &key_id.to_string(),
                    &principal_id.to_string(),
                    input.expected_record_digest,
                    &identity_proof_digest,
                ],
            );
            sqlx::query("INSERT INTO session_archive_correlations (tenant_id,source,external_request_id,disposition,key_id,principal_id,target_request_id,target_request_created_at,external_event_hash,record_digest,proof_digest,identity_proof_kind,identity_proof_digest,source_model,source_started_at,correlated_at) VALUES ($1,$2,$3,'unlinked',$4,$5,NULL,NULL,NULL,$6,$7,'operator-evidence-v1',$8,$9,$10,$11)")
                .bind(tenant_id.to_string()).bind(&source).bind(&external_request_id)
                .bind(key_id.to_string()).bind(principal_id.to_string()).bind(&record_digest)
                .bind(&correlation_proof_digest).bind(&identity_proof_digest).bind(&model)
                .bind(source_started_at).bind(now).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO session_archive_unlinked_requests (tenant_id,source,external_request_id,archive_request_id,key_id,principal_id,conversation_cluster_id,source_started_at,source_completed_at,protocol,model,status_code,duration_ms,input_tokens,output_tokens,error_code,request_digest,response_digest,request_object,response_object,imported_at,source_session_id) VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
                .bind(tenant_id.to_string()).bind(&source).bind(&external_request_id)
                .bind(input.quarantine_id.to_string()).bind(key_id.to_string()).bind(principal_id.to_string())
                .bind(source_started_at).bind(quarantine.try_get::<Option<i64>,_>("source_completed_at")?)
                .bind(quarantine.try_get::<String,_>("protocol")?).bind(&model)
                .bind(quarantine.try_get::<Option<i64>,_>("status_code")?).bind(quarantine.try_get::<Option<i64>,_>("duration_ms")?)
                .bind(quarantine.try_get::<i64,_>("input_tokens")?).bind(quarantine.try_get::<i64,_>("output_tokens")?)
                .bind(quarantine.try_get::<Option<String>,_>("error_code")?)
                .bind(quarantine.try_get::<Option<String>,_>("request_digest")?).bind(quarantine.try_get::<Option<String>,_>("response_digest")?)
                .bind(quarantine.try_get::<Option<String>,_>("request_object")?).bind(quarantine.try_get::<Option<String>,_>("response_object")?)
                .bind(now).bind(quarantine.try_get::<String,_>("source_session_id")?)
                .execute(&mut *tx).await?;
            add_archive_record_to_session_projection_in_transaction(
                &mut tx,
                tenant_id,
                key_id,
                &source,
                &external_request_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(SessionArchiveQuarantineResolutionView {
            id: resolution_id,
            quarantine_id: input.quarantine_id,
            action: input.action.to_owned(),
            key_id,
            evidence_digest: input.evidence_digest.to_owned(),
            created_at: now,
        })
    }
}

async fn tenant_id(db: &Database, external_id: &str) -> Result<Uuid, AppError> {
    let value: String = sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
        .bind(external_id)
        .fetch_optional(&db.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    parse_uuid(value)
}

fn validate_quarantine_commit(
    input: &SessionArchiveQuarantineCommitInput<'_>,
) -> Result<(), AppError> {
    let expected_proof_digest = archive_proof_digest(
        "memeloop-session-archive-quarantine-v1",
        &[
            input.batch.tenant_external_id,
            input.batch.archive_source,
            input.external_request_id,
            &input.target.reason_code,
            input
                .target
                .identity_claim_digest
                .as_deref()
                .unwrap_or("none"),
            input.record_digest,
        ],
    );
    let hashes = [
        input.batch.source_digest,
        input.batch.tenant_binding_proof,
        input.record_digest,
        &input.target.proof_digest,
    ];
    if hashes.into_iter().any(|value| !is_sha256_hex(value))
        || input
            .target
            .identity_claim_digest
            .as_deref()
            .is_some_and(|value| !is_sha256_hex(value))
        || input
            .request_digest
            .is_some_and(|value| !is_sha256_hex(value))
        || input
            .response_digest
            .is_some_and(|value| !is_sha256_hex(value))
        || !matches!(
            input.target.reason_code.as_str(),
            QUARANTINE_REASON_MISSING | QUARANTINE_REASON_UNPROVEN
        )
        || (input.target.reason_code == QUARANTINE_REASON_MISSING
            && input.target.identity_claim_digest.is_some())
        || (input.target.reason_code == QUARANTINE_REASON_UNPROVEN
            && input.target.identity_claim_digest.is_none())
        || !valid_archive_identifier(input.batch.archive_source, 256)
        || !valid_archive_identifier(input.batch.cpamp_source, 256)
        || !valid_archive_identifier(input.external_request_id, 512)
        || !valid_archive_identifier(input.batch.tenant_binding_kind, 128)
        || input.batch.source_size_bytes < 0
        || input.batch.eligible_records < 0
        || input.batch.quarantine_records < 0
        || input.sequence < 0
        || input.protocol.is_empty()
        || input.protocol.len() > 256
        || input.model.is_empty()
        || input.model.len() > 512
        || input.input_tokens < 0
        || input.output_tokens < 0
        || !valid_archive_identifier(input.source_session_id, 512)
    {
        return Err(AppError::BadRequest(
            "quarantine metadata or proof is invalid".into(),
        ));
    }
    if input.target.proof_digest != expected_proof_digest {
        return Err(AppError::Conflict(
            "quarantine proof changed after import planning".into(),
        ));
    }
    Ok(())
}

async fn ensure_quarantine_replay(
    tx: &mut Transaction<'_, Any>,
    input: &SessionArchiveQuarantineCommitInput<'_>,
) -> Result<(), AppError> {
    let row = sqlx::query("SELECT id,tenant_id,source,cpamp_source,external_request_id,record_digest,identity_claim_digest,reason_code,proof_digest,source_started_at,source_completed_at,protocol,model,status_code,duration_ms,input_tokens,output_tokens,error_code,request_digest,response_digest,request_object,response_object,source_session_id FROM session_archive_quarantine_record_versions WHERE id=$1")
        .bind(input.target.quarantine_id.to_string())
        .fetch_one(&mut **tx).await?;
    let compatible = row.try_get::<String, _>("id")? == input.target.quarantine_id.to_string()
        && row.try_get::<String, _>("tenant_id")? == input.target.tenant_id.to_string()
        && row.try_get::<String, _>("source")? == input.batch.archive_source
        && row.try_get::<String, _>("cpamp_source")? == input.batch.cpamp_source
        && row.try_get::<String, _>("external_request_id")? == input.external_request_id
        && row.try_get::<String, _>("record_digest")? == input.record_digest
        && row.try_get::<Option<String>, _>("identity_claim_digest")?
            == input.target.identity_claim_digest
        && row.try_get::<String, _>("reason_code")? == input.target.reason_code
        && row.try_get::<String, _>("proof_digest")? == input.target.proof_digest
        && row.try_get::<i64, _>("source_started_at")? == input.source_started_at
        && row.try_get::<Option<i64>, _>("source_completed_at")? == input.source_completed_at
        && row.try_get::<String, _>("protocol")? == input.protocol
        && row.try_get::<String, _>("model")? == input.model
        && row.try_get::<Option<i64>, _>("status_code")? == input.status_code
        && row.try_get::<Option<i64>, _>("duration_ms")? == input.duration_ms
        && row.try_get::<i64, _>("input_tokens")? == input.input_tokens
        && row.try_get::<i64, _>("output_tokens")? == input.output_tokens
        && row.try_get::<Option<String>, _>("error_code")?.as_deref() == input.error_code
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
        && row.try_get::<String, _>("source_session_id")? == input.source_session_id;
    if compatible {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "quarantine record changed on replay".into(),
        ))
    }
}

fn validate_resolution(
    input: &SessionArchiveQuarantineResolutionInput<'_>,
) -> Result<(), AppError> {
    validate_idempotency_key(input.idempotency_key, "Idempotency-Key")?;
    if !matches!(input.action, "associate" | "dismiss")
        || !is_sha256_hex(input.expected_record_digest)
        || !is_sha256_hex(input.evidence_digest)
        || input.note.is_some_and(|note| {
            note.len() > 2_000 || note.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return Err(AppError::BadRequest(
            "invalid quarantine resolution proof".into(),
        ));
    }
    Ok(())
}

fn resolution_request_digest(
    input: &SessionArchiveQuarantineResolutionInput<'_>,
    key_id: Option<Uuid>,
) -> String {
    let quarantine_id = input.quarantine_id.to_string();
    let key_id = key_id.map(|id| id.to_string());
    let service_id = input.resolved_by_service_id.to_string();
    archive_proof_digest(
        "memeloop-session-archive-quarantine-resolution-request-v1",
        &[
            input.tenant_external_id,
            &quarantine_id,
            input.action,
            key_id.as_deref().unwrap_or("none"),
            input.expected_record_digest,
            input.evidence_digest,
            input.note.unwrap_or(""),
            input.idempotency_key,
            &service_id,
        ],
    )
}

fn deterministic_quarantine_version_id(
    tenant_external_id: &str,
    source: &str,
    external_request_id: &str,
    record_digest: &str,
    source_session_id: &str,
) -> Uuid {
    let evidence_identity = archive_proof_digest(
        "memeloop-session-archive-quarantine-version-v2",
        &[
            tenant_external_id,
            source,
            external_request_id,
            record_digest,
            source_session_id,
        ],
    );
    deterministic_archive_request_id(
        tenant_external_id,
        "session-archive-quarantine-version-v2",
        &evidence_identity,
    )
}

fn deterministic_resolution_id(quarantine_id: Uuid, idempotency_key: &str) -> Uuid {
    deterministic_archive_request_id(&quarantine_id.to_string(), "resolution", idempotency_key)
}

async fn ensure_resolution_replay(
    tx: &mut Transaction<'static, Any>,
    input: &SessionArchiveQuarantineResolutionInput<'_>,
    resolution_id: Uuid,
    key_id: Option<Uuid>,
    request_digest: &str,
) -> Result<SessionArchiveQuarantineResolutionView, AppError> {
    let row = sqlx::query("SELECT id,action,key_id,evidence_digest,note,idempotency_key,request_digest,resolved_by_service_id,created_at FROM session_archive_quarantine_resolutions WHERE quarantine_id=$1")
        .bind(input.quarantine_id.to_string()).fetch_one(&mut **tx).await?;
    let expected_service_id = input.resolved_by_service_id.to_string();
    let compatible = row.try_get::<String, _>("id")? == resolution_id.to_string()
        && row.try_get::<String, _>("action")? == input.action
        && row.try_get::<Option<String>, _>("key_id")? == key_id.map(|id| id.to_string())
        && row.try_get::<String, _>("evidence_digest")? == input.evidence_digest
        && row.try_get::<Option<String>, _>("note")?.as_deref() == input.note
        && row.try_get::<String, _>("idempotency_key")? == input.idempotency_key
        && row.try_get::<String, _>("request_digest")? == request_digest
        && row
            .try_get::<Option<String>, _>("resolved_by_service_id")?
            .as_deref()
            == Some(expected_service_id.as_str());
    if !compatible {
        return Err(AppError::Conflict(
            "quarantine already has a different final resolution".into(),
        ));
    }
    Ok(SessionArchiveQuarantineResolutionView {
        id: resolution_id,
        quarantine_id: input.quarantine_id,
        action: input.action.to_owned(),
        key_id,
        evidence_digest: input.evidence_digest.to_owned(),
        created_at: row.try_get("created_at")?,
    })
}

fn quarantine_view(row: AnyRow) -> Result<SessionArchiveQuarantineRecordView, AppError> {
    Ok(SessionArchiveQuarantineRecordView {
        id: parse_uuid(row.try_get("id")?)?,
        tenant_external_id: row.try_get("tenant_external_id")?,
        source: row.try_get("source")?,
        external_request_id: row.try_get("external_request_id")?,
        record_digest: row.try_get("record_digest")?,
        reason_code: row.try_get("reason_code")?,
        source_started_at: row.try_get("source_started_at")?,
        source_completed_at: row.try_get("source_completed_at")?,
        protocol: row.try_get("protocol")?,
        model: row.try_get("model")?,
        status_code: row.try_get("status_code")?,
        duration_ms: row.try_get("duration_ms")?,
        input_tokens: row.try_get("input_tokens")?,
        output_tokens: row.try_get("output_tokens")?,
        error_code: row.try_get("error_code")?,
        state: row.try_get("state")?,
    })
}
