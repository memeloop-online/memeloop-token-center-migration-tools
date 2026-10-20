use std::sync::{Arc, OnceLock};

use super::super::*;

static SQLITE_SESSION_ARCHIVE_IMPORT_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

const CPAMP_IMPORT_LOCK_KEY: &str = "memeloop-token-center:cpamp:global-staging-v1";

const CPAMP_IMPORT_LOCK_SEED: i64 = 734_627_102_948_313;

const SESSION_ARCHIVE_IMPORT_LOCK_SEED: i64 = 734_627_102_948_314;

pub(super) const ARCHIVE_IDENTITY_UNPROVEN: &str =
    "archive request has no proven stable key/principal identity";
pub(super) const ARCHIVE_IDENTITY_AMBIGUOUS: &str =
    "archive credential hash maps to multiple stable identities";

#[derive(Clone, Debug)]
pub struct SessionArchiveMatchInput<'a> {
    pub tenant_external_id: &'a str,
    pub cpamp_source: &'a str,
    pub archive_source: &'a str,
    pub external_request_id: &'a str,
    pub started_at: i64,
    pub requested_model: Option<&'a str>,
    pub resolved_model: Option<&'a str>,
    pub source_key_hash: &'a str,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub record_digest: &'a str,
    pub time_tolerance_ms: i64,
    pub allow_stable_replacement: bool,
}

#[derive(Clone, Debug)]
pub struct SessionArchiveTarget {
    pub tenant_id: Uuid,
    pub target_request_id: Uuid,
    pub request_created_at: i64,
    pub key: AuthenticatedKey,
    pub external_event_hash: String,
    pub source_created_at: i64,
    pub source_model: String,
    pub replay: bool,
}

#[derive(Clone, Debug)]
pub struct SessionArchiveUnlinkedTarget {
    pub tenant_id: Uuid,
    pub archive_request_id: Uuid,
    pub key: AuthenticatedKey,
    pub identity_proof_kind: String,
    pub identity_proof_digest: String,
    pub correlation_proof_digest: String,
    pub replay: bool,
}

#[derive(Clone, Debug)]
pub enum SessionArchiveCorrelation {
    Exact {
        target: SessionArchiveTarget,
        identity_proof_kind: String,
        identity_proof_digest: String,
        correlation_proof_digest: String,
    },
    Unlinked(SessionArchiveUnlinkedTarget),
}

enum SessionArchiveTargetMatch {
    Exact(Box<SessionArchiveTarget>),
    Ambiguous,
    Incompatible,
    Absent,
}

pub struct SessionArchiveImportLock {
    postgres: Option<(AnyConnection, String)>,
    sqlite: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl SessionArchiveCorrelation {
    pub fn key(&self) -> &AuthenticatedKey {
        match self {
            Self::Exact { target, .. } => &target.key,
            Self::Unlinked(target) => &target.key,
        }
    }

    pub fn replay(&self) -> bool {
        match self {
            Self::Exact { target, .. } => target.replay,
            Self::Unlinked(target) => target.replay,
        }
    }
}

impl SessionArchiveImportLock {
    pub async fn release(mut self) -> Result<(), AppError> {
        self.sqlite.take();
        let Some((mut connection, scoped_key)) = self.postgres.take() else {
            return Ok(());
        };
        let scoped_released: bool =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, $2))")
                .bind(&scoped_key)
                .bind(SESSION_ARCHIVE_IMPORT_LOCK_SEED)
                .fetch_one(&mut connection)
                .await?;
        let global_released: bool =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, $2))")
                .bind(CPAMP_IMPORT_LOCK_KEY)
                .bind(CPAMP_IMPORT_LOCK_SEED)
                .fetch_one(&mut connection)
                .await?;
        drop(connection);
        if scoped_released && global_released {
            Ok(())
        } else {
            Err(AppError::Internal)
        }
    }
}

impl Database {
    pub async fn match_session_archive_request(
        &self,
        input: SessionArchiveMatchInput<'_>,
    ) -> Result<SessionArchiveTarget, AppError> {
        let source_key_hash =
            normalize_archive_source_key_hash(input.source_key_hash).ok_or_else(|| {
                AppError::BadRequest("archive request has no verified credential hash".into())
            })?;
        let input = SessionArchiveMatchInput {
            source_key_hash: &source_key_hash,
            ..input
        };
        match self.classify_session_archive_request(&input).await? {
            SessionArchiveTargetMatch::Exact(target) => {
                let target = *target;
                let (verified_key, _) = self
                    .resolve_session_archive_identity(
                        input.tenant_external_id,
                        input.cpamp_source,
                        input.source_key_hash,
                    )
                    .await?;
                ensure_archive_target_identity(&target, &verified_key)?;
                Ok(target)
            }
            SessionArchiveTargetMatch::Ambiguous
            | SessionArchiveTargetMatch::Incompatible
            | SessionArchiveTargetMatch::Absent => Err(AppError::BadRequest(
                "archive request does not map uniquely to a CPAMP event".into(),
            )),
        }
    }

    async fn classify_session_archive_request(
        &self,
        input: &SessionArchiveMatchInput<'_>,
    ) -> Result<SessionArchiveTargetMatch, AppError> {
        let rows = sqlx::query(
            "SELECT t.id AS tenant_id, l.target_request_id, rl.created_at AS request_created_at, l.external_event_hash, l.source_created_at, l.source_model, l.source_key_hash, r.input_tokens, r.output_tokens, r.key_id, k.principal_id, k.account_id, k.alias, k.currency, k.credential_generation, k.policy_json FROM import_request_links l JOIN tenants t ON t.id = l.tenant_id JOIN request_record_locators rl ON rl.id = l.target_request_id AND rl.tenant_id = l.tenant_id JOIN request_records r ON r.id = rl.id AND r.created_at = rl.created_at AND r.tenant_id = rl.tenant_id JOIN key_records k ON k.id = r.key_id AND k.tenant_id = l.tenant_id WHERE t.external_id = $1 AND l.source = $2 AND l.external_request_id = $3 ORDER BY l.source_created_at, l.external_event_hash",
        )
        .bind(input.tenant_external_id)
        .bind(input.cpamp_source)
        .bind(input.external_request_id)
        .fetch_all(&self.pool)
        .await?;

        let mut matches = Vec::new();
        for row in rows {
            let source_created_at: i64 = row.try_get("source_created_at")?;
            if source_created_at.abs_diff(input.started_at) > input.time_tolerance_ms.max(0) as u64
            {
                continue;
            }
            let source_model: String = row.try_get("source_model")?;
            let model_matches = [input.requested_model, input.resolved_model]
                .into_iter()
                .flatten()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .any(|value| value == source_model);
            if !model_matches {
                continue;
            }
            let source_key_hash: String = row.try_get("source_key_hash")?;
            if !input.source_key_hash.eq_ignore_ascii_case(&source_key_hash) {
                continue;
            }
            matches.push((row, source_created_at, source_model));
        }
        if matches.len() > 1 {
            let usage = input
                .input_tokens
                .zip(input.output_tokens)
                .filter(|(input_tokens, output_tokens)| *input_tokens >= 0 && *output_tokens >= 0);
            if let Some((input_tokens, output_tokens)) = usage {
                let mut usage_matches = Vec::with_capacity(matches.len());
                for candidate in matches {
                    let candidate_input: i64 = candidate.0.try_get("input_tokens")?;
                    let candidate_output: i64 = candidate.0.try_get("output_tokens")?;
                    if candidate_input == input_tokens && candidate_output == output_tokens {
                        usage_matches.push(candidate);
                    }
                }
                matches = usage_matches;
            }
        }
        if matches.len() > 1 {
            return Ok(SessionArchiveTargetMatch::Ambiguous);
        }
        if matches.is_empty() {
            let raw_candidates: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM import_request_links l JOIN tenants t ON t.id = l.tenant_id WHERE t.external_id = $1 AND l.source = $2 AND l.external_request_id = $3",
            )
            .bind(input.tenant_external_id)
            .bind(input.cpamp_source)
            .bind(input.external_request_id)
            .fetch_one(&self.pool)
            .await?;
            return Ok(if raw_candidates == 0 {
                SessionArchiveTargetMatch::Absent
            } else {
                SessionArchiveTargetMatch::Incompatible
            });
        }
        let (row, source_created_at, source_model) = matches.pop().expect("one match");
        let tenant_id = parse_uuid(row.try_get("tenant_id")?)?;
        let target_request_id = parse_uuid(row.try_get("target_request_id")?)?;
        let key_id = parse_uuid(row.try_get("key_id")?)?;
        let policy_json: String = row.try_get("policy_json")?;
        let policy = serde_json::from_str(&policy_json).map_err(|_| AppError::Internal)?;

        let imported = sqlx::query(
            "SELECT target_request_id, record_digest FROM session_archive_import_records WHERE tenant_id = $1 AND source = $2 AND external_request_id = $3",
        )
        .bind(tenant_id.to_string())
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .fetch_optional(&self.pool)
        .await?;
        let replay = if let Some(existing) = imported {
            let existing_target: String = existing.try_get("target_request_id")?;
            let existing_digest: String = existing.try_get("record_digest")?;
            if (existing_target != target_request_id.to_string()
                || existing_digest != input.record_digest)
                && !input.allow_stable_replacement
            {
                return Err(AppError::BadRequest(
                    "archive request changed after it was imported".into(),
                ));
            }
            existing_target == target_request_id.to_string()
                && existing_digest == input.record_digest
        } else {
            false
        };

        Ok(SessionArchiveTargetMatch::Exact(Box::new(
            SessionArchiveTarget {
                tenant_id,
                target_request_id,
                request_created_at: row.try_get("request_created_at")?,
                key: AuthenticatedKey {
                    key_id,
                    tenant_id,
                    principal_id: parse_uuid(row.try_get("principal_id")?)?,
                    account_id: parse_uuid(row.try_get("account_id")?)?,
                    alias: row.try_get("alias")?,
                    currency: row.try_get("currency")?,
                    credential_generation: row.try_get("credential_generation")?,
                    policy,
                },
                external_event_hash: row.try_get("external_event_hash")?,
                source_created_at,
                source_model,
                replay,
            },
        )))
    }

    /// Correlate an archive record without inventing a CPAMP edge.  An exact
    /// target is used only when the existing deterministic matcher proves one;
    /// otherwise the source credential hash must still prove exactly one stable
    /// key/principal identity before an archive-only row can be planned.
    pub async fn correlate_session_archive_request(
        &self,
        input: SessionArchiveMatchInput<'_>,
    ) -> Result<SessionArchiveCorrelation, AppError> {
        let Some(source_key_hash) = normalize_archive_source_key_hash(input.source_key_hash) else {
            return Err(AppError::BadRequest(
                "archive correlation proof input is invalid".into(),
            ));
        };
        let input = SessionArchiveMatchInput {
            source_key_hash: &source_key_hash,
            ..input
        };
        if !is_sha256_hex(input.record_digest)
            || !valid_archive_identifier(input.cpamp_source, 256)
            || !valid_archive_identifier(input.archive_source, 256)
            || !valid_archive_identifier(input.external_request_id, 512)
        {
            return Err(AppError::BadRequest(
                "archive correlation proof input is invalid".into(),
            ));
        }

        // Caller identity is independent of request-edge correlation.  Both exact
        // and archive-only dispositions require this hash to prove one tenant-
        // scoped key/principal before any target is considered.
        let (verified_key, identity_proof_kind) = self
            .resolve_session_archive_identity(
                input.tenant_external_id,
                input.cpamp_source,
                input.source_key_hash,
            )
            .await?;

        if let Some(existing) = self
            .existing_session_archive_correlation(&input, &verified_key, &identity_proof_kind)
            .await?
        {
            return Ok(existing);
        }

        match self.classify_session_archive_request(&input).await? {
            SessionArchiveTargetMatch::Exact(target) => {
                let target = *target;
                ensure_archive_target_identity(&target, &verified_key)?;
                let identity_proof_kind = "cpamp-exact-target-v1".to_owned();
                let identity_proof_digest = archive_proof_digest(
                    "memeloop-session-archive-identity-v1",
                    &[
                        input.tenant_external_id,
                        input.cpamp_source,
                        input.source_key_hash,
                        &target.key.key_id.to_string(),
                        &target.key.principal_id.to_string(),
                        &target.target_request_id.to_string(),
                        &target.external_event_hash,
                    ],
                );
                let correlation_proof_digest = archive_proof_digest(
                    "memeloop-session-archive-correlation-v1",
                    &[
                        input.tenant_external_id,
                        input.archive_source,
                        input.external_request_id,
                        "exact",
                        &target.key.key_id.to_string(),
                        &target.key.principal_id.to_string(),
                        &target.target_request_id.to_string(),
                        input.record_digest,
                        &identity_proof_digest,
                    ],
                );
                Ok(SessionArchiveCorrelation::Exact {
                    target,
                    identity_proof_kind,
                    identity_proof_digest,
                    correlation_proof_digest,
                })
            }
            disposition @ (SessionArchiveTargetMatch::Ambiguous
            | SessionArchiveTargetMatch::Incompatible
            | SessionArchiveTargetMatch::Absent) => {
                // A provenance row from a previous exact import is authoritative.
                // Never downgrade a changed exact replay to archive-only.
                let prior_exact: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM session_archive_import_records r JOIN tenants t ON t.id = r.tenant_id WHERE t.external_id = $1 AND r.source = $2 AND r.external_request_id = $3",
                )
                .bind(input.tenant_external_id)
                .bind(input.archive_source)
                .bind(input.external_request_id)
                .fetch_one(&self.pool)
                .await?;
                if prior_exact != 0 {
                    return Err(AppError::BadRequest(
                        "existing exact archive provenance no longer verifies".into(),
                    ));
                }
                if matches!(disposition, SessionArchiveTargetMatch::Incompatible) {
                    // A claimed target whose time/model/hash/usage evidence is
                    // incompatible is corruption, not an ambiguous edge.
                    return Err(AppError::BadRequest(
                        "archive request conflicts with its CPAMP target candidates".into(),
                    ));
                }

                let key = verified_key;
                let identity_proof_digest = archive_proof_digest(
                    "memeloop-session-archive-identity-v1",
                    &[
                        input.tenant_external_id,
                        input.cpamp_source,
                        input.source_key_hash,
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        &identity_proof_kind,
                    ],
                );
                let correlation_proof_digest = archive_proof_digest(
                    "memeloop-session-archive-correlation-v1",
                    &[
                        input.tenant_external_id,
                        input.archive_source,
                        input.external_request_id,
                        "unlinked",
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        input.record_digest,
                        &identity_proof_digest,
                    ],
                );
                let archive_request_id = deterministic_archive_request_id(
                    input.tenant_external_id,
                    input.archive_source,
                    input.external_request_id,
                );
                Ok(SessionArchiveCorrelation::Unlinked(
                    SessionArchiveUnlinkedTarget {
                        tenant_id: key.tenant_id,
                        archive_request_id,
                        key,
                        identity_proof_kind,
                        identity_proof_digest,
                        correlation_proof_digest,
                        replay: false,
                    },
                ))
            }
        }
    }

    async fn existing_session_archive_correlation(
        &self,
        input: &SessionArchiveMatchInput<'_>,
        verified_key: &AuthenticatedKey,
        verified_identity_proof_kind: &str,
    ) -> Result<Option<SessionArchiveCorrelation>, AppError> {
        let row = sqlx::query(
            "SELECT c.tenant_id, c.disposition, c.key_id, c.principal_id, c.target_request_id, c.target_request_created_at, c.external_event_hash, c.record_digest, c.proof_digest, c.identity_proof_kind, c.identity_proof_digest, c.source_started_at, c.source_model, u.archive_request_id, k.account_id, k.alias, k.currency, k.credential_generation, k.policy_json FROM session_archive_correlations c JOIN tenants t ON t.id = c.tenant_id JOIN key_records k ON k.id = c.key_id AND k.tenant_id = c.tenant_id LEFT JOIN session_archive_unlinked_requests u ON u.tenant_id = c.tenant_id AND u.source = c.source AND u.external_request_id = c.external_request_id WHERE t.external_id = $1 AND c.source = $2 AND c.external_request_id = $3",
        )
        .bind(input.tenant_external_id)
        .bind(input.archive_source)
        .bind(input.external_request_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.try_get::<String, _>("record_digest")? != input.record_digest {
            if input.allow_stable_replacement {
                return Ok(None);
            }
            return Err(AppError::BadRequest(
                "archive request changed after correlation".into(),
            ));
        }
        let key = archive_authenticated_key(&row)?;
        if key.principal_id.to_string() != row.try_get::<String, _>("principal_id")? {
            return Err(AppError::BadRequest(
                "archive correlation identity no longer verifies".into(),
            ));
        }
        let identity_proof_kind: String = row.try_get("identity_proof_kind")?;
        let identity_proof_digest: String = row.try_get("identity_proof_digest")?;
        let correlation_proof_digest: String = row.try_get("proof_digest")?;
        match row.try_get::<String, _>("disposition")?.as_str() {
            "exact" => {
                let target_request_id = parse_uuid(
                    row.try_get::<Option<String>, _>("target_request_id")?
                        .ok_or(AppError::Internal)?,
                )?;
                let external_event_hash = row
                    .try_get::<Option<String>, _>("external_event_hash")?
                    .ok_or(AppError::Internal)?;
                let expected_identity = archive_proof_digest(
                    "memeloop-session-archive-identity-v1",
                    &[
                        input.tenant_external_id,
                        input.cpamp_source,
                        input.source_key_hash,
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        &target_request_id.to_string(),
                        &external_event_hash,
                    ],
                );
                let expected_correlation = archive_proof_digest(
                    "memeloop-session-archive-correlation-v1",
                    &[
                        input.tenant_external_id,
                        input.archive_source,
                        input.external_request_id,
                        "exact",
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        &target_request_id.to_string(),
                        input.record_digest,
                        &expected_identity,
                    ],
                );
                if verified_key.tenant_id != key.tenant_id
                    || verified_key.key_id != key.key_id
                    || verified_key.principal_id != key.principal_id
                    || identity_proof_kind != "cpamp-exact-target-v1"
                    || identity_proof_digest != expected_identity
                    || correlation_proof_digest != expected_correlation
                {
                    return Err(AppError::BadRequest(
                        "stored exact archive correlation proof is invalid".into(),
                    ));
                }
                Ok(Some(SessionArchiveCorrelation::Exact {
                    target: SessionArchiveTarget {
                        tenant_id: key.tenant_id,
                        target_request_id,
                        request_created_at: row
                            .try_get::<Option<i64>, _>("target_request_created_at")?
                            .ok_or(AppError::Internal)?,
                        key,
                        external_event_hash,
                        source_created_at: row.try_get("source_started_at")?,
                        source_model: row.try_get("source_model")?,
                        replay: true,
                    },
                    identity_proof_kind,
                    identity_proof_digest,
                    correlation_proof_digest,
                }))
            }
            "unlinked" => {
                let expected_identity = archive_proof_digest(
                    "memeloop-session-archive-identity-v1",
                    &[
                        input.tenant_external_id,
                        input.cpamp_source,
                        input.source_key_hash,
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        verified_identity_proof_kind,
                    ],
                );
                let expected_correlation = archive_proof_digest(
                    "memeloop-session-archive-correlation-v1",
                    &[
                        input.tenant_external_id,
                        input.archive_source,
                        input.external_request_id,
                        "unlinked",
                        &key.key_id.to_string(),
                        &key.principal_id.to_string(),
                        input.record_digest,
                        &expected_identity,
                    ],
                );
                let expected_request_id = deterministic_archive_request_id(
                    input.tenant_external_id,
                    input.archive_source,
                    input.external_request_id,
                );
                let archive_request_id = parse_uuid(
                    row.try_get::<Option<String>, _>("archive_request_id")?
                        .ok_or(AppError::Internal)?,
                )?;
                if verified_key.tenant_id != key.tenant_id
                    || verified_key.key_id != key.key_id
                    || verified_key.principal_id != key.principal_id
                    || identity_proof_kind != verified_identity_proof_kind
                    || identity_proof_digest != expected_identity
                    || correlation_proof_digest != expected_correlation
                    || archive_request_id != expected_request_id
                {
                    return Err(AppError::BadRequest(
                        "stored unlinked archive correlation proof is invalid".into(),
                    ));
                }
                Ok(Some(SessionArchiveCorrelation::Unlinked(
                    SessionArchiveUnlinkedTarget {
                        tenant_id: key.tenant_id,
                        archive_request_id,
                        key,
                        identity_proof_kind,
                        identity_proof_digest,
                        correlation_proof_digest,
                        replay: true,
                    },
                )))
            }
            _ => Err(AppError::Internal),
        }
    }

    pub(super) async fn resolve_session_archive_identity_optional(
        &self,
        tenant_external_id: &str,
        cpamp_source: &str,
        source_key_hash: &str,
    ) -> Result<Option<(AuthenticatedKey, String)>, AppError> {
        let rows = sqlx::query(
            "SELECT k.id AS key_id, k.tenant_id, k.principal_id, k.account_id, k.alias, k.currency, k.credential_generation, k.policy_json, 'external-source-key-hash-v1' AS proof_kind FROM key_credential_source_proofs proof JOIN key_credentials credential ON credential.id = proof.credential_id JOIN key_records k ON k.id = credential.key_id JOIN tenants t ON t.id = k.tenant_id WHERE t.external_id = $1 AND proof.proof_kind = 'external-source-key-hash-v1' AND LOWER(proof.source_digest) = LOWER($2) UNION ALL SELECT DISTINCT k.id AS key_id, k.tenant_id, k.principal_id, k.account_id, k.alias, k.currency, k.credential_generation, k.policy_json, 'cpamp-source-key-hash-v1' AS proof_kind FROM import_request_links l JOIN tenants t ON t.id = l.tenant_id JOIN request_record_locators q ON q.id = l.target_request_id AND q.tenant_id = l.tenant_id JOIN request_records r ON r.id = q.id AND r.created_at = q.created_at AND r.tenant_id = q.tenant_id JOIN key_records k ON k.id = r.key_id AND k.tenant_id = l.tenant_id WHERE t.external_id = $1 AND l.source = $3 AND LOWER(l.source_key_hash) = LOWER($2)",
        )
        .bind(tenant_external_id)
        .bind(source_key_hash)
        .bind(cpamp_source)
        .fetch_all(&self.pool)
        .await?;
        let mut selected: Option<AuthenticatedKey> = None;
        let mut proof_kinds = std::collections::BTreeSet::new();
        for row in rows {
            let candidate = archive_authenticated_key(&row)?;
            if selected.as_ref().is_some_and(|current| {
                current.key_id != candidate.key_id
                    || current.tenant_id != candidate.tenant_id
                    || current.principal_id != candidate.principal_id
            }) {
                return Err(AppError::BadRequest(ARCHIVE_IDENTITY_AMBIGUOUS.into()));
            }
            proof_kinds.insert(row.try_get::<String, _>("proof_kind")?);
            selected = Some(candidate);
        }
        Ok(selected.map(|key| (key, proof_kinds.into_iter().collect::<Vec<_>>().join("+"))))
    }

    async fn resolve_session_archive_identity(
        &self,
        tenant_external_id: &str,
        cpamp_source: &str,
        source_key_hash: &str,
    ) -> Result<(AuthenticatedKey, String), AppError> {
        self.resolve_session_archive_identity_optional(
            tenant_external_id,
            cpamp_source,
            source_key_hash,
        )
        .await?
        .ok_or_else(|| AppError::BadRequest(ARCHIVE_IDENTITY_UNPROVEN.into()))
    }

    pub async fn acquire_session_archive_import_lock(
        &self,
        tenant_external_id: &str,
        archive_source: &str,
    ) -> Result<SessionArchiveImportLock, AppError> {
        if matches!(self.backend, DatabaseBackend::Sqlite) {
            let lock = SQLITE_SESSION_ARCHIVE_IMPORT_LOCK
                .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
                .lock_owned()
                .await;
            return Ok(SessionArchiveImportLock {
                postgres: None,
                sqlite: Some(lock),
            });
        }

        // Detaching is deliberate: cancellation drops the raw connection instead
        // of returning a session-level advisory lock to the pool.
        let mut connection = self.pool.acquire().await?.detach();
        let global_acquired: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, $2))")
                .bind(CPAMP_IMPORT_LOCK_KEY)
                .bind(CPAMP_IMPORT_LOCK_SEED)
                .fetch_one(&mut connection)
                .await?;
        if !global_acquired {
            return Err(AppError::BadRequest(
                "a CPAMP or session archive import is already running".into(),
            ));
        }

        let scoped_key =
            format!("memeloop-token-center:session-archive:{tenant_external_id}:{archive_source}");
        let scoped_acquired: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, $2))")
                .bind(&scoped_key)
                .bind(SESSION_ARCHIVE_IMPORT_LOCK_SEED)
                .fetch_one(&mut connection)
                .await?;
        if !scoped_acquired {
            let _: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, $2))")
                .bind(CPAMP_IMPORT_LOCK_KEY)
                .bind(CPAMP_IMPORT_LOCK_SEED)
                .fetch_one(&mut connection)
                .await?;
            return Err(AppError::BadRequest(
                "this tenant and archive source are already being imported".into(),
            ));
        }
        Ok(SessionArchiveImportLock {
            postgres: Some((connection, scoped_key)),
            sqlite: None,
        })
    }

    /// Verify the independently migrated target schema without performing DDL.
    /// The one-shot archive importer must never acquire schema-owner privileges
    /// or mutate the target before the complete source and local plan are sealed.
    pub async fn ensure_session_archive_import_schema(&self) -> Result<(), AppError> {
        let migrations = match self.backend {
            DatabaseBackend::PostgreSql => POSTGRES_MIGRATIONS,
            DatabaseBackend::Sqlite => SQLITE_MIGRATIONS,
        };
        let expected = migrations
            .last()
            .map(|migration| migration.version)
            .unwrap_or(0);
        let row = sqlx::query(
            "SELECT COUNT(*) AS applied, COALESCE(MAX(version), 0) AS latest FROM schema_migrations",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| {
            AppError::BadRequest(
                "target database must be migrated before session archive import".into(),
            )
        })?
        .ok_or_else(|| {
            AppError::BadRequest(
                "target database must be migrated before session archive import".into(),
            )
        })?;
        let applied: i64 = row.try_get("applied")?;
        let latest: i64 = row.try_get("latest")?;
        if expected != 130 || applied != expected || latest != expected {
            return Err(AppError::BadRequest(format!(
                "target database schema is incomplete: expected migrations 1 through {expected}"
            )));
        }

        // Reference every importer-owned relation and the post-v21 locator/source
        // columns. A forged or drifted schema_migrations table therefore remains
        // fail-closed before source planning or CAS writes.
        sqlx::query(
            "SELECT l.source_digest, r.record_digest, r.source_session_id, c.watermark_ms, q.created_at, x.proof_digest, u.archive_request_id, u.source_session_id, z.tenant_binding_proof, y.proof_digest, y.source_session_id, b.sequence, s.evidence_digest, v.ingest_fence, d.deleted_at_ms, p.records_sha256 FROM import_request_links l CROSS JOIN session_archive_import_records r CROSS JOIN session_archive_import_checkpoints c CROSS JOIN request_record_locators q CROSS JOIN session_archive_correlations x CROSS JOIN session_archive_unlinked_requests u CROSS JOIN session_archive_quarantine_batches z CROSS JOIN session_archive_quarantine_records y CROSS JOIN session_archive_quarantine_batch_records b CROSS JOIN session_archive_quarantine_resolutions s CROSS JOIN session_archive_snapshot_checkpoints v CROSS JOIN session_archive_applied_tombstones d CROSS JOIN session_archive_source_sessions p WHERE 1 = 0",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| {
            AppError::BadRequest(
                "target database session archive schema is incomplete or drifted".into(),
            )
        })?;
        Ok(())
    }

    pub async fn session_archive_lower_bound(
        &self,
        tenant_external_id: &str,
        archive_source: &str,
        overlap_ms: i64,
    ) -> Result<i64, AppError> {
        let row = sqlx::query(
            "SELECT c.watermark_ms FROM session_archive_import_checkpoints c JOIN tenants t ON t.id = c.tenant_id WHERE t.external_id = $1 AND c.source = $2",
        )
        .bind(tenant_external_id)
        .bind(archive_source)
        .fetch_optional(&self.pool)
        .await?;
        let watermark = row
            .map(|row| row.try_get::<i64, _>("watermark_ms"))
            .transpose()?
            .unwrap_or(0);
        Ok(watermark.saturating_sub(overlap_ms.max(0)).max(0))
    }
}

pub(super) fn archive_authenticated_key(row: &AnyRow) -> Result<AuthenticatedKey, AppError> {
    let policy_json: String = row.try_get("policy_json")?;
    Ok(AuthenticatedKey {
        key_id: parse_uuid(row.try_get("key_id")?)?,
        tenant_id: parse_uuid(row.try_get("tenant_id")?)?,
        principal_id: parse_uuid(row.try_get("principal_id")?)?,
        account_id: parse_uuid(row.try_get("account_id")?)?,
        alias: row.try_get("alias")?,
        currency: row.try_get("currency")?,
        credential_generation: row.try_get("credential_generation")?,
        policy: serde_json::from_str(&policy_json).map_err(|_| AppError::Internal)?,
    })
}

fn ensure_archive_target_identity(
    target: &SessionArchiveTarget,
    verified_key: &AuthenticatedKey,
) -> Result<(), AppError> {
    if target.key.tenant_id == verified_key.tenant_id
        && target.key.key_id == verified_key.key_id
        && target.key.principal_id == verified_key.principal_id
    {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "archive target does not match the proven caller identity".into(),
        ))
    }
}

pub(super) fn archive_proof_digest(domain: &str, fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    for field in fields {
        digest.update([0]);
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

pub(super) fn deterministic_archive_request_id(
    tenant_external_id: &str,
    source: &str,
    external_request_id: &str,
) -> Uuid {
    let digest = Sha256::digest(
        [
            b"memeloop-session-archive-request-v1".as_slice(),
            &[0],
            tenant_external_id.as_bytes(),
            &[0],
            source.as_bytes(),
            &[0],
            external_request_id.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // UUIDv8 gives the stable opaque request identity standard variant/version bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub(super) fn normalize_archive_source_key_hash(value: &str) -> Option<String> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    is_sha256_hex(value).then(|| value.to_ascii_lowercase())
}

pub(crate) fn valid_archive_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.bytes().any(|byte| byte.is_ascii_control())
}
