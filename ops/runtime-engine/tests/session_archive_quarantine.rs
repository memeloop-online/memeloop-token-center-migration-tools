use memeloop_token_center::{
    db::{
        CreateKeyInput, Database, NewRequest, RequestListFilter, SessionArchiveImportMatch,
        SessionArchiveImportMatchInput, SessionArchiveQuarantineBatchInput,
        SessionArchiveQuarantineCommitInput, SessionArchiveQuarantineFilter,
        SessionArchiveQuarantineResolutionInput, SessionArchiveQuarantineTarget,
    },
    error::AppError,
    model::{AuthenticatedKey, IssuedKey, KeyPolicy},
};
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Row};
use tempfile::TempDir;
use uuid::Uuid;

const CPAMP_SOURCE: &str = "cpamp-usage-events-v1";
const ARCHIVE_SOURCE: &str = "cpa-session-archive-quarantine-test-v1";
const PEPPER: &[u8] = b"session archive quarantine test pepper is long enough";
const STARTED_AT: i64 = 1_787_097_600_000;

struct SqliteFixture {
    _directory: TempDir,
    db: Database,
    pool: AnyPool,
}

#[derive(Debug, Eq, PartialEq)]
struct IsolationCounts {
    requests: i64,
    request_facts: i64,
    usage_rollups: i64,
    ledger_entries: i64,
    conversations: i64,
    unlinked: i64,
}

async fn sqlite_fixture() -> SqliteFixture {
    let directory = tempfile::tempdir().expect("quarantine sqlite directory");
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("quarantine.sqlite").display()
    );
    let db = Database::connect(&database_url)
        .await
        .expect("connect quarantine sqlite");
    db.migrate().await.expect("migrate quarantine sqlite");
    let pool = AnyPool::connect(&database_url)
        .await
        .expect("connect quarantine inspection pool");
    SqliteFixture {
        _directory: directory,
        db,
        pool,
    }
}

async fn create_key(db: &Database, tenant: &str, principal: &str) -> (IssuedKey, AuthenticatedKey) {
    let issued = db
        .create_key(
            CreateKeyInput {
                tenant_external_id: tenant.to_owned(),
                principal_external_id: principal.to_owned(),
                alias: principal.to_owned(),
                currency: "USD".to_owned(),
                policy: KeyPolicy::default(),
                initial_balance: Decimal::ZERO,
                idempotency_key: Some(format!("quarantine-key-{tenant}-{principal}")),
            },
            PEPPER,
        )
        .await
        .expect("create quarantine fixture key");
    let key = db
        .authenticate_key(&issued.key, PEPPER)
        .await
        .expect("authenticate quarantine fixture key");
    (issued, key)
}

async fn insert_retained_source_mapping(pool: &AnyPool, key_id: Uuid, source_hash: &str) {
    sqlx::query(
        "INSERT INTO key_credential_source_proofs (credential_id,proof_kind,source_digest,created_at) SELECT credential.id,'external-source-key-hash-v1',$1,$2 FROM key_credentials credential JOIN key_records stable_key ON stable_key.id = credential.key_id AND stable_key.credential_generation = credential.generation WHERE credential.key_id = $3 AND credential.revoked_at IS NULL",
    )
    .bind(source_hash)
    .bind(STARTED_AT)
    .bind(key_id.to_string())
    .execute(pool)
    .await
    .expect("insert retained source mapping fixture");
}

fn hex_digest(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}

async fn classify(
    db: &Database,
    tenant: &str,
    external_request_id: &str,
    source_key_hash: Option<&str>,
    record_digest: &str,
) -> Result<SessionArchiveImportMatch, AppError> {
    classify_in_session(
        db,
        tenant,
        external_request_id,
        "quarantine-session",
        source_key_hash,
        record_digest,
    )
    .await
}

async fn classify_in_session(
    db: &Database,
    tenant: &str,
    external_request_id: &str,
    source_session_id: &str,
    source_key_hash: Option<&str>,
    record_digest: &str,
) -> Result<SessionArchiveImportMatch, AppError> {
    db.match_session_archive_import(SessionArchiveImportMatchInput {
        tenant_external_id: tenant,
        cpamp_source: CPAMP_SOURCE,
        archive_source: ARCHIVE_SOURCE,
        external_request_id,
        source_session_id,
        started_at: STARTED_AT,
        requested_model: Some("gpt-quarantine"),
        resolved_model: Some("gpt-quarantine"),
        source_key_hash,
        input_tokens: Some(13),
        output_tokens: Some(7),
        record_digest,
        time_tolerance_ms: 5_000,
        allow_stable_replacement: false,
    })
    .await
}

fn quarantined(match_result: SessionArchiveImportMatch) -> SessionArchiveQuarantineTarget {
    match match_result {
        SessionArchiveImportMatch::Quarantine(target) => target,
        SessionArchiveImportMatch::Correlated(_) => {
            panic!("unknown identity must not be correlated")
        }
    }
}

struct CommitFixture<'a> {
    tenant: &'a str,
    external_request_id: &'a str,
    record_digest: &'a str,
    batch_id: Uuid,
    sequence: i64,
    batch_records: i64,
}

async fn commit_quarantine(
    db: &Database,
    target: &SessionArchiveQuarantineTarget,
    input: CommitFixture<'_>,
) -> Result<bool, AppError> {
    commit_quarantine_in_session(db, target, input, "quarantine-session").await
}

async fn commit_quarantine_in_session(
    db: &Database,
    target: &SessionArchiveQuarantineTarget,
    input: CommitFixture<'_>,
    source_session_id: &str,
) -> Result<bool, AppError> {
    let request_digest = hex_digest(format!("{}:request", input.external_request_id));
    let response_digest = hex_digest(format!("{}:response", input.external_request_id));
    let source_digest = hex_digest(input.batch_id.as_bytes());
    let binding_proof = hex_digest(format!("{}:binding", input.tenant));
    db.commit_session_archive_quarantine(SessionArchiveQuarantineCommitInput {
        batch: SessionArchiveQuarantineBatchInput {
            batch_id: input.batch_id,
            tenant_external_id: input.tenant,
            archive_source: ARCHIVE_SOURCE,
            cpamp_source: CPAMP_SOURCE,
            source_digest: &source_digest,
            source_size_bytes: 4_096,
            eligible_records: input.batch_records,
            quarantine_records: input.batch_records,
            tenant_binding_kind: "operator-attestation-v1",
            tenant_binding_proof: &binding_proof,
            approved_by_service_id: Some(input.batch_id),
        },
        sequence: input.sequence,
        target,
        external_request_id: input.external_request_id,
        source_session_id,
        record_digest: input.record_digest,
        source_started_at: STARTED_AT + input.sequence,
        source_completed_at: Some(STARTED_AT + input.sequence + 500),
        protocol: "openai-responses",
        model: "gpt-quarantine",
        status_code: Some(200),
        duration_ms: Some(500),
        input_tokens: 13,
        output_tokens: 7,
        error_code: None,
        request_digest: Some(&request_digest),
        response_digest: Some(&response_digest),
        request_object: Some(
            "objects/blake3/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        response_object: Some(
            "objects/blake3/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        defer_checkpoint: false,
    })
    .await
}

async fn isolation_counts(pool: &AnyPool) -> IsolationCounts {
    let row = sqlx::query(
        "SELECT (SELECT COUNT(*) FROM request_records) AS requests, (SELECT COUNT(*) FROM request_stats_facts) AS request_facts, (SELECT COUNT(*) FROM usage_daily_aggregates) AS usage_rollups, (SELECT COUNT(*) FROM ledger_entries) AS ledger_entries, (SELECT COUNT(*) FROM conversation_observations) AS conversations, (SELECT COUNT(*) FROM session_archive_unlinked_requests) AS unlinked",
    )
    .fetch_one(pool)
    .await
    .expect("read quarantine isolation counts");
    IsolationCounts {
        requests: row.get("requests"),
        request_facts: row.get("request_facts"),
        usage_rollups: row.get("usage_rollups"),
        ledger_entries: row.get("ledger_entries"),
        conversations: row.get("conversations"),
        unlinked: row.get("unlinked"),
    }
}

async fn insert_cpamp_identity(
    db: &Database,
    pool: &AnyPool,
    key: &AuthenticatedKey,
    source_key_hash: &str,
    suffix: &str,
) {
    let request_id = Uuid::now_v7();
    db.record_request_started(NewRequest {
        request_id,
        key_id: key.key_id,
        tenant_id: key.tenant_id,
        protocol: "openai-responses".to_owned(),
        model: "gpt-quarantine".to_owned(),
        request_object: "gap://cpamp/quarantine-test".to_owned(),
        reservation_id: Uuid::now_v7(),
        upstream_account_id: None,
        model_route_id: None,
    })
    .await
    .expect("insert CPAMP identity request");
    sqlx::query(
        "INSERT INTO import_request_links (tenant_id,source,external_event_hash,external_request_id,source_key_hash,target_request_id,source_created_at,source_model,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'gpt-quarantine',$7)",
    )
    .bind(key.tenant_id.to_string())
    .bind(CPAMP_SOURCE)
    .bind(hex_digest(format!("event-{suffix}")))
    .bind(format!("cpamp-{suffix}"))
    .bind(source_key_hash)
    .bind(request_id.to_string())
    .bind(STARTED_AT)
    .execute(pool)
    .await
    .expect("insert CPAMP identity proof");
}

#[tokio::test]
async fn sqlite_quarantine_classification_commit_replay_and_isolation_are_fail_closed() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-core-{}", Uuid::now_v7());
    let (_issued, key) = create_key(&fixture.db, &tenant, "reader").await;
    let before = isolation_counts(&fixture.pool).await;

    let missing_digest = hex_digest("missing-record");
    let missing = quarantined(
        classify(
            &fixture.db,
            &tenant,
            "archive-missing",
            None,
            &missing_digest,
        )
        .await
        .expect("missing identity is quarantinable"),
    );
    assert_eq!(missing.reason_code, "missing_credential_hash");
    assert!(missing.identity_claim_digest.is_none());

    let unknown_hash = hex_digest("unknown-credential");
    let record_digest = hex_digest("unknown-record");
    let target = quarantined(
        classify(
            &fixture.db,
            &tenant,
            "archive-unknown",
            Some(&unknown_hash),
            &record_digest,
        )
        .await
        .expect("unknown identity is quarantinable"),
    );
    assert_eq!(target.reason_code, "unproven_identity");
    assert!(target.identity_claim_digest.is_some());

    let malformed = classify(
        &fixture.db,
        &tenant,
        "archive-malformed",
        Some("not-a-sha256"),
        &hex_digest("malformed-record"),
    )
    .await
    .expect_err("malformed identity evidence must fail");
    assert!(matches!(malformed, AppError::BadRequest(_)));

    let batch_id = Uuid::now_v7();
    let commit = CommitFixture {
        tenant: &tenant,
        external_request_id: "archive-unknown",
        record_digest: &record_digest,
        batch_id,
        sequence: 1,
        batch_records: 1,
    };
    assert!(
        commit_quarantine(&fixture.db, &target, commit)
            .await
            .unwrap()
    );
    assert!(
        !commit_quarantine(
            &fixture.db,
            &target,
            CommitFixture {
                tenant: &tenant,
                external_request_id: "archive-unknown",
                record_digest: &record_digest,
                batch_id,
                sequence: 1,
                batch_records: 1,
            },
        )
        .await
        .unwrap()
    );
    let drift = commit_quarantine(
        &fixture.db,
        &target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-unknown",
            record_digest: &hex_digest("changed-record"),
            batch_id,
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .expect_err("record digest drift must conflict");
    assert!(matches!(drift, AppError::Conflict(_)));

    assert_eq!(isolation_counts(&fixture.pool).await, before);
    assert!(matches!(
        fixture
            .db
            .request_archive_refs(key.key_id, target.quarantine_id)
            .await,
        Err(AppError::NotFound)
    ));
    assert!(
        fixture
            .db
            .list_requests_filtered(key.key_id, RequestListFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    let pending = fixture
        .db
        .list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: Some("pending"),
            limit: 100,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, target.quarantine_id);
}

#[tokio::test]
async fn sqlite_quarantine_versions_preserve_changed_digest_session_move_and_resolution() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-version-{}", Uuid::now_v7());
    create_key(&fixture.db, &tenant, "tenant-anchor").await;
    let external_request_id = "archive-versioned";
    let source_hash = hex_digest("versioned-unknown-credential");
    let first_digest = hex_digest("versioned-record-first");
    let corrected_digest = hex_digest("versioned-record-corrected");

    let first = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-a",
            Some(&source_hash),
            &first_digest,
        )
        .await
        .unwrap(),
    );
    let first_batch = Uuid::now_v7();
    assert!(
        commit_quarantine_in_session(
            &fixture.db,
            &first,
            CommitFixture {
                tenant: &tenant,
                external_request_id,
                record_digest: &first_digest,
                batch_id: first_batch,
                sequence: 1,
                batch_records: 1,
            },
            "session-a",
        )
        .await
        .unwrap()
    );
    fixture
        .db
        .resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            tenant_external_id: &tenant,
            quarantine_id: first.quarantine_id,
            action: "dismiss",
            key_id: None,
            expected_record_digest: &first_digest,
            evidence_digest: &hex_digest("versioned-first-dismissal"),
            note: Some("preserve this version-specific decision"),
            idempotency_key: "versioned-first-dismissal",
            resolved_by_service_id: Uuid::now_v7(),
        })
        .await
        .unwrap();

    let corrected = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-a",
            Some(&source_hash),
            &corrected_digest,
        )
        .await
        .unwrap(),
    );
    assert_ne!(corrected.quarantine_id, first.quarantine_id);
    let corrected_batch = Uuid::now_v7();
    let corrected_commit = || CommitFixture {
        tenant: &tenant,
        external_request_id,
        record_digest: &corrected_digest,
        batch_id: corrected_batch,
        sequence: 1,
        batch_records: 1,
    };
    assert!(
        commit_quarantine_in_session(&fixture.db, &corrected, corrected_commit(), "session-a",)
            .await
            .unwrap()
    );
    let corrected_replay = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-a",
            Some(&source_hash),
            &corrected_digest,
        )
        .await
        .unwrap(),
    );
    assert_eq!(corrected_replay.quarantine_id, corrected.quarantine_id);
    assert!(
        !commit_quarantine_in_session(
            &fixture.db,
            &corrected_replay,
            corrected_commit(),
            "session-a",
        )
        .await
        .unwrap()
    );

    let moved = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-b",
            Some(&source_hash),
            &corrected_digest,
        )
        .await
        .unwrap(),
    );
    assert_ne!(moved.quarantine_id, corrected.quarantine_id);
    let moved_batch = Uuid::now_v7();
    let moved_commit = || CommitFixture {
        tenant: &tenant,
        external_request_id,
        record_digest: &corrected_digest,
        batch_id: moved_batch,
        sequence: 1,
        batch_records: 1,
    };
    assert!(
        commit_quarantine_in_session(&fixture.db, &moved, moved_commit(), "session-b",)
            .await
            .unwrap()
    );
    let moved_replay = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-b",
            Some(&source_hash),
            &corrected_digest,
        )
        .await
        .unwrap(),
    );
    assert_eq!(moved_replay.quarantine_id, moved.quarantine_id);
    assert!(
        !commit_quarantine_in_session(&fixture.db, &moved_replay, moved_commit(), "session-b",)
            .await
            .unwrap()
    );

    let versions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM session_archive_quarantine_record_versions WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3",
    )
    .bind(first.tenant_id.to_string())
    .bind(ARCHIVE_SOURCE)
    .bind(external_request_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(versions, 3);
    let legacy: (i64, String, String) = sqlx::query_as(
        "SELECT COUNT(*),MIN(record_digest),MIN(source_session_id) FROM session_archive_quarantine_records WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3",
    )
    .bind(first.tenant_id.to_string())
    .bind(ARCHIVE_SOURCE)
    .bind(external_request_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(legacy, (1, first_digest.clone(), "session-a".to_owned()));
    let occurrences: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT quarantine_id,record_digest,source_session_id FROM session_archive_quarantine_occurrences WHERE tenant_id=$1 ORDER BY created_at,quarantine_id",
    )
    .bind(first.tenant_id.to_string())
    .fetch_all(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(occurrences.len(), 3);
    assert!(occurrences.iter().any(|row| {
        row.0 == first.quarantine_id.to_string() && row.1 == first_digest && row.2 == "session-a"
    }));
    assert!(occurrences.iter().any(|row| {
        row.0 == corrected.quarantine_id.to_string()
            && row.1 == corrected_digest
            && row.2 == "session-a"
    }));
    assert!(occurrences.iter().any(|row| {
        row.0 == moved.quarantine_id.to_string()
            && row.1 == corrected_digest
            && row.2 == "session-b"
    }));
    let head: (String, String, String) = sqlx::query_as(
        "SELECT quarantine_id,record_digest,source_session_id FROM session_archive_quarantine_record_heads WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3",
    )
    .bind(first.tenant_id.to_string())
    .bind(ARCHIVE_SOURCE)
    .bind(external_request_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(head.0, moved.quarantine_id.to_string());
    assert_eq!(head.1, corrected_digest);
    assert_eq!(head.2, "session-b");

    let preserved = fixture
        .db
        .get_session_archive_quarantine(&tenant, first.quarantine_id)
        .await
        .unwrap();
    assert_eq!(preserved.record_digest, first_digest);
    assert_eq!(preserved.state, "dismissed");
    assert_eq!(
        fixture
            .db
            .get_session_archive_quarantine(&tenant, corrected.quarantine_id)
            .await
            .unwrap()
            .state,
        "pending"
    );
    let current = fixture
        .db
        .list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: None,
            limit: 100,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, moved.quarantine_id);

    let returned = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "session-a",
            Some(&source_hash),
            &first_digest,
        )
        .await
        .unwrap(),
    );
    assert_eq!(returned.quarantine_id, first.quarantine_id);
    assert!(
        !commit_quarantine_in_session(
            &fixture.db,
            &returned,
            CommitFixture {
                tenant: &tenant,
                external_request_id,
                record_digest: &first_digest,
                batch_id: Uuid::now_v7(),
                sequence: 1,
                batch_records: 1,
            },
            "session-a",
        )
        .await
        .unwrap()
    );
    let occurrence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM session_archive_quarantine_occurrences WHERE tenant_id=$1",
    )
    .bind(first.tenant_id.to_string())
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(occurrence_count, 4);
    let returned_head: String = sqlx::query_scalar(
        "SELECT quarantine_id FROM session_archive_quarantine_record_heads WHERE tenant_id=$1 AND source=$2 AND external_request_id=$3",
    )
    .bind(first.tenant_id.to_string())
    .bind(ARCHIVE_SOURCE)
    .bind(external_request_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(returned_head, first.quarantine_id.to_string());
    let current = fixture
        .db
        .list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: None,
            limit: 100,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, first.quarantine_id);
    assert_eq!(current[0].state, "dismissed");
}

#[tokio::test]
async fn sqlite_quarantine_v1_evidence_is_backfilled_without_changing_resolution_identity() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-v1-backfill-{}", Uuid::now_v7());
    create_key(&fixture.db, &tenant, "tenant-anchor").await;
    let external_request_id = "archive-v1-backfill";
    let record_digest = hex_digest("v1-backfill-record");
    let target = quarantined(
        classify_in_session(
            &fixture.db,
            &tenant,
            external_request_id,
            "legacy-session",
            None,
            &record_digest,
        )
        .await
        .unwrap(),
    );
    let batch_id = Uuid::now_v7();
    commit_quarantine_in_session(
        &fixture.db,
        &target,
        CommitFixture {
            tenant: &tenant,
            external_request_id,
            record_digest: &record_digest,
            batch_id,
            sequence: 1,
            batch_records: 1,
        },
        "legacy-session",
    )
    .await
    .unwrap();
    fixture
        .db
        .resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            tenant_external_id: &tenant,
            quarantine_id: target.quarantine_id,
            action: "dismiss",
            key_id: None,
            expected_record_digest: &record_digest,
            evidence_digest: &hex_digest("v1-backfill-resolution"),
            note: None,
            idempotency_key: "v1-backfill-resolution",
            resolved_by_service_id: Uuid::now_v7(),
        })
        .await
        .unwrap();

    // Recreate the exact pre-0057 state inside this disposable fixture, then
    // exercise the real migration runner and its statement splitter.
    sqlx::query("DROP TABLE session_archive_quarantine_occurrences")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE session_archive_quarantine_record_heads")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE session_archive_quarantine_record_versions")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM schema_migrations WHERE version=57")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.db.migrate().await.unwrap();

    let version: (String, String, String) = sqlx::query_as(
        "SELECT id,record_digest,source_session_id FROM session_archive_quarantine_record_versions WHERE id=$1",
    )
    .bind(target.quarantine_id.to_string())
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(version.0, target.quarantine_id.to_string());
    assert_eq!(version.1, record_digest);
    assert_eq!(version.2, "legacy-session");
    let head: String = sqlx::query_scalar(
        "SELECT quarantine_id FROM session_archive_quarantine_record_heads WHERE external_request_id=$1",
    )
    .bind(external_request_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(head, target.quarantine_id.to_string());
    let occurrence: (String, String) = sqlx::query_as(
        "SELECT quarantine_id,source_session_id FROM session_archive_quarantine_occurrences WHERE batch_id=$1 AND sequence=1",
    )
    .bind(batch_id.to_string())
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(occurrence.0, target.quarantine_id.to_string());
    assert_eq!(occurrence.1, "legacy-session");
    let preserved = fixture
        .db
        .get_session_archive_quarantine(&tenant, target.quarantine_id)
        .await
        .unwrap();
    assert_eq!(preserved.state, "dismissed");
}

#[tokio::test]
async fn sqlite_ambiguous_identity_and_cross_tenant_resolution_fail_closed() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-ambiguous-{}", Uuid::now_v7());
    let (_, first) = create_key(&fixture.db, &tenant, "first").await;
    let (_, second) = create_key(&fixture.db, &tenant, "second").await;
    let shared_hash = hex_digest("ambiguous-source-key");
    insert_cpamp_identity(&fixture.db, &fixture.pool, &first, &shared_hash, "first").await;
    insert_cpamp_identity(&fixture.db, &fixture.pool, &second, &shared_hash, "second").await;
    let ambiguous = classify(
        &fixture.db,
        &tenant,
        "archive-ambiguous",
        Some(&shared_hash),
        &hex_digest("ambiguous-record"),
    )
    .await
    .expect_err("one source hash mapped to two stable keys must fail");
    assert!(matches!(ambiguous, AppError::BadRequest(_)));

    let other_tenant = format!("quarantine-other-{}", Uuid::now_v7());
    let (_, other_key) = create_key(&fixture.db, &other_tenant, "other").await;
    let record_digest = hex_digest("cross-tenant-record");
    let target = quarantined(
        classify(
            &fixture.db,
            &tenant,
            "archive-cross-tenant",
            Some(&hex_digest("cross-tenant-unknown")),
            &record_digest,
        )
        .await
        .unwrap(),
    );
    commit_quarantine(
        &fixture.db,
        &target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-cross-tenant",
            record_digest: &record_digest,
            batch_id: Uuid::now_v7(),
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .unwrap();
    let cross_tenant = fixture
        .db
        .resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            tenant_external_id: &other_tenant,
            quarantine_id: target.quarantine_id,
            action: "associate",
            key_id: Some(other_key.key_id),
            expected_record_digest: &record_digest,
            evidence_digest: &hex_digest("cross-tenant-evidence"),
            note: Some("must remain invisible"),
            idempotency_key: "quarantine-cross-tenant-resolution",
            resolved_by_service_id: Uuid::now_v7(),
        })
        .await
        .expect_err("another tenant cannot resolve quarantine");
    assert!(matches!(cross_tenant, AppError::NotFound));
    assert!(matches!(
        fixture
            .db
            .get_session_archive_quarantine(&other_tenant, target.quarantine_id)
            .await,
        Err(AppError::NotFound)
    ));
}

#[tokio::test]
async fn sqlite_association_is_key_scoped_and_resolution_audit_is_immutable() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-resolve-{}", Uuid::now_v7());
    let (_, selected) = create_key(&fixture.db, &tenant, "selected").await;
    let (_, unselected) = create_key(&fixture.db, &tenant, "unselected").await;
    let record_digest = hex_digest("association-record");
    let target = quarantined(
        classify(
            &fixture.db,
            &tenant,
            "archive-associate",
            Some(&hex_digest("association-unknown")),
            &record_digest,
        )
        .await
        .unwrap(),
    );
    commit_quarantine(
        &fixture.db,
        &target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-associate",
            record_digest: &record_digest,
            batch_id: Uuid::now_v7(),
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .unwrap();
    let before = isolation_counts(&fixture.pool).await;
    let actor = Uuid::now_v7();
    let evidence = hex_digest("association-evidence");
    let resolve = || SessionArchiveQuarantineResolutionInput {
        tenant_external_id: &tenant,
        quarantine_id: target.quarantine_id,
        action: "associate",
        key_id: Some(selected.key_id),
        expected_record_digest: &record_digest,
        evidence_digest: &evidence,
        note: Some("operator verified immutable evidence"),
        idempotency_key: "quarantine-association-resolution",
        resolved_by_service_id: actor,
    };
    let first = fixture
        .db
        .resolve_session_archive_quarantine(resolve())
        .await
        .expect("associate quarantine");
    let replay = fixture
        .db
        .resolve_session_archive_quarantine(resolve())
        .await
        .expect("replay exact association");
    assert_eq!(replay.id, first.id);
    assert_eq!(replay.key_id, Some(selected.key_id));

    let after = isolation_counts(&fixture.pool).await;
    assert_eq!(after.requests, before.requests);
    assert_eq!(after.request_facts, before.request_facts);
    assert_eq!(after.usage_rollups, before.usage_rollups);
    assert_eq!(after.ledger_entries, before.ledger_entries);
    assert_eq!(after.conversations, before.conversations);
    assert_eq!(after.unlinked, before.unlinked + 1);
    let diagnostic_projection: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT requests, errors, input_tokens, output_tokens, duration_count, duration_sum_ms FROM session_archive_totals WHERE tenant_id = $1 AND key_id = $2 AND session_id = $3",
    )
    .bind(selected.tenant_id.to_string())
    .bind(selected.key_id.to_string())
    .bind(format!("unlinked:{}", selected.key_id))
    .fetch_one(&fixture.pool)
    .await
    .expect("quarantine association diagnostic projection");
    assert_eq!(diagnostic_projection, (1, 0, 13, 7, 1, 500));
    let refs = fixture
        .db
        .request_archive_refs(selected.key_id, target.quarantine_id)
        .await
        .expect("selected key can address associated archive row");
    assert!(refs.provenance.expect("archive provenance").unlinked);
    assert!(matches!(
        fixture
            .db
            .request_archive_refs(unselected.key_id, target.quarantine_id)
            .await,
        Err(AppError::NotFound)
    ));

    for changed in [
        SessionArchiveQuarantineResolutionInput {
            note: Some("changed note"),
            ..resolve()
        },
        SessionArchiveQuarantineResolutionInput {
            evidence_digest: &hex_digest("changed evidence"),
            ..resolve()
        },
        SessionArchiveQuarantineResolutionInput {
            resolved_by_service_id: Uuid::now_v7(),
            ..resolve()
        },
    ] {
        assert!(matches!(
            fixture.db.resolve_session_archive_quarantine(changed).await,
            Err(AppError::Conflict(_))
        ));
    }
    let resolved = fixture
        .db
        .get_session_archive_quarantine(&tenant, target.quarantine_id)
        .await
        .unwrap();
    assert_eq!(resolved.state, "resolved");
}

#[tokio::test]
async fn sqlite_dismissal_cannot_be_bypassed_by_a_later_key_mapping() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-dismiss-{}", Uuid::now_v7());
    let (issued, _) = create_key(&fixture.db, &tenant, "later-owner").await;
    let legacy_credential = format!("legacy-quarantine-credential-{}", Uuid::now_v7());
    let source_hash = hex_digest(legacy_credential.as_bytes());
    let record_digest = hex_digest("dismissed-record");
    let target = quarantined(
        classify(
            &fixture.db,
            &tenant,
            "archive-dismiss",
            Some(&source_hash),
            &record_digest,
        )
        .await
        .unwrap(),
    );
    commit_quarantine(
        &fixture.db,
        &target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-dismiss",
            record_digest: &record_digest,
            batch_id: Uuid::now_v7(),
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .unwrap();
    fixture
        .db
        .resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            tenant_external_id: &tenant,
            quarantine_id: target.quarantine_id,
            action: "dismiss",
            key_id: None,
            expected_record_digest: &record_digest,
            evidence_digest: &hex_digest("dismiss-evidence"),
            note: Some("identity cannot be proven"),
            idempotency_key: "quarantine-dismiss-resolution",
            resolved_by_service_id: Uuid::now_v7(),
        })
        .await
        .expect("dismiss quarantine");
    insert_retained_source_mapping(&fixture.pool, issued.key_id, &source_hash).await;
    let replay = classify(
        &fixture.db,
        &tenant,
        "archive-dismiss",
        Some(&source_hash),
        &record_digest,
    )
    .await
    .expect("dismissed replay remains quarantined");
    let replay = quarantined(replay);
    assert_eq!(replay.quarantine_id, target.quarantine_id);
    let dismissed = fixture
        .db
        .get_session_archive_quarantine(&tenant, target.quarantine_id)
        .await
        .unwrap();
    assert_eq!(dismissed.state, "dismissed");
}

#[tokio::test]
async fn sqlite_quarantine_list_never_exceeds_the_requested_or_compiled_limit() {
    let fixture = sqlite_fixture().await;
    let tenant = format!("quarantine-page-{}", Uuid::now_v7());
    create_key(&fixture.db, &tenant, "tenant-anchor").await;
    let batch_id = Uuid::now_v7();
    for index in 0..105_i64 {
        let external_request_id = format!("archive-page-{index:03}");
        let record_digest = hex_digest(format!("page-record-{index}"));
        let source_hash = hex_digest(format!("page-identity-{index}"));
        let target = quarantined(
            classify(
                &fixture.db,
                &tenant,
                &external_request_id,
                Some(&source_hash),
                &record_digest,
            )
            .await
            .unwrap(),
        );
        commit_quarantine(
            &fixture.db,
            &target,
            CommitFixture {
                tenant: &tenant,
                external_request_id: &external_request_id,
                record_digest: &record_digest,
                batch_id,
                sequence: index + 1,
                batch_records: 105,
            },
        )
        .await
        .unwrap();
    }
    let requested = fixture
        .db
        .list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: None,
            limit: 7,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap();
    assert_eq!(requested.len(), 7);
    let capped = fixture
        .db
        .list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: None,
            limit: 10_000,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap();
    assert_eq!(capped.len(), 100);
}

#[tokio::test]
async fn postgres_quarantine_core_invariants_match_sqlite() {
    let Ok(database_url) = std::env::var("MTC_TEST_POSTGRES_URL") else {
        return;
    };
    let db = Database::connect_with_max(&database_url, 4)
        .await
        .expect("connect quarantine postgres");
    db.migrate().await.expect("migrate quarantine postgres");
    let pool = AnyPool::connect(&database_url)
        .await
        .expect("connect quarantine postgres inspection pool");
    let tenant = format!("quarantine-postgres-{}", Uuid::now_v7());
    let (_, selected) = create_key(&db, &tenant, "selected").await;
    let (_, unselected) = create_key(&db, &tenant, "unselected").await;
    let (_, later_owner) = create_key(&db, &tenant, "later-owner").await;
    let missing = quarantined(
        classify(
            &db,
            &tenant,
            "archive-postgres-missing",
            None,
            &hex_digest("postgres-missing-record"),
        )
        .await
        .expect("PostgreSQL missing identity is quarantinable"),
    );
    assert_eq!(missing.reason_code, "missing_credential_hash");
    assert!(matches!(
        classify(
            &db,
            &tenant,
            "archive-postgres-malformed",
            Some("malformed"),
            &hex_digest("postgres-malformed-record"),
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    let ambiguous_hash = hex_digest(format!("postgres-ambiguous-{}", Uuid::now_v7()));
    insert_cpamp_identity(&db, &pool, &selected, &ambiguous_hash, "postgres-first").await;
    insert_cpamp_identity(&db, &pool, &unselected, &ambiguous_hash, "postgres-second").await;
    assert!(matches!(
        classify(
            &db,
            &tenant,
            "archive-postgres-ambiguous",
            Some(&ambiguous_hash),
            &hex_digest("postgres-ambiguous-record"),
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    let source_hash = hex_digest(format!("postgres-unknown-{}", Uuid::now_v7()));
    let record_digest = hex_digest(format!("postgres-record-{}", Uuid::now_v7()));
    let external_request_id = format!("archive-postgres-{}", Uuid::now_v7());
    let target = quarantined(
        classify(
            &db,
            &tenant,
            &external_request_id,
            Some(&source_hash),
            &record_digest,
        )
        .await
        .unwrap(),
    );
    let batch_id = Uuid::now_v7();
    assert!(
        commit_quarantine(
            &db,
            &target,
            CommitFixture {
                tenant: &tenant,
                external_request_id: &external_request_id,
                record_digest: &record_digest,
                batch_id,
                sequence: 1,
                batch_records: 1,
            },
        )
        .await
        .unwrap()
    );
    assert!(
        !commit_quarantine(
            &db,
            &target,
            CommitFixture {
                tenant: &tenant,
                external_request_id: &external_request_id,
                record_digest: &record_digest,
                batch_id,
                sequence: 1,
                batch_records: 1,
            },
        )
        .await
        .unwrap()
    );
    let before = isolation_counts(&pool).await;
    let actor = Uuid::now_v7();
    let evidence = hex_digest("postgres-association-evidence");
    let resolution = || SessionArchiveQuarantineResolutionInput {
        tenant_external_id: &tenant,
        quarantine_id: target.quarantine_id,
        action: "associate",
        key_id: Some(selected.key_id),
        expected_record_digest: &record_digest,
        evidence_digest: &evidence,
        note: Some("postgres operator evidence"),
        idempotency_key: "postgres-quarantine-association",
        resolved_by_service_id: actor,
    };
    let resolved = db
        .resolve_session_archive_quarantine(resolution())
        .await
        .expect("associate postgres quarantine");
    assert_eq!(
        db.resolve_session_archive_quarantine(resolution())
            .await
            .expect("replay postgres resolution")
            .id,
        resolved.id
    );
    assert!(matches!(
        db.resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            note: Some("changed postgres note"),
            ..resolution()
        })
        .await,
        Err(AppError::Conflict(_))
    ));
    let after = isolation_counts(&pool).await;
    assert_eq!(after.requests, before.requests);
    assert_eq!(after.request_facts, before.request_facts);
    assert_eq!(after.usage_rollups, before.usage_rollups);
    assert_eq!(after.ledger_entries, before.ledger_entries);
    assert_eq!(after.conversations, before.conversations);
    assert_eq!(after.unlinked, before.unlinked + 1);
    db.request_archive_refs(selected.key_id, target.quarantine_id)
        .await
        .expect("associated postgres row belongs to selected key");
    assert!(matches!(
        db.request_archive_refs(unselected.key_id, target.quarantine_id)
            .await,
        Err(AppError::NotFound)
    ));

    let other_tenant = format!("quarantine-postgres-other-{}", Uuid::now_v7());
    let (_, other_key) = create_key(&db, &other_tenant, "other").await;
    let cross_digest = hex_digest("postgres-cross-record");
    let cross_target = quarantined(
        classify(
            &db,
            &tenant,
            "archive-postgres-cross",
            Some(&hex_digest("postgres-cross-unknown")),
            &cross_digest,
        )
        .await
        .unwrap(),
    );
    commit_quarantine(
        &db,
        &cross_target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-postgres-cross",
            record_digest: &cross_digest,
            batch_id: Uuid::now_v7(),
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        db.resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
            tenant_external_id: &other_tenant,
            quarantine_id: cross_target.quarantine_id,
            action: "associate",
            key_id: Some(other_key.key_id),
            expected_record_digest: &cross_digest,
            evidence_digest: &hex_digest("postgres-cross-evidence"),
            note: None,
            idempotency_key: "postgres-cross-resolution",
            resolved_by_service_id: Uuid::now_v7(),
        })
        .await,
        Err(AppError::NotFound)
    ));

    let legacy_credential = format!("postgres-quarantine-legacy-{}", Uuid::now_v7());
    let late_hash = hex_digest(legacy_credential.as_bytes());
    let dismiss_digest = hex_digest("postgres-dismiss-record");
    let dismiss_target = quarantined(
        classify(
            &db,
            &tenant,
            "archive-postgres-dismiss",
            Some(&late_hash),
            &dismiss_digest,
        )
        .await
        .unwrap(),
    );
    commit_quarantine(
        &db,
        &dismiss_target,
        CommitFixture {
            tenant: &tenant,
            external_request_id: "archive-postgres-dismiss",
            record_digest: &dismiss_digest,
            batch_id: Uuid::now_v7(),
            sequence: 1,
            batch_records: 1,
        },
    )
    .await
    .unwrap();
    db.resolve_session_archive_quarantine(SessionArchiveQuarantineResolutionInput {
        tenant_external_id: &tenant,
        quarantine_id: dismiss_target.quarantine_id,
        action: "dismiss",
        key_id: None,
        expected_record_digest: &dismiss_digest,
        evidence_digest: &hex_digest("postgres-dismiss-evidence"),
        note: Some("postgres dismissal"),
        idempotency_key: "postgres-dismiss-resolution",
        resolved_by_service_id: Uuid::now_v7(),
    })
    .await
    .unwrap();
    insert_retained_source_mapping(&pool, later_owner.key_id, &late_hash).await;
    let dismissed_replay = quarantined(
        classify(
            &db,
            &tenant,
            "archive-postgres-dismiss",
            Some(&late_hash),
            &dismiss_digest,
        )
        .await
        .expect("PostgreSQL dismissal remains authoritative"),
    );
    assert_eq!(dismissed_replay.quarantine_id, dismiss_target.quarantine_id);

    let page_batch_id = Uuid::now_v7();
    for index in 0..101_i64 {
        let external_request_id = format!("archive-postgres-page-{index:03}");
        let page_digest = hex_digest(format!("postgres-page-record-{index}"));
        let page_hash = hex_digest(format!("postgres-page-hash-{index}"));
        let page_target = quarantined(
            classify(
                &db,
                &tenant,
                &external_request_id,
                Some(&page_hash),
                &page_digest,
            )
            .await
            .unwrap(),
        );
        commit_quarantine(
            &db,
            &page_target,
            CommitFixture {
                tenant: &tenant,
                external_request_id: &external_request_id,
                record_digest: &page_digest,
                batch_id: page_batch_id,
                sequence: index + 1,
                batch_records: 101,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(
        db.list_session_archive_quarantine(SessionArchiveQuarantineFilter {
            tenant_external_id: &tenant,
            state: None,
            limit: 10_000,
            before_started_at: None,
            before_id: None,
        })
        .await
        .unwrap()
        .len(),
        100
    );
}
