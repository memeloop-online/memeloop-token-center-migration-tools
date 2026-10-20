use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use memeloop_token_center::{
    AppState, api,
    config::Config,
    conversation::ConversationHints,
    db::{
        ConversationDetailFilter, ConversationListFilter, CreateKeyInput, CreateServiceTokenInput,
        Database, NewRequest, RequestListFilter, SessionArchiveCommitInput,
        SessionArchiveCorrelation, SessionArchiveMatchInput, SessionArchiveUnlinkedCommitInput,
        SessionArchiveUnlinkedMetadata,
    },
    error::AppError,
    model::KeyPolicy,
};
use rust_decimal::Decimal;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

async fn http_get(state: &AppState, path: &str, bearer: &str) -> (StatusCode, serde_json::Value) {
    let response = api::router(state.clone())
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn archive_only_history_is_key_scoped_conversational_and_never_billed_twice() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("archive-unlinked.db").display()
    );
    let config = Config::for_test(database_url.clone());
    let pepper = config.key_pepper.clone();
    let state = AppState::initialize(config)
        .await
        .expect("initialize state");
    let db = state.db.clone();
    let issued = db
        .create_key(
            CreateKeyInput {
                tenant_external_id: "archive-only-tenant".into(),
                principal_external_id: "linux-codex".into(),
                alias: "Linux Codex".into(),
                currency: "USD".into(),
                policy: KeyPolicy::default(),
                initial_balance: Decimal::new(100, 0),
                idempotency_key: Some("archive-only-key".into()),
            },
            pepper.as_bytes(),
        )
        .await
        .expect("create key");
    let key = db
        .authenticate_key(&issued.key, pepper.as_bytes())
        .await
        .expect("authenticate key");
    let second_issued = db
        .create_key(
            CreateKeyInput {
                tenant_external_id: "archive-only-tenant".into(),
                principal_external_id: "another-user".into(),
                alias: "Another User".into(),
                currency: "USD".into(),
                policy: KeyPolicy::default(),
                initial_balance: Decimal::ZERO,
                idempotency_key: Some("archive-only-second-key".into()),
            },
            pepper.as_bytes(),
        )
        .await
        .expect("create second key");
    let second_key = db
        .authenticate_key(&second_issued.key, pepper.as_bytes())
        .await
        .expect("authenticate second key");
    db.create_tenant("another-tenant", None)
        .await
        .expect("create active tenant before issuing scoped service credential");
    let tenant_service = db
        .create_service_token(
            CreateServiceTokenInput {
                name: "archive tenant reader".into(),
                scopes: vec!["requests:read".into()],
                tenant_external_id: Some("archive-only-tenant".into()),
            },
            pepper.as_bytes(),
        )
        .await
        .expect("create tenant service token");
    let other_tenant_service = db
        .create_service_token(
            CreateServiceTokenInput {
                name: "other tenant reader".into(),
                scopes: vec!["requests:read".into()],
                tenant_external_id: Some("another-tenant".into()),
            },
            pepper.as_bytes(),
        )
        .await
        .expect("create other tenant service token");

    let cpamp_request_id = Uuid::now_v7();
    let cpamp_external_id = "1a2b3c4d";
    let source_key_hash = "a".repeat(64);
    let started_at = 1_786_492_800_000_i64;
    db.record_request_started(NewRequest {
        request_id: cpamp_request_id,
        key_id: key.key_id,
        tenant_id: key.tenant_id,
        protocol: "openai-responses".into(),
        model: "gpt-fixture".into(),
        request_object: "gap://cpamp/request".into(),
        reservation_id: Uuid::now_v7(),
        upstream_account_id: None,
        model_route_id: None,
    })
    .await
    .expect("create CPAMP target");

    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&database_url)
        .await
        .expect("connect fixture pool");
    sqlx::query("UPDATE request_records SET created_at = $1 WHERE id = $2")
        .bind(started_at)
        .bind(cpamp_request_id.to_string())
        .execute(&pool)
        .await
        .expect("move request time");
    sqlx::query("UPDATE request_record_locators SET created_at = $1 WHERE id = $2")
        .bind(started_at)
        .bind(cpamp_request_id.to_string())
        .execute(&pool)
        .await
        .expect("move locator time");
    sqlx::query(
        "INSERT INTO import_request_links (tenant_id, source, external_event_hash, external_request_id, source_key_hash, target_request_id, source_created_at, source_model, created_at) VALUES ($1, 'cpamp-usage-events-v1', $2, $3, $4, $5, $6, 'gpt-fixture', $6)",
    )
    .bind(key.tenant_id.to_string())
    .bind("e".repeat(64))
    .bind(cpamp_external_id)
    .bind(&source_key_hash)
    .bind(cpamp_request_id.to_string())
    .bind(started_at)
    .execute(&pool)
    .await
    .expect("insert CPAMP identity proof");

    // The archive UUID intentionally cannot join the CPAMP eight-character id.
    let archive_external_id = "01900000-0000-7000-8000-000000000123";
    let record_digest = "b".repeat(64);
    let correlation = db
        .correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: "archive-only-tenant",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v1",
            external_request_id: archive_external_id,
            started_at: started_at + 100,
            requested_model: Some("gpt-fixture"),
            resolved_model: Some("gpt-fixture"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await
        .expect("prove archive-only stable identity");
    let SessionArchiveCorrelation::Unlinked(target) = correlation else {
        panic!("different source request ids must not fabricate an exact edge");
    };
    let request_json = json!({
        "model": "gpt-fixture",
        "input": [{"role": "user", "content": "old logical session"}]
    });
    let hints = ConversationHints {
        session_id: Some("old-codex-session".into()),
        turn_id: Some("archive-turn-1".into()),
        ..ConversationHints::default()
    };
    let commit = || SessionArchiveUnlinkedCommitInput {
        tenant_external_id: "archive-only-tenant",
        archive_source: "cpa-session-archive-v1",
        external_request_id: archive_external_id,
        source_session_id: "archive-only-session",
        target: &target,
        record_digest: &record_digest,
        request_digest: Some(&record_digest),
        response_digest: None,
        request_object: Some(
            "objects/blake3/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        response_object: None,
        request_json: Some(&request_json),
        conversation_hints: &hints,
        client_name: Some("Codex"),
        source_started_at: started_at + 100,
        metadata: SessionArchiveUnlinkedMetadata {
            source_completed_at: Some(started_at + 900),
            protocol: "openai-responses",
            model: "gpt-fixture",
            status_code: Some(200),
            duration_ms: Some(800),
            input_tokens: 20,
            output_tokens: 10,
            error_code: None,
        },
        defer_checkpoint: false,
    };
    assert!(
        db.commit_session_archive_unlinked_request(commit())
            .await
            .unwrap()
    );
    assert!(
        !db.commit_session_archive_unlinked_request(commit())
            .await
            .unwrap()
    );

    let checkpoint: (i64, i64) = sqlx::query_as(
        "SELECT imported_records, watermark_ms FROM session_archive_import_checkpoints WHERE tenant_id = $1 AND source = 'cpa-session-archive-v1'",
    )
    .bind(key.tenant_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("checkpoint");
    assert_eq!(checkpoint, (1, started_at + 900));
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM request_records), (SELECT COUNT(*) FROM session_archive_unlinked_requests), (SELECT COUNT(*) FROM conversation_observations)",
    )
    .fetch_one(&pool)
    .await
    .expect("projection counts");
    assert_eq!(
        counts,
        (1, 1, 1),
        "archive-only must not duplicate billing rows"
    );
    let ordinary = db
        .list_requests_filtered(
            key.key_id,
            RequestListFilter {
                limit: 100,
                ..RequestListFilter::default()
            },
        )
        .await
        .expect("ordinary requests");
    assert_eq!(ordinary.len(), 1, "archive-only stays out of request list");

    let clusters = db
        .conversation_clusters(
            key.key_id,
            ConversationListFilter {
                limit: 10,
                before_updated_at: None,
                before_cluster_id: None,
            },
        )
        .await
        .expect("conversation list");
    assert_eq!(clusters.len(), 1);
    let detail = db
        .conversation_cluster_detail(
            key.key_id,
            clusters[0].cluster_id,
            ConversationDetailFilter {
                limit: 10,
                before_created_at: None,
                before_request_id: None,
            },
        )
        .await
        .expect("conversation detail");
    assert_eq!(detail.requests.len(), 1);
    assert!(detail.requests[0].unlinked);
    assert_eq!(
        detail.requests[0].request.request_id,
        target.archive_request_id
    );

    let refs = db
        .request_archive_refs(key.key_id, target.archive_request_id)
        .await
        .expect("key-scoped archive detail");
    assert!(refs.provenance.as_ref().is_some_and(|value| value.unlinked));
    assert!(matches!(
        db.request_archive_refs(second_key.key_id, target.archive_request_id)
            .await,
        Err(AppError::NotFound)
    ));
    assert!(matches!(
        db.request_archive_refs_for_tenant("another-tenant", target.archive_request_id)
            .await,
        Err(AppError::NotFound)
    ));
    let (status, conversations) = http_get(&state, "/self/v1/conversations", &issued.key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(conversations.as_array().map(Vec::len), Some(1));
    let cluster_id = conversations[0]["cluster_id"].as_str().unwrap();
    let (status, conversation) = http_get(
        &state,
        &format!("/self/v1/conversations/{cluster_id}"),
        &issued.key,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(conversation["requests"][0]["unlinked"], true);
    assert_eq!(
        conversation["requests"][0]["provenance"],
        "archive_unlinked"
    );
    let archive_detail_path = format!("/self/v1/requests/{}", target.archive_request_id);
    let (status, archive_detail) = http_get(&state, &archive_detail_path, &issued.key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(archive_detail["provenance"]["unlinked"], true);
    assert_eq!(archive_detail["provenance"]["disposition"], "unlinked");
    let (status, _) = http_get(&state, &archive_detail_path, &second_issued.key).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, ordinary_requests) = http_get(&state, "/self/v1/requests", &issued.key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ordinary_requests.as_array().map(Vec::len), Some(1));
    let internal_detail_path = format!("/internal/v1/requests/{}", target.archive_request_id);
    let (status, internal_detail) =
        http_get(&state, &internal_detail_path, &tenant_service.token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(internal_detail["provenance"]["unlinked"], true);
    let (status, _) = http_get(&state, &internal_detail_path, &other_tenant_service.token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mismatched_record_digest = "9".repeat(64);
    assert!(matches!(
        db.correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: "archive-only-tenant",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v1",
            external_request_id: cpamp_external_id,
            started_at,
            requested_model: Some("tampered-model"),
            resolved_model: Some("tampered-model"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &mismatched_record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await,
        Err(AppError::BadRequest(_))
    ));
    let mismatched_correlations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM session_archive_correlations WHERE tenant_id = $1 AND source = 'cpa-session-archive-v1' AND external_request_id = $2",
    )
    .bind(key.tenant_id.to_string())
    .bind(cpamp_external_id)
    .fetch_one(&pool)
    .await
    .expect("mismatched correlation count");
    assert_eq!(mismatched_correlations, 0);

    let exact_record_digest = "1".repeat(64);
    let exact = db
        .correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: "archive-only-tenant",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v1",
            external_request_id: cpamp_external_id,
            started_at,
            requested_model: Some("gpt-fixture"),
            resolved_model: Some("gpt-fixture"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &exact_record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await
        .expect("exact correlation");
    let SessionArchiveCorrelation::Exact {
        target: exact_target,
        identity_proof_kind,
        identity_proof_digest,
        correlation_proof_digest,
    } = exact
    else {
        panic!("matching CPAMP id and evidence must be exact");
    };
    let exact_request_digest = "2".repeat(64);
    let exact_response_digest = "3".repeat(64);
    let exact_hints = ConversationHints::default();
    let exact_commit = SessionArchiveCommitInput {
        tenant_external_id: "archive-only-tenant",
        archive_source: "cpa-session-archive-v1",
        external_request_id: cpamp_external_id,
        source_session_id: "exact-session",
        target: &exact_target,
        record_digest: &exact_record_digest,
        request_digest: Some(&exact_request_digest),
        response_digest: Some(&exact_response_digest),
        request_object: Some(
            "objects/blake3/22/2222222222222222222222222222222222222222222222222222222222222222",
        ),
        response_object: Some(
            "objects/blake3/33/3333333333333333333333333333333333333333333333333333333333333333",
        ),
        request_json: None,
        conversation_hints: &exact_hints,
        client_name: Some("Codex"),
        source_started_at: started_at,
        source_completed_at: Some(started_at + 1_000),
        identity_proof_kind: &identity_proof_kind,
        identity_proof_digest: &identity_proof_digest,
        correlation_proof_digest: &correlation_proof_digest,
        defer_checkpoint: false,
    };
    assert!(
        db.commit_session_archive_request(exact_commit)
            .await
            .expect("first exact commit")
    );
    let changed_response_digest = "4".repeat(64);
    let changed_replay = SessionArchiveCommitInput {
        tenant_external_id: "archive-only-tenant",
        archive_source: "cpa-session-archive-v1",
        external_request_id: cpamp_external_id,
        source_session_id: "exact-session",
        target: &exact_target,
        record_digest: &exact_record_digest,
        request_digest: Some(&exact_request_digest),
        response_digest: Some(&changed_response_digest),
        request_object: Some(
            "objects/blake3/22/2222222222222222222222222222222222222222222222222222222222222222",
        ),
        response_object: Some(
            "objects/blake3/33/3333333333333333333333333333333333333333333333333333333333333333",
        ),
        request_json: None,
        conversation_hints: &exact_hints,
        client_name: Some("Codex"),
        source_started_at: started_at,
        source_completed_at: Some(started_at + 1_000),
        identity_proof_kind: &identity_proof_kind,
        identity_proof_digest: &identity_proof_digest,
        correlation_proof_digest: &correlation_proof_digest,
        defer_checkpoint: false,
    };
    assert!(matches!(
        db.commit_session_archive_request(changed_replay).await,
        Err(AppError::BadRequest(_))
    ));

    let conflicting_identity_request = Uuid::now_v7();
    db.record_request_started(NewRequest {
        request_id: conflicting_identity_request,
        key_id: second_key.key_id,
        tenant_id: second_key.tenant_id,
        protocol: "openai-responses".into(),
        model: "gpt-fixture".into(),
        request_object: "gap://cpamp/conflicting-identity".into(),
        reservation_id: Uuid::now_v7(),
        upstream_account_id: None,
        model_route_id: None,
    })
    .await
    .expect("create conflicting identity target");
    sqlx::query(
        "INSERT INTO import_request_links (tenant_id, source, external_event_hash, external_request_id, source_key_hash, target_request_id, source_created_at, source_model, created_at) VALUES ($1, 'cpamp-usage-events-v1', $2, 'conflicting-identity', $3, $4, $5, 'gpt-fixture', $5)",
    )
    .bind(second_key.tenant_id.to_string())
    .bind("5".repeat(64))
    .bind(&source_key_hash)
    .bind(conflicting_identity_request.to_string())
    .bind(started_at)
    .execute(&pool)
    .await
    .expect("insert conflicting identity proof");
    let conflicting_record_digest = "6".repeat(64);
    assert!(matches!(
        db.correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: "archive-only-tenant",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "credential-conflict-test",
            external_request_id: "conflicting-identity",
            started_at,
            requested_model: Some("gpt-fixture"),
            resolved_model: Some("gpt-fixture"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &conflicting_record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await,
        Err(AppError::BadRequest(_))
    ));
}

#[tokio::test]
async fn archive_only_without_stable_identity_fails_before_any_provenance_write() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("archive-no-identity.db").display()
    );
    let db = Database::connect(&database_url)
        .await
        .expect("connect SQLite");
    db.migrate().await.expect("migrate target");
    let source_key_hash = "f".repeat(64);
    let record_digest = "e".repeat(64);
    let error = db
        .correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: "missing-tenant",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v1",
            external_request_id: "archive-without-proof",
            started_at: 1,
            requested_model: Some("gpt-fixture"),
            resolved_model: None,
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await
        .expect_err("missing identity must fail closed");
    assert!(matches!(error, AppError::BadRequest(_)));

    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&database_url)
        .await
        .expect("connect fixture pool");
    let correlations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_correlations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(correlations, 0);
}

#[tokio::test]
async fn postgres_archive_only_commit_and_conversation_union_use_native_types() {
    let Ok(database_url) = std::env::var("MTC_TEST_POSTGRES_URL") else {
        return;
    };
    let db = Database::connect_with_max(&database_url, 8)
        .await
        .expect("connect isolated PostgreSQL");
    db.migrate().await.expect("migrate PostgreSQL through v28");
    let unique = Uuid::now_v7();
    let tenant_external_id = format!("archive-pg-{unique}");
    let archive_source = format!("archive-pg-source-{unique}");
    let issued = db
        .create_key(
            CreateKeyInput {
                tenant_external_id: tenant_external_id.clone(),
                principal_external_id: "linux-codex".into(),
                alias: "PostgreSQL archive".into(),
                currency: "USD".into(),
                policy: KeyPolicy::default(),
                initial_balance: Decimal::ZERO,
                idempotency_key: None,
            },
            b"postgres archive-only pepper is safely long",
        )
        .await
        .expect("create PostgreSQL key");
    let key = db
        .authenticate_key(&issued.key, b"postgres archive-only pepper is safely long")
        .await
        .expect("authenticate PostgreSQL key");
    let cpamp_request_id = Uuid::now_v7();
    let started_at = memeloop_token_center::db::unix_millis();
    db.record_request_started(NewRequest {
        request_id: cpamp_request_id,
        key_id: key.key_id,
        tenant_id: key.tenant_id,
        protocol: "openai-responses".into(),
        model: "gpt-pg-archive".into(),
        request_object: "gap://cpamp/postgres/request".into(),
        reservation_id: Uuid::now_v7(),
        upstream_account_id: None,
        model_route_id: None,
    })
    .await
    .expect("create PostgreSQL CPAMP request");
    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&database_url)
        .await
        .expect("connect PostgreSQL fixture pool");
    let source_key_hash = "6".repeat(64);
    sqlx::query(
        "INSERT INTO import_request_links (tenant_id, source, external_event_hash, external_request_id, source_key_hash, target_request_id, source_created_at, source_model, created_at) VALUES ($1, 'cpamp-usage-events-v1', $2, 'pg8abcd0', $3, $4, $5, 'gpt-pg-archive', $5)",
    )
    .bind(key.tenant_id.to_string())
    .bind("7".repeat(64))
    .bind(&source_key_hash)
    .bind(cpamp_request_id.to_string())
    .bind(started_at)
    .execute(&pool)
    .await
    .expect("insert PostgreSQL CPAMP proof");
    let second_cpamp_request_id = Uuid::now_v7();
    db.record_request_started(NewRequest {
        request_id: second_cpamp_request_id,
        key_id: key.key_id,
        tenant_id: key.tenant_id,
        protocol: "openai-responses".into(),
        model: "gpt-pg-archive".into(),
        request_object: "gap://cpamp/postgres/ambiguous-request".into(),
        reservation_id: Uuid::now_v7(),
        upstream_account_id: None,
        model_route_id: None,
    })
    .await
    .expect("create second PostgreSQL CPAMP request");
    sqlx::query(
        "INSERT INTO import_request_links (tenant_id, source, external_event_hash, external_request_id, source_key_hash, target_request_id, source_created_at, source_model, created_at) VALUES ($1, 'cpamp-usage-events-v1', $2, 'pg8abcd0', $3, $4, $5, 'gpt-pg-archive', $5)",
    )
    .bind(key.tenant_id.to_string())
    .bind("9".repeat(64))
    .bind(&source_key_hash)
    .bind(second_cpamp_request_id.to_string())
    .bind(started_at)
    .execute(&pool)
    .await
    .expect("insert second PostgreSQL CPAMP proof");

    let ambiguous_record_digest = "a".repeat(64);
    let ambiguous_archive_source = format!("{archive_source}-ambiguous");
    let ambiguous = db
        .correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: &tenant_external_id,
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: &ambiguous_archive_source,
            external_request_id: "pg8abcd0",
            started_at,
            requested_model: Some("gpt-pg-archive"),
            resolved_model: Some("gpt-pg-archive"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &ambiguous_record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await
        .expect("PostgreSQL compatible ambiguity must become archive-only");
    assert!(matches!(ambiguous, SessionArchiveCorrelation::Unlinked(_)));
    let incompatible_archive_source = format!("{archive_source}-incompatible");
    assert!(matches!(
        db.correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: &tenant_external_id,
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: &incompatible_archive_source,
            external_request_id: "pg8abcd0",
            started_at,
            requested_model: Some("tampered-model"),
            resolved_model: Some("tampered-model"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &ambiguous_record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await,
        Err(AppError::BadRequest(_))
    ));
    let external_request_id = unique.to_string();
    let record_digest = "8".repeat(64);
    let correlation = db
        .correlate_session_archive_request(SessionArchiveMatchInput {
            tenant_external_id: &tenant_external_id,
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: &archive_source,
            external_request_id: &external_request_id,
            started_at: started_at + 1,
            requested_model: Some("gpt-pg-archive"),
            resolved_model: Some("gpt-pg-archive"),
            source_key_hash: &source_key_hash,
            input_tokens: None,
            output_tokens: None,
            record_digest: &record_digest,
            time_tolerance_ms: 5_000,
            allow_stable_replacement: false,
        })
        .await
        .expect("correlate PostgreSQL archive-only row");
    let SessionArchiveCorrelation::Unlinked(target) = correlation else {
        panic!("PostgreSQL archive UUID must remain unlinked");
    };
    let hints = ConversationHints {
        session_id: Some(format!("pg-session-{unique}")),
        ..ConversationHints::default()
    };
    let request_json = json!({"input": [{"role": "user", "content": "postgres archive"}]});
    assert!(
        db.commit_session_archive_unlinked_request(SessionArchiveUnlinkedCommitInput {
            tenant_external_id: &tenant_external_id,
            archive_source: &archive_source,
            external_request_id: &external_request_id,
            source_session_id: "postgres-unlinked-session",
            target: &target,
            record_digest: &record_digest,
            request_digest: None,
            response_digest: None,
            request_object: None,
            response_object: None,
            request_json: Some(&request_json),
            conversation_hints: &hints,
            client_name: Some("Codex"),
            source_started_at: started_at + 1,
            metadata: SessionArchiveUnlinkedMetadata {
                source_completed_at: Some(started_at + 2),
                protocol: "openai-responses",
                model: "gpt-pg-archive",
                status_code: Some(200),
                duration_ms: Some(1),
                input_tokens: 1,
                output_tokens: 1,
                error_code: None,
            },
            defer_checkpoint: false,
        })
        .await
        .expect("commit PostgreSQL archive-only row")
    );
    let clusters = db
        .conversation_clusters(
            key.key_id,
            ConversationListFilter {
                limit: 10,
                before_updated_at: None,
                before_cluster_id: None,
            },
        )
        .await
        .expect("list PostgreSQL archive conversation");
    let detail = db
        .conversation_cluster_detail(
            key.key_id,
            clusters[0].cluster_id,
            ConversationDetailFilter {
                limit: 10,
                before_created_at: None,
                before_request_id: None,
            },
        )
        .await
        .expect("decode PostgreSQL BIGINT conversation union");
    assert_eq!(detail.requests.len(), 1);
    assert!(detail.requests[0].unlinked);
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM session_archive_correlations WHERE tenant_id = $1 AND source = $2), (SELECT COUNT(*) FROM session_archive_unlinked_requests WHERE tenant_id = $1 AND source = $2), (SELECT COUNT(*) FROM request_records WHERE tenant_id = $1)",
    )
    .bind(key.tenant_id.to_string())
    .bind(&archive_source)
    .fetch_one(&pool)
    .await
    .expect("PostgreSQL archive counts");
    assert_eq!(counts, (1, 1, 2));
}
